#include "GlobalAccessHarvester.h"

#include <vector>
#include <chrono>

#include "../../Architecture/IArchDecoder.h"
#include "../../Memory/IMemory.h"
#include "../../Utils/Utils.h"

#include "CallGraph.h"
#include "CodeWindow.h"

namespace nextdumper::analyzer
{
	namespace
	{

		/// Tracked value of a register, when it is known to hold a computed address.
		struct RegState
		{
			uint64_t Value = 0;
			bool bKnown = false;

			/// Set while Value is page-granular and still awaits the displacement
			/// that completes the address.
			bool bPageBase = false;
		};

	} // namespace

	GlobalAccessHarvester::GlobalAccessHarvester() = default;
	GlobalAccessHarvester::~GlobalAccessHarvester() = default;
	GlobalAccessHarvester::GlobalAccessHarvester(GlobalAccessHarvester &&) noexcept = default;
	GlobalAccessHarvester &GlobalAccessHarvester::operator=(GlobalAccessHarvester &&) noexcept = default;

	const AccessInfo *GlobalAccessHarvester::Find(uint64_t Address) const
	{
		auto It = Accesses_.find(Address);
		return It == Accesses_.end() ? nullptr : &It->second;
	}

	void GlobalAccessHarvester::RecordTo(AccessMap &Map, uint64_t Global, EAccessKind Kind, uint64_t Site, const HarvestOptions &Options, int64_t Offset, uint8_t AccessWidth, bool bRecordOffset)
	{
		AccessInfo &Info = Map[Global];
		++Info.Count;
		Info.Kinds |= static_cast<uint8_t>(Kind);
		if (Info.Sites.size() < Options.MaxSitesPerGlobal)
			Info.Sites.push_back(Site);
		if (bRecordOffset && Info.Offsets.size() < Options.MaxOffsetsPerGlobal)
			Info.Offsets.insert(Offset);
		if (AccessWidth)
		{
			// "Wide" means pointer-width for the image being analysed, which is why
			// the tool is built at the image's width: on a 32-bit target a pointer
			// load is 4 bytes, and comparing against a fixed 8 would file every
			// pointer field under NarrowAccesses.
			if (AccessWidth >= sizeof(uintptr_t))
				++Info.WideAccesses;
			else
				++Info.NarrowAccesses;
		}
	}

	bool GlobalAccessHarvester::Run(IMemory *Memory, const IArchDecoder *Arch, const HarvestOptions &Options, CallGraph *OutCalls)
	{
		Accesses_.clear();
		// An image yields ~200k entries (see the class doc comment); reserving avoids repeated
		// full rehashes on the way up from empty. Iteration order never matters here (every
		// consumer sorts what it pulls out), so the hint has no observable effect on output.
		Accesses_.reserve(200'000);
		Decoded_ = 0;

		Module_ = Memory->GetUnrealModule();
		Arch_ = Arch;
		if (!Arch_)
			return false;

		// Permissions, not names: "executable" is the portable way to say "code".
		// The scan runs to the region end and CodeWindow stops it wherever the bytes
		// stop being readable, so no file-only size is needed to find the boundary.
		for (const auto &Seg : Module_.GetSegments())
		{
			if (!Seg.IsExecutable() || Seg.GetSize() == 0)
				continue;
			ScanRange(Memory, Seg.GetStart(), Seg.GetEnd(), Options, OutCalls);
		}
		return true;
	}

	void GlobalAccessHarvester::ScanRange(const IMemory *Memory, uint64_t Start, uint64_t End, const HarvestOptions &Options, CallGraph *OutCalls)
	{
		Walk(Memory, Start, End, Options, Accesses_, &Decoded_, OutCalls);
	}

	AccessMap GlobalAccessHarvester::ScanFunction(const IMemory *Memory, uint64_t Start, uint64_t End, const HarvestOptions &Options) const
	{
		AccessMap Local;
		if (Arch_)
			Walk(Memory, Start, End, Options, Local, nullptr);
		return Local;
	}

	void GlobalAccessHarvester::Walk(const IMemory *Memory, uint64_t Start, uint64_t End, const HarvestOptions &Options, AccessMap &Out, uint64_t *DecodedOut, CallGraph *OutCalls) const
	{
		// Dereferenced once into a reference: Walk decodes millions of instructions
		// and every one of them asks the decoder something.
		const IArchDecoder &Arch = *Arch_;

		const uint32_t Stride = Arch.InstructionStride();
		if (Stride)
			Start &= ~static_cast<uint64_t>(Stride - 1);

		const size_t Total = (End > Start) ? static_cast<size_t>(End - Start) : 0;

		// Walk backs both the whole-image sweep and ScanFunction's single function,
		// and the right window differs by three orders of magnitude between them.
		// Deriving it from the range covers both without the caller having to say.
		CodeWindow Code(Memory, CodeWindow::ChunkForSpan(Total));

		const int NumRegs = Arch.RegisterCount();
		std::vector<RegState> Regs(static_cast<size_t>(NumRegs));
		// Accumulated immediates per register, for composed MOVZ/MOVK-style pairs.
		std::vector<uint64_t> Imms(static_cast<size_t>(NumRegs), 0);

		auto ClearAll = [&]
		{
			for (auto &R : Regs)
				R.bKnown = false;
			std::fill(Imms.begin(), Imms.end(), 0);
		};

		// Constants and globals are correlated by instruction distance in both
		// directions, since the chunk size may be materialized either side of the
		// access.
		struct Seen
		{
			uint64_t Key = 0;
			uint64_t Index = 0;
		};
		std::vector<Seen> RecentConsts(12), RecentGlobals(12);
		size_t ConstHead = 0, GlobalHead = 0;

		auto IsChunkConst = [](uint64_t V)
		{ return V == kNumElementsPerChunk_4_20 || V == kNumElementsPerChunk_4_21; };

		auto Attach = [&](uint64_t Global, uint32_t Value)
		{
			auto It = Out.find(Global);
			if (It != Out.end())
				It->second.NearbyConstants.insert(Value);
		};

		auto PushConst = [&](uint32_t V, uint64_t Index)
		{
			if (!IsChunkConst(V))
				return;
			RecentConsts[ConstHead] = {V, Index};
			ConstHead = (ConstHead + 1) % RecentConsts.size();
			for (const auto &G : RecentGlobals)
				if (G.Key && Index - G.Index <= Options.ConstantWindow)
					Attach(G.Key, V);
		};

		auto PushGlobal = [&](uint64_t G, uint64_t Index)
		{
			RecentGlobals[GlobalHead] = {G, Index};
			GlobalHead = (GlobalHead + 1) % RecentGlobals.size();
			for (const auto &C : RecentConsts)
				if (C.Key && Index - C.Index <= Options.ConstantWindow)
					Attach(G, static_cast<uint32_t>(C.Key));
		};

		auto AcceptTarget = [&](uint64_t Address) -> bool
		{
			// Borrowed, not copied: this runs for every candidate address of every
			// decoded instruction, and the region carries a std::string.
			const MemRegionInfo *R = Module_.FindAddressRegion(Address);
			if (!R)
				return false;
			if (Options.RequireNonExecutableTarget && R->IsExecutable())
				return false;
			return true;
		};

		NormalizedInsn Insn;
		size_t Cursor = 0;
		uint64_t Index = 0;
		auto LastProgress = std::chrono::steady_clock::now();

		while (Cursor + 4 <= Total)
		{
			if (Options.Progress && Index % 65536 == 0 && std::chrono::steady_clock::now() - LastProgress >= std::chrono::seconds(1))
			{
				Options.Progress("analyzer: instruction bytes=" + std::to_string(Cursor) + "/" + std::to_string(Total));
				LastProgress = std::chrono::steady_clock::now();
			}
			const uint64_t Addr = Start + Cursor;

			// A failed window read means the readable bytes ended here - the end of a
			// segment's file-backed content, for instance - so the scan stops rather
			// than decoding whatever follows.
			const size_t Want = Stride ? Stride : 4;
			const uint8_t *P = Code.At(Addr, Want);
			if (!P)
				break;

			const bool bOk = Arch.DecodeLocalBytes(P, Want, Addr, Insn);
			if (DecodedOut)
				++*DecodedOut;

			const size_t Advance = Stride ? Stride : (Insn.Length ? Insn.Length : 4);

			if (!bOk)
			{
				Cursor += Advance;
				++Index;
				continue;
			}

			if (Insn.bClobbersAll)
			{
				ClearAll();
				Cursor += Advance;
				++Index;
				continue;
			}

			const int Dest = (Insn.Dest >= 0 && Insn.Dest < NumRegs) ? Insn.Dest : -1;
			const int Src = (Insn.Base >= 0 && Insn.Base < NumRegs) ? Insn.Base : -1;
			if (Insn.Kind != NormalizedInsn::EKind::MoveImm && Dest >= 0)
				Imms[Dest] = 0;

			switch (Insn.Kind)
			{
			case NormalizedInsn::EKind::Return:
				// Nothing established in this function may leak into the next.
				ClearAll();
				break;

			case NormalizedInsn::EKind::Call:
				// Recorded here rather than by a second sweep of the same bytes. Only
				// direct calls landing inside the image are useful, which is the same
				// test CallGraph::Build applied.
				if (OutCalls && Insn.Value != 0 && Module_.FindAddressRegion(Insn.Value) != nullptr)
					OutCalls->AddEdge(Insn.Value, Addr);

				for (int R = 0; R < NumRegs; ++R)
					if (Arch.CallClobbers(R))
					{
						Regs[static_cast<size_t>(R)].bKnown = false;
						Imms[static_cast<size_t>(R)] = 0;
					}
				break;

			case NormalizedInsn::EKind::Branch:
				// Deliberately does not invalidate. A base established before a loop
				// stays live through its backward branch, and that hoisted form is the
				// dominant real-world idiom; clearing here loses most real accesses.
				break;

			case NormalizedInsn::EKind::SetBase:
				if (Dest >= 0)
				{
					Regs[Dest].Value = Insn.Value;
					Regs[Dest].bKnown = true;
					Regs[Dest].bPageBase = !Insn.bExactAddress;

					// An exact address is an access in itself; a page-granular base
					// still needs a completing add or load.
					if (Insn.bExactAddress && AcceptTarget(Insn.Value))
					{
						RecordTo(Out, Insn.Value, EAccessKind::AddressTaken, Addr, Options);
						PushGlobal(Insn.Value, Index);
					}
				}
				break;

			case NormalizedInsn::EKind::LoadLiteral:
				// The word at a literal pool slot, taken as a value and nothing more.
				// Whether it is an address or a displacement is settled by the next
				// instruction - ARM32's PIC idiom completes it with ADD Rd,PC,Rd - so
				// nothing is recorded here. Recording it would name a global for every
				// displacement that happens to land inside the image, and on this
				// target that is one instruction in seven.
				if (Dest >= 0)
				{
					uint64_t Word = 0;
					if (ReadLiteralValue(Memory, Insn, Word))
					{
						Regs[Dest].Value = static_cast<uint64_t>(Word);
						Regs[Dest].bKnown = true;
						Regs[Dest].bPageBase = false;
					}
					else
					{
						Regs[Dest].bKnown = false;
					}
				}
				break;

			case NormalizedInsn::EKind::AddImm:
				if (Dest >= 0)
				{
					if (Src >= 0 && Regs[Src].bKnown)
					{
						const uint64_t G = Utils::Memory::WrapAddress(Regs[Src].Value + Insn.Value);
						Regs[Dest].Value = G;
						Regs[Dest].bKnown = true;
						Regs[Dest].bPageBase = false;
						if (AcceptTarget(G))
						{
							RecordTo(Out, G, EAccessKind::AddressTaken, Addr, Options);
							PushGlobal(G, Index);
						}
					}
					else
					{
						Regs[Dest].bKnown = false;
					}
				}
				break;

			case NormalizedInsn::EKind::Load:
			case NormalizedInsn::EKind::Store:
			{
				const bool bLoad = (Insn.Kind == NormalizedInsn::EKind::Load);
				bool bPropagated = false;

				if (Src >= 0 && Regs[Src].bKnown)
				{
					// Value is a constant addend folded into the address that is *not*
					// a field displacement - ARM32's `LDR Rd,[PC,Rm]` puts the PC
					// there, since the base register the tracker follows is Rm. It is 0
					// for every ordinary load, and Offset alone is what gets recorded
					// as the struct offset.
					const uint64_t G = Utils::Memory::WrapAddress(Regs[Src].Value + Insn.Value + static_cast<uint64_t>(Insn.Offset));

					// A displacement that completes a page-granular base forms the
					// address rather than reaching a field within one, so it is no
					// evidence about the object's layout and is not recorded as an
					// offset. Recording it would describe a page offset as a struct
					// member; recording zero instead would claim the address is named
					// as a base, which a page completion does not establish either.
					const bool bFieldOffset = !Regs[Src].bPageBase;
					if (AcceptTarget(G))
					{
						RecordTo(Out, G, bLoad ? EAccessKind::Load : EAccessKind::Store, Addr, Options, Insn.Offset, Insn.AccessWidth, bFieldOffset);
						PushGlobal(G, Index);
					}

					// Indirect resolution: a pointer-width load from a relocated slot
					// yields another image address. Following it is what reaches the
					// dominant real form: a base, then a load through a GOT slot,
					// then the access.
					if (Options.FollowIndirect && bLoad && Dest >= 0 &&
						Insn.AccessWidth == sizeof(uintptr_t))
					{
						// uintptr_t, not uint64_t: this is the memory interface's own
						// address type, and the two differ in the 32-bit build.
						uintptr_t Slot = 0;
						if (Memory->ReadRelocationPointer(static_cast<uintptr_t>(G), Slot) &&
							Module_.FindAddressRegion(Slot) != nullptr)
						{
							const uint64_t Pointee = static_cast<uint64_t>(Slot);
							Regs[Dest].Value = Pointee;
							Regs[Dest].bKnown = true;
							Regs[Dest].bPageBase = false;
							bPropagated = true;

							// Record the pointee, not just the slot. Reading a pointer out
							// of a relocated slot names the object it points at, and that
							// object is frequently the container the target is a member of.
							//
							// Width is deliberately 0: this site observes the container's
							// address, it does not read a field of it, so it must not count
							// towards the pointer-width totals the structure verifier uses
							// to decide whether a header field is hot.
							// No offset recorded: reading a pointer to an object is not
							// reading its field 0. Claiming displacement 0 here would make
							// every indirectly-referenced global look like a struct base,
							// which breaks the name table's "exactly one candidate
							// verifies" rule.
							if (AcceptTarget(Pointee))
							{
								RecordTo(Out, Pointee, EAccessKind::IndirectBase, Addr, Options,
										 /*Offset=*/0,
										 /*AccessWidth=*/0,
										 /*bRecordOffset=*/false);
								PushGlobal(Pointee, Index);
							}
						}
					}
				}

				// An unresolved load leaves unknown data in its destination.
				if (bLoad && Dest >= 0 && !bPropagated)
					Regs[Dest].bKnown = false;

				// A pre/post-indexed access moves its own base. Keeping the old value
				// would name addresses the program never computes, which is the exact
				// shape of a confident wrong answer.
				if (Insn.bWritesBackBase && Src >= 0)
					Regs[Src].bKnown = false;
				break;
			}

			case NormalizedInsn::EKind::MoveImm:
				if (Dest >= 0)
				{
					Imms[Dest] = Insn.bComposes ? ((Imms[Dest] & ~Insn.ValueMask) | Insn.Value) : Insn.Value;

					// A composed immediate is an address on the targets that build
					// them this way, so it wraps like one.
					const uint64_t V = Utils::Memory::WrapAddress(Imms[Dest]);
					if (Insn.bAddressLike)
					{
						// Targets that build addresses from immediate pairs (ARM32
						// MOVW/MOVT) promote the composed value to a base.
						if (Module_.FindAddressRegion(V))
						{
							Regs[Dest].Value = V;
							Regs[Dest].bKnown = true;
							Regs[Dest].bPageBase = false;
							break;
						}
					}
					else if (V != 0 && V <= 0xFFFFFFFFull)
					{
						PushConst(static_cast<uint32_t>(V), Index);
					}
					Regs[Dest].bKnown = false;
				}
				break;

			case NormalizedInsn::EKind::MoveReg:
				// A copy carries the tracked value with it.
				if (Dest >= 0)
				{
					if (Src >= 0 && Regs[Src].bKnown)
					{
						Regs[Dest].Value = Regs[Src].Value;
						Regs[Dest].bKnown = true;
						Regs[Dest].bPageBase = Regs[Src].bPageBase;
					}
					else
					{
						Regs[Dest].bKnown = false;
					}
				}
				break;

			case NormalizedInsn::EKind::Other:
			default:
				if (Dest >= 0)
					Regs[Dest].bKnown = false;
				break;
			}

			Cursor += Advance;
			++Index;
		}
	}

} // namespace nextdumper::analyzer
