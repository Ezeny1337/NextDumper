#include "AnchoredResolution.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "../../Architecture/IArchDecoder.h"
#include "../../Memory/IMemory.h"
#include "../../Utils/Utils.h"
#include "../Strategies/IStrategy.h"

#include "CallGraph.h"
#include "CodeWindow.h"
#include "GlobalAccessHarvester.h"
#include "LiteralScanner.h"
#include "StructureVerifier.h"

namespace nextdumper::analyzer
{
	namespace
	{
		bool AddDisplacement(int64_t left, int64_t right, int64_t &value)
		{
			if ((right > 0 && left > INT64_MAX - right) || (right < 0 && left < INT64_MIN - right))
				return false;
			value = left + right;
			return true;
		}

		bool IsWritableData(const ModuleInfo &Module, uint64_t Address)
		{
			// Permissions, never names - see MemRegionInfo::PathName.
			const MemRegionInfo *R = Module.FindAddressRegion(Address);
			return R && R->IsWriteable() && !R->IsExecutable();
		}

	} // namespace

	AnchoredResolution::AnchorSites AnchoredResolution::ScanAnchorSites(
		const IMemory *Memory, const ModuleInfo &Module, const GlobalAccessHarvester &Harvester,
		std::span<const Anchor *const> Anchors)
	{
		LiteralScanBatch Batch;
		AnchorSites Literals;
		QueueAnchorLiterals(Batch, Anchors, Literals);
		Batch.Run(Memory, Module);
		return MapAnchorSites(Literals, Harvester);
	}

	void AnchoredResolution::QueueAnchorLiterals(LiteralScanBatch &Batch, std::span<const Anchor *const> Anchors,
												 AnchorSites &Literals)
	{
		AnchorSites Result;
		for (const Anchor *A : Anchors)
			if (A && A->Text && *A->Text)
				Result.try_emplace({A->Text, A->Match});
		LiteralScanner Scanner;
		std::vector<std::pair<std::string, EAnchorMatch>> Owners;
		for (auto &[Key, Sites] : Result)
		{
			const std::string &Text = Key.first;
			const EAnchorMatch Match = Key.second;
			const size_t Owner = Owners.size();
			(void)Sites;
			Owners.push_back(Key);
			const auto add = [&](std::vector<uint8_t> Bytes, int Encoding)
			{
				if (Match == EAnchorMatch::Terminated)
					Bytes.insert(Bytes.end(), static_cast<size_t>(Encoding), 0);
				Scanner.AddRaw(Bytes.data(), Bytes.size(), Owner, Encoding, 64);
			};
			add(std::vector<uint8_t>(Text.begin(), Text.end()), 1);
			add(LiteralScanner::Widen<uint16_t>(Text.c_str()), 2);
			add(LiteralScanner::Widen<uint32_t>(Text.c_str()), 4);
		}
		Batch.Add(std::move(Scanner), true,
				  [&Literals, Result = std::move(Result), Owners = std::move(Owners)](const LiteralScanner &Scanner, const std::vector<LiteralScanner::Hit> &Hits) mutable
				  {
					  for (const auto &Hit : Hits)
						  Result.at(Owners[Scanner.GetNeedles()[Hit.NeedleIndex].OwnerIndex]).push_back(Hit.Address);
					  Literals = std::move(Result);
				  });
	}

	AnchoredResolution::AnchorSites AnchoredResolution::MapAnchorSites(const AnchorSites &Literals,
																	   const GlobalAccessHarvester &Harvester)
	{
		AnchorSites Result;
		for (const auto &[Key, Addresses] : Literals)
		{
			auto &Sites = Result[Key];
			for (const auto Address : Addresses)
				if (const AccessInfo *Info = Harvester.Find(Address))
					Sites.insert(Sites.end(), Info->Sites.begin(), Info->Sites.end());
			std::sort(Sites.begin(), Sites.end());
			Sites.erase(std::unique(Sites.begin(), Sites.end()), Sites.end());
		}
		return Result;
	}

	const std::vector<uint64_t> &AnchoredResolution::FindAnchorSites(const char *Text, EAnchorMatch Match) const
	{
		static const std::vector<uint64_t> Empty;
		const AnchorSites &Sites = SharedSites_ ? *SharedSites_ : LocalSites_;
		const auto found = Sites.find({Text ? Text : "", Match});
		return found == Sites.end() ? Empty : found->second;
	}

	bool AnchoredResolution::DeriveMember(uint64_t Container, const AccessMap &Local, uint64_t &OutMember, int64_t &OutOffset) const
	{
		// Candidate members are the addresses this function reaches just above the
		// container. Only offsets the binary actually uses are considered, so a fork
		// that reorders FUObjectArray still resolves.
		struct Cand
		{
			uint64_t Address;
			int64_t Offset;
			float Score;
		};
		std::vector<Cand> Cands;

		for (const auto &[Addr, Info] : Local)
		{
			// Header-sized window. The element table lives in FUObjectArray's header
			// in every shipped layout, including reordered forks, not out into the
			// trailing TArray members. Anything further out is a different object.
			if (Addr <= Container || Addr - Container > 0x40)
				continue;
			if (!IsWritableData(Module_, Addr))
				continue;

			// The member must be a base symbol, not an interior field of one. Code
			// names a struct base at displacement 0 somewhere - to pass it, store it,
			// or read its first field - while a field buried inside it is only ever
			// reached as base+N.
			//
			// This is the same rule that separates NamePoolData from its own interior
			// fields, and it is what reordered forks need: scoring alone tends to
			// pick the table, since that is where the pointer-width traffic goes,
			// so the base check has to run first.
			if (const AccessInfo *Whole = Harvester_.Find(Addr))
				if (!Whole->Offsets.empty() && Whole->Offsets.count(0) == 0)
					continue;

			const int64_t Off = static_cast<int64_t>(Addr - Container);
			float Score = 0.0f;

			// The array's own first field is a pointer table, so the member is read
			// at pointer width.
			if (Info.WideAccesses > 0)
				Score += 2.0f;
			// Counts (NumElements / MaxElements / chunk counts) are 32-bit and sit
			// just above the table pointer.
			if (Info.NarrowAccesses > 0)
				Score += 1.0f;
			// A chunk-size constant nearby is specific to the object array.
			if (Info.NearbyConstants.count(kNumElementsPerChunk_4_20) ||
				Info.NearbyConstants.count(kNumElementsPerChunk_4_21))
				Score += 3.0f;
			// Being reached by several distinct offsets means it is a struct base.
			Score += std::min<float>(static_cast<float>(Info.Offsets.size()), 3.0f) * 0.5f;
			// Prefer 8-byte alignment; UE members here are pointer-aligned.
			if ((Off % 8) == 0)
				Score += 0.5f;

			Cands.push_back({Addr, Off, Score});
		}

		if (Cands.empty())
			return false;

		std::sort(Cands.begin(), Cands.end(), [](const Cand &A, const Cand &B)
				  { return A.Score != B.Score ? A.Score > B.Score : A.Offset < B.Offset; });

		OutMember = Cands.front().Address;
		OutOffset = Cands.front().Offset;
		return true;
	}

	bool AnchoredResolution::DeriveThisOffset(const FunctionBounds &Fn, int64_t &OutOffset) const
	{
		// AAPCS64: `this` arrives in X0. Compilers routinely move it to a
		// callee-saved register at entry, so both are tracked and the offsets used
		// off either are collected.
		const uint32_t Stride = Arch_.InstructionStride();
		if (!Stride)
			return false;

		const int NumRegs = Arch_.RegisterCount();
		std::vector<bool> IsThis(static_cast<size_t>(NumRegs), false);
		if (NumRegs > 0)
			IsThis[0] = true;

		struct Cand
		{
			int64_t Offset;
			float Score;
		};
		std::unordered_map<int64_t, float> Scores;

		NormalizedInsn Insn;
		// Bounded to this one function, so the window need never exceed it.
		CodeWindow Code(Memory_, CodeWindow::ChunkForSpan(Fn.Size()));
		for (uint64_t At = Fn.Start; At < Fn.End; At += Stride)
		{
			const uint8_t *P = Code.At(At, Stride);
			if (!P)
				break;
			if (!Arch_.DecodeLocalBytes(P, Stride, At, Insn))
				continue;

			if (Insn.bClobbersAll)
			{
				std::fill(IsThis.begin(), IsThis.end(), false);
				continue;
			}

			const int Dest = (Insn.Dest >= 0 && Insn.Dest < NumRegs) ? Insn.Dest : -1;
			const int Src = (Insn.Base >= 0 && Insn.Base < NumRegs) ? Insn.Base : -1;

			switch (Insn.Kind)
			{
			case NormalizedInsn::EKind::Load:
			case NormalizedInsn::EKind::Store:
				if (Src >= 0 && IsThis[static_cast<size_t>(Src)])
				{
					// The object array's own first field is a pointer table, so the
					// member is read at pointer width; the counts around it are 32-bit.
					const float W = (Insn.AccessWidth == sizeof(uintptr_t)) ? 3.0f : 0.25f;
					Scores[Insn.Offset] += W;
				}
				// A load overwrites its destination, which is then no longer `this`.
				if (Insn.Kind == NormalizedInsn::EKind::Load && Dest >= 0)
					IsThis[static_cast<size_t>(Dest)] = false;
				if (Insn.bWritesBackBase && Src >= 0)
					IsThis[static_cast<size_t>(Src)] = false;
				break;

			case NormalizedInsn::EKind::MoveReg:
				// `this` is usually copied into a callee-saved register at entry, so
				// the marking has to follow the copy.
				if (Dest >= 0)
					IsThis[static_cast<size_t>(Dest)] =
						(Src >= 0 && IsThis[static_cast<size_t>(Src)]);
				break;

			case NormalizedInsn::EKind::Call:
				for (int R = 0; R < NumRegs; ++R)
					if (Arch_.CallClobbers(R))
						IsThis[static_cast<size_t>(R)] = false;
				break;

			default:
				if (Dest >= 0)
					IsThis[static_cast<size_t>(Dest)] = false;
				break;
			}
		}

		if (Scores.empty())
			return false;

		auto Best = std::max_element(Scores.begin(), Scores.end(), [](const auto &X, const auto &Y)
									 {
										 if (X.second != Y.second)
											 return X.second < Y.second;
										 return X.first > Y.first; // prefer the lower offset
									 });
		OutOffset = Best->first;
		return Best->second >= 3.0f; // require at least one pointer-width access
	}

	bool AnchoredResolution::ResolveViaCaller(const FunctionBounds &Fn, AnchorHit &Out, bool bSelfIsTarget) const
	{
		if (!Calls_)
			return false;

		// The detected start can sit a few instructions off the real entry, which is
		// enough to lose every caller. Snap to an address something actually calls.
		uint64_t Entry = Fn.Start;
		if (!Calls_->IsEntry(Entry))
			Calls_->SnapToEntry(Fn.Start, 0x40, Entry);

		const std::vector<uint64_t> *Callers = Calls_->CallersOf(Entry);
		if (!Callers || Callers->empty())
			return false;

		// Only when the target is a *member* of the recovered object. When the object
		// itself is the answer there is nothing to derive and requiring a derivable
		// member would reject the pool outright - FNamePool::FNamePool writes through
		// `this` without ever reading a field of it at a fixed offset.
		int64_t Offset = 0;
		if (!bSelfIsTarget && !DeriveThisOffset(Fn, Offset))
			return false;

		FunctionBoundary Boundary(Memory_, Module_, Arch_);

		// Several callers usually pass the same global; agreement is the check that
		// the recovered `this` is the engine singleton and not some other instance.
		std::unordered_map<uint64_t, int> Votes;
		for (uint64_t Call : *Callers)
		{
			const FunctionBounds CallerFn = Boundary.Find(Call);
			if (!CallerFn.IsValid())
				continue;
			uint64_t This = 0;
			if (!CallGraph::ResolveArgumentAtCall(Memory_, Module_, Arch_, CallerFn.Start, Call, /*X0=*/0, This))
				continue;
			if (!This || !IsWritableData(Module_, This))
				continue;
			++Votes[This];
		}

		if (Votes.empty())
			return false;

		auto Best = std::max_element(Votes.begin(), Votes.end(), [](const auto &X, const auto &Y)
									 {
			if (X.second != Y.second)
				return X.second < Y.second;
			return X.first > Y.first; });

		Out.Container = Best->first;
		Out.MemberOffset = Offset;
		Out.Result = Best->first + static_cast<uint64_t>(Offset);
		Out.bViaCaller = true;
		return IsWritableData(Module_, Out.Result);
	}

	bool AnchoredResolution::ResolveViaCalleeArgument(const IStrategy &Strategy, const FunctionBounds &Fn, AnchorHit &Out) const
	{
		if (Fn.End <= Fn.Start)
			return false;

		// Bounded to this one function, so the window need never exceed it.
		CodeWindow Code(Memory_, CodeWindow::ChunkForSpan(Fn.Size()));
		const uint32_t Stride = Arch_.InstructionStride();
		const size_t Total = static_cast<size_t>(Fn.Size());
		const StructureVerifier Verifier(Module_, Harvester_);

		// Several call sites usually pass the same singleton - FName::StaticInit
		// registers dozens of names through the same helper - so agreement across
		// sites is what separates the pool from an incidental argument.
		std::unordered_map<uint64_t, int> Votes;

		NormalizedInsn Insn;
		for (size_t Cursor = 0; Cursor + 4 <= Total;)
		{
			const uint64_t Addr = Fn.Start + Cursor;
			const size_t Want = Stride ? Stride : 4;
			const uint8_t *P = Code.At(Addr, Want);
			if (!P)
				break;
			const bool bOk = Arch_.DecodeLocalBytes(P, Want, Addr, Insn);
			Cursor += Stride ? Stride : (bOk && Insn.Length ? Insn.Length : 4);

			if (!bOk || Insn.Kind != NormalizedInsn::EKind::Call)
				continue;

			uint64_t Arg = 0;
			if (!CallGraph::ResolveArgumentAtCall(Memory_, Module_, Arch_, Fn.Start, Addr, /*X0=*/0, Arg))
				continue;
			// A stack local or scratch value fails this outright, which is what makes
			// the rule precise on the StaticInit shape.
			if (!Arg || !IsWritableData(Module_, Arg))
				continue;
			if (!Strategy.Verify(Verifier, Arg).Passed)
				continue;

			++Votes[Arg];
		}

		if (Votes.empty())
			return false;

		auto Best = std::max_element(Votes.begin(), Votes.end(), [](const auto &X, const auto &Y)
									 {
			if (X.second != Y.second)
				return X.second < Y.second;
			return X.first > Y.first; });

		// A tie between two different globals is not evidence; say nothing.
		int TopCount = 0;
		for (const auto &[Addr, N] : Votes)
			if (N == Best->second)
				++TopCount;
		if (TopCount != 1)
			return false;

		Out.Result = Best->first;
		Out.bViaCaller = false;
		return true;
	}

	FunctionBounds AnchoredResolution::BoundsFor(uint64_t Site) const
	{
		const auto It = BoundsCache_.find(Site);
		if (It != BoundsCache_.end())
			return It->second;

		FunctionBoundary Boundary(Memory_, Module_, Arch_);
		const FunctionBounds F = Boundary.Find(Site);
		BoundsCache_.emplace(Site, F);
		return F;
	}

	void AnchoredResolution::BuildAnchorCluster(const IStrategy &Strategy) const
	{
		AnchorsPerFunction_.clear();
		ClusterLeader_ = 0;
		ClusterLeaderCount_ = 0;
		ClusterRunnerUp_ = 0;

		// One anchor contributes at most once to a function, however many times it
		// is referenced there: what identifies a function is how many *different*
		// anchors agree on it, not how often one of them repeats.
		for (const Anchor &A : Strategy.ResolutionAnchors())
		{
			std::unordered_set<uint64_t> Seen;
			for (uint64_t Site : FindAnchorSites(A.Text, A.Match))
			{
				const FunctionBounds F = BoundsFor(Site);
				if (F.IsValid() && Seen.insert(F.Start).second)
					++AnchorsPerFunction_[F.Start];
			}
		}

		for (const auto &[Start, Count] : AnchorsPerFunction_)
		{
			if (Count > ClusterLeaderCount_)
			{
				ClusterRunnerUp_ = ClusterLeaderCount_;
				ClusterLeader_ = Start;
				ClusterLeaderCount_ = Count;
			}
			else if (Count > ClusterRunnerUp_)
			{
				ClusterRunnerUp_ = Count;
			}
		}
	}

	bool AnchoredResolution::IsClusterLeader(const FunctionBounds &Fn) const
	{
		// Enough anchors to be an identification rather than a coincidence, and a
		// clear margin over the next function: the true registrar carries most of
		// the reserved names, while a function that merely mentions one carries
		// only that one.
		//
		// The margin is a difference, not a ratio, because how many anchors can
		// match at all is a property of the binary rather than of the function. A
		// shipping build with FName's diagnostics compiled out leaves only a
		// handful of usable anchors, and a ratio then demands a lead the binary
		// cannot supply - a registrar carrying every anchor there is fails against
		// a helper that merely mentions three. A difference asks the same question
		// at every anchor count, and is the stricter of the two where the risk
		// actually lies, against a runner-up of one.
		constexpr int kMinAnchors = 4;
		constexpr int kMargin = 2;

		return Fn.IsValid() && Fn.Start == ClusterLeader_ && ClusterLeaderCount_ >= kMinAnchors &&
			   ClusterLeaderCount_ >= ClusterRunnerUp_ + kMargin;
	}

	bool AnchoredResolution::ResolveViaAllocatedTable(const IStrategy &Strategy, const FunctionBounds &Fn, AnchorHit &Out) const
	{
		const uint32_t Stride = Arch_.InstructionStride();
		if (!Stride || Fn.End <= Fn.Start)
			return false;

		const int NumRegs = Arch_.RegisterCount();
		if (NumRegs <= 0)
			return false;

		// Addresses materialized into registers, so a store's destination can be
		// named; the last scalar immediate seen, which is the allocation size at the
		// call that returns the block; and which global each loaded register holds.
		std::vector<uint64_t> Bases(static_cast<size_t>(NumRegs), 0);
		std::vector<uint64_t> Immediates(static_cast<size_t>(NumRegs), 0);
		std::vector<bool> ImmediateKnown(static_cast<size_t>(NumRegs), false);
		std::vector<uint64_t> HoldsGlobal(static_cast<size_t>(NumRegs), 0);
		std::vector<uint64_t> FromAllocation(static_cast<size_t>(NumRegs), 0);

		// How far into the global a register has already been advanced. The counts
		// are not always reached by a displacement on the load: when they are touched
		// atomically the compiler hoists the pointer, and the offset moves into an
		// earlier ADD.
		std::vector<int64_t> Displacement(static_cast<size_t>(NumRegs), 0);

		std::unordered_map<uint64_t, uint64_t> AllocatedSize;
		std::unordered_map<uint64_t, std::unordered_set<int64_t>> DerefOffsets;

		// A chunk table plus its two counts. Below this is a lock or a small record;
		// above it is implausibly large for a name table.
		constexpr uint64_t kMinTableAllocation = 0x100;
		constexpr uint64_t kMaxTableAllocation = 0x100000;

		NormalizedInsn Insn;
		// Bounded to this one function, so the window need never exceed it.
		CodeWindow Code(Memory_, CodeWindow::ChunkForSpan(Fn.Size()));
		for (uint64_t At = Fn.Start; At < Fn.End; At += Stride)
		{
			const uint8_t *P = Code.At(At, Stride);
			if (!P)
				break;
			if (!Arch_.DecodeLocalBytes(P, Stride, At, Insn))
				continue;

			if (Insn.bClobbersAll)
			{
				std::fill(Bases.begin(), Bases.end(), 0);
				std::fill(Immediates.begin(), Immediates.end(), 0);
				std::fill(ImmediateKnown.begin(), ImmediateKnown.end(), false);
				std::fill(HoldsGlobal.begin(), HoldsGlobal.end(), 0);
				std::fill(FromAllocation.begin(), FromAllocation.end(), 0);
				std::fill(Displacement.begin(), Displacement.end(), 0);
				continue;
			}

			const int D = Insn.Dest;
			const int B = Insn.Base;
			if (Insn.Kind == NormalizedInsn::EKind::Return)
				break;
			if (D >= 0 && D < NumRegs && Insn.Kind != NormalizedInsn::EKind::MoveImm &&
				Insn.Kind != NormalizedInsn::EKind::MoveReg && Insn.Kind != NormalizedInsn::EKind::Store)
			{
				Immediates[D] = 0;
				ImmediateKnown[D] = false;
			}

			switch (Insn.Kind)
			{
			case NormalizedInsn::EKind::SetBase:
				if (D >= 0 && D < NumRegs)
				{
					Bases[D] = Insn.Value;
					HoldsGlobal[D] = 0;
					Displacement[D] = 0;
					FromAllocation[D] = 0;
				}
				break;

			case NormalizedInsn::EKind::AddImm:
				if (D >= 0 && D < NumRegs)
				{
					const bool sourceValid = B >= 0 && B < NumRegs;
					const uint64_t base = sourceValid ? Bases[B] : 0;
					const uint64_t global = sourceValid ? HoldsGlobal[B] : 0;
					const int64_t displacement = sourceValid ? Displacement[B] : 0;
					Bases[D] = HoldsGlobal[D] = FromAllocation[D] = 0;
					Displacement[D] = 0;
					if (base)
					{
						Bases[D] = Utils::Memory::WrapAddress(base + Insn.Value);
					}
					else if (global)
					{
						// 先保存源状态以支持 D == B，未知源则必须清空旧目标值。
						if (AddDisplacement(displacement, std::bit_cast<int64_t>(Insn.Value), Displacement[D]))
							HoldsGlobal[D] = global;
					}
				}
				break;

			case NormalizedInsn::EKind::LoadLiteral:
			{
				// A literal-pool word carrying a displacement, which the following
				// add completes into an address. Without it the register is cleared
				// before the add can use it, and every global a target reaches
				// through that idiom becomes invisible to this rule - which on a
				// position-independent build is most of them.
				uint64_t Word = 0;
				if (D >= 0 && D < NumRegs)
				{
					const bool bRead = ReadLiteralValue(Memory_, Insn, Word);
					Bases[D] = bRead ? static_cast<uint64_t>(Word) : 0;
					HoldsGlobal[D] = 0;
					Displacement[D] = 0;
					FromAllocation[D] = 0;
					Immediates[D] = 0;
				}
				break;
			}

			case NormalizedInsn::EKind::MoveImm:
				if (D >= 0 && D < NumRegs)
				{
					const bool known = !Insn.bComposes || ImmediateKnown[D];
					Immediates[D] = !known ? 0 : Insn.bComposes ? ((Immediates[D] & ~Insn.ValueMask) | Insn.Value)
																: Insn.Value;
					ImmediateKnown[D] = known;
					Bases[D] = 0;
					if (known && Insn.bAddressLike && Module_.FindAddressRegion(Utils::Memory::WrapAddress(Immediates[D])))
						Bases[D] = Utils::Memory::WrapAddress(Immediates[D]);
					HoldsGlobal[D] = 0;
					Displacement[D] = 0;
					FromAllocation[D] = 0;
				}
				break;

			case NormalizedInsn::EKind::Call:
			{
				// The size is read from the argument register at the call, not from
				// the last immediate seen anywhere: the mutex beside the table is
				// allocated too, and a sticky value would credit its store with a
				// size that belongs to something else.
				const uint64_t Requested = Immediates[0];
				const bool bPlausible = ImmediateKnown[0] && Requested >= kMinTableAllocation && Requested <= kMaxTableAllocation;

				// Only caller-saved registers are clobbered. The table is routinely
				// parked in a callee-saved register across the memset that follows
				// the allocation, and forgetting that loses the store entirely.
				for (int R = 0; R < NumRegs; ++R)
				{
					if (!Arch_.CallClobbers(R))
						continue;
					FromAllocation[R] = 0;
					Immediates[R] = 0;
					ImmediateKnown[R] = false;
					HoldsGlobal[R] = 0;
					Displacement[R] = 0;
					Bases[R] = 0;
				}
				if (bPlausible)
					FromAllocation[0] = Requested;
				break;
			}

			case NormalizedInsn::EKind::MoveReg:
				if (D >= 0 && D < NumRegs && B >= 0 && B < NumRegs)
				{
					FromAllocation[D] = FromAllocation[B];
					HoldsGlobal[D] = HoldsGlobal[B];
					Displacement[D] = Displacement[B];
					Bases[D] = Bases[B];
					Immediates[D] = Immediates[B];
					ImmediateKnown[D] = ImmediateKnown[B];
				}
				else if (D >= 0 && D < NumRegs)
				{
					Bases[D] = HoldsGlobal[D] = FromAllocation[D] = Immediates[D] = 0;
					ImmediateKnown[D] = false;
					Displacement[D] = 0;
				}
				break;

			case NormalizedInsn::EKind::Store:
				// Storing an allocated block into a global records the size, which is
				// the half of the correspondence the counts are read against.
				//
				// The register keeps holding that global's value afterwards, and the
				// counts are read straight through it rather than through a reload -
				// the compiler has the pointer in hand, so it does not fetch it back.
				if (B >= 0 && B < NumRegs && Bases[B] && D >= 0 && D < NumRegs && FromAllocation[D] &&
					Insn.AccessWidth == sizeof(uintptr_t))
				{
					const uint64_t Global = Utils::Memory::WrapAddress(Bases[B] + static_cast<uint64_t>(Insn.Offset));
					AllocatedSize[Global] = FromAllocation[D];
					HoldsGlobal[D] = Global;
					Displacement[D] = 0;
				}
				// A write through a register loaded from a global counts as a
				// dereference of it, the same way a read does.
				if (B >= 0 && B < NumRegs && HoldsGlobal[B])
				{
					int64_t offset = 0;
					if (AddDisplacement(Displacement[B], Insn.Offset, offset))
						DerefOffsets[HoldsGlobal[B]].insert(offset);
				}
				break;

			case NormalizedInsn::EKind::Load:
				if (B >= 0 && B < NumRegs && HoldsGlobal[B])
				{
					int64_t offset = 0;
					if (AddDisplacement(Displacement[B], Insn.Offset, offset))
						DerefOffsets[HoldsGlobal[B]].insert(offset);
				}

				if (D >= 0 && D < NumRegs)
				{
					// Loading a global's contents makes the destination that global's
					// value, which is what later dereferences are measured against.
					const uint64_t Global = (B >= 0 && B < NumRegs && Bases[B] && Insn.AccessWidth == sizeof(uintptr_t))
												? Utils::Memory::WrapAddress(Bases[B] + static_cast<uint64_t>(Insn.Offset))
												: 0;
					HoldsGlobal[D] = Global;
					Displacement[D] = 0;
					FromAllocation[D] = 0;
					Bases[D] = 0;
					Immediates[D] = 0;
				}
				break;

			default:
				if (D >= 0 && D < NumRegs)
				{
					Bases[D] = 0;
					HoldsGlobal[D] = 0;
					Displacement[D] = 0;
					FromAllocation[D] = 0;
					Immediates[D] = 0;
				}
				break;
			}
			if (Insn.bWritesBackBase && B >= 0 && B < NumRegs)
			{
				Bases[B] = HoldsGlobal[B] = FromAllocation[B] = Immediates[B] = 0;
				ImmediateKnown[B] = false;
				Displacement[B] = 0;
			}
		}

		// The counts sit at the end of the allocation, so a table read at Size-8 is
		// the structure identifying itself. Anything else the function stored - a
		// mutex, a flag - has no such correspondence.
		const StructureVerifier Verifier(Module_, Harvester_);
		uint64_t Match = 0;
		int Matches = 0;

		for (const auto &[Global, Size] : AllocatedSize)
		{
			if (Size < 16)
				continue;
			const auto It = DerefOffsets.find(Global);
			if (It == DerefOffsets.end())
				continue;
			if (It->second.count(static_cast<int64_t>(Size) - 8) == 0)
				continue;
			if (!IsWritableData(Module_, Global) || !Strategy.Verify(Verifier, Global).Passed)
				continue;

			Match = Global;
			++Matches;
		}

		if (Matches != 1)
			return false;

		Out.Result = Match;
		return true;
	}

	bool AnchoredResolution::Apply(const IStrategy &Strategy, const Anchor &A, uint64_t Site, AnchorHit &Out) const
	{
		const FunctionBounds Fn = BoundsFor(Site);
		if (!Fn.IsValid())
			return false;

		Out.Function = Fn;

		// Handled before the function's own globals are collected, because it does
		// not use them: the answer comes from what the *callers* pass in. Gating it
		// on this function touching a global would reject exactly the shape it
		// exists for - a constructor that touches, stores and passes nothing of
		// its own, where every other rule fails.
		if (A.Rule == EPickRule::CallerArgSelf)
		{
			// Verified before it is accepted, so a caller that happens to hand over
			// some unrelated global cannot win on vote count alone.
			if (ResolveViaCaller(Fn, Out, /*bSelfIsTarget=*/true))
			{
				const StructureVerifier Verifier(Module_, Harvester_);
				if (Strategy.Verify(Verifier, Out.Result).Passed)
					return true;
			}

			// The rule assumes a constructor that receives the table. A legacy build
			// may instead allocate and store it itself, so no caller passes anything
			// and there is nothing to read; the rules below can still reach it. They
			// are only sound on the function the anchors actually identify, though -
			// unguarded, a reserved-name literal resolves correctly once out of the
			// real registrar and wrongly out of every small function that merely
			// mentions it. Only the rule written for this shape is used here, never
			// the generic ones, to avoid exactly that.
			if (!IsClusterLeader(Fn))
				return false;

			if (!ResolveViaAllocatedTable(Strategy, Fn, Out))
				return false;

			const StructureVerifier CallerVerifier(Module_, Harvester_);
			if (!Strategy.Verify(CallerVerifier, Out.Result).Passed)
				return false;

			Out.bReconstructedLayout = true;
			return true;
		}

		const AccessMap Local = Harvester_.ScanFunction(Memory_, Fn.Start, Fn.End);
		if (Local.empty())
			return false;

		// Only writable data can be an engine global.
		std::vector<std::pair<uint64_t, const AccessInfo *>> Globals;
		for (const auto &[Addr, Info] : Local)
			if (IsWritableData(Module_, Addr))
				Globals.emplace_back(Addr, &Info);
		if (Globals.empty())
			return false;

		switch (A.Rule)
		{
		case EPickRule::ContainerMember:
		case EPickRule::Container:
		{
			// Both rules find the same pair and differ only in which half they
			// report, so the discovery below is shared rather than duplicated.
			const bool bWantContainer = (A.Rule == EPickRule::Container);

			// The anchored function is often a *member* function that reaches the
			// global through `this` and never names it. That case is both the most
			// precise and invisible to a purely local scan, so it is tried first.
			if (ResolveViaCaller(Fn, Out))
			{
				if (bWantContainer)
				{
					// The recovered `this` is the container itself.
					Out.Result = Out.Container;
					return IsWritableData(Module_, Out.Result);
				}
				return true;
			}

			// Otherwise the container is an address this function *names*, and the
			// target is a member read from it at a derived offset. Naming covers both
			// computing the address (ADRP+ADD) and reading it out of a relocated
			// pointer slot: requiring AddressTaken alone misses every build that
			// reaches GUObjectArray indirectly, since the container never becomes a
			// candidate and the anchor silently contributes nothing.
			std::vector<uint64_t> Containers;
			for (const auto &[Addr, Info] : Globals)
				if (Info->HasKind(EAccessKind::AddressTaken) ||
					Info->HasKind(EAccessKind::IndirectBase))
					Containers.push_back(Addr);

			std::sort(Containers.begin(), Containers.end());
			for (uint64_t C : Containers)
			{
				uint64_t Member = 0;
				int64_t Off = -1;
				if (DeriveMember(C, Local, Member, Off))
				{
					Out.Container = C;
					Out.MemberOffset = Off;
					// The member still has to be found either way: a global holding no
					// array is not the array's container, so the derivation is what
					// makes the container an answer rather than a guess.
					Out.Result = bWantContainer ? C : Member;
					return true;
				}
			}

			// Deliberately no fallback: if the container and offset cannot both be
			// recovered, this anchor contributes nothing rather than guessing at the
			// first address-taken global, which would emit unrelated globals with
			// unwarranted confidence.
			return false;
		}

		case EPickRule::SingleWritable:
			if (Globals.size() != 1)
				return false;
			Out.Result = Globals.front().first;
			return true;

		case EPickRule::CalleeArgument:
		case EPickRule::SingleVerified:
		default:
		{
			// CalleeArgument is tried first and falls through to SingleVerified when
			// the function makes no qualifying call, so adopting it can only add
			// resolutions, never remove them.
			if (A.Rule == EPickRule::CalleeArgument && ResolveViaCalleeArgument(Strategy, Fn, Out))
				return true;

			// "The most touched global in the function" is a guess, not a rule. A
			// candidate is only produced when exactly one global in the function
			// survives structure verification, so the choice is made by evidence
			// rather than by frequency.
			const StructureVerifier Verifier(Module_, Harvester_);
			uint64_t Only = 0;
			int Passed = 0;
			uint64_t WithCorroboration = 0;
			int CorroboratedCount = 0;

			for (const auto &[Addr, Info] : Globals)
			{
				(void)Info;
				const StructureEvidence Ev = Strategy.Verify(Verifier, Addr);
				if (!Ev.Passed)
					continue;
				Only = Addr;
				++Passed;
				if (Ev.bHasSecondaryField)
				{
					WithCorroboration = Addr;
					++CorroboratedCount;
				}
			}
			if (Passed == 1)
			{
				Out.Result = Only;
				return true;
			}

			// Multiple survivors: break the tie only on corroborating evidence
			// beyond the shape's minimum (StructureEvidence::bHasSecondaryField),
			// and only when exactly one candidate has it - that is a decisive
			// structural difference, not a preference. Which structure that extra
			// field is is the strategy's business, not this dispatcher's; anything
			// less clear still returns nothing rather than guessing.
			if (Passed > 1 && CorroboratedCount == 1)
			{
				Out.Result = WithCorroboration;
				return true;
			}

			// The legacy shape - a StaticInit-style function that allocates the
			// table and stores it, so nothing passes it in or out - still needs a
			// rule that separates the table from other globals it stores alongside
			// it (a mutex, a flag). Frequency of dereference alone is not reliable
			// enough to decide that, so no candidate is produced here for this case.
			return false;
		}
		}
	}

	std::vector<Candidate> AnchoredResolution::Resolve(const IStrategy &Strategy,
													   const ScoringWeights &Weights) const
	{
		(void)Weights;
		Hits_.clear();
		Traces_.clear();
		BoundsCache_.clear();
		if (!SharedSites_)
		{
			std::vector<const Anchor *> Anchors;
			for (const Anchor &A : Strategy.ResolutionAnchors())
				Anchors.push_back(&A);
			LocalSites_ = ScanAnchorSites(Memory_, Module_, Harvester_, Anchors);
		}
		BuildAnchorCluster(Strategy);

		// address -> (accumulated trust, contributing anchors)
		std::unordered_map<uint64_t, float> Votes;
		std::unordered_map<uint64_t, std::vector<const AnchorHit *>> Support;

		// The strategy owns its anchors; strongest trust first, so a high-trust
		// resolution is seen before the weaker ones that might corroborate it.
		std::vector<const Anchor *> Ordered;
		for (const Anchor &A : Strategy.ResolutionAnchors())
			Ordered.push_back(&A);
		std::sort(Ordered.begin(), Ordered.end(), [](const Anchor *X, const Anchor *Y)
				  { return X->Trust > Y->Trust; });

		for (const Anchor *A : Ordered)
		{
			AnchorTrace Trace;
			Trace.Which = A;

			const auto &Sites = FindAnchorSites(A->Text, A->Match);
			Trace.Sites = Sites.size();

			// A literal referenced from hundreds of places is not identifying a single
			// function; skip rather than guess which one is meant. The count that
			// matters is *distinct functions*, though, not raw sites: a loop that
			// formats many names from one function is still one identification, so
			// capping on site count alone would discard it wrongly.
			std::vector<uint64_t> Kept;
			if (Sites.empty())
			{
				Trace.Skip = "string not referenced by code";
			}
			else
			{
				std::unordered_set<uint64_t> Functions;
				for (uint64_t Site : Sites)
				{
					const FunctionBounds F = BoundsFor(Site);
					if (!F.IsValid())
						continue;
					if (Functions.insert(F.Start).second)
						Kept.push_back(Site);
				}
				if (Functions.empty())
					Trace.Skip = "no resolvable function around any reference";
				// Generous: every candidate site still has to yield a verified global
				// through a call argument, and agreement across sites is what decides,
				// so more functions costs time rather than precision.
				else if (Functions.size() > 48)
					Trace.Skip = "too many distinct functions to identify one";
			}

			if (!Trace.Skip)
			{
				for (uint64_t Site : Kept)
				{
					AnchorHit Hit;
					Hit.Which = A;
					Hit.SiteAddress = Site;
					if (!Apply(Strategy, *A, Site, Hit) || !Hit.Result)
					{
						++Trace.NoPick;
						continue;
					}

					// Nothing is emitted unless it is *used* like the structure we are
					// looking for. This is the gate whose absence produced confident
					// wrong answers.
					const StructureVerifier Verifier(Module_, Harvester_);
					const StructureEvidence Ev = Strategy.Verify(Verifier, Hit.Result);
					if (!Ev.Passed)
					{
						Trace.Rejected++;
						if (Trace.RejectedDetail.size() < 5)
							Trace.RejectedDetail.emplace_back(Hit.Result, Ev.Why);
						continue;
					}
					Hit.Evidence = Ev.Why;
					++Trace.Applied;
					Hits_.push_back(Hit);
				}
				if (!Trace.Applied)
					Trace.Skip = Trace.Rejected ? "candidates failed structure verification"
												: "no rule could pick a global from the function";
			}
			Traces_.push_back(Trace);
		}

		// A reserved-name cluster anchor (grouping FName::StaticInit by how many
		// reserved names a function references) remains unimplemented. It reliably
		// identifies the right function, but not the right global within it: a
		// legacy TNameEntryArray build stores an interior field a fixed distance
		// from the true base, and nothing about function-level clustering
		// distinguishes the two. That needs a way to choose between adjacent
		// fields, which does not exist yet.

		// One anchor votes once, however many sites reference it: several call
		// sites of the same helper are one piece of evidence, not several, and
		// counting them separately lets a weak anchor outvote a precise one.
		// Independent evidence is a *connected component*, not an anchor and not a
		// function.
		//
		// Two hits are the same evidence if they share an anchor string or share
		// the function they resolved through - collapsing only one of those
		// direction undercounts shared code in the other. So hits are unioned over
		// both, and each component contributes the best single weight in it.
		std::unordered_map<uint64_t, std::vector<const AnchorHit *>> ByAddress;
		for (const AnchorHit &H : Hits_)
		{
			ByAddress[H.Result].push_back(&H);
			Support[H.Result].push_back(&H);
		}

		std::unordered_map<uint64_t, size_t> PathCount;
		for (const auto &[Address, Group] : ByAddress)
		{
			const size_t N = Group.size();

			std::vector<size_t> Parent(N);
			for (size_t i = 0; i < N; ++i)
				Parent[i] = i;
			const auto Find = [&Parent](size_t X)
			{
				while (Parent[X] != X)
					X = Parent[X] = Parent[Parent[X]];
				return X;
			};
			for (size_t i = 0; i < N; ++i)
				for (size_t j = i + 1; j < N; ++j)
					if (Group[i]->Which == Group[j]->Which ||
						Group[i]->Function.Start == Group[j]->Function.Start)
						Parent[Find(i)] = Find(j);

			std::unordered_map<size_t, float> Best;
			for (size_t i = 0; i < N; ++i)
			{
				float Weight = Group[i]->Which->Trust;

				// A resolution that recovered `this` from the callers and derived the
				// member offset from how the function uses it is far stronger than
				// picking the most-touched global out of a GC helper: it identifies
				// the container exactly and reconstructs the member rather than
				// guessing.
				if (Group[i]->bViaCaller && Group[i]->MemberOffset >= 0)
					Weight += 4.0f;

				// Same reasoning, and the same class of evidence: the allocation size
				// and the offset its counts are read at agree, which reconstructs the
				// structure rather than choosing among the globals a function touches.
				// A single anchored function otherwise caps at 0.412 and cannot clear
				// the confidence gate however sound the identification is.
				if (Group[i]->bReconstructedLayout)
					Weight += 1.0f;

				float &Slot = Best[Find(i)];
				Slot = std::max(Slot, Weight);
			}

			// Each component contributes its best single weight, never a sum: summing
			// distinct anchors that corroborate through one shared function would
			// let weak, unreliable evidence accumulate past the confidence gate.
			float Total = 0.0f;
			for (const auto &[Root, W] : Best)
			{
				(void)Root;
				Total += W;
			}
			Votes[Address] = Total;
			PathCount[Address] = Best.size();
		}

		std::vector<Candidate> Out;
		Out.reserve(Votes.size());
		for (const auto &[Address, Trust] : Votes)
		{
			Candidate C(Address, 0.0f, "Anchored");
			C.FindMethod = EFindMethod::Anchored;
			char Buf[192];

			const auto &Hs = Support[Address];
			// Agreement between *independent* paths is the strongest evidence
			// available statically, so it is what drives confidence. Anchors that
			// proved the same address through the same function are one path.
			const size_t Paths = PathCount[Address];
			std::snprintf(Buf, sizeof(Buf), "%zu independent path%s (%zu anchor hit%s)", Paths, Paths == 1 ? "" : "s", Hs.size(), Hs.size() == 1 ? "" : "s");
			C.Add("anchor_agreement", 0.0f, Buf);

			for (const AnchorHit *H : Hs)
			{
				std::snprintf(Buf, sizeof(Buf), "\"%s\" in %s @0x%llX", H->Which->Text, H->Which->Function, (unsigned long long)H->Function.Start);
				C.Add("anchor", H->Which->Trust, Buf);
				if (H->MemberOffset >= 0)
				{
					std::snprintf(Buf, sizeof(Buf), "container 0x%llX + 0x%llX (derived)", (unsigned long long)H->Container, (unsigned long long)H->MemberOffset);
					C.Add("container_member", 0.0f, Buf);
				}
			}

			// Trust sums are unbounded; squash so several weak anchors cannot
			// outrank one strong one plus corroboration.
			const float Agreement = 1.0f - 1.0f / (1.0f + Trust);
			C.Confidence = std::clamp(Agreement, 0.0f, 1.0f);
			Out.push_back(std::move(C));
		}

		Scoring::SortByConfidence(Out);
		return Out;
	}

} // namespace nextdumper::analyzer
