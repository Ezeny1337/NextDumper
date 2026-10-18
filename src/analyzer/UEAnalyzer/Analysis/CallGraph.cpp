#include "CallGraph.h"

#include <vector>

#include "../../Architecture/IArchDecoder.h"
#include "../../Memory/IMemory.h"
#include "../../Utils/Utils.h"

#include "CodeWindow.h"

namespace nextdumper::analyzer
{

	void CallGraph::Build(IMemory *Memory, const IArchDecoder &Arch)
	{
		Clear();

		const uint32_t Stride = Arch.InstructionStride();
		if (Stride == 0)
			return;

		const ModuleInfo Module = Memory->GetUnrealModule();
		CodeWindow Code(Memory);

		NormalizedInsn Insn;
		for (const auto &Seg : Module.GetSegments())
		{
			if (!Seg.IsExecutable() || Seg.GetSize() == 0)
				continue;

			const uint64_t Start = Seg.GetStart() & ~static_cast<uint64_t>(Stride - 1);
			const uint64_t End = Seg.GetEnd();

			for (uint64_t At = Start; At + Stride <= End; At += Stride)
			{
				// nullptr means the readable bytes ran out - the end of this segment's
				// real content - so move to the next segment rather than decode noise.
				const uint8_t *P = Code.At(At, Stride);
				if (!P)
					break;
				if (!Arch.DecodeLocalBytes(P, Stride, At, Insn))
					continue;
				if (Insn.Kind != NormalizedInsn::EKind::Call || Insn.Value == 0)
					continue;
				// Only direct calls landing inside the image are useful.
				if (!Module.FindAddressRegion(Insn.Value))
					continue;
				AddEdge(Insn.Value, At);
			}
		}
	}

	bool CallGraph::SnapToEntry(uint64_t Address, uint64_t Window, uint64_t &OutEntry) const
	{
		// Entries are sparse, so walking down instruction by instruction is cheaper
		// than maintaining a sorted index.
		for (uint64_t At = Address; At + Window >= Address; At -= 4)
		{
			if (Callers_.count(At))
			{
				OutEntry = At;
				return true;
			}
			if (At < 4 || Address - At >= Window)
				break;
		}
		return false;
	}

	const std::vector<uint64_t> *CallGraph::CallersOf(uint64_t Callee) const
	{
		auto It = Callers_.find(Callee);
		return It == Callers_.end() ? nullptr : &It->second;
	}

	bool CallGraph::ResolveArgumentAtCall(const IMemory *Memory, const ModuleInfo &Module, const IArchDecoder &Arch, uint64_t CallerStart, uint64_t CallSite, int ArgReg, uint64_t &OutValue)
	{
		const uint32_t Stride = Arch.InstructionStride();
		if (Stride == 0 || CallSite < CallerStart)
			return false;

		const int NumRegs = Arch.RegisterCount();
		if (ArgReg < 0 || ArgReg >= NumRegs)
			return false;

		struct Reg
		{
			uint64_t Value = 0;
			bool bKnown = false;
		};
		std::vector<Reg> Regs(static_cast<size_t>(NumRegs));

		NormalizedInsn Insn;
		// Walks from the caller's entry to the call site and stops; the sweep in
		// Build is the one that wants a full chunk.
		CodeWindow Code(Memory, CodeWindow::ChunkForSpan(CallSite - CallerStart));
		for (uint64_t At = CallerStart; At < CallSite; At += Stride)
		{
			const uint8_t *P = Code.At(At, Stride);
			if (!P)
				return false;
			if (!Arch.DecodeLocalBytes(P, Stride, At, Insn))
				continue;

			if (Insn.bClobbersAll)
			{
				for (auto &Reg : Regs)
					Reg.bKnown = false;
				continue;
			}

			const int Dest = (Insn.Dest >= 0 && Insn.Dest < NumRegs) ? Insn.Dest : -1;
			const int Src = (Insn.Base >= 0 && Insn.Base < NumRegs) ? Insn.Base : -1;

			switch (Insn.Kind)
			{
			case NormalizedInsn::EKind::SetBase:
				if (Dest >= 0)
				{
					Regs[Dest].Value = Insn.Value;
					Regs[Dest].bKnown = true;
				}
				break;

			case NormalizedInsn::EKind::AddImm:
				if (Dest >= 0)
				{
					if (Src >= 0 && Regs[Src].bKnown)
					{
						Regs[Dest].Value = Utils::Memory::WrapAddress(Regs[Src].Value + Insn.Value);
						Regs[Dest].bKnown = true;
					}
					else
					{
						Regs[Dest].bKnown = false;
					}
				}
				break;

			case NormalizedInsn::EKind::Load:
			{
				// A load through a known base may be a pointer slot; follow it, since
				// `this` is often fetched from the GOT rather than formed inline.
				bool bResolved = false;
				if (Dest >= 0 && Src >= 0 && Regs[Src].bKnown &&
					Insn.AccessWidth == sizeof(uintptr_t))
				{
					// uintptr_t, not uint64_t: this is the memory interface's own
					// address type, and the two differ in the 32-bit build.
					uintptr_t Pointee = 0;
					const uint64_t Slot = Utils::Memory::WrapAddress(Regs[Src].Value + static_cast<uint64_t>(Insn.Offset));
					if (Memory->ReadRelocationPointer(static_cast<uintptr_t>(Slot), Pointee) && Pointee &&
						Module.FindAddressRegion(Pointee) != nullptr)
					{
						Regs[Dest].Value = static_cast<uint64_t>(Pointee);
						Regs[Dest].bKnown = true;
						bResolved = true;
					}
				}
				if (Dest >= 0 && !bResolved)
					Regs[Dest].bKnown = false;
				if (Insn.bWritesBackBase && Src >= 0)
					Regs[Src].bKnown = false;
				break;
			}

			case NormalizedInsn::EKind::MoveReg:
				if (Dest >= 0)
				{
					if (Src >= 0 && Regs[Src].bKnown)
					{
						Regs[Dest].Value = Regs[Src].Value;
						Regs[Dest].bKnown = true;
					}
					else
					{
						Regs[Dest].bKnown = false;
					}
				}
				break;

			case NormalizedInsn::EKind::Call:
				// A nested call clobbers the argument registers, so anything set
				// before it cannot be the argument to *this* call.
				for (int R = 0; R < NumRegs; ++R)
					if (Arch.CallClobbers(R))
						Regs[static_cast<size_t>(R)].bKnown = false;
				break;

			case NormalizedInsn::EKind::Return:
				// Ran past the end of the caller; the boundary was wrong.
				return false;

			default:
				if (Dest >= 0)
					Regs[Dest].bKnown = false;
				break;
			}
		}

		if (!Regs[static_cast<size_t>(ArgReg)].bKnown)
			return false;
		OutValue = Regs[static_cast<size_t>(ArgReg)].Value;
		return true;
	}

} // namespace nextdumper::analyzer
