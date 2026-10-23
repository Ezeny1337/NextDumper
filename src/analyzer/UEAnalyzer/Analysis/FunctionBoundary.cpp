#include "FunctionBoundary.h"

#include "../../Architecture/IArchDecoder.h"
#include "../../Memory/IMemory.h"

#include "CodeWindow.h"
#include "EhFrameIndex.h"

namespace nextdumper::analyzer
{

	FunctionBounds FunctionBoundary::Find(uint64_t Address, uint32_t MaxScan) const
	{
		FunctionBounds Out;

		const MemRegionInfo *Seg = Module_.FindAddressRegion(Address);
		if (!Seg || !Seg->IsExecutable())
			return Out;

		// The unwind table is compiler output, not a heuristic: prefer it whenever
		// this address has an entry, independent of the instruction set.
		if (EhFrame_ && EhFrame_->Find(Address, Out))
			return Out;

		const uint32_t Stride = Arch_.InstructionStride();
		if (Stride == 0)
			return Out; // variable-width targets need a different walk

		// The scan runs to the region's end; CodeWindow stops it earlier if the bytes
		// are not actually readable, which is what bounds it at the end of file-backed
		// content without needing a file-only notion of size.
		const uint64_t Lo = Seg->GetStart();
		const uint64_t Hi = Seg->GetEnd();
		Address &= ~static_cast<uint64_t>(Stride - 1);
		if (Address < Lo || Address >= Hi)
			return Out;

		NormalizedInsn Insn;
		// The scan reaches MaxScan in each direction and no further, so a window
		// covering both is the most this walk can ever use.
		CodeWindow Code(Memory_, CodeWindow::ChunkForSpan(uint64_t(MaxScan) * 2));
		auto DecodeAt = [&](uint64_t At) -> bool
		{
			if (At + Stride > Hi)
				return false;
			const uint8_t *P = Code.At(At, Stride);
			if (!P)
				return false;
			// Avail describes the *buffer*, not the segment: the window guarantees
			// Stride bytes, and promising more would invite a read past its end.
			return Arch_.DecodeLocalBytes(P, Stride, At, Insn);
		};

		// Backwards: the nearer of "previous function's return" and "this function's
		// frame setup" is the start.
		for (uint64_t At = Address; At >= Lo; At -= Stride)
		{
			if (DecodeAt(At))
			{
				if (Insn.Kind == NormalizedInsn::EKind::Return)
				{
					// The return belongs to the previous function.
					Out.Start = At + Stride;
					break;
				}
				if (Insn.Kind == NormalizedInsn::EKind::Prologue)
				{
					Out.Start = At;
					break;
				}
			}
			if (At < Lo + Stride || (Address - At) >= MaxScan)
				break;
		}

		if (Out.Start == 0 || Out.Start > Address)
			return {};

		// Forwards: the first return ends the function.
		for (uint64_t At = Address; At + Stride <= Hi; At += Stride)
		{
			if (DecodeAt(At) && Insn.Kind == NormalizedInsn::EKind::Return)
			{
				Out.End = At + Stride;
				break;
			}
			if ((At - Address) >= MaxScan)
				break;
		}

		if (Out.End <= Out.Start)
			return {};

		return Out;
	}

} // namespace nextdumper::analyzer
