#pragma once

#include <cstdint>

#include "../../Memory/IMemory.h"

class IArchDecoder;

namespace nextdumper::analyzer
{

	class EhFrameIndex;

	/**
	 * @brief Half-open address range of one recovered function.
	 */
	struct FunctionBounds
	{
		uint64_t Start = 0; ///< Function entry.
		uint64_t End = 0;	///< Exclusive.

		bool IsValid() const { return Start != 0 && End > Start; }
		uint64_t Size() const { return IsValid() ? End - Start : 0; }
		bool Contains(uint64_t A) const { return IsValid() && A >= Start && A < End; }
	};

	/**
	 * @brief Finds the function enclosing an arbitrary instruction address.
	 *
	 * When the caller built an EhFrameIndex for this module, its .eh_frame_hdr
	 * search table is consulted first: it records the exact start of every function
	 * the compiler emitted unwind data for, at instruction precision, and does not
	 * depend on symbols. The instruction stream remains the fallback for the small
	 * remainder of functions without unwind data and for modules without the table:
	 * scanning backwards, the first return means the previous function ended there,
	 * and the first frame setup means this function began there - whichever is
	 * nearer wins. Scanning forwards, the first return ends the function.
	 *
	 * The scan is deliberately conservative. Over-reaching is the dangerous failure:
	 * it would pull in a neighbouring function's globals and produce a confident
	 * wrong answer, so an unbounded scan returns nothing instead.
	 */
	class FunctionBoundary
	{
	public:
		/**
		 * @param Memory Backend to read code from. Borrowed.
		 * @param Module Module being analysed. Borrowed, and must outlive this - a
		 *        boundary is built per anchor site, and fetching the module by value
		 *        each time copied its whole segment list on every one.
		 * @param Arch   Decoder for the module's architecture.
		 * @param EhFrame Optional function table decoded from the module's
		 *        .eh_frame_hdr. Borrowed; must outlive this. Nullptr keeps the
		 *        instruction-scanning behaviour.
		 */
		FunctionBoundary(const IMemory *Memory, const ModuleInfo &Module, const IArchDecoder &Arch,
						 const EhFrameIndex *EhFrame = nullptr)
			: Memory_(Memory),
			  Module_(Module),
			  Arch_(Arch),
			  EhFrame_(EhFrame)
		{
		}

		/**
		 * @brief Recovers the bounds of the function containing Address.
		 *
		 * Both ends must be found, so the limit has to clear the *whole* function
		 * from wherever inside it the caller is looking - not half of one. A large
		 * outlined constructor can span tens of kilobytes with anchor sites well
		 * short of its closing return; too small a limit misses the boundary
		 * entirely, drops the sites before clustering, and makes the function
		 * invisible to the anchor that names it.
		 *
		 * @param Address Any instruction inside the function.
		 * @param MaxScan How far to scan in each direction before giving up. A hit
		 *        in the unwind table is exact and is not subject to this limit.
		 * @return Invalid bounds when no boundary is found inside MaxScan bytes.
		 */
		FunctionBounds Find(uint64_t Address, uint32_t MaxScan = 0x8000) const;

	private:
		const IMemory *Memory_;
		const ModuleInfo &Module_;
		const IArchDecoder &Arch_;
		const EhFrameIndex *EhFrame_ = nullptr;
	};

} // namespace nextdumper::analyzer
