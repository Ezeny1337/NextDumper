#pragma once

#include <cstddef>
#include <cstdint>

#include "FunctionBoundary.h"

namespace nextdumper::analyzer
{

    /**
     * @brief Function-entry index decoded from the module's .eh_frame_hdr table.
     *
     * The linker writes .eh_frame_hdr as a sorted binary-search table over every
     * function the compiler emitted unwind data for. Unlike the symbol table it is
     * not optional: the unwinder needs it for C++ exceptions, so it survives
     * hardening that strips symbols and rewrites relocations. It therefore gives
     * instruction-precise function starts on binaries where no other function
     * table remains.
     *
     * Only the table is decoded - the DWARF CFI in .eh_frame is irrelevant here.
     * Entries are read on demand, so building the index costs one ELF header and
     * one program-header table read, and a lookup costs O(log n) small reads
     * instead of a multi-megabyte buffer.
     *
     * The table records function starts, not ends; a function's end is the next
     * entry's start. The last entry has no successor, so Find() declines it and
     * the caller falls back to the instruction scan.
     */
    class EhFrameIndex
    {
    public:
        EhFrameIndex() = default;

        /**
         * @brief Builds the index from the module's PT_GNU_EH_FRAME segment.
         *
         * @param Memory Backend to read the image through. Borrowed.
         * @param Module Module whose loaded image is inspected. Borrowed.
         * @return A usable index, or an empty one when the table is absent or uses
         *         an encoding this decoder does not understand. Never throws.
         */
        static EhFrameIndex Build(const IMemory &Memory, const ModuleInfo &Module);

        bool IsValid() const { return Memory_ != nullptr && Count_ != 0; }

        /**
         * @brief Looks up the function containing Address.
         *
         * @param Address Instruction address inside the module.
         * @param Out Receives [start, next start) on success.
         * @return false when Address is outside the tabled range, the table cannot
         *         be read, or the entry is the last one. The caller then falls back
         *         to its instruction-scanning heuristic.
         */
        bool Find(uint64_t Address, FunctionBounds &Out) const;

    private:
        /// Reads one entry's initial_location, rebased to a runtime address.
        bool ReadStart(size_t Index, uint64_t &Start) const;

        const IMemory *Memory_ = nullptr;
        uint64_t Section_ = 0; ///< Runtime address of .eh_frame_hdr, the datarel base.
        uint64_t Table_ = 0;   ///< Runtime address of the first table entry.
        size_t Count_ = 0;     ///< Number of entries.
        uint64_t FirstStart_ = 0;
        uint64_t LastStart_ = 0;
    };

} // namespace nextdumper::analyzer
