#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "nextdumper/analysis/ImageModel.hpp"
#include "nextdumper/analysis/MemoryView.hpp"

namespace nextdumper::analysis
{
    struct FunctionRange
    {
        uint64_t Start = 0;
        uint64_t End = 0;
    };

    class FunctionIndex
    {
    public:
        FunctionIndex() = default;

        [[nodiscard]] static FunctionIndex Build(const ImageModel &image, std::string &error);

        [[nodiscard]] bool IsValid() const { return memory_ != nullptr && count_ != 0; }
        [[nodiscard]] size_t Count() const { return count_; }
        [[nodiscard]] uint64_t FirstStart() const { return firstStart_; }
        [[nodiscard]] uint64_t LastStart() const { return lastStart_; }

        [[nodiscard]] bool StartAt(size_t index, uint64_t &start) const;
        [[nodiscard]] bool Find(uint64_t address, FunctionRange &out) const;
        [[nodiscard]] bool CopyStarts(std::vector<uint64_t> &starts, std::string &error) const;

    private:
        [[nodiscard]] bool ReadStart(size_t index, uint64_t &start) const;
        [[nodiscard]] bool ReadFdeOffset(size_t index, int32_t &offset) const;
        [[nodiscard]] bool ReadFdeRange(uint64_t expectedStart, uint64_t fde, FunctionRange &out) const;

        const MemoryView *memory_ = nullptr;
        uintptr_t moduleBase_ = 0;
        uintptr_t moduleEnd_ = 0;
        uint64_t section_ = 0;
        uint64_t table_ = 0;
        size_t count_ = 0;
        uint64_t firstStart_ = 0;
        uint64_t lastStart_ = 0;
        bool elf64_ = false;
    };
} // namespace nextdumper::analysis
