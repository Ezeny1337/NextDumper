#pragma once

#include <vector>

#include "nextdumper/memory/MemorySource.hpp"

namespace nextdumper::memory
{
    struct ScanResult
    {
        std::vector<uintptr_t> hits;
        bool complete = true;
        ReadResult failure;
    };

    // mask 的每一位表示对应 pattern 位是否参与比较，alignment 作用于目标地址
    [[nodiscard]] ScanResult ScanMemory(const IMemorySource &memory, uintptr_t start, size_t size,
                                        std::span<const uint8_t> pattern, std::span<const uint8_t> mask,
                                        size_t alignment = 1, size_t maxHits = 0);
} // namespace nextdumper::memory
