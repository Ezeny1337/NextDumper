#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "nextdumper/analysis/MemoryView.hpp"

namespace nextdumper::analysis
{
    class CodeWindow
    {
    public:
        static constexpr size_t kDefaultChunk = 4096;

        explicit CodeWindow(const MemoryView &memory, size_t chunkSize = kDefaultChunk);

        [[nodiscard]] const uint8_t *At(uintptr_t address, size_t needBytes);
        [[nodiscard]] uint64_t BytesFetched() const { return bytesFetched_; }
        [[nodiscard]] static size_t ChunkForSpan(size_t span);

    private:
        [[nodiscard]] bool Refill(uintptr_t address, size_t needBytes);

        const MemoryView &memory_;
        size_t chunkSize_ = kDefaultChunk;
        std::vector<uint8_t> buffer_;
        uintptr_t bufferStart_ = 0;
        size_t valid_ = 0;
        uint64_t bytesFetched_ = 0;
    };
} // namespace nextdumper::analysis
