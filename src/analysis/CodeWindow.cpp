#include "nextdumper/analysis/CodeWindow.hpp"

#include <algorithm>

namespace nextdumper::analysis
{
    CodeWindow::CodeWindow(const MemoryView &memory, size_t chunkSize)
        : memory_(memory), chunkSize_(chunkSize ? chunkSize : kDefaultChunk)
    {
    }

    size_t CodeWindow::ChunkForSpan(size_t span)
    {
        size_t chunk = kDefaultChunk;
        while (chunk < span && chunk < 65536)
            chunk <<= 1;
        return chunk;
    }

    const uint8_t *CodeWindow::At(uintptr_t address, size_t needBytes)
    {
        if (needBytes == 0 || address > UINTPTR_MAX - needBytes)
            return nullptr;

        if (valid_ != 0 && address >= bufferStart_ && address - bufferStart_ <= valid_ &&
            needBytes <= valid_ - static_cast<size_t>(address - bufferStart_))
            return buffer_.data() + (address - bufferStart_);

        if (!Refill(address, needBytes))
            return nullptr;
        return buffer_.data() + (address - bufferStart_);
    }

    bool CodeWindow::Refill(uintptr_t address, size_t needBytes)
    {
        const bool backward = valid_ != 0 && address < bufferStart_;
        valid_ = 0;

        const size_t want = std::max(chunkSize_, needBytes);
        if (buffer_.size() < want)
            buffer_.resize(want);

        const size_t behind = backward ? want - needBytes : 0;
        uintptr_t base = address >= behind ? address - behind : 0;

        for (;;)
        {
            const size_t least = static_cast<size_t>(address - base) + needBytes;

            size_t size = want;
            while (size >= least)
            {
                const auto read = memory_.ReadBytes(base, buffer_.data(), size);
                const size_t received = read.transferred;
                if (received >= least && received <= size)
                {
                    bufferStart_ = base;
                    valid_ = received;
                    bytesFetched_ += received;
                    return true;
                }
                if (size == least)
                    break;
                size = std::max(least, size / 2);
            }

            if (base == address)
                return false;
            base = address;
        }
    }
} // namespace nextdumper::analysis
