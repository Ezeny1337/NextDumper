#include "nextdumper/memory/MemoryScanner.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>

namespace nextdumper::memory
{
    ScanResult ScanMemory(const IMemorySource &memory, uintptr_t start, size_t size,
                          std::span<const uint8_t> pattern, std::span<const uint8_t> mask,
                          size_t alignment, size_t maxHits)
    {
        constexpr size_t kChunk = 4096, kVectors = 128, kMaxHits = 1024 * 1024;
        if (!start || !size || start > UINTPTR_MAX - size || size > 2ULL * 1024 * 1024 * 1024 ||
            pattern.empty() || pattern.size() > kChunk || pattern.size() != mask.size() || !alignment || maxHits > kMaxHits)
            throw std::invalid_argument("Invalid or excessive memory scan request");
        ScanResult result;
        if (!memory.IsInitialized() || memory.Regions().empty())
        {
            result.complete = false;
            result.failure = {memory.IsInitialized() ? ReadError::UnreadableRange : ReadError::NotInitialized, start, size, 0};
            return result;
        }
        size_t anchor = 0;
        while (anchor < mask.size() && mask[anchor] == 0)
            ++anchor;
        const uintptr_t end = start + size;
        std::vector<uint8_t> storage(kChunk * kVectors), pending;
        pending.reserve(kChunk * 2);
        std::array<ReadRequest, kVectors> requests{};
        std::array<ReadResult, kVectors> reads{};
        uintptr_t nextAddress = 0;
        size_t scanned = 0;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        for (const auto &region : memory.Regions())
        {
            if (!region.readable || region.end <= start || region.start >= end)
                continue;
            uintptr_t cursor = std::max(start, region.start);
            const uintptr_t limit = std::min(end, region.end);
            while (cursor < limit)
            {
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    result.complete = false;
                    result.failure = {ReadError::LimitExceeded, cursor, static_cast<size_t>(limit - cursor), 0};
                    return result;
                }
                size_t count = 0;
                while (count < kVectors && cursor < limit)
                {
                    const size_t wanted = std::min<size_t>(limit - cursor, kChunk - cursor % kChunk);
                    requests[count] = {cursor, storage.data() + count * kChunk, wanted};
                    cursor += wanted;
                    ++count;
                }
                if (!memory.ReadBatch({requests.data(), count}, {reads.data(), count}, true))
                    throw std::runtime_error("Memory scan batch contract failed");
                for (size_t index = 0; index < count; ++index)
                {
                    const auto &read = reads[index];
                    if (read.transferred > requests[index].size)
                        throw std::runtime_error("Invalid memory scan transfer count");
                    if (!read.Ok())
                    {
                        result.complete = false;
                        if (result.failure.error == ReadError::None)
                            result.failure = read;
                    }
                    const size_t valid = read.Ok() || read.error == ReadError::PartialRead ? read.transferred : 0;
                    const auto *bytes = static_cast<const uint8_t *>(requests[index].buffer);
                    if (requests[index].address != nextAddress)
                        pending.clear();
                    const uintptr_t base = requests[index].address - pending.size();
                    pending.insert(pending.end(), bytes, bytes + valid);
                    if (pending.size() >= pattern.size())
                    {
                        const size_t last = pending.size() - pattern.size();
                        for (size_t offset = 0; offset <= last; ++offset)
                        {
                            if (offset % 4096 == 0 && std::chrono::steady_clock::now() >= deadline)
                            {
                                result.complete = false;
                                result.failure = {ReadError::LimitExceeded, base + offset, pattern.size(), 0};
                                return result;
                            }
                            if ((base + offset) % alignment || (anchor < mask.size() &&
                                                                (pending[offset + anchor] & mask[anchor]) != (pattern[anchor] & mask[anchor])))
                                continue;
                            bool match = true;
                            for (size_t byte = 0; byte < pattern.size(); ++byte)
                                if ((pending[offset + byte] & mask[byte]) != (pattern[byte] & mask[byte]))
                                {
                                    match = false;
                                    break;
                                }
                            if (!match)
                                continue;
                            if (result.hits.size() == kMaxHits)
                                throw std::length_error("Memory scan hit limit exceeded");
                            result.hits.push_back(base + offset);
                            if (maxHits && result.hits.size() == maxHits)
                                return result;
                        }
                    }
                    const size_t tail = std::min(pending.size(), pattern.size() - 1);
                    pending.erase(pending.begin(), pending.end() - static_cast<ptrdiff_t>(tail));
                    nextAddress = requests[index].address + valid;
                    if (!read.Ok())
                    {
                        pending.clear();
                        nextAddress = 0;
                    }
                    if (read.error == ReadError::Cancelled || read.error == ReadError::TargetExited ||
                        read.error == ReadError::LimitExceeded || read.error == ReadError::AccessDenied)
                        return result;
                    scanned += requests[index].size;
                    if (scanned > size)
                        throw std::runtime_error("Overlapping scan mappings");
                }
            }
        }
        return result;
    }
} // namespace nextdumper::memory
