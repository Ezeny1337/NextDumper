#include "nextdumper/memory/RemoteMemorySource.hpp"

#include <algorithm>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <sys/uio.h>
#include <unistd.h>

namespace nextdumper::memory
{
    namespace
    {
        uintptr_t BlockAddress(uintptr_t address) { return address & ~(uintptr_t{RemoteMemorySource::kCacheBlockSize} - 1); }
        size_t BlockOffset(uintptr_t address) { return address & (RemoteMemorySource::kCacheBlockSize - 1); }

        ReadError SystemReadError(int error)
        {
            if (error == ESRCH)
                return ReadError::TargetExited;
            if (error == EPERM || error == EACCES)
                return ReadError::AccessDenied;
            return ReadError::BackendFailure;
        }
    }

    RemoteMemorySource::RemoteMemorySource(size_t cacheSize)
        : maxCacheSize_((std::min(cacheSize, kMaxRequestBytes) / kCacheBlockSize) * kCacheBlockSize) {}

    void RemoteMemorySource::Reset()
    {
        initialized_ = false;
        invalidated_ = false;
        process_.Close();
        regions_.clear();
        ClearCache();
        stats_ = {};
        errorCount_ = 0;
        lastError_ = 0;
        pageSize_ = 0;
        vectorLimit_ = 0;
        cancelled_.store(false, std::memory_order_relaxed);
        ++addressSpaceGeneration_;
    }

    bool RemoteMemorySource::Initialize(pid_t pid)
    {
        Reset();
        const long pageSize = sysconf(_SC_PAGESIZE);
        const long vectors = sysconf(_SC_IOV_MAX);
        if (pageSize <= 0 || vectors <= 0)
        {
            lastError_ = EINVAL;
            return false;
        }
        pageSize_ = static_cast<size_t>(pageSize);
        vectorLimit_ = std::min(static_cast<size_t>(vectors), kMaxVectors);
        if (!process_.Open(pid) || !process_.ReadRegions(regions_))
        {
            lastError_ = process_.LastError();
            return false;
        }
        initialized_ = true;
        ++stats_.mapRefreshes;
        // 以真实可读映射验证后端，接口存在不代表目标读取成功
        const auto region = std::find_if(regions_.begin(), regions_.end(), [](const auto &item)
                                         { return item.readable; });
        uint8_t byte = 0;
        if (region == regions_.end())
        {
            lastError_ = ENXIO;
            initialized_ = false;
            return false;
        }
        if (!ReadFreshBytes(region->start, &byte, sizeof(byte)).Ok())
        {
            initialized_ = false;
            return false;
        }
        return true;
    }

    bool RemoteMemorySource::RefreshAddressSpace()
    {
        if (!IsInitialized())
            return false;
        ClearCache();
        ++addressSpaceGeneration_;
        ++stats_.mapRefreshes;
        std::vector<MemoryRegion> updated;
        if (!process_.ReadRegions(updated))
        {
            lastError_ = process_.LastError();
            initialized_ = false;
            regions_.clear();
            return false;
        }
        regions_ = std::move(updated);
        return true;
    }

    bool RemoteMemorySource::IsReadable(uintptr_t address, size_t size) const
    {
        ScopedReadTiming timing(performanceEnabled_ ? &performance_.mappingCheck : nullptr);
        return IsInitialized() && ContainsRange(regions_, address, size);
    }

    bool RemoteMemorySource::IsExecutable(uintptr_t address, size_t size) const
    {
        ScopedReadTiming timing(performanceEnabled_ ? &performance_.mappingCheck : nullptr);
        return IsInitialized() && ContainsRange(regions_, address, size, true);
    }

    void RemoteMemorySource::ClearCache() const
    {
        ScopedReadTiming timing(performanceEnabled_ ? &performance_.cacheClear : nullptr, 1);
        blocks_.clear();
        lru_.clear();
        stats_.cacheBytes = 0;
    }

    void RemoteMemorySource::InvalidateCache(uintptr_t address, size_t size) const
    {
        ScopedReadTiming timing(performanceEnabled_ ? &performance_.cacheInvalidate : nullptr);
        while (size)
        {
            const size_t offset = BlockOffset(address);
            const size_t count = std::min(size, kCacheBlockSize - offset);
            const auto at = blocks_.find(BlockAddress(address));
            if (at != blocks_.end())
            {
                if (count == kCacheBlockSize)
                    at->second.valid.reset();
                else
                    for (size_t index = 0; index < count; ++index)
                        at->second.valid.reset(offset + index);
            }
            size -= count;
            if (size)
                address += count;
        }
    }

    bool RemoteMemorySource::GetCached(uintptr_t address, void *buffer, size_t size) const
    {
        ScopedReadTiming timing(performanceEnabled_ ? &performance_.cacheLookup : nullptr);
        if (size > maxCacheSize_)
            return false;
        const uintptr_t first = address;
        const size_t total = size;
        while (size)
        {
            const size_t offset = BlockOffset(address);
            const size_t count = std::min(size, kCacheBlockSize - offset);
            const auto at = blocks_.find(BlockAddress(address));
            if (at == blocks_.end())
                return false;
            if (count == kCacheBlockSize)
            {
                if (!at->second.valid.all())
                    return false;
            }
            else
                for (size_t index = 0; index < count; ++index)
                    if (!at->second.valid.test(offset + index))
                        return false;
            size -= count;
            if (size)
                address += count;
        }
        address = first;
        size = total;
        auto *output = static_cast<uint8_t *>(buffer);
        while (size)
        {
            const size_t offset = BlockOffset(address);
            const size_t count = std::min(size, kCacheBlockSize - offset);
            auto &block = blocks_.at(BlockAddress(address));
            std::memcpy(output, block.bytes.data() + offset, count);
            lru_.splice(lru_.begin(), lru_, block.lru);
            output += count;
            size -= count;
            if (size)
                address += count;
        }
        return true;
    }

    void RemoteMemorySource::PutCached(uintptr_t address, const uint8_t *data, size_t size) const
    {
        ScopedReadTiming timing(performanceEnabled_ ? &performance_.cacheStore : nullptr);
        if (!maxCacheSize_ || size > maxCacheSize_)
            return;
        while (size)
        {
            const uintptr_t base = BlockAddress(address);
            const size_t offset = BlockOffset(address);
            const size_t count = std::min(size, kCacheBlockSize - offset);
            auto at = blocks_.find(base);
            if (at == blocks_.end())
            {
                while (stats_.cacheBytes >= maxCacheSize_)
                {
                    blocks_.erase(lru_.back());
                    lru_.pop_back();
                    stats_.cacheBytes -= kCacheBlockSize;
                    ++stats_.evictions;
                }
                auto [entry, inserted] = blocks_.try_emplace(base);
                (void)inserted;
                try
                {
                    lru_.push_front(base);
                }
                catch (...)
                {
                    blocks_.erase(entry);
                    throw;
                }
                entry->second.lru = lru_.begin();
                at = entry;
                stats_.cacheBytes += kCacheBlockSize;
                stats_.peakCacheBytes = std::max(stats_.peakCacheBytes, stats_.cacheBytes);
            }
            else
                lru_.splice(lru_.begin(), lru_, at->second.lru);
            std::memcpy(at->second.bytes.data() + offset, data, count);
            if (count == kCacheBlockSize)
                at->second.valid.set();
            else
                for (size_t index = 0; index < count; ++index)
                    at->second.valid.set(offset + index);
            data += count;
            size -= count;
            if (size)
                address += count;
        }
    }

    void RemoteMemorySource::FinishResult(const ReadResult &result) const
    {
        stats_.transferredBytes += result.transferred;
        if (result.Ok())
            return;
        ++stats_.failures;
        switch (result.error)
        {
        case ReadError::NotInitialized:
            ++stats_.notInitialized;
            break;
        case ReadError::InvalidArgument:
        case ReadError::LimitExceeded:
            ++stats_.invalidArguments;
            break;
        case ReadError::UnreadableRange:
            ++stats_.unreadableRanges;
            break;
        case ReadError::PartialRead:
            ++stats_.partialReads;
            break;
        case ReadError::Cancelled:
            ++stats_.cancellations;
            break;
        default:
            ++stats_.backendFailures;
            break;
        }
        if (errorCount_ < errors_.size())
            errors_[errorCount_++] = result;
    }

    ReadResult RemoteMemorySource::ReadBytes(uintptr_t address, void *buffer, size_t size) const
    {
        const ReadRequest request{address, buffer, size};
        ReadResult result;
        (void)Transfer({&request, 1}, {&result, 1}, false);
        return result;
    }

    ReadResult RemoteMemorySource::ReadFreshBytes(uintptr_t address, void *buffer, size_t size) const
    {
        const ReadRequest request{address, buffer, size};
        ReadResult result;
        (void)Transfer({&request, 1}, {&result, 1}, true);
        return result;
    }

    bool RemoteMemorySource::ReadBatch(std::span<const ReadRequest> requests, std::span<ReadResult> results, bool fresh) const
    {
        ++stats_.batchOperations;
        stats_.batchRequests += requests.size();
        return Transfer(requests, results, fresh);
    }

    bool RemoteMemorySource::Transfer(std::span<const ReadRequest> requests, std::span<ReadResult> results, bool fresh) const
    {
        ScopedReadTiming timing(performanceEnabled_ ? &performance_.transfer : nullptr);
        if (requests.size() != results.size() || requests.size() > kMaxBatchRequests)
            return false;
        if (performanceEnabled_)
            ++performance_.transferRequestCounts[ReadCountBucket(requests.size())];
        size_t total = 0;
        bool overLimit = false;
        for (const auto &request : requests)
        {
            if (request.size > kMaxRequestBytes - total)
            {
                overLimit = true;
                break;
            }
            total += request.size;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool alive = IsInitialized();
        if (alive && !process_.Alive())
        {
            invalidated_ = true;
            ++stats_.targetInvalidations;
            lastError_ = process_.LastError();
            ClearCache();
            alive = false;
        }
        std::array<bool, kMaxBatchRequests> cached{};
        for (size_t index = 0; index < requests.size(); ++index)
        {
            const auto &request = requests[index];
            auto &result = results[index];
            result = {ReadError::None, request.address, request.size, 0};
            ++stats_.operations;
            stats_.requestedBytes += request.size;
            if (fresh)
                ++stats_.freshOperations;
            if (cancelled_.load(std::memory_order_relaxed))
                result.error = ReadError::Cancelled;
            else if (!alive)
            {
                result.error = invalidated_ ? SystemReadError(lastError_) : ReadError::NotInitialized;
                result.systemError = lastError_;
            }
            else if (overLimit)
                result.error = ReadError::LimitExceeded;
            else if (!request.buffer || !request.address || !request.size || request.address > UINTPTR_MAX - (request.size - 1))
                result.error = ReadError::InvalidArgument;
            else if (!IsReadable(request.address, request.size))
                result.error = ReadError::UnreadableRange;
            else if (fresh)
                InvalidateCache(request.address, request.size);
            else if (GetCached(request.address, request.buffer, request.size))
            {
                result.transferred = request.size;
                cached[index] = true;
                ++stats_.cacheHits;
                stats_.cacheHitBytes += request.size;
            }
            else
            {
                ++stats_.cacheMisses;
                stats_.cacheMissBytes += request.size;
            }
        }
        std::array<iovec, kMaxVectors> local{}, remote{};
        std::array<size_t, kMaxVectors> owners{};
        size_t calls = 0;
        for (;;)
        {
            const bool cancelled = cancelled_.load(std::memory_order_relaxed);
            const bool expired = std::chrono::steady_clock::now() >= deadline;
            size_t count = 0, bytes = 0;
            for (size_t index = 0; index < requests.size(); ++index)
            {
                auto &result = results[index];
                if (result.error != ReadError::None || result.transferred == result.requested)
                    continue;
                if (cancelled || expired || calls >= 4096 || invalidated_)
                {
                    result.error = cancelled ? ReadError::Cancelled : invalidated_ ? SystemReadError(lastError_)
                                                                                   : ReadError::LimitExceeded;
                    if (invalidated_)
                        result.systemError = lastError_;
                    continue;
                }
                const auto &request = requests[index];
                size_t offset = result.transferred;
                while (offset < request.size && count < vectorLimit_ && bytes < kMaxTransferBytes)
                {
                    const uintptr_t address = request.address + offset;
                    const size_t size = std::min({request.size - offset, pageSize_ - address % pageSize_, kMaxTransferBytes - bytes});
                    local[count] = {static_cast<uint8_t *>(request.buffer) + offset, size};
                    remote[count] = {reinterpret_cast<void *>(address), size};
                    owners[count++] = index;
                    offset += size;
                    bytes += size;
                    if (offset < request.size)
                        ++stats_.pageSplits;
                }
                if (count == vectorLimit_ || bytes == kMaxTransferBytes)
                    break;
            }
            if (!count)
                break;
            if (!process_.Alive())
            {
                invalidated_ = true;
                ++stats_.targetInvalidations;
                lastError_ = process_.LastError();
                ClearCache();
                continue;
            }
            ssize_t received = -1;
            int error = 0;
            unsigned retries = 0;
            do
            {
                const auto start = std::chrono::steady_clock::now();
                received = process_vm_readv(ProcessId(), local.data(), count, remote.data(), count, 0);
                error = received < 0 ? errno : 0;
                const auto nanos = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                             std::chrono::steady_clock::now() - start)
                                                             .count());
                ++calls;
                ++stats_.backendOperations;
                if (performanceEnabled_)
                    ++performance_.backendVectorCounts[ReadCountBucket(count)];
                stats_.backendVectors += count;
                stats_.backendRequestedBytes += bytes;
                stats_.backendTransferredBytes += received > 0 ? static_cast<size_t>(received) : 0;
                stats_.backendNanos += nanos;
                stats_.minBackendNanos = stats_.backendOperations == 1 ? nanos : std::min(stats_.minBackendNanos, nanos);
                stats_.maxBackendNanos = std::max(stats_.maxBackendNanos, nanos);
                ++stats_.latencyBuckets[std::min<size_t>(31, std::bit_width(nanos))];
                stats_.maxBatchVectors = std::max<uint64_t>(stats_.maxBatchVectors, count);
                stats_.maxBatchBytes = std::max<uint64_t>(stats_.maxBatchBytes, bytes);
                if (error)
                    ++stats_.errnoCounts[std::min(static_cast<size_t>(error), stats_.errnoCounts.size() - 1)];
                if (error != EINTR || retries == 3 || cancelled_.load(std::memory_order_relaxed) ||
                    std::chrono::steady_clock::now() >= deadline)
                    break;
                ++retries;
                ++stats_.retries;
            } while (calls < 4096);
            if (received > static_cast<ssize_t>(bytes))
            {
                received = -1;
                error = EIO;
            }
            lastError_ = error;
            size_t remaining = received > 0 ? static_cast<size_t>(received) : 0;
            bool stopped = false;
            for (size_t index = 0; index < count; ++index)
            {
                auto &result = results[owners[index]];
                const size_t done = std::min(remaining, remote[index].iov_len);
                result.transferred += done;
                remaining -= done;
                if (done != remote[index].iov_len)
                {
                    result.error = received >= 0 || result.transferred ? ReadError::PartialRead : SystemReadError(error);
                    result.systemError = error;
                    stopped = true;
                    break;
                }
            }
            if (error == ESRCH)
            {
                invalidated_ = true;
                ++stats_.targetInvalidations;
                ClearCache();
            }
            if (stopped && (error == EPERM || error == EACCES || error == ENOSYS || error == EINVAL))
            {
                for (auto &result : results)
                    if (result.error == ReadError::None && result.transferred != result.requested)
                    {
                        result.error = result.transferred ? ReadError::PartialRead : SystemReadError(error);
                        result.systemError = error;
                    }
                break;
            }
        }
        // 生命周期复核失败时，已复制的字节也不能冒充可靠结果
        if (alive && !invalidated_ && !process_.Alive())
        {
            invalidated_ = true;
            ++stats_.targetInvalidations;
            lastError_ = process_.LastError();
            ClearCache();
        }
        for (size_t index = 0; index < results.size(); ++index)
        {
            auto &result = results[index];
            if (invalidated_ && result.error == ReadError::None)
            {
                result.error = SystemReadError(lastError_);
                result.systemError = lastError_;
            }
            if (result.Ok() && !fresh && !cached[index])
                PutCached(requests[index].address, static_cast<const uint8_t *>(requests[index].buffer), requests[index].size);
            FinishResult(result);
        }
        if (performanceEnabled_ && calls == 0)
        {
            ++performance_.transferWithoutBackend;
            if (!requests.empty() && std::all_of(cached.begin(), cached.begin() + requests.size(), [](bool hit)
                                                 { return hit; }))
                ++performance_.transferAllCacheHits;
        }
        return true;
    }
} // namespace nextdumper::memory
