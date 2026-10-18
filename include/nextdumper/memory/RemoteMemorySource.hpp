#pragma once

#include <atomic>
#include <bitset>
#include <list>
#include <unordered_map>

#include "nextdumper/memory/MemorySource.hpp"

namespace nextdumper::memory
{
    // 会话由一个读取线程拥有，仅 Cancel 可由其他线程调用
    class RemoteMemorySource final : public IMemorySource
    {
    public:
        static constexpr size_t kCacheBlockSize = 4096;
        static constexpr size_t kDefaultCacheSize = 16 * 1024 * 1024;
        static constexpr size_t kMaxRequestBytes = 64 * 1024 * 1024;
        static constexpr size_t kMaxBatchRequests = 1024;
        static constexpr size_t kMaxTransferBytes = 1024 * 1024;
        static constexpr size_t kMaxVectors = 128;

        explicit RemoteMemorySource(size_t cacheSize = kDefaultCacheSize);
        RemoteMemorySource(const RemoteMemorySource &) = delete;
        RemoteMemorySource &operator=(const RemoteMemorySource &) = delete;

        [[nodiscard]] bool Initialize(pid_t pid);
        void Reset();
        // 取消标志不发布其他数据，因此 relaxed 足以通知读取线程
        void Cancel() { cancelled_.store(true, std::memory_order_relaxed); }
        [[nodiscard]] bool IsInitialized() const override { return initialized_ && !invalidated_; }
        [[nodiscard]] pid_t ProcessId() const override { return process_.Identity().pid; }
        [[nodiscard]] std::string ProcessName() const override { return process_.Identity().name; }
        [[nodiscard]] uint64_t AddressSpaceGeneration() const override { return addressSpaceGeneration_; }
        [[nodiscard]] bool RefreshAddressSpace() override;
        [[nodiscard]] bool IsReadable(uintptr_t address, size_t size) const override;
        [[nodiscard]] bool IsExecutable(uintptr_t address, size_t size) const override;
        [[nodiscard]] ReadResult ReadBytes(uintptr_t address, void *buffer, size_t size) const override;
        [[nodiscard]] ReadResult ReadFreshBytes(uintptr_t address, void *buffer, size_t size) const override;
        [[nodiscard]] bool ReadBatch(std::span<const ReadRequest> requests, std::span<ReadResult> results,
                                     bool fresh = false) const override;
        [[nodiscard]] const ReadStats &Stats() const override { return stats_; }
        [[nodiscard]] std::span<const MemoryRegion> Regions() const override { return regions_; }
        [[nodiscard]] const ProcessIdentity &Identity() const { return process_.Identity(); }
        [[nodiscard]] size_t PageSize() const { return pageSize_; }
        [[nodiscard]] int LastError() const { return lastError_; }
        [[nodiscard]] std::span<const ReadResult> ErrorSamples() const { return {errors_.data(), errorCount_}; }

    private:
        struct CacheBlock
        {
            std::array<uint8_t, kCacheBlockSize> bytes{};
            std::bitset<kCacheBlockSize> valid;
            std::list<uintptr_t>::iterator lru;
        };
        void ClearCache() const;
        void InvalidateCache(uintptr_t address, size_t size) const;
        [[nodiscard]] bool GetCached(uintptr_t address, void *buffer, size_t size) const;
        void PutCached(uintptr_t address, const uint8_t *data, size_t size) const;
        [[nodiscard]] bool Transfer(std::span<const ReadRequest> requests, std::span<ReadResult> results, bool fresh) const;
        void FinishResult(const ReadResult &result) const;

        ProcessInfo process_;
        std::vector<MemoryRegion> regions_;
        mutable ReadStats stats_;
        mutable std::unordered_map<uintptr_t, CacheBlock> blocks_;
        mutable std::list<uintptr_t> lru_;
        mutable std::array<ReadResult, 16> errors_{};
        mutable size_t errorCount_ = 0;
        size_t maxCacheSize_ = 0;
        size_t pageSize_ = 0;
        size_t vectorLimit_ = 0;
        uint64_t addressSpaceGeneration_ = 0;
        std::atomic_bool cancelled_{false};
        bool initialized_ = false;
        mutable bool invalidated_ = false;
        mutable int lastError_ = 0;
    };
} // namespace nextdumper::memory
