#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "nextdumper/memory/MemorySource.hpp"

namespace nextdumper::memory
{
    struct CaptureValidation
    {
        struct Change
        {
            uintptr_t address = 0;
            size_t size = 0;
            ReadResult read;
            std::vector<uint8_t> before;
            std::vector<uint8_t> after;
        };
        size_t observedRanges = 0;
        size_t observedBytes = 0;
        size_t changedRanges = 0;
        size_t unreadableRanges = 0;
        bool limitExceeded = false;
        bool generationChanged = false;
        std::vector<uintptr_t> failedAddresses;
        std::vector<Change> changes;
        size_t readFailures = 0;
        std::vector<ReadResult> readFailureSamples;

        // 预算耗尽表示部分读取未被冻结，校验覆盖不完整，但不代表已冻结的字节发生了变化
        // 它单独由 limitExceeded 与 coverageComplete 表达，不参与稳定性判定
        [[nodiscard]] bool Stable() const
        {
            return !generationChanged && changedRanges == 0 && unreadableRanges == 0;
        }
    };

    // 单线程采集视图，只冻结已消费的字节，验证稳定不等于获得原子快照
    // 冻结以对齐块为单位，预算因此取决于被访问的对象数，而不是读取次数
    class CaptureMemorySource final : public IMemorySource
    {
    public:
        explicit CaptureMemorySource(IMemorySource &source,
                                     std::function<void(const std::string &)> diagnostic = {})
            : source_(source), diagnostic_(std::move(diagnostic)), generation_(source.AddressSpaceGeneration()) {}

        void Reset() const;
        void Observe(bool enabled) const { observing_ = enabled; }
        [[nodiscard]] bool IsObserving() const { return observing_; }
        [[nodiscard]] bool LimitExceeded() const { return limitExceeded_; }
        void CopyReadFailures(CaptureValidation &validation) const
        {
            validation.readFailures = readFailures_;
            validation.readFailureSamples = readFailureSamples_;
        }
        void Invalidate() const { changedDuringRead_ = true; }
        [[nodiscard]] CaptureValidation Validate() const;
        [[nodiscard]] bool IsInitialized() const override { return source_.IsInitialized(); }
        [[nodiscard]] pid_t ProcessId() const override { return source_.ProcessId(); }
        [[nodiscard]] std::span<const MemoryRegion> Regions() const override { return source_.Regions(); }
        [[nodiscard]] std::string ProcessName() const override { return source_.ProcessName(); }
        [[nodiscard]] uint64_t AddressSpaceGeneration() const override { return source_.AddressSpaceGeneration(); }
        [[nodiscard]] bool RefreshAddressSpace() override;
        [[nodiscard]] bool IsReadable(uintptr_t address, size_t size) const override { return source_.IsReadable(address, size); }
        [[nodiscard]] bool IsExecutable(uintptr_t address, size_t size) const override { return source_.IsExecutable(address, size); }
        [[nodiscard]] ReadResult ReadBytes(uintptr_t address, void *buffer, size_t size) const override;
        [[nodiscard]] ReadResult ReadFreshBytes(uintptr_t address, void *buffer, size_t size) const override;
        [[nodiscard]] bool ReadBatch(std::span<const ReadRequest> requests, std::span<ReadResult> results,
                                     bool fresh = false) const override;
        [[nodiscard]] const ReadStats &Stats() const override { return source_.Stats(); }
        [[nodiscard]] ReadPerformance *Performance() const override { return source_.Performance(); }

    private:
        static constexpr size_t kBlockSize = 64;
        static constexpr size_t kMaxBlocks = 512 * 1024;
        static constexpr size_t kMaxBytes = 64 * 1024 * 1024;
        static constexpr size_t kMaxReadSize = 2048;

        struct Block
        {
            std::array<uint8_t, kBlockSize> bytes{};
            std::array<uint64_t, kBlockSize / 64> covered{};
        };

        void RecordFailure(const ReadResult &read) const;
        void ObserveBytes(uintptr_t address, const uint8_t *bytes, size_t size) const;
        [[nodiscard]] static bool IsCovered(const Block &block, size_t offset, size_t size);
        [[nodiscard]] bool ServeFromBlocks(uintptr_t address, void *buffer, size_t size) const;

        IMemorySource &source_;
        std::function<void(const std::string &)> diagnostic_;
        mutable std::map<uintptr_t, Block> blocks_;
        mutable size_t observedBytes_ = 0;
        mutable bool observing_ = false;
        mutable bool limitExceeded_ = false;
        mutable bool changedDuringRead_ = false;
        mutable std::vector<CaptureValidation::Change> changesDuringRead_;
        mutable uint64_t generation_ = 0;
        mutable size_t readFailures_ = 0;
        mutable std::vector<ReadResult> readFailureSamples_;
    };

    class CaptureObservationScope
    {
    public:
        explicit CaptureObservationScope(const CaptureMemorySource &memory)
            : memory_(memory), previous_(memory.IsObserving()) { memory_.Observe(true); }
        ~CaptureObservationScope() { memory_.Observe(previous_); }
        CaptureObservationScope(const CaptureObservationScope &) = delete;
        CaptureObservationScope &operator=(const CaptureObservationScope &) = delete;

    private:
        const CaptureMemorySource &memory_;
        bool previous_ = false;
    };
} // namespace nextdumper::memory
