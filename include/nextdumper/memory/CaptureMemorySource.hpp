#pragma once

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

        [[nodiscard]] bool Stable() const
        {
            return !limitExceeded && !generationChanged && changedRanges == 0 && unreadableRanges == 0;
        }
    };

    // 单线程采集视图，只冻结已消费的字节，验证稳定不等于获得原子快照
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

    private:
        static constexpr size_t kMaxRanges = 2 * 1024 * 1024;
        static constexpr size_t kMaxBytes = 64 * 1024 * 1024;
        static constexpr size_t kMaxReadSize = 2048;

        void RecordFailure(const ReadResult &read) const;
        void ObserveBytes(uintptr_t address, const uint8_t *bytes, size_t size) const;

        IMemorySource &source_;
        std::function<void(const std::string &)> diagnostic_;
        mutable std::map<uintptr_t, std::vector<uint8_t>> observations_;
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
