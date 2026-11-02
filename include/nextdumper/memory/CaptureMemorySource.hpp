#pragma once

#include <cstdint>
#include <functional>
#include <map>
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
        size_t allocatedBytes = 0;
        size_t changedRanges = 0;
        size_t unreadableRanges = 0;
        bool limitExceeded = false;
        bool generationChanged = false;
        std::vector<uintptr_t> failedAddresses;
        std::vector<Change> changes;
        size_t readFailures = 0;
        size_t unfrozenReads = 0;
        std::vector<ReadResult> readFailureSamples;

        // 只回答已冻结字节是否一致，覆盖是否完整由 limitExceeded 单独表达
        [[nodiscard]] bool Stable() const
        {
            return !generationChanged && changedRanges == 0 && unreadableRanges == 0;
        }
    };

    // 采集视图：冻结读过的字节，供事后比对目标是否变化
    // 只冻结实际读到的部分，因此校验稳定不等于原子快照，非线程安全
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
        // 单区域跨度上限。区域数取决于被访问的内存簇而非读取次数
        static constexpr size_t kMaxRegionBytes = 64 * 1024;
        // 小于该间隙的相邻读取并入同一区域，更大的空洞只填零却永不比对
        static constexpr uintptr_t kMaxRegionGap = 0x100;
        // 校验要逐字节重读，故该上限同时约束内存与耗时
        static constexpr size_t kMaxObservedBytes = 256 * 1024 * 1024;
        // 单次逻辑批次的传输预算，与冻结无关
        static constexpr size_t kMaxBytes = 64 * 1024 * 1024;
        // 必须覆盖最宽的一次读取：UTF-16 名称上界为 1024 字符
        static constexpr size_t kMaxNameTextBytes = 1024 * sizeof(uint16_t);
        static constexpr size_t kMaxReadSize = 2048;
        static_assert(kMaxReadSize >= kMaxNameTextBytes, "kMaxReadSize 必须覆盖 UTF-16 名称读取");

        // 连续地址范围。covered 逐位标记真正读过的字节，未标记处不参与比对与回放
        struct Region
        {
            uintptr_t base = 0;
            std::vector<uint8_t> bytes;
            std::vector<uint64_t> covered;
        };

        [[nodiscard]] size_t RemainingBudget() const
        {
            return allocatedBytes_ < kMaxObservedBytes ? kMaxObservedBytes - allocatedBytes_ : 0;
        }

        void RecordFailure(const ReadResult &read) const;
        void ObserveBytes(uintptr_t address, const uint8_t *bytes, size_t size) const;
        [[nodiscard]] static bool IsCovered(const Region &region, size_t offset, size_t size);
        [[nodiscard]] Region *FindRegion(uintptr_t address) const;
        [[nodiscard]] bool ServeFromRegion(uintptr_t address, void *buffer, size_t size) const;
        size_t WriteRegion(Region &region, size_t offset, const uint8_t *bytes, size_t size) const;

        IMemorySource &source_;
        std::function<void(const std::string &)> diagnostic_;
        // 按基址升序且互不重叠。erase/emplace 不使其他区域的迭代器失效
        mutable std::map<uintptr_t, Region> regions_;
        // 区域容量之和。覆盖字节数见 observedBytes_
        mutable size_t allocatedBytes_ = 0;
        mutable size_t observedBytes_ = 0;
        mutable bool observing_ = false;
        // 覆盖率不是全量，供上层门禁使用
        mutable bool limitExceeded_ = false;
        // 总量触顶后停冻，否则已冻结内容的采集时刻会横跨整个枚举
        mutable bool freezeStopped_ = false;
        // 未进入冻结集合的读取次数。纯统计量：区域重叠是常规情况，不参与门禁
        mutable size_t unfrozenReads_ = 0;
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
