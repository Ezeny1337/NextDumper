#pragma once

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace nextdumper::memory
{
    struct ReadTiming
    {
        uint64_t calls = 0;
        uint64_t samples = 0;
        uint64_t nanos = 0;
    };

    // 由会话读取线程独占，仅在 --memory-log 启用时访问，不参与读取决策
    struct ReadPerformance
    {
        static constexpr uint64_t kSampleInterval = 1024;
        ReadTiming transfer, lifecyclePoll, lifecycleStat;
        ReadTiming mappingCheck, cacheLookup, cacheStore, cacheInvalidate, cacheClear;
        ReadTiming captureRead, captureBatch, captureObserve, captureValidate, captureReset;
        ReadTiming reflectionRead, reflectionAttempt, reflectionEnumeration, reflectionFinalize;
        ReadTiming delegateClosure, reflectionEvidence, artifactGeneration;
        ReadTiming runtimeLogFormat, runtimeLogWrite, runtimeLogFlush, runtimeLogClose, consoleOutput;
        ReadTiming performanceLogFormat, performanceLogWrite, performanceLogFlush, diagnosisOutput;
        uint64_t transferWithoutBackend = 0;
        uint64_t transferAllCacheHits = 0;
        // 请求数分桶：0、1、2-4、5-16、17-64、65-128、129-1024
        std::array<uint64_t, 7> transferRequestCounts{};
        std::array<uint64_t, 7> backendVectorCounts{};
        uint64_t lifecycleCalls = 0;
        uint64_t lifecycleInvalidDescriptor = 0;
        uint64_t lifecyclePollSyscalls = 0;
        uint64_t procOpenCalls = 0;
        uint64_t procReadCalls = 0;
        uint64_t procCloseCalls = 0;
        bool pidfdCompiled = false;
        uint64_t pidfdOpenCalls = 0;
        int pidfdOpenError = 0;
        uint64_t captureLookups = 0;
        uint64_t captureHits = 0;
        uint64_t captureHitBytes = 0;
        uint64_t captureInsertedRanges = 0;
        uint64_t captureGrownRanges = 0;
        uint64_t captureOverlapCandidates = 0;
        uint64_t captureOverlapComparisons = 0;
        uint64_t captureOverlapBytes = 0;
        uint64_t captureValidationRanges = 0;
        uint64_t captureValidationBytes = 0;
        uint64_t captureValidationBatches = 0;
        uint64_t captureValidationFallbacks = 0;
    };

    // 高频路径每 1024 次记录一次原始耗时，粗粒度阶段使用 interval=1
    // 关闭时不读时钟，嵌套计时为 inclusive，不能直接相加
    class ScopedReadTiming
    {
    public:
        explicit ScopedReadTiming(ReadTiming *timing, uint64_t interval = ReadPerformance::kSampleInterval) noexcept
        {
            if (timing && timing->calls++ % interval == 0)
            {
                timing_ = timing;
                started_ = Now();
            }
        }
        ~ScopedReadTiming() { Stop(); }
        ScopedReadTiming(const ScopedReadTiming &) = delete;
        ScopedReadTiming &operator=(const ScopedReadTiming &) = delete;

        void Stop() noexcept
        {
            if (!timing_)
                return;
            timing_->nanos += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                        Now() - started_)
                                                        .count());
            ++timing_->samples;
            timing_ = nullptr;
        }

    private:
        static std::chrono::steady_clock::time_point Now() noexcept
        {
            // 调查计时不得覆盖调用方尚未读取的 errno
            const int saved = errno;
            const auto now = std::chrono::steady_clock::now();
            errno = saved;
            return now;
        }
        ReadTiming *timing_ = nullptr;
        std::chrono::steady_clock::time_point started_{};
    };

    [[nodiscard]] inline size_t ReadCountBucket(size_t count)
    {
        if (count <= 1)
            return count;
        if (count <= 4)
            return 2;
        if (count <= 16)
            return 3;
        if (count <= 64)
            return 4;
        if (count <= 128)
            return 5;
        return 6;
    }
} // namespace nextdumper::memory
