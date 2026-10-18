#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <cstring>
#include <span>
#include <string>
#include <type_traits>
#include <sys/types.h>

#include "nextdumper/memory/ProcessInfo.hpp"

namespace nextdumper::memory
{
    enum class ReadError
    {
        None,
        NotInitialized,
        InvalidArgument,
        UnreadableRange,
        PartialRead,
        BackendFailure,
        ProbeLimit,
        AccessDenied,
        TargetExited,
        LimitExceeded,
        Cancelled,
        NotAttempted,
    };

    struct ReadResult
    {
        ReadError error = ReadError::None;
        uintptr_t address = 0;
        size_t requested = 0;
        size_t transferred = 0;
        int systemError = 0;

        [[nodiscard]] bool Ok() const { return error == ReadError::None && transferred == requested; }
    };

    struct ReadRequest
    {
        uintptr_t address = 0;
        void *buffer = nullptr;
        size_t size = 0;
    };

    struct ReadStats
    {
        uint64_t operations = 0;
        uint64_t requestedBytes = 0;
        uint64_t transferredBytes = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
        uint64_t backendOperations = 0;
        uint64_t backendRequestedBytes = 0;
        uint64_t backendTransferredBytes = 0;
        uint64_t failures = 0;
        uint64_t notInitialized = 0;
        uint64_t invalidArguments = 0;
        uint64_t unreadableRanges = 0;
        uint64_t partialReads = 0;
        uint64_t backendFailures = 0;
        uint64_t freshOperations = 0;
        uint64_t batchOperations = 0;
        uint64_t batchRequests = 0;
        uint64_t backendVectors = 0;
        uint64_t maxBatchVectors = 0;
        uint64_t maxBatchBytes = 0;
        uint64_t backendNanos = 0;
        uint64_t minBackendNanos = 0;
        uint64_t maxBackendNanos = 0;
        std::array<uint64_t, 32> latencyBuckets{};
        std::array<uint64_t, 134> errnoCounts{};
        uint64_t cacheHitBytes = 0;
        uint64_t cacheMissBytes = 0;
        uint64_t cacheBytes = 0;
        uint64_t peakCacheBytes = 0;
        uint64_t evictions = 0;
        uint64_t retries = 0;
        uint64_t pageSplits = 0;
        uint64_t mapRefreshes = 0;
        uint64_t targetInvalidations = 0;
        uint64_t cancellations = 0;
    };

    class IMemorySource
    {
    public:
        virtual ~IMemorySource() = default;

        [[nodiscard]] virtual bool IsInitialized() const = 0;
        [[nodiscard]] virtual pid_t ProcessId() const = 0;
        [[nodiscard]] virtual uint64_t AddressSpaceGeneration() const = 0;
        [[nodiscard]] virtual bool RefreshAddressSpace() = 0;
        [[nodiscard]] virtual bool IsReadable(uintptr_t address, size_t size) const = 0;
        [[nodiscard]] virtual bool IsExecutable(uintptr_t address, size_t size) const = 0;
        [[nodiscard]] virtual ReadResult ReadBytes(uintptr_t address, void *buffer, size_t size) const = 0;
        [[nodiscard]] virtual ReadResult ReadFreshBytes(uintptr_t address, void *buffer, size_t size) const = 0;
        [[nodiscard]] virtual const ReadStats &Stats() const = 0;
        [[nodiscard]] virtual std::span<const MemoryRegion> Regions() const { return {}; }
        [[nodiscard]] virtual std::string ProcessName() const { return {}; }
        [[nodiscard]] virtual bool ReadBatch(std::span<const ReadRequest> requests, std::span<ReadResult> results,
                                             bool fresh = false) const
        {
            if (requests.size() != results.size() || requests.size() > 1024)
                return false;
            // 包装源默认逐项调用自身接口，不能绕过 Capture 或 Probe 的约束
            for (size_t index = 0; index < requests.size(); ++index)
            {
                const auto &request = requests[index];
                results[index] = fresh ? ReadFreshBytes(request.address, request.buffer, request.size)
                                       : ReadBytes(request.address, request.buffer, request.size);
            }
            return true;
        }

        template <typename T>
        [[nodiscard]] bool Read(uintptr_t address, T &value) const
        {
            static_assert(std::is_trivially_copyable_v<T>);
            std::array<std::byte, sizeof(T)> bytes{};
            const ReadResult result = ReadBytes(address, bytes.data(), bytes.size());
            if (!result.Ok())
                return false;
            std::memcpy(&value, bytes.data(), sizeof(T));
            return true;
        }
    };
} // namespace nextdumper::memory
