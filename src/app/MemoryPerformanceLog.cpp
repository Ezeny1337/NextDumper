#include "nextdumper/app/MemoryPerformanceLog.hpp"

#include <cerrno>
#include <fcntl.h>
#include <iomanip>
#include <locale>
#include <new>
#include <sstream>

#if defined(_WIN32)
#include <io.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#endif

#include "nextdumper/memory/ReadDiagnostics.hpp"
#include "nextdumper/memory/RemoteMemorySource.hpp"

namespace nextdumper::app
{
    namespace
    {
        void String(std::ostream &out, std::string_view text)
        {
            static constexpr char hex[] = "0123456789ABCDEF";
            out << '"';
            for (const unsigned char ch : text)
            {
                if (ch == '"' || ch == '\\')
                    out << '\\' << static_cast<char>(ch);
                else if (ch < 0x20 || ch >= 0x7f)
                    out << "\\u00" << hex[ch >> 4] << hex[ch & 15];
                else
                    out << static_cast<char>(ch);
            }
            out << '"';
        }

        void Ratio(std::ostream &out, uint64_t numerator, uint64_t denominator, double scale = 1.0)
        {
            if (!denominator)
                out << "null";
            else
                out << static_cast<double>(numerator) / static_cast<double>(denominator) * scale;
        }

        void Quantile(std::ostream &out, const memory::ReadStats &stats, uint64_t percentile)
        {
            if (!stats.backendOperations)
            {
                out << "null";
                return;
            }
            const uint64_t rank = stats.backendOperations / 100 * percentile +
                                  (stats.backendOperations % 100 * percentile + 99) / 100;
            uint64_t count = 0;
            for (size_t index = 0; index < stats.latencyBuckets.size(); ++index)
            {
                count += stats.latencyBuckets[index];
                if (count >= rank)
                {
                    if (index == stats.latencyBuckets.size() - 1)
                        out << "null";
                    else
                        out << ((uint64_t{1} << index) - 1);
                    return;
                }
            }
            out << "null";
        }
    }

    MemoryPerformanceLog::~MemoryPerformanceLog()
    {
        if (file_ && !Close())
            std::fprintf(stderr, "Memory performance log close failed: errno=%d\n", error_);
    }

    bool MemoryPerformanceLog::Open(const std::string &path, const generation::ArtifactProvenance &provenance,
                                    std::chrono::steady_clock::time_point started) noexcept
    {
        if (file_ && !Close())
            return false;
        failed_ = false;
        error_ = 0;
        started_ = started;
        lastSnapshot_ = {};
        try
        {
            provenance_ = provenance;
#if defined(_WIN32)
            const int fd = _open(path.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT,
                                 _S_IREAD | _S_IWRITE);
#else
            const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
#endif
            if (fd < 0)
            {
                error_ = errno;
                failed_ = true;
                return false;
            }
#if defined(_WIN32)
            file_ = _fdopen(fd, "wb");
#else
            file_ = fdopen(fd, "wb");
#endif
            if (!file_)
            {
                error_ = errno;
                failed_ = true;
#if defined(_WIN32)
                const int closed = _close(fd);
#else
                const int closed = close(fd);
#endif
                if (closed != 0)
                    std::fprintf(stderr, "Memory log descriptor close failed: errno=%d\n", errno);
                return false;
            }
            return true;
        }
        catch (...)
        {
            error_ = ENOMEM;
            failed_ = true;
            return false;
        }
    }

    void MemoryPerformanceLog::Write(std::string_view event, std::string_view stage,
                                     const memory::RemoteMemorySource &memory,
                                     std::string_view architecture, std::string_view status) noexcept
    {
        if (!file_ || failed_)
            return;
        const auto now = std::chrono::steady_clock::now();
        if (event == "snapshot" && now - lastSnapshot_ < std::chrono::seconds(1))
            return;
        lastSnapshot_ = now;
        try
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - started_).count();
            const auto &stats = memory.Stats();
            std::ostringstream out;
            out.imbue(std::locale::classic());
            out.exceptions(std::ios::badbit | std::ios::failbit);
            out << std::setprecision(10) << "{\"format_version\":1,\"event\":";
            String(out, event);
            out << ",\"stage\":";
            String(out, stage);
            out << ",\"status\":";
            String(out, status);
            out << ",\"run_id\":";
            String(out, provenance_.runId);
            out << ",\"run_timestamp\":";
            String(out, provenance_.runTimestamp);
            out << ",\"producer_commit\":";
            String(out, provenance_.producerCommit);
            out << ",\"producer_version\":";
            String(out, provenance_.producerVersion);
            out << ",\"producer_worktree_at_configure\":";
            String(out, provenance_.producerWorktree);
            out << ",\"backend\":\"process_vm_readv\",\"pid\":" << memory.ProcessId();
            out << ",\"process_start_time_ticks\":" << memory.Identity().startTime;
            out << ",\"process_name\":";
            String(out, memory.Identity().name);
            out << ",\"architecture\":";
            String(out, architecture);
            out << ",\"reader_pointer_width\":" << sizeof(uintptr_t)
                << ",\"page_size\":" << memory.PageSize()
                << ",\"last_errno\":" << memory.LastError()
                << ",\"address_space_generation\":" << memory.AddressSpaceGeneration()
                << ",\"elapsed_ns\":" << elapsed
                << ",\"limits\":{\"request_bytes\":" << memory::RemoteMemorySource::kMaxRequestBytes
                << ",\"batch_requests\":" << memory::RemoteMemorySource::kMaxBatchRequests
                << ",\"transfer_bytes\":" << memory::RemoteMemorySource::kMaxTransferBytes
                << ",\"vectors\":" << memory::RemoteMemorySource::kMaxVectors
                << ",\"effective_vectors\":" << memory.VectorLimit()
                << ",\"cache_bytes\":" << memory.CacheCapacity()
                << ",\"cooperative_transfer_deadline_ms\":5000,\"syscalls_per_transfer\":4096}"
                << ",\"operations\":" << stats.operations
                << ",\"requested_bytes\":" << stats.requestedBytes
                << ",\"transferred_bytes\":" << stats.transferredBytes
                << ",\"fresh_operations\":" << stats.freshOperations
                << ",\"batch_operations\":" << stats.batchOperations
                << ",\"batch_requests\":" << stats.batchRequests
                << ",\"cache_hits\":" << stats.cacheHits
                << ",\"cache_misses\":" << stats.cacheMisses
                << ",\"cache_hit_bytes\":" << stats.cacheHitBytes
                << ",\"cache_miss_bytes\":" << stats.cacheMissBytes
                << ",\"cache_bytes\":" << stats.cacheBytes
                << ",\"peak_cache_bytes\":" << stats.peakCacheBytes
                << ",\"evictions\":" << stats.evictions
                << ",\"backend_operations\":" << stats.backendOperations
                << ",\"backend_vectors\":" << stats.backendVectors
                << ",\"backend_requested_bytes\":" << stats.backendRequestedBytes
                << ",\"backend_transferred_bytes\":" << stats.backendTransferredBytes
                << ",\"backend_nanos\":" << stats.backendNanos
                << ",\"backend_min_nanos\":" << stats.minBackendNanos
                << ",\"backend_max_nanos\":" << stats.maxBackendNanos
                << ",\"max_batch_vectors\":" << stats.maxBatchVectors
                << ",\"max_batch_bytes\":" << stats.maxBatchBytes
                << ",\"page_splits\":" << stats.pageSplits
                << ",\"retries\":" << stats.retries
                << ",\"map_refreshes\":" << stats.mapRefreshes
                << ",\"target_invalidations\":" << stats.targetInvalidations
                << ",\"cancellations\":" << stats.cancellations
                << ",\"failures\":" << stats.failures
                << ",\"not_initialized\":" << stats.notInitialized
                << ",\"invalid_arguments\":" << stats.invalidArguments
                << ",\"unreadable_ranges\":" << stats.unreadableRanges
                << ",\"partial_reads\":" << stats.partialReads
                << ",\"backend_failures\":" << stats.backendFailures
                << ",\"logical_bytes_per_wall_second\":";
            Ratio(out, stats.transferredBytes, static_cast<uint64_t>(elapsed), 1e9);
            out << ",\"backend_bytes_per_syscall_second\":";
            Ratio(out, stats.backendTransferredBytes, stats.backendNanos, 1e9);
            out << ",\"mean_syscall_ns\":";
            Ratio(out, stats.backendNanos, stats.backendOperations);
            out << ",\"mean_vectors_per_syscall\":";
            Ratio(out, stats.backendVectors, stats.backendOperations);
            out << ",\"mean_requested_bytes_per_syscall\":";
            Ratio(out, stats.backendRequestedBytes, stats.backendOperations);
            out << ",\"cache_hit_ratio\":";
            Ratio(out, stats.cacheHits, stats.cacheHits + stats.cacheMisses);
            out << ",\"request_failure_ratio\":";
            Ratio(out, stats.failures, stats.operations);
            out << ",\"read_amplification\":";
            Ratio(out, stats.backendRequestedBytes, stats.requestedBytes);
            out << ",\"p50_syscall_ns_upper_bound\":";
            Quantile(out, stats, 50);
            out << ",\"p95_syscall_ns_upper_bound\":";
            Quantile(out, stats, 95);
            out << ",\"p99_syscall_ns_upper_bound\":";
            Quantile(out, stats, 99);
            out << ",\"latency_buckets\":[";
            for (size_t index = 0; index < stats.latencyBuckets.size(); ++index)
                out << (index ? "," : "") << stats.latencyBuckets[index];
            out << "],\"errno_counts\":[";
            for (size_t index = 0; index < stats.errnoCounts.size(); ++index)
                out << (index ? "," : "") << stats.errnoCounts[index];
            out << "],\"error_samples\":[";
            bool first = true;
            for (const auto &sample : memory.ErrorSamples())
            {
                out << (first ? "" : ",") << "{\"error\":";
                String(out, memory::ReadErrorName(sample.error));
                out << ",\"errno\":" << sample.systemError << ",\"requested_bytes\":" << sample.requested
                    << ",\"transferred_bytes\":" << sample.transferred << '}';
                first = false;
            }
            if (event == "session_start")
                out << "],\"metric_notes\":{\"scope\":\"cumulative per initialization; snapshots are cooperative\""
                       ",\"transferred_bytes\":\"logical delivered bytes, including partial results and cache hits\""
                       ",\"read_amplification\":\"backend requested bytes / logical requested bytes; includes retries\""
                       ",\"latency_buckets\":\"0: zero ns; i=1..30: [2^(i-1), 2^i-1] ns; 31: >=2^30 ns\""
                       ",\"errno_counts\":\"index is errno; last index includes all greater errno values\""
                       ",\"ratios\":\"null when denominator is zero\""
                       ",\"quantiles\":\"histogram upper bounds; null for no samples or saturated bucket\""
                       ",\"session_end\":\"status before final performance-log write/close; close failure is reported by CLI\"}}";
            else
                out << "]}";
            out << '\n';
            const std::string line = out.str();
            errno = 0;
            if (std::fwrite(line.data(), 1, line.size(), file_) != line.size() || std::fflush(file_) != 0)
            {
                error_ = errno ? errno : EIO;
                failed_ = true;
            }
        }
        catch (const std::bad_alloc &)
        {
            error_ = ENOMEM;
            failed_ = true;
        }
        catch (...)
        {
            error_ = EIO;
            failed_ = true;
        }
    }

    bool MemoryPerformanceLog::Close() noexcept
    {
        if (file_)
        {
            std::FILE *owned = file_;
            file_ = nullptr;
            if (std::fclose(owned) != 0)
            {
                error_ = errno ? errno : EIO;
                failed_ = true;
            }
        }
        return !failed_;
    }
} // namespace nextdumper::app
