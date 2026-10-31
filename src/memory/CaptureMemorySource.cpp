#include "nextdumper/memory/CaptureMemorySource.hpp"

#include <algorithm>
#include <cstring>
#include <array>
#include <stdexcept>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::memory
{
    namespace
    {
        using ::nextdumper::common::Hex;
    }

    void CaptureMemorySource::Reset() const
    {
        auto *performance = Performance();
        ScopedReadTiming timing(performance ? &performance->captureReset : nullptr, 1);
        observations_.clear();
        observationsDisjoint_ = true;
        observedBytes_ = 0;
        observing_ = false;
        limitExceeded_ = false;
        changedDuringRead_ = false;
        changesDuringRead_.clear();
        generation_ = source_.AddressSpaceGeneration();
        readFailures_ = 0;
        readFailureSamples_.clear();
    }

    void CaptureMemorySource::RecordFailure(const ReadResult &read) const
    {
        if (read.Ok())
            return;
        ++readFailures_;
        if (readFailureSamples_.size() < 16)
            readFailureSamples_.push_back(read);
        if (diagnostic_)
            diagnostic_("capture_read_failure address=" + Hex(read.address) +
                        " error=" + std::to_string(static_cast<int32_t>(read.error)) +
                        " requested=" + std::to_string(read.requested) + " transferred=" + std::to_string(read.transferred) +
                        " errno=" + std::to_string(read.systemError));
    }

    ReadResult CaptureMemorySource::ReadFreshBytes(uintptr_t address, void *buffer, size_t size) const
    {
        const auto read = source_.ReadFreshBytes(address, buffer, size);
        RecordFailure(read);
        return read;
    }

    ReadResult CaptureMemorySource::ReadBytes(uintptr_t address, void *buffer, size_t size) const
    {
        auto *performance = Performance();
        ScopedReadTiming timing(performance ? &performance->captureRead : nullptr);
        if (!observing_ || !buffer || !size)
            return ReadFreshBytes(address, buffer, size);
        if (generation_ != source_.AddressSpaceGeneration())
        {
            changedDuringRead_ = true;
            const ReadResult read{ReadError::AddressSpaceChanged, address, size, 0};
            RecordFailure(read);
            return read;
        }
        if (performance)
            ++performance->captureLookups;
        const auto previous = observations_.find(address);
        if (source_.IsInitialized() && previous != observations_.end() && previous->second.size() >= size)
        {
            if (performance)
            {
                ++performance->captureHits;
                performance->captureHitBytes += size;
            }
            std::memcpy(buffer, previous->second.data(), size);
            return {ReadError::None, address, size, size};
        }
        const auto read = ReadFreshBytes(address, buffer, size);
        if (read.Ok())
            ObserveBytes(address, static_cast<const uint8_t *>(buffer), size);
        return read;
    }

    bool CaptureMemorySource::ReadBatch(std::span<const ReadRequest> requests, std::span<ReadResult> results, bool fresh) const
    {
        auto *performance = Performance();
        ScopedReadTiming timing(performance ? &performance->captureBatch : nullptr);
        if (requests.size() != results.size() || requests.size() > 1024)
            return false;
        size_t total = 0;
        for (const auto &request : requests)
        {
            if (request.size > kMaxBytes - total)
            {
                // 拆分内部批次不能绕过逻辑批次的总字节预算
                for (size_t index = 0; index < requests.size(); ++index)
                {
                    results[index] = {ReadError::LimitExceeded, requests[index].address, requests[index].size, 0};
                    RecordFailure(results[index]);
                }
                return true;
            }
            total += request.size;
        }
        if (fresh || !observing_)
        {
            if (!source_.ReadBatch(requests, results, true))
                return false;
            for (const auto &result : results)
                RecordFailure(result);
            return true;
        }
        const bool changed = generation_ != source_.AddressSpaceGeneration();
        if (changed)
            changedDuringRead_ = true;
        std::array<ReadRequest, 128> pending{};
        std::array<ReadResult, 128> reads{};
        std::array<size_t, 128> owners{};
        size_t count = 0;
        const auto flush = [&]()
        {
            if (!count)
                return;
            if (!source_.ReadBatch({pending.data(), count}, {reads.data(), count}, true))
                throw std::runtime_error("Capture batch contract failed");
            for (size_t index = 0; index < count; ++index)
            {
                results[owners[index]] = reads[index];
                RecordFailure(reads[index]);
                if (reads[index].Ok())
                    ObserveBytes(pending[index].address,
                                 static_cast<const uint8_t *>(pending[index].buffer), pending[index].size);
            }
            count = 0;
        };
        for (size_t index = 0; index < requests.size(); ++index)
        {
            const auto &request = requests[index];
            results[index] = {ReadError::None, request.address, request.size, 0};
            if (changed || !source_.IsInitialized())
            {
                results[index].error = changed ? ReadError::AddressSpaceChanged : ReadError::NotInitialized;
                RecordFailure(results[index]);
                continue;
            }
            if (performance)
                ++performance->captureLookups;
            const auto previous = observations_.find(request.address);
            if (request.buffer && request.size && previous != observations_.end() && previous->second.size() >= request.size)
            {
                if (performance)
                {
                    ++performance->captureHits;
                    performance->captureHitBytes += request.size;
                }
                std::memcpy(request.buffer, previous->second.data(), request.size);
                results[index].transferred = request.size;
                continue;
            }
            pending[count] = request;
            owners[count++] = index;
            if (count == pending.size())
                flush();
        }
        flush();
        return true;
    }

    void CaptureMemorySource::ObserveBytes(uintptr_t address, const uint8_t *bytes, size_t size) const
    {
        auto *performance = Performance();
        ScopedReadTiming timing(performance ? &performance->captureObserve : nullptr);
        const auto position = observations_.lower_bound(address);
        const auto previous = position != observations_.end() && position->first == address ? position : observations_.end();
        const size_t previousSize = previous == observations_.end() ? 0 : previous->second.size();
        // 同一批内的重叠请求也逐项验证，不能冻结从未同时成立的字节
        // 超出预算只停止冻结新的范围，读取本身已经成功
        // 据此中断调用方会把内存护栏变成采集中止条件，使余下对象永远无法枚举
        if (size > kMaxReadSize || (size > previousSize && size - previousSize > kMaxBytes - observedBytes_) ||
            (previous == observations_.end() && observations_.size() >= kMaxRanges))
        {
            limitExceeded_ = true;
            return;
        }
        auto overlap = position;
        if (observationsDisjoint_)
        {
            // 互不重叠时，起点之前最多只有直接前驱可能覆盖本次读取
            if (overlap != observations_.begin())
            {
                const auto preceding = std::prev(overlap);
                if (address - preceding->first < preceding->second.size())
                    overlap = preceding;
            }
        }
        else
        {
            // 存在嵌套范围后不能只看前驱，继续使用由最大读取长度限定的完整扫描
            const uintptr_t first = address >= kMaxReadSize ? address - kMaxReadSize : 0;
            overlap = observations_.lower_bound(first);
        }
        bool crossOverlap = false;
        for (; overlap != observations_.end(); ++overlap)
        {
            if (overlap->first >= address && overlap->first - address >= size)
                break;
            if (performance)
                ++performance->captureOverlapCandidates;
            const uintptr_t start = std::max(address, overlap->first);
            const size_t oldOffset = static_cast<size_t>(start - overlap->first), newOffset = static_cast<size_t>(start - address);
            if (oldOffset >= overlap->second.size() || newOffset >= size)
                continue;
            const size_t length = std::min(overlap->second.size() - oldOffset, size - newOffset);
            crossOverlap = crossOverlap || overlap->first != address;
            if (performance)
            {
                ++performance->captureOverlapComparisons;
                performance->captureOverlapBytes += length;
            }
            if (std::memcmp(bytes + newOffset, overlap->second.data() + oldOffset, length) == 0)
                continue;
            changedDuringRead_ = true;
            if (diagnostic_)
                diagnostic_("capture_overlap_change address=" + Hex(start) + " size=" + std::to_string(length));
            if (changesDuringRead_.size() < 8)
            {
                const size_t sampleSize = std::min<size_t>(length, 16);
                CaptureValidation::Change change;
                change.address = start;
                change.size = length;
                change.read = {ReadError::None, start, length, length};
                change.before.assign(overlap->second.data() + oldOffset, overlap->second.data() + oldOffset + sampleSize);
                change.after.assign(bytes + newOffset, bytes + newOffset + sampleSize);
                changesDuringRead_.push_back(std::move(change));
            }
        }
        // 已观测的较长范围不能被同批中的较短请求截断
        if (size >= previousSize)
        {
            if (previous == observations_.end())
                observations_.emplace_hint(position, address, std::vector<uint8_t>(bytes, bytes + size));
            else
                previous->second.assign(bytes, bytes + size);
            observationsDisjoint_ = observationsDisjoint_ && !crossOverlap;
            if (performance)
            {
                if (previousSize == 0)
                    ++performance->captureInsertedRanges;
                else if (size > previousSize)
                    ++performance->captureGrownRanges;
            }
            observedBytes_ += size - previousSize;
        }
    }

    bool CaptureMemorySource::RefreshAddressSpace()
    {
        const bool refreshed = source_.RefreshAddressSpace();
        Reset();
        return refreshed;
    }

    CaptureValidation CaptureMemorySource::Validate() const
    {
        auto *performance = Performance();
        ScopedReadTiming timing(performance ? &performance->captureValidate : nullptr, 1);
        if (performance)
        {
            performance->captureValidationRanges += observations_.size();
            performance->captureValidationBytes += observedBytes_;
        }
        CaptureValidation result;
        result.observedRanges = observations_.size();
        result.observedBytes = observedBytes_;
        result.limitExceeded = limitExceeded_;
        result.generationChanged = generation_ != source_.AddressSpaceGeneration();
        result.changedRanges = changedDuringRead_ ? 1 : 0;
        result.changes = changesDuringRead_;
        result.readFailures = readFailures_;
        result.readFailureSamples = readFailureSamples_;
        if (observations_.empty())
        {
            result.generationChanged = result.generationChanged || generation_ != source_.AddressSpaceGeneration();
            return result;
        }
        constexpr size_t maxBatchSize = 64 * 1024;
        constexpr size_t maxGap = 64;
        std::vector<uint8_t> current;
        const auto compare = [&](uintptr_t address, const std::vector<uint8_t> &bytes,
                                 const uint8_t *data, const ReadResult &read)
        {
            if (!read.Ok())
                ++result.unreadableRanges;
            else if (std::memcmp(data, bytes.data(), bytes.size()) != 0)
                ++result.changedRanges;
            else
                return;
            if (diagnostic_)
                diagnostic_("capture_validation_range address=" + Hex(address) +
                            " size=" + std::to_string(bytes.size()) +
                            " changed=" + std::to_string(read.Ok()) +
                            " error=" + std::to_string(static_cast<int32_t>(read.error)) +
                            " requested=" + std::to_string(read.requested) +
                            " transferred=" + std::to_string(read.transferred));
            if (result.failedAddresses.size() < 8)
                result.failedAddresses.push_back(address);
            if (result.changes.size() < 8)
            {
                const size_t sampleSize = std::min<size_t>(bytes.size(), 16);
                CaptureValidation::Change change;
                change.address = address;
                change.size = bytes.size();
                change.read = read;
                change.before.assign(bytes.begin(), bytes.begin() + sampleSize);
                if (read.Ok())
                    change.after.assign(data, data + sampleSize);
                result.changes.push_back(std::move(change));
            }
        };
        using Iterator = decltype(observations_)::const_iterator;
        struct BatchRange
        {
            Iterator first;
            Iterator last;
            uintptr_t start;
        };
        std::array<BatchRange, 16> ranges{};
        std::array<ReadRequest, 16> requests{};
        std::array<ReadResult, 16> reads{};
        current.resize(maxBatchSize * ranges.size());
        for (auto first = observations_.cbegin(); first != observations_.cend();)
        {
            size_t count = 0;
            while (count < ranges.size() && first != observations_.cend())
            {
                auto last = std::next(first);
                const uintptr_t start = first->first;
                size_t span = first->second.size();
                while (last != observations_.cend())
                {
                    const uintptr_t offset = last->first - start;
                    if (offset > maxBatchSize || last->second.size() > maxBatchSize - offset ||
                        (offset > span && offset - span > maxGap))
                        break;
                    span = std::max(span, static_cast<size_t>(offset) + last->second.size());
                    ++last;
                }
                ranges[count] = {first, last, start};
                requests[count] = {start, current.data() + count * maxBatchSize, span};
                ++count;
                first = last;
            }
            if (performance)
                ++performance->captureValidationBatches;
            if (!source_.ReadBatch({requests.data(), count}, {reads.data(), count}, true))
                throw std::runtime_error("Capture validation batch contract failed");
            for (size_t index = 0; index < count; ++index)
            {
                const auto &range = ranges[index];
                for (auto item = range.first; item != range.last; ++item)
                {
                    const auto &[address, bytes] = *item;
                    if (reads[index].Ok())
                    {
                        // 间隙只参与传输，不参与冻结或比较
                        compare(address, bytes, current.data() + index * maxBatchSize + (address - range.start),
                                {ReadError::None, address, bytes.size(), bytes.size()});
                    }
                    else
                    {
                        if (performance)
                            ++performance->captureValidationFallbacks;
                        std::vector<uint8_t> exact(bytes.size());
                        const auto read = source_.ReadFreshBytes(address, exact.data(), bytes.size());
                        compare(address, bytes, exact.data(), read);
                    }
                }
            }
        }
        result.generationChanged = result.generationChanged || generation_ != source_.AddressSpaceGeneration();
        return result;
    }
} // namespace nextdumper::memory
