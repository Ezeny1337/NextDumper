#include "nextdumper/memory/CaptureMemorySource.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <utility>

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
        regions_.clear();
        allocatedBytes_ = 0;
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
        if (source_.IsInitialized() && ServeFromRegion(address, buffer, size))
        {
            if (performance)
            {
                ++performance->captureHits;
                performance->captureHitBytes += size;
            }
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
            if (request.buffer && request.size && ServeFromRegion(request.address, request.buffer, request.size))
            {
                if (performance)
                {
                    ++performance->captureHits;
                    performance->captureHitBytes += request.size;
                }
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

    bool CaptureMemorySource::IsCovered(const Region &region, size_t offset, size_t size)
    {
        if (offset > region.covered.size() * 64 || size > region.covered.size() * 64 - offset)
            return false;
        size_t index = offset;
        // 先处理首尾不完整的字，中间整字判断，避免逐位循环
        while (index < offset + size && index % 64 != 0)
        {
            if ((region.covered[index / 64] & (uint64_t{1} << (index % 64))) == 0)
                return false;
            ++index;
        }
        while (index + 64 <= offset + size)
        {
            if (region.covered[index / 64] != ~uint64_t{0})
                return false;
            index += 64;
        }
        while (index < offset + size)
        {
            if ((region.covered[index / 64] & (uint64_t{1} << (index % 64))) == 0)
                return false;
            ++index;
        }
        return true;
    }

    // 只有请求范围内每个字节都已冻结时才从区域取值
    // 部分覆盖必须回落到真实读取，否则会把未观测的字节补成零
    bool CaptureMemorySource::ServeFromRegion(uintptr_t address, void *buffer, size_t size) const
    {
        if (!buffer || !size || address + size < address)
            return false;
        // regions_ 按 base 升序且互不重叠，落在某个区域内时其 base 必然是不大于 address 的最大值
        const auto found = std::upper_bound(regions_.begin(), regions_.end(), address,
                                            [](uintptr_t value, const Region &region)
                                            { return value < region.base; });
        if (found == regions_.begin())
            return false;
        const Region &region = *std::prev(found);
        if (address - region.base >= region.bytes.size() || size > region.bytes.size() - (address - region.base))
            return false;
        const size_t offset = static_cast<size_t>(address - region.base);
        if (!IsCovered(region, offset, size))
            return false;
        std::memcpy(buffer, region.bytes.data() + offset, size);
        return true;
    }

    void CaptureMemorySource::ObserveBytes(uintptr_t address, const uint8_t *bytes, size_t size) const
    {
        auto *performance = Performance();
        ScopedReadTiming timing(performance ? &performance->captureObserve : nullptr);
        // 超出预算只停止冻结新的字节，读取本身已经成功
        // 据此中断调用方会把内存护栏变成采集中止条件，使余下对象永远无法枚举
        if (size > kMaxReadSize || address + size < address)
        {
            limitExceeded_ = true;
            return;
        }
        // 区域基址按 64 字节对齐，使覆盖位图中的整字可以直接搬运
        const uintptr_t first = address - address % 64;
        const uintptr_t last = (address + size + 63) / 64 * 64;
        // 定位可能与新区间相接或重叠的区域，把间隙不超过上限的相邻区域一并并入
        auto begin = std::upper_bound(regions_.begin(), regions_.end(), first,
                                      [](uintptr_t value, const Region &region)
                                      { return value < region.base; });
        if (begin != regions_.begin())
        {
            const auto preceding = std::prev(begin);
            if (first - preceding->base <= preceding->bytes.size() + kMaxRegionGap)
                begin = preceding;
        }
        const uintptr_t newBase = begin != regions_.end() ? std::min(first, begin->base) : first;
        uintptr_t newEnd = last;
        auto end = begin;
        while (end != regions_.end())
        {
            // 与当前合并范围只有小间隙的区域才并入,更大间隙留给独立区域
            const uintptr_t gap = end->base > newEnd ? end->base - newEnd : 0;
            if (gap > kMaxRegionGap)
                break;
            newEnd = std::max(newEnd, end->base + end->bytes.size());
            ++end;
        }
        // 合并后仍超出单区域上限时放弃冻结：拆分会破坏相邻读取共享一条记录的意图
        if (newEnd - newBase > kMaxRegionBytes)
        {
            limitExceeded_ = true;
            return;
        }
        // 预算按合并后的净增量检查：被并入的旧区域会随合并释放
        size_t replaced = 0;
        for (auto item = begin; item != end; ++item)
            replaced += item->bytes.size();
        const size_t grown = static_cast<size_t>(newEnd - newBase);
        if (grown > replaced && grown - replaced > kMaxObservedBytes - allocatedBytes_)
        {
            limitExceeded_ = true;
            return;
        }
        // 新区间只覆盖已被真实读取的字节,其余位置保持未覆盖，不参与比较或回放
        Region merged;
        merged.base = newBase;
        merged.bytes.assign(static_cast<size_t>(newEnd - newBase), 0);
        merged.covered.assign((merged.bytes.size() + 63) / 64, 0);
        for (auto item = begin; item != end; ++item)
        {
            const size_t offset = static_cast<size_t>(item->base - newBase);
            std::copy(item->bytes.begin(), item->bytes.end(), merged.bytes.begin() + static_cast<ptrdiff_t>(offset));
            std::copy(item->covered.begin(), item->covered.end(),
                      merged.covered.begin() + static_cast<ptrdiff_t>(offset / 64));
        }
        const size_t offset = static_cast<size_t>(address - newBase);
        size_t fresh = 0;
        for (size_t index = 0; index < size; ++index)
        {
            const size_t position = offset + index;
            const uint64_t bit = uint64_t{1} << (position % 64);
            if (merged.covered[position / 64] & bit)
            {
                // 同一批内的重叠读取逐字节验证：冻结内容必须与本次读到的一致
                if (merged.bytes[position] == bytes[index])
                    continue;
                changedDuringRead_ = true;
                if (changesDuringRead_.size() < 8)
                {
                    CaptureValidation::Change change;
                    change.address = address + index;
                    change.size = 1;
                    change.read = {ReadError::None, address + index, 1, 1};
                    change.before.assign(1, merged.bytes[position]);
                    change.after.assign(1, bytes[index]);
                    changesDuringRead_.push_back(std::move(change));
                }
                if (diagnostic_)
                    diagnostic_("capture_overlap_change address=" + Hex(address + index) + " size=1");
            }
            merged.covered[position / 64] |= bit;
            merged.bytes[position] = bytes[index];
            ++fresh;
        }
        if (performance)
        {
            if (end == begin)
                ++performance->captureInsertedRanges;
            else if (fresh)
                ++performance->captureGrownRanges;
        }
        // 旧区域的字节被并进 merged，先归还可分配量再计入新占用
        for (auto item = begin; item != end; ++item)
            allocatedBytes_ -= item->bytes.size();
        allocatedBytes_ += merged.bytes.size();
        observedBytes_ += fresh;
        regions_.erase(begin, end);
        regions_.insert(std::upper_bound(regions_.begin(), regions_.end(), merged.base,
                                         [](uintptr_t value, const Region &region)
                                         { return value < region.base; }),
                        std::move(merged));
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
            performance->captureValidationRanges += regions_.size();
            performance->captureValidationBytes += observedBytes_;
        }
        CaptureValidation result;
        result.observedRanges = regions_.size();
        result.observedBytes = observedBytes_;
        result.limitExceeded = limitExceeded_;
        result.generationChanged = generation_ != source_.AddressSpaceGeneration();
        result.changedRanges = changedDuringRead_ ? 1 : 0;
        result.changes = changesDuringRead_;
        result.readFailures = readFailures_;
        result.readFailureSamples = readFailureSamples_;
        if (regions_.empty())
        {
            result.generationChanged = result.generationChanged || generation_ != source_.AddressSpaceGeneration();
            return result;
        }
        constexpr size_t maxBatchSize = 64 * 1024;
        constexpr size_t maxGap = 64;
        constexpr size_t kBatchRegions = 8;
        const auto compare = [&](uintptr_t address, const uint8_t *expected, size_t size,
                                 const uint8_t *data, const ReadResult &read)
        {
            if (!read.Ok())
                ++result.unreadableRanges;
            else if (std::memcmp(data, expected, size) != 0)
                ++result.changedRanges;
            else
                return;
            if (diagnostic_)
                diagnostic_("capture_validation_range address=" + Hex(address) +
                            " size=" + std::to_string(size) +
                            " changed=" + std::to_string(read.Ok()) +
                            " error=" + std::to_string(static_cast<int32_t>(read.error)) +
                            " requested=" + std::to_string(read.requested) +
                            " transferred=" + std::to_string(read.transferred));
            if (result.failedAddresses.size() < 8)
                result.failedAddresses.push_back(address);
            if (result.changes.size() < 8)
            {
                const size_t sampleSize = std::min<size_t>(size, 16);
                CaptureValidation::Change change;
                change.address = address;
                change.size = size;
                change.read = read;
                change.before.assign(expected, expected + sampleSize);
                if (read.Ok())
                    change.after.assign(data, data + sampleSize);
                result.changes.push_back(std::move(change));
            }
        };
        // 只比较已冻结的字节
        // 覆盖区可能被未读字节分隔成多段，必须逐段比较
        const auto compareRegion = [&](const Region &region, const uint8_t *data, const ReadResult &read)
        {
            size_t index = 0;
            while (index < region.bytes.size())
            {
                while (index < region.bytes.size() && (region.covered[index / 64] & (uint64_t{1} << (index % 64))) == 0)
                    ++index;
                const size_t begin = index;
                while (index < region.bytes.size() && (region.covered[index / 64] & (uint64_t{1} << (index % 64))) != 0)
                    ++index;
                if (begin == index)
                    break;
                // 诊断字段跟随被比较的区间，而不是整段起点
                ReadResult aligned = read;
                aligned.address = region.base + begin;
                aligned.requested = index - begin;
                if (read.Ok())
                    aligned.transferred = index - begin;
                compare(region.base + begin, region.bytes.data() + begin, index - begin, data + begin, aligned);
            }
        };
        std::array<ReadRequest, kBatchRegions> requests{};
        std::array<ReadResult, kBatchRegions> reads{};
        // 每个批次记录首尾区域下标，回放时据此确定批内包含的区域
        std::array<std::pair<size_t, size_t>, kBatchRegions> batches{};
        std::vector<uint8_t> current;
        current.resize(maxBatchSize * kBatchRegions);
        for (size_t index = 0; index < regions_.size();)
        {
            size_t count = 0;
            while (count < kBatchRegions && index < regions_.size())
            {
                const size_t begin = index;
                const uintptr_t start = regions_[begin].base;
                size_t span = regions_[begin].bytes.size();
                size_t end = begin + 1;
                // 相邻区域常落在同一页内，合并成一次读取以减少系统调用
                while (end < regions_.size())
                {
                    const Region &next = regions_[end];
                    const uintptr_t offset = next.base - start;
                    if (offset > maxBatchSize || next.bytes.size() > maxBatchSize - offset ||
                        (offset > span && offset - span > maxGap))
                        break;
                    span = std::max(span, static_cast<size_t>(offset) + next.bytes.size());
                    ++end;
                }
                requests[count] = {start, current.data() + count * maxBatchSize, span};
                batches[count] = {begin, end};
                ++count;
                index = end;
            }
            if (performance)
                ++performance->captureValidationBatches;
            if (!source_.ReadBatch({requests.data(), count}, {reads.data(), count}, true))
                throw std::runtime_error("Capture validation batch contract failed");
            for (size_t batch = 0; batch < count; ++batch)
            {
                const uint8_t *data = current.data() + batch * maxBatchSize;
                const uintptr_t start = requests[batch].address;
                for (size_t item = batches[batch].first; item < batches[batch].second; ++item)
                {
                    const Region &region = regions_[item];
                    if (reads[batch].Ok())
                        compareRegion(region, data + (region.base - start),
                                      {ReadError::None, region.base, region.bytes.size(), region.bytes.size()});
                    else
                    {
                        if (performance)
                            ++performance->captureValidationFallbacks;
                        std::vector<uint8_t> exact(region.bytes.size());
                        const auto read = source_.ReadFreshBytes(region.base, exact.data(), exact.size());
                        compareRegion(region, exact.data(), read);
                    }
                }
            }
        }
        result.generationChanged = result.generationChanged || generation_ != source_.AddressSpaceGeneration();
        return result;
    }
} // namespace nextdumper::memory
