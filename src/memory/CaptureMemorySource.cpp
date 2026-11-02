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
        freezeStopped_ = false;
        unfrozenReads_ = 0;
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

    // 返回包含 address 的区域，区域按基址升序且互不重叠
    CaptureMemorySource::Region *CaptureMemorySource::FindRegion(uintptr_t address) const
    {
        auto found = regions_.upper_bound(address);
        if (found == regions_.begin())
            return nullptr;
        --found;
        Region &region = found->second;
        return address - region.base < region.bytes.size() ? &region : nullptr;
    }

    // 只有请求范围内每个字节都已冻结时才从区域取值
    // 部分覆盖必须回落到真实读取，否则会把未观测的字节补成零
    bool CaptureMemorySource::ServeFromRegion(uintptr_t address, void *buffer, size_t size) const
    {
        if (!buffer || !size || address + size < address)
            return false;
        const Region *region = FindRegion(address);
        if (!region)
            return false;
        const size_t offset = static_cast<size_t>(address - region->base);
        if (size > region->bytes.size() - offset || !IsCovered(*region, offset, size))
            return false;
        std::memcpy(buffer, region->bytes.data() + offset, size);
        return true;
    }

    // 把一次读取写入区域，返回此前未冻结的字节数
    // 已冻结字节若与本次读到的不一致，说明同一批内出现了相互矛盾的内容
    size_t CaptureMemorySource::WriteRegion(Region &region, size_t offset, const uint8_t *bytes, size_t size) const
    {
        size_t fresh = 0;
        for (size_t index = 0; index < size; ++index)
        {
            const size_t position = offset + index;
            const uint64_t bit = uint64_t{1} << (position % 64);
            if (region.covered[position / 64] & bit)
            {
                if (region.bytes[position] == bytes[index])
                    continue;
                changedDuringRead_ = true;
                if (changesDuringRead_.size() < 8)
                {
                    CaptureValidation::Change change;
                    change.address = region.base + position;
                    change.size = 1;
                    change.read = {ReadError::None, region.base + position, 1, 1};
                    change.before.assign(1, region.bytes[position]);
                    change.after.assign(1, bytes[index]);
                    changesDuringRead_.push_back(std::move(change));
                }
                if (diagnostic_)
                    diagnostic_("capture_overlap_change address=" + Hex(region.base + position) + " size=1");
            }
            region.covered[position / 64] |= bit;
            region.bytes[position] = bytes[index];
            ++fresh;
        }
        return fresh;
    }

    void CaptureMemorySource::ObserveBytes(uintptr_t address, const uint8_t *bytes, size_t size) const
    {
        auto *performance = Performance();
        ScopedReadTiming timing(performance ? &performance->captureObserve : nullptr);
        // 超出单次上限只是这一次不冻结，读取本身已经成功
        // 它让覆盖不完整，但不构成停止冻结的理由：后续的普通读取仍可安全冻结
        // 只有总量预算耗尽才需要停冻，见下面的 freezeStopped_
        if (size > kMaxReadSize || address + size < address)
        {
            limitExceeded_ = true;
            return;
        }
        // 预算一旦耗尽就停止冻结
        // 继续写入会让冻结内容的采集时刻跨度整个枚举
        // 校验时与当前内存比较必然出现大量并不存在的差异
        if (freezeStopped_)
            return;
        // 快路径：读取完全落在已有区域内时原地写入
        // 属性头部、链接槽与派生成员落在同一段描述符数组内，绝大多数读取走这条路径
        if (Region *region = FindRegion(address))
        {
            const size_t offset = static_cast<size_t>(address - region->base);
            if (size <= region->bytes.size() - offset)
            {
                observedBytes_ += WriteRegion(*region, offset, bytes, size);
                if (performance)
                    ++performance->captureGrownRanges;
                return;
            }
        }
        // 向后扩展：读取起点仍在区域内而末端越界时，直接追加到区域末尾
        // 属性尾部与链接槽紧接头部之后，这条路径承担了区域生长的主要部分
        const uintptr_t first = address - address % 64;
        const uintptr_t last = (address + size + 63) / 64 * 64;
        if (Region *region = FindRegion(address))
        {
            auto found = regions_.find(region->base);
            const auto next = std::next(found);
            const uintptr_t currentEnd = region->base + region->bytes.size();
            // 仅当后续区域不与新范围相接下才原地追加，否则交给合并路径
            // 区域达到上限时另起一段继续冻结：单个区域的上限是布局约束，不应升级为整个采集的终止条件
            if (next == regions_.end() || (next->first > last && next->first - last > kMaxRegionGap))
            {
                // 区域只能向后增长：last 落在已有末端之前时保留原尺寸
                // 截断会丢弃已冻结的字节并使分配量统计与真实占用失配
                const uintptr_t wanted = std::max(last, currentEnd);
                const size_t grown = static_cast<size_t>(wanted - region->base);
                if (grown <= kMaxRegionBytes &&
                    (grown <= region->bytes.size() || grown - region->bytes.size() <= RemainingBudget()))
                {
                    if (grown > region->bytes.size())
                    {
                        allocatedBytes_ += grown - region->bytes.size();
                        region->bytes.resize(grown, 0);
                        region->covered.resize((grown + 63) / 64, 0);
                    }
                    observedBytes_ += WriteRegion(*region, static_cast<size_t>(address - region->base), bytes, size);
                    if (performance)
                        ++performance->captureGrownRanges;
                    return;
                }
            }
        }
        // 新建区域或向前并入先前区域
        auto begin = regions_.upper_bound(first);
        if (begin != regions_.begin())
        {
            const auto preceding = std::prev(begin);
            if (first - preceding->second.base <= preceding->second.bytes.size() + kMaxRegionGap)
                begin = preceding;
        }
        uintptr_t newBase = begin != regions_.end() ? std::min(first, begin->first) : first;
        uintptr_t newEnd = last;
        auto end = begin;
        while (end != regions_.end())
        {
            // 与当前合并范围只有小间隙的区域才并入，更大间隙留给独立区域
            const uintptr_t gap = end->first > newEnd ? end->first - newEnd : 0;
            if (gap > kMaxRegionGap)
                break;
            newEnd = std::max(newEnd, end->second.base + end->second.bytes.size());
            ++end;
        }
        // 合并会超出单区域上限时只放弃合并，按本次读取单独建区
        // 合并只是减少记录数的优化，放弃它不应丢弃已读到的字节
        if (newEnd - newBase > kMaxRegionBytes)
        {
            begin = end = regions_.upper_bound(first);
            newBase = first;
            newEnd = last;
            // 新区域必须与已有区域互斥，region 已满且本次读取落在它内部时
            // 单独建区会与它重叠并破坏有序不变量，此时放弃冻结这一次读取
            // 放弃同时意味着该读取的字节不在校验范围内，计入覆盖缺口
            //
            // 这里只计数不置 limitExceeded_：区域已满后再遇到落在其内部的读取
            // 是区域布局的常规结果，每次采集都会发生若干次
            // 用它判定覆盖不完整会让每次运行都降级为 Partial，失去门禁的区分度
            if (begin != regions_.begin())
            {
                const auto preceding = std::prev(begin);
                if (preceding->second.base + preceding->second.bytes.size() > newBase)
                {
                    ++unfrozenReads_;
                    return;
                }
            }
            if (begin != regions_.end() && begin->first < newEnd)
            {
                ++unfrozenReads_;
                return;
            }
        }
        // 预算按合并后的净增量检查：被并入的旧区域会随合并释放
        size_t replaced = 0;
        for (auto item = begin; item != end; ++item)
            replaced += item->second.bytes.size();
        const size_t grown = static_cast<size_t>(newEnd - newBase);
        if (grown > replaced && grown - replaced > RemainingBudget())
        {
            limitExceeded_ = true;
            freezeStopped_ = true;
            return;
        }
        const bool inserted = begin == end;
        // 新范围只承载已被真实读取的字节，间隙保持未覆盖，不参与比较或回放
        Region merged;
        merged.base = newBase;
        merged.bytes.assign(grown, 0);
        merged.covered.assign((grown + 63) / 64, 0);
        for (auto item = begin; item != end; ++item)
        {
            const size_t offset = static_cast<size_t>(item->second.base - newBase);
            std::copy(item->second.bytes.begin(), item->second.bytes.end(),
                      merged.bytes.begin() + static_cast<ptrdiff_t>(offset));
            std::copy(item->second.covered.begin(), item->second.covered.end(),
                      merged.covered.begin() + static_cast<ptrdiff_t>(offset / 64));
            allocatedBytes_ -= item->second.bytes.size();
        }
        regions_.erase(begin, end);
        // 键由本轮区间决定，与已擦除范围不重叠，插入必然成功
        const auto [position, emplaced] = regions_.emplace(newBase, std::move(merged));
        if (!emplaced)
            throw std::logic_error("capture region overlap");
        allocatedBytes_ += position->second.bytes.size();
        observedBytes_ += WriteRegion(position->second, static_cast<size_t>(address - newBase), bytes, size);
        if (performance)
        {
            if (inserted)
                ++performance->captureInsertedRanges;
            else
                ++performance->captureGrownRanges;
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
            performance->captureValidationRanges += regions_.size();
            performance->captureValidationBytes += observedBytes_;
        }
        CaptureValidation result;
        result.observedRanges = regions_.size();
        result.observedBytes = observedBytes_;
        result.allocatedBytes = allocatedBytes_;
        result.limitExceeded = limitExceeded_;
        result.generationChanged = generation_ != source_.AddressSpaceGeneration();
        result.changedRanges = changedDuringRead_ ? 1 : 0;
        result.changes = changesDuringRead_;
        result.readFailures = readFailures_;
        result.unfrozenReads = unfrozenReads_;
        result.readFailureSamples = readFailureSamples_;
        if (regions_.empty())
        {
            result.generationChanged = result.generationChanged || generation_ != source_.AddressSpaceGeneration();
            return result;
        }
        // 批槽位取自区域上限：任何区域都能整体放入一个槽位，两者的关系由类型强制
        constexpr size_t maxBatchSize = kMaxRegionBytes;
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
        using Iterator = decltype(regions_)::const_iterator;
        // 每个批次记录首尾区域迭代器，回放时据此确定批内包含的区域
        std::array<std::pair<Iterator, Iterator>, kBatchRegions> batches{};
        std::vector<uint8_t> current;
        current.resize(maxBatchSize * kBatchRegions);
        for (auto first = regions_.cbegin(); first != regions_.cend();)
        {
            size_t count = 0;
            while (count < kBatchRegions && first != regions_.cend())
            {
                const auto begin = first;
                const uintptr_t start = begin->second.base;
                size_t span = begin->second.bytes.size();
                auto end = std::next(begin);
                // 相邻区域常落在同一页内，合并成一次读取以减少系统调用
                while (end != regions_.cend())
                {
                    const uintptr_t offset = end->second.base - start;
                    // 批缓冲区按 maxBatchSize 划分槽位，跨度不得超过一个槽位
                    if (offset >= maxBatchSize || end->second.bytes.size() > maxBatchSize - offset ||
                        (offset > span && offset - span > maxGap))
                        break;
                    span = std::max(span, static_cast<size_t>(offset) + end->second.bytes.size());
                    ++end;
                }
                requests[count] = {start, current.data() + count * maxBatchSize, span};
                batches[count] = {begin, end};
                ++count;
                first = end;
            }
            if (performance)
                ++performance->captureValidationBatches;
            if (!source_.ReadBatch({requests.data(), count}, {reads.data(), count}, true))
                throw std::runtime_error("Capture validation batch contract failed");
            for (size_t batch = 0; batch < count; ++batch)
            {
                const uint8_t *data = current.data() + batch * maxBatchSize;
                const uintptr_t start = requests[batch].address;
                for (auto item = batches[batch].first; item != batches[batch].second; ++item)
                {
                    const Region &region = item->second;
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
