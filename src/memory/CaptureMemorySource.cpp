#include "nextdumper/memory/CaptureMemorySource.hpp"

#include <algorithm>
#include <cstring>
#include <array>
#include <iterator>
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
        blocks_.clear();
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
        if (source_.IsInitialized() && ServeFromBlocks(address, buffer, size))
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
            if (request.buffer && request.size && ServeFromBlocks(request.address, request.buffer, request.size))
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

    bool CaptureMemorySource::IsCovered(const Block &block, size_t offset, size_t size)
    {
        for (size_t index = offset; index < offset + size; ++index)
        {
            if ((block.covered[index / 64] & (uint64_t{1} << (index % 64))) == 0)
                return false;
        }
        return true;
    }

    // 只有在请求的每个字节都已冻结时才从块内取值
    // 部分覆盖必须回落到真实读取，否则会把未观测的字节补成零
    bool CaptureMemorySource::ServeFromBlocks(uintptr_t address, void *buffer, size_t size) const
    {
        if (!buffer || !size ||
            (address % kBlockSize) + size > kBlockSize)
            return false;
        const uintptr_t base = address - address % kBlockSize;
        const auto found = blocks_.find(base);
        if (found == blocks_.end())
            return false;
        const size_t offset = static_cast<size_t>(address - base);
        if (!IsCovered(found->second, offset, size))
            return false;
        std::memcpy(buffer, found->second.bytes.data() + offset, size);
        return true;
    }

    void CaptureMemorySource::ObserveBytes(uintptr_t address, const uint8_t *bytes, size_t size) const
    {
        auto *performance = Performance();
        ScopedReadTiming timing(performance ? &performance->captureObserve : nullptr);
        // 超出预算只停止冻结新的块，读取本身已经成功
        // 据此中断调用方会把内存护栏变成采集中止条件，使余下对象永远无法枚举
        if (size > kMaxReadSize)
        {
            limitExceeded_ = true;
            return;
        }
        // 逐块冻结，只标记本次实际覆盖到的字节
        size_t consumed = 0;
        while (consumed < size)
        {
            const uintptr_t current = address + consumed;
            const uintptr_t base = current - current % kBlockSize;
            const size_t offset = static_cast<size_t>(current - base);
            const size_t length = std::min(kBlockSize - offset, size - consumed);
            auto found = blocks_.find(base);
            const bool inserted = found == blocks_.end();
            if (inserted && blocks_.size() >= kMaxBlocks)
            {
                limitExceeded_ = true;
                return;
            }
            if (inserted)
                found = blocks_.emplace(base, Block{}).first;
            Block &block = found->second;
            size_t fresh = 0;
            for (size_t index = 0; index < length; ++index)
            {
                const size_t position = offset + index;
                const uint64_t bit = uint64_t{1} << (position % 64);
                if (block.covered[position / 64] & bit)
                {
                    if (block.bytes[position] == bytes[consumed + index])
                        continue;
                    changedDuringRead_ = true;
                    if (changesDuringRead_.size() < 8)
                    {
                        CaptureValidation::Change change;
                        change.address = current + index;
                        change.size = 1;
                        change.read = {ReadError::None, current + index, 1, 1};
                        change.before.assign(1, block.bytes[position]);
                        change.after.assign(1, bytes[consumed + index]);
                        changesDuringRead_.push_back(std::move(change));
                    }
                    if (diagnostic_)
                        diagnostic_("capture_overlap_change address=" + Hex(current + index) + " size=1");
                }
                block.covered[position / 64] |= bit;
                block.bytes[position] = bytes[consumed + index];
                ++fresh;
            }
            if (performance)
            {
                if (inserted)
                    ++performance->captureInsertedRanges;
                else if (fresh)
                    ++performance->captureGrownRanges;
            }
            observedBytes_ += fresh;
            consumed += length;
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
            performance->captureValidationRanges += blocks_.size();
            performance->captureValidationBytes += observedBytes_;
        }
        CaptureValidation result;
        result.observedRanges = blocks_.size();
        result.observedBytes = observedBytes_;
        result.limitExceeded = limitExceeded_;
        result.generationChanged = generation_ != source_.AddressSpaceGeneration();
        result.changedRanges = changedDuringRead_ ? 1 : 0;
        result.changes = changesDuringRead_;
        result.readFailures = readFailures_;
        result.readFailureSamples = readFailureSamples_;
        if (blocks_.empty())
        {
            result.generationChanged = result.generationChanged || generation_ != source_.AddressSpaceGeneration();
            return result;
        }
        constexpr size_t maxBatchSize = 64 * 1024;
        constexpr size_t maxGap = 64;
        constexpr size_t kBatchBlocks = 16;
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
        const auto compareBlock = [&](uintptr_t base, const Block &block, const uint8_t *data, const ReadResult &read)
        {
            size_t index = 0;
            while (index < kBlockSize)
            {
                while (index < kBlockSize && (block.covered[index / 64] & (uint64_t{1} << (index % 64))) == 0)
                    ++index;
                const size_t begin = index;
                while (index < kBlockSize && (block.covered[index / 64] & (uint64_t{1} << (index % 64))) != 0)
                    ++index;
                if (begin == index)
                    break;
                // 诊断字段跟随被比较的区间，而不是整块起点
                ReadResult aligned = read;
                aligned.address = base + begin;
                aligned.requested = index - begin;
                if (read.Ok())
                    aligned.transferred = index - begin;
                compare(base + begin, block.bytes.data() + begin, index - begin, data + begin, aligned);
            }
        };
        std::array<uintptr_t, kBatchBlocks> starts{};
        std::array<size_t, kBatchBlocks> spans{};
        std::array<ReadRequest, kBatchBlocks> requests{};
        std::array<ReadResult, kBatchBlocks> reads{};
        std::vector<uint8_t> current;
        current.resize(maxBatchSize * kBatchBlocks);
        for (auto first = blocks_.cbegin(); first != blocks_.cend();)
        {
            size_t count = 0;
            while (count < kBatchBlocks && first != blocks_.cend())
            {
                auto last = std::next(first);
                const uintptr_t start = first->first;
                size_t span = kBlockSize;
                while (last != blocks_.cend())
                {
                    const uintptr_t offset = last->first - start;
                    if (offset > maxBatchSize || kBlockSize > maxBatchSize - offset ||
                        (offset > span && offset - span > maxGap))
                        break;
                    span = std::max(span, static_cast<size_t>(offset) + kBlockSize);
                    ++last;
                }
                starts[count] = start;
                spans[count] = span;
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
                const uint8_t *data = current.data() + index * maxBatchSize;
                // 块在批内按地址有序排列，逐个对齐到各自的批内偏移
                size_t block = 0;
                for (auto item = blocks_.lower_bound(starts[index]);
                     item != blocks_.end() && item->first < starts[index] + spans[index]; ++item, ++block)
                {
                    (void)block;
                    const auto &[base, contents] = *item;
                    if (reads[index].Ok())
                        compareBlock(base, contents, data + (base - starts[index]),
                                     {ReadError::None, base, kBlockSize, kBlockSize});
                    else
                    {
                        if (performance)
                            ++performance->captureValidationFallbacks;
                        std::array<uint8_t, kBlockSize> exact{};
                        const auto read = source_.ReadFreshBytes(base, exact.data(), exact.size());
                        compareBlock(base, contents, exact.data(), read);
                    }
                }
            }
        }
        result.generationChanged = result.generationChanged || generation_ != source_.AddressSpaceGeneration();
        return result;
    }
} // namespace nextdumper::memory
