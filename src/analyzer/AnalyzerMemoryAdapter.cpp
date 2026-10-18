#include "nextdumper/analyzer/AnalyzerMemoryAdapter.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

#include <stdexcept>
#include <sstream>

#include "nextdumper/memory/MemoryScanner.hpp"
#include "nextdumper/module/ElfSymbols.hpp"

namespace nextdumper::analyzer
{
    AnalyzerMemoryAdapter::AnalyzerMemoryAdapter(IMemorySource &memory, const module::ModuleImage &module)
        : memory_(&memory), module_(module)
    {
        RebuildMaps();
    }

    void AnalyzerMemoryAdapter::RebuildMaps()
    {
        regions_.clear();
        if (memory_ == nullptr || !memory_->IsInitialized())
            return;
        const auto maps = memory_->Regions();
        regions_.reserve(maps.size());
        for (const auto &map : maps)
            regions_.emplace_back(map.path, map.start, map.end, map.fileOffset,
                                  map.readable, map.writable, map.executable);
        std::sort(regions_.begin(), regions_.end(), [](const MemRegionInfo &left, const MemRegionInfo &right)
                  { return left.GetStart() < right.GetStart(); });

        std::vector<MemRegionInfo> segments;
        for (const auto &segment : module_.segments)
            segments.emplace_back(segment.path, segment.start, segment.end, segment.fileOffset,
                                  segment.readable, segment.writable, segment.executable);
        unreal_ = ModuleInfo(module_.name, module_.base, module_.end, module_.base, std::move(segments));
    }

    bool AnalyzerMemoryAdapter::Initialize()
    {
        return memory_ != nullptr && memory_->IsInitialized() && RefreshMemory();
    }

    std::string AnalyzerMemoryAdapter::GetProcessName() const
    {
        return memory_ ? memory_->ProcessName() : std::string();
    }

    int AnalyzerMemoryAdapter::GetProcessID() const
    {
        return memory_ ? static_cast<int>(memory_->ProcessId()) : 0;
    }

    bool AnalyzerMemoryAdapter::RefreshMemory()
    {
        if (!memory_ || !memory_->RefreshAddressSpace())
            return false;
        RebuildMaps();
        return IsMemoryAccessOk();
    }

    bool AnalyzerMemoryAdapter::IsMemoryAccessOk() const
    {
        return memory_ != nullptr && memory_->IsInitialized() && module_.IsValid() && !regions_.empty();
    }

    bool AnalyzerMemoryAdapter::IsValidAddress(uintptr_t address) const
    {
        return GetAddressRegionInfo(address).IsValid();
    }

    bool AnalyzerMemoryAdapter::IsAddressReadable(uintptr_t address, size_t size) const
    {
        return memory_ && memory_->IsReadable(address, size);
    }

    bool AnalyzerMemoryAdapter::IsAddressWriteable(uintptr_t address, size_t size) const
    {
        if (address == 0 || size == 0 || address > UINTPTR_MAX - (size - 1))
            return false;
        const uintptr_t last = address + size - 1;
        const MemRegionInfo region = GetAddressRegionInfo(address);
        return region.IsValid() && region.Contains(last) && region.IsWriteable();
    }

    bool AnalyzerMemoryAdapter::IsAddressExecutable(uintptr_t address, size_t size) const
    {
        return memory_ && memory_->IsExecutable(address, size);
    }

    MemRegionInfo AnalyzerMemoryAdapter::GetAddressRegionInfo(uintptr_t address) const
    {
        auto at = std::upper_bound(regions_.begin(), regions_.end(), address,
                                   [](uintptr_t value, const MemRegionInfo &region)
                                   { return value < region.GetStart(); });
        if (at == regions_.begin())
            return {};
        --at;
        return at->Contains(address) ? *at : MemRegionInfo{};
    }

    size_t AnalyzerMemoryAdapter::ReadBytes(uintptr_t address, void *buffer, size_t size) const
    {
        if (!memory_)
            return 0;
        const auto read = memory_->ReadBytes(address, buffer, size);
        return read.Ok() || read.error == memory::ReadError::PartialRead ? read.transferred : 0;
    }

    bool AnalyzerMemoryAdapter::ReadRelocationPointer(uintptr_t slot, uintptr_t &out) const
    {
        if (!memory_ || !memory_->Read(slot, out) || out == 0)
            return false;
        return IsAddressReadable(out);
    }

    ModuleInfo AnalyzerMemoryAdapter::GetModuleInfo(const std::string &moduleName)
    {
        if (moduleName == module_.name || module_.name.find(moduleName) != std::string::npos)
            return unreal_;
        return {};
    }

    uintptr_t AnalyzerMemoryAdapter::FindModuleSymbol(const std::string &moduleName, const std::string &symbolName)
    {
        if (!memory_ || moduleName != module_.name)
            return 0;
        const auto result = module::QueryElfSymbols(*memory_, module_, {symbolName});
        if (const auto found = result.exported.find(symbolName); found != result.exported.end())
            return found->second;
        const auto found = result.debug.find(symbolName);
        return found == result.debug.end() ? 0 : found->second;
    }

    ModuleInfo AnalyzerMemoryAdapter::GetUnrealModule()
    {
        return unreal_;
    }

    uintptr_t AnalyzerMemoryAdapter::FindUnrealSymbol(const std::string &symbolName)
    {
        return FindModuleSymbol(module_.name, symbolName);
    }

    bool AnalyzerMemoryAdapter::RangeEnd(uintptr_t start, size_t range, uintptr_t &end) const
    {
        if (range == 0 || start > UINTPTR_MAX - range)
            return false;
        end = start + range;
        return true;
    }

    std::vector<uintptr_t> AnalyzerMemoryAdapter::FindAllPatternInRange(uintptr_t start, size_t range,
                                                                        const std::string &pattern, int step,
                                                                        size_t maxHits) const
    {
        uintptr_t end = 0;
        if (!memory_ || pattern.empty() || !RangeEnd(start, range, end))
            return {};
        std::vector<uint8_t> values, masks;
        std::istringstream input(pattern);
        std::string token;
        const auto hex = [](char value) -> int
        {
            if (value >= '0' && value <= '9')
                return value - '0';
            if (value >= 'a' && value <= 'f')
                return value - 'a' + 10;
            if (value >= 'A' && value <= 'F')
                return value - 'A' + 10;
            return -1;
        };
        while (input >> token)
        {
            if (values.size() >= 4096)
                throw std::length_error("Pattern length limit exceeded");
            if (token == "?")
                token = "??";
            if (token.size() != 2)
                throw std::invalid_argument("Invalid IDA pattern token");
            uint8_t value = 0, mask = 0;
            for (char digit : token)
            {
                value = static_cast<uint8_t>(value << 4);
                mask = static_cast<uint8_t>(mask << 4);
                if (digit == '?')
                    continue;
                const int number = hex(digit);
                if (number < 0)
                    throw std::invalid_argument("Invalid IDA pattern digit");
                value |= static_cast<uint8_t>(number);
                mask |= 15;
            }
            values.push_back(value);
            masks.push_back(mask);
        }
        auto result = memory::ScanMemory(*memory_, start, range, values, masks, 1, maxHits);
        if (!result.complete)
            throw std::runtime_error("Pattern scan encountered unreadable memory");
        for (auto &hit : result.hits)
        {
            if (step >= 0)
            {
                if (static_cast<uintptr_t>(step) > UINTPTR_MAX - hit)
                    throw std::overflow_error("Pattern result overflow");
                hit += static_cast<uintptr_t>(step);
            }
            else
            {
                const uint64_t delta = static_cast<uint64_t>(-static_cast<int64_t>(step));
                if (delta > hit)
                    throw std::overflow_error("Pattern result underflow");
                hit -= static_cast<uintptr_t>(delta);
            }
        }
        return result.hits;
    }

    uintptr_t AnalyzerMemoryAdapter::FindPatternInRange(uintptr_t start, size_t range,
                                                        const std::string &pattern, int step,
                                                        uint32_t skipCount) const
    {
        const auto hits = FindAllPatternInRange(start, range, pattern, step, 0);
        return skipCount < hits.size() ? hits[skipCount] : 0;
    }

    std::vector<uintptr_t> AnalyzerMemoryAdapter::FindAllAlignedValuesInRange(uintptr_t value,
                                                                              int32_t alignment,
                                                                              uintptr_t start,
                                                                              size_t range,
                                                                              size_t maxHits) const
    {
        if (!memory_ || alignment <= 0)
            return {};
        const auto *bytes = reinterpret_cast<const uint8_t *>(&value);
        std::array<uint8_t, sizeof(value)> mask;
        mask.fill(255);
        auto result = memory::ScanMemory(*memory_, start, range, {bytes, sizeof(value)}, mask,
                                         static_cast<size_t>(alignment), maxHits);
        if (!result.complete)
            throw std::runtime_error("Aligned scan encountered unreadable memory");
        return result.hits;
    }

    uintptr_t AnalyzerMemoryAdapter::FindAlignedValueInRange(uintptr_t value, int32_t alignment,
                                                             uintptr_t start, size_t range) const
    {
        const auto hits = FindAllAlignedValuesInRange(value, alignment, start, range, 1);
        return hits.empty() ? 0 : hits.front();
    }

    std::vector<uintptr_t> AnalyzerMemoryAdapter::FindAllRawDataInRange(const void *data,
                                                                        size_t dataSize,
                                                                        uintptr_t start,
                                                                        size_t range,
                                                                        size_t maxHits) const
    {
        if (!memory_ || !data || !dataSize)
            return {};
        if (dataSize > 4096)
            throw std::length_error("Raw scan pattern length limit exceeded");
        std::vector<uint8_t> mask(dataSize, 255);
        auto result = memory::ScanMemory(*memory_, start, range,
                                         {static_cast<const uint8_t *>(data), dataSize}, mask, 1, maxHits);
        if (!result.complete)
            throw std::runtime_error("Raw scan encountered unreadable memory");
        return result.hits;
    }

    uintptr_t AnalyzerMemoryAdapter::FindRawDataInRange(const void *data, size_t dataSize,
                                                        uintptr_t start, size_t range) const
    {
        const auto hits = FindAllRawDataInRange(data, dataSize, start, range, 1);
        return hits.empty() ? 0 : hits.front();
    }
} // namespace nextdumper::analyzer
