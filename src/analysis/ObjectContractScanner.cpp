#include "nextdumper/analysis/ObjectContractScanner.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::analysis
{
    namespace
    {
        constexpr int32_t kMaxNameBlocks = 8192;
        constexpr int32_t kReadChunkBytes = 64 * 1024;
        constexpr size_t kMaxNameCache = 4096;

        struct FieldLayout
        {
            int32_t maxElements;
            int32_t count;
            int32_t maxChunks;
            int32_t numChunks;
            const char *name;
        };

        constexpr std::array<FieldLayout, 3> kFieldLayouts = {{
            {16, 20, 24, 28, "stock"},
            {24, 28, 32, 36, "plus8"},
            {32, 36, 40, 44, "plus16"},
        }};

        struct ShapeResult
        {
            int32_t stride = 0;
            int32_t indexOffset = 0;
            uint32_t tested = 0;
            uint32_t empty = 0;
            uint32_t valid = 0;
            double confidence = 0.0;
            std::string sampleNames;
        };

        std::optional<uintptr_t> AddOffset(uintptr_t base, int64_t offset)
        {
            if (offset >= 0)
            {
                const uintptr_t value = static_cast<uintptr_t>(offset);
                if (base > UINTPTR_MAX - value)
                    return std::nullopt;
                return base + value;
            }
            const uintptr_t value = static_cast<uintptr_t>(-(offset + 1)) + 1;
            if (base < value)
                return std::nullopt;
            return base - value;
        }

        bool ReadExact(const MemoryView &memory, uintptr_t address, void *buffer, size_t size)
        {
            return memory.ReadBytes(address, buffer, size).Ok();
        }

        bool ReadPointerValue(const MemoryView &memory, uintptr_t address, uintptr_t &value)
        {
            return ReadExact(memory, address, &value, sizeof(value));
        }

        bool ReadInt32Value(const MemoryView &memory, uintptr_t address, int32_t &value)
        {
            return ReadExact(memory, address, &value, sizeof(value));
        }

        bool IsPrintable(const std::vector<uint8_t> &bytes)
        {
            if (bytes.empty())
                return false;
            return std::all_of(bytes.begin(), bytes.end(), [](uint8_t value)
                               { return value >= 0x20 && value <= 0x7E; });
        }

        bool IsLikelyObject(const MemoryView &memory, uintptr_t object)
        {
            if (object == 0 || !memory.IsReadable(object, sizeof(uintptr_t)))
                return false;
            uintptr_t vtable = 0;
            uintptr_t function = 0;
            return ReadPointerValue(memory, object, vtable) && vtable != 0 &&
                   memory.IsReadable(vtable, sizeof(uintptr_t)) &&
                   ReadPointerValue(memory, vtable, function) && function != 0 &&
                   memory.IsExecutable(function, sizeof(uintptr_t));
        }

        class NameResolver
        {
        public:
            NameResolver(const MemoryView &memory, uintptr_t root, const NamePoolFields &fields,
                         const NameTextDecoder &decoder)
                : memory_(memory), root_(root), fields_(fields), decoder_(decoder)
            {
            }

            bool Resolve(int32_t index, std::string &out)
            {
                if (index < 0 || !fields_.Complete())
                    return false;
                const auto cached = cache_.find(index);
                if (cached != cache_.end())
                {
                    out = cached->second;
                    return true;
                }

                const uint32_t unstable = static_cast<uint32_t>(index);
                const int32_t blockIndex = static_cast<int32_t>(unstable >> fields_.BlocksBit);
                if (blockIndex < 0 || blockIndex >= kMaxNameBlocks)
                    return false;
                const uint32_t within = unstable & ((1u << fields_.BlocksBit) - 1u);
                const auto blocksAddress = AddOffset(root_, fields_.BlocksOffset);
                const auto blockSlot = blocksAddress
                                           ? AddOffset(*blocksAddress, static_cast<int64_t>(blockIndex) * static_cast<int64_t>(sizeof(uintptr_t)))
                                           : std::nullopt;
                uintptr_t block = 0;
                if (!blockSlot || !ReadPointerValue(memory_, *blockSlot, block) || block == 0 ||
                    !memory_.IsReadable(block, sizeof(uint16_t)))
                    return false;
                const auto entry = AddOffset(block, static_cast<int64_t>(within) * fields_.EntryStride);
                const auto headerAddress = entry ? AddOffset(*entry, fields_.HeaderOffset) : std::nullopt;
                uint16_t header = 0;
                if (!headerAddress || !ReadExact(memory_, *headerAddress, &header, sizeof(header)))
                    return false;
                const int32_t length = static_cast<int32_t>(header >> fields_.LengthShift);
                const bool wide = (header & fields_.WideMask) != 0;
                if (length <= 0 || length > 1024 || wide)
                    return false;
                std::vector<uint8_t> text(static_cast<size_t>(length));
                const auto textAddress = entry ? AddOffset(*entry, fields_.StringOffset) : std::nullopt;
                if (!textAddress || !ReadExact(memory_, *textAddress, text.data(), text.size()) ||
                    !decoder_.Apply(text, static_cast<size_t>(length), false) || !IsPrintable(text))
                    return false;
                out.assign(reinterpret_cast<const char *>(text.data()), text.size());
                if (cache_.size() < kMaxNameCache)
                    cache_.emplace(index, out);
                return true;
            }

        private:
            const MemoryView &memory_;
            uintptr_t root_ = 0;
            NamePoolFields fields_;
            NameTextDecoder decoder_;
            std::unordered_map<int32_t, std::string> cache_;
        };

        bool ReadObjectName(const MemoryView &memory, NameResolver &names, uintptr_t object, std::string &out)
        {
            const auto comparisonAddress = AddOffset(object, 24);
            const auto displayAddress = AddOffset(object, 28);
            int32_t comparison = 0;
            int32_t display = 0;
            if (!comparisonAddress || !displayAddress ||
                !ReadInt32Value(memory, *comparisonAddress, comparison) ||
                !ReadInt32Value(memory, *displayAddress, display))
                return false;
            if (names.Resolve(comparison, out))
                return true;
            return display != comparison && names.Resolve(display, out);
        }

        bool ValidateObject(const MemoryView &memory, NameResolver &names, uintptr_t object,
                            int32_t index, int32_t indexOffset, std::string &name)
        {
            if (!IsLikelyObject(memory, object))
                return false;
            const auto indexAddress = AddOffset(object, indexOffset);
            int32_t reported = 0;
            if (!indexAddress || !ReadInt32Value(memory, *indexAddress, reported) || reported != index)
                return false;
            if (!ReadObjectName(memory, names, object, name))
                return false;
            bool classValid = false;
            for (const int32_t classOffset : {16, 40, 48})
            {
                const auto classAddress = AddOffset(object, classOffset);
                uintptr_t classPointer = 0;
                std::string className;
                if (classAddress && ReadPointerValue(memory, *classAddress, classPointer) &&
                    IsLikelyObject(memory, classPointer) &&
                    ReadObjectName(memory, names, classPointer, className))
                {
                    classValid = true;
                    break;
                }
            }
            if (!classValid)
                return false;

            bool outerValid = false;
            for (const int32_t outerOffset : {36, 32, 48})
            {
                const auto outerAddress = AddOffset(object, outerOffset);
                uintptr_t outer = 0;
                if (!outerAddress || !ReadPointerValue(memory, *outerAddress, outer))
                    continue;
                if (outer == 0 || IsLikelyObject(memory, outer))
                {
                    outerValid = true;
                    break;
                }
            }
            return outerValid;
        }

        bool IsInReadableRanges(const std::vector<std::pair<uintptr_t, uintptr_t>> &ranges,
                                uintptr_t address, size_t size)
        {
            if (ranges.empty())
                return true;
            const auto bound = std::lower_bound(ranges.begin(), ranges.end(), address,
                                                [](const auto &range, uintptr_t value)
                                                { return range.first < value; });
            auto it = bound;
            if (it != ranges.begin())
            {
                const auto previous = std::prev(it);
                if (address >= previous->first && address < previous->second)
                    it = previous;
            }
            if (it == ranges.end() || address < it->first || address >= it->second)
                return false;
            if (size > it->second - address)
            {
                const auto next = std::next(it);
                return next != ranges.end() && next->first <= address + size && address + size <= next->second;
            }
            return true;
        }

        std::string BuildShapeSamples(const std::vector<std::string> &samples)
        {
            std::string result;
            const size_t count = std::min<size_t>(samples.size(), 4);
            for (size_t index = 0; index < count; ++index)
            {
                if (index != 0)
                    result += ",";
                result += samples[index];
            }
            return result;
        }

        std::optional<Contract> TryCandidate(const MemoryView &memory, NameResolver &names,
                                             uintptr_t pointerAddress, uintptr_t chunkTable,
                                             const ObjectContractScanOptions &options,
                                             std::string &bestRejected)
        {
            for (const FieldLayout &field : kFieldLayouts)
            {
                const auto maxAddress = AddOffset(pointerAddress, field.maxElements);
                const auto countAddress = AddOffset(pointerAddress, field.count);
                const auto maxChunksAddress = AddOffset(pointerAddress, field.maxChunks);
                const auto numChunksAddress = AddOffset(pointerAddress, field.numChunks);
                int32_t maxElements = 0;
                int32_t count = 0;
                int32_t maxChunks = 0;
                int32_t numChunks = 0;
                if (!maxAddress || !countAddress || !maxChunksAddress || !numChunksAddress ||
                    !ReadInt32Value(memory, *maxAddress, maxElements) ||
                    !ReadInt32Value(memory, *countAddress, count) ||
                    !ReadInt32Value(memory, *maxChunksAddress, maxChunks) ||
                    !ReadInt32Value(memory, *numChunksAddress, numChunks))
                    continue;
                if (count < static_cast<int32_t>(options.MinCount) || count > 0x08000000 ||
                    maxElements < count || maxElements > 0x08000000 ||
                    maxChunks <= 0 || maxChunks > 0x1000 || numChunks <= 0 || numChunks > maxChunks)
                    continue;

                std::vector<int32_t> elementsPerChunk = {64 * 1024};
                if (maxElements % maxChunks == 0)
                {
                    const int32_t derived = maxElements / maxChunks;
                    if (derived != elementsPerChunk.front() && derived >= 0x1000 && derived <= 0x200000)
                        elementsPerChunk.push_back(derived);
                }

                for (const int32_t perChunk : elementsPerChunk)
                {
                    if (perChunk <= 0 || maxElements % perChunk != 0 || maxElements / perChunk != maxChunks ||
                        static_cast<int64_t>(numChunks) * perChunk < count)
                        continue;

                    std::vector<ShapeResult> shapes;
                    for (const int32_t stride : {24, 16, 32})
                    {
                        for (const int32_t indexOffset : {12, 36})
                        {
                            ShapeResult shape;
                            shape.stride = stride;
                            shape.indexOffset = indexOffset;
                            std::vector<std::string> namesSample;
                            const auto validateIndex = [&](int32_t index)
                            {
                                if (index < 0 || index >= count)
                                    return;
                                ++shape.tested;
                                const int32_t chunkIndex = index / perChunk;
                                const int32_t within = index % perChunk;
                                if (chunkIndex >= numChunks)
                                    return;
                                const auto chunkSlot = AddOffset(chunkTable, static_cast<int64_t>(chunkIndex) * static_cast<int64_t>(sizeof(uintptr_t)));
                                uintptr_t chunk = 0;
                                if (!chunkSlot || !ReadPointerValue(memory, *chunkSlot, chunk) || chunk == 0 ||
                                    !memory.IsReadable(chunk, sizeof(uintptr_t)))
                                    return;
                                const auto item = AddOffset(chunk, static_cast<int64_t>(within) * stride);
                                uintptr_t object = 0;
                                if (!item || !ReadPointerValue(memory, *item, object))
                                    return;
                                if (object == 0)
                                {
                                    ++shape.empty;
                                    return;
                                }
                                std::string name;
                                if (!ValidateObject(memory, names, object, index, indexOffset, name))
                                    return;
                                ++shape.valid;
                                if (namesSample.size() < 4)
                                    namesSample.push_back(std::move(name));
                            };

                            constexpr std::array<int32_t, 16> kSamples = {0, 1, 2, 4, 8, 16, 32, 64,
                                                                          128, 256, 512, 1024, 2048, 4096, 8192, 16384};
                            for (const int32_t index : kSamples)
                                validateIndex(index);
                            const std::array<int32_t, 6> tail = {
                                count - 1, count / 2, std::min(count - 1, perChunk - 1),
                                std::min(count - 1, perChunk), std::min(count - 1, 2 * perChunk - 1),
                                std::min(count - 1, 2 * perChunk)};
                            for (const int32_t index : tail)
                                validateIndex(index);

                            const uint32_t nonEmpty = shape.tested - shape.empty;
                            shape.confidence = nonEmpty > 0 ? static_cast<double>(shape.valid) / nonEmpty : 0.0;
                            shape.sampleNames = BuildShapeSamples(namesSample);
                            if (shape.valid >= 5 && nonEmpty >= 5 && shape.confidence >= 0.80)
                                shapes.push_back(std::move(shape));
                        }
                    }
                    if (shapes.empty())
                    {
                        if (bestRejected.empty())
                        {
                            bestRejected = "root=" + common::Hex(pointerAddress) +
                                           " count=" + std::to_string(count) +
                                           " max=" + std::to_string(maxElements) +
                                           " max_chunks=" + std::to_string(maxChunks) +
                                           " num_chunks=" + std::to_string(numChunks) +
                                           " field=" + field.name;
                        }
                        continue;
                    }
                    std::sort(shapes.begin(), shapes.end(), [](const ShapeResult &left, const ShapeResult &right)
                              {
                                  if ((left.indexOffset == 12) != (right.indexOffset == 12))
                                      return left.indexOffset == 12;
                                  if (left.valid != right.valid)
                                      return left.valid > right.valid;
                                  return left.confidence > right.confidence; });
                    const ShapeResult &best = shapes.front();
                    Contract contract;
                    contract.Kind = ContractKind::ObjectArray;
                    contract.Root = pointerAddress;
                    contract.State = ContractState::Validated;
                    ObjectArrayFields &fields = contract.ObjectArray;
                    fields.ObjectsOffset = 0;
                    fields.MaxElementsOffset = field.maxElements;
                    fields.NumElementsOffset = field.count;
                    fields.MaxChunksOffset = field.maxChunks;
                    fields.NumChunksOffset = field.numChunks;
                    fields.ElementsPerChunk = perChunk;
                    fields.ItemStride = best.stride;
                    fields.ItemObjectOffset = 0;
                    fields.ItemIndexOffset = best.indexOffset;
                    fields.Count = static_cast<uint32_t>(count);
                    fields.MaxElements = static_cast<uint32_t>(maxElements);
                    fields.Chunks = static_cast<uint32_t>(numChunks);
                    contract.Evidence.push_back({EvidenceKind::TableLoad, pointerAddress, chunkTable});
                    contract.Evidence.push_back({EvidenceKind::EntryLoad, pointerAddress, static_cast<uint64_t>(count)});
                    contract.Evidence.push_back({EvidenceKind::ScaleAdd, pointerAddress, static_cast<uint64_t>(best.stride)});
                    if (!fields.Complete())
                        continue;
                    return contract;
                }
            }
            return std::nullopt;
        }
    } // namespace

    ObjectContractScanResult ScanObjectContracts(const ImageModel &image, uintptr_t nameRoot,
                                                 const NamePoolFields &nameFields,
                                                 const NameTextDecoder &nameDecoder,
                                                 const ObjectContractScanOptions &options)
    {
        ObjectContractScanResult result;
        if (!image.IsValid() || nameRoot == 0 || !nameFields.Complete())
        {
            result.Error = "image-or-name-contract-invalid";
            return result;
        }

        NameResolver names(image.Memory(), nameRoot, nameFields, nameDecoder);
        std::vector<std::pair<uintptr_t, uintptr_t>> readableRanges;
        for (const auto &region : image.Memory().Regions())
        {
            if (region.readable && region.end > region.start)
                readableRanges.emplace_back(region.start, region.end);
        }
        std::sort(readableRanges.begin(), readableRanges.end());

        std::vector<Contract> candidates;
        const auto considerPointer = [&](uintptr_t pointerAddress, uintptr_t rawChunkTable)
        {
            if (rawChunkTable == 0 || !IsInReadableRanges(readableRanges, rawChunkTable, sizeof(uintptr_t)) ||
                !image.Memory().IsReadable(rawChunkTable, sizeof(uintptr_t)) ||
                image.Memory().IsExecutable(rawChunkTable, sizeof(uintptr_t)))
                return;
            uintptr_t chunk0 = 0;
            if (!ReadPointerValue(image.Memory(), rawChunkTable, chunk0) || chunk0 == 0 ||
                !image.Memory().IsReadable(chunk0, sizeof(uintptr_t)))
                return;
            ++result.Candidates;
            std::string rejected;
            const auto contract = TryCandidate(image.Memory(), names, pointerAddress, rawChunkTable,
                                               options, rejected);
            if (contract)
                candidates.push_back(*contract);
            else if (result.BestRejected.empty() && !rejected.empty())
                result.BestRejected = rejected;
        };

        std::vector<const module::ModuleImage::Segment *> scanSegments;
        for (const auto &segment : image.Module().segments)
        {
            if (segment.readable && segment.writable && segment.end > segment.start)
                scanSegments.push_back(&segment);
        }
        // 名称池和对象全局通常位于同一写段，优先扫描该段以尽早发现对象数组
        std::stable_sort(scanSegments.begin(), scanSegments.end(),
                         [nameRoot](const auto *left, const auto *right)
                         {
                             const bool leftHasName = nameRoot >= left->start && nameRoot < left->end;
                             const bool rightHasName = nameRoot >= right->start && nameRoot < right->end;
                             return leftHasName > rightHasName;
                         });

        std::vector<uint8_t> buffer(kReadChunkBytes);
        for (const auto *segment : scanSegments)
        {
            if (!segment->readable || !segment->writable || segment->end <= segment->start)
                continue;
            if (result.ScannedBytes >= options.MaxScanBytes)
            {
                result.BudgetExhausted = true;
                break;
            }
            const uint64_t segmentBytes = static_cast<uint64_t>(segment->end - segment->start);
            uint64_t offset = 0;
            while (offset < segmentBytes && result.ScannedBytes < options.MaxScanBytes)
            {
                const size_t want = static_cast<size_t>(std::min<uint64_t>(
                    {static_cast<uint64_t>(kReadChunkBytes), segmentBytes - offset,
                     options.MaxScanBytes - result.ScannedBytes}));
                if (want < sizeof(uintptr_t))
                    break;
                const auto chunkAddress = AddOffset(segment->start, static_cast<int64_t>(offset));
                if (!chunkAddress ||
                    !image.Memory().ReadBytes(*chunkAddress, buffer.data(), want).Ok())
                {
                    offset += want;
                    continue;
                }
                result.ScannedBytes += want;
                for (size_t position = 0; position + sizeof(uintptr_t) <= want; position += sizeof(uintptr_t))
                {
                    uintptr_t rawChunkTable = 0;
                    std::memcpy(&rawChunkTable, buffer.data() + position, sizeof(rawChunkTable));
                    if (rawChunkTable < 0x10000)
                        continue;
                    if (!IsInReadableRanges(readableRanges, rawChunkTable, sizeof(uintptr_t)))
                        continue;
                    const auto pointerAddress = AddOffset(*chunkAddress, static_cast<int64_t>(position));
                    if (pointerAddress)
                        considerPointer(*pointerAddress, rawChunkTable);
                }
                offset += want;
            }
        }

        std::sort(candidates.begin(), candidates.end(), [](const Contract &left, const Contract &right)
                  { return left.ObjectArray.Count > right.ObjectArray.Count; });
        if (candidates.size() > options.MaxCandidates)
            candidates.resize(options.MaxCandidates);
        result.Contracts = std::move(candidates);
        return result;
    }
} // namespace nextdumper::analysis
