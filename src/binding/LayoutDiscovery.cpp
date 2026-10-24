#include "nextdumper/binding/LayoutDiscovery.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <map>
#include <tuple>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::binding
{
    namespace
    {
        using ::nextdumper::common::Hex;

        const char *RootTargetName(RootTarget target)
        {
            switch (target)
            {
            case RootTarget::Unknown:
                return "unknown";
            case RootTarget::GUObjectArray:
                return "guobjectarray";
            case RootTarget::ObjObjects:
                return "objobjects";
            case RootTarget::NamePool:
                return "namepool";
            }
            return "unknown";
        }

        std::optional<uintptr_t> Add(uintptr_t base, uintptr_t offset)
        {
            if (base > UINTPTR_MAX - offset)
                return std::nullopt;
            return base + offset;
        }

        std::optional<uintptr_t> Scaled(uintptr_t base, int32_t index, int32_t stride)
        {
            if (index < 0 || stride <= 0)
                return std::nullopt;
            const uintptr_t uIndex = static_cast<uintptr_t>(index);
            const uintptr_t uStride = static_cast<uintptr_t>(stride);
            if (uIndex != 0 && uStride > UINTPTR_MAX / uIndex)
                return std::nullopt;
            return Add(base, uIndex * uStride);
        }

        bool ReadInt32(const IMemorySource &memory, uintptr_t address, int32_t &value)
        {
            return memory.Read(address, value);
        }

        std::string DescribeRawFields(const IMemorySource &memory, uintptr_t address, int32_t limit = 0x30)
        {
            std::string result;
            for (int32_t offset = 0; offset + static_cast<int32_t>(sizeof(int32_t)) <= limit; offset += 4)
            {
                int32_t value = 0;
                const auto fieldAddress = Add(address, static_cast<uintptr_t>(offset));
                result += " +" + std::to_string(offset) + "=";
                if (fieldAddress && ReadInt32(memory, *fieldAddress, value))
                    result += Hex(static_cast<uint32_t>(value));
                else
                    result += "unreadable";
            }
            return result;
        }

        bool IsReadablePointer(const IMemorySource &memory, uintptr_t pointer)
        {
            return pointer != 0 && memory.IsReadable(pointer, sizeof(uintptr_t));
        }

        bool IsLikelyObject(const IMemorySource &memory, uintptr_t object)
        {
            if (!IsReadablePointer(memory, object))
                return false;
            uintptr_t vtable = 0;
            uintptr_t firstFunction = 0;
            return memory.Read(object, vtable) && IsReadablePointer(memory, vtable) && memory.Read(vtable, firstFunction) &&
                   firstFunction != 0 && memory.IsExecutable(firstFunction, sizeof(uintptr_t));
        }

        void AddUniqueObjectCandidate(std::vector<std::pair<ObjectContainerLayout, double>> &out,
                                      ObjectContainerLayout layout,
                                      double confidence,
                                      int32_t maxCandidates)
        {
            for (const auto &[existing, score] : out)
            {
                if (existing.kind == layout.kind && existing.objectsOffset == layout.objectsOffset &&
                    existing.numElementsOffset == layout.numElementsOffset && existing.elementsPerChunk == layout.elementsPerChunk &&
                    existing.itemObjectOffset == layout.itemObjectOffset && existing.itemStride == layout.itemStride &&
                    existing.itemIndexOffset == layout.itemIndexOffset && existing.packedPointers == layout.packedPointers)
                    return;
            }
            out.emplace_back(std::move(layout), confidence);
            std::sort(out.begin(), out.end(), [](const auto &left, const auto &right)
                      { return left.second > right.second; });
            if (static_cast<int32_t>(out.size()) > maxCandidates)
                out.resize(static_cast<size_t>(maxCandidates));
        }
    } // namespace

    bool ObjectLayoutDiscovery::ReadPointer(uintptr_t address, uintptr_t &value) const
    {
        return memory_.Read(address, value);
    }

    bool ObjectLayoutDiscovery::ReadItemObject(uintptr_t item,
                                               int32_t objectOffset,
                                               bool packed,
                                               const DecodePlan &decode,
                                               uintptr_t &object) const
    {
        const auto slot = Add(item, static_cast<uintptr_t>(objectOffset));
        if (!slot || !ReadPointer(*slot, object))
            return false;
        object = decode.objectPointer(UnpackObjectItemPointer(object, packed), *slot);
        return object == 0 || IsLikelyObject(memory_, object);
    }

    bool ObjectLayoutDiscovery::DiscoverItemShape(uintptr_t storage,
                                                  bool chunked,
                                                  bool packed,
                                                  int32_t elementsPerChunk,
                                                  const DecodePlan &decode,
                                                  int32_t &objectOffset,
                                                  int32_t &itemStride,
                                                  int32_t &indexOffset,
                                                  double &confidence) const
    {
        uintptr_t firstStorage = storage;
        if (chunked)
        {
            if (!ReadPointer(storage, firstStorage))
                return false;
            firstStorage = decode.objectChunk(firstStorage, storage);
            if (!IsReadablePointer(memory_, firstStorage))
                return false;
        }

        constexpr std::array<int32_t, 8> samples = {1, 4, 8, 20, 50, 100, 250, 500};
        for (int32_t candidateObjectOffset = 0; candidateObjectOffset <= 0x30; candidateObjectOffset += 4)
        {
            for (int32_t candidateStride = 8; candidateStride <= 0x40; candidateStride += 4)
            {
                std::vector<std::pair<int32_t, uintptr_t>> objects;
                for (int32_t index : samples)
                {
                    if (chunked && elementsPerChunk <= 0)
                        continue;
                    const int32_t localIndex = chunked ? index % elementsPerChunk : index;
                    const auto item = Scaled(firstStorage, localIndex, candidateStride);
                    if (!item)
                        continue;
                    uintptr_t object = 0;
                    if (!ReadItemObject(*item, candidateObjectOffset, packed, decode, object) || object == 0)
                        continue;
                    objects.emplace_back(index, object);
                }

                if (objects.size() < 3)
                    continue;

                for (int32_t candidateIndexOffset = 0; candidateIndexOffset <= 0x80 - 4; candidateIndexOffset += 4)
                {
                    size_t matches = 0;
                    for (const auto &[index, object] : objects)
                    {
                        int32_t reported = 0;
                        const auto address = Add(object, static_cast<uintptr_t>(candidateIndexOffset));
                        if (address && ReadInt32(memory_, *address, reported) &&
                            decode.objectIndex(reported, *address) == index)
                            ++matches;
                    }
                    if (matches < 3)
                        continue;

                    objectOffset = candidateObjectOffset;
                    itemStride = candidateStride;
                    indexOffset = candidateIndexOffset;
                    confidence = static_cast<double>(matches) / static_cast<double>(objects.size());
                    return true;
                }
            }
        }
        return false;
    }

    std::vector<std::pair<ObjectContainerLayout, double>> ObjectLayoutDiscovery::Discover(
        uintptr_t root,
        const DecodePlan &decode,
        int32_t maxCandidates) const
    {
        std::vector<std::pair<ObjectContainerLayout, double>> result;
        if (root == 0 || maxCandidates <= 0 || !memory_.IsReadable(root, 0x40))
            return result;

        constexpr int32_t headerBytes = 0x40;

        struct Shape
        {
            bool valid = false;
            int32_t objectOffset = -1;
            int32_t stride = -1;
            int32_t indexOffset = -1;
            double confidence = 0;
        };
        std::map<std::tuple<uintptr_t, bool, bool, int32_t>, Shape> shapes;
        const auto shapeFor = [&](uintptr_t storage, bool chunked, bool packed, int32_t elementsPerChunk) -> const Shape &
        {
            const auto key = std::make_tuple(storage, chunked, packed, elementsPerChunk);
            auto [at, inserted] = shapes.try_emplace(key);
            if (inserted)
                at->second.valid = DiscoverItemShape(storage, chunked, packed, elementsPerChunk, decode,
                                                     at->second.objectOffset, at->second.stride,
                                                     at->second.indexOffset, at->second.confidence);
            return at->second;
        };

        for (int32_t pointerOffset = 0; pointerOffset <= headerBytes - static_cast<int32_t>(sizeof(uintptr_t)); pointerOffset += 4)
        {
            uintptr_t rawStorage = 0;
            if (!ReadPointer(root + static_cast<uintptr_t>(pointerOffset), rawStorage))
                continue;
            const uintptr_t storage = decode.objectStorage(rawStorage, root + static_cast<uintptr_t>(pointerOffset));
            if (!IsReadablePointer(memory_, storage))
                continue;

            for (int32_t countOffset = 0; countOffset <= headerBytes - static_cast<int32_t>(sizeof(int32_t)); countOffset += 4)
            {
                int32_t count = 0;
                if (!ReadInt32(memory_, root + static_cast<uintptr_t>(countOffset), count))
                    continue;
                count = decode.objectCount(count, root + static_cast<uintptr_t>(countOffset));
                if (count < 64 || count > 0x08000000)
                    continue;

                const auto &fixedShape = shapeFor(storage, false, false, 0);
                if (fixedShape.valid)
                {
                    ObjectContainerLayout layout;
                    layout.kind = ObjectContainerKind::Fixed;
                    layout.objectsOffset = pointerOffset;
                    layout.numElementsOffset = countOffset;
                    layout.itemObjectOffset = fixedShape.objectOffset;
                    layout.itemStride = fixedShape.stride;
                    layout.itemIndexOffset = fixedShape.indexOffset;
                    AddUniqueObjectCandidate(result, std::move(layout), 0.30 + 0.70 * fixedShape.confidence, maxCandidates);
                }

                for (int32_t maxElementsOffset = 0; maxElementsOffset <= headerBytes - static_cast<int32_t>(sizeof(int32_t)); maxElementsOffset += 4)
                {
                    int32_t maxElements = 0;
                    if (!ReadInt32(memory_, root + static_cast<uintptr_t>(maxElementsOffset), maxElements))
                        continue;
                    maxElements = decode.objectCount(maxElements, root + static_cast<uintptr_t>(maxElementsOffset));
                    if (maxElements <= count || maxElements > 0x08000000 || maxElements % 0x1000 != 0)
                        continue;

                    for (int32_t maxChunksOffset = 0; maxChunksOffset <= headerBytes - 2 * static_cast<int32_t>(sizeof(int32_t)); maxChunksOffset += 4)
                    {
                        int32_t maxChunks = 0;
                        if (!ReadInt32(memory_, root + static_cast<uintptr_t>(maxChunksOffset), maxChunks))
                            continue;
                        if (maxChunks <= 0 || maxChunks > 0x1000 || maxElements % maxChunks != 0)
                            continue;
                        const int32_t elementsPerChunk = maxElements / maxChunks;
                        for (int packed = 0; packed <= (sizeof(uintptr_t) == 8 ? 1 : 0); ++packed)
                        {
                            const auto &chunkShape = shapeFor(storage, true, packed != 0, elementsPerChunk);
                            if (!chunkShape.valid)
                                continue;

                            ObjectContainerLayout layout;
                            layout.kind = ObjectContainerKind::Chunked;
                            layout.objectsOffset = pointerOffset;
                            layout.numElementsOffset = countOffset;
                            layout.maxElementsOffset = maxElementsOffset;
                            layout.maxChunksOffset = maxChunksOffset;
                            layout.elementsPerChunk = elementsPerChunk;
                            layout.itemObjectOffset = chunkShape.objectOffset;
                            layout.itemStride = chunkShape.stride;
                            layout.itemIndexOffset = chunkShape.indexOffset;
                            layout.packedPointers = packed != 0;
                            layout.numChunksOffset = maxChunksOffset + static_cast<int32_t>(sizeof(int32_t));
                            AddUniqueObjectCandidate(result, std::move(layout), 0.35 + 0.65 * chunkShape.confidence, maxCandidates);
                        }
                    }
                }
            }
        }
        return result;
    }

    StandardObjectLayoutResult ObjectLayoutDiscovery::DiscoverStandard(uintptr_t root,
                                                                       RootTarget target,
                                                                       const DecodePlan &decode,
                                                                       int32_t maxCandidates) const
    {
        StandardObjectLayoutResult result;
        if (root == 0 || maxCandidates <= 0)
            return result;

        std::vector<int32_t> chunkOffsets;
        switch (target)
        {
        case RootTarget::ObjObjects:
            chunkOffsets = {0};
            break;
        case RootTarget::GUObjectArray:
            chunkOffsets = {16, 24, 0, 32};
            break;
        case RootTarget::Unknown:
            chunkOffsets = {0, 16, 24};
            break;
        case RootTarget::NamePool:
            return result;
        }

        constexpr int32_t kElementsPerChunk = 64 * 1024;
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
        constexpr std::array<int32_t, 16> kSamples = {0, 1, 2, 4, 8, 16, 32, 64,
                                                      128, 256, 512, 1024, 2048, 4096, 8192, 16384};

        struct Shape
        {
            int32_t stride = 0;
            int32_t indexOffset = 0;
            int32_t tested = 0;
            int32_t empty = 0;
            int32_t valid = 0;
            double confidence = 0.0;
        };

        for (const int32_t chunkOffset : chunkOffsets)
        {
            const auto chunkArray = Add(root, static_cast<uintptr_t>(chunkOffset));
            if (!chunkArray)
                continue;
            const std::string rootPrefix = "root=" + Hex(root) + " target=" + RootTargetName(target) +
                                           " chunk_offset=" + std::to_string(chunkOffset);
            uintptr_t rawObjects = 0;
            if (!ReadPointer(*chunkArray, rawObjects))
            {
                result.Evidence.push_back(rootPrefix + " status=rejected reason=objects-field-unreadable raw=" +
                                          DescribeRawFields(memory_, *chunkArray));
                continue;
            }
            const uintptr_t objects = decode.objectStorage(rawObjects, *chunkArray);
            if (!IsReadablePointer(memory_, objects))
            {
                result.Evidence.push_back(rootPrefix + " objects=" + Hex(objects) +
                                          " status=rejected reason=chunk-table-unreadable raw=" +
                                          DescribeRawFields(memory_, *chunkArray));
                continue;
            }

            for (const FieldLayout &fieldLayout : kFieldLayouts)
            {
                const auto maxAddress = Add(*chunkArray, static_cast<uintptr_t>(fieldLayout.maxElements));
                const auto countAddress = Add(*chunkArray, static_cast<uintptr_t>(fieldLayout.count));
                const auto maxChunksAddress = Add(*chunkArray, static_cast<uintptr_t>(fieldLayout.maxChunks));
                const auto numChunksAddress = Add(*chunkArray, static_cast<uintptr_t>(fieldLayout.numChunks));
                int32_t rawMax = 0;
                int32_t rawCount = 0;
                int32_t rawMaxChunks = 0;
                int32_t rawNumChunks = 0;
                if (!maxAddress || !countAddress || !maxChunksAddress || !numChunksAddress ||
                    !ReadInt32(memory_, *maxAddress, rawMax) || !ReadInt32(memory_, *countAddress, rawCount) ||
                    !ReadInt32(memory_, *maxChunksAddress, rawMaxChunks) ||
                    !ReadInt32(memory_, *numChunksAddress, rawNumChunks))
                {
                    result.Evidence.push_back(rootPrefix + " field_layout=" + fieldLayout.name +
                                              " status=rejected reason=field-unreadable raw=" +
                                              DescribeRawFields(memory_, *chunkArray));
                    continue;
                }
                const int32_t maxElements = decode.objectCount(rawMax, *maxAddress);
                const int32_t count = decode.objectCount(rawCount, *countAddress);
                const int32_t maxChunks = decode.objectCount(rawMaxChunks, *maxChunksAddress);
                const int32_t numChunks = decode.objectCount(rawNumChunks, *numChunksAddress);

                std::string prefix = "root=" + Hex(root) + " target=" + RootTargetName(target) +
                                     " chunk_offset=" + std::to_string(chunkOffset) +
                                     " field_layout=" + fieldLayout.name +
                                     " objects=" + Hex(objects) +
                                     " count=" + std::to_string(count) +
                                     " max_elements=" + std::to_string(maxElements) +
                                     " max_chunks=" + std::to_string(maxChunks) +
                                     " num_chunks=" + std::to_string(numChunks);
                if (count < 64 || count > 0x08000000 || maxElements < count || maxElements > 0x08000000 ||
                    maxChunks <= 0 || maxChunks > 0x1000 || numChunks <= 0 || numChunks > maxChunks)
                {
                    result.Evidence.push_back(prefix + " status=rejected reason=field-relations");
                    continue;
                }

                std::vector<int32_t> elementsPerChunkValues = {kElementsPerChunk};
                if (maxElements % maxChunks == 0)
                {
                    const int32_t derived = maxElements / maxChunks;
                    if (derived != kElementsPerChunk && derived >= 0x1000 && derived <= 0x200000)
                        elementsPerChunkValues.push_back(derived);
                }

                for (const int32_t elementsPerChunk : elementsPerChunkValues)
                {
                    if (elementsPerChunk <= 0 || maxElements % elementsPerChunk != 0 ||
                        maxElements / elementsPerChunk != maxChunks ||
                        static_cast<int64_t>(numChunks) * elementsPerChunk < count)
                        continue;

                    std::vector<Shape> shapes;
                    for (const int32_t stride : {24, 16, 32})
                    {
                        for (const int32_t indexOffset : {12, 36})
                        {
                            Shape shape;
                            shape.stride = stride;
                            shape.indexOffset = indexOffset;
                            const auto validateIndex = [&](int32_t index)
                            {
                                if (index < 0 || index >= count)
                                    return;
                                ++shape.tested;
                                const int32_t chunkIndex = index / elementsPerChunk;
                                const int32_t withinChunk = index % elementsPerChunk;
                                if (chunkIndex >= numChunks)
                                    return;
                                const auto chunkSlot = Scaled(objects, chunkIndex, static_cast<int32_t>(sizeof(uintptr_t)));
                                if (!chunkSlot)
                                    return;
                                uintptr_t rawChunk = 0;
                                if (!ReadPointer(*chunkSlot, rawChunk))
                                    return;
                                const uintptr_t chunk = decode.objectChunk(rawChunk, *chunkSlot);
                                if (chunk == 0 || !memory_.IsReadable(chunk, sizeof(uintptr_t)))
                                    return;
                                const auto itemAddress = Scaled(chunk, withinChunk, stride);
                                if (!itemAddress)
                                    return;
                                uintptr_t rawObject = 0;
                                if (!ReadPointer(*itemAddress, rawObject))
                                    return;
                                const uintptr_t object = decode.objectPointer(rawObject, *itemAddress);
                                if (object == 0)
                                {
                                    ++shape.empty;
                                    return;
                                }
                                if (!IsLikelyObject(memory_, object))
                                    return;
                                const auto indexAddress = Add(object, static_cast<uintptr_t>(indexOffset));
                                int32_t reportedIndex = 0;
                                if (!indexAddress || !ReadInt32(memory_, *indexAddress, reportedIndex) ||
                                    decode.objectIndex(reportedIndex, *indexAddress) != index)
                                    return;

                                const auto classAddress = Add(object, 16);
                                const auto nameAddress = Add(object, 24);
                                const auto displayAddress = Add(object, 28);
                                const auto numberAddress = Add(object, 32);
                                uintptr_t classPointer = 0;
                                int32_t comparisonIndex = 0;
                                int32_t displayIndex = 0;
                                int32_t number = 0;
                                if (!classAddress || !nameAddress || !displayAddress || !numberAddress ||
                                    !ReadPointer(*classAddress, classPointer) ||
                                    !ReadInt32(memory_, *nameAddress, comparisonIndex) ||
                                    !ReadInt32(memory_, *displayAddress, displayIndex) ||
                                    !ReadInt32(memory_, *numberAddress, number))
                                    return;
                                if (classPointer == 0 || !IsLikelyObject(memory_, classPointer))
                                    return;
                                if (comparisonIndex == 0 && displayIndex == 0)
                                    return;
                                const auto classDisplay = Add(classPointer, 28);
                                int32_t classDisplayIndex = 0;
                                if (!classDisplay || !ReadInt32(memory_, *classDisplay, classDisplayIndex))
                                    return;

                                const auto outer32 = Add(object, 32);
                                const auto outer36 = Add(object, 36);
                                bool outerValid = false;
                                for (const auto &outerAddress : {outer36, outer32})
                                {
                                    if (!outerAddress)
                                        continue;
                                    uintptr_t outer = 0;
                                    if (ReadPointer(*outerAddress, outer) && (outer == 0 || IsLikelyObject(memory_, outer)))
                                    {
                                        outerValid = true;
                                        break;
                                    }
                                }
                                if (!outerValid)
                                    return;
                                ++shape.valid;
                            };

                            for (const int32_t index : kSamples)
                                validateIndex(index);
                            const std::array<int32_t, 6> tailSamples = {
                                count - 1, count / 2, std::min(count - 1, elementsPerChunk - 1),
                                std::min(count - 1, elementsPerChunk), std::min(count - 1, 2 * elementsPerChunk - 1),
                                std::min(count - 1, 2 * elementsPerChunk)};
                            for (const int32_t index : tailSamples)
                                validateIndex(index);

                            const int32_t nonEmpty = shape.tested - shape.empty;
                            shape.confidence = nonEmpty > 0 ? static_cast<double>(shape.valid) / nonEmpty : 0.0;
                            if (shape.valid >= 5 && nonEmpty >= 5 && shape.confidence >= 0.80)
                                shapes.push_back(shape);
                        }
                    }

                    prefix += " elements_per_chunk=" + std::to_string(elementsPerChunk);
                    if (shapes.empty())
                    {
                        result.Evidence.push_back(prefix + " status=rejected reason=no-consistent-item-shape");
                        continue;
                    }
                    std::sort(shapes.begin(), shapes.end(), [](const Shape &left, const Shape &right)
                              {
                                  if ((left.indexOffset == 12) != (right.indexOffset == 12))
                                      return left.indexOffset == 12;
                                  if (left.valid != right.valid)
                                      return left.valid > right.valid;
                                  return left.confidence > right.confidence; });
                    const Shape &best = shapes.front();
                    ObjectContainerLayout layout;
                    layout.kind = ObjectContainerKind::Chunked;
                    layout.objectsOffset = chunkOffset;
                    layout.maxElementsOffset = chunkOffset + fieldLayout.maxElements;
                    layout.numElementsOffset = chunkOffset + fieldLayout.count;
                    layout.maxChunksOffset = chunkOffset + fieldLayout.maxChunks;
                    layout.numChunksOffset = chunkOffset + fieldLayout.numChunks;
                    layout.elementsPerChunk = elementsPerChunk;
                    layout.itemObjectOffset = 0;
                    layout.itemStride = best.stride;
                    layout.itemIndexOffset = best.indexOffset;
                    layout.packedPointers = false;
                    layout.chunkFieldsValidated = true;
                    if (!layout.IsValid())
                    {
                        result.Evidence.push_back(prefix + " status=rejected reason=layout-invalid");
                        continue;
                    }
                    AddUniqueObjectCandidate(result.Layouts, layout, 0.90 + 0.10 * best.confidence, maxCandidates);
                    result.Evidence.push_back(prefix + " item_stride=" + std::to_string(best.stride) +
                                              " item_index=" + std::to_string(best.indexOffset) +
                                              " valid=" + std::to_string(best.valid) +
                                              " tested=" + std::to_string(best.tested) +
                                              " empty=" + std::to_string(best.empty) +
                                              " confidence=" + std::to_string(best.confidence) +
                                              " status=accepted");
                }
            }
        }
        return result;
    }

    bool NameLayoutDiscovery::ReadPointer(uintptr_t address, uintptr_t &value) const
    {
        return memory_.Read(address, value);
    }

    bool NameLayoutDiscovery::ReadPoolEntry(uintptr_t entry,
                                            const NamePoolLayout &layout,
                                            const DecodePlan &decode,
                                            std::string &name) const
    {
        uint16_t header = 0;
        const uintptr_t headerAddress = entry + static_cast<uintptr_t>(layout.entryHeaderOffset);
        if (!memory_.Read(headerAddress, header))
            return false;
        header = decode.nameHeader(header, headerAddress);
        const int32_t length = static_cast<int32_t>(header >> layout.entryLengthShift);
        if (length != 4 || (header & layout.entryWideMask) != 0)
            return false;
        std::array<uint8_t, 4> text{};
        const uintptr_t stringAddress = entry + static_cast<uintptr_t>(layout.entryStringOffset);
        if (!memory_.ReadBytes(stringAddress, text.data(), text.size()).Ok() ||
            !decode.nameText(text, stringAddress, false))
            return false;
        name.assign(reinterpret_cast<const char *>(text.data()), text.size());
        return true;
    }

    std::vector<std::pair<NameContainerLayout, double>> NameLayoutDiscovery::Discover(
        uintptr_t root,
        const DecodePlan &decode,
        int32_t maxCandidates) const
    {
        std::vector<std::pair<NameContainerLayout, double>> result;
        if (root == 0 || maxCandidates <= 0 || !memory_.IsReadable(root, 0x100))
            return result;

        for (int32_t pointerOffset = 0; pointerOffset <= 0x100 - static_cast<int32_t>(sizeof(uintptr_t)); pointerOffset += 4)
        {
            uintptr_t raw = 0;
            if (!ReadPointer(root + static_cast<uintptr_t>(pointerOffset), raw))
                continue;

            const uintptr_t target = decode.nameBlocks(raw, root + static_cast<uintptr_t>(pointerOffset));
            if (!IsReadablePointer(memory_, target))
                continue;

            for (int32_t stringOffset : {2, 4, 6, 8})
            {
                for (int32_t headerOffset : {0, 2, 4})
                {
                    if (headerOffset + 2 > stringOffset)
                        continue;
                    for (int32_t shift = 0; shift < 16; ++shift)
                    {
                        if ((static_cast<uint16_t>(4) << shift) == 0)
                            continue;
                        for (int32_t stride : {2, 4})
                        {
                            // 0x10 是 UE 标准块大小，厂商变体只在其不通过校验时才有机会
                            // 每个组合只采用首个通过的候选，重复布局会让下游探针判定为歧义并整体拒绝
                            for (int32_t blocksBit : {0x10, 0x0e, 0x12})
                            {
                                NamePoolLayout pool;
                                pool.blocksOffset = pointerOffset;
                                pool.blocksBit = blocksBit;
                                pool.entryStride = stride;
                                pool.entryHeaderOffset = headerOffset;
                                pool.entryStringOffset = stringOffset;
                                pool.entryLengthShift = shift;
                                pool.entryWideMask = 1;
                                const uintptr_t table = root + static_cast<uintptr_t>(pointerOffset);
                                if (table >= 8 && memory_.IsReadable(table - 8, 8))
                                {
                                    uint32_t block = 0;
                                    uint32_t cursor = 0;
                                    const size_t blockSize = (size_t{1} << pool.blocksBit) * stride;
                                    if (memory_.Read(table - 8, block) && memory_.Read(table - 4, cursor) &&
                                        block < 8192 && cursor <= blockSize && cursor % static_cast<uint32_t>(stride) == 0)
                                    {
                                        pool.currentBlockFromBlocks = -8;
                                        pool.byteCursorFromBlocks = -4;
                                    }
                                }
                                std::string name;
                                if (!ReadPoolEntry(target, pool, decode, name) || name != "None")
                                    continue;
                                NameContainerLayout layout;
                                layout.kind = NameContainerKind::Pool;
                                layout.pool = pool;
                                result.emplace_back(std::move(layout), 0.90);
                                if (static_cast<int32_t>(result.size()) >= maxCandidates)
                                    return result;
                                break;
                            }
                        }
                    }
                }
            }
        }

        for (int32_t chunksOffset = 0; chunksOffset <= 0x100 - static_cast<int32_t>(sizeof(uintptr_t)); chunksOffset += 4)
        {
            const uintptr_t chunksAddress = root + static_cast<uintptr_t>(chunksOffset);
            uintptr_t rawChunk = 0;
            if (!ReadPointer(chunksAddress, rawChunk))
                continue;
            const uintptr_t chunk = decode.nameChunks(rawChunk, chunksAddress);
            if (!IsReadablePointer(memory_, chunk))
                continue;
            uintptr_t rawEntry = 0;
            if (!ReadPointer(chunk, rawEntry))
                continue;
            const uintptr_t entry = decode.nameEntry(rawEntry, chunk);
            if (!IsReadablePointer(memory_, entry))
                continue;

            int32_t stringOffset = -1;
            for (int32_t offset = 0; offset <= 0x20 - 4; offset += 2)
            {
                std::array<uint8_t, 4> text{};
                const uintptr_t stringAddress = entry + static_cast<uintptr_t>(offset);
                if (memory_.ReadBytes(stringAddress, text.data(), text.size()).Ok() &&
                    decode.nameText(text, stringAddress, false) &&
                    std::memcmp(text.data(), "None", 4) == 0)
                {
                    stringOffset = offset;
                    break;
                }
            }
            if (stringOffset < 0)
                continue;

            int32_t indexOffset = -1;
            for (int32_t offset = 0; offset <= stringOffset; offset += 4)
            {
                int32_t indexValue = 0;
                if (!memory_.Read(entry + static_cast<uintptr_t>(offset), indexValue))
                    continue;
                indexValue = static_cast<int32_t>(decode.nameEntryIndex(static_cast<uint32_t>(indexValue), entry + static_cast<uintptr_t>(offset)) >> 1);
                if (indexValue == 0)
                {
                    indexOffset = offset;
                    break;
                }
            }
            if (indexOffset < 0)
                continue;

            NameArrayLayout array;
            array.chunksOffset = chunksOffset;
            array.elementsPerChunk = 0x4000;
            array.entryIndexOffset = indexOffset;
            array.entryStringOffset = stringOffset;
            NameContainerLayout layout;
            layout.kind = NameContainerKind::Array;
            layout.array = array;
            result.emplace_back(std::move(layout), 0.80);
            if (static_cast<int32_t>(result.size()) >= maxCandidates)
                break;
        }
        return result;
    }
} // namespace nextdumper::binding
