#include "nextdumper/binding/LayoutDiscovery.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <map>
#include <tuple>

namespace nextdumper::binding
{
    namespace
    {
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
