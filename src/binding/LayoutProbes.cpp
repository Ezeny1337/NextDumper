#include "nextdumper/binding/LayoutProbes.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <optional>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::binding
{
    namespace
    {
        using ::nextdumper::common::Hex;

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

        bool ReadPointer(const IMemorySource &memory, uintptr_t address, uintptr_t &value)
        {
            return memory.Read(address, value);
        }
    } // namespace

    bool ObjectLayoutProbe::IsLikelyObject(uintptr_t address) const
    {
        if (address == 0 || !memory_.IsReadable(address, sizeof(uintptr_t)))
            return false;

        uintptr_t vtable = 0;
        if (!memory_.Read(address, vtable) || vtable == 0)
            return false;
        if (!memory_.IsReadable(vtable, sizeof(uintptr_t)))
            return false;

        uintptr_t firstFunction = 0;
        if (!memory_.Read(vtable, firstFunction) || firstFunction == 0)
            return false;
        return memory_.IsExecutable(firstFunction, sizeof(uintptr_t));
    }

    bool ObjectLayoutProbe::ReadItemAddress(uintptr_t root,
                                            const ObjectContainerLayout &layout,
                                            const DecodePlan &decode,
                                            int32_t index,
                                            uintptr_t &item) const
    {
        const auto storageAddress = Add(root, static_cast<uintptr_t>(layout.objectsOffset));
        if (!storageAddress)
            return false;

        uintptr_t rawStorage = 0;
        if (!ReadPointer(memory_, *storageAddress, rawStorage))
            return false;
        const uintptr_t storage = decode.objectStorage(rawStorage, *storageAddress);

        if (layout.kind == ObjectContainerKind::Fixed)
        {
            const auto itemAddress = Scaled(storage, index, layout.itemStride);
            if (!itemAddress)
                return false;
            item = *itemAddress;
            return true;
        }

        if (layout.elementsPerChunk <= 0)
            return false;
        const int32_t chunkIndex = index / layout.elementsPerChunk;
        const int32_t withinChunk = index % layout.elementsPerChunk;
        const auto chunkSlot = Scaled(storage, chunkIndex, static_cast<int32_t>(sizeof(uintptr_t)));
        if (!chunkSlot)
            return false;

        uintptr_t rawChunk = 0;
        if (!ReadPointer(memory_, *chunkSlot, rawChunk))
            return false;
        const uintptr_t chunk = decode.objectChunk(rawChunk, *chunkSlot);
        if (chunk == 0 || !memory_.IsReadable(chunk, sizeof(uintptr_t)))
            return false;
        const auto itemAddress = Scaled(chunk, withinChunk, layout.itemStride);
        if (!itemAddress)
            return false;
        item = *itemAddress;
        return true;
    }

    LayoutProbeReport ObjectLayoutProbe::Validate(uintptr_t root,
                                                  const ObjectContainerLayout &layout,
                                                  const DecodePlan &decode,
                                                  int32_t maxSamples) const
    {
        LayoutProbeReport report;
        if (root == 0 || !layout.IsValid() || maxSamples <= 0)
        {
            report.failures.push_back("invalid object layout probe input");
            return report;
        }

        if (layout.kind == ObjectContainerKind::Chunked)
        {
            // UE 5.6 的 FChunkedFixedUObjectArray 嵌在 FUObjectArray 中
            // 字段顺序为：Objects、PreAllocatedObjects、MaxElements、NumElements、MaxChunks、NumChunks
            // 检查该关系可以避免仅因为数值碰巧等于抽样索引，就把 FUObjectArray 的 ObjFirstGCIndex 等 bookkeeping 字段接受为 NumElements
            const int32_t expectedMaxElements = layout.objectsOffset + static_cast<int32_t>(sizeof(uintptr_t) * 2);
            const int32_t expectedNumElements = expectedMaxElements + static_cast<int32_t>(sizeof(int32_t));
            const int32_t expectedMaxChunks = expectedNumElements + static_cast<int32_t>(sizeof(int32_t));
            if (layout.maxElementsOffset != expectedMaxElements ||
                layout.numElementsOffset != expectedNumElements ||
                layout.maxChunksOffset != expectedMaxChunks)
            {
                report.failures.push_back("chunked UObject array field ordering is inconsistent with UE 5.6 source");
                return report;
            }
        }

        const auto countAddress = Add(root, static_cast<uintptr_t>(layout.numElementsOffset));
        if (!countAddress)
        {
            report.failures.push_back("object count address overflow");
            return report;
        }

        int32_t rawCount = 0;
        if (!memory_.Read(*countAddress, rawCount))
        {
            report.failures.push_back("object count is unreadable");
            return report;
        }
        const int32_t count = decode.objectCount(rawCount, *countAddress);
        if (count <= 0 || count > 0x08000000)
        {
            report.failures.push_back("object count is outside the supported range");
            return report;
        }

        constexpr std::array<int32_t, 16> samples = {0, 1, 2, 4, 8, 16, 32, 64,
                                                     128, 256, 512, 1024, 2048, 4096, 8192, 16384};
        const int32_t stride = std::max(1, count / std::max(1, maxSamples));

        auto validateIndex = [&](int32_t index)
        {
            if (index < 0 || index >= count)
                return;
            ++report.tested;

            uintptr_t item = 0;
            if (!ReadItemAddress(root, layout, decode, index, item))
                return;

            uintptr_t rawObject = 0;
            const auto objectSlot = Add(item, static_cast<uintptr_t>(layout.itemObjectOffset));
            if (!objectSlot || !ReadPointer(memory_, *objectSlot, rawObject))
                return;
            const uintptr_t object = decode.objectPointer(UnpackObjectItemPointer(rawObject, layout.packedPointers), *objectSlot);

            // 允许存在空槽，这不违背容器的布局规则
            if (object == 0)
            {
                ++report.empty;
                return;
            }
            if (!IsLikelyObject(object))
                return;

            const auto indexAddress = Add(object, static_cast<uintptr_t>(layout.itemIndexOffset));
            if (!indexAddress)
                return;
            int32_t reportedIndex = 0;
            if (!memory_.Read(*indexAddress, reportedIndex))
                return;
            reportedIndex = decode.objectIndex(reportedIndex, *indexAddress);
            if (reportedIndex == index)
                ++report.valid;
        };

        for (int32_t index : samples)
            validateIndex(index);
        for (int32_t index = 0; index < count && report.tested < maxSamples; index += stride)
            validateIndex(index);

        const int32_t nonEmpty = report.tested - report.empty;
        report.confidence = nonEmpty > 0 ? static_cast<double>(report.valid) / nonEmpty : 0.0;
        report.accepted = report.valid >= 5 && report.confidence >= 0.80;
        report.evidence.push_back("empty object slots were treated as holes, not layout failures");
        report.evidence.push_back("validated non-empty slots through UObject internal index");
        report.evidence.push_back("object probe empty=" + std::to_string(report.empty) +
                                  " failed=" + std::to_string(nonEmpty - report.valid));
        if (!report.accepted)
            report.failures.push_back("insufficient self-consistent UObject samples");
        return report;
    }

    bool NameLayoutProbe::ReadString(uintptr_t address, int32_t length, bool wide,
                                     const DecodePlan &decode, std::string &out) const
    {
        if (length <= 0 || length > 1024)
            return false;
        const size_t characterWidth = wide ? sizeof(char16_t) : sizeof(char);
        const size_t characterCount = static_cast<size_t>(length);
        if (characterCount > std::numeric_limits<size_t>::max() / characterWidth)
            return false;
        std::vector<uint8_t> bytes(characterCount * characterWidth);
        if (!memory_.ReadBytes(address, bytes.data(), bytes.size()).Ok() ||
            !decode.nameText(bytes, address, wide))
            return false;
        if (!wide)
        {
            out.assign(reinterpret_cast<const char *>(bytes.data()), bytes.size());
            return true;
        }

        out.clear();
        for (size_t offset = 0; offset < bytes.size(); offset += sizeof(char16_t))
        {
            char16_t character = 0;
            std::memcpy(&character, bytes.data() + offset, sizeof(character));
            if (character == 0)
                break;
            if (character < 0x80)
                out.push_back(static_cast<char>(character));
            else
                out.push_back('?');
        }
        return true;
    }

    bool NameLayoutProbe::ReadEntry(uintptr_t entry,
                                    const NameContainerLayout &layout,
                                    const DecodePlan &decode,
                                    std::string &out) const
    {
        if (entry == 0)
            return false;
        uint16_t rawHeader = 0;

        if (layout.kind == NameContainerKind::Array)
        {
            uint32_t rawIndex = 0;
            const auto indexAddress = Add(entry, static_cast<uintptr_t>(layout.array.entryIndexOffset));
            const auto stringAddress = Add(entry, static_cast<uintptr_t>(layout.array.entryStringOffset));
            if (!indexAddress || !stringAddress || !memory_.Read(*indexAddress, rawIndex))
                return false;
            const uint32_t index = decode.nameEntryIndex(rawIndex, *indexAddress);
            return ReadString(*stringAddress, 4, (index & 1u) != 0, decode, out);
        }

        const auto headerAddress = Add(entry, static_cast<uintptr_t>(layout.pool.entryHeaderOffset));
        const auto stringAddress = Add(entry, static_cast<uintptr_t>(layout.pool.entryStringOffset));
        if (!headerAddress || !stringAddress || !memory_.Read(*headerAddress, rawHeader))
            return false;
        const uint16_t header = decode.nameHeader(rawHeader, *headerAddress);
        const int32_t length = static_cast<int32_t>(header >> layout.pool.entryLengthShift);
        const bool wide = (header & layout.pool.entryWideMask) != 0;
        return ReadString(*stringAddress, length, wide, decode, out);
    }

    LayoutProbeReport NameLayoutProbe::Validate(uintptr_t root,
                                                const NameContainerLayout &layout,
                                                const DecodePlan &decode) const
    {
        LayoutProbeReport report;
        if (root == 0 || !layout.IsValid())
        {
            report.failures.push_back("invalid name layout probe input");
            return report;
        }

        uintptr_t entry0 = 0;
        if (layout.kind == NameContainerKind::Array)
        {
            const auto chunks = Add(root, static_cast<uintptr_t>(layout.array.chunksOffset));
            uintptr_t rawChunk = 0;
            if (!chunks || !memory_.Read(*chunks, rawChunk))
            {
                report.failures.push_back("name array chunk table is unreadable");
                return report;
            }
            const uintptr_t chunk = decode.nameChunks(rawChunk, *chunks);
            if (!memory_.Read(chunk, entry0))
            {
                report.failures.push_back("name array entry zero is unreadable");
                return report;
            }
            entry0 = decode.nameEntry(entry0, chunk);
        }
        else
        {
            const auto blocks = Add(root, static_cast<uintptr_t>(layout.pool.blocksOffset));
            uintptr_t rawBlock = 0;
            if (!blocks || !memory_.Read(*blocks, rawBlock))
            {
                report.failures.push_back("name pool block table is unreadable");
                return report;
            }
            const uintptr_t block = decode.nameBlocks(rawBlock, *blocks);
            entry0 = decode.nameEntry(block, block);
        }

        std::string none;
        if (!ReadEntry(entry0, layout, decode, none) || none != "None")
        {
            report.failures.push_back("name entry zero did not decode to None");
            return report;
        }

        report.tested = 1;
        report.valid = 1;
        report.confidence = 1.0;
        report.accepted = true;
        report.evidence.push_back("name entry zero decoded to None");
        if (layout.kind == NameContainerKind::Pool)
        {
            uintptr_t entry = entry0;
            size_t consumed = 0;
            int knownNames = 0;
            const char *stopReason = "sample-limit";
            const size_t blockSize = (size_t{1} << layout.pool.blocksBit) * static_cast<size_t>(layout.pool.entryStride);
            constexpr std::array<const char *, 8> known = {"None", "ByteProperty", "IntProperty", "BoolProperty",
                                                           "FloatProperty", "ObjectProperty", "NameProperty", "DelegateProperty"};
            report.accepted = false;
            report.tested = 0;
            report.valid = 0;
            for (int sample = 0; sample < 16; ++sample)
            {
                ++report.tested;
                const auto headerAddress = Add(entry, static_cast<uintptr_t>(layout.pool.entryHeaderOffset));
                uint16_t header = 0;
                if (!headerAddress || !memory_.Read(*headerAddress, header))
                {
                    stopReason = "header-unreadable";
                    break;
                }
                header = decode.nameHeader(header, *headerAddress);
                const size_t length = header >> layout.pool.entryLengthShift;
                const size_t width = (header & layout.pool.entryWideMask) != 0 ? 2 : 1;
                if (length == 0 || length > 1024)
                {
                    stopReason = "invalid-length";
                    break;
                }
                const size_t extent = static_cast<size_t>(layout.pool.entryStringOffset) + length * width;
                const size_t stride = static_cast<size_t>(layout.pool.entryStride);
                const size_t advance = (extent + stride - 1) / stride * stride;
                if (consumed > blockSize || advance > blockSize - consumed)
                {
                    stopReason = "block-boundary";
                    break;
                }
                std::string text;
                if (!ReadEntry(entry, layout, decode, text) || text.empty() ||
                    !std::all_of(text.begin(), text.end(), [](unsigned char c)
                                 { return c >= 0x20 && c <= 0x7E; }))
                {
                    stopReason = "entry-unreadable-or-invalid-text";
                    break;
                }
                ++report.valid;
                knownNames += std::find(known.begin(), known.end(), text) != known.end() ? 1 : 0;
                const auto next = Add(entry, advance);
                if (!next)
                {
                    stopReason = "address-overflow";
                    break;
                }
                entry = decode.nameEntry(*next, *next);
                consumed += advance;
            }
            report.confidence = report.tested > 0 ? static_cast<double>(report.valid) / report.tested : 0;
            report.accepted = report.valid >= 8 && knownNames >= 3 && report.confidence == 1.0;
            if (report.accepted && layout.pool.HasPublicationBoundary())
            {
                const auto addresses = layout.pool.Locate(root);
                uint32_t current = 0;
                uint32_t cursor = 0;
                const bool readable = addresses && memory_.ReadFreshBytes(addresses->currentBlock, &current, sizeof(current)).Ok() &&
                                      memory_.ReadFreshBytes(addresses->byteCursor, &cursor, sizeof(cursor)).Ok();
                report.accepted = readable && current < 8192 && cursor <= blockSize &&
                                  cursor % static_cast<uint32_t>(layout.pool.entryStride) == 0 &&
                                  (current != 0 || cursor >= consumed);
                uintptr_t publishedBlock = 0;
                if (report.accepted)
                {
                    const auto table = Add(root, static_cast<uintptr_t>(layout.pool.blocksOffset));
                    const auto slot = table ? Add(*table, static_cast<uintptr_t>(current) * sizeof(uintptr_t)) : std::nullopt;
                    report.accepted = slot && memory_.ReadFreshBytes(*slot, &publishedBlock, sizeof(publishedBlock)).Ok();
                    if (report.accepted)
                    {
                        publishedBlock = decode.nameBlocks(publishedBlock, *slot);
                        report.accepted = publishedBlock != 0 && memory_.IsReadable(publishedBlock, sizeof(uint16_t));
                    }
                }
                report.evidence.push_back("name pool publication boundary current_block=" + std::to_string(current) +
                                          " byte_cursor=" + std::to_string(cursor) +
                                          " published_block=" + Hex(publishedBlock) +
                                          " readable=" + std::to_string(readable) +
                                          " validated=" + std::to_string(report.accepted));
                if (!report.accepted)
                    report.failures.push_back("name pool publication boundary failed validation");
            }
            report.evidence.push_back("name pool sequential entries=" + std::to_string(report.valid) +
                                      " known_names=" + std::to_string(knownNames) +
                                      " stride=" + std::to_string(layout.pool.entryStride) +
                                      " consumed_bytes=" + std::to_string(consumed) +
                                      " stop_reason=" + stopReason);
            if (!report.accepted && report.failures.empty())
                report.failures.push_back("name pool stride/header failed sequential name validation");
        }
        return report;
    }
} // namespace nextdumper::binding
