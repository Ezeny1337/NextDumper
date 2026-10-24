#include "nextdumper/binding/RuntimeBinding.hpp"

namespace nextdumper::binding
{
    bool ObjectContainerLayout::IsValid() const
    {
        if (packedPointers && sizeof(uintptr_t) != 8)
            return false;
        if (objectsOffset < 0 || numElementsOffset < 0 || itemObjectOffset < 0 || itemStride <= 0 || itemIndexOffset < 0 ||
            itemObjectOffset > itemStride || sizeof(uintptr_t) > static_cast<size_t>(itemStride - itemObjectOffset))
            return false;
        if (kind == ObjectContainerKind::Chunked)
            return elementsPerChunk > 0;
        return true;
    }

    bool NameArrayLayout::IsValid() const
    {
        return chunksOffset >= 0 && elementsPerChunk > 0 && entryIndexOffset >= 0 && entryStringOffset >= 0;
    }

    bool NamePoolLayout::IsValid() const
    {
        // 上界涵盖布局探测尝试的 14/16/18 block-bit 候选
        return blocksOffset >= 0 && blocksBit >= 1 && blocksBit <= 18 && (entryStride == 2 || entryStride == 4) &&
               entryHeaderOffset >= 0 && entryHeaderOffset <= 64 && entryStringOffset >= entryHeaderOffset + 2 &&
               entryStringOffset <= 64 && entryLengthShift >= 0 && entryLengthShift < 16 && entryWideMask != 0 &&
               currentBlockFromBlocks.has_value() == byteCursorFromBlocks.has_value();
    }

    std::optional<NamePoolAddresses> NamePoolLayout::Locate(uintptr_t root) const
    {
        if (root == 0 || !IsValid() || root > UINTPTR_MAX - static_cast<uintptr_t>(blocksOffset))
            return std::nullopt;
        NamePoolAddresses addresses{root + static_cast<uintptr_t>(blocksOffset), 0, 0};
        const auto relative = [&](int32_t offset) -> std::optional<uintptr_t>
        {
            const uint64_t magnitude = offset < 0 ? static_cast<uint64_t>(-int64_t{offset}) : static_cast<uint64_t>(offset);
            if (offset < 0)
                return magnitude <= addresses.blocks ? std::optional<uintptr_t>(addresses.blocks - magnitude) : std::nullopt;
            return magnitude <= UINTPTR_MAX - addresses.blocks ? std::optional<uintptr_t>(addresses.blocks + magnitude) : std::nullopt;
        };
        if (HasPublicationBoundary())
        {
            const auto current = relative(*currentBlockFromBlocks);
            const auto cursor = relative(*byteCursorFromBlocks);
            if (!current || !cursor || *cursor == 0)
                return std::nullopt;
            addresses.currentBlock = *current;
            addresses.byteCursor = *cursor;
        }
        return addresses;
    }

    bool NameContainerLayout::IsValid() const
    {
        return kind == NameContainerKind::Pool ? pool.IsValid() : array.IsValid();
    }

    DecodePlan DecodePlan::Identity()
    {
        DecodePlan result;
        result.objectStorage = [](uintptr_t value, uintptr_t)
        { return value; };
        result.objectChunk = [](uintptr_t value, uintptr_t)
        { return value; };
        result.objectPointer = [](uintptr_t value, uintptr_t)
        { return value; };
        result.objectClass = [](uintptr_t value, uintptr_t)
        { return value; };
        result.objectOuter = [](uintptr_t value, uintptr_t)
        { return value; };
        result.nameBlocks = [](uintptr_t value, uintptr_t)
        { return value; };
        result.nameChunks = [](uintptr_t value, uintptr_t)
        { return value; };
        result.nameEntry = [](uintptr_t value, uintptr_t)
        { return value; };
        result.objectCount = [](int32_t value, uintptr_t)
        { return value; };
        result.objectFlags = [](int32_t value, uintptr_t)
        { return value; };
        result.objectIndex = [](int32_t value, uintptr_t)
        { return value; };
        result.nameIndex = [](int32_t value, uintptr_t)
        { return value; };
        result.nameNumber = [](uint32_t value, uintptr_t)
        { return value; };
        result.nameEntryIndex = [](uint32_t value, uintptr_t)
        { return value; };
        result.nameHeader = [](uint16_t value, uintptr_t)
        { return value; };
        result.nameText = [](std::span<uint8_t>, uintptr_t, bool)
        { return true; };
        return result;
    }

    bool DecodePlan::IsValid() const
    {
        return objectStorage && objectChunk && objectPointer && objectClass && objectOuter &&
               nameBlocks && nameChunks && nameEntry && objectCount && objectFlags && objectIndex &&
               nameIndex && nameNumber && nameEntryIndex && nameHeader && nameText;
    }

    bool RuntimeBinding::IsValid() const
    {
        return objectRoot.address != 0 && nameRoot.address != 0 && objects.IsValid() && names.IsValid() &&
               decode.IsValid() && objectSchema && report.objectContainerValidated && report.nameContainerValidated &&
               report.semanticValidationPassed;
    }
} // namespace nextdumper::binding
