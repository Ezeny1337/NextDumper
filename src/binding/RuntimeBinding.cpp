#include "nextdumper/binding/RuntimeBinding.hpp"

namespace nextdumper::binding
{
    namespace
    {
        uintptr_t IdentityPointer(uintptr_t value, uintptr_t) { return value; }
        int32_t IdentityInt32(int32_t value, uintptr_t) { return value; }
        uint32_t IdentityUInt32(uint32_t value, uintptr_t) { return value; }
        uint16_t IdentityUInt16(uint16_t value, uintptr_t) { return value; }
        bool IdentityNameText(std::span<uint8_t>, uintptr_t, bool) { return true; }
    }

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
        result.objectStorage = IdentityPointer;
        result.objectChunk = IdentityPointer;
        result.objectPointer = IdentityPointer;
        result.objectClass = IdentityPointer;
        result.objectOuter = IdentityPointer;
        result.nameBlocks = IdentityPointer;
        result.nameChunks = IdentityPointer;
        result.nameEntry = IdentityPointer;
        result.objectCount = IdentityInt32;
        result.objectFlags = IdentityInt32;
        result.objectIndex = IdentityInt32;
        result.nameIndex = IdentityInt32;
        result.nameNumber = IdentityUInt32;
        result.nameEntryIndex = IdentityUInt32;
        result.nameHeader = IdentityUInt16;
        result.nameText = IdentityNameText;
        return result;
    }

    bool DecodePlan::IsIdentity() const
    {
        const auto pointerIsIdentity = [](const PointerDecoder &decoder)
        {
            const auto function = decoder.target<uintptr_t (*)(uintptr_t, uintptr_t)>();
            return function && *function == IdentityPointer;
        };
        const auto int32IsIdentity = [](const Int32Decoder &decoder)
        {
            const auto function = decoder.target<int32_t (*)(int32_t, uintptr_t)>();
            return function && *function == IdentityInt32;
        };
        const auto uint32IsIdentity = [](const UInt32Decoder &decoder)
        {
            const auto function = decoder.target<uint32_t (*)(uint32_t, uintptr_t)>();
            return function && *function == IdentityUInt32;
        };
        const auto uint16IsIdentity = [](const UInt16Decoder &decoder)
        {
            const auto function = decoder.target<uint16_t (*)(uint16_t, uintptr_t)>();
            return function && *function == IdentityUInt16;
        };
        const auto nameTextFunction = nameText.target<bool (*)(std::span<uint8_t>, uintptr_t, bool)>();
        return pointerIsIdentity(objectStorage) && pointerIsIdentity(objectChunk) &&
               pointerIsIdentity(objectPointer) && pointerIsIdentity(objectClass) &&
               pointerIsIdentity(objectOuter) && pointerIsIdentity(nameBlocks) &&
               pointerIsIdentity(nameChunks) && pointerIsIdentity(nameEntry) &&
               int32IsIdentity(objectCount) && int32IsIdentity(objectFlags) &&
               int32IsIdentity(objectIndex) && int32IsIdentity(nameIndex) &&
               uint32IsIdentity(nameNumber) && uint32IsIdentity(nameEntryIndex) &&
               uint16IsIdentity(nameHeader) && nameTextFunction &&
               *nameTextFunction == IdentityNameText;
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
