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

    bool DecodePlan::IsIdentity() const
    {
        const auto descriptor = Describe();
        return descriptor.IsValid() && descriptor.customSlots == 0 && nameText.IsIdentity();
    }

    decoding::DecodeDescriptor DecodePlan::Describe() const
    {
        using decoding::DecodeSlot;
        decoding::DecodeDescriptor descriptor;
        if (const auto *codec = nameText.BuiltinCodec())
            descriptor.nameText = *codec;
        const auto mark = [&](DecodeSlot slot, const auto &decoder)
        {
            if (decoder.IsCustom())
                descriptor.customSlots |= decoding::DecodeSlotBit(slot);
        };
        mark(DecodeSlot::ObjectStorage, objectStorage);
        mark(DecodeSlot::ObjectChunk, objectChunk);
        mark(DecodeSlot::ObjectPointer, objectPointer);
        mark(DecodeSlot::ObjectClass, objectClass);
        mark(DecodeSlot::ObjectOuter, objectOuter);
        mark(DecodeSlot::NameBlocks, nameBlocks);
        mark(DecodeSlot::NameChunks, nameChunks);
        mark(DecodeSlot::NameEntry, nameEntry);
        mark(DecodeSlot::ObjectCount, objectCount);
        mark(DecodeSlot::ObjectFlags, objectFlags);
        mark(DecodeSlot::ObjectIndex, objectIndex);
        mark(DecodeSlot::NameIndex, nameIndex);
        mark(DecodeSlot::NameNumber, nameNumber);
        mark(DecodeSlot::NameEntryIndex, nameEntryIndex);
        mark(DecodeSlot::NameHeader, nameHeader);
        mark(DecodeSlot::NameText, nameText);
        return descriptor;
    }

    bool DecodePlan::IsValid() const
    {
        return objectStorage.IsValid() && objectChunk.IsValid() && objectPointer.IsValid() &&
               objectClass.IsValid() && objectOuter.IsValid() && nameBlocks.IsValid() && nameChunks.IsValid() &&
               nameEntry.IsValid() && objectCount.IsValid() && objectFlags.IsValid() && objectIndex.IsValid() &&
               nameIndex.IsValid() && nameNumber.IsValid() && nameEntryIndex.IsValid() && nameHeader.IsValid() && nameText.IsValid();
    }

    bool RuntimeBinding::IsValid() const
    {
        return objectRoot.address != 0 && nameRoot.address != 0 && objects.IsValid() && names.IsValid() &&
               decode.IsValid() && (names.kind == NameContainerKind::Pool || !decode.nameText.RequiresLength()) &&
               objectSchema && report.objectContainerValidated && report.nameContainerValidated &&
               report.semanticValidationPassed;
    }
} // namespace nextdumper::binding
