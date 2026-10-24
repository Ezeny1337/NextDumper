#pragma once

#include <cstdint>
#include <vector>

namespace nextdumper::analysis
{
    enum class ContractKind : uint8_t
    {
        NamePool,
        ObjectArray,
    };

    enum class ContractState : uint8_t
    {
        Observed,
        Validated,
        Unsupported,
    };

    enum class EvidenceKind : uint8_t
    {
        GlobalBase,
        Shift,
        Mask,
        ScaleAdd,
        TableLoad,
        EntryLoad,
        HeaderLoad,
        WidthTest,
        TextOffset,
        CallArgument,
        UnresolvedRoot,
    };

    struct EvidenceStep
    {
        EvidenceKind Kind = EvidenceKind::GlobalBase;
        uintptr_t Site = 0;
        uint64_t Value = 0;
    };

    struct NamePoolFields
    {
        int32_t BlocksOffset = -1;
        int32_t BlocksBit = -1;
        int32_t EntryStride = 0;
        int32_t HeaderOffset = 0;
        int32_t StringOffset = 2;
        int32_t LengthShift = 0;
        uint16_t WideMask = 0;

        [[nodiscard]] bool Complete() const
        {
            return BlocksOffset >= 0 && BlocksBit > 0 && EntryStride > 0 && HeaderOffset >= 0 &&
                   StringOffset >= HeaderOffset + 2 && LengthShift > 0 && WideMask != 0;
        }
    };

    struct UObjectLayoutFields
    {
        int32_t Name = -1;
        int32_t InternalIndex = -1;
        int32_t Class = -1;
        int32_t Outer = -1;

        [[nodiscard]] bool Complete() const
        {
            return Name >= 0 && InternalIndex >= 0 && Class >= 0 && Outer >= 0;
        }
    };

    struct ObjectArrayFields
    {
        int32_t ObjectsOffset = 0;
        int32_t MaxElementsOffset = -1;
        int32_t NumElementsOffset = -1;
        int32_t MaxChunksOffset = -1;
        int32_t NumChunksOffset = -1;
        int32_t ElementsPerChunk = 0;
        int32_t ItemStride = 0;
        int32_t ItemObjectOffset = -1;
        int32_t ItemIndexOffset = -1;
        bool PackedPointers = false;
        bool Fixed = false;
        uint32_t Count = 0;
        uint32_t MaxElements = 0;
        uint32_t Chunks = 0;

        [[nodiscard]] bool Complete() const
        {
            return ObjectsOffset >= 0 && MaxElementsOffset >= 0 && NumElementsOffset >= 0 &&
                   MaxChunksOffset >= 0 && NumChunksOffset >= 0 && (Fixed || ElementsPerChunk > 0) &&
                   ItemStride > 0 && ItemObjectOffset >= 0 && ItemIndexOffset >= 0 && Count > 0;
        }
    };

    struct Contract
    {
        ContractKind Kind = ContractKind::NamePool;
        uintptr_t Root = 0;
        ContractState State = ContractState::Observed;
        NamePoolFields NamePool;
        ObjectArrayFields ObjectArray;
        UObjectLayoutFields UObject;
        std::vector<EvidenceStep> Evidence;
    };
} // namespace nextdumper::analysis
