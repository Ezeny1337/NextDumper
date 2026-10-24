#pragma once

#include <cstdint>
#include <vector>

namespace nextdumper::analysis
{
    enum class ContractState : uint8_t
    {
        Observed,
        Validated,
        Unsupported,
        Ambiguous,
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

        [[nodiscard]] bool operator==(const NamePoolFields &other) const = default;
    };

    enum class FNameNumberLayout : uint8_t
    {
        Inline,
        Outlined,
    };

    struct FNameLayoutFields
    {
        int32_t Size = -1;
        int32_t ComparisonIndex = -1;
        int32_t DisplayIndex = -1;
        int32_t Number = -1;
        FNameNumberLayout NumberLayout = FNameNumberLayout::Inline;

        [[nodiscard]] bool Complete() const
        {
            if (Size < static_cast<int32_t>(sizeof(int32_t)) || ComparisonIndex < 0 ||
                ComparisonIndex > Size - static_cast<int32_t>(sizeof(int32_t)))
                return false;
            if (DisplayIndex >= 0 && DisplayIndex > Size - static_cast<int32_t>(sizeof(int32_t)))
                return false;
            return NumberLayout == FNameNumberLayout::Outlined ||
                   (Number >= 0 && Number <= Size - static_cast<int32_t>(sizeof(int32_t)));
        }

        [[nodiscard]] bool operator==(const FNameLayoutFields &other) const = default;
    };

    struct UObjectLayoutFields
    {
        int32_t Name = -1;
        int32_t InternalIndex = -1;
        int32_t Class = -1;
        int32_t Outer = -1;

        [[nodiscard]] bool Complete() const
        {
            return Name >= 0 && InternalIndex >= 0 && Class >= 0 && Outer >= 0 &&
                   Name != InternalIndex && Name != Class && Name != Outer &&
                   InternalIndex != Class && InternalIndex != Outer && Class != Outer;
        }

        [[nodiscard]] bool operator==(const UObjectLayoutFields &other) const = default;
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

        [[nodiscard]] bool Complete() const
        {
            return ObjectsOffset >= 0 && MaxElementsOffset >= 0 && NumElementsOffset >= 0 &&
                   MaxChunksOffset >= 0 && NumChunksOffset >= 0 && (Fixed || ElementsPerChunk > 0) &&
                   ItemStride > 0 && ItemObjectOffset >= 0 && ItemIndexOffset >= 0;
        }

        [[nodiscard]] bool operator==(const ObjectArrayFields &other) const = default;
    };

    struct ObjectArrayObservation
    {
        uint32_t Count = 0;
        uint32_t MaxElements = 0;
        uint32_t Chunks = 0;
    };

    struct NamePoolContract
    {
        uintptr_t Root = 0;
        ContractState State = ContractState::Observed;
        NamePoolFields NamePool;
        std::vector<EvidenceStep> Evidence;
    };

    struct ObjectArrayContract
    {
        uintptr_t Root = 0;
        ContractState State = ContractState::Observed;
        ObjectArrayFields ObjectArray;
        ObjectArrayObservation Observation;
        std::vector<EvidenceStep> Evidence;
    };

    struct FNameLayoutContract
    {
        ContractState State = ContractState::Unsupported;
        FNameLayoutFields FName;
        std::vector<EvidenceStep> Evidence;
    };

    struct UObjectLayoutContract
    {
        uintptr_t ObjectRoot = 0;
        ContractState State = ContractState::Observed;
        UObjectLayoutFields UObject;
        FNameLayoutContract FName;
        std::vector<EvidenceStep> Evidence;
    };
} // namespace nextdumper::analysis
