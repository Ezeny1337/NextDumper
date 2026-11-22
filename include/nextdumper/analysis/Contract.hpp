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

    // 名称存储的两个结构族：块池（4.23 起）与间接数组（4.22 及更早）
    // 族由代码形状与数据形状判定，不按引擎版本号选择
    enum class NameStoreFamily : uint8_t
    {
        Pool,
        Array,
    };

    [[nodiscard]] const char *NameStoreFamilyName(NameStoreFamily family);

    // 池族：uint16 条目头携带长度与宽窄，块内条目按 stride 对齐，发布边界之外视为未初始化
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

    // 数组族：根对象内的 chunk 指针表指向定长槽数组，每个槽是指向条目的指针
    // 条目内 Index 的 bit0 表示宽字符，文本以 NUL 结尾且没有长度字段
    struct NameArrayFields
    {
        int32_t ChunksOffset = -1;
        int32_t ChunkShift = -1;
        int32_t SlotStride = 0;
        int32_t EntryIndexOffset = -1;
        int32_t StringOffset = -1;

        [[nodiscard]] bool Complete() const
        {
            return ChunksOffset >= 0 && ChunksOffset <= 4096 && ChunkShift >= 8 && ChunkShift <= 24 &&
                   SlotStride >= static_cast<int32_t>(sizeof(uint32_t)) && SlotStride <= 64 &&
                   EntryIndexOffset >= 0 && EntryIndexOffset <= 64 &&
                   StringOffset >= EntryIndexOffset + static_cast<int32_t>(sizeof(uint32_t)) &&
                   StringOffset <= 128;
        }

        [[nodiscard]] bool operator==(const NameArrayFields &other) const = default;
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
        // 只有 chunked 容器才有这两个字段；fixed 容器（4.19 及更早）没有它们
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
                   (Fixed ? ElementsPerChunk == 0
                          : (MaxChunksOffset >= 0 && NumChunksOffset >= 0 && ElementsPerChunk > 0)) &&
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

    struct NameStoreContract
    {
        uintptr_t Root = 0;
        ContractState State = ContractState::Observed;
        NameStoreFamily Family = NameStoreFamily::Pool;
        NamePoolFields NamePool;
        NameArrayFields NameArray;
        std::vector<EvidenceStep> Evidence;

        [[nodiscard]] bool Complete() const
        {
            return Family == NameStoreFamily::Pool ? NamePool.Complete() : NameArray.Complete();
        }

        // 同一族且字段一致即视为同一契约，用于跨候选去重与歧义判定
        [[nodiscard]] bool SameShape(const NameStoreContract &other) const
        {
            return Family == other.Family &&
                   (Family == NameStoreFamily::Pool ? NamePool == other.NamePool : NameArray == other.NameArray);
        }
    };

    // 解析名称所需的全部信息：根地址、族与族内字段；派生自契约，也用于直接指定
    struct NameStoreView
    {
        uintptr_t Root = 0;
        NameStoreFamily Family = NameStoreFamily::Pool;
        NamePoolFields Pool;
        NameArrayFields Array;

        [[nodiscard]] bool Complete() const
        {
            return Root != 0 &&
                   (Family == NameStoreFamily::Pool ? Pool.Complete() : Array.Complete());
        }

        [[nodiscard]] static NameStoreView From(const NameStoreContract &contract)
        {
            NameStoreView view;
            view.Root = contract.Root;
            view.Family = contract.Family;
            view.Pool = contract.NamePool;
            view.Array = contract.NameArray;
            return view;
        }
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
