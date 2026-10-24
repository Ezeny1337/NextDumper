#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace nextdumper::binding
{
    enum class AddressMeaning
    {
        Direct,
        PointerSlot,
        ResolvedValue,
    };

    enum class RootTarget : uint8_t
    {
        Unknown,
        GUObjectArray,
        ObjObjects,
        NamePool,
    };

    struct LocatedAddress
    {
        uintptr_t address = 0;
        AddressMeaning meaning = AddressMeaning::Direct;
        uint8_t confidence = 0;
        std::string source;
        RootTarget target = RootTarget::Unknown;
    };

    enum class ObjectContainerKind
    {
        Fixed,
        Chunked,
    };

    struct ObjectContainerLayout
    {
        ObjectContainerKind kind = ObjectContainerKind::Chunked;
        int32_t objectsOffset = -1;
        int32_t numElementsOffset = -1;
        int32_t maxElementsOffset = -1;
        int32_t numChunksOffset = -1;
        int32_t maxChunksOffset = -1;
        int32_t elementsPerChunk = -1;
        int32_t itemObjectOffset = -1;
        int32_t itemStride = -1;
        int32_t itemIndexOffset = -1;
        bool packedPointers = false;
        // 由对象契约探针按实际数据验证过 chunk 字段布局，读取器不再套用固定的 UE 字段顺序
        bool chunkFieldsValidated = false;

        [[nodiscard]] bool IsValid() const;
    };

    // UE 5.6 可能会对 FUObjectItem 指针进行打包，运行时布局探测会据此选择该候选布局
    [[nodiscard]] inline uintptr_t UnpackObjectItemPointer(uintptr_t value, bool packed)
    {
        if (!packed)
            return value;
        const uint64_t raw = static_cast<uint64_t>(value);
        return static_cast<uintptr_t>(((raw >> 32) & 0x3FFFu) << 35 | (raw & UINT32_MAX) << 3);
    }

    enum class NameContainerKind
    {
        Array,
        Pool,
    };

    struct NameArrayLayout
    {
        int32_t chunksOffset = -1;
        int32_t numElementsOffset = -1;
        int32_t elementsPerChunk = -1;
        int32_t entryIndexOffset = -1;
        int32_t entryStringOffset = -1;

        [[nodiscard]] bool IsValid() const;
    };

    struct NamePoolAddresses
    {
        uintptr_t blocks = 0;
        uintptr_t currentBlock = 0;
        uintptr_t byteCursor = 0;
    };

    struct NamePoolLayout
    {
        int32_t blocksOffset = -1;
        // Boundary fields are relative to the table, so a blocks-table alias and
        // a full pool root have the same publication contract. Empty means unknown.
        std::optional<int32_t> currentBlockFromBlocks;
        std::optional<int32_t> byteCursorFromBlocks;
        int32_t blocksBit = -1;
        int32_t entryStride = -1;
        int32_t entryHeaderOffset = -1;
        int32_t entryStringOffset = -1;
        int32_t entryLengthShift = -1;
        uint16_t entryWideMask = 0;

        [[nodiscard]] bool IsValid() const;
        [[nodiscard]] std::optional<NamePoolAddresses> Locate(uintptr_t root) const;
        [[nodiscard]] bool HasPublicationBoundary() const
        {
            return currentBlockFromBlocks.has_value() && byteCursorFromBlocks.has_value();
        }
    };

    struct NameContainerLayout
    {
        NameContainerKind kind = NameContainerKind::Pool;
        NameArrayLayout array;
        NamePoolLayout pool;

        [[nodiscard]] bool IsValid() const;
    };

    struct BindingLayoutHints
    {
        std::optional<ObjectContainerLayout> objects;
        std::optional<NameContainerLayout> names;
        // 仅分析层已验证但无法定位发布边界的名称池使用：读取器按整块上界工作
        bool allowFullBlockNameBound = false;

        [[nodiscard]] bool IsValid() const
        {
            return (!objects || objects->IsValid()) && (!names || names->IsValid());
        }
    };

    struct DecodePlan
    {
        using PointerDecoder = std::function<uintptr_t(uintptr_t value, uintptr_t fieldAddress)>;
        using Int32Decoder = std::function<int32_t(int32_t value, uintptr_t fieldAddress)>;
        using UInt32Decoder = std::function<uint32_t(uint32_t value, uintptr_t fieldAddress)>;
        using UInt16Decoder = std::function<uint16_t(uint16_t value, uintptr_t fieldAddress)>;
        using NameTextDecoder = std::function<bool(std::span<uint8_t> bytes, uintptr_t address, bool wide)>;

        PointerDecoder objectStorage;
        PointerDecoder objectChunk;
        PointerDecoder objectPointer;
        PointerDecoder objectClass;
        PointerDecoder objectOuter;
        PointerDecoder nameBlocks;
        PointerDecoder nameChunks;
        PointerDecoder nameEntry;
        Int32Decoder objectCount;
        Int32Decoder objectFlags;
        Int32Decoder objectIndex;
        Int32Decoder nameIndex;
        UInt32Decoder nameNumber;
        UInt32Decoder nameEntryIndex;
        UInt16Decoder nameHeader;
        NameTextDecoder nameText;

        static DecodePlan Identity();
        [[nodiscard]] bool IsValid() const;
    };

    struct CommonObjectInfo
    {
        std::string name;
        uintptr_t address = 0;
        int32_t index = -1;
    };

    struct BindingReport
    {
        bool staticCandidatesFound = false;
        bool objectContainerValidated = false;
        bool nameContainerValidated = false;
        bool semanticValidationPassed = false;
        std::vector<std::string> evidence;
        std::vector<std::string> failures;
    };

    struct RuntimeBinding
    {
        LocatedAddress objectRoot;
        LocatedAddress nameRoot;
        ObjectContainerLayout objects;
        NameContainerLayout names;
        DecodePlan decode = DecodePlan::Identity();
        BindingReport report;
        std::vector<CommonObjectInfo> commonObjects;

        [[nodiscard]] bool IsValid() const;
    };
} // namespace nextdumper::binding
