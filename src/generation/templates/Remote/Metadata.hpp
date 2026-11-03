#pragma once

#include "../BasicTypes.hpp"

#include <cstddef>
#include <cstdint>

namespace NextDumper
{
    enum class PropertyKind : std::uint8_t
    {
        Unknown,
        Bool,
        Byte,
        Int8,
        Int16,
        Int32,
        Int64,
        UInt16,
        UInt32,
        UInt64,
        Float,
        Double,
        Name,
        String,
        Text,
        Object,
        SoftObject,
        WeakObject,
        LazyObject,
        Class,
        SoftClass,
        Struct,
        Enum,
        Array,
        Set,
        Map,
        Interface,
        Delegate,
        MulticastDelegate,
        FieldPath,
        Optional,
    };

    enum class TypeKind : std::uint8_t
    {
        Class,
        Struct,
    };

    enum class DelegateStorageKind : std::uint8_t
    {
        None,
        Unicast,
        InlineMulticast,
        SparseMulticast,
        UnknownMulticast,
    };

    enum class ContainerAllocatorKind : std::uint8_t
    {
        Unknown,
        Heap,
        MemoryImage,
    };

    struct BoolLayoutDescriptor
    {
        std::uint8_t fieldSize = 0;
        std::uint8_t byteOffset = 0;
        std::uint8_t byteMask = 0;
        std::uint8_t fieldMask = 0;
        bool valid = false;
    };

    struct StorageMemberDescriptor
    {
        const char *name = "";
        std::int32_t offset = -1;
    };

    struct ValueStorageDescriptor
    {
        const char *id = "";
        const char *sourceRange = "";
        std::int32_t size = 0;
        std::int32_t alignment = 0;
        const StorageMemberDescriptor *members = nullptr;
        std::size_t memberCount = 0;
    };

    struct ContainerDescriptor
    {
        ContainerAllocatorKind allocator = ContainerAllocatorKind::Unknown;
        const char *allocatorStatus = "";
        const char *layoutStatus = "";
        const char *headerStatus = "";
        const char *layoutId = "";
        std::int32_t valueOffset = -1;
        std::int32_t hashNextOffset = -1;
        std::int32_t hashIndexOffset = -1;
        std::int32_t setElementSize = -1;
        std::int32_t elementAlignment = -1;
        std::int32_t elementStride = -1;
    };

    struct ValueDescriptor
    {
        PropertyKind kind = PropertyKind::Unknown;
        const char *reflectedClass = "";
        const char *referencedType = "";
        const char *secondaryType = "";
        std::int32_t elementSize = 0;
        std::int32_t arrayDim = 0;
        bool detailsResolved = false;
        bool nodeDetailsResolved = false;
        DelegateStorageKind delegateStorage = DelegateStorageKind::None;
        BoolLayoutDescriptor boolean;
        ContainerDescriptor container;
        ValueStorageDescriptor storage;
        const ValueDescriptor *inner = nullptr;
        const ValueDescriptor *key = nullptr;
        const ValueDescriptor *value = nullptr;
    };

    struct FieldDescriptor
    {
        const char *name = "";
        std::int32_t offset = -1;
        std::int32_t elementSize = 0;
        std::int32_t arrayDim = 0;
        std::uint64_t flags = 0;
        bool validBounds = false;
        bool virtualProperty = false;
        const char *status = "";
        BoolLayoutDescriptor boolean;
        const ValueDescriptor *type = nullptr;
    };

    struct TypeDescriptor
    {
        const char *fullName = "";
        const char *name = "";
        const char *superFullName = "";
        TypeKind kind = TypeKind::Struct;
        std::int32_t size = 0;
        const char *status = "";
        const FieldDescriptor *fields = nullptr;
        std::size_t fieldCount = 0;
    };

    struct EnumValueDescriptor
    {
        const char *name = "";
        std::int64_t value = 0;
    };

    struct EnumDescriptor
    {
        const char *fullName = "";
        const char *name = "";
        std::uint8_t storageSize = 0;
        bool storageUnsigned = false;
        const EnumValueDescriptor *values = nullptr;
        std::size_t valueCount = 0;
    };

    enum class ObjectArrayKind : std::uint8_t
    {
        Fixed,
        Chunked,
    };

    struct ObjectArrayDescriptor
    {
        ObjectArrayKind kind = ObjectArrayKind::Chunked;
        std::int32_t objectsOffset = -1;
        std::int32_t numElementsOffset = -1;
        std::int32_t maxElementsOffset = -1;
        std::int32_t numChunksOffset = -1;
        std::int32_t maxChunksOffset = -1;
        std::int32_t elementsPerChunk = -1;
        std::int32_t itemObjectOffset = -1;
        std::int32_t itemStride = -1;
        std::int32_t itemIndexOffset = -1;
        bool packedPointers = false;
    };

    enum class NameStoreKind : std::uint8_t
    {
        Array,
        Pool,
    };

    struct NameStoreDescriptor
    {
        NameStoreKind kind = NameStoreKind::Pool;
        std::int32_t chunksOffset = -1;
        std::int32_t numElementsOffset = -1;
        std::int32_t elementsPerChunk = -1;
        std::int32_t entryIndexOffset = -1;
        std::int32_t entryStringOffset = -1;
        std::int32_t blocksOffset = -1;
        std::int32_t currentBlockFromBlocks = -1;
        std::int32_t byteCursorFromBlocks = -1;
        std::int32_t blocksBit = -1;
        std::int32_t entryStride = -1;
        std::int32_t entryHeaderOffset = -1;
        std::int32_t poolStringOffset = -1;
        std::int32_t entryLengthShift = -1;
        std::uint16_t entryWideMask = 0;
        bool hasPublicationBoundary = false;
    };

    struct FNameDescriptor
    {
        std::int32_t size = -1;
        std::int32_t comparisonIndex = -1;
        std::int32_t number = -1;
        std::int32_t displayIndex = -1;
        bool numberInline = true;
    };

    struct ObjectDescriptor
    {
        std::int32_t classOffset = -1;
        std::int32_t flagsOffset = -1;
        std::int32_t internalIndexOffset = -1;
        std::int32_t nameOffset = -1;
        std::int32_t outerOffset = -1;
    };

    struct RuntimeBindingDescriptor
    {
        const char *moduleName = "";
        std::uint8_t pointerWidth = 0;
        bool hasObjectRootRva = false;
        bool hasNameRootRva = false;
        bool customDecodingRequired = false;
        TargetAddress objectRootRva = 0;
        TargetAddress nameRootRva = 0;
        ObjectArrayDescriptor objects;
        NameStoreDescriptor names;
        FNameDescriptor fname;
        ObjectDescriptor uobject;
        bool casePreservingName = false;
    };

    struct RuntimeRoots
    {
        TargetAddress objectRoot = 0;
        TargetAddress nameRoot = 0;
    };

    struct RuntimeOptions
    {
        std::int32_t maxObjectCount = 0x08000000;
        std::size_t maxObjectsPerSearch = 1000000;
        std::size_t maxSearchResults = 4096;
        std::size_t maxNameEntries = 0x08000000;
        std::size_t maxContainerSlots = 1000000;
        std::size_t maxSparseSlots = 65536;
        std::size_t maxStringCharacters = 1024 * 1024;
        std::size_t maxOpaqueBytes = 1024 * 1024;
        std::size_t maxOuterDepth = 64;
    };
} // namespace NextDumper
