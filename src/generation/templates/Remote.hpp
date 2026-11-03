#pragma once

#include "BasicTypes.hpp"
#include "EngineLayouts.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace NextDumper
{
    enum class ReadStatus : std::uint8_t
    {
        Ok,
        Empty,
        Incomplete,
        InvalidArgument,
        NotInitialized,
        Unsupported,
        ReadFailure,
        PartialRead,
        InvalidHeader,
        InvalidReference,
        InvalidIndex,
        AddressOverflow,
        LimitExceeded,
        NotFound,
        Ambiguous,
        StaleObject,
    };

    struct ReadResult
    {
        ReadStatus status = ReadStatus::Ok;
        std::size_t requested = 0;
        std::size_t transferred = 0;

        [[nodiscard]] bool Ok() const { return status == ReadStatus::Ok; }
    };

    using ReadMemoryCallback = std::int64_t (*)(void *, TargetAddress, void *, std::size_t);

    struct MemoryReader
    {
        void *context = nullptr;
        ReadMemoryCallback read = nullptr;
        std::size_t maxTransferBytes = std::numeric_limits<std::size_t>::max();

        [[nodiscard]] ReadResult Read(TargetAddress address, void *buffer, std::size_t size) const
        {
            ReadResult result{ReadStatus::Ok, size, 0};
            if ((!buffer && size != 0) || (size != 0 && address == 0) ||
                (size != 0 && size - 1 > std::numeric_limits<TargetAddress>::max() - address) ||
                !read || maxTransferBytes == 0)
            {
                result.status = ReadStatus::InvalidArgument;
                return result;
            }
            auto *output = static_cast<std::uint8_t *>(buffer);
            while (result.transferred < size)
            {
                const std::size_t requested = std::min(maxTransferBytes, size - result.transferred);
                const TargetAddress current = static_cast<TargetAddress>(address + result.transferred);
                const std::int64_t transferred = read(context, current, output + result.transferred, requested);
                if (transferred <= 0)
                {
                    result.status = result.transferred == 0 ? ReadStatus::ReadFailure : ReadStatus::PartialRead;
                    return result;
                }
                if (static_cast<std::uint64_t>(transferred) > requested)
                {
                    result.status = ReadStatus::ReadFailure;
                    return result;
                }
                result.transferred += static_cast<std::size_t>(transferred);
            }
            return result;
        }
    };

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

    struct ObjectHandle
    {
        TargetAddress address = 0;
        std::int32_t index = -1;
        std::int32_t serial = 0;
        bool serialKnown = false;
    };

    class RemoteRuntime;

    struct RemoteObjectView
    {
        RemoteRuntime *runtime = nullptr;
        ObjectHandle handle;
        const TypeDescriptor *type = nullptr;
    };

    struct RemoteStructView
    {
        RemoteRuntime *runtime = nullptr;
        TargetAddress address = 0;
        const TypeDescriptor *type = nullptr;
    };

    struct RemoteStaticArrayView
    {
        RemoteRuntime *runtime = nullptr;
        TargetAddress address = 0;
        const ValueDescriptor *element = nullptr;
        std::int32_t count = 0;
        std::int32_t stride = 0;
        BoolLayoutDescriptor boolean;
    };

    struct RemoteArrayView
    {
        RemoteRuntime *runtime = nullptr;
        TargetAddress address = 0;
        TargetAddress data = 0;
        const ValueDescriptor *element = nullptr;
        std::int32_t count = 0;
        std::int32_t capacity = 0;
        std::int32_t stride = 0;
        bool memoryImage = false;
        bool frozen = false;
    };

    struct RemoteSparseContainerView
    {
        RemoteRuntime *runtime = nullptr;
        TargetAddress address = 0;
        TargetAddress data = 0;
        const ValueDescriptor *key = nullptr;
        const ValueDescriptor *value = nullptr;
        std::vector<std::uint32_t> allocationBits;
        std::int32_t slots = 0;
        std::int32_t count = 0;
        std::int32_t stride = 0;
        std::int32_t valueOffset = 0;
        bool isMap = false;
    };

    struct RemoteMapEntryView
    {
        RemoteRuntime *runtime = nullptr;
        TargetAddress keyAddress = 0;
        TargetAddress valueAddress = 0;
        const ValueDescriptor *key = nullptr;
        const ValueDescriptor *value = nullptr;
    };

    struct ObjectReference
    {
        TargetAddress address = 0;
        const char *typeName = "";
        std::optional<RemoteObjectView> object;
    };

    struct EnumValue
    {
        const EnumDescriptor *type = nullptr;
        std::int64_t value = 0;
        std::uint64_t unsignedValue = 0;
        bool isUnsigned = false;
        const char *name = "";
    };

    struct WeakObjectReference
    {
        std::int32_t index = -1;
        std::int32_t serial = 0;
        std::optional<RemoteObjectView> object;
    };

    struct SoftObjectReference
    {
        std::int32_t index = -1;
        std::int32_t serial = 0;
        std::uint32_t tagAtLastTest = 0;
        std::uint64_t remoteId = 0;
        std::string packageName;
        std::string assetName;
        std::string subPath;
    };

    struct LazyObjectReference
    {
        std::int32_t index = -1;
        std::int32_t serial = 0;
        std::uint32_t tagAtLastTest = 0;
        std::uint64_t remoteId = 0;
        std::array<std::uint8_t, 16> objectId{};
    };

    struct InterfaceReference
    {
        TargetAddress object = 0;
        TargetAddress interface = 0;
        std::optional<RemoteObjectView> resolvedObject;
    };

    struct DelegateReference
    {
        std::int32_t index = -1;
        std::int32_t serial = 0;
        std::string functionName;
        std::optional<RemoteObjectView> target;
    };

    struct TextReference
    {
        TargetAddress data = 0;
        std::uint64_t flags = 0;
        std::string status = "text-history-unresolved";
    };

    struct OpaqueValue
    {
        TargetAddress address = 0;
        std::string reason;
        std::vector<std::uint8_t> bytes;
    };

    using RemoteValue = std::variant<std::monostate, bool, std::int64_t, std::uint64_t, double,
                                     std::string, ObjectReference, EnumValue, WeakObjectReference,
                                     SoftObjectReference, LazyObjectReference, InterfaceReference, DelegateReference,
                                     TextReference, RemoteObjectView, RemoteStructView,
                                     RemoteStaticArrayView, RemoteArrayView, RemoteSparseContainerView,
                                     RemoteMapEntryView, OpaqueValue>;

    struct ValueReadResult
    {
        ReadStatus status = ReadStatus::Ok;
        RemoteValue value;

        [[nodiscard]] bool Ok() const { return status == ReadStatus::Ok; }
    };

    struct ObjectInfo
    {
        ObjectHandle handle;
        TargetAddress classAddress = 0;
        TargetAddress outerAddress = 0;
        std::uint32_t flags = 0;
        std::string name;
        std::string className;
        std::string classFullName;
        std::string fullName;
    };

    struct ObjectQuery
    {
        std::string_view fullName;
        std::string_view classFullName;
        std::string_view className;
        std::string_view name;
    };

    struct ObjectQueryResult
    {
        ReadStatus status = ReadStatus::Ok;
        std::size_t slotsVisited = 0;
        bool complete = false;
        std::vector<RemoteObjectView> objects;
    };

    struct ObjectLookupResult
    {
        ReadStatus status = ReadStatus::NotFound;
        std::optional<RemoteObjectView> object;
        std::size_t slotsVisited = 0;
    };

    class RemoteRuntime
    {
    public:
        RemoteRuntime(MemoryReader memory, TargetAddress moduleBase,
                      const RuntimeBindingDescriptor &binding,
                      const TypeDescriptor *types, std::size_t typeCount,
                      const EnumDescriptor *enums, std::size_t enumCount,
                      RuntimeOptions options = {})
            : memory_(memory), moduleBase_(moduleBase), binding_(binding),
              moduleName_(binding.moduleName ? binding.moduleName : ""),
              types_(types), typeCount_(typeCount), enums_(enums), enumCount_(enumCount),
              options_(options)
        {
            binding_.moduleName = moduleName_.c_str();
            options_.maxObjectCount = std::min(options_.maxObjectCount, 0x08000000);
            options_.maxObjectsPerSearch = std::min<std::size_t>(options_.maxObjectsPerSearch, 0x08000000);
            options_.maxSearchResults = std::min<std::size_t>(options_.maxSearchResults, 65536);
            options_.maxNameEntries = std::min<std::size_t>(options_.maxNameEntries, 0x08000000);
            options_.maxContainerSlots = std::min<std::size_t>(options_.maxContainerSlots, 1'000'000);
            options_.maxSparseSlots = std::min<std::size_t>(options_.maxSparseSlots, 65536);
            options_.maxStringCharacters = std::min<std::size_t>(options_.maxStringCharacters, 1024 * 1024);
            options_.maxOpaqueBytes = std::min<std::size_t>(options_.maxOpaqueBytes, 1024 * 1024);
            options_.maxOuterDepth = std::min<std::size_t>(options_.maxOuterDepth, 256);
        }

        RemoteRuntime(const RemoteRuntime &) = delete;
        RemoteRuntime &operator=(const RemoteRuntime &) = delete;
        RemoteRuntime(RemoteRuntime &&) = delete;
        RemoteRuntime &operator=(RemoteRuntime &&) = delete;

        [[nodiscard]] ReadStatus Initialize(const char *moduleName, RuntimeRoots roots = {})
        {
            Reset();
            if (!memory_.read || !moduleName || Empty(binding_.moduleName) ||
                (typeCount_ && !types_) || (enumCount_ && !enums_) ||
                binding_.pointerWidth != sizeof(TargetAddress) ||
                std::string_view(moduleName) != binding_.moduleName)
                return ReadStatus::InvalidArgument;
            if (binding_.customDecodingRequired)
                return ReadStatus::Unsupported;
            if (!moduleBase_ && ((!roots.objectRoot && binding_.hasObjectRootRva) ||
                                 (!roots.nameRoot && binding_.hasNameRootRva)))
                return ReadStatus::InvalidArgument;
            objectRoot_ = roots.objectRoot;
            nameRoot_ = roots.nameRoot;
            if (!objectRoot_ && binding_.hasObjectRootRva &&
                !Add(moduleBase_, binding_.objectRootRva, objectRoot_))
                return ReadStatus::AddressOverflow;
            if (!nameRoot_ && binding_.hasNameRootRva &&
                !Add(moduleBase_, binding_.nameRootRva, nameRoot_))
                return ReadStatus::AddressOverflow;
            if (!objectRoot_ || !nameRoot_ || !ValidLayouts())
                return ReadStatus::Unsupported;

            initialized_ = true;
            const ReadStatus objects = RefreshObjectCount();
            if (objects != ReadStatus::Ok)
            {
                Reset();
                return objects;
            }
            const auto none = ReadName(0);
            if (!none || *none != "None")
            {
                Reset();
                return ReadStatus::InvalidHeader;
            }
            return ReadStatus::Ok;
        }

        void Reset()
        {
            initialized_ = false;
            objectRoot_ = 0;
            nameRoot_ = 0;
            objectStorage_ = 0;
            objectCount_ = 0;
            nameCache_.clear();
        }

        [[nodiscard]] bool IsInitialized() const { return initialized_; }
        [[nodiscard]] std::int32_t ObjectCount() const { return objectCount_; }
        [[nodiscard]] TargetAddress ObjectRoot() const { return objectRoot_; }
        [[nodiscard]] TargetAddress NameRoot() const { return nameRoot_; }

        [[nodiscard]] ReadStatus RefreshObjectCount()
        {
            if (!initialized_ || !objectRoot_)
                return ReadStatus::NotInitialized;
            TargetAddress countAddress = 0;
            TargetAddress storageAddress = 0;
            if (!Add(objectRoot_, static_cast<std::uint32_t>(binding_.objects.numElementsOffset), countAddress) ||
                !Add(objectRoot_, static_cast<std::uint32_t>(binding_.objects.objectsOffset), storageAddress))
                return ReadStatus::AddressOverflow;
            std::int32_t count = 0;
            TargetAddress storage = 0;
            if (!ReadExact(countAddress, &count, sizeof(count)).Ok() ||
                ReadPointer(storageAddress, storage).status != ReadStatus::Ok)
                return ReadStatus::ReadFailure;
            if (count <= 0 || count > options_.maxObjectCount || !storage ||
                (objectStorage_ && storage != objectStorage_) ||
                (objectStorage_ && binding_.objects.kind == ObjectArrayKind::Fixed &&
                 count != objectCount_))
                return ReadStatus::InvalidHeader;
            if (binding_.objects.maxElementsOffset >= 0)
            {
                std::int32_t capacity = 0;
                TargetAddress capacityAddress = 0;
                if (!Add(objectRoot_, static_cast<std::uint32_t>(binding_.objects.maxElementsOffset), capacityAddress) ||
                    !ReadExact(capacityAddress, &capacity, sizeof(capacity)).Ok() ||
                    capacity < count || capacity > options_.maxObjectCount)
                    return ReadStatus::InvalidHeader;
            }
            if (binding_.objects.kind == ObjectArrayKind::Chunked)
            {
                const std::int32_t requiredChunks = (count - 1) / binding_.objects.elementsPerChunk + 1;
                for (const std::int32_t offset : {binding_.objects.numChunksOffset, binding_.objects.maxChunksOffset})
                {
                    if (offset < 0)
                        continue;
                    TargetAddress address = 0;
                    std::int32_t chunks = 0;
                    if (!Add(objectRoot_, static_cast<std::uint32_t>(offset), address) ||
                        !ReadExact(address, &chunks, sizeof(chunks)).Ok() || chunks < requiredChunks ||
                        chunks > 0x1000)
                        return ReadStatus::InvalidHeader;
                }
            }
            objectStorage_ = storage;
            objectCount_ = count;
            return ReadStatus::Ok;
        }

        [[nodiscard]] ReadStatus ReadObject(std::int32_t index, RemoteObjectView &out)
        {
            out = {};
            if (!initialized_)
                return ReadStatus::NotInitialized;
            if (index < 0 || index >= objectCount_)
                return ReadStatus::InvalidIndex;
            TargetAddress itemBase = objectStorage_;
            if (binding_.objects.kind == ObjectArrayKind::Chunked)
            {
                const std::int32_t chunkIndex = index / binding_.objects.elementsPerChunk;
                const std::int32_t withinChunk = index % binding_.objects.elementsPerChunk;
                TargetAddress chunkSlot = 0;
                TargetAddress chunk = 0;
                if (!AddScaled(objectStorage_, chunkIndex, static_cast<std::int32_t>(sizeof(TargetAddress)), chunkSlot))
                    return ReadStatus::AddressOverflow;
                const ReadStatus chunkRead = ReadPointer(chunkSlot, chunk);
                if (chunkRead != ReadStatus::Ok)
                    return chunkRead;
                if (!chunk)
                    return ReadStatus::InvalidReference;
                if (!AddScaled(chunk, withinChunk, binding_.objects.itemStride, itemBase))
                    return ReadStatus::AddressOverflow;
            }
            else if (!AddScaled(objectStorage_, index, binding_.objects.itemStride, itemBase))
                return ReadStatus::AddressOverflow;

            TargetAddress objectSlot = 0;
            TargetAddress address = 0;
            if (!Add(itemBase, static_cast<std::uint32_t>(binding_.objects.itemObjectOffset), objectSlot))
                return ReadStatus::AddressOverflow;
            const ReadStatus pointerRead = ReadPointer(objectSlot, address);
            if (pointerRead != ReadStatus::Ok)
                return pointerRead;
            if (binding_.objects.packedPointers)
                address = static_cast<TargetAddress>((((static_cast<std::uint64_t>(address) >> 32) & 0x3FFFu) << 35) |
                                                     ((static_cast<std::uint64_t>(address) & UINT32_MAX) << 3));
            if (!address)
                return ReadStatus::Empty;

            std::int32_t reportedIndex = -1;
            TargetAddress indexAddress = 0;
            if (binding_.uobject.internalIndexOffset < 0 ||
                !Add(address, static_cast<std::uint32_t>(binding_.uobject.internalIndexOffset), indexAddress) ||
                !ReadExact(indexAddress, &reportedIndex, sizeof(reportedIndex)).Ok() || reportedIndex != index)
                return ReadStatus::InvalidReference;
            ObjectHandle handle{address, index, 0, false};
            handle.serialKnown = ReadObjectSerial(index, handle.serial);
            out = {this, handle, nullptr};
            return ReadStatus::Ok;
        }

        [[nodiscard]] std::optional<ObjectInfo> Describe(const RemoteObjectView &object)
        {
            if (object.runtime != this || !ValidateHandle(object.handle))
                return std::nullopt;
            return ReadObjectInfo(object.handle);
        }

        [[nodiscard]] ObjectQueryResult FindObjects(const ObjectQuery &query,
                                                    std::size_t maxResults = 128)
        {
            ObjectQueryResult result;
            if (!initialized_)
            {
                result.status = ReadStatus::NotInitialized;
                return result;
            }
            if (query.fullName.empty() && query.classFullName.empty() &&
                query.className.empty() && query.name.empty())
            {
                result.status = ReadStatus::InvalidArgument;
                return result;
            }
            if (maxResults == 0)
            {
                result.status = ReadStatus::InvalidArgument;
                return result;
            }
            const std::size_t resultLimit = std::min(maxResults, options_.maxSearchResults);
            if (RefreshObjectCount() != ReadStatus::Ok)
            {
                result.status = ReadStatus::InvalidHeader;
                return result;
            }
            const std::size_t limit = std::min<std::size_t>(objectCount_, options_.maxObjectsPerSearch);
            for (std::size_t index = 0; index < limit; ++index)
            {
                ++result.slotsVisited;
                RemoteObjectView object;
                const ReadStatus objectStatus = ReadObject(static_cast<std::int32_t>(index), object);
                if (objectStatus == ReadStatus::Empty)
                    continue;
                if (objectStatus != ReadStatus::Ok)
                {
                    result.status = ReadStatus::Incomplete;
                    continue;
                }
                bool matches = true;
                std::string objectName, className, classFullName, fullName;
                TargetAddress classAddress = 0;
                if (!query.name.empty() || !query.fullName.empty())
                {
                    if (!ReadObjectName(object.handle.address, objectName))
                    {
                        result.status = ReadStatus::Incomplete;
                        continue;
                    }
                    matches = query.name.empty() || objectName == query.name;
                }
                if (matches && (!query.className.empty() || !query.classFullName.empty() ||
                                !query.fullName.empty()))
                {
                    if (!ReadObjectClass(object.handle.address, classAddress) ||
                        !ReadObjectName(classAddress, className))
                    {
                        result.status = ReadStatus::Incomplete;
                        continue;
                    }
                    matches = query.className.empty() || className == query.className;
                }
                if (matches && !query.classFullName.empty())
                {
                    if (!ReadFullName(classAddress, classFullName))
                    {
                        result.status = ReadStatus::Incomplete;
                        continue;
                    }
                    matches = classFullName == query.classFullName;
                }
                if (matches && !query.fullName.empty())
                {
                    if (!ReadFullName(object.handle.address, fullName))
                    {
                        result.status = ReadStatus::Incomplete;
                        continue;
                    }
                    matches = fullName == query.fullName;
                }
                if (matches)
                {
                    if (!classFullName.empty())
                        object.type = FindType(classFullName);
                    result.objects.push_back(object);
                    if (result.objects.size() >= resultLimit)
                    {
                        if (result.status != ReadStatus::Incomplete)
                            result.status = ReadStatus::LimitExceeded;
                        return result;
                    }
                }
            }
            result.complete = limit == static_cast<std::size_t>(objectCount_);
            if (!result.complete && result.status == ReadStatus::Ok)
                result.status = ReadStatus::LimitExceeded;
            return result;
        }

        [[nodiscard]] ObjectLookupResult FindFirstObject(const ObjectQuery &query)
        {
            ObjectQueryResult matches = FindObjects(query, 1);
            if (!matches.objects.empty())
                return {matches.status == ReadStatus::Incomplete ? ReadStatus::Incomplete : ReadStatus::Ok,
                        matches.objects.front(), matches.slotsVisited};
            return {matches.status == ReadStatus::Ok ? ReadStatus::NotFound : matches.status,
                    std::nullopt, matches.slotsVisited};
        }

        [[nodiscard]] ValueReadResult ReadField(const RemoteObjectView &object, std::string_view name)
        {
            if (object.runtime != this || !ValidateHandle(object.handle))
                return {ReadStatus::StaleObject, {}};
            const TypeDescriptor *type = object.type;
            if (!type)
            {
                const auto info = ReadObjectInfo(object.handle);
                type = info ? FindType(info->classFullName) : nullptr;
            }
            const FieldDescriptor *field = FindField(type, name);
            if (!field)
                return {ReadStatus::NotFound, {}};
            return ReadFieldAt(object.handle.address, *field);
        }

        [[nodiscard]] ValueReadResult ReadField(const RemoteStructView &structure, std::string_view name)
        {
            if (structure.runtime != this || !structure.address || !structure.type)
                return {ReadStatus::InvalidArgument, {}};
            const FieldDescriptor *field = FindField(structure.type, name);
            if (!field)
                return {ReadStatus::NotFound, {}};
            return ReadFieldAt(structure.address, *field);
        }

        template <typename T>
        [[nodiscard]] ReadStatus ReadField(const RemoteObjectView &object, std::string_view name, T &out)
        {
            const auto result = ReadField(object, name);
            if (!result.Ok())
                return result.status;
            return Convert(result.value, out) ? ReadStatus::Ok : ReadStatus::Unsupported;
        }

        template <typename T>
        [[nodiscard]] ReadStatus ReadField(const RemoteStructView &structure, std::string_view name, T &out)
        {
            const auto result = ReadField(structure, name);
            if (!result.Ok())
                return result.status;
            return Convert(result.value, out) ? ReadStatus::Ok : ReadStatus::Unsupported;
        }

        [[nodiscard]] ValueReadResult ReadFieldAt(TargetAddress owner, const FieldDescriptor &field)
        {
            if (!initialized_)
                return {ReadStatus::NotInitialized, {}};
            if (!field.validBounds || field.virtualProperty || !field.type || field.offset < 0 ||
                field.elementSize <= 0 || field.arrayDim <= 0)
                return {ReadStatus::Unsupported, {}};
            TargetAddress address = 0;
            if (!Add(owner, static_cast<std::uint32_t>(field.offset), address))
                return {ReadStatus::AddressOverflow, {}};
            if (field.arrayDim > 1)
            {
                const std::int64_t stride = static_cast<std::int64_t>(field.elementSize);
                if (stride <= 0 || stride > INT32_MAX)
                    return {ReadStatus::InvalidHeader, {}};
                return {ReadStatus::Ok, RemoteStaticArrayView{this, address, field.type, field.arrayDim,
                                                              static_cast<std::int32_t>(stride), field.boolean}};
            }
            return ReadValueAt(address, *field.type, field.boolean);
        }

        [[nodiscard]] ValueReadResult ReadValueAt(TargetAddress address, const ValueDescriptor &type,
                                                  BoolLayoutDescriptor boolean = {})
        {
            if (!initialized_)
                return {ReadStatus::NotInitialized, {}};
            if (!address || type.elementSize <= 0 || type.arrayDim <= 0)
                return {ReadStatus::InvalidArgument, {}};
            if (!boolean.valid)
                boolean = type.boolean;
            if (type.arrayDim > 1)
                return {ReadStatus::Ok, RemoteStaticArrayView{this, address, &type, type.arrayDim,
                                                              type.elementSize, type.boolean}};
            if (!type.detailsResolved && type.kind != PropertyKind::Unknown)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize),
                                  "type-details-unresolved");
            const std::int32_t expectedSize = ScalarSize(type.kind);
            if (expectedSize > 0 && expectedSize != type.elementSize)
                return {ReadStatus::Unsupported, {}};
            switch (type.kind)
            {
            case PropertyKind::Bool:
                return ReadBoolean(address, type.elementSize, boolean);
            case PropertyKind::Int8:
            case PropertyKind::Int16:
            case PropertyKind::Int32:
            case PropertyKind::Int64:
                return ReadSignedValue(address, type.elementSize);
            case PropertyKind::Byte:
            case PropertyKind::UInt16:
            case PropertyKind::UInt32:
            case PropertyKind::UInt64:
                if (type.kind == PropertyKind::Byte && !Empty(type.referencedType))
                    return ReadEnum(address, type.elementSize, true, type.referencedType);
                return ReadUnsigned(address, type.elementSize);
            case PropertyKind::Float:
                return ReadFloat(address, type.elementSize);
            case PropertyKind::Double:
                return ReadFloat(address, type.elementSize);
            case PropertyKind::Enum:
                return ReadEnumStorage(address, type);
            case PropertyKind::Name:
            {
                if (type.elementSize != binding_.fname.size)
                    return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "fname-size-mismatch");
                const auto name = ReadFName(address);
                return name ? ValueReadResult{ReadStatus::Ok, *name}
                            : ValueReadResult{ReadStatus::ReadFailure, {}};
            }
            case PropertyKind::String:
                return ReadString(address, type);
            case PropertyKind::Object:
            case PropertyKind::Class:
                if (std::string_view(type.reflectedClass ? type.reflectedClass : "").find("PtrProperty") != std::string_view::npos)
                    return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "object-pointer-storage-unverified");
                if (type.elementSize != binding_.pointerWidth)
                    return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "object-pointer-size-mismatch");
                return ReadObjectReference(address, type.referencedType);
            case PropertyKind::WeakObject:
                return ReadWeakObject(address, type);
            case PropertyKind::SoftObject:
            case PropertyKind::SoftClass:
                return ReadSoftObject(address, type);
            case PropertyKind::LazyObject:
                return ReadLazyObject(address, type);
            case PropertyKind::Interface:
                return ReadInterface(address, type);
            case PropertyKind::Struct:
            {
                const TypeDescriptor *descriptor = FindType(type.referencedType);
                if (!descriptor || descriptor->size != type.elementSize)
                    return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "struct-type-unavailable");
                return {ReadStatus::Ok, RemoteStructView{this, address, descriptor}};
            }
            case PropertyKind::Array:
                return OpenArray(address, type);
            case PropertyKind::Set:
            case PropertyKind::Map:
                return OpenSparseContainer(address, type);
            case PropertyKind::Delegate:
                return ReadDelegate(address, type);
            case PropertyKind::MulticastDelegate:
                if (type.delegateStorage == DelegateStorageKind::SparseMulticast && type.elementSize == 1)
                {
                    const auto bound = ReadBoolean(address, 1, {1, 0, 1, 1, true});
                    return bound;
                }
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize),
                                  "multicast-bindings-require-validated-element-layout");
            case PropertyKind::Text:
                return ReadText(address, type);
            case PropertyKind::Unknown:
            case PropertyKind::FieldPath:
            case PropertyKind::Optional:
            default:
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize),
                                  type.detailsResolved ? "value-semantics-not-supported" : "type-details-unresolved");
            }
        }

        [[nodiscard]] ValueReadResult ReadElement(const RemoteStaticArrayView &array, std::int32_t index)
        {
            if (array.runtime != this || !array.address || !array.element || array.count <= 0 ||
                array.stride <= 0 || index < 0 || index >= array.count)
                return {ReadStatus::InvalidIndex, {}};
            TargetAddress address = 0;
            if (!AddScaled(array.address, index, array.stride, address))
                return {ReadStatus::AddressOverflow, {}};
            ValueDescriptor element = *array.element;
            element.arrayDim = 1;
            return ReadValueAt(address, element, array.boolean);
        }

        [[nodiscard]] ValueReadResult ReadElement(const RemoteArrayView &array, std::int32_t index)
        {
            if (array.runtime != this || !array.address || !array.element || array.count <= 0 ||
                array.stride <= 0 || index < 0 || index >= array.count)
                return {ReadStatus::InvalidIndex, {}};
            if (array.frozen)
                return {ReadStatus::Unsupported, {}};
            TargetAddress address = 0;
            if (!AddScaled(array.data, index, array.stride, address))
                return {ReadStatus::AddressOverflow, {}};
            return ReadValueAt(address, *array.element);
        }

        [[nodiscard]] ValueReadResult ReadSparseSlot(const RemoteSparseContainerView &container,
                                                     std::int32_t slot)
        {
            if (container.runtime != this || !container.data || container.slots <= 0 ||
                container.stride <= 0 || slot < 0 || slot >= container.slots)
                return {ReadStatus::InvalidIndex, {}};
            const std::size_t wordIndex = static_cast<std::size_t>(slot) / 32;
            if (wordIndex >= container.allocationBits.size())
                return {ReadStatus::InvalidHeader, {}};
            const std::uint32_t word = container.allocationBits[wordIndex];
            if ((word & (std::uint32_t{1} << (slot % 32))) == 0)
                return {ReadStatus::InvalidIndex, {}};
            TargetAddress address = 0;
            if (!AddScaled(container.data, slot, container.stride, address))
                return {ReadStatus::AddressOverflow, {}};
            if (!container.isMap)
            {
                const auto extent = ValueExtent(container.key);
                if (!container.key || !extent || *extent > container.stride)
                    return {ReadStatus::InvalidHeader, {}};
                return ReadValueAt(address, *container.key);
            }
            TargetAddress valueAddress = 0;
            const auto keyExtent = ValueExtent(container.key);
            const auto valueExtent = ValueExtent(container.value);
            if (!container.value || !keyExtent || !valueExtent ||
                container.valueOffset < *keyExtent ||
                container.valueOffset > container.stride - *valueExtent ||
                !Add(address, static_cast<std::uint32_t>(container.valueOffset), valueAddress))
                return {ReadStatus::InvalidHeader, {}};
            return {ReadStatus::Ok, RemoteMapEntryView{this, address, valueAddress,
                                                       container.key, container.value}};
        }

        [[nodiscard]] ValueReadResult ReadMapKey(const RemoteMapEntryView &entry)
        {
            if (entry.runtime != this || !entry.key || !entry.keyAddress)
                return {ReadStatus::InvalidArgument, {}};
            return ReadValueAt(entry.keyAddress, *entry.key);
        }

        [[nodiscard]] ValueReadResult ReadMapValue(const RemoteMapEntryView &entry)
        {
            if (entry.runtime != this || !entry.value || !entry.valueAddress)
                return {ReadStatus::InvalidArgument, {}};
            return ReadValueAt(entry.valueAddress, *entry.value);
        }

    private:
        template <typename T>
        [[nodiscard]] static bool Convert(const RemoteValue &value, T &out)
        {
            if constexpr (std::is_same_v<T, std::string>)
            {
                const auto text = std::get_if<std::string>(&value);
                if (!text)
                    return false;
                out = *text;
                return true;
            }
            else if constexpr (std::is_same_v<T, bool>)
            {
                const auto boolean = std::get_if<bool>(&value);
                if (!boolean)
                    return false;
                out = *boolean;
                return true;
            }
            else if constexpr (std::is_enum_v<T>)
            {
                using Underlying = std::underlying_type_t<T>;
                Underlying raw{};
                if (!Convert(value, raw))
                    return false;
                out = static_cast<T>(raw);
                return true;
            }
            else if constexpr (std::is_integral_v<T>)
            {
                if (const auto signedValue = std::get_if<std::int64_t>(&value))
                {
                    if (!InRange<T>(*signedValue))
                        return false;
                    out = static_cast<T>(*signedValue);
                    return true;
                }
                if (const auto unsignedValue = std::get_if<std::uint64_t>(&value))
                {
                    if (!InRange<T>(*unsignedValue))
                        return false;
                    out = static_cast<T>(*unsignedValue);
                    return true;
                }
                if (const auto enumeration = std::get_if<EnumValue>(&value))
                {
                    if (enumeration->isUnsigned)
                    {
                        if (!InRange<T>(enumeration->unsignedValue))
                            return false;
                        out = static_cast<T>(enumeration->unsignedValue);
                        return true;
                    }
                    if (InRange<T>(enumeration->value))
                    {
                        out = static_cast<T>(enumeration->value);
                        return true;
                    }
                    return false;
                }
                return false;
            }
            else if constexpr (std::is_floating_point_v<T>)
            {
                const auto number = std::get_if<double>(&value);
                if (!number)
                    return false;
                if constexpr (sizeof(T) < sizeof(double))
                    if (*number < -std::numeric_limits<T>::max() ||
                        *number > std::numeric_limits<T>::max())
                        return false;
                out = static_cast<T>(*number);
                return true;
            }
            else
                return false;
        }

        [[nodiscard]] static bool Empty(const char *value) { return !value || value[0] == '\0'; }

        [[nodiscard]] static std::int32_t ScalarSize(PropertyKind kind)
        {
            switch (kind)
            {
            case PropertyKind::Byte:
            case PropertyKind::Int8:
                return 1;
            case PropertyKind::Int16:
            case PropertyKind::UInt16:
                return 2;
            case PropertyKind::Int32:
            case PropertyKind::UInt32:
            case PropertyKind::Float:
                return 4;
            case PropertyKind::Int64:
            case PropertyKind::UInt64:
            case PropertyKind::Double:
                return 8;
            default:
                return 0;
            }
        }

        [[nodiscard]] static std::optional<std::int32_t> ValueExtent(const ValueDescriptor *value)
        {
            if (!value || value->elementSize <= 0 || value->arrayDim <= 0)
                return std::nullopt;
            const std::int64_t extent = static_cast<std::int64_t>(value->elementSize) * value->arrayDim;
            if (extent <= 0 || extent > INT32_MAX)
                return std::nullopt;
            return static_cast<std::int32_t>(extent);
        }

        [[nodiscard]] std::optional<std::int32_t> SparseHeaderSize(bool memoryImage) const
        {
            if (memoryImage)
                return binding_.pointerWidth == 8 ? std::optional<std::int32_t>(56) : std::nullopt;
            const std::int64_t pointer = binding_.pointerWidth;
            if (pointer != 4 && pointer != 8)
                return std::nullopt;
            const auto align = [pointer](std::int64_t size)
            { return (size + pointer - 1) / pointer * pointer; };
            const std::int64_t bits = pointer + 8;
            const std::int64_t bitsSecondary = bits + 16;
            const std::int64_t bitsNum = bitsSecondary + pointer;
            const std::int64_t bitsMax = bitsNum + 4;
            const std::int64_t firstFree = bitsMax + 4;
            const std::int64_t freeCount = firstFree + 4;
            const std::int64_t hash = align(freeCount + 4);
            const std::int64_t hashSecondary = hash + align(4);
            const std::int64_t hashSize = hashSecondary + pointer;
            const std::int64_t size = align(hashSize + 4);
            return size <= INT32_MAX ? std::optional<std::int32_t>(static_cast<std::int32_t>(size))
                                     : std::nullopt;
        }

        [[nodiscard]] static bool Add(TargetAddress base, std::uint64_t offset, TargetAddress &out)
        {
            if (!base || offset > std::numeric_limits<TargetAddress>::max() - base)
                return false;
            out = static_cast<TargetAddress>(base + offset);
            return true;
        }

        [[nodiscard]] static bool AddScaled(TargetAddress base, std::int32_t index,
                                            std::int32_t stride, TargetAddress &out)
        {
            if (index < 0 || stride <= 0 ||
                static_cast<std::uint64_t>(index) >
                    std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint32_t>(stride))
                return false;
            return Add(base, static_cast<std::uint64_t>(index) * static_cast<std::uint32_t>(stride), out);
        }

        [[nodiscard]] ReadResult ReadExact(TargetAddress address, void *buffer, std::size_t size) const
        {
            return memory_.Read(address, buffer, size);
        }

        [[nodiscard]] ReadStatus ReadPointer(TargetAddress address, TargetAddress &value) const
        {
            value = 0;
            if (binding_.pointerWidth == 4)
            {
                std::uint32_t raw = 0;
                if (!ReadExact(address, &raw, sizeof(raw)).Ok())
                    return ReadStatus::ReadFailure;
                value = static_cast<TargetAddress>(raw);
                return ReadStatus::Ok;
            }
            if (binding_.pointerWidth == 8)
            {
                std::uint64_t raw = 0;
                if (!ReadExact(address, &raw, sizeof(raw)).Ok() ||
                    raw > std::numeric_limits<TargetAddress>::max())
                    return ReadStatus::ReadFailure;
                value = static_cast<TargetAddress>(raw);
                return ReadStatus::Ok;
            }
            return ReadStatus::Unsupported;
        }

        [[nodiscard]] bool ValidLayouts() const
        {
            const auto &objects = binding_.objects;
            const auto &names = binding_.names;
            const auto &object = binding_.uobject;
            const std::int32_t pointer = binding_.pointerWidth;
            if ((binding_.pointerWidth != 4 && binding_.pointerWidth != 8) ||
                binding_.fname.size <= 0 || binding_.fname.comparisonIndex < 0 ||
                binding_.fname.comparisonIndex > binding_.fname.size - 4 ||
                objects.objectsOffset < 0 || objects.numElementsOffset < 0 ||
                objects.itemObjectOffset < 0 || objects.itemStride <= 0 ||
                objects.itemObjectOffset > objects.itemStride - pointer ||
                objects.itemIndexOffset < 0 ||
                object.classOffset < 0 || object.internalIndexOffset < 0 ||
                object.nameOffset < 0 || object.outerOffset < 0)
                return false;
            if (binding_.casePreservingName &&
                (binding_.fname.displayIndex < 0 ||
                 binding_.fname.displayIndex > binding_.fname.size - 4))
                return false;
            if (binding_.fname.numberInline &&
                (binding_.fname.number < 0 || binding_.fname.number > binding_.fname.size - 4))
                return false;
            if (objects.kind != ObjectArrayKind::Fixed && objects.kind != ObjectArrayKind::Chunked)
                return false;
            if (objects.kind == ObjectArrayKind::Chunked &&
                (objects.elementsPerChunk <= 0 || objects.numChunksOffset < 0))
                return false;
            if (names.kind == NameStoreKind::Pool)
                return names.blocksOffset >= 0 && names.blocksBit > 0 && names.blocksBit <= 18 &&
                       (names.entryStride == 2 || names.entryStride == 4) &&
                       names.entryHeaderOffset >= 0 && names.poolStringOffset >= names.entryHeaderOffset + 2 &&
                       names.entryLengthShift >= 0 && names.entryLengthShift < 16 &&
                       names.entryWideMask != 0;
            if (names.kind != NameStoreKind::Array)
                return false;
            return names.chunksOffset >= 0 && names.elementsPerChunk > 0 &&
                   names.entryIndexOffset >= 0 && names.entryStringOffset >= 0;
        }

        [[nodiscard]] const TypeDescriptor *FindType(std::string_view fullName) const
        {
            if (fullName.empty())
                return nullptr;
            const TypeDescriptor *found = nullptr;
            for (std::size_t index = 0; index < typeCount_; ++index)
            {
                if (types_[index].fullName != fullName)
                    continue;
                if (found)
                    return nullptr;
                found = &types_[index];
            }
            return found;
        }

        [[nodiscard]] const EnumDescriptor *FindEnum(std::string_view fullName) const
        {
            if (fullName.empty())
                return nullptr;
            for (std::size_t index = 0; index < enumCount_; ++index)
                if (enums_[index].fullName == fullName)
                    return &enums_[index];
            return nullptr;
        }

        [[nodiscard]] const FieldDescriptor *FindField(const TypeDescriptor *type,
                                                       std::string_view name) const
        {
            for (std::size_t depth = 0; type && depth < 64; ++depth)
            {
                for (std::size_t index = 0; index < type->fieldCount; ++index)
                    if (type->fields[index].name == name)
                        return &type->fields[index];
                type = FindType(type->superFullName);
            }
            return nullptr;
        }

        [[nodiscard]] bool IsTypeA(const TypeDescriptor *type, std::string_view baseName) const
        {
            std::array<std::string_view, 64> visited{};
            std::size_t count = 0;
            for (; type && count < visited.size(); ++count)
            {
                if (type->fullName == baseName)
                    return true;
                if (std::find(visited.begin(), visited.begin() + static_cast<std::ptrdiff_t>(count),
                              std::string_view(type->fullName)) !=
                    visited.begin() + static_cast<std::ptrdiff_t>(count))
                    return false;
                visited[count] = type->fullName;
                type = FindType(type->superFullName);
            }
            return false;
        }

        [[nodiscard]] bool ValidateHandle(const ObjectHandle &handle)
        {
            if (!initialized_ || handle.index < 0 || handle.index >= objectCount_ || !handle.address)
                return false;
            RemoteObjectView current;
            if (ReadObject(handle.index, current) != ReadStatus::Ok ||
                current.handle.address != handle.address)
                return false;
            return !handle.serialKnown ||
                   (current.handle.serialKnown && current.handle.serial == handle.serial);
        }

        [[nodiscard]] bool ReadObjectSerial(std::int32_t index, std::int32_t &serial)
        {
            serial = 0;
            const std::size_t pointerWidth = binding_.objects.packedPointers ? sizeof(std::uint32_t)
                                                                             : binding_.pointerWidth;
            const std::int64_t offset = static_cast<std::int64_t>(binding_.objects.itemObjectOffset) +
                                        static_cast<std::int64_t>(pointerWidth) + 8;
            if (binding_.objects.itemObjectOffset != 0 || offset < 0 ||
                offset + 4 > binding_.objects.itemStride)
                return false;
            TargetAddress item = 0;
            TargetAddress address = 0;
            if (binding_.objects.kind == ObjectArrayKind::Fixed)
            {
                if (!AddScaled(objectStorage_, index, binding_.objects.itemStride, item))
                    return false;
            }
            else
            {
                const std::int32_t chunkIndex = index / binding_.objects.elementsPerChunk;
                const std::int32_t within = index % binding_.objects.elementsPerChunk;
                TargetAddress chunkSlot = 0;
                TargetAddress chunk = 0;
                if (!AddScaled(objectStorage_, chunkIndex, binding_.pointerWidth, chunkSlot) ||
                    ReadPointer(chunkSlot, chunk) != ReadStatus::Ok ||
                    !AddScaled(chunk, within, binding_.objects.itemStride, item))
                    return false;
            }
            if (!Add(item, static_cast<std::uint32_t>(offset), address))
                return false;
            return ReadExact(address, &serial, sizeof(serial)).Ok() && serial > 0;
        }

        [[nodiscard]] bool ReadObjectName(TargetAddress object, std::string &name)
        {
            TargetAddress address = 0;
            return binding_.uobject.nameOffset >= 0 &&
                   Add(object, static_cast<std::uint32_t>(binding_.uobject.nameOffset), address) &&
                   ReadFName(address, name);
        }

        [[nodiscard]] bool ReadObjectClass(TargetAddress object, TargetAddress &classAddress)
        {
            TargetAddress address = 0;
            return binding_.uobject.classOffset >= 0 &&
                   Add(object, static_cast<std::uint32_t>(binding_.uobject.classOffset), address) &&
                   ReadPointer(address, classAddress) == ReadStatus::Ok && classAddress != 0;
        }

        [[nodiscard]] bool ReadObjectClassName(TargetAddress object, std::string &className)
        {
            TargetAddress classAddress = 0;
            return ReadObjectClass(object, classAddress) && ReadObjectName(classAddress, className);
        }

        [[nodiscard]] bool ReadOuter(TargetAddress object, TargetAddress &outer)
        {
            TargetAddress address = 0;
            return binding_.uobject.outerOffset >= 0 &&
                   Add(object, static_cast<std::uint32_t>(binding_.uobject.outerOffset), address) &&
                   ReadPointer(address, outer) == ReadStatus::Ok;
        }

        [[nodiscard]] bool ReadFullName(TargetAddress object, std::string &fullName,
                                        std::size_t depth = 0)
        {
            if (depth >= options_.maxOuterDepth)
                return false;
            std::string objectName;
            std::string className;
            if (!ReadObjectName(object, objectName) || !ReadObjectClassName(object, className))
                return false;
            std::vector<std::string> outerNames;
            std::vector<TargetAddress> visited{object};
            TargetAddress current = object;
            for (std::size_t level = 0; level < options_.maxOuterDepth; ++level)
            {
                TargetAddress outer = 0;
                if (!ReadOuter(current, outer))
                    return false;
                if (!outer)
                    break;
                if (std::find(visited.begin(), visited.end(), outer) != visited.end())
                    return false;
                visited.push_back(outer);
                std::string name;
                if (!ReadObjectName(outer, name))
                    return false;
                outerNames.push_back(std::move(name));
                current = outer;
                if (level + 1 == options_.maxOuterDepth)
                    return false;
            }
            fullName = std::move(className);
            fullName.push_back(' ');
            for (auto at = outerNames.rbegin(); at != outerNames.rend(); ++at)
            {
                fullName += *at;
                fullName.push_back('.');
            }
            fullName += objectName;
            return true;
        }

        [[nodiscard]] std::optional<ObjectInfo> ReadObjectInfo(const ObjectHandle &handle)
        {
            ObjectInfo info;
            info.handle = handle;
            if (!ReadObjectClass(handle.address, info.classAddress) ||
                !ReadOuter(handle.address, info.outerAddress) ||
                !ReadObjectName(handle.address, info.name) ||
                !ReadObjectClassName(handle.address, info.className) ||
                !ReadFullName(handle.address, info.fullName))
                return std::nullopt;
            TargetAddress flagsAddress = 0;
            std::int32_t flags = 0;
            if (binding_.uobject.flagsOffset >= 0 &&
                Add(handle.address, static_cast<std::uint32_t>(binding_.uobject.flagsOffset), flagsAddress) &&
                ReadExact(flagsAddress, &flags, sizeof(flags)).Ok())
                info.flags = static_cast<std::uint32_t>(flags);
            std::string classFullName;
            if (!ReadFullName(info.classAddress, classFullName))
                return std::nullopt;
            info.classFullName = std::move(classFullName);
            return info;
        }

        [[nodiscard]] bool LocateNameEntry(std::int32_t index, TargetAddress &entry,
                                           std::size_t &available)
        {
            entry = 0;
            available = 0;
            if (index < 0)
                return false;
            if (binding_.names.kind == NameStoreKind::Array)
            {
                const auto &layout = binding_.names;
                if (layout.elementsPerChunk <= 0)
                    return false;
                if (layout.numElementsOffset >= 0)
                {
                    TargetAddress countAddress = 0;
                    std::int32_t count = 0;
                    if (!Add(nameRoot_, static_cast<std::uint32_t>(layout.numElementsOffset), countAddress) ||
                        !ReadExact(countAddress, &count, sizeof(count)).Ok() || count < 0 ||
                        static_cast<std::size_t>(count) > options_.maxNameEntries || index >= count)
                        return false;
                }
                const std::int32_t chunkIndex = index / layout.elementsPerChunk;
                const std::int32_t within = index % layout.elementsPerChunk;
                if (chunkIndex >= 128)
                    return false;
                TargetAddress chunksAddress = 0, chunkSlot = 0, chunk = 0, entrySlot = 0;
                if (!Add(nameRoot_, static_cast<std::uint32_t>(layout.chunksOffset), chunksAddress) ||
                    ReadPointer(chunksAddress, chunk) != ReadStatus::Ok ||
                    !AddScaled(chunk, chunkIndex, binding_.pointerWidth, chunkSlot) ||
                    ReadPointer(chunkSlot, chunk) != ReadStatus::Ok || !chunk ||
                    !AddScaled(chunk, within, binding_.pointerWidth, entrySlot) ||
                    ReadPointer(entrySlot, entry) != ReadStatus::Ok || !entry)
                    return false;
                available = 2048;
                return true;
            }

            const auto &layout = binding_.names;
            const std::int32_t blockIndex = index >> layout.blocksBit;
            const std::int32_t entryIndex = index & ((1 << layout.blocksBit) - 1);
            if (blockIndex < 0 || blockIndex >= 8192)
                return false;
            const std::size_t blockSize = (std::size_t{1} << layout.blocksBit) *
                                          static_cast<std::size_t>(layout.entryStride);
            const std::size_t offset = static_cast<std::size_t>(entryIndex) *
                                       static_cast<std::size_t>(layout.entryStride);
            std::size_t usedBytes = blockSize;
            TargetAddress blocks = 0;
            if (!Add(nameRoot_, static_cast<std::uint32_t>(layout.blocksOffset), blocks))
                return false;
            if (layout.hasPublicationBoundary)
            {
                TargetAddress currentAddress = 0, cursorAddress = 0;
                std::uint32_t current = 0, cursor = 0;
                if (!AddSigned(blocks, layout.currentBlockFromBlocks, currentAddress) ||
                    !AddSigned(blocks, layout.byteCursorFromBlocks, cursorAddress) ||
                    !ReadExact(currentAddress, &current, sizeof(current)).Ok() ||
                    !ReadExact(cursorAddress, &cursor, sizeof(cursor)).Ok() ||
                    current >= 8192 || cursor > blockSize ||
                    cursor % static_cast<std::uint32_t>(layout.entryStride) != 0 ||
                    static_cast<std::uint32_t>(blockIndex) > current)
                    return false;
                if (static_cast<std::uint32_t>(blockIndex) == current)
                    usedBytes = cursor;
            }
            if (offset >= usedBytes ||
                usedBytes - offset < static_cast<std::size_t>(layout.poolStringOffset))
                return false;
            TargetAddress blockSlot = 0, block = 0;
            if (!AddScaled(blocks, blockIndex, binding_.pointerWidth, blockSlot) ||
                ReadPointer(blockSlot, block) != ReadStatus::Ok || !block ||
                !AddScaled(block, entryIndex, layout.entryStride, entry))
                return false;
            available = usedBytes - offset;
            return true;
        }

        [[nodiscard]] static bool AddSigned(TargetAddress base, std::int32_t offset,
                                            TargetAddress &out)
        {
            if (!base)
                return false;
            if (offset < 0)
            {
                const std::uint64_t magnitude = static_cast<std::uint64_t>(-static_cast<std::int64_t>(offset));
                if (magnitude > base)
                    return false;
                out = static_cast<TargetAddress>(base - magnitude);
                return true;
            }
            return Add(base, static_cast<std::uint32_t>(offset), out);
        }

        [[nodiscard]] bool ReadNameEntry(std::int32_t index, std::string &name, std::size_t depth = 0)
        {
            if (depth >= 32)
                return false;
            if (const auto cached = nameCache_.find(index); cached != nameCache_.end())
            {
                name = cached->second;
                return true;
            }
            TargetAddress entry = 0;
            std::size_t available = 0;
            if (!LocateNameEntry(index, entry, available))
                return false;
            if (binding_.names.kind == NameStoreKind::Array)
            {
                TargetAddress indexAddress = 0, stringAddress = 0;
                std::uint32_t rawIndex = 0;
                if (!Add(entry, static_cast<std::uint32_t>(binding_.names.entryIndexOffset), indexAddress) ||
                    !Add(entry, static_cast<std::uint32_t>(binding_.names.entryStringOffset), stringAddress) ||
                    !ReadExact(indexAddress, &rawIndex, sizeof(rawIndex)).Ok())
                    return false;
                const bool wide = (rawIndex & 1u) != 0;
                const std::size_t chars = std::min<std::size_t>(1024, available / (wide ? 2 : 1));
                if (chars == 0 || !ReadTextBytes(stringAddress, chars, wide, name))
                    return false;
            }
            else
            {
                const auto &layout = binding_.names;
                TargetAddress headerAddress = 0, stringAddress = 0;
                std::uint16_t header = 0;
                if (!Add(entry, static_cast<std::uint32_t>(layout.entryHeaderOffset), headerAddress) ||
                    !Add(entry, static_cast<std::uint32_t>(layout.poolStringOffset), stringAddress) ||
                    !ReadExact(headerAddress, &header, sizeof(header)).Ok())
                    return false;
                const std::size_t length = header >> layout.entryLengthShift;
                if (length > 1024)
                    return false;
                if (length == 0)
                {
                    const std::int32_t indexOffset = layout.poolStringOffset +
                                                     (layout.poolStringOffset == 6 ? 2 : 0);
                    TargetAddress baseIndexAddress = 0, numberAddress = 0;
                    std::int32_t baseIndex = -1;
                    std::uint32_t number = 0;
                    if (static_cast<std::size_t>(indexOffset) + 8 > available ||
                        !Add(entry, static_cast<std::uint32_t>(indexOffset), baseIndexAddress) ||
                        !Add(baseIndexAddress, sizeof(baseIndex), numberAddress) ||
                        !ReadExact(baseIndexAddress, &baseIndex, sizeof(baseIndex)).Ok() ||
                        !ReadExact(numberAddress, &number, sizeof(number)).Ok() ||
                        !ReadNameEntry(baseIndex, name, depth + 1))
                        return false;
                    if (number > 0)
                        name += "_" + std::to_string(number - 1);
                }
                else
                {
                    const bool wide = (header & layout.entryWideMask) != 0;
                    const std::size_t bytes = length * (wide ? 2 : 1);
                    if (layout.poolStringOffset > available ||
                        bytes > available - static_cast<std::size_t>(layout.poolStringOffset) ||
                        !ReadTextBytes(stringAddress, length, wide, name))
                        return false;
                }
            }
            if (nameCache_.size() < 65536)
                nameCache_.emplace(index, name);
            return true;
        }

        [[nodiscard]] bool ReadTextBytes(TargetAddress address, std::size_t chars,
                                         bool wide, std::string &result) const
        {
            if (chars == 0 || chars > 1024)
                return false;
            if (!wide)
            {
                std::vector<char> bytes(chars);
                if (!ReadExact(address, bytes.data(), bytes.size()).Ok())
                    return false;
                const auto end = std::find(bytes.begin(), bytes.end(), '\0');
                result.assign(bytes.begin(), end);
                return true;
            }
            std::vector<char16_t> text(chars);
            if (!ReadExact(address, text.data(), text.size() * sizeof(char16_t)).Ok())
                return false;
            result.clear();
            for (std::size_t index = 0; index < text.size() && text[index] != 0; ++index)
            {
                std::uint32_t codePoint = text[index];
                if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
                {
                    if (index + 1 >= text.size() || text[index + 1] < 0xDC00 ||
                        text[index + 1] > 0xDFFF)
                        return false;
                    codePoint = 0x10000 + ((codePoint - 0xD800) << 10) +
                                (static_cast<std::uint32_t>(text[++index]) - 0xDC00);
                }
                else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF)
                    return false;
                AppendUtf8(result, codePoint);
            }
            return true;
        }

        static void AppendUtf8(std::string &output, std::uint32_t codePoint)
        {
            if (codePoint <= 0x7F)
                output.push_back(static_cast<char>(codePoint));
            else if (codePoint <= 0x7FF)
            {
                output.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
                output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
            }
            else if (codePoint <= 0xFFFF)
            {
                output.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
                output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
                output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
            }
            else if (codePoint <= 0x10FFFF)
            {
                output.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
                output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
                output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
                output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
            }
        }

        [[nodiscard]] std::optional<std::string> ReadName(std::int32_t index)
        {
            std::string result;
            return ReadNameEntry(index, result) ? std::optional<std::string>(std::move(result))
                                                : std::nullopt;
        }

        [[nodiscard]] bool ReadFName(TargetAddress address, std::string &result)
        {
            TargetAddress comparisonAddress = 0;
            std::int32_t comparisonIndex = -1;
            if (!Add(address, static_cast<std::uint32_t>(binding_.fname.comparisonIndex), comparisonAddress) ||
                !ReadExact(comparisonAddress, &comparisonIndex, sizeof(comparisonIndex)).Ok())
                return false;
            if (!ReadNameEntry(comparisonIndex, result))
                return false;
            if (binding_.casePreservingName && binding_.fname.displayIndex >= 0)
            {
                TargetAddress displayAddress = 0;
                std::int32_t displayIndex = -1;
                std::string display;
                if (!Add(address, static_cast<std::uint32_t>(binding_.fname.displayIndex), displayAddress) ||
                    !ReadExact(displayAddress, &displayIndex, sizeof(displayIndex)).Ok() ||
                    !ReadNameEntry(displayIndex, display))
                    return false;
                result = std::move(display);
            }
            if (binding_.fname.numberInline && binding_.fname.number >= 0)
            {
                TargetAddress numberAddress = 0;
                std::uint32_t number = 0;
                if (!Add(address, static_cast<std::uint32_t>(binding_.fname.number), numberAddress) ||
                    !ReadExact(numberAddress, &number, sizeof(number)).Ok())
                    return false;
                if (number > 0)
                    result += "_" + std::to_string(number - 1);
            }
            return true;
        }

        [[nodiscard]] ValueReadResult ReadSignedValue(TargetAddress address, std::int32_t size)
        {
            std::uint64_t raw = 0;
            if (size != 1 && size != 2 && size != 4 && size != 8)
                return {ReadStatus::Unsupported, {}};
            if (!ReadExact(address, &raw, static_cast<std::size_t>(size)).Ok())
                return {ReadStatus::ReadFailure, {}};
            std::int64_t value = 0;
            if (size == 1)
            {
                std::int8_t typed = 0;
                std::memcpy(&typed, &raw, 1);
                value = typed;
            }
            else if (size == 2)
            {
                std::int16_t typed = 0;
                std::memcpy(&typed, &raw, 2);
                value = typed;
            }
            else if (size == 4)
            {
                std::int32_t typed = 0;
                std::memcpy(&typed, &raw, 4);
                value = typed;
            }
            else
                std::memcpy(&value, &raw, 8);
            return {ReadStatus::Ok, value};
        }

        [[nodiscard]] ValueReadResult ReadUnsigned(TargetAddress address, std::int32_t size)
        {
            std::uint64_t value = 0;
            if (size != 1 && size != 2 && size != 4 && size != 8)
                return {ReadStatus::Unsupported, {}};
            if (!ReadExact(address, &value, static_cast<std::size_t>(size)).Ok())
                return {ReadStatus::ReadFailure, {}};
            return {ReadStatus::Ok, value};
        }

        [[nodiscard]] ValueReadResult ReadFloat(TargetAddress address, std::int32_t size)
        {
            if (size == 4)
            {
                float value = 0;
                if (!ReadExact(address, &value, sizeof(value)).Ok())
                    return {ReadStatus::ReadFailure, {}};
                return {ReadStatus::Ok, static_cast<double>(value)};
            }
            if (size == 8)
            {
                double value = 0;
                if (!ReadExact(address, &value, sizeof(value)).Ok())
                    return {ReadStatus::ReadFailure, {}};
                return {ReadStatus::Ok, value};
            }
            return {ReadStatus::Unsupported, {}};
        }

        [[nodiscard]] ValueReadResult ReadBoolean(TargetAddress address, std::int32_t size,
                                                  const BoolLayoutDescriptor &layout)
        {
            if (!layout.valid || layout.fieldSize != size || layout.byteOffset >= size ||
                size <= 0 || size > 8 || layout.fieldMask == 0)
                return {ReadStatus::Unsupported, {}};
            std::uint64_t bits = 0;
            if (!ReadExact(address, &bits, static_cast<std::size_t>(size)).Ok())
                return {ReadStatus::ReadFailure, {}};
            const std::uint8_t byte = static_cast<std::uint8_t>(bits >> (layout.byteOffset * 8));
            return {ReadStatus::Ok, (byte & layout.fieldMask) != 0};
        }

        [[nodiscard]] ValueReadResult ReadEnum(TargetAddress address, std::int32_t size,
                                               bool isUnsigned, const char *name)
        {
            const EnumDescriptor *descriptor = FindEnum(name ? name : "");
            if (!descriptor)
                return isUnsigned ? ReadUnsigned(address, size) : ReadSignedValue(address, size);
            const auto raw = isUnsigned ? ReadUnsigned(address, size) : ReadSignedValue(address, size);
            if (!raw.Ok())
                return raw;
            const std::uint64_t unsignedValue = isUnsigned ? std::get<std::uint64_t>(raw.value) : 0;
            const std::int64_t value = isUnsigned
                                           ? 0
                                           : std::get<std::int64_t>(raw.value);
            const char *valueName = "";
            for (std::size_t index = 0; index < descriptor->valueCount; ++index)
            {
                const bool matches = isUnsigned
                                         ? static_cast<std::uint64_t>(descriptor->values[index].value) == unsignedValue
                                         : descriptor->values[index].value == value;
                if (matches)
                {
                    valueName = descriptor->values[index].name;
                    break;
                }
            }
            return {ReadStatus::Ok, EnumValue{descriptor, value, unsignedValue, isUnsigned, valueName}};
        }

        [[nodiscard]] ValueReadResult ReadEnumStorage(TargetAddress address, const ValueDescriptor &type)
        {
            if (!type.inner)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "enum-underlying-type-unavailable");
            const std::int32_t underlyingSize = ScalarSize(type.inner->kind);
            if (underlyingSize <= 0 || underlyingSize != type.elementSize)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize),
                                  "enum-storage-size-mismatch");
            const char *enumName = Empty(type.secondaryType) ? type.referencedType : type.secondaryType;
            if (type.inner->kind == PropertyKind::Byte || type.inner->kind == PropertyKind::UInt16 ||
                type.inner->kind == PropertyKind::UInt32 || type.inner->kind == PropertyKind::UInt64)
                return ReadEnum(address, type.elementSize, true, enumName);
            if (type.inner->kind == PropertyKind::Int8 || type.inner->kind == PropertyKind::Int16 ||
                type.inner->kind == PropertyKind::Int32 || type.inner->kind == PropertyKind::Int64)
                return ReadEnum(address, type.elementSize, false, enumName);
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "enum-storage-unsupported");
        }

        [[nodiscard]] ValueReadResult ReadString(TargetAddress address, const ValueDescriptor &type)
        {
            if (type.elementSize != binding_.pointerWidth + 8)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "string-header-size-mismatch");
            TargetAddress dataAddress = 0, countAddress = 0, capacityAddress = 0;
            TargetAddress data = 0;
            std::int32_t count = 0, capacity = 0;
            if (!Add(address, 0, dataAddress) ||
                !Add(address, binding_.pointerWidth, countAddress) ||
                !Add(address, binding_.pointerWidth + 4, capacityAddress) ||
                ReadPointer(dataAddress, data) != ReadStatus::Ok ||
                !ReadExact(countAddress, &count, sizeof(count)).Ok() ||
                !ReadExact(capacityAddress, &capacity, sizeof(capacity)).Ok() ||
                count < 0 || capacity < count ||
                static_cast<std::size_t>(capacity) > options_.maxStringCharacters ||
                static_cast<std::size_t>(count) > options_.maxStringCharacters)
                return {ReadStatus::InvalidHeader, {}};
            if (count == 0)
                return {ReadStatus::Ok, std::string{}};
            if (!data)
                return {ReadStatus::InvalidHeader, {}};
            const std::string_view reflected(type.reflectedClass ? type.reflectedClass : "");
            const bool utf8 = reflected.find("Utf8StrProperty") != std::string_view::npos;
            const bool ansi = reflected.find("AnsiStrProperty") != std::string_view::npos;
            const std::size_t charWidth = utf8 || ansi ? 1 : 2;
            std::size_t bytes = 0;
            if (static_cast<std::size_t>(count) >
                std::numeric_limits<std::size_t>::max() / charWidth)
                return {ReadStatus::LimitExceeded, {}};
            bytes = static_cast<std::size_t>(count) * charWidth;
            if (bytes > options_.maxOpaqueBytes)
                return {ReadStatus::LimitExceeded, {}};
            if (utf8 || ansi)
            {
                std::string result(static_cast<std::size_t>(count), '\0');
                if (!ReadExact(data, result.data(), result.size()).Ok())
                    return {ReadStatus::ReadFailure, {}};
                const auto terminator = result.find('\0');
                if (terminator != std::string::npos)
                    result.resize(terminator);
                return {ReadStatus::Ok, std::move(result)};
            }
            std::vector<char16_t> text(static_cast<std::size_t>(count));
            if (!ReadExact(data, text.data(), bytes).Ok())
                return {ReadStatus::ReadFailure, {}};
            std::string result;
            for (std::size_t index = 0; index < text.size(); ++index)
            {
                std::uint32_t codePoint = text[index];
                if (codePoint == 0)
                    break;
                if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
                {
                    if (index + 1 >= text.size() || text[index + 1] < 0xDC00 || text[index + 1] > 0xDFFF)
                        return {ReadStatus::InvalidHeader, {}};
                    codePoint = 0x10000 + ((codePoint - 0xD800) << 10) +
                                (static_cast<std::uint32_t>(text[++index]) - 0xDC00);
                }
                else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF)
                    return {ReadStatus::InvalidHeader, {}};
                AppendUtf8(result, codePoint);
            }
            return {ReadStatus::Ok, std::move(result)};
        }

        [[nodiscard]] ValueReadResult ReadObjectReference(TargetAddress address, const char *typeName)
        {
            TargetAddress objectAddress = 0;
            const ReadStatus status = ReadPointer(address, objectAddress);
            if (status != ReadStatus::Ok)
                return {status, {}};
            ObjectReference reference{objectAddress, typeName ? typeName : "", std::nullopt};
            if (objectAddress)
            {
                ObjectHandle handle;
                if (ReadObjectHandle(objectAddress, handle))
                {
                    const auto info = ReadObjectInfo(handle);
                    const TypeDescriptor *type = info ? FindType(info->classFullName) : nullptr;
                    if (type && (Empty(typeName) || IsTypeA(type, typeName)))
                        reference.object = RemoteObjectView{this, handle, type};
                }
            }
            return {ReadStatus::Ok, std::move(reference)};
        }

        [[nodiscard]] bool ReadObjectHandle(TargetAddress address, ObjectHandle &handle)
        {
            std::int32_t index = -1;
            TargetAddress indexAddress = 0;
            if (!Add(address, static_cast<std::uint32_t>(binding_.uobject.internalIndexOffset), indexAddress) ||
                !ReadExact(indexAddress, &index, sizeof(index)).Ok() || index < 0 || index >= objectCount_)
                return false;
            RemoteObjectView object;
            if (ReadObject(index, object) != ReadStatus::Ok || object.handle.address != address)
                return false;
            handle = object.handle;
            return true;
        }

        [[nodiscard]] ValueReadResult ReadWeakObject(TargetAddress address, const ValueDescriptor &type)
        {
            if (type.storage.size != type.elementSize)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "weak-object-size-unverified");
            const std::int32_t indexOffset = StorageOffset(type.storage, "ObjectIndex");
            const std::int32_t serialOffset = StorageOffset(type.storage, "ObjectSerialNumber");
            if (!StorageMemberFits(type.storage, "ObjectIndex", 4) ||
                !StorageMemberFits(type.storage, "ObjectSerialNumber", 4) ||
                indexOffset < 0 || serialOffset < 0)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "weak-object-layout-unselected");
            TargetAddress indexAddress = 0, serialAddress = 0;
            std::int32_t index = -1, serial = 0;
            if (!Add(address, static_cast<std::uint32_t>(indexOffset), indexAddress) ||
                !Add(address, static_cast<std::uint32_t>(serialOffset), serialAddress) ||
                !ReadExact(indexAddress, &index, sizeof(index)).Ok() ||
                !ReadExact(serialAddress, &serial, sizeof(serial)).Ok())
                return {ReadStatus::ReadFailure, {}};
            WeakObjectReference result{index, serial, std::nullopt};
            if ((index == 0 || index == -1) && serial == 0)
                return {ReadStatus::Ok, std::move(result)};
            if (index < 0 || serial <= 0)
                return {ReadStatus::InvalidReference, {}};
            RemoteObjectView object;
            if (ReadObject(index, object) != ReadStatus::Ok)
                return {ReadStatus::InvalidReference, {}};
            if (!object.handle.serialKnown)
                return {ReadStatus::Unsupported, {}};
            if (object.handle.serial != serial)
                return {ReadStatus::StaleObject, {}};
            const auto info = ReadObjectInfo(object.handle);
            const TypeDescriptor *objectType = info ? FindType(info->classFullName) : nullptr;
            if (!objectType ||
                (!Empty(type.referencedType) && !IsTypeA(objectType, type.referencedType)))
                return {ReadStatus::InvalidReference, {}};
            object.type = objectType;
            result.object = object;
            return {ReadStatus::Ok, std::move(result)};
        }

        [[nodiscard]] ValueReadResult ReadSoftObject(TargetAddress address, const ValueDescriptor &type)
        {
            if (type.storage.size != type.elementSize)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "soft-object-size-unverified");
            const auto layoutId = std::string_view(type.storage.id ? type.storage.id : "");
            const std::int32_t indexOffset = StorageOffset(type.storage, "ObjectIndex");
            const std::int32_t serialOffset = StorageOffset(type.storage, "ObjectSerialNumber");
            const std::int32_t assetOffset = StorageOffset(type.storage, "AssetPath");
            const std::int32_t subPathOffset = StorageOffset(type.storage, "SubPath");
            const std::int32_t assetSize =
                layoutId.find("top-level") != std::string_view::npos
                    ? 2 * binding_.fname.size
                    : binding_.fname.size;
            if (assetOffset < 0 || subPathOffset < 0 ||
                !StorageMemberFits(type.storage, "AssetPath", assetSize) ||
                !StorageMemberFits(type.storage, "SubPath", binding_.pointerWidth + 8) ||
                (indexOffset >= 0 && !StorageMemberFits(type.storage, "ObjectIndex", 4)) ||
                (serialOffset >= 0 && !StorageMemberFits(type.storage, "ObjectSerialNumber", 4)))
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "soft-object-layout-unselected");
            SoftObjectReference result;
            if (indexOffset >= 0 && serialOffset >= 0)
            {
                TargetAddress indexAddress = 0, serialAddress = 0;
                if (!Add(address, static_cast<std::uint32_t>(indexOffset), indexAddress) ||
                    !Add(address, static_cast<std::uint32_t>(serialOffset), serialAddress) ||
                    !ReadExact(indexAddress, &result.index, sizeof(result.index)).Ok() ||
                    !ReadExact(serialAddress, &result.serial, sizeof(result.serial)).Ok())
                    return {ReadStatus::ReadFailure, {}};
            }
            const std::int32_t tagOffset = StorageOffset(type.storage, "TagAtLastTest");
            if (tagOffset >= 0)
            {
                TargetAddress tagAddress = 0;
                if (!StorageMemberFits(type.storage, "TagAtLastTest", 4) ||
                    !Add(address, static_cast<std::uint32_t>(tagOffset), tagAddress) ||
                    !ReadExact(tagAddress, &result.tagAtLastTest, sizeof(result.tagAtLastTest)).Ok())
                    return {ReadStatus::ReadFailure, {}};
            }
            const std::int32_t remoteOffset = StorageOffset(type.storage, "RemoteObjectId");
            if (remoteOffset >= 0)
            {
                TargetAddress remoteAddress = 0;
                if (!StorageMemberFits(type.storage, "RemoteObjectId", 8) ||
                    !Add(address, static_cast<std::uint32_t>(remoteOffset), remoteAddress) ||
                    !ReadExact(remoteAddress, &result.remoteId, sizeof(result.remoteId)).Ok())
                    return {ReadStatus::ReadFailure, {}};
            }
            TargetAddress assetAddress = 0;
            if (!Add(address, static_cast<std::uint32_t>(assetOffset), assetAddress))
                return {ReadStatus::AddressOverflow, {}};
            std::string firstName;
            if (!ReadFName(assetAddress, firstName))
                return {ReadStatus::ReadFailure, {}};
            if (layoutId.find("top-level") != std::string_view::npos)
            {
                TargetAddress secondAddress = 0;
                if (!Add(assetAddress, binding_.fname.size, secondAddress) ||
                    !ReadFName(secondAddress, result.assetName))
                    return {ReadStatus::ReadFailure, {}};
                result.packageName = std::move(firstName);
            }
            else
                result.assetName = std::move(firstName);
            TargetAddress subPathAddress = 0;
            if (!Add(address, static_cast<std::uint32_t>(subPathOffset), subPathAddress))
                return {ReadStatus::AddressOverflow, {}};
            ValueDescriptor stringType;
            stringType.kind = PropertyKind::String;
            stringType.elementSize = binding_.pointerWidth + 8;
            stringType.arrayDim = 1;
            stringType.detailsResolved = true;
            stringType.reflectedClass = "FStrProperty";
            const auto subPath = ReadString(subPathAddress, stringType);
            if (!subPath.Ok())
                return subPath;
            result.subPath = std::get<std::string>(subPath.value);
            return {ReadStatus::Ok, std::move(result)};
        }

        [[nodiscard]] ValueReadResult ReadLazyObject(TargetAddress address, const ValueDescriptor &type)
        {
            if (type.storage.size != type.elementSize)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "lazy-object-size-unverified");
            const std::int32_t indexOffset = StorageOffset(type.storage, "ObjectIndex");
            const std::int32_t serialOffset = StorageOffset(type.storage, "ObjectSerialNumber");
            const std::int32_t idOffset = StorageOffset(type.storage, "ObjectId");
            if (!StorageMemberFits(type.storage, "ObjectIndex", 4) ||
                !StorageMemberFits(type.storage, "ObjectSerialNumber", 4) ||
                !StorageMemberFits(type.storage, "ObjectId", 16) ||
                indexOffset < 0 || serialOffset < 0 || idOffset < 0)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "lazy-object-layout-unselected");
            LazyObjectReference result;
            TargetAddress indexAddress = 0, serialAddress = 0, idAddress = 0;
            if (!Add(address, static_cast<std::uint32_t>(indexOffset), indexAddress) ||
                !Add(address, static_cast<std::uint32_t>(serialOffset), serialAddress) ||
                !Add(address, static_cast<std::uint32_t>(idOffset), idAddress) ||
                !ReadExact(indexAddress, &result.index, sizeof(result.index)).Ok() ||
                !ReadExact(serialAddress, &result.serial, sizeof(result.serial)).Ok() ||
                !ReadExact(idAddress, result.objectId.data(), result.objectId.size()).Ok())
                return {ReadStatus::ReadFailure, {}};
            const std::int32_t tagOffset = StorageOffset(type.storage, "TagAtLastTest");
            if (tagOffset >= 0)
            {
                TargetAddress tagAddress = 0;
                if (!StorageMemberFits(type.storage, "TagAtLastTest", 4) ||
                    !Add(address, static_cast<std::uint32_t>(tagOffset), tagAddress) ||
                    !ReadExact(tagAddress, &result.tagAtLastTest, sizeof(result.tagAtLastTest)).Ok())
                    return {ReadStatus::ReadFailure, {}};
            }
            const std::int32_t remoteOffset = StorageOffset(type.storage, "RemoteObjectId");
            if (remoteOffset >= 0)
            {
                TargetAddress remoteAddress = 0;
                if (!StorageMemberFits(type.storage, "RemoteObjectId", 8) ||
                    !Add(address, static_cast<std::uint32_t>(remoteOffset), remoteAddress) ||
                    !ReadExact(remoteAddress, &result.remoteId, sizeof(result.remoteId)).Ok())
                    return {ReadStatus::ReadFailure, {}};
            }
            return {ReadStatus::Ok, std::move(result)};
        }

        [[nodiscard]] ValueReadResult ReadInterface(TargetAddress address, const ValueDescriptor &type)
        {
            if (type.elementSize != static_cast<std::int32_t>(2 * binding_.pointerWidth))
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "interface-size-mismatch");
            TargetAddress objectAddress = 0, interfaceAddress = 0;
            if (ReadPointer(address, objectAddress) != ReadStatus::Ok ||
                !Add(address, binding_.pointerWidth, interfaceAddress))
                return {ReadStatus::ReadFailure, {}};
            TargetAddress interfacePointer = 0;
            if (ReadPointer(interfaceAddress, interfacePointer) != ReadStatus::Ok)
                return {ReadStatus::ReadFailure, {}};
            InterfaceReference result{objectAddress, interfacePointer, std::nullopt};
            if (objectAddress)
            {
                ObjectHandle handle;
                if (ReadObjectHandle(objectAddress, handle))
                {
                    const auto info = ReadObjectInfo(handle);
                    result.resolvedObject = RemoteObjectView{this, handle,
                                                             info ? FindType(info->classFullName) : nullptr};
                }
            }
            return {ReadStatus::Ok, std::move(result)};
        }

        [[nodiscard]] ValueReadResult ReadDelegate(TargetAddress address, const ValueDescriptor &type)
        {
            if (type.storage.size != type.elementSize)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "delegate-size-unverified");
            if (type.delegateStorage != DelegateStorageKind::Unicast)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "delegate-layout-unselected");
            const std::int32_t indexOffset = StorageOffset(type.storage, "ObjectIndex");
            const std::int32_t serialOffset = StorageOffset(type.storage, "ObjectSerialNumber");
            const std::int32_t nameOffset = StorageOffset(type.storage, "FunctionName");
            if (!StorageMemberFits(type.storage, "ObjectIndex", 4) ||
                !StorageMemberFits(type.storage, "ObjectSerialNumber", 4) ||
                !StorageMemberFits(type.storage, "FunctionName", binding_.fname.size) ||
                indexOffset < 0 || serialOffset < 0 || nameOffset < 0)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "delegate-layout-unselected");
            TargetAddress indexAddress = 0, serialAddress = 0, nameAddress = 0;
            DelegateReference result;
            if (!Add(address, static_cast<std::uint32_t>(indexOffset), indexAddress) ||
                !Add(address, static_cast<std::uint32_t>(serialOffset), serialAddress) ||
                !Add(address, static_cast<std::uint32_t>(nameOffset), nameAddress) ||
                !ReadExact(indexAddress, &result.index, sizeof(result.index)).Ok() ||
                !ReadExact(serialAddress, &result.serial, sizeof(result.serial)).Ok() ||
                !ReadFName(nameAddress, result.functionName))
                return {ReadStatus::ReadFailure, {}};
            if ((result.index == 0 || result.index == -1) && result.serial == 0)
                return {ReadStatus::Ok, std::move(result)};
            if (result.index < 0 || result.serial <= 0)
                return {ReadStatus::InvalidReference, {}};
            RemoteObjectView target;
            if (ReadObject(result.index, target) != ReadStatus::Ok)
                return {ReadStatus::InvalidReference, {}};
            if (!target.handle.serialKnown)
                return {ReadStatus::Unsupported, {}};
            if (target.handle.serial != result.serial)
                return {ReadStatus::StaleObject, {}};
            result.target = target;
            return {ReadStatus::Ok, std::move(result)};
        }

        [[nodiscard]] ValueReadResult ReadText(TargetAddress address, const ValueDescriptor &type)
        {
            if (type.storage.size != type.elementSize)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "text-size-unverified");
            const std::int32_t dataOffset = StorageOffset(type.storage, "TextData");
            const std::int32_t flagsOffset = StorageOffset(type.storage, "Flags");
            if (!StorageMemberFits(type.storage, "TextData", binding_.pointerWidth) ||
                !StorageMemberFits(type.storage, "Flags", 4) ||
                dataOffset < 0 || flagsOffset < 0)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "text-layout-unselected");
            TargetAddress dataAddress = 0, flagsAddress = 0;
            TextReference result;
            if (!Add(address, static_cast<std::uint32_t>(dataOffset), dataAddress) ||
                !Add(address, static_cast<std::uint32_t>(flagsOffset), flagsAddress) ||
                ReadPointer(dataAddress, result.data) != ReadStatus::Ok ||
                !ReadExact(flagsAddress, &result.flags, sizeof(std::uint32_t)).Ok())
                return {ReadStatus::ReadFailure, {}};
            return {ReadStatus::Ok, result};
        }

        [[nodiscard]] ValueReadResult OpenArray(TargetAddress address, const ValueDescriptor &type)
        {
            if (!type.inner || type.inner->elementSize <= 0 || type.inner->arrayDim <= 0)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "array-element-layout-unresolved");
            const std::int64_t stride64 = static_cast<std::int64_t>(type.inner->elementSize) * type.inner->arrayDim;
            if (stride64 <= 0 || stride64 > INT32_MAX)
                return {ReadStatus::InvalidHeader, {}};
            const bool memoryImage = type.container.allocator == ContainerAllocatorKind::MemoryImage;
            if (type.container.allocator == ContainerAllocatorKind::Unknown ||
                Empty(type.container.layoutId))
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "array-storage-layout-unselected");
            if (memoryImage && binding_.pointerWidth != 8)
                return {ReadStatus::Unsupported, {}};
            const std::string expectedLayout =
                std::string(memoryImage ? "memory-image-array-p" : "heap-array-p") +
                std::to_string(binding_.pointerWidth);
            const std::int32_t expectedSize = memoryImage ? 16 : binding_.pointerWidth + 8;
            if (std::string_view(type.container.layoutId) != expectedLayout ||
                type.elementSize != expectedSize ||
                Empty(type.container.headerStatus) ||
                std::string_view(type.container.headerStatus).find("source-model-") != 0)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "array-layout-id-mismatch");
            const std::int32_t dataOffset = 0;
            const std::int32_t countOffset = memoryImage ? 8 : binding_.pointerWidth;
            const std::int32_t capacityOffset = countOffset + 4;
            TargetAddress dataField = 0, countAddress = 0, capacityAddress = 0;
            if (!Add(address, dataOffset, dataField) || !Add(address, countOffset, countAddress) ||
                !Add(address, capacityOffset, capacityAddress))
                return {ReadStatus::AddressOverflow, {}};
            std::int32_t count = 0, capacity = 0;
            if (!ReadExact(countAddress, &count, sizeof(count)).Ok() ||
                !ReadExact(capacityAddress, &capacity, sizeof(capacity)).Ok() ||
                count < 0 || capacity < count ||
                static_cast<std::size_t>(capacity) > options_.maxContainerSlots)
                return {ReadStatus::InvalidHeader, {}};
            TargetAddress data = 0;
            bool frozen = false;
            if (memoryImage)
            {
                std::uint64_t raw = 0;
                if (!ReadExact(dataField, &raw, sizeof(raw)).Ok())
                    return {ReadStatus::ReadFailure, {}};
                frozen = (raw & 1) != 0;
                if (frozen)
                {
                    if (count > 0)
                        return {ReadStatus::Unsupported, {}};
                }
                else if (raw > std::numeric_limits<TargetAddress>::max())
                    return {ReadStatus::InvalidReference, {}};
                else
                    data = static_cast<TargetAddress>(raw);
            }
            else if (ReadPointer(dataField, data) != ReadStatus::Ok)
                return {ReadStatus::ReadFailure, {}};
            if (count > 0 && !data)
                return {ReadStatus::InvalidHeader, {}};
            return {ReadStatus::Ok, RemoteArrayView{this, address, data, type.inner, count,
                                                    capacity, static_cast<std::int32_t>(stride64),
                                                    memoryImage, frozen}};
        }

        [[nodiscard]] ValueReadResult OpenSparseContainer(TargetAddress address, const ValueDescriptor &type)
        {
            const bool isMap = type.kind == PropertyKind::Map;
            const ValueDescriptor *key = isMap ? type.key : type.inner;
            if (!key || (isMap && !type.value) || type.container.allocator == ContainerAllocatorKind::Unknown ||
                Empty(type.container.layoutId) || Empty(type.container.headerStatus) ||
                std::string_view(type.container.headerStatus).find("source-model-") != 0 ||
                (std::string_view(type.container.layoutStatus) != "conditional-formula-match" &&
                 std::string_view(type.container.layoutStatus) != "independent-formula-match"))
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "sparse-layout-unvalidated");
            const bool memoryImage = type.container.allocator == ContainerAllocatorKind::MemoryImage;
            if (memoryImage && binding_.pointerWidth != 8)
                return {ReadStatus::Unsupported, {}};
            const std::int32_t pointer = binding_.pointerWidth;
            const std::string expectedLayout =
                std::string(memoryImage ? "memory-image-sparse-set-p" : "heap-sparse-set-p") +
                std::to_string(binding_.pointerWidth);
            if (std::string_view(type.container.layoutId) != expectedLayout)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "sparse-layout-id-mismatch");
            const auto alignPointer = [pointer](std::int32_t size)
            { return (size + pointer - 1) / pointer * pointer; };
            const std::int32_t dataOffset = 0;
            const std::int32_t dataNumOffset = memoryImage ? 8 : pointer;
            const std::int32_t dataMaxOffset = dataNumOffset + 4;
            const std::int32_t bitsInlineOffset = pointer + 8;
            const std::int32_t bitsPointerOffset = memoryImage ? 16 : bitsInlineOffset + 16;
            const std::int32_t bitsNumOffset = memoryImage ? 24 : bitsPointerOffset + pointer;
            const std::int32_t bitsMaxOffset = bitsNumOffset + 4;
            const std::int32_t firstFreeOffset = memoryImage ? 32 : bitsMaxOffset + 4;
            const std::int32_t freeCountOffset = firstFreeOffset + 4;
            const std::int32_t hashInlineOffset = alignPointer(freeCountOffset + 4);
            const std::int32_t hashPointerOffset = memoryImage ? 40 : hashInlineOffset + alignPointer(4);
            const std::int32_t hashSizeOffset = hashPointerOffset + (memoryImage ? pointer : pointer);
            TargetAddress countAddress = 0, capacityAddress = 0, firstFreeAddress = 0, freeCountAddress = 0;
            TargetAddress bitsNumAddress = 0, bitsMaxAddress = 0, hashSizeAddress = 0;
            if (!Add(address, dataNumOffset, countAddress) || !Add(address, dataMaxOffset, capacityAddress) ||
                !Add(address, firstFreeOffset, firstFreeAddress) || !Add(address, freeCountOffset, freeCountAddress) ||
                !Add(address, bitsNumOffset, bitsNumAddress) || !Add(address, bitsMaxOffset, bitsMaxAddress) ||
                !Add(address, hashSizeOffset, hashSizeAddress))
                return {ReadStatus::AddressOverflow, {}};
            std::int32_t slots = 0, capacity = 0, firstFree = -1, freeCount = 0;
            std::int32_t bitsNum = 0, bitsMax = 0, hashSize = 0;
            if (!ReadExact(countAddress, &slots, sizeof(slots)).Ok() ||
                !ReadExact(capacityAddress, &capacity, sizeof(capacity)).Ok() ||
                !ReadExact(firstFreeAddress, &firstFree, sizeof(firstFree)).Ok() ||
                !ReadExact(freeCountAddress, &freeCount, sizeof(freeCount)).Ok() ||
                !ReadExact(bitsNumAddress, &bitsNum, sizeof(bitsNum)).Ok() ||
                !ReadExact(bitsMaxAddress, &bitsMax, sizeof(bitsMax)).Ok() ||
                !ReadExact(hashSizeAddress, &hashSize, sizeof(hashSize)).Ok() ||
                slots < 0 || capacity < slots || freeCount < 0 || freeCount > slots ||
                bitsNum != slots || bitsMax < slots ||
                static_cast<std::size_t>(slots) > options_.maxSparseSlots ||
                (freeCount > 0 && (firstFree < 0 || firstFree >= slots)) ||
                hashSize < 0 || hashSize > static_cast<std::int32_t>(2 * options_.maxSparseSlots) ||
                (slots - freeCount > 0 && hashSize == 0) ||
                (hashSize > 0 && (hashSize & (hashSize - 1)) != 0))
                return {ReadStatus::InvalidHeader, {}};
            TargetAddress dataField = 0, bitsField = 0, hashField = 0;
            if (!Add(address, dataOffset, dataField) ||
                !Add(address, bitsPointerOffset, bitsField) ||
                !Add(address, hashPointerOffset, hashField))
                return {ReadStatus::AddressOverflow, {}};
            TargetAddress data = 0, bits = 0, hash = 0;
            bool frozen = false;
            if (memoryImage)
            {
                std::uint64_t rawData = 0, rawBits = 0, rawHash = 0;
                if (!ReadExact(dataField, &rawData, 8).Ok() ||
                    !ReadExact(bitsField, &rawBits, 8).Ok() ||
                    !ReadExact(hashField, &rawHash, 8).Ok())
                    return {ReadStatus::ReadFailure, {}};
                frozen = ((rawData | rawBits | rawHash) & 1) != 0;
                if (frozen && slots > 0)
                    return {ReadStatus::Unsupported, {}};
                if (!frozen)
                {
                    if (rawData > std::numeric_limits<TargetAddress>::max() ||
                        rawBits > std::numeric_limits<TargetAddress>::max() ||
                        rawHash > std::numeric_limits<TargetAddress>::max())
                        return {ReadStatus::InvalidReference, {}};
                    data = static_cast<TargetAddress>(rawData);
                    bits = static_cast<TargetAddress>(rawBits);
                    hash = static_cast<TargetAddress>(rawHash);
                }
            }
            else
            {
                if (ReadPointer(dataField, data) != ReadStatus::Ok ||
                    ReadPointer(bitsField, bits) != ReadStatus::Ok ||
                    ReadPointer(hashField, hash) != ReadStatus::Ok)
                    return {ReadStatus::ReadFailure, {}};
                if (!bits)
                {
                    if (bitsMax > 128)
                        return {ReadStatus::InvalidHeader, {}};
                    if (!Add(address, static_cast<std::uint32_t>(bitsInlineOffset), bits))
                        return {ReadStatus::AddressOverflow, {}};
                }
                if (!hash)
                {
                    if (hashSize > 1)
                        return {ReadStatus::InvalidHeader, {}};
                    if (!Add(address, static_cast<std::uint32_t>(hashInlineOffset), hash))
                        return {ReadStatus::AddressOverflow, {}};
                }
            }
            if ((slots > 0 && (!data || !bits)) ||
                (hashSize > 0 && !hash && !(memoryImage && frozen && slots == 0)))
                return {ReadStatus::InvalidHeader, {}};
            const std::int64_t stride64 = type.container.elementStride;
            const std::int64_t valueOffset = type.container.valueOffset;
            const auto keyExtent = ValueExtent(key);
            const auto valueExtent = isMap ? ValueExtent(type.value) : std::optional<std::int32_t>{0};
            const auto headerSize = SparseHeaderSize(memoryImage);
            if (stride64 <= 0 || stride64 > INT32_MAX || valueOffset < 0 ||
                !keyExtent || !valueExtent || !headerSize ||
                type.container.elementAlignment <= 0 ||
                (type.container.elementAlignment & (type.container.elementAlignment - 1)) != 0 ||
                type.container.setElementSize <= 0 ||
                type.container.setElementSize > stride64 ||
                (memoryImage ? type.elementSize < *headerSize : type.elementSize != *headerSize) ||
                (!isMap && *keyExtent > type.container.setElementSize) ||
                (isMap && (valueOffset < *keyExtent ||
                           valueOffset > stride64 - *valueExtent)))
                return {ReadStatus::Unsupported, {}};
            RemoteSparseContainerView view;
            view.runtime = this;
            view.address = address;
            view.data = data;
            view.key = key;
            view.value = type.value;
            view.slots = slots;
            view.count = slots - freeCount;
            view.stride = static_cast<std::int32_t>(stride64);
            view.valueOffset = static_cast<std::int32_t>(valueOffset);
            view.isMap = isMap;
            const std::size_t words = (static_cast<std::size_t>(slots) + 31) / 32;
            view.allocationBits.resize(words);
            if (words > 0 && !ReadExact(bits, view.allocationBits.data(), words * sizeof(std::uint32_t)).Ok())
                return {ReadStatus::ReadFailure, {}};
            std::size_t allocated = 0;
            for (const auto word : view.allocationBits)
                allocated += BitCount(word);
            if (allocated != static_cast<std::size_t>(view.count) ||
                (slots % 32 && words &&
                 (view.allocationBits.back() >> (slots % 32)) != 0))
                return {ReadStatus::InvalidHeader, {}};
            if (freeCount > 0 &&
                (view.allocationBits[static_cast<std::size_t>(firstFree) / 32] &
                 (std::uint32_t{1} << (firstFree % 32))) != 0)
                return {ReadStatus::InvalidHeader, {}};
            if (frozen)
                return {ReadStatus::Unsupported, {}};
            return {ReadStatus::Ok, std::move(view)};
        }

        [[nodiscard]] ValueReadResult ReadOpaque(TargetAddress address, std::size_t size,
                                                 const char *reason)
        {
            if (size > options_.maxOpaqueBytes)
                return {ReadStatus::LimitExceeded, {}};
            OpaqueValue value{address, reason ? reason : "opaque", std::vector<std::uint8_t>(size)};
            if (!ReadExact(address, value.bytes.data(), value.bytes.size()).Ok())
                return {ReadStatus::ReadFailure, {}};
            return {ReadStatus::Ok, std::move(value)};
        }

        [[nodiscard]] static std::int32_t StorageOffset(const ValueStorageDescriptor &storage,
                                                        std::string_view name)
        {
            for (std::size_t index = 0; index < storage.memberCount; ++index)
                if (storage.members[index].name == name)
                    return storage.members[index].offset;
            return -1;
        }

        [[nodiscard]] static bool StorageMemberFits(const ValueStorageDescriptor &storage,
                                                    std::string_view name, std::int32_t size)
        {
            const std::int32_t offset = StorageOffset(storage, name);
            return storage.size > 0 && size > 0 && offset >= 0 &&
                   offset <= storage.size - size;
        }

        [[nodiscard]] static std::size_t BitCount(std::uint32_t value)
        {
            std::size_t count = 0;
            while (value)
            {
                value &= value - 1;
                ++count;
            }
            return count;
        }

        MemoryReader memory_;
        TargetAddress moduleBase_ = 0;
        RuntimeBindingDescriptor binding_;
        std::string moduleName_;
        const TypeDescriptor *types_ = nullptr;
        std::size_t typeCount_ = 0;
        const EnumDescriptor *enums_ = nullptr;
        std::size_t enumCount_ = 0;
        RuntimeOptions options_;
        TargetAddress objectRoot_ = 0;
        TargetAddress nameRoot_ = 0;
        TargetAddress objectStorage_ = 0;
        std::int32_t objectCount_ = 0;
        bool initialized_ = false;
        std::unordered_map<std::int32_t, std::string> nameCache_;
    };
} // namespace NextDumper
