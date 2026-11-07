#pragma once

#include "Memory.hpp"
#include "Metadata.hpp"
#include "Views.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace NextDumper
{
  class RemoteRuntime
  {
  public:
    RemoteRuntime(MemoryReader memory, TargetAddress moduleBase, const RuntimeBindingDescriptor &binding,
                  const TypeDescriptor *types, std::size_t typeCount, const EnumDescriptor *enums,
                  std::size_t enumCount, RuntimeOptions options = {});

    RemoteRuntime(const RemoteRuntime &) = delete;
    RemoteRuntime &operator=(const RemoteRuntime &) = delete;
    RemoteRuntime(RemoteRuntime &&) = delete;
    RemoteRuntime &operator=(RemoteRuntime &&) = delete;

    [[nodiscard]] ReadStatus Initialize(const char *moduleName, RuntimeRoots roots = {});

    void Reset();

    [[nodiscard]] bool IsInitialized() const;
    [[nodiscard]] std::int32_t ObjectCount() const;
    [[nodiscard]] TargetAddress ObjectRoot() const;
    [[nodiscard]] TargetAddress NameRoot() const;

    [[nodiscard]] ReadStatus RefreshObjectCount();

    [[nodiscard]] ReadStatus ReadObject(std::int32_t index, RemoteObjectView &out);

    [[nodiscard]] std::optional<ObjectInfo> Describe(const RemoteObjectView &object);

    // Object queries scan the raw UObject array; no object flags are excluded by default.
    [[nodiscard]] ObjectQueryResult FindObjects(const ObjectQuery &query, std::size_t maxResults = 128,
                                                ObjectFlagsFilter flags = {});

    [[nodiscard]] ObjectLookupResult FindFirstObject(const ObjectQuery &query, ObjectFlagsFilter flags = {});

    // Finds the first UClass metadata object with this short object name, including reflected subclasses.
    [[nodiscard]] ObjectLookupResult FindFirstUClassObject(std::string_view name, ObjectFlagsFilter flags = {});

    // classFullName must match TypeDescriptor::fullName; derived matches require complete reflected ancestry.
    [[nodiscard]] ObjectLookupResult FindFirstObjectOfType(std::string_view classFullName,
                                                           bool includeDerived = true, ObjectFlagsFilter flags = {});

    // Uses reflected type matching and returns up to maxResults objects.
    [[nodiscard]] ObjectQueryResult FindObjectsOfType(std::string_view classFullName, std::size_t maxResults = 128,
                                                      bool includeDerived = true, ObjectFlagsFilter flags = {});

    // Uses an exact TypeDescriptor::fullName match.
    [[nodiscard]] const TypeDescriptor *FindType(std::string_view fullName) const;

    // Searches available descriptors and reports incomplete type or ancestry metadata.
    [[nodiscard]] FieldLookupResult FindField(const TypeDescriptor *type, std::string_view name) const;

    // Tests reflected inheritance metadata without reading target memory. False may mean
    // either a non-match or that ancestry metadata was unavailable.
    [[nodiscard]] bool IsTypeA(const TypeDescriptor *type, std::string_view baseFullName) const;

    [[nodiscard]] ValueReadResult ReadField(const RemoteObjectView &object, std::string_view name);

    [[nodiscard]] ValueReadResult ReadField(const RemoteStructView &structure, std::string_view name);

    template <typename T>
    [[nodiscard]] ReadStatus ReadField(const RemoteObjectView &object, std::string_view name, T &out);

    template <typename T>
    [[nodiscard]] ReadStatus ReadField(const RemoteStructView &structure, std::string_view name, T &out);

    [[nodiscard]] ValueReadResult ReadFieldAt(TargetAddress owner, const FieldDescriptor &field);

    [[nodiscard]] ValueReadResult ReadValueAt(TargetAddress address, const ValueDescriptor &type,
                                              BoolLayoutDescriptor boolean = {});

    [[nodiscard]] ValueReadResult ReadElement(const RemoteStaticArrayView &array, std::int32_t index);

    [[nodiscard]] ValueReadResult ReadElement(const RemoteArrayView &array, std::int32_t index);

    template <typename T>
    [[nodiscard]] ReadStatus ReadElement(const RemoteStaticArrayView &array, std::int32_t index, T &out);

    template <typename T>
    [[nodiscard]] ReadStatus ReadElement(const RemoteArrayView &array, std::int32_t index, T &out);

    [[nodiscard]] ValueReadResult ReadSparseSlot(const RemoteSparseContainerView &container, std::int32_t slot);

    template <typename T>
    [[nodiscard]] ReadStatus ReadSparseSlot(const RemoteSparseContainerView &container, std::int32_t slot, T &out);

    [[nodiscard]] ValueReadResult ReadMapKey(const RemoteMapEntryView &entry);

    [[nodiscard]] ValueReadResult ReadMapValue(const RemoteMapEntryView &entry);

    template <typename T>
    [[nodiscard]] ReadStatus ReadMapKey(const RemoteMapEntryView &entry, T &out);

    template <typename T>
    [[nodiscard]] ReadStatus ReadMapValue(const RemoteMapEntryView &entry, T &out);

  private:
    template <typename T>
    [[nodiscard]] static bool Convert(RemoteValue &value, T &out);

    template <typename T>
    [[nodiscard]] static ReadStatus ConvertResult(ValueReadResult result, T &out);

    [[nodiscard]] static ReadStatus ConvertObjectReference(const RemoteValue &value, RemoteObjectView &out);

    [[nodiscard]] static bool Empty(const char *value);

    [[nodiscard]] static std::int32_t ScalarSize(PropertyKind kind);

    [[nodiscard]] static std::optional<std::int32_t> ValueExtent(const ValueDescriptor *value);

    [[nodiscard]] std::optional<std::int32_t> SparseHeaderSize(bool memoryImage) const;

    [[nodiscard]] static bool Add(TargetAddress base, std::uint64_t offset, TargetAddress &out);

    [[nodiscard]] static bool AddScaled(TargetAddress base, std::int32_t index, std::int32_t stride,
                                        TargetAddress &out);

    [[nodiscard]] ReadResult ReadExact(TargetAddress address, void *buffer, std::size_t size) const;

    [[nodiscard]] ReadStatus ReadPointer(TargetAddress address, TargetAddress &value) const;

    [[nodiscard]] bool ValidLayouts() const;

    [[nodiscard]] const EnumDescriptor *FindEnum(std::string_view fullName) const;

    [[nodiscard]] bool ValidateHandle(const ObjectHandle &handle);

    [[nodiscard]] ObjectQueryResult FindObjectsImpl(const ObjectQuery &query, std::size_t maxResults,
                                                    std::string_view requiredTypeFullName,
                                                    const TypeDescriptor *requiredType, bool includeDerived,
                                                    ObjectFlagsFilter flags);

    [[nodiscard]] bool IsTypeA(const TypeDescriptor *type, std::string_view baseFullName,
                               bool &chainComplete) const;

    [[nodiscard]] bool ReadObjectSerial(std::int32_t index, std::int32_t &serial);

    [[nodiscard]] bool ReadObjectName(TargetAddress object, std::string &name);

    [[nodiscard]] bool ReadObjectClass(TargetAddress object, TargetAddress &classAddress);

    [[nodiscard]] bool ReadObjectClassName(TargetAddress object, std::string &className);

    [[nodiscard]] bool ReadOuter(TargetAddress object, TargetAddress &outer);

    [[nodiscard]] bool ReadFullName(TargetAddress object, std::string &fullName, std::size_t depth = 0);

    [[nodiscard]] std::optional<ObjectInfo> ReadObjectInfo(const ObjectHandle &handle);

    [[nodiscard]] ReadStatus ReadObjectFlags(TargetAddress object, std::uint32_t &flags) const;

    [[nodiscard]] bool LocateNameEntry(std::int32_t index, TargetAddress &entry, std::size_t &available);

    [[nodiscard]] static bool AddSigned(TargetAddress base, std::int32_t offset, TargetAddress &out);

    [[nodiscard]] bool ReadNameEntry(std::int32_t index, std::string &name, std::size_t depth = 0);

    [[nodiscard]] bool ReadNameText(TargetAddress address, std::size_t chars, bool wide,
                                    std::string &result) const;

    static void AppendUtf8(std::string &output, std::uint32_t codePoint);

    [[nodiscard]] std::optional<std::string> ReadName(std::int32_t index);

    [[nodiscard]] bool ReadFName(TargetAddress address, std::string &result);

    [[nodiscard]] ValueReadResult ReadSignedValue(TargetAddress address, std::int32_t size);

    [[nodiscard]] ValueReadResult ReadUnsigned(TargetAddress address, std::int32_t size);

    [[nodiscard]] ValueReadResult ReadFloat(TargetAddress address, std::int32_t size);

    [[nodiscard]] ValueReadResult ReadBoolean(TargetAddress address, std::int32_t size,
                                              const BoolLayoutDescriptor &layout);

    [[nodiscard]] ValueReadResult ReadEnum(TargetAddress address, std::int32_t size, bool isUnsigned,
                                           const char *name);

    [[nodiscard]] ValueReadResult ReadEnumStorage(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult ReadString(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult ReadObjectReference(TargetAddress address, const char *typeName);

    [[nodiscard]] bool ReadObjectHandle(TargetAddress address, ObjectHandle &handle);

    [[nodiscard]] ValueReadResult ReadWeakObject(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult ReadSoftObject(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult ReadLazyObject(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult ReadInterface(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult ReadDelegate(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult ReadText(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult OpenArray(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult OpenSparseContainer(TargetAddress address, const ValueDescriptor &type);

    [[nodiscard]] ValueReadResult ReadOpaque(TargetAddress address, std::size_t size, const char *reason);

    [[nodiscard]] static std::int32_t StorageOffset(const ValueStorageDescriptor &storage, std::string_view name);

    [[nodiscard]] static bool StorageMemberFits(const ValueStorageDescriptor &storage, std::string_view name,
                                                std::int32_t size);

    [[nodiscard]] static std::size_t BitCount(std::uint32_t value);

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

#include "detail/RuntimeContainers.hpp"
#include "detail/RuntimeCore.hpp"
#include "detail/RuntimeFields.hpp"
#include "detail/RuntimeNames.hpp"
#include "detail/RuntimeObjects.hpp"
#include "detail/RuntimeReferences.hpp"
#include "detail/RuntimeScalars.hpp"
