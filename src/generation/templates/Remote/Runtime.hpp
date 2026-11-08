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
    [[nodiscard]] ReadStatus Describe(const RemoteObjectView &object, ObjectInfo &out);

    // 只解析对象的类描述，不读取对象自身的名称或 Outer 链，失败时清空 type
    [[nodiscard]] ReadStatus ResolveObjectType(RemoteObjectView &object);
    [[nodiscard]] ReadStatus ReadObjectFlags(const RemoteObjectView &object, std::uint32_t &flags);

    // 对象查询扫描原始 UObject 数组；默认不排除任何 object flags
    [[nodiscard]] ObjectQueryResult FindObjects(const ObjectQuery &query, std::size_t maxResults = 128,
                                                ObjectFlagsFilter flags = {});

    [[nodiscard]] ObjectLookupResult FindFirstObject(const ObjectQuery &query, ObjectFlagsFilter flags = {});

    // 查找首个具有该短对象名的 UClass 元数据对象，包括反射出的子类
    [[nodiscard]] ObjectLookupResult FindFirstUClassObject(std::string_view name, ObjectFlagsFilter flags = {});

    // classFullName 必须与 TypeDescriptor::fullName 匹配，派生匹配要求完整的反射祖先链
    [[nodiscard]] ObjectLookupResult FindFirstObjectOfType(std::string_view classFullName,
                                                           bool includeDerived = true, ObjectFlagsFilter flags = {});

    // 使用反射类型匹配，最多返回 maxResults 个对象
    [[nodiscard]] ObjectQueryResult FindObjectsOfType(std::string_view classFullName, std::size_t maxResults = 128,
                                                      bool includeDerived = true, ObjectFlagsFilter flags = {});

    // 使用精确的 TypeDescriptor::fullName 匹配
    [[nodiscard]] const TypeDescriptor *FindType(std::string_view fullName) const;

    // 搜索可用的描述符，并报告不完整的类型或祖先元数据
    [[nodiscard]] FieldLookupResult FindField(const TypeDescriptor *type, std::string_view name) const;

    // 在不读取目标内存的情况下测试反射继承元数据，返回 False 可能意味着不匹配，或祖先元数据不可用
    [[nodiscard]] bool IsTypeA(const TypeDescriptor *type, std::string_view baseFullName) const;
    // Ok 时 matches 表示确定的匹配结果，祖先链不足以判定时返回 Incomplete
    [[nodiscard]] ReadStatus MatchType(const TypeDescriptor *type, std::string_view baseFullName,
                                       bool &matches) const;

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

    [[nodiscard]] ReadStatus ValidateHandle(const ObjectHandle &handle);

    [[nodiscard]] ObjectQueryResult FindObjectsImpl(const ObjectQuery &query, std::size_t maxResults,
                                                    std::string_view requiredTypeFullName,
                                                    const TypeDescriptor *requiredType, bool includeDerived,
                                                    ObjectFlagsFilter flags);

    [[nodiscard]] bool IsTypeA(const TypeDescriptor *type, std::string_view baseFullName,
                               bool &chainComplete) const;

    [[nodiscard]] ReadStatus ReadObjectName(TargetAddress object, std::string &name);

    [[nodiscard]] ReadStatus ReadObjectClass(TargetAddress object, TargetAddress &classAddress);

    [[nodiscard]] ReadStatus ReadObjectType(TargetAddress object, const TypeDescriptor *&type);

    [[nodiscard]] ReadStatus ReadObjectClassName(TargetAddress object, std::string &className);

    [[nodiscard]] ReadStatus ReadOuter(TargetAddress object, TargetAddress &outer);

    [[nodiscard]] ReadStatus ReadFullName(TargetAddress object, std::string &fullName);

    [[nodiscard]] ReadStatus ReadObjectInfo(const ObjectHandle &handle, ObjectInfo &out);

    [[nodiscard]] ReadStatus ReadObjectFlags(TargetAddress object, std::uint32_t &flags) const;

    [[nodiscard]] ReadStatus LocateNameEntry(std::int32_t index, TargetAddress &entry, std::size_t &available);

    [[nodiscard]] static bool AddSigned(TargetAddress base, std::int32_t offset, TargetAddress &out);

    [[nodiscard]] ReadStatus ReadNameEntry(std::int32_t index, std::string &name, std::size_t depth = 0);

    [[nodiscard]] ReadStatus ReadNameText(TargetAddress address, std::size_t chars, bool wide,
                                          std::string &result) const;

    static void AppendUtf8(std::string &output, std::uint32_t codePoint);

    [[nodiscard]] ReadStatus ReadFName(TargetAddress address, std::string &result);

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
