#pragma once

#include "Memory.hpp"
#include "Metadata.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace NextDumper
{
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

    using RemoteValue =
        std::variant<std::monostate, bool, std::int64_t, std::uint64_t, double, std::string, ObjectReference, EnumValue,
                     WeakObjectReference, SoftObjectReference, LazyObjectReference, InterfaceReference,
                     DelegateReference, TextReference, RemoteObjectView, RemoteStructView, RemoteStaticArrayView,
                     RemoteArrayView, RemoteSparseContainerView, RemoteMapEntryView, OpaqueValue>;

    namespace detail
    {
        template <typename T, typename Variant>
        struct IsVariantAlternative;

        template <typename T, typename... Alternatives>
        struct IsVariantAlternative<T, std::variant<Alternatives...>>
            : std::bool_constant<(std::is_same_v<T, Alternatives> || ...)>
        {
        };
    } // namespace detail

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

    namespace ObjectFlag
    {
        inline constexpr std::uint32_t ClassDefaultObject = 0x00000010u;
        inline constexpr std::uint32_t ArchetypeObject = 0x00000020u;
    } // namespace ObjectFlag

    struct ObjectFlagsFilter
    {
        std::uint32_t requireAll = 0;
        std::uint32_t excludeAny = 0;

        [[nodiscard]] bool IsEmpty() const { return requireAll == 0 && excludeAny == 0; }
        [[nodiscard]] bool Matches(std::uint32_t flags) const
        {
            return (flags & requireAll) == requireAll && (flags & excludeAny) == 0;
        }
    };

    struct FieldLookupResult
    {
        ReadStatus status = ReadStatus::NotFound;
        const FieldDescriptor *field = nullptr;

        [[nodiscard]] bool Ok() const { return status == ReadStatus::Ok && field != nullptr; }
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
} // namespace NextDumper
