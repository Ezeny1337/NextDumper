#pragma once

#include "../Runtime.hpp"

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

namespace NextDumper
{

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadField(const RemoteObjectView &object, std::string_view name)
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

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadField(const RemoteStructView &structure,
                                                                  std::string_view name)
    {
        if (structure.runtime != this || !structure.address || !structure.type)
            return {ReadStatus::InvalidArgument, {}};
        const FieldDescriptor *field = FindField(structure.type, name);
        if (!field)
            return {ReadStatus::NotFound, {}};
        return ReadFieldAt(structure.address, *field);
    }

    template <typename T>
    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadField(const RemoteObjectView &object, std::string_view name,
                                                             T &out)
    {
        const auto result = ReadField(object, name);
        if (!result.Ok())
            return result.status;
        return Convert(result.value, out) ? ReadStatus::Ok : ReadStatus::Unsupported;
    }

    template <typename T>
    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadField(const RemoteStructView &structure, std::string_view name,
                                                             T &out)
    {
        const auto result = ReadField(structure, name);
        if (!result.Ok())
            return result.status;
        return Convert(result.value, out) ? ReadStatus::Ok : ReadStatus::Unsupported;
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadFieldAt(TargetAddress owner, const FieldDescriptor &field)
    {
        if (!initialized_)
            return {ReadStatus::NotInitialized, {}};
        if (!field.validBounds || field.virtualProperty || !field.type || field.offset < 0 || field.elementSize <= 0 ||
            field.arrayDim <= 0)
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

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadValueAt(TargetAddress address, const ValueDescriptor &type,
                                                                    BoolLayoutDescriptor boolean)
    {
        if (!initialized_)
            return {ReadStatus::NotInitialized, {}};
        if (!address || type.elementSize <= 0 || type.arrayDim <= 0)
            return {ReadStatus::InvalidArgument, {}};
        if (!boolean.valid)
            boolean = type.boolean;
        if (type.arrayDim > 1)
            return {ReadStatus::Ok,
                    RemoteStaticArrayView{this, address, &type, type.arrayDim, type.elementSize, type.boolean}};
        if (!type.detailsResolved && type.kind != PropertyKind::Unknown)
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "type-details-unresolved");
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
            return name ? ValueReadResult{ReadStatus::Ok, *name} : ValueReadResult{ReadStatus::ReadFailure, {}};
        }
        case PropertyKind::String:
            return ReadString(address, type);
        case PropertyKind::Object:
        case PropertyKind::Class:
            if (std::string_view(type.reflectedClass ? type.reflectedClass : "").find("PtrProperty") !=
                std::string_view::npos)
                return ReadOpaque(address, static_cast<std::size_t>(type.elementSize),
                                  "object-pointer-storage-unverified");
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

    template <typename T>
    [[nodiscard]] inline bool RemoteRuntime::Convert(const RemoteValue &value, T &out)
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
                if (*number < -std::numeric_limits<T>::max() || *number > std::numeric_limits<T>::max())
                    return false;
            out = static_cast<T>(*number);
            return true;
        }
        else
            return false;
    }

} // namespace NextDumper
