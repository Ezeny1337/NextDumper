#pragma once

#include "../Runtime.hpp"

#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace NextDumper
{

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadSignedValue(TargetAddress address, std::int32_t size)
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

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadUnsigned(TargetAddress address, std::int32_t size)
    {
        std::uint64_t value = 0;
        if (size != 1 && size != 2 && size != 4 && size != 8)
            return {ReadStatus::Unsupported, {}};
        if (!ReadExact(address, &value, static_cast<std::size_t>(size)).Ok())
            return {ReadStatus::ReadFailure, {}};
        return {ReadStatus::Ok, value};
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadFloat(TargetAddress address, std::int32_t size)
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

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadBoolean(TargetAddress address, std::int32_t size,
                                                                    const BoolLayoutDescriptor &layout)
    {
        if (!layout.valid || layout.fieldSize != size || layout.byteOffset >= size || size <= 0 || size > 8 ||
            layout.fieldMask == 0)
            return {ReadStatus::Unsupported, {}};
        std::uint64_t bits = 0;
        if (!ReadExact(address, &bits, static_cast<std::size_t>(size)).Ok())
            return {ReadStatus::ReadFailure, {}};
        const std::uint8_t byte = static_cast<std::uint8_t>(bits >> (layout.byteOffset * 8));
        return {ReadStatus::Ok, (byte & layout.fieldMask) != 0};
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadEnum(TargetAddress address, std::int32_t size,
                                                                 bool isUnsigned, const char *name)
    {
        const EnumDescriptor *descriptor = FindEnum(name ? name : "");
        if (!descriptor)
            return isUnsigned ? ReadUnsigned(address, size) : ReadSignedValue(address, size);
        const auto raw = isUnsigned ? ReadUnsigned(address, size) : ReadSignedValue(address, size);
        if (!raw.Ok())
            return raw;
        const std::uint64_t unsignedValue = isUnsigned ? std::get<std::uint64_t>(raw.value) : 0;
        const std::int64_t value = isUnsigned ? 0 : std::get<std::int64_t>(raw.value);
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

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadEnumStorage(TargetAddress address,
                                                                        const ValueDescriptor &type)
    {
        if (!type.inner)
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "enum-underlying-type-unavailable");
        const std::int32_t underlyingSize = ScalarSize(type.inner->kind);
        if (underlyingSize <= 0 || underlyingSize != type.elementSize)
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "enum-storage-size-mismatch");
        const char *enumName = Empty(type.secondaryType) ? type.referencedType : type.secondaryType;
        if (type.inner->kind == PropertyKind::Byte || type.inner->kind == PropertyKind::UInt16 ||
            type.inner->kind == PropertyKind::UInt32 || type.inner->kind == PropertyKind::UInt64)
            return ReadEnum(address, type.elementSize, true, enumName);
        if (type.inner->kind == PropertyKind::Int8 || type.inner->kind == PropertyKind::Int16 ||
            type.inner->kind == PropertyKind::Int32 || type.inner->kind == PropertyKind::Int64)
            return ReadEnum(address, type.elementSize, false, enumName);
        return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "enum-storage-unsupported");
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadString(TargetAddress address, const ValueDescriptor &type)
    {
        if (type.elementSize != binding_.pointerWidth + 8)
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "string-header-size-mismatch");
        TargetAddress dataAddress = 0, countAddress = 0, capacityAddress = 0;
        TargetAddress data = 0;
        std::int32_t count = 0, capacity = 0;
        if (!Add(address, 0, dataAddress) || !Add(address, binding_.pointerWidth, countAddress) ||
            !Add(address, binding_.pointerWidth + 4, capacityAddress) ||
            ReadPointer(dataAddress, data) != ReadStatus::Ok || !ReadExact(countAddress, &count, sizeof(count)).Ok() ||
            !ReadExact(capacityAddress, &capacity, sizeof(capacity)).Ok() || count < 0 || capacity < count ||
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
        if (static_cast<std::size_t>(count) > std::numeric_limits<std::size_t>::max() / charWidth)
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
                codePoint =
                    0x10000 + ((codePoint - 0xD800) << 10) + (static_cast<std::uint32_t>(text[++index]) - 0xDC00);
            }
            else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF)
                return {ReadStatus::InvalidHeader, {}};
            AppendUtf8(result, codePoint);
        }
        return {ReadStatus::Ok, std::move(result)};
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadOpaque(TargetAddress address, std::size_t size,
                                                                   const char *reason)
    {
        if (size > options_.maxOpaqueBytes)
            return {ReadStatus::LimitExceeded, {}};
        OpaqueValue value{address, reason ? reason : "opaque", std::vector<std::uint8_t>(size)};
        if (!ReadExact(address, value.bytes.data(), value.bytes.size()).Ok())
            return {ReadStatus::ReadFailure, {}};
        return {ReadStatus::Ok, std::move(value)};
    }

    [[nodiscard]] inline std::int32_t RemoteRuntime::StorageOffset(const ValueStorageDescriptor &storage,
                                                                   std::string_view name)
    {
        for (std::size_t index = 0; index < storage.memberCount; ++index)
            if (storage.members[index].name == name)
                return storage.members[index].offset;
        return -1;
    }

    [[nodiscard]] inline bool RemoteRuntime::StorageMemberFits(const ValueStorageDescriptor &storage,
                                                               std::string_view name, std::int32_t size)
    {
        const std::int32_t offset = StorageOffset(storage, name);
        return storage.size > 0 && size > 0 && offset >= 0 && offset <= storage.size - size;
    }

    [[nodiscard]] inline std::size_t RemoteRuntime::BitCount(std::uint32_t value)
    {
        std::size_t count = 0;
        while (value)
        {
            value &= value - 1;
            ++count;
        }
        return count;
    }

} // namespace NextDumper
