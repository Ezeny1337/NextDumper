#pragma once

#include "../Runtime.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace NextDumper
{

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadObjectReference(TargetAddress address, const char *typeName)
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

    [[nodiscard]] inline bool RemoteRuntime::ReadObjectHandle(TargetAddress address, ObjectHandle &handle)
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

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadWeakObject(TargetAddress address,
                                                                       const ValueDescriptor &type)
    {
        if (type.storage.size != type.elementSize)
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "weak-object-size-unverified");
        const std::int32_t indexOffset = StorageOffset(type.storage, "ObjectIndex");
        const std::int32_t serialOffset = StorageOffset(type.storage, "ObjectSerialNumber");
        if (!StorageMemberFits(type.storage, "ObjectIndex", 4) ||
            !StorageMemberFits(type.storage, "ObjectSerialNumber", 4) || indexOffset < 0 || serialOffset < 0)
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
        if (!objectType || (!Empty(type.referencedType) && !IsTypeA(objectType, type.referencedType)))
            return {ReadStatus::InvalidReference, {}};
        object.type = objectType;
        result.object = object;
        return {ReadStatus::Ok, std::move(result)};
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadSoftObject(TargetAddress address,
                                                                       const ValueDescriptor &type)
    {
        if (type.storage.size != type.elementSize)
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "soft-object-size-unverified");
        const auto layoutId = std::string_view(type.storage.id ? type.storage.id : "");
        const std::int32_t indexOffset = StorageOffset(type.storage, "ObjectIndex");
        const std::int32_t serialOffset = StorageOffset(type.storage, "ObjectSerialNumber");
        const std::int32_t assetOffset = StorageOffset(type.storage, "AssetPath");
        const std::int32_t subPathOffset = StorageOffset(type.storage, "SubPath");
        const std::int32_t assetSize =
            layoutId.find("top-level") != std::string_view::npos ? 2 * binding_.fname.size : binding_.fname.size;
        if (assetOffset < 0 || subPathOffset < 0 || !StorageMemberFits(type.storage, "AssetPath", assetSize) ||
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
            if (!Add(assetAddress, binding_.fname.size, secondAddress) || !ReadFName(secondAddress, result.assetName))
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

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadLazyObject(TargetAddress address,
                                                                       const ValueDescriptor &type)
    {
        if (type.storage.size != type.elementSize)
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "lazy-object-size-unverified");
        const std::int32_t indexOffset = StorageOffset(type.storage, "ObjectIndex");
        const std::int32_t serialOffset = StorageOffset(type.storage, "ObjectSerialNumber");
        const std::int32_t idOffset = StorageOffset(type.storage, "ObjectId");
        if (!StorageMemberFits(type.storage, "ObjectIndex", 4) ||
            !StorageMemberFits(type.storage, "ObjectSerialNumber", 4) ||
            !StorageMemberFits(type.storage, "ObjectId", 16) || indexOffset < 0 || serialOffset < 0 || idOffset < 0)
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

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadInterface(TargetAddress address,
                                                                      const ValueDescriptor &type)
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
                result.resolvedObject = RemoteObjectView{this, handle, info ? FindType(info->classFullName) : nullptr};
            }
        }
        return {ReadStatus::Ok, std::move(result)};
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadDelegate(TargetAddress address, const ValueDescriptor &type)
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
            !StorageMemberFits(type.storage, "FunctionName", binding_.fname.size) || indexOffset < 0 ||
            serialOffset < 0 || nameOffset < 0)
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

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadText(TargetAddress address, const ValueDescriptor &type)
    {
        if (type.storage.size != type.elementSize)
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "text-size-unverified");
        const std::int32_t dataOffset = StorageOffset(type.storage, "TextData");
        const std::int32_t flagsOffset = StorageOffset(type.storage, "Flags");
        if (!StorageMemberFits(type.storage, "TextData", binding_.pointerWidth) ||
            !StorageMemberFits(type.storage, "Flags", 4) || dataOffset < 0 || flagsOffset < 0)
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

} // namespace NextDumper
