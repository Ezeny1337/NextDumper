#pragma once

#include "../Runtime.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace NextDumper
{

    [[nodiscard]] inline ReadStatus RemoteRuntime::RefreshObjectCount()
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
        const ReadResult countRead = ReadExact(countAddress, &count, sizeof(count));
        if (!countRead.Ok())
            return countRead.status;
        const ReadStatus storageStatus = ReadPointer(storageAddress, storage);
        if (storageStatus != ReadStatus::Ok)
            return storageStatus;
        if (count <= 0 || count > options_.maxObjectCount || !storage ||
            (objectStorage_ && storage != objectStorage_) ||
            (objectStorage_ && binding_.objects.kind == ObjectArrayKind::Fixed && count != objectCount_))
            return ReadStatus::InvalidHeader;
        if (binding_.objects.maxElementsOffset >= 0)
        {
            std::int32_t capacity = 0;
            TargetAddress capacityAddress = 0;
            if (!Add(objectRoot_, static_cast<std::uint32_t>(binding_.objects.maxElementsOffset), capacityAddress))
                return ReadStatus::AddressOverflow;
            const ReadResult capacityRead = ReadExact(capacityAddress, &capacity, sizeof(capacity));
            if (!capacityRead.Ok())
                return capacityRead.status;
            if (capacity < count || capacity > options_.maxObjectCount)
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
                if (!Add(objectRoot_, static_cast<std::uint32_t>(offset), address))
                    return ReadStatus::AddressOverflow;
                const ReadResult chunkRead = ReadExact(address, &chunks, sizeof(chunks));
                if (!chunkRead.Ok())
                    return chunkRead.status;
                if (chunks < requiredChunks || chunks > 0x1000)
                    return ReadStatus::InvalidHeader;
            }
        }
        objectStorage_ = storage;
        objectCount_ = count;
        return ReadStatus::Ok;
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadObject(std::int32_t index, RemoteObjectView &out)
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
        if (binding_.uobject.internalIndexOffset < 0)
            return ReadStatus::Unsupported;
        if (!Add(address, static_cast<std::uint32_t>(binding_.uobject.internalIndexOffset), indexAddress))
            return ReadStatus::AddressOverflow;
        const ReadResult indexRead = ReadExact(indexAddress, &reportedIndex, sizeof(reportedIndex));
        if (!indexRead.Ok())
            return indexRead.status;
        if (reportedIndex != index)
            return ReadStatus::InvalidReference;
        ObjectHandle handle{address, index, 0, false};
        if (binding_.objects.itemSerialOffset >= 0)
        {
            TargetAddress serialAddress = 0;
            if (!Add(itemBase, static_cast<std::uint32_t>(binding_.objects.itemSerialOffset), serialAddress))
                return ReadStatus::AddressOverflow;
            const ReadResult serialRead = ReadExact(serialAddress, &handle.serial, sizeof(handle.serial));
            if (!serialRead.Ok())
                return serialRead.status;
            if (handle.serial < 0)
                return ReadStatus::InvalidReference;
            handle.serialKnown = handle.serial > 0;
            handle.serialState = handle.serialKnown ? ObjectSerialState::Known : ObjectSerialState::Unassigned;
        }
        out = {this, handle, nullptr};
        return ReadStatus::Ok;
    }

    [[nodiscard]] inline std::optional<ObjectInfo> RemoteRuntime::Describe(const RemoteObjectView &object)
    {
        ObjectInfo info;
        if (Describe(object, info) != ReadStatus::Ok)
            return std::nullopt;
        return info;
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::Describe(const RemoteObjectView &object, ObjectInfo &out)
    {
        out = {};
        if (object.runtime != this)
            return ReadStatus::InvalidArgument;
        const ReadStatus status = ValidateHandle(object.handle);
        return status == ReadStatus::Ok ? ReadObjectInfo(object.handle, out) : status;
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ResolveObjectType(RemoteObjectView &object)
    {
        object.type = nullptr;
        if (object.runtime != this)
            return ReadStatus::InvalidArgument;
        const ReadStatus status = ValidateHandle(object.handle);
        if (status != ReadStatus::Ok)
            return status;
        return ReadObjectType(object.handle.address, object.type);
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadObjectFlags(const RemoteObjectView &object, std::uint32_t &flags)
    {
        flags = 0;
        if (object.runtime != this)
            return ReadStatus::InvalidArgument;
        const ReadStatus status = ValidateHandle(object.handle);
        return status == ReadStatus::Ok ? ReadObjectFlags(object.handle.address, flags) : status;
    }

    [[nodiscard]] inline ObjectQueryResult RemoteRuntime::FindObjects(const ObjectQuery &query, std::size_t maxResults,
                                                                      ObjectFlagsFilter flags)
    {
        return FindObjectsImpl(query, maxResults, {}, nullptr, false, flags);
    }

    [[nodiscard]] inline ObjectLookupResult RemoteRuntime::FindFirstUClassObject(std::string_view name,
                                                                                 ObjectFlagsFilter flags)
    {
        if (name.empty())
            return {ReadStatus::InvalidArgument, std::nullopt, 0};
        if (!initialized_)
            return {ReadStatus::NotInitialized, std::nullopt, 0};
        constexpr std::string_view uclassFullName = "Class /Script/CoreUObject.Class";
        const TypeDescriptor *uclassType = FindType(uclassFullName);
        if (!uclassType || uclassType->kind != TypeKind::Class)
            return {ReadStatus::Unsupported, std::nullopt, 0};
        ObjectQuery query;
        query.name = name;
        ObjectQueryResult matches = FindObjectsImpl(query, 1, uclassFullName, uclassType, true, flags);
        if (!matches.objects.empty())
            return {matches.status == ReadStatus::Incomplete ? ReadStatus::Incomplete : ReadStatus::Ok,
                    matches.objects.front(), matches.slotsVisited};
        return {matches.status == ReadStatus::Ok ? ReadStatus::NotFound : matches.status, std::nullopt,
                matches.slotsVisited};
    }

    [[nodiscard]] inline ObjectLookupResult RemoteRuntime::FindFirstObjectOfType(std::string_view classFullName,
                                                                                 bool includeDerived,
                                                                                 ObjectFlagsFilter flags)
    {
        ObjectQueryResult matches = FindObjectsOfType(classFullName, 1, includeDerived, flags);
        if (!matches.objects.empty())
            return {matches.status == ReadStatus::Incomplete ? ReadStatus::Incomplete : ReadStatus::Ok,
                    matches.objects.front(), matches.slotsVisited};
        return {matches.status == ReadStatus::Ok ? ReadStatus::NotFound : matches.status, std::nullopt,
                matches.slotsVisited};
    }

    [[nodiscard]] inline ObjectQueryResult RemoteRuntime::FindObjectsOfType(std::string_view classFullName,
                                                                            std::size_t maxResults, bool includeDerived,
                                                                            ObjectFlagsFilter flags)
    {
        if (!initialized_)
            return {ReadStatus::NotInitialized, 0, false, {}};
        if (classFullName.empty())
            return {ReadStatus::InvalidArgument, 0, false, {}};
        if (maxResults == 0)
            return {ReadStatus::InvalidArgument, 0, false, {}};
        const TypeDescriptor *requestedType = FindType(classFullName);
        if ((includeDerived && !requestedType) || (requestedType && requestedType->kind != TypeKind::Class))
            return {ReadStatus::Unsupported, 0, false, {}};
        return FindObjectsImpl({}, maxResults, classFullName, requestedType, includeDerived, flags);
    }

    [[nodiscard]] inline ObjectQueryResult RemoteRuntime::FindObjectsImpl(const ObjectQuery &query,
                                                                          std::size_t maxResults,
                                                                          std::string_view requiredTypeFullName,
                                                                          const TypeDescriptor *requiredType,
                                                                          bool includeDerived,
                                                                          ObjectFlagsFilter flags)
    {
        ObjectQueryResult result;
        if (!initialized_)
        {
            result.status = ReadStatus::NotInitialized;
            return result;
        }
        if (query.fullName.empty() && query.classFullName.empty() && query.className.empty() && query.name.empty() &&
            requiredTypeFullName.empty())
        {
            result.status = ReadStatus::InvalidArgument;
            return result;
        }
        if (maxResults == 0)
        {
            result.status = ReadStatus::InvalidArgument;
            return result;
        }
        if ((flags.requireAll & flags.excludeAny) != 0)
        {
            result.status = ReadStatus::InvalidArgument;
            return result;
        }
        if (!flags.IsEmpty() && binding_.uobject.flagsOffset < 0)
        {
            result.status = ReadStatus::Unsupported;
            return result;
        }
        const std::size_t resultLimit = std::min(maxResults, options_.maxSearchResults);
        const ReadStatus refreshStatus = RefreshObjectCount();
        if (refreshStatus != ReadStatus::Ok)
        {
            result.status = refreshStatus;
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
            if (!flags.IsEmpty())
            {
                std::uint32_t objectFlags = 0;
                if (ReadObjectFlags(object.handle.address, objectFlags) != ReadStatus::Ok)
                {
                    result.status = ReadStatus::Incomplete;
                    continue;
                }
                if (!flags.Matches(objectFlags))
                    continue;
            }
            bool matches = true;
            std::string objectName, className, classFullName, fullName;
            TargetAddress classAddress = 0;
            if (!query.name.empty() || !query.fullName.empty())
            {
                if (ReadObjectName(object.handle.address, objectName) != ReadStatus::Ok)
                {
                    result.status = ReadStatus::Incomplete;
                    continue;
                }
                matches = query.name.empty() || objectName == query.name;
            }
            if (matches && (!query.className.empty() || !query.classFullName.empty() ||
                            !requiredTypeFullName.empty()))
            {
                if (ReadObjectClass(object.handle.address, classAddress) != ReadStatus::Ok)
                {
                    result.status = ReadStatus::Incomplete;
                    continue;
                }
                if (!query.className.empty())
                {
                    if (ReadObjectName(classAddress, className) != ReadStatus::Ok)
                    {
                        result.status = ReadStatus::Incomplete;
                        continue;
                    }
                    matches = className == query.className;
                }
            }
            if (matches && (!query.classFullName.empty() || !requiredTypeFullName.empty()))
            {
                if (ReadFullName(classAddress, classFullName) != ReadStatus::Ok)
                {
                    result.status = ReadStatus::Incomplete;
                    continue;
                }
                if (!query.classFullName.empty())
                    matches = classFullName == query.classFullName;
                if (matches && !requiredTypeFullName.empty())
                {
                    if (classFullName == requiredTypeFullName)
                    {
                        object.type = requiredType;
                        matches = true;
                    }
                    else if (!includeDerived)
                        matches = false;
                    else
                    {
                        object.type = FindType(classFullName);
                        if (!object.type)
                        {
                            result.status = ReadStatus::Incomplete;
                            continue;
                        }
                        bool chainComplete = false;
                        matches = IsTypeA(object.type, requiredTypeFullName, chainComplete);
                        if (!chainComplete)
                        {
                            result.status = ReadStatus::Incomplete;
                            continue;
                        }
                    }
                }
            }
            if (matches && !query.fullName.empty())
            {
                if (ReadFullName(object.handle.address, fullName) != ReadStatus::Ok)
                {
                    result.status = ReadStatus::Incomplete;
                    continue;
                }
                matches = fullName == query.fullName;
            }
            if (matches)
            {
                if (!classFullName.empty() && !object.type)
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

    [[nodiscard]] inline ObjectLookupResult RemoteRuntime::FindFirstObject(const ObjectQuery &query,
                                                                           ObjectFlagsFilter flags)
    {
        ObjectQueryResult matches = FindObjects(query, 1, flags);
        if (!matches.objects.empty())
            return {matches.status == ReadStatus::Incomplete ? ReadStatus::Incomplete : ReadStatus::Ok,
                    matches.objects.front(), matches.slotsVisited};
        return {matches.status == ReadStatus::Ok ? ReadStatus::NotFound : matches.status, std::nullopt,
                matches.slotsVisited};
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadObjectName(TargetAddress object, std::string &name)
    {
        if (binding_.uobject.nameOffset < 0)
            return ReadStatus::Unsupported;
        TargetAddress address = 0;
        if (!Add(object, static_cast<std::uint32_t>(binding_.uobject.nameOffset), address))
            return ReadStatus::AddressOverflow;
        return ReadFName(address, name);
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadObjectClass(TargetAddress object, TargetAddress &classAddress)
    {
        classAddress = 0;
        if (binding_.uobject.classOffset < 0)
            return ReadStatus::Unsupported;
        TargetAddress address = 0;
        if (!Add(object, static_cast<std::uint32_t>(binding_.uobject.classOffset), address))
            return ReadStatus::AddressOverflow;
        const ReadStatus status = ReadPointer(address, classAddress);
        if (status != ReadStatus::Ok)
            return status;
        return classAddress ? ReadStatus::Ok : ReadStatus::InvalidReference;
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadObjectType(TargetAddress object, const TypeDescriptor *&type)
    {
        type = nullptr;
        TargetAddress classAddress = 0;
        ReadStatus status = ReadObjectClass(object, classAddress);
        if (status != ReadStatus::Ok)
            return status;
        std::string classFullName;
        status = ReadFullName(classAddress, classFullName);
        if (status != ReadStatus::Ok)
            return status;
        const TypeDescriptor *resolved = FindType(classFullName);
        if (!resolved || resolved->kind != TypeKind::Class)
            return ReadStatus::Incomplete;
        type = resolved;
        return ReadStatus::Ok;
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadObjectClassName(TargetAddress object, std::string &className)
    {
        TargetAddress classAddress = 0;
        const ReadStatus status = ReadObjectClass(object, classAddress);
        return status == ReadStatus::Ok ? ReadObjectName(classAddress, className) : status;
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadOuter(TargetAddress object, TargetAddress &outer)
    {
        outer = 0;
        if (binding_.uobject.outerOffset < 0)
            return ReadStatus::Unsupported;
        TargetAddress address = 0;
        if (!Add(object, static_cast<std::uint32_t>(binding_.uobject.outerOffset), address))
            return ReadStatus::AddressOverflow;
        return ReadPointer(address, outer);
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadFullName(TargetAddress object, std::string &fullName)
    {
        if (options_.maxOuterDepth == 0)
            return ReadStatus::LimitExceeded;
        std::string objectName;
        std::string className;
        ReadStatus status = ReadObjectName(object, objectName);
        if (status != ReadStatus::Ok)
            return status;
        status = ReadObjectClassName(object, className);
        if (status != ReadStatus::Ok)
            return status;
        std::vector<std::string> outerNames;
        std::vector<TargetAddress> visited{object};
        TargetAddress current = object;
        for (std::size_t level = 0; level < options_.maxOuterDepth; ++level)
        {
            TargetAddress outer = 0;
            status = ReadOuter(current, outer);
            if (status != ReadStatus::Ok)
                return status;
            if (!outer)
                break;
            if (std::find(visited.begin(), visited.end(), outer) != visited.end())
                return ReadStatus::InvalidReference;
            visited.push_back(outer);
            std::string name;
            status = ReadObjectName(outer, name);
            if (status != ReadStatus::Ok)
                return status;
            outerNames.push_back(std::move(name));
            current = outer;
            if (level + 1 == options_.maxOuterDepth)
                return ReadStatus::LimitExceeded;
        }
        fullName = std::move(className);
        fullName.push_back(' ');
        for (auto at = outerNames.rbegin(); at != outerNames.rend(); ++at)
        {
            fullName += *at;
            fullName.push_back('.');
        }
        fullName += objectName;
        return ReadStatus::Ok;
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadObjectInfo(const ObjectHandle &handle, ObjectInfo &out)
    {
        ObjectInfo info;
        info.handle = handle;
        ReadStatus status = ReadObjectClass(handle.address, info.classAddress);
        if (status != ReadStatus::Ok)
            return status;
        status = ReadOuter(handle.address, info.outerAddress);
        if (status != ReadStatus::Ok)
            return status;
        status = ReadObjectName(handle.address, info.name);
        if (status != ReadStatus::Ok)
            return status;
        status = ReadObjectName(info.classAddress, info.className);
        if (status != ReadStatus::Ok)
            return status;
        status = ReadFullName(handle.address, info.fullName);
        if (status != ReadStatus::Ok)
            return status;
        status = ReadObjectFlags(handle.address, info.flags);
        if (status != ReadStatus::Ok)
            return status;
        status = ReadFullName(info.classAddress, info.classFullName);
        if (status != ReadStatus::Ok)
            return status;
        out = std::move(info);
        return ReadStatus::Ok;
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadObjectFlags(TargetAddress object, std::uint32_t &flags) const
    {
        flags = 0;
        if (!object || binding_.uobject.flagsOffset < 0)
            return ReadStatus::Unsupported;
        TargetAddress flagsAddress = 0;
        if (!Add(object, static_cast<std::uint32_t>(binding_.uobject.flagsOffset), flagsAddress))
            return ReadStatus::AddressOverflow;
        return ReadExact(flagsAddress, &flags, sizeof(flags)).status;
    }

} // namespace NextDumper
