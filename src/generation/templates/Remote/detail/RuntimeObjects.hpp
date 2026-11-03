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
        if (!ReadExact(countAddress, &count, sizeof(count)).Ok() ||
            ReadPointer(storageAddress, storage).status != ReadStatus::Ok)
            return ReadStatus::ReadFailure;
        if (count <= 0 || count > options_.maxObjectCount || !storage ||
            (objectStorage_ && storage != objectStorage_) ||
            (objectStorage_ && binding_.objects.kind == ObjectArrayKind::Fixed && count != objectCount_))
            return ReadStatus::InvalidHeader;
        if (binding_.objects.maxElementsOffset >= 0)
        {
            std::int32_t capacity = 0;
            TargetAddress capacityAddress = 0;
            if (!Add(objectRoot_, static_cast<std::uint32_t>(binding_.objects.maxElementsOffset), capacityAddress) ||
                !ReadExact(capacityAddress, &capacity, sizeof(capacity)).Ok() || capacity < count ||
                capacity > options_.maxObjectCount)
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
                    !ReadExact(address, &chunks, sizeof(chunks)).Ok() || chunks < requiredChunks || chunks > 0x1000)
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
        if (binding_.uobject.internalIndexOffset < 0 ||
            !Add(address, static_cast<std::uint32_t>(binding_.uobject.internalIndexOffset), indexAddress) ||
            !ReadExact(indexAddress, &reportedIndex, sizeof(reportedIndex)).Ok() || reportedIndex != index)
            return ReadStatus::InvalidReference;
        ObjectHandle handle{address, index, 0, false};
        handle.serialKnown = ReadObjectSerial(index, handle.serial);
        out = {this, handle, nullptr};
        return ReadStatus::Ok;
    }

    [[nodiscard]] inline std::optional<ObjectInfo> RemoteRuntime::Describe(const RemoteObjectView &object)
    {
        if (object.runtime != this || !ValidateHandle(object.handle))
            return std::nullopt;
        return ReadObjectInfo(object.handle);
    }

    [[nodiscard]] inline ObjectQueryResult RemoteRuntime::FindObjects(const ObjectQuery &query, std::size_t maxResults)
    {
        ObjectQueryResult result;
        if (!initialized_)
        {
            result.status = ReadStatus::NotInitialized;
            return result;
        }
        if (query.fullName.empty() && query.classFullName.empty() && query.className.empty() && query.name.empty())
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
            if (matches && (!query.className.empty() || !query.classFullName.empty() || !query.fullName.empty()))
            {
                if (!ReadObjectClass(object.handle.address, classAddress) || !ReadObjectName(classAddress, className))
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

    [[nodiscard]] inline ObjectLookupResult RemoteRuntime::FindFirstObject(const ObjectQuery &query)
    {
        ObjectQueryResult matches = FindObjects(query, 1);
        if (!matches.objects.empty())
            return {matches.status == ReadStatus::Incomplete ? ReadStatus::Incomplete : ReadStatus::Ok,
                    matches.objects.front(), matches.slotsVisited};
        return {matches.status == ReadStatus::Ok ? ReadStatus::NotFound : matches.status, std::nullopt,
                matches.slotsVisited};
    }

    [[nodiscard]] inline bool RemoteRuntime::ReadObjectSerial(std::int32_t index, std::int32_t &serial)
    {
        serial = 0;
        const std::size_t pointerWidth =
            binding_.objects.packedPointers ? sizeof(std::uint32_t) : binding_.pointerWidth;
        const std::int64_t offset =
            static_cast<std::int64_t>(binding_.objects.itemObjectOffset) + static_cast<std::int64_t>(pointerWidth) + 8;
        if (binding_.objects.itemObjectOffset != 0 || offset < 0 || offset + 4 > binding_.objects.itemStride)
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

    [[nodiscard]] inline bool RemoteRuntime::ReadObjectName(TargetAddress object, std::string &name)
    {
        TargetAddress address = 0;
        return binding_.uobject.nameOffset >= 0 &&
               Add(object, static_cast<std::uint32_t>(binding_.uobject.nameOffset), address) &&
               ReadFName(address, name);
    }

    [[nodiscard]] inline bool RemoteRuntime::ReadObjectClass(TargetAddress object, TargetAddress &classAddress)
    {
        TargetAddress address = 0;
        return binding_.uobject.classOffset >= 0 &&
               Add(object, static_cast<std::uint32_t>(binding_.uobject.classOffset), address) &&
               ReadPointer(address, classAddress) == ReadStatus::Ok && classAddress != 0;
    }

    [[nodiscard]] inline bool RemoteRuntime::ReadObjectClassName(TargetAddress object, std::string &className)
    {
        TargetAddress classAddress = 0;
        return ReadObjectClass(object, classAddress) && ReadObjectName(classAddress, className);
    }

    [[nodiscard]] inline bool RemoteRuntime::ReadOuter(TargetAddress object, TargetAddress &outer)
    {
        TargetAddress address = 0;
        return binding_.uobject.outerOffset >= 0 &&
               Add(object, static_cast<std::uint32_t>(binding_.uobject.outerOffset), address) &&
               ReadPointer(address, outer) == ReadStatus::Ok;
    }

    [[nodiscard]] inline bool RemoteRuntime::ReadFullName(TargetAddress object, std::string &fullName,
                                                          std::size_t depth)
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

    [[nodiscard]] inline std::optional<ObjectInfo> RemoteRuntime::ReadObjectInfo(const ObjectHandle &handle)
    {
        ObjectInfo info;
        info.handle = handle;
        if (!ReadObjectClass(handle.address, info.classAddress) || !ReadOuter(handle.address, info.outerAddress) ||
            !ReadObjectName(handle.address, info.name) || !ReadObjectClassName(handle.address, info.className) ||
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

} // namespace NextDumper
