#pragma once

#include "../Runtime.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

namespace NextDumper
{

    inline RemoteRuntime::RemoteRuntime(MemoryReader memory, TargetAddress moduleBase,
                                        const RuntimeBindingDescriptor &binding, const TypeDescriptor *types,
                                        std::size_t typeCount, const EnumDescriptor *enums, std::size_t enumCount,
                                        RuntimeOptions options)
        : memory_(memory), moduleBase_(moduleBase), binding_(binding),
          moduleName_(binding.moduleName ? binding.moduleName : ""), types_(types), typeCount_(typeCount),
          enums_(enums), enumCount_(enumCount), options_(options)
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

    [[nodiscard]] inline ReadStatus RemoteRuntime::Initialize(const char *moduleName, RuntimeRoots roots)
    {
        Reset();
        if (!memory_.read || !moduleName || Empty(binding_.moduleName) || (typeCount_ && !types_) ||
            (enumCount_ && !enums_) || binding_.pointerWidth != sizeof(TargetAddress) ||
            std::string_view(moduleName) != binding_.moduleName)
            return ReadStatus::InvalidArgument;
        if (!binding_.decoding.IsValid())
            return ReadStatus::InvalidArgument;
        if (!binding_.decoding.IsSupported(binding_.names.kind == NameStoreKind::Pool,
                                           binding_.objects.kind == ObjectArrayKind::Chunked))
            return ReadStatus::Unsupported;
        if (!moduleBase_ &&
            ((!roots.objectRoot && binding_.hasObjectRootRva) || (!roots.nameRoot && binding_.hasNameRootRva)))
            return ReadStatus::InvalidArgument;
        objectRoot_ = roots.objectRoot;
        nameRoot_ = roots.nameRoot;
        if (!objectRoot_ && binding_.hasObjectRootRva && !Add(moduleBase_, binding_.objectRootRva, objectRoot_))
            return ReadStatus::AddressOverflow;
        if (!nameRoot_ && binding_.hasNameRootRva && !Add(moduleBase_, binding_.nameRootRva, nameRoot_))
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

    inline void RemoteRuntime::Reset()
    {
        initialized_ = false;
        objectRoot_ = 0;
        nameRoot_ = 0;
        objectStorage_ = 0;
        objectCount_ = 0;
        nameCache_.clear();
    }

    [[nodiscard]] inline bool RemoteRuntime::IsInitialized() const { return initialized_; }

    [[nodiscard]] inline std::int32_t RemoteRuntime::ObjectCount() const { return objectCount_; }

    [[nodiscard]] inline TargetAddress RemoteRuntime::ObjectRoot() const { return objectRoot_; }

    [[nodiscard]] inline TargetAddress RemoteRuntime::NameRoot() const { return nameRoot_; }

    [[nodiscard]] inline bool RemoteRuntime::Empty(const char *value) { return !value || value[0] == '\0'; }

    [[nodiscard]] inline std::int32_t RemoteRuntime::ScalarSize(PropertyKind kind)
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

    [[nodiscard]] inline std::optional<std::int32_t> RemoteRuntime::ValueExtent(const ValueDescriptor *value)
    {
        if (!value || value->elementSize <= 0 || value->arrayDim <= 0)
            return std::nullopt;
        const std::int64_t extent = static_cast<std::int64_t>(value->elementSize) * value->arrayDim;
        if (extent <= 0 || extent > INT32_MAX)
            return std::nullopt;
        return static_cast<std::int32_t>(extent);
    }

    [[nodiscard]] inline std::optional<std::int32_t> RemoteRuntime::SparseHeaderSize(bool memoryImage) const
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
        return size <= INT32_MAX ? std::optional<std::int32_t>(static_cast<std::int32_t>(size)) : std::nullopt;
    }

    [[nodiscard]] inline bool RemoteRuntime::Add(TargetAddress base, std::uint64_t offset, TargetAddress &out)
    {
        if (!base || offset > std::numeric_limits<TargetAddress>::max() - base)
            return false;
        out = static_cast<TargetAddress>(base + offset);
        return true;
    }

    [[nodiscard]] inline bool RemoteRuntime::AddScaled(TargetAddress base, std::int32_t index, std::int32_t stride,
                                                       TargetAddress &out)
    {
        if (index < 0 || stride <= 0 ||
            static_cast<std::uint64_t>(index) >
                std::numeric_limits<std::uint64_t>::max() / static_cast<std::uint32_t>(stride))
            return false;
        return Add(base, static_cast<std::uint64_t>(index) * static_cast<std::uint32_t>(stride), out);
    }

    [[nodiscard]] inline ReadResult RemoteRuntime::ReadExact(TargetAddress address, void *buffer,
                                                             std::size_t size) const
    {
        return memory_.Read(address, buffer, size);
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadPointer(TargetAddress address, TargetAddress &value) const
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
            if (!ReadExact(address, &raw, sizeof(raw)).Ok() || raw > std::numeric_limits<TargetAddress>::max())
                return ReadStatus::ReadFailure;
            value = static_cast<TargetAddress>(raw);
            return ReadStatus::Ok;
        }
        return ReadStatus::Unsupported;
    }

    [[nodiscard]] inline bool RemoteRuntime::ValidLayouts() const
    {
        const auto &objects = binding_.objects;
        const auto &names = binding_.names;
        const auto &object = binding_.uobject;
        const std::int32_t pointer = binding_.pointerWidth;
        if ((binding_.pointerWidth != 4 && binding_.pointerWidth != 8) || binding_.fname.size <= 0 ||
            binding_.fname.comparisonIndex < 0 || binding_.fname.comparisonIndex > binding_.fname.size - 4 ||
            objects.objectsOffset < 0 || objects.numElementsOffset < 0 || objects.itemObjectOffset < 0 ||
            objects.itemStride <= 0 || objects.itemObjectOffset > objects.itemStride - pointer ||
            objects.itemIndexOffset < 0 || object.classOffset < 0 || object.internalIndexOffset < 0 ||
            object.nameOffset < 0 || object.outerOffset < 0)
            return false;
        if (binding_.casePreservingName &&
            (binding_.fname.displayIndex < 0 || binding_.fname.displayIndex > binding_.fname.size - 4))
            return false;
        if (binding_.fname.numberInline &&
            (binding_.fname.number < 0 || binding_.fname.number > binding_.fname.size - 4))
            return false;
        if (objects.kind != ObjectArrayKind::Fixed && objects.kind != ObjectArrayKind::Chunked)
            return false;
        if (objects.kind == ObjectArrayKind::Chunked && (objects.elementsPerChunk <= 0 || objects.numChunksOffset < 0))
            return false;
        if (names.kind == NameStoreKind::Pool)
            return names.blocksOffset >= 0 && names.blocksBit > 0 && names.blocksBit <= 18 &&
                   (names.entryStride == 2 || names.entryStride == 4) && names.entryHeaderOffset >= 0 &&
                   names.poolStringOffset >= names.entryHeaderOffset + 2 && names.entryLengthShift >= 0 &&
                   names.entryLengthShift < 16 && names.entryWideMask != 0;
        if (names.kind != NameStoreKind::Array)
            return false;
        return names.chunksOffset >= 0 && names.elementsPerChunk > 0 && names.entryIndexOffset >= 0 &&
               names.entryStringOffset >= 0;
    }

    [[nodiscard]] inline const TypeDescriptor *RemoteRuntime::FindType(std::string_view fullName) const
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

    [[nodiscard]] inline const EnumDescriptor *RemoteRuntime::FindEnum(std::string_view fullName) const
    {
        if (fullName.empty())
            return nullptr;
        for (std::size_t index = 0; index < enumCount_; ++index)
            if (enums_[index].fullName == fullName)
                return &enums_[index];
        return nullptr;
    }

    [[nodiscard]] inline FieldLookupResult RemoteRuntime::FindField(const TypeDescriptor *type,
                                                                    std::string_view name) const
    {
        if (!type || name.empty())
            return {ReadStatus::InvalidArgument, nullptr};

        std::array<const TypeDescriptor *, 64> visited{};
        std::size_t depth = 0;
        bool descriptorIncomplete = false;
        while (type && depth < visited.size())
        {
            if (std::find(visited.begin(), visited.begin() + static_cast<std::ptrdiff_t>(depth), type) !=
                visited.begin() + static_cast<std::ptrdiff_t>(depth))
                return {ReadStatus::Incomplete, nullptr};
            visited[depth++] = type;

            if (!type->status || std::string_view(type->status) != "Complete")
                descriptorIncomplete = true;
            if (type->fieldCount != 0 && !type->fields)
                return {ReadStatus::Incomplete, nullptr};
            for (std::size_t index = 0; index < type->fieldCount; ++index)
            {
                if (!type->fields[index].name)
                    return {ReadStatus::Incomplete, nullptr};
                if (std::string_view(type->fields[index].name) == name)
                    return {ReadStatus::Ok, &type->fields[index]};
            }

            if (!type->superFullName || type->superFullName[0] == '\0')
                return {type->superTypeResolved && !descriptorIncomplete ? ReadStatus::NotFound
                                                                         : ReadStatus::Incomplete,
                        nullptr};

            if (!type->superTypeResolved)
                return {ReadStatus::Incomplete, nullptr};
            type = FindType(type->superFullName);
            if (!type)
                return {ReadStatus::Incomplete, nullptr};
        }
        return {ReadStatus::Incomplete, nullptr};
    }

    [[nodiscard]] inline bool RemoteRuntime::IsTypeA(const TypeDescriptor *type, std::string_view baseName) const
    {
        bool chainComplete = false;
        return IsTypeA(type, baseName, chainComplete);
    }

    [[nodiscard]] inline bool RemoteRuntime::IsTypeA(const TypeDescriptor *type, std::string_view baseName,
                                                     bool &chainComplete) const
    {
        std::array<std::string_view, 64> visited{};
        std::size_t count = 0;
        chainComplete = type != nullptr;
        for (; type && count < visited.size(); ++count)
        {
            if (type->fullName == baseName)
                return true;
            if (std::find(visited.begin(), visited.begin() + static_cast<std::ptrdiff_t>(count),
                          std::string_view(type->fullName)) != visited.begin() + static_cast<std::ptrdiff_t>(count))
            {
                chainComplete = false;
                return false;
            }
            visited[count] = type->fullName;
            if (!type->superFullName || type->superFullName[0] == '\0')
            {
                chainComplete = type->superTypeResolved;
                return false;
            }
            type = FindType(type->superFullName);
            if (!type)
            {
                chainComplete = false;
                return false;
            }
        }
        if (count == visited.size())
            chainComplete = false;
        return false;
    }

    [[nodiscard]] inline bool RemoteRuntime::ValidateHandle(const ObjectHandle &handle)
    {
        if (!initialized_ || handle.index < 0 || handle.index >= objectCount_ || !handle.address)
            return false;
        RemoteObjectView current;
        if (ReadObject(handle.index, current) != ReadStatus::Ok || current.handle.address != handle.address)
            return false;
        return !handle.serialKnown || (current.handle.serialKnown && current.handle.serial == handle.serial);
    }

} // namespace NextDumper
