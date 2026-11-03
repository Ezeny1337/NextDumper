#pragma once

#include "../Runtime.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace NextDumper
{

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadElement(const RemoteStaticArrayView &array,
                                                                    std::int32_t index)
    {
        if (array.runtime != this || !array.address || !array.element || array.count <= 0 || array.stride <= 0 ||
            index < 0 || index >= array.count)
            return {ReadStatus::InvalidIndex, {}};
        TargetAddress address = 0;
        if (!AddScaled(array.address, index, array.stride, address))
            return {ReadStatus::AddressOverflow, {}};
        ValueDescriptor element = *array.element;
        element.arrayDim = 1;
        return ReadValueAt(address, element, array.boolean);
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadElement(const RemoteArrayView &array, std::int32_t index)
    {
        if (array.runtime != this || !array.address || !array.element || array.count <= 0 || array.stride <= 0 ||
            index < 0 || index >= array.count)
            return {ReadStatus::InvalidIndex, {}};
        if (array.frozen)
            return {ReadStatus::Unsupported, {}};
        TargetAddress address = 0;
        if (!AddScaled(array.data, index, array.stride, address))
            return {ReadStatus::AddressOverflow, {}};
        return ReadValueAt(address, *array.element);
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadSparseSlot(const RemoteSparseContainerView &container,
                                                                       std::int32_t slot)
    {
        if (container.runtime != this || !container.data || container.slots <= 0 || container.stride <= 0 || slot < 0 ||
            slot >= container.slots)
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
        if (!container.value || !keyExtent || !valueExtent || container.valueOffset < *keyExtent ||
            container.valueOffset > container.stride - *valueExtent ||
            !Add(address, static_cast<std::uint32_t>(container.valueOffset), valueAddress))
            return {ReadStatus::InvalidHeader, {}};
        return {ReadStatus::Ok, RemoteMapEntryView{this, address, valueAddress, container.key, container.value}};
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadMapKey(const RemoteMapEntryView &entry)
    {
        if (entry.runtime != this || !entry.key || !entry.keyAddress)
            return {ReadStatus::InvalidArgument, {}};
        return ReadValueAt(entry.keyAddress, *entry.key);
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::ReadMapValue(const RemoteMapEntryView &entry)
    {
        if (entry.runtime != this || !entry.value || !entry.valueAddress)
            return {ReadStatus::InvalidArgument, {}};
        return ReadValueAt(entry.valueAddress, *entry.value);
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::OpenArray(TargetAddress address, const ValueDescriptor &type)
    {
        if (!type.inner || type.inner->elementSize <= 0 || type.inner->arrayDim <= 0)
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "array-element-layout-unresolved");
        const std::int64_t stride64 = static_cast<std::int64_t>(type.inner->elementSize) * type.inner->arrayDim;
        if (stride64 <= 0 || stride64 > INT32_MAX)
            return {ReadStatus::InvalidHeader, {}};
        const bool memoryImage = type.container.allocator == ContainerAllocatorKind::MemoryImage;
        if (type.container.allocator == ContainerAllocatorKind::Unknown || Empty(type.container.layoutId))
            return ReadOpaque(address, static_cast<std::size_t>(type.elementSize), "array-storage-layout-unselected");
        if (memoryImage && binding_.pointerWidth != 8)
            return {ReadStatus::Unsupported, {}};
        const std::string expectedLayout =
            std::string(memoryImage ? "memory-image-array-p" : "heap-array-p") + std::to_string(binding_.pointerWidth);
        const std::int32_t expectedSize = memoryImage ? 16 : binding_.pointerWidth + 8;
        if (std::string_view(type.container.layoutId) != expectedLayout || type.elementSize != expectedSize ||
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
            !ReadExact(capacityAddress, &capacity, sizeof(capacity)).Ok() || count < 0 || capacity < count ||
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
        return {ReadStatus::Ok, RemoteArrayView{this, address, data, type.inner, count, capacity,
                                                static_cast<std::int32_t>(stride64), memoryImage, frozen}};
    }

    [[nodiscard]] inline ValueReadResult RemoteRuntime::OpenSparseContainer(TargetAddress address,
                                                                            const ValueDescriptor &type)
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
            !ReadExact(hashSizeAddress, &hashSize, sizeof(hashSize)).Ok() || slots < 0 || capacity < slots ||
            freeCount < 0 || freeCount > slots || bitsNum != slots || bitsMax < slots ||
            static_cast<std::size_t>(slots) > options_.maxSparseSlots ||
            (freeCount > 0 && (firstFree < 0 || firstFree >= slots)) || hashSize < 0 ||
            hashSize > static_cast<std::int32_t>(2 * options_.maxSparseSlots) ||
            (slots - freeCount > 0 && hashSize == 0) || (hashSize > 0 && (hashSize & (hashSize - 1)) != 0))
            return {ReadStatus::InvalidHeader, {}};
        TargetAddress dataField = 0, bitsField = 0, hashField = 0;
        if (!Add(address, dataOffset, dataField) || !Add(address, bitsPointerOffset, bitsField) ||
            !Add(address, hashPointerOffset, hashField))
            return {ReadStatus::AddressOverflow, {}};
        TargetAddress data = 0, bits = 0, hash = 0;
        bool frozen = false;
        if (memoryImage)
        {
            std::uint64_t rawData = 0, rawBits = 0, rawHash = 0;
            if (!ReadExact(dataField, &rawData, 8).Ok() || !ReadExact(bitsField, &rawBits, 8).Ok() ||
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
            if (ReadPointer(dataField, data) != ReadStatus::Ok || ReadPointer(bitsField, bits) != ReadStatus::Ok ||
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
        if ((slots > 0 && (!data || !bits)) || (hashSize > 0 && !hash && !(memoryImage && frozen && slots == 0)))
            return {ReadStatus::InvalidHeader, {}};
        const std::int64_t stride64 = type.container.elementStride;
        const std::int64_t valueOffset = type.container.valueOffset;
        const auto keyExtent = ValueExtent(key);
        const auto valueExtent = isMap ? ValueExtent(type.value) : std::optional<std::int32_t>{0};
        const auto headerSize = SparseHeaderSize(memoryImage);
        if (stride64 <= 0 || stride64 > INT32_MAX || valueOffset < 0 || !keyExtent || !valueExtent || !headerSize ||
            type.container.elementAlignment <= 0 ||
            (type.container.elementAlignment & (type.container.elementAlignment - 1)) != 0 ||
            type.container.setElementSize <= 0 || type.container.setElementSize > stride64 ||
            (memoryImage ? type.elementSize < *headerSize : type.elementSize != *headerSize) ||
            (!isMap && *keyExtent > type.container.setElementSize) ||
            (isMap && (valueOffset < *keyExtent || valueOffset > stride64 - *valueExtent)))
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
            (slots % 32 && words && (view.allocationBits.back() >> (slots % 32)) != 0))
            return {ReadStatus::InvalidHeader, {}};
        if (freeCount > 0 && (view.allocationBits[static_cast<std::size_t>(firstFree) / 32] &
                              (std::uint32_t{1} << (firstFree % 32))) != 0)
            return {ReadStatus::InvalidHeader, {}};
        if (frozen)
            return {ReadStatus::Unsupported, {}};
        return {ReadStatus::Ok, std::move(view)};
    }

} // namespace NextDumper
