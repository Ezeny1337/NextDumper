#include "nextdumper/ue/ObjectStoreReader.hpp"

#include <limits>
#include <optional>
#include <array>
#include <stdexcept>

namespace nextdumper::ue
{
    namespace
    {
        std::optional<uintptr_t> AddOffset(uintptr_t address, uintptr_t offset)
        {
            if (address > std::numeric_limits<uintptr_t>::max() - offset)
                return std::nullopt;
            return address + offset;
        }

        std::optional<uintptr_t> AddScaled(uintptr_t address, int32_t index, int32_t stride)
        {
            if (index < 0 || stride <= 0)
                return std::nullopt;
            const uintptr_t uIndex = static_cast<uintptr_t>(index);
            const uintptr_t uStride = static_cast<uintptr_t>(stride);
            if (uIndex != 0 && uStride > std::numeric_limits<uintptr_t>::max() / uIndex)
                return std::nullopt;
            return AddOffset(address, uIndex * uStride);
        }
    } // namespace

    ObjectStoreReader::ObjectStoreReader(const IMemorySource &memory,
                                         uintptr_t root,
                                         const ObjectContainerLayout &layout,
                                         const DecodePlan &decode)
        : memory_(memory), root_(root), layout_(layout), decode_(decode)
    {
    }

    const char *ObjectReadStatusName(ObjectReadStatus status)
    {
        switch (status)
        {
        case ObjectReadStatus::Valid:
            return "valid";
        case ObjectReadStatus::Empty:
            return "empty";
        case ObjectReadStatus::NotInitialized:
            return "not-initialized";
        case ObjectReadStatus::InvalidIndex:
            return "invalid-index";
        case ObjectReadStatus::AddressOverflow:
            return "address-overflow";
        case ObjectReadStatus::UnreadableChunk:
            return "unreadable-chunk";
        case ObjectReadStatus::InvalidChunk:
            return "invalid-chunk";
        case ObjectReadStatus::UnreadableObject:
            return "unreadable-object";
        case ObjectReadStatus::InvalidObject:
            return "invalid-object";
        }
        return "unknown";
    }

    bool ObjectStoreReader::Initialize()
    {
        initialized_ = false;
        storage_ = 0;
        count_ = 0;

        if (root_ == 0 || !layout_.IsValid())
            return false;

        const auto countAddress = AddOffset(root_, static_cast<uintptr_t>(layout_.numElementsOffset));
        const auto storageAddress = AddOffset(root_, static_cast<uintptr_t>(layout_.objectsOffset));
        if (!countAddress || !storageAddress)
            return false;

        int32_t rawCount = 0;
        uintptr_t rawStorage = 0;
        const std::array<memory::ReadRequest, 2> requests{{{*countAddress, &rawCount, sizeof(rawCount)}, {*storageAddress, &rawStorage, sizeof(rawStorage)}}};
        std::array<memory::ReadResult, 2> reads{};
        if (!memory_.ReadBatch(requests, reads, true) || !reads[0].Ok() || !reads[1].Ok())
            return false;

        count_ = decode_.objectCount(rawCount, *countAddress);
        storage_ = decode_.objectStorage(rawStorage, *storageAddress);
        if (count_ <= 0 || count_ > 0x08000000 || storage_ == 0)
            return false;

        if (!memory_.IsReadable(storage_, sizeof(uintptr_t)))
            return false;

        initialized_ = true;
        const auto boundary = RefreshCount();
        initialized_ = boundary.valid;
        return initialized_;
    }

    ObjectStoreBoundary ObjectStoreReader::RefreshCount()
    {
        ObjectStoreBoundary result;
        const auto countAddress = AddOffset(root_, static_cast<uintptr_t>(layout_.numElementsOffset));
        const auto storageAddress = AddOffset(root_, static_cast<uintptr_t>(layout_.objectsOffset));
        if (!initialized_ || !countAddress || !storageAddress)
        {
            result.reason = "object-store-unavailable";
            return result;
        }
        result.countAddress = *countAddress;
        int32_t rawCount = 0;
        uintptr_t rawStorage = 0;
        const std::array<memory::ReadRequest, 2> requests{{{*countAddress, &rawCount, sizeof(rawCount)}, {*storageAddress, &rawStorage, sizeof(rawStorage)}}};
        std::array<memory::ReadResult, 2> reads{};
        if (!memory_.ReadBatch(requests, reads, true) || !reads[0].Ok() || !reads[1].Ok())
        {
            result.reason = "object-boundary-unreadable";
            return result;
        }
        result.count = decode_.objectCount(rawCount, *countAddress);
        if (result.count <= 0 || result.count > 0x08000000 || result.count < count_ ||
            decode_.objectStorage(rawStorage, *storageAddress) != storage_)
        {
            result.reason = "object-count-decreased-invalid-or-storage-changed";
            return result;
        }
        const auto readCapacity = [&](int32_t offset, int32_t minimum, bool decodeCount)
        {
            if (offset < 0)
                return true;
            const auto address = AddOffset(root_, static_cast<uintptr_t>(offset));
            int32_t value = 0;
            if (!address || !memory_.ReadFreshBytes(*address, &value, sizeof(value)).Ok())
                return false;
            if (decodeCount)
                value = decode_.objectCount(value, *address);
            return value >= minimum && value <= 0x08000000;
        };
        if (!readCapacity(layout_.maxElementsOffset, result.count, true))
        {
            result.reason = "object-capacity-invalid-or-unreadable";
            return result;
        }
        if (layout_.kind == ObjectContainerKind::Chunked)
        {
            const int32_t chunks = (result.count - 1) / layout_.elementsPerChunk + 1;
            if (!readCapacity(layout_.numChunksOffset, chunks, false) || !readCapacity(layout_.maxChunksOffset, chunks, false))
            {
                result.reason = "object-chunk-capacity-invalid-or-unreadable";
                return result;
            }
        }
        else if (result.count != count_)
        {
            result.reason = "fixed-object-count-changed";
            return result;
        }
        count_ = result.count;
        result.valid = true;
        result.reason = "object-boundary-valid";
        return result;
    }

    ObjectReadResult ObjectStoreReader::ReadObject(int32_t index, bool fresh) const
    {
        if (!initialized_)
            return {};
        if (index < 0 || index >= count_)
            return {ObjectReadStatus::InvalidIndex};

        std::optional<uintptr_t> item;
        if (layout_.kind == ObjectContainerKind::Fixed)
        {
            item = AddScaled(storage_, index, layout_.itemStride);
        }
        else
        {
            const int32_t chunkIndex = index / layout_.elementsPerChunk;
            const int32_t withinChunk = index % layout_.elementsPerChunk;
            const auto chunkSlot = AddScaled(storage_, chunkIndex, static_cast<int32_t>(sizeof(uintptr_t)));
            if (!chunkSlot)
                return {ObjectReadStatus::AddressOverflow};

            uintptr_t rawChunk = 0;
            const auto read = fresh ? memory_.ReadFreshBytes(*chunkSlot, &rawChunk, sizeof(rawChunk))
                                    : memory_.ReadBytes(*chunkSlot, &rawChunk, sizeof(rawChunk));
            if (!read.Ok())
                return {ObjectReadStatus::UnreadableChunk, 0, *chunkSlot, read.error};
            const uintptr_t chunk = decode_.objectChunk(rawChunk, *chunkSlot);
            if (chunk == 0 || !memory_.IsReadable(chunk, sizeof(uintptr_t)))
                return {ObjectReadStatus::InvalidChunk, chunk, *chunkSlot};
            item = AddScaled(chunk, withinChunk, layout_.itemStride);
        }
        if (!item)
            return {ObjectReadStatus::AddressOverflow};

        const auto objectSlot = AddOffset(*item, static_cast<uintptr_t>(layout_.itemObjectOffset));
        if (!objectSlot)
            return {ObjectReadStatus::AddressOverflow};

        uintptr_t rawObject = 0;
        const auto read = fresh ? memory_.ReadFreshBytes(*objectSlot, &rawObject, sizeof(rawObject))
                                : memory_.ReadBytes(*objectSlot, &rawObject, sizeof(rawObject));
        if (!read.Ok())
            return {ObjectReadStatus::UnreadableObject, 0, *objectSlot, read.error};
        return DecodeObject(rawObject, *objectSlot);
    }

    ObjectReadResult ObjectStoreReader::DecodeObject(uintptr_t rawObject, uintptr_t slot) const
    {
        rawObject = ::nextdumper::binding::UnpackObjectItemPointer(rawObject, layout_.packedPointers);
        if (rawObject == 0)
            return {ObjectReadStatus::Empty, 0, slot};

        const uintptr_t object = decode_.objectPointer(rawObject, slot);
        if (object == 0 || !memory_.IsReadable(object, sizeof(uintptr_t)))
            return {ObjectReadStatus::InvalidObject, object, slot};
        return {ObjectReadStatus::Valid, object, slot};
    }

    bool ObjectStoreReader::ReadObjects(int32_t first, std::span<ObjectReadResult> objects, bool fresh) const
    {
        if (objects.size() > kReadWindowSize || first < 0)
            return false;
        for (auto &object : objects)
            object = {};
        if (!initialized_)
            return true;
        if (first > count_ || objects.size() > static_cast<size_t>(count_ - first))
            return false;

        std::array<uintptr_t, kReadWindowSize> chunks{}, chunkSlots{}, rawObjects{};
        std::array<size_t, kReadWindowSize> chunkForObject{}, owners{};
        std::array<memory::ReadRequest, kReadWindowSize> requests{};
        std::array<memory::ReadResult, kReadWindowSize> reads{};
        size_t chunkCount = 0;
        int32_t previousChunk = -1;
        if (layout_.kind == ObjectContainerKind::Chunked)
        {
            for (size_t index = 0; index < objects.size(); ++index)
            {
                const int32_t chunkIndex = (first + static_cast<int32_t>(index)) / layout_.elementsPerChunk;
                if (chunkIndex != previousChunk)
                {
                    const auto slot = AddScaled(storage_, chunkIndex, static_cast<int32_t>(sizeof(uintptr_t)));
                    if (!slot)
                        throw std::overflow_error("Object chunk table address overflow");
                    chunkSlots[chunkCount] = *slot;
                    requests[chunkCount] = {*slot, &chunks[chunkCount], sizeof(uintptr_t)};
                    previousChunk = chunkIndex;
                    ++chunkCount;
                }
                chunkForObject[index] = chunkCount - 1;
            }
            if (!memory_.ReadBatch({requests.data(), chunkCount}, {reads.data(), chunkCount}, fresh))
                throw std::runtime_error("Object chunk batch contract failed");
            for (size_t index = 0; index < chunkCount; ++index)
                if (reads[index].Ok())
                    chunks[index] = decode_.objectChunk(chunks[index], chunkSlots[index]);
        }

        size_t count = 0;
        for (size_t index = 0; index < objects.size(); ++index)
        {
            const int32_t objectIndex = first + static_cast<int32_t>(index);
            uintptr_t base = storage_;
            int32_t within = objectIndex;
            if (layout_.kind == ObjectContainerKind::Chunked)
            {
                const size_t chunk = chunkForObject[index];
                if (!reads[chunk].Ok())
                {
                    objects[index] = {ObjectReadStatus::UnreadableChunk, 0, chunkSlots[chunk], reads[chunk].error};
                    continue;
                }
                base = chunks[chunk];
                if (!base || !memory_.IsReadable(base, sizeof(uintptr_t)))
                {
                    objects[index] = {ObjectReadStatus::InvalidChunk, base, chunkSlots[chunk]};
                    continue;
                }
                within %= layout_.elementsPerChunk;
            }
            const auto item = AddScaled(base, within, layout_.itemStride);
            const auto slot = item ? AddOffset(*item, static_cast<uintptr_t>(layout_.itemObjectOffset)) : std::nullopt;
            if (!slot)
            {
                objects[index] = {ObjectReadStatus::AddressOverflow};
                continue;
            }
            requests[count] = {*slot, &rawObjects[index], sizeof(uintptr_t)};
            owners[count++] = index;
        }
        if (!memory_.ReadBatch({requests.data(), count}, {reads.data(), count}, fresh))
            throw std::runtime_error("Object pointer batch contract failed");
        for (size_t index = 0; index < count; ++index)
        {
            const size_t owner = owners[index];
            objects[owner] = reads[index].Ok() ? DecodeObject(rawObjects[owner], requests[index].address)
                                               : ObjectReadResult{ObjectReadStatus::UnreadableObject, 0, requests[index].address, reads[index].error};
        }
        return true;
    }

    std::optional<uint32_t> ObjectStoreReader::ReadInternalFlags(const ObjectReadResult &object) const
    {
        // 已支持的 FUObjectItem 结构族中，Flags 紧接 Object/ObjectPtrLow。
        const size_t pointerSize = layout_.packedPointers ? sizeof(uint32_t) : sizeof(uintptr_t);
        if (!object.IsValid() || layout_.itemObjectOffset != 0 ||
            static_cast<size_t>(layout_.itemStride) < pointerSize + sizeof(uint32_t))
            return std::nullopt;
        const auto address = AddOffset(object.readAddress, pointerSize);
        uint32_t flags = 0;
        if (!address || !memory_.ReadFreshBytes(*address, &flags, sizeof(flags)).Ok())
            return std::nullopt;
        return flags;
    }

    std::optional<int32_t> ObjectStoreReader::ReadSerialNumber(const ObjectReadResult &object) const
    {
        // 4.23-5.6 的公共前缀为 Object、Flags、ClusterRootIndex、SerialNumber
        // packing 只改变 Object 的存储宽度，尾部可选字段不影响此前缀
        const size_t offset = (layout_.packedPointers ? sizeof(uint32_t) : sizeof(uintptr_t)) + 8;
        if (!object.IsValid() || layout_.itemObjectOffset != 0 ||
            static_cast<size_t>(layout_.itemStride) < offset + sizeof(int32_t))
            return std::nullopt;
        const auto address = AddOffset(object.readAddress, offset);
        int32_t serial = 0;
        if (!address || !memory_.Read(*address, serial))
            return std::nullopt;
        return serial;
    }
} // namespace nextdumper::ue
