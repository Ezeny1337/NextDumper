#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <optional>

#include "nextdumper/ue/EngineSchema.hpp"
#include "nextdumper/memory/MemorySource.hpp"
#include "nextdumper/binding/RuntimeBinding.hpp"

namespace nextdumper::ue
{
    using ::nextdumper::binding::DecodePlan;
    using ::nextdumper::binding::ObjectContainerKind;
    using ::nextdumper::binding::ObjectContainerLayout;
    using ::nextdumper::memory::IMemorySource;
    using ::nextdumper::memory::ReadError;

    enum class ObjectReadStatus
    {
        Valid,
        Empty,
        NotInitialized,
        InvalidIndex,
        AddressOverflow,
        UnreadableChunk,
        InvalidChunk,
        UnreadableObject,
        InvalidObject,
    };

    [[nodiscard]] const char *ObjectReadStatusName(ObjectReadStatus status);

    struct ObjectReadResult
    {
        ObjectReadStatus status = ObjectReadStatus::NotInitialized;
        uintptr_t address = 0;
        uintptr_t readAddress = 0;
        ReadError readError = ReadError::None;

        [[nodiscard]] bool IsValid() const { return status == ObjectReadStatus::Valid; }
    };

    struct ObjectStoreBoundary
    {
        uintptr_t countAddress = 0;
        int32_t count = -1;
        bool valid = false;
        std::string reason;
    };

    class ObjectStoreReader
    {
    public:
        static constexpr size_t kReadWindowSize = 128;

        ObjectStoreReader(const IMemorySource &memory,
                          uintptr_t root,
                          const ObjectContainerLayout &layout,
                          const DecodePlan &decode);

        [[nodiscard]] bool Initialize();
        [[nodiscard]] bool IsInitialized() const { return initialized_; }
        [[nodiscard]] int32_t Count() const { return count_; }
        [[nodiscard]] ObjectReadResult ReadObject(int32_t index, bool fresh = false) const;
        [[nodiscard]] bool ReadObjects(int32_t first, std::span<ObjectReadResult> objects, bool fresh = false) const;
        [[nodiscard]] ObjectStoreBoundary RefreshCount();
        [[nodiscard]] std::optional<uint32_t> ReadInternalFlags(const ObjectReadResult &object) const;
        [[nodiscard]] std::optional<int32_t> ReadSerialNumber(const ObjectReadResult &object) const;

    private:
        [[nodiscard]] ObjectReadResult DecodeObject(uintptr_t raw, uintptr_t slot) const;

        const IMemorySource &memory_;
        uintptr_t root_ = 0;
        ObjectContainerLayout layout_;
        const DecodePlan &decode_;
        uintptr_t storage_ = 0;
        int32_t count_ = 0;
        bool initialized_ = false;
    };
} // namespace nextdumper::ue
