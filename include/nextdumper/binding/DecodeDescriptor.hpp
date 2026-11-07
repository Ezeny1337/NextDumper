#pragma once

#include <cstddef>
#include <cstdint>

#include "NameTextCodec.hpp"

namespace nextdumper::decoding
{
    enum class DecodeSlot : std::uint8_t
    {
        ObjectStorage,
        ObjectChunk,
        ObjectPointer,
        ObjectClass,
        ObjectOuter,
        NameBlocks,
        NameChunks,
        NameEntry,
        ObjectCount,
        ObjectFlags,
        ObjectIndex,
        NameIndex,
        NameNumber,
        NameEntryIndex,
        NameHeader,
        NameText,
        Count,
    };

    static_assert(static_cast<std::uint8_t>(DecodeSlot::Count) < 32);

    [[nodiscard]] inline constexpr std::uint32_t DecodeSlotBit(DecodeSlot slot)
    {
        const auto index = static_cast<std::uint8_t>(slot);
        return index < static_cast<std::uint8_t>(DecodeSlot::Count) ? std::uint32_t{1} << index : 0;
    }

    [[nodiscard]] inline const char *DecodeSlotName(DecodeSlot slot)
    {
        constexpr const char *names[]{
            "objectStorage",
            "objectChunk",
            "objectPointer",
            "objectClass",
            "objectOuter",
            "nameBlocks",
            "nameChunks",
            "nameEntry",
            "objectCount",
            "objectFlags",
            "objectIndex",
            "nameIndex",
            "nameNumber",
            "nameEntryIndex",
            "nameHeader",
            "nameText",
        };
        static_assert(sizeof(names) / sizeof(*names) == static_cast<std::size_t>(DecodeSlot::Count));
        const auto index = static_cast<std::uint8_t>(slot);
        return index < static_cast<std::uint8_t>(DecodeSlot::Count) ? names[index] : "unknown";
    }

    struct DecodeDescriptor
    {
        NameTextCodec nameText;
        std::uint32_t customSlots = 0;

        [[nodiscard]] constexpr bool IsValid() const
        {
            constexpr std::uint32_t knownSlots = (std::uint32_t{1} << static_cast<std::uint8_t>(DecodeSlot::Count)) - 1;
            return (customSlots & ~knownSlots) == 0 && nameText.IsValid() &&
                   ((customSlots & DecodeSlotBit(DecodeSlot::NameText)) == 0 ||
                    nameText.Family == NameTextFamily::Identity);
        }

        [[nodiscard]] constexpr std::uint32_t RequiredCustomSlots(bool namePool, bool chunkedObjects) const
        {
            std::uint32_t unused =
                namePool ? DecodeSlotBit(DecodeSlot::NameChunks) | DecodeSlotBit(DecodeSlot::NameEntryIndex)
                         : DecodeSlotBit(DecodeSlot::NameBlocks) | DecodeSlotBit(DecodeSlot::NameHeader);
            if (!chunkedObjects)
                unused |= DecodeSlotBit(DecodeSlot::ObjectChunk);
            return customSlots & ~unused;
        }

        [[nodiscard]] constexpr bool IsSupported(bool namePool, bool chunkedObjects) const
        {
            return IsValid() && RequiredCustomSlots(namePool, chunkedObjects) == 0 &&
                   (namePool || !nameText.RequiresLength());
        }
    };
} // namespace nextdumper::decoding
