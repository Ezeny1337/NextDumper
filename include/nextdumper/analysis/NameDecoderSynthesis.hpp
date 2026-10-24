#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace nextdumper::analysis
{
    enum class NameTextFamily : uint8_t
    {
        Identity,
        ByteXor,
        LengthSchedule,
    };

    struct NameTextDecoder
    {
        NameTextFamily Family = NameTextFamily::Identity;
        uint8_t Key = 0;

        [[nodiscard]] bool Apply(std::span<uint8_t> bytes, size_t length, bool wide) const;
    };

    [[nodiscard]] const char *NameTextFamilyName(NameTextFamily family);
} // namespace nextdumper::analysis
