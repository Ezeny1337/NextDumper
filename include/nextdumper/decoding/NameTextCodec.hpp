#pragma once

#include <cstddef>
#include <cstdint>

namespace nextdumper::decoding
{
    enum class NameTextFamily : std::uint8_t
    {
        Identity,
        ByteXor,
        LengthSchedule,
    };

    [[nodiscard]] inline const char *NameTextFamilyName(NameTextFamily family)
    {
        switch (family)
        {
        case NameTextFamily::Identity:
            return "identity";
        case NameTextFamily::ByteXor:
            return "byte-xor";
        case NameTextFamily::LengthSchedule:
            return "length-schedule";
        }
        return "unknown";
    }

    struct NameTextCodec
    {
        NameTextFamily Family = NameTextFamily::Identity;
        std::uint8_t Key = 0;

        [[nodiscard]] constexpr bool IsValid() const
        {
            switch (Family)
            {
            case NameTextFamily::Identity:
            case NameTextFamily::LengthSchedule:
                return Key == 0;
            case NameTextFamily::ByteXor:
                return true;
            }
            return false;
        }

        [[nodiscard]] constexpr bool RequiresLength() const { return Family == NameTextFamily::LengthSchedule; }

        [[nodiscard]] bool Apply(std::uint8_t *bytes, std::size_t byteCount, std::size_t length, bool wide) const
        {
            const std::size_t width = wide ? 2 : 1;
            if (!IsValid() || !bytes || length == 0 || length > 1024 || length > byteCount / width ||
                length * width != byteCount)
                return false;

            if (Family == NameTextFamily::Identity)
                return true;
            if (Family == NameTextFamily::ByteXor)
            {
                for (std::size_t index = 0; index < byteCount; ++index)
                    bytes[index] ^= Key;
                return true;
            }

            const std::uint32_t key = LengthKey(static_cast<std::uint32_t>(length));
            if (!wide)
            {
                for (std::size_t index = 0; index < byteCount; ++index)
                    bytes[index] = static_cast<std::uint8_t>(~bytes[index]) ^ static_cast<std::uint8_t>(key & 0x80u);
                return true;
            }

            // NamePool 以目标小端序存储 UTF-16 代码单元
            const std::uint16_t wideKey = static_cast<std::uint16_t>((key | 0x7Fu) + 0x80u);
            for (std::size_t index = 0; index < byteCount; index += 2)
            {
                bytes[index] ^= static_cast<std::uint8_t>(wideKey);
                bytes[index + 1] ^= static_cast<std::uint8_t>(wideKey >> 8);
            }
            return true;
        }

    private:
        [[nodiscard]] static std::uint32_t LengthKey(std::uint32_t length)
        {
            switch (length % 9u)
            {
            case 0u:
                return (length & 0x1Fu) + length;
            case 1u:
                return (length ^ 0xDFu) + length;
            case 2u:
                return (length | 0xCFu) + length;
            case 3u:
                return 33u * length;
            case 4u:
                return length + (length >> 2);
            case 5u:
                return 3u * length + 5u;
            case 6u:
                return ((4u * length) | 5u) + length;
            case 7u:
                return ((length >> 4) | 7u) + length;
            default:
                return (length ^ 0xCu) + length;
            }
        }
    };
} // namespace nextdumper::decoding
