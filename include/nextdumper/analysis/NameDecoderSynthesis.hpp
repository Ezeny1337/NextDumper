#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

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

    struct KnownName
    {
        std::vector<uint8_t> Cipher;
        std::string Plain;
        size_t Length = 0;
        bool Wide = false;
    };

    struct NameDecoderSynthesisResult
    {
        std::optional<NameTextDecoder> Decoder;
        size_t Pairs = 0;
        std::string Detail;

        [[nodiscard]] bool IsValid() const { return Decoder.has_value(); }
    };

    [[nodiscard]] NameDecoderSynthesisResult SynthesizeNameDecoder(const std::vector<KnownName> &known);
    [[nodiscard]] const char *NameTextFamilyName(NameTextFamily family);
} // namespace nextdumper::analysis
