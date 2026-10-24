#include "nextdumper/analysis/NameDecoderSynthesis.hpp"

#include <algorithm>
#include <cstring>

namespace nextdumper::analysis
{
    namespace
    {
        constexpr size_t kMaxNameLength = 1024;
        constexpr size_t kMinimumKnownPairs = 8;

        uint32_t LengthKey(size_t length)
        {
            const uint32_t len = static_cast<uint32_t>(length);
            switch (len % 9u)
            {
            case 0u:
                return (len & 0x1Fu) + len;
            case 1u:
                return (len ^ 0xDFu) + len;
            case 2u:
                return (len | 0xCFu) + len;
            case 3u:
                return 33u * len;
            case 4u:
                return len + (len >> 2);
            case 5u:
                return 3u * len + 5u;
            case 6u:
                return ((4u * len) | 5u) + len;
            case 7u:
                return ((len >> 4) | 7u) + len;
            default:
                return (len ^ 0xCu) + len;
            }
        }

        bool MatchPlain(const KnownName &known, const NameTextDecoder &decoder)
        {
            if (known.Wide || known.Length != known.Plain.size() || known.Cipher.size() != known.Length)
                return false;
            std::vector<uint8_t> text = known.Cipher;
            if (!decoder.Apply(text, known.Length, false))
                return false;
            return text.size() == known.Plain.size() &&
                   std::memcmp(text.data(), known.Plain.data(), text.size()) == 0;
        }

        bool MatchesAll(const std::vector<KnownName> &known, const NameTextDecoder &decoder)
        {
            size_t compared = 0;
            for (const KnownName &entry : known)
            {
                if (entry.Wide)
                    continue;
                if (!MatchPlain(entry, decoder))
                    return false;
                ++compared;
            }
            return compared >= kMinimumKnownPairs;
        }
    } // namespace

    const char *NameTextFamilyName(NameTextFamily family)
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

    bool NameTextDecoder::Apply(std::span<uint8_t> bytes, size_t length, bool wide) const
    {
        if (length == 0 || length > kMaxNameLength)
            return false;
        const size_t width = wide ? sizeof(uint16_t) : sizeof(uint8_t);
        if (length > bytes.size() / width || length * width != bytes.size())
            return false;

        switch (Family)
        {
        case NameTextFamily::Identity:
            return true;
        case NameTextFamily::ByteXor:
            std::transform(bytes.begin(), bytes.end(), bytes.begin(),
                           [key = Key](uint8_t value)
                           { return static_cast<uint8_t>(value ^ key); });
            return true;
        case NameTextFamily::LengthSchedule:
            if (!wide)
            {
                // 该族的窄字符路径只使用长度键的最高位
                const uint8_t key = static_cast<uint8_t>(LengthKey(length) & 0x80u);
                std::transform(bytes.begin(), bytes.end(), bytes.begin(),
                               [key](uint8_t value)
                               { return static_cast<uint8_t>(static_cast<uint8_t>(~value) ^ key); });
                return true;
            }
            {
                const uint16_t key = static_cast<uint16_t>((LengthKey(length) | 0x7Fu) + 0x80u);
                for (size_t index = 0; index < length; ++index)
                {
                    uint16_t value = 0;
                    std::memcpy(&value, bytes.data() + index * sizeof(uint16_t), sizeof(value));
                    value ^= key;
                    std::memcpy(bytes.data() + index * sizeof(uint16_t), &value, sizeof(value));
                }
                return true;
            }
        }
        return false;
    }

    NameDecoderSynthesisResult SynthesizeNameDecoder(const std::vector<KnownName> &known)
    {
        NameDecoderSynthesisResult result;
        const size_t pairs = static_cast<size_t>(std::count_if(known.begin(), known.end(),
                                                               [](const KnownName &entry)
                                                               { return !entry.Wide; }));
        result.Pairs = pairs;
        if (pairs < kMinimumKnownPairs)
        {
            result.Detail = "insufficient-known-pairs";
            return result;
        }

        NameTextDecoder identity;
        if (MatchesAll(known, identity))
        {
            result.Decoder = identity;
            result.Detail = "family=identity";
            return result;
        }

        for (uint32_t key = 1; key <= 0xFFu; ++key)
        {
            NameTextDecoder decoder{NameTextFamily::ByteXor, static_cast<uint8_t>(key)};
            if (MatchesAll(known, decoder))
            {
                result.Decoder = decoder;
                result.Detail = "family=byte-xor key=" + std::to_string(key);
                return result;
            }
        }

        NameTextDecoder schedule{NameTextFamily::LengthSchedule, 0};
        if (MatchesAll(known, schedule))
        {
            result.Decoder = schedule;
            result.Detail = "family=length-schedule";
            return result;
        }

        result.Detail = "no-consistent-family";
        return result;
    }
} // namespace nextdumper::analysis
