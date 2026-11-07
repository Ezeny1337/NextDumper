#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <utility>
#include <variant>

#include "nextdumper/decoding/NameTextCodec.hpp"

namespace nextdumper::binding
{
    template <typename T>
    class ValueDecoder
    {
    public:
        using Callback = std::function<T(T value, uintptr_t fieldAddress)>;

        [[nodiscard]] static ValueDecoder Custom(Callback callback)
        {
            ValueDecoder result;
            result.callback_ = std::move(callback);
            return result;
        }

        [[nodiscard]] bool IsCustom() const { return callback_.has_value(); }
        [[nodiscard]] bool IsIdentity() const { return !IsCustom(); }
        [[nodiscard]] bool IsValid() const { return !callback_ || static_cast<bool>(*callback_); }

        [[nodiscard]] T operator()(T value, uintptr_t fieldAddress) const
        {
            return callback_ ? (*callback_)(value, fieldAddress) : value;
        }

    private:
        std::optional<Callback> callback_;
    };

    class NameTextDecoder
    {
    public:
        using Callback = std::function<bool(std::span<uint8_t> bytes, uintptr_t address, bool wide)>;

        [[nodiscard]] static NameTextDecoder Builtin(decoding::NameTextCodec codec)
        {
            NameTextDecoder result;
            result.decoder_ = codec;
            return result;
        }

        [[nodiscard]] static NameTextDecoder Custom(Callback callback)
        {
            NameTextDecoder result;
            result.decoder_ = std::move(callback);
            return result;
        }

        [[nodiscard]] const decoding::NameTextCodec *BuiltinCodec() const
        {
            return std::get_if<decoding::NameTextCodec>(&decoder_);
        }

        [[nodiscard]] bool IsCustom() const { return !BuiltinCodec(); }
        [[nodiscard]] bool IsIdentity() const
        {
            const auto *codec = BuiltinCodec();
            return codec && codec->IsValid() && codec->Family == decoding::NameTextFamily::Identity;
        }

        [[nodiscard]] bool IsValid() const
        {
            const auto *codec = BuiltinCodec();
            return codec ? codec->IsValid() : static_cast<bool>(std::get<Callback>(decoder_));
        }

        [[nodiscard]] bool RequiresLength() const
        {
            const auto *codec = BuiltinCodec();
            return codec && codec->RequiresLength();
        }

        [[nodiscard]] bool operator()(std::span<uint8_t> bytes, uintptr_t address, bool wide) const
        {
            if (const auto *codec = BuiltinCodec())
                return codec->Apply(bytes.data(), bytes.size(), bytes.size() / (wide ? 2 : 1), wide);
            return std::get<Callback>(decoder_)(bytes, address, wide);
        }

    private:
        std::variant<decoding::NameTextCodec, Callback> decoder_;
    };

    struct DecodePlan
    {
        using PointerDecoder = ValueDecoder<uintptr_t>;
        using Int32Decoder = ValueDecoder<int32_t>;
        using UInt32Decoder = ValueDecoder<uint32_t>;
        using UInt16Decoder = ValueDecoder<uint16_t>;

        PointerDecoder objectStorage;
        PointerDecoder objectChunk;
        PointerDecoder objectPointer;
        PointerDecoder objectClass;
        PointerDecoder objectOuter;
        PointerDecoder nameBlocks;
        PointerDecoder nameChunks;
        PointerDecoder nameEntry;
        Int32Decoder objectCount;
        Int32Decoder objectFlags;
        Int32Decoder objectIndex;
        Int32Decoder nameIndex;
        UInt32Decoder nameNumber;
        UInt32Decoder nameEntryIndex;
        UInt16Decoder nameHeader;
        NameTextDecoder nameText;

        [[nodiscard]] static DecodePlan Identity() { return {}; }
        [[nodiscard]] bool IsValid() const;
        [[nodiscard]] bool IsIdentity() const;
    };
} // namespace nextdumper::binding
