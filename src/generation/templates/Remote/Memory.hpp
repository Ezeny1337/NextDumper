#pragma once

#include "../BasicTypes.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace NextDumper
{
    enum class ReadStatus : std::uint8_t
    {
        Ok,
        Empty,
        Incomplete,
        InvalidArgument,
        NotInitialized,
        Unsupported,
        ReadFailure,
        PartialRead,
        InvalidHeader,
        InvalidReference,
        InvalidIndex,
        AddressOverflow,
        LimitExceeded,
        NotFound,
        Ambiguous,
        StaleObject,
    };

    struct ReadResult
    {
        ReadStatus status = ReadStatus::Ok;
        std::size_t requested = 0;
        std::size_t transferred = 0;

        [[nodiscard]] bool Ok() const { return status == ReadStatus::Ok; }
    };

    using ReadMemoryCallback = std::int64_t (*)(void *, TargetAddress, void *, std::size_t);

    struct MemoryReader
    {
        void *context = nullptr;
        ReadMemoryCallback read = nullptr;
        std::size_t maxTransferBytes = std::numeric_limits<std::size_t>::max();

        [[nodiscard]] ReadResult Read(TargetAddress address, void *buffer, std::size_t size) const
        {
            ReadResult result{ReadStatus::Ok, size, 0};
            if ((!buffer && size != 0) || (size != 0 && address == 0) ||
                (size != 0 && size - 1 > std::numeric_limits<TargetAddress>::max() - address) || !read ||
                maxTransferBytes == 0)
            {
                result.status = ReadStatus::InvalidArgument;
                return result;
            }
            auto *output = static_cast<std::uint8_t *>(buffer);
            while (result.transferred < size)
            {
                const std::size_t requested = std::min(maxTransferBytes, size - result.transferred);
                const TargetAddress current = static_cast<TargetAddress>(address + result.transferred);
                const std::int64_t transferred = read(context, current, output + result.transferred, requested);
                if (transferred <= 0)
                {
                    result.status = result.transferred == 0 ? ReadStatus::ReadFailure : ReadStatus::PartialRead;
                    return result;
                }
                if (static_cast<std::uint64_t>(transferred) > requested)
                {
                    result.status = ReadStatus::ReadFailure;
                    return result;
                }
                result.transferred += static_cast<std::size_t>(transferred);
            }
            return result;
        }
    };
} // namespace NextDumper
