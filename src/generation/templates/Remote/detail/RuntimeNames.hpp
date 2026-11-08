#pragma once

#include "../Runtime.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace NextDumper
{

    [[nodiscard]] inline ReadStatus RemoteRuntime::LocateNameEntry(std::int32_t index, TargetAddress &entry,
                                                                   std::size_t &available)
    {
        entry = 0;
        available = 0;
        if (index < 0)
            return ReadStatus::InvalidIndex;
        if (binding_.names.kind == NameStoreKind::Array)
        {
            const auto &layout = binding_.names;
            if (layout.elementsPerChunk <= 0)
                return ReadStatus::InvalidHeader;
            if (layout.numElementsOffset >= 0)
            {
                TargetAddress countAddress = 0;
                std::int32_t count = 0;
                if (!Add(nameRoot_, static_cast<std::uint32_t>(layout.numElementsOffset), countAddress))
                    return ReadStatus::AddressOverflow;
                const ReadResult read = ReadExact(countAddress, &count, sizeof(count));
                if (!read.Ok())
                    return read.status;
                if (count < 0 || static_cast<std::size_t>(count) > options_.maxNameEntries || index >= count)
                    return ReadStatus::InvalidHeader;
            }
            const std::int32_t chunkIndex = index / layout.elementsPerChunk;
            const std::int32_t within = index % layout.elementsPerChunk;
            if (chunkIndex >= 128)
                return ReadStatus::LimitExceeded;
            TargetAddress chunksAddress = 0, chunkSlot = 0, chunk = 0, entrySlot = 0;
            if (!Add(nameRoot_, static_cast<std::uint32_t>(layout.chunksOffset), chunksAddress) ||
                !AddScaled(chunksAddress, chunkIndex, binding_.pointerWidth, chunkSlot))
                return ReadStatus::AddressOverflow;
            ReadStatus status = ReadPointer(chunkSlot, chunk);
            if (status != ReadStatus::Ok)
                return status;
            if (!chunk)
                return ReadStatus::InvalidReference;
            if (!AddScaled(chunk, within, binding_.pointerWidth, entrySlot))
                return ReadStatus::AddressOverflow;
            status = ReadPointer(entrySlot, entry);
            if (status != ReadStatus::Ok)
                return status;
            if (!entry)
                return ReadStatus::InvalidReference;
            available = 2048;
            return ReadStatus::Ok;
        }

        const auto &layout = binding_.names;
        const std::int32_t blockIndex = index >> layout.blocksBit;
        const std::int32_t entryIndex = index & ((1 << layout.blocksBit) - 1);
        if (blockIndex < 0 || blockIndex >= 8192)
            return ReadStatus::InvalidIndex;
        const std::size_t blockSize =
            (std::size_t{1} << layout.blocksBit) * static_cast<std::size_t>(layout.entryStride);
        const std::size_t offset = static_cast<std::size_t>(entryIndex) * static_cast<std::size_t>(layout.entryStride);
        std::size_t usedBytes = blockSize;
        TargetAddress blocks = 0;
        if (!Add(nameRoot_, static_cast<std::uint32_t>(layout.blocksOffset), blocks))
            return ReadStatus::AddressOverflow;
        if (layout.hasPublicationBoundary)
        {
            TargetAddress currentAddress = 0, cursorAddress = 0;
            std::uint32_t current = 0, cursor = 0;
            if (!AddSigned(blocks, layout.currentBlockFromBlocks, currentAddress) ||
                !AddSigned(blocks, layout.byteCursorFromBlocks, cursorAddress))
                return ReadStatus::AddressOverflow;
            ReadResult read = ReadExact(currentAddress, &current, sizeof(current));
            if (!read.Ok())
                return read.status;
            read = ReadExact(cursorAddress, &cursor, sizeof(cursor));
            if (!read.Ok())
                return read.status;
            if (current >= 8192 || cursor > blockSize ||
                cursor % static_cast<std::uint32_t>(layout.entryStride) != 0 ||
                static_cast<std::uint32_t>(blockIndex) > current)
                return ReadStatus::InvalidHeader;
            if (static_cast<std::uint32_t>(blockIndex) == current)
                usedBytes = cursor;
        }
        if (offset >= usedBytes || usedBytes - offset < static_cast<std::size_t>(layout.poolStringOffset))
            return ReadStatus::InvalidHeader;
        TargetAddress blockSlot = 0, block = 0;
        if (!AddScaled(blocks, blockIndex, binding_.pointerWidth, blockSlot))
            return ReadStatus::AddressOverflow;
        const ReadStatus status = ReadPointer(blockSlot, block);
        if (status != ReadStatus::Ok)
            return status;
        if (!block)
            return ReadStatus::InvalidReference;
        if (!AddScaled(block, entryIndex, layout.entryStride, entry))
            return ReadStatus::AddressOverflow;
        available = usedBytes - offset;
        return ReadStatus::Ok;
    }

    [[nodiscard]] inline bool RemoteRuntime::AddSigned(TargetAddress base, std::int32_t offset, TargetAddress &out)
    {
        if (!base)
            return false;
        if (offset < 0)
        {
            const std::uint64_t magnitude = static_cast<std::uint64_t>(-static_cast<std::int64_t>(offset));
            if (magnitude > base)
                return false;
            out = static_cast<TargetAddress>(base - magnitude);
            return true;
        }
        return Add(base, static_cast<std::uint32_t>(offset), out);
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadNameEntry(std::int32_t index, std::string &name,
                                                                 std::size_t depth)
    {
        if (depth >= 32)
            return ReadStatus::LimitExceeded;
        if (const auto cached = nameCache_.find(index); cached != nameCache_.end())
        {
            name = cached->second;
            return ReadStatus::Ok;
        }
        TargetAddress entry = 0;
        std::size_t available = 0;
        ReadStatus status = LocateNameEntry(index, entry, available);
        if (status != ReadStatus::Ok)
            return status;
        if (binding_.names.kind == NameStoreKind::Array)
        {
            TargetAddress indexAddress = 0, stringAddress = 0;
            std::uint32_t rawIndex = 0;
            if (!Add(entry, static_cast<std::uint32_t>(binding_.names.entryIndexOffset), indexAddress) ||
                !Add(entry, static_cast<std::uint32_t>(binding_.names.entryStringOffset), stringAddress))
                return ReadStatus::AddressOverflow;
            const ReadResult read = ReadExact(indexAddress, &rawIndex, sizeof(rawIndex));
            if (!read.Ok())
                return read.status;
            const bool wide = (rawIndex & 1u) != 0;
            const std::size_t chars = std::min<std::size_t>(1024, available / (wide ? 2 : 1));
            if (chars == 0)
                return ReadStatus::InvalidHeader;
            status = ReadNameText(stringAddress, chars, wide, name);
            if (status != ReadStatus::Ok)
                return status;
        }
        else
        {
            const auto &layout = binding_.names;
            TargetAddress headerAddress = 0, stringAddress = 0;
            std::uint16_t header = 0;
            if (!Add(entry, static_cast<std::uint32_t>(layout.entryHeaderOffset), headerAddress) ||
                !Add(entry, static_cast<std::uint32_t>(layout.poolStringOffset), stringAddress))
                return ReadStatus::AddressOverflow;
            const ReadResult read = ReadExact(headerAddress, &header, sizeof(header));
            if (!read.Ok())
                return read.status;
            const std::size_t length = header >> layout.entryLengthShift;
            if (length > 1024)
                return ReadStatus::InvalidHeader;
            if (length == 0)
            {
                const std::int32_t indexOffset = layout.poolStringOffset + (layout.poolStringOffset == 6 ? 2 : 0);
                TargetAddress baseIndexAddress = 0, numberAddress = 0;
                std::int32_t baseIndex = -1;
                std::uint32_t number = 0;
                if (static_cast<std::size_t>(indexOffset) + 8 > available)
                    return ReadStatus::InvalidHeader;
                if (!Add(entry, static_cast<std::uint32_t>(indexOffset), baseIndexAddress) ||
                    !Add(baseIndexAddress, sizeof(baseIndex), numberAddress))
                    return ReadStatus::AddressOverflow;
                ReadResult numberedRead = ReadExact(baseIndexAddress, &baseIndex, sizeof(baseIndex));
                if (!numberedRead.Ok())
                    return numberedRead.status;
                numberedRead = ReadExact(numberAddress, &number, sizeof(number));
                if (!numberedRead.Ok())
                    return numberedRead.status;
                status = ReadNameEntry(baseIndex, name, depth + 1);
                if (status != ReadStatus::Ok)
                    return status;
                if (number > 0)
                    name += "_" + std::to_string(number - 1);
            }
            else
            {
                const bool wide = (header & layout.entryWideMask) != 0;
                const std::size_t bytes = length * (wide ? 2 : 1);
                if (layout.poolStringOffset < 0 || static_cast<std::size_t>(layout.poolStringOffset) > available ||
                    bytes > available - static_cast<std::size_t>(layout.poolStringOffset))
                    return ReadStatus::InvalidHeader;
                status = ReadNameText(stringAddress, length, wide, name);
                if (status != ReadStatus::Ok)
                    return status;
            }
        }
        if (nameCache_.size() < 65536)
            nameCache_.emplace(index, name);
        return ReadStatus::Ok;
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadNameText(TargetAddress address, std::size_t chars, bool wide,
                                                                std::string &result) const
    {
        if (chars == 0 || chars > 1024)
            return ReadStatus::InvalidHeader;
        if (!wide)
        {
            std::vector<std::uint8_t> bytes(chars);
            const ReadResult read = ReadExact(address, bytes.data(), bytes.size());
            if (!read.Ok())
                return read.status;
            if (!binding_.decoding.nameText.Apply(bytes.data(), bytes.size(), chars, false))
                return ReadStatus::Unsupported;
            const auto end = std::find(bytes.begin(), bytes.end(), std::uint8_t{0});
            result.assign(bytes.begin(), end);
            return ReadStatus::Ok;
        }
        std::vector<char16_t> text(chars);
        const ReadResult read = ReadExact(address, text.data(), text.size() * sizeof(char16_t));
        if (!read.Ok())
            return read.status;
        if (!binding_.decoding.nameText.Apply(reinterpret_cast<std::uint8_t *>(text.data()),
                                              text.size() * sizeof(char16_t), chars, true))
            return ReadStatus::Unsupported;
        result.clear();
        for (std::size_t index = 0; index < text.size() && text[index] != 0; ++index)
        {
            std::uint32_t codePoint = text[index];
            if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
            {
                if (index + 1 >= text.size() || text[index + 1] < 0xDC00 || text[index + 1] > 0xDFFF)
                    return ReadStatus::InvalidHeader;
                codePoint =
                    0x10000 + ((codePoint - 0xD800) << 10) + (static_cast<std::uint32_t>(text[++index]) - 0xDC00);
            }
            else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF)
                return ReadStatus::InvalidHeader;
            AppendUtf8(result, codePoint);
        }
        return ReadStatus::Ok;
    }

    inline void RemoteRuntime::AppendUtf8(std::string &output, std::uint32_t codePoint)
    {
        if (codePoint <= 0x7F)
            output.push_back(static_cast<char>(codePoint));
        else if (codePoint <= 0x7FF)
        {
            output.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else if (codePoint <= 0xFFFF)
        {
            output.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
        else if (codePoint <= 0x10FFFF)
        {
            output.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        }
    }

    [[nodiscard]] inline ReadStatus RemoteRuntime::ReadFName(TargetAddress address, std::string &result)
    {
        TargetAddress comparisonAddress = 0;
        std::int32_t comparisonIndex = -1;
        if (!Add(address, static_cast<std::uint32_t>(binding_.fname.comparisonIndex), comparisonAddress))
            return ReadStatus::AddressOverflow;
        ReadResult read = ReadExact(comparisonAddress, &comparisonIndex, sizeof(comparisonIndex));
        if (!read.Ok())
            return read.status;
        ReadStatus status = ReadNameEntry(comparisonIndex, result);
        if (status != ReadStatus::Ok)
            return status;
        if (binding_.casePreservingName && binding_.fname.displayIndex >= 0)
        {
            TargetAddress displayAddress = 0;
            std::int32_t displayIndex = -1;
            std::string display;
            if (!Add(address, static_cast<std::uint32_t>(binding_.fname.displayIndex), displayAddress))
                return ReadStatus::AddressOverflow;
            read = ReadExact(displayAddress, &displayIndex, sizeof(displayIndex));
            if (!read.Ok())
                return read.status;
            status = ReadNameEntry(displayIndex, display);
            if (status != ReadStatus::Ok)
                return status;
            result = std::move(display);
        }
        if (binding_.fname.numberInline && binding_.fname.number >= 0)
        {
            TargetAddress numberAddress = 0;
            std::uint32_t number = 0;
            if (!Add(address, static_cast<std::uint32_t>(binding_.fname.number), numberAddress))
                return ReadStatus::AddressOverflow;
            read = ReadExact(numberAddress, &number, sizeof(number));
            if (!read.Ok())
                return read.status;
            if (number > 0)
                result += "_" + std::to_string(number - 1);
        }
        return ReadStatus::Ok;
    }

} // namespace NextDumper
