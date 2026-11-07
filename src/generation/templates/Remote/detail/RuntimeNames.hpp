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

    [[nodiscard]] inline bool RemoteRuntime::LocateNameEntry(std::int32_t index, TargetAddress &entry,
                                                             std::size_t &available)
    {
        entry = 0;
        available = 0;
        if (index < 0)
            return false;
        if (binding_.names.kind == NameStoreKind::Array)
        {
            const auto &layout = binding_.names;
            if (layout.elementsPerChunk <= 0)
                return false;
            if (layout.numElementsOffset >= 0)
            {
                TargetAddress countAddress = 0;
                std::int32_t count = 0;
                if (!Add(nameRoot_, static_cast<std::uint32_t>(layout.numElementsOffset), countAddress) ||
                    !ReadExact(countAddress, &count, sizeof(count)).Ok() || count < 0 ||
                    static_cast<std::size_t>(count) > options_.maxNameEntries || index >= count)
                    return false;
            }
            const std::int32_t chunkIndex = index / layout.elementsPerChunk;
            const std::int32_t within = index % layout.elementsPerChunk;
            if (chunkIndex >= 128)
                return false;
            TargetAddress chunksAddress = 0, chunkSlot = 0, chunk = 0, entrySlot = 0;
            if (!Add(nameRoot_, static_cast<std::uint32_t>(layout.chunksOffset), chunksAddress) ||
                !AddScaled(chunksAddress, chunkIndex, binding_.pointerWidth, chunkSlot) ||
                ReadPointer(chunkSlot, chunk) != ReadStatus::Ok || !chunk ||
                !AddScaled(chunk, within, binding_.pointerWidth, entrySlot) ||
                ReadPointer(entrySlot, entry) != ReadStatus::Ok || !entry)
                return false;
            available = 2048;
            return true;
        }

        const auto &layout = binding_.names;
        const std::int32_t blockIndex = index >> layout.blocksBit;
        const std::int32_t entryIndex = index & ((1 << layout.blocksBit) - 1);
        if (blockIndex < 0 || blockIndex >= 8192)
            return false;
        const std::size_t blockSize =
            (std::size_t{1} << layout.blocksBit) * static_cast<std::size_t>(layout.entryStride);
        const std::size_t offset = static_cast<std::size_t>(entryIndex) * static_cast<std::size_t>(layout.entryStride);
        std::size_t usedBytes = blockSize;
        TargetAddress blocks = 0;
        if (!Add(nameRoot_, static_cast<std::uint32_t>(layout.blocksOffset), blocks))
            return false;
        if (layout.hasPublicationBoundary)
        {
            TargetAddress currentAddress = 0, cursorAddress = 0;
            std::uint32_t current = 0, cursor = 0;
            if (!AddSigned(blocks, layout.currentBlockFromBlocks, currentAddress) ||
                !AddSigned(blocks, layout.byteCursorFromBlocks, cursorAddress) ||
                !ReadExact(currentAddress, &current, sizeof(current)).Ok() ||
                !ReadExact(cursorAddress, &cursor, sizeof(cursor)).Ok() || current >= 8192 || cursor > blockSize ||
                cursor % static_cast<std::uint32_t>(layout.entryStride) != 0 ||
                static_cast<std::uint32_t>(blockIndex) > current)
                return false;
            if (static_cast<std::uint32_t>(blockIndex) == current)
                usedBytes = cursor;
        }
        if (offset >= usedBytes || usedBytes - offset < static_cast<std::size_t>(layout.poolStringOffset))
            return false;
        TargetAddress blockSlot = 0, block = 0;
        if (!AddScaled(blocks, blockIndex, binding_.pointerWidth, blockSlot) ||
            ReadPointer(blockSlot, block) != ReadStatus::Ok || !block ||
            !AddScaled(block, entryIndex, layout.entryStride, entry))
            return false;
        available = usedBytes - offset;
        return true;
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

    [[nodiscard]] inline bool RemoteRuntime::ReadNameEntry(std::int32_t index, std::string &name, std::size_t depth)
    {
        if (depth >= 32)
            return false;
        if (const auto cached = nameCache_.find(index); cached != nameCache_.end())
        {
            name = cached->second;
            return true;
        }
        TargetAddress entry = 0;
        std::size_t available = 0;
        if (!LocateNameEntry(index, entry, available))
            return false;
        if (binding_.names.kind == NameStoreKind::Array)
        {
            TargetAddress indexAddress = 0, stringAddress = 0;
            std::uint32_t rawIndex = 0;
            if (!Add(entry, static_cast<std::uint32_t>(binding_.names.entryIndexOffset), indexAddress) ||
                !Add(entry, static_cast<std::uint32_t>(binding_.names.entryStringOffset), stringAddress) ||
                !ReadExact(indexAddress, &rawIndex, sizeof(rawIndex)).Ok())
                return false;
            const bool wide = (rawIndex & 1u) != 0;
            const std::size_t chars = std::min<std::size_t>(1024, available / (wide ? 2 : 1));
            if (chars == 0 || !ReadNameText(stringAddress, chars, wide, name))
                return false;
        }
        else
        {
            const auto &layout = binding_.names;
            TargetAddress headerAddress = 0, stringAddress = 0;
            std::uint16_t header = 0;
            if (!Add(entry, static_cast<std::uint32_t>(layout.entryHeaderOffset), headerAddress) ||
                !Add(entry, static_cast<std::uint32_t>(layout.poolStringOffset), stringAddress) ||
                !ReadExact(headerAddress, &header, sizeof(header)).Ok())
                return false;
            const std::size_t length = header >> layout.entryLengthShift;
            if (length > 1024)
                return false;
            if (length == 0)
            {
                const std::int32_t indexOffset = layout.poolStringOffset + (layout.poolStringOffset == 6 ? 2 : 0);
                TargetAddress baseIndexAddress = 0, numberAddress = 0;
                std::int32_t baseIndex = -1;
                std::uint32_t number = 0;
                if (static_cast<std::size_t>(indexOffset) + 8 > available ||
                    !Add(entry, static_cast<std::uint32_t>(indexOffset), baseIndexAddress) ||
                    !Add(baseIndexAddress, sizeof(baseIndex), numberAddress) ||
                    !ReadExact(baseIndexAddress, &baseIndex, sizeof(baseIndex)).Ok() ||
                    !ReadExact(numberAddress, &number, sizeof(number)).Ok() ||
                    !ReadNameEntry(baseIndex, name, depth + 1))
                    return false;
                if (number > 0)
                    name += "_" + std::to_string(number - 1);
            }
            else
            {
                const bool wide = (header & layout.entryWideMask) != 0;
                const std::size_t bytes = length * (wide ? 2 : 1);
                if (layout.poolStringOffset < 0 || static_cast<std::size_t>(layout.poolStringOffset) > available ||
                    bytes > available - static_cast<std::size_t>(layout.poolStringOffset) ||
                    !ReadNameText(stringAddress, length, wide, name))
                    return false;
            }
        }
        if (nameCache_.size() < 65536)
            nameCache_.emplace(index, name);
        return true;
    }

    [[nodiscard]] inline bool RemoteRuntime::ReadNameText(TargetAddress address, std::size_t chars, bool wide,
                                                          std::string &result) const
    {
        if (chars == 0 || chars > 1024)
            return false;
        if (!wide)
        {
            std::vector<std::uint8_t> bytes(chars);
            if (!ReadExact(address, bytes.data(), bytes.size()).Ok() ||
                !binding_.decoding.nameText.Apply(bytes.data(), bytes.size(), chars, false))
                return false;
            const auto end = std::find(bytes.begin(), bytes.end(), std::uint8_t{0});
            result.assign(bytes.begin(), end);
            return true;
        }
        std::vector<char16_t> text(chars);
        if (!ReadExact(address, text.data(), text.size() * sizeof(char16_t)).Ok() ||
            !binding_.decoding.nameText.Apply(reinterpret_cast<std::uint8_t *>(text.data()),
                                              text.size() * sizeof(char16_t), chars, true))
            return false;
        result.clear();
        for (std::size_t index = 0; index < text.size() && text[index] != 0; ++index)
        {
            std::uint32_t codePoint = text[index];
            if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
            {
                if (index + 1 >= text.size() || text[index + 1] < 0xDC00 || text[index + 1] > 0xDFFF)
                    return false;
                codePoint =
                    0x10000 + ((codePoint - 0xD800) << 10) + (static_cast<std::uint32_t>(text[++index]) - 0xDC00);
            }
            else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF)
                return false;
            AppendUtf8(result, codePoint);
        }
        return true;
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

    [[nodiscard]] inline std::optional<std::string> RemoteRuntime::ReadName(std::int32_t index)
    {
        std::string result;
        return ReadNameEntry(index, result) ? std::optional<std::string>(std::move(result)) : std::nullopt;
    }

    [[nodiscard]] inline bool RemoteRuntime::ReadFName(TargetAddress address, std::string &result)
    {
        TargetAddress comparisonAddress = 0;
        std::int32_t comparisonIndex = -1;
        if (!Add(address, static_cast<std::uint32_t>(binding_.fname.comparisonIndex), comparisonAddress) ||
            !ReadExact(comparisonAddress, &comparisonIndex, sizeof(comparisonIndex)).Ok())
            return false;
        if (!ReadNameEntry(comparisonIndex, result))
            return false;
        if (binding_.casePreservingName && binding_.fname.displayIndex >= 0)
        {
            TargetAddress displayAddress = 0;
            std::int32_t displayIndex = -1;
            std::string display;
            if (!Add(address, static_cast<std::uint32_t>(binding_.fname.displayIndex), displayAddress) ||
                !ReadExact(displayAddress, &displayIndex, sizeof(displayIndex)).Ok() ||
                !ReadNameEntry(displayIndex, display))
                return false;
            result = std::move(display);
        }
        if (binding_.fname.numberInline && binding_.fname.number >= 0)
        {
            TargetAddress numberAddress = 0;
            std::uint32_t number = 0;
            if (!Add(address, static_cast<std::uint32_t>(binding_.fname.number), numberAddress) ||
                !ReadExact(numberAddress, &number, sizeof(number)).Ok())
                return false;
            if (number > 0)
                result += "_" + std::to_string(number - 1);
        }
        return true;
    }

} // namespace NextDumper
