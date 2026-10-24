#include "nextdumper/analysis/FunctionIndex.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace nextdumper::analysis
{
    namespace
    {
        constexpr uint32_t kPtLoad = 1;
        constexpr uint32_t kPtGnuEhFrame = 0x6474e550;
        constexpr uint8_t kVersion = 1;
        constexpr uint8_t kFdeCountUdata4 = 0x03;
        constexpr uint8_t kTableSdata4Datarel = 0x3B;
        constexpr uint8_t kEhFramePtrSdata4Datarel = 0x1B;
        constexpr size_t kHeaderBytes = 12;
        constexpr size_t kEntryBytes = 8;
        constexpr size_t kMaxProgramHeaders = 1024;
        constexpr uint64_t kMaxProgramHeaderOffset = 1024 * 1024;
        constexpr uint32_t kMaxCieBytes = 256;
        constexpr uint32_t kMaxFdeBytes = 4096;

        uint16_t ReadU16(const uint8_t *data)
        {
            uint16_t value = 0;
            std::memcpy(&value, data, sizeof(value));
            return value;
        }

        uint32_t ReadU32(const uint8_t *data)
        {
            uint32_t value = 0;
            std::memcpy(&value, data, sizeof(value));
            return value;
        }

        uint64_t ReadU64(const uint8_t *data)
        {
            uint64_t value = 0;
            std::memcpy(&value, data, sizeof(value));
            return value;
        }

        struct ProgramView
        {
            uint32_t Type = 0;
            uint64_t Offset = 0;
            uint64_t Vaddr = 0;
            uint64_t Filesz = 0;
            uint64_t Memsz = 0;
        };

        ProgramView ReadProgram(const uint8_t *data, bool elf64)
        {
            ProgramView program;
            program.Type = ReadU32(data);
            if (elf64)
            {
                program.Offset = ReadU64(data + 8);
                program.Vaddr = ReadU64(data + 16);
                program.Filesz = ReadU64(data + 32);
                program.Memsz = ReadU64(data + 40);
            }
            else
            {
                program.Offset = ReadU32(data + 4);
                program.Vaddr = ReadU32(data + 8);
                program.Filesz = ReadU32(data + 16);
                program.Memsz = ReadU32(data + 20);
            }
            return program;
        }

        uint64_t BackedBytes(uint64_t filesz, uint64_t memsz)
        {
            if (filesz == 0)
                return memsz;
            return memsz == 0 ? filesz : std::min(filesz, memsz);
        }

        bool FieldSize(uint8_t encoding, bool elf64, size_t &size, bool &signedValue, bool &pcrel)
        {
            const uint8_t format = encoding & 0x0F;
            const uint8_t application = encoding & 0x70;
            if ((encoding & 0x80) != 0 || (application != 0x00 && application != 0x10))
                return false;

            pcrel = application == 0x10;
            signedValue = false;
            switch (format)
            {
            case 0x00:
                size = elf64 ? 8 : 4;
                return true;
            case 0x02:
                size = 2;
                return true;
            case 0x03:
                size = 4;
                return true;
            case 0x04:
                size = 8;
                return true;
            case 0x0A:
                size = 2;
                signedValue = true;
                return true;
            case 0x0B:
                size = 4;
                signedValue = true;
                return true;
            case 0x0C:
                size = 8;
                signedValue = true;
                return true;
            default:
                return false;
            }
        }

        bool ReadUnsigned(const MemoryView &memory, uintptr_t address, size_t size, uint64_t &value)
        {
            if (size != 1 && size != 2 && size != 4 && size != 8)
                return false;
            std::array<uint8_t, 8> bytes{};
            const auto read = memory.ReadBytes(address, bytes.data(), size);
            if (!read.Ok())
                return false;

            value = 0;
            for (size_t index = 0; index < size; ++index)
                value |= uint64_t{bytes[index]} << (index * 8);
            return true;
        }

        bool ReadSigned(const MemoryView &memory, uintptr_t address, size_t size, int64_t &value)
        {
            uint64_t raw = 0;
            if (!ReadUnsigned(memory, address, size, raw))
                return false;
            const unsigned bits = static_cast<unsigned>(size * 8);
            if (bits == 64)
            {
                std::memcpy(&value, &raw, sizeof(value));
                return true;
            }
            const uint64_t sign = uint64_t{1} << (bits - 1);
            value = (raw & sign) ? -static_cast<int64_t>((uint64_t{1} << bits) - raw) : static_cast<int64_t>(raw);
            return true;
        }

        bool ReadUleb(const uint8_t *data, size_t size, size_t &offset, uint64_t &value)
        {
            value = 0;
            unsigned shift = 0;
            while (offset < size && shift < 64)
            {
                const uint8_t byte = data[offset++];
                value |= static_cast<uint64_t>(byte & 0x7F) << shift;
                if ((byte & 0x80) == 0)
                    return true;
                shift += 7;
            }
            return false;
        }

        bool ReadSleb(const uint8_t *data, size_t size, size_t &offset, int64_t &value)
        {
            uint64_t raw = 0;
            unsigned shift = 0;
            uint8_t byte = 0;
            while (offset < size && shift < 64)
            {
                byte = data[offset++];
                raw |= static_cast<uint64_t>(byte & 0x7F) << shift;
                shift += 7;
                if ((byte & 0x80) == 0)
                {
                    if (shift < 64 && (byte & 0x40) != 0)
                        raw |= ~uint64_t{0} << shift;
                    value = static_cast<int64_t>(raw);
                    return true;
                }
            }
            return false;
        }

        bool ParseCie(const MemoryView &memory, uint64_t cie, bool elf64, uint8_t &fdeEncoding)
        {
            if (cie > UINTPTR_MAX || cie > UINTPTR_MAX - 4 - kMaxCieBytes)
                return false;

            uint32_t length = 0;
            const auto lengthRead = memory.ReadBytes(static_cast<uintptr_t>(cie), &length, sizeof(length));
            if (!lengthRead.Ok() || length < 4 || length > kMaxCieBytes)
                return false;

            std::array<uint8_t, kMaxCieBytes> body{};
            const auto bodyRead = memory.ReadBytes(static_cast<uintptr_t>(cie + 4), body.data(), length);
            if (!bodyRead.Ok())
                return false;

            if (ReadU32(body.data()) != 0)
                return false;

            size_t offset = 4;
            if (offset >= length)
                return false;
            const uint8_t version = body[offset++];
            if (version != 1)
                return false;

            char augmentation[16]{};
            size_t augmentationSize = 0;
            while (offset < length && body[offset] != 0)
            {
                if (augmentationSize + 1 >= sizeof(augmentation))
                    return false;
                augmentation[augmentationSize++] = static_cast<char>(body[offset++]);
            }
            if (offset >= length)
                return false;
            ++offset;

            uint64_t codeAlignment = 0;
            int64_t dataAlignment = 0;
            if (!ReadUleb(body.data(), length, offset, codeAlignment) ||
                !ReadSleb(body.data(), length, offset, dataAlignment))
                return false;
            (void)codeAlignment;
            (void)dataAlignment;
            if (offset >= length)
                return false;
            ++offset; // 返回地址寄存器，version 1 为单字节

            fdeEncoding = 0x00;
            if (augmentationSize == 0)
                return false;
            if (augmentation[0] != 'z')
                return false;

            uint64_t augmentationLength = 0;
            if (!ReadUleb(body.data(), length, offset, augmentationLength) ||
                augmentationLength > length - offset)
                return false;

            if (augmentationSize == 2 && augmentation[1] == 'R')
            {
                if (augmentationLength < 1)
                    return false;
                fdeEncoding = body[offset];
            }
            else if (augmentationSize == 1)
            {
                fdeEncoding = 0x00;
            }
            else
            {
                return false;
            }

            size_t fieldSize = 0;
            bool signedValue = false;
            bool pcrel = false;
            if (!FieldSize(fdeEncoding, elf64, fieldSize, signedValue, pcrel))
                return false;
            (void)fieldSize;
            (void)signedValue;
            (void)pcrel;
            return true;
        }
    } // namespace

    bool FunctionIndex::ReadStart(size_t index, uint64_t &start) const
    {
        if (memory_ == nullptr || index >= count_)
            return false;
        const uint64_t offset = static_cast<uint64_t>(index) * kEntryBytes;
        if (table_ > UINTPTR_MAX - 4 || offset > UINTPTR_MAX - table_ - 4)
            return false;

        int32_t delta = 0;
        const auto read = memory_->ReadBytes(static_cast<uintptr_t>(table_ + offset), &delta, sizeof(delta));
        if (!read.Ok())
            return false;

        const int64_t value = static_cast<int64_t>(section_) + delta;
        if (value <= 0 || static_cast<uint64_t>(value) > UINTPTR_MAX)
            return false;
        start = static_cast<uint64_t>(value);
        return start >= moduleBase_ && start < moduleEnd_;
    }

    bool FunctionIndex::ReadFdeOffset(size_t index, int32_t &offset) const
    {
        if (memory_ == nullptr || index >= count_)
            return false;
        const uint64_t entryOffset = static_cast<uint64_t>(index) * kEntryBytes;
        if (table_ > UINTPTR_MAX - 4 || entryOffset > UINTPTR_MAX - table_ - 4)
            return false;
        const auto read = memory_->ReadBytes(static_cast<uintptr_t>(table_ + entryOffset + 4), &offset, sizeof(offset));
        return read.Ok();
    }

    bool FunctionIndex::ReadFdeRange(uint64_t expectedStart, uint64_t fde, FunctionRange &out) const
    {
        if (memory_ == nullptr || fde > UINTPTR_MAX || fde > UINTPTR_MAX - 8)
            return false;

        std::array<uint8_t, 8> header{};
        const auto headerRead = memory_->ReadBytes(static_cast<uintptr_t>(fde), header.data(), header.size());
        if (!headerRead.Ok())
            return false;
        const uint32_t length = ReadU32(header.data());
        const uint32_t ciePointer = ReadU32(header.data() + 4);
        if (length < 12 || length > kMaxFdeBytes || ciePointer == 0)
            return false;

        const uint64_t cieField = fde + 4;
        if (ciePointer > cieField)
            return false;
        const uint64_t cie = cieField - ciePointer;
        if (cie < moduleBase_ || cie >= moduleEnd_)
            return false;

        uint8_t fdeEncoding = 0;
        if (!ParseCie(*memory_, cie, elf64_, fdeEncoding))
            return false;

        size_t initialSize = 0;
        bool signedValue = false;
        bool pcrel = false;
        if (!FieldSize(fdeEncoding, elf64_, initialSize, signedValue, pcrel))
            return false;
        if (length < 4 + initialSize + initialSize)
            return false;
        if (initialSize > UINTPTR_MAX - 8 || fde > UINTPTR_MAX - 8 - initialSize * 2)
            return false;

        const uint64_t initialField = fde + 8;
        uint64_t initialValue = 0;
        if (pcrel && signedValue)
        {
            int64_t signedInitial = 0;
            if (!ReadSigned(*memory_, static_cast<uintptr_t>(initialField), initialSize, signedInitial))
                return false;
            initialValue = static_cast<uint64_t>(static_cast<int64_t>(initialField) + signedInitial);
        }
        else
        {
            if (!ReadUnsigned(*memory_, static_cast<uintptr_t>(initialField), initialSize, initialValue))
                return false;
            if (pcrel)
                initialValue += initialField;
        }
        if (initialValue != expectedStart)
            return false;

        uint64_t range = 0;
        if (!ReadUnsigned(*memory_, static_cast<uintptr_t>(initialField + initialSize), initialSize, range) || range == 0)
            return false;

        const uint64_t end = expectedStart + range;
        if (end < expectedStart || end > moduleEnd_ || expectedStart < moduleBase_ ||
            expectedStart > UINTPTR_MAX || end - 1 > UINTPTR_MAX)
            return false;
        if (!memory_->IsExecutable(static_cast<uintptr_t>(expectedStart), 1) ||
            !memory_->IsExecutable(static_cast<uintptr_t>(end - 1), 1))
            return false;

        out.Start = expectedStart;
        out.End = end;
        return true;
    }

    FunctionIndex FunctionIndex::Build(const ImageModel &image, std::string &error)
    {
        error.clear();
        if (!image.IsValid())
        {
            error = "image-invalid";
            return {};
        }

        const MemoryView &memory = image.Memory();
        const uintptr_t base = image.Base();
        if (!memory.IsReadable(base, 16))
        {
            error = "elf-header-unreadable";
            return {};
        }

        std::array<uint8_t, 64> header{};
        const auto magicRead = memory.ReadBytes(base, header.data(), 16);
        if (!magicRead.Ok() || std::memcmp(header.data(), "\177ELF", 4) != 0 || header[5] != 1)
        {
            error = "elf-header-invalid";
            return {};
        }

        const bool elf64 = header[4] == 2;
        if (!elf64 && header[4] != 1)
        {
            error = "elf-class-unsupported";
            return {};
        }

        const size_t headerSize = elf64 ? 64 : 52;
        const auto headerRead = memory.ReadBytes(base, header.data(), headerSize);
        if (!headerRead.Ok())
        {
            error = "elf-header-short-read";
            return {};
        }

        const uint64_t programOffset = elf64 ? ReadU64(header.data() + 0x20) : ReadU32(header.data() + 0x1C);
        const uint16_t programEntrySize = ReadU16(header.data() + (elf64 ? 0x36 : 0x2A));
        const uint16_t programCount = ReadU16(header.data() + (elf64 ? 0x38 : 0x2C));
        const size_t expectedEntrySize = elf64 ? 56 : 32;
        if (programEntrySize != expectedEntrySize || programCount == 0 ||
            programCount > kMaxProgramHeaders || programOffset < headerSize ||
            programOffset > kMaxProgramHeaderOffset || programOffset > UINTPTR_MAX - base)
        {
            error = "program-headers-invalid";
            return {};
        }

        const size_t programBytes = static_cast<size_t>(programCount) * expectedEntrySize;
        std::vector<uint8_t> programs(programBytes);
        const auto programRead = memory.ReadBytes(base + static_cast<uintptr_t>(programOffset),
                                                  programs.data(), programs.size());
        if (!programRead.Ok())
        {
            error = "program-headers-unreadable";
            return {};
        }

        bool haveLoad = false;
        uint64_t firstLoadVaddr = 0;
        bool haveEhFrame = false;
        uint64_t ehFrameVaddr = 0;
        uint64_t ehFrameAvailable = 0;
        for (size_t index = 0; index < programCount; ++index)
        {
            const ProgramView program = ReadProgram(programs.data() + index * expectedEntrySize, elf64);
            if (program.Type == kPtLoad && program.Offset == 0 && !haveLoad)
            {
                firstLoadVaddr = program.Vaddr;
                haveLoad = true;
            }
            if (program.Type == kPtGnuEhFrame && !haveEhFrame)
            {
                ehFrameVaddr = program.Vaddr;
                ehFrameAvailable = BackedBytes(program.Filesz, program.Memsz);
                haveEhFrame = true;
            }
        }

        if (!haveLoad || base < firstLoadVaddr || !haveEhFrame || ehFrameAvailable < kHeaderBytes)
        {
            error = "eh-frame-header-missing";
            return {};
        }

        const uint64_t loadBias = static_cast<uint64_t>(base) - firstLoadVaddr;
        if (ehFrameVaddr > UINTPTR_MAX - loadBias)
        {
            error = "eh-frame-address-overflow";
            return {};
        }
        const uint64_t section = loadBias + ehFrameVaddr;
        if (section > UINTPTR_MAX || section > UINTPTR_MAX - kHeaderBytes ||
            section < base || section >= image.End() ||
            !memory.IsReadable(static_cast<uintptr_t>(section), kHeaderBytes))
        {
            error = "eh-frame-header-unreadable";
            return {};
        }

        std::array<uint8_t, kHeaderBytes> tableHeader{};
        const auto tableHeaderRead = memory.ReadBytes(static_cast<uintptr_t>(section),
                                                      tableHeader.data(), tableHeader.size());
        if (!tableHeaderRead.Ok() || tableHeader[0] != kVersion ||
            tableHeader[1] != kEhFramePtrSdata4Datarel ||
            tableHeader[2] != kFdeCountUdata4 ||
            tableHeader[3] != kTableSdata4Datarel)
        {
            error = "eh-frame-encoding-unsupported";
            return {};
        }

        const uint32_t count = ReadU32(tableHeader.data() + 8);
        if (count == 0)
        {
            error = "eh-frame-empty";
            return {};
        }
        if (static_cast<uint64_t>(count) * kEntryBytes > ehFrameAvailable - kHeaderBytes)
        {
            error = "eh-frame-table-truncated";
            return {};
        }

        FunctionIndex result;
        result.memory_ = &memory;
        result.moduleBase_ = base;
        result.moduleEnd_ = image.End();
        result.section_ = section;
        result.table_ = section + kHeaderBytes;
        result.count_ = count;
        result.elf64_ = elf64;

        if (!result.ReadStart(0, result.firstStart_) ||
            !result.ReadStart(count - 1, result.lastStart_) ||
            result.firstStart_ > result.lastStart_ ||
            !memory.IsExecutable(static_cast<uintptr_t>(result.firstStart_), 1) ||
            !memory.IsExecutable(static_cast<uintptr_t>(result.lastStart_), 1))
        {
            error = "eh-frame-starts-invalid";
            return {};
        }

        return result;
    }

    bool FunctionIndex::StartAt(size_t index, uint64_t &start) const
    {
        return ReadStart(index, start);
    }

    bool FunctionIndex::CopyStarts(std::vector<uint64_t> &starts, std::string &error) const
    {
        error.clear();
        if (!IsValid())
        {
            error = "function-index-invalid";
            return false;
        }
        if (table_ > UINTPTR_MAX - kEntryBytes || count_ > (UINTPTR_MAX - table_) / kEntryBytes)
        {
            error = "function-table-address-overflow";
            return false;
        }

        starts.resize(count_);
        constexpr size_t kChunkEntries = 1024;
        std::array<uint8_t, kChunkEntries * kEntryBytes> buffer{};
        size_t done = 0;
        while (done < count_)
        {
            const size_t chunk = std::min(kChunkEntries, count_ - done);
            const uint64_t offset = static_cast<uint64_t>(done) * kEntryBytes;
            const auto read = memory_->ReadBytes(static_cast<uintptr_t>(table_ + offset),
                                                 buffer.data(), chunk * kEntryBytes);
            if (!read.Ok())
            {
                error = "function-table-read-failed";
                return false;
            }

            for (size_t index = 0; index < chunk; ++index)
            {
                int32_t delta = 0;
                std::memcpy(&delta, buffer.data() + index * kEntryBytes, sizeof(delta));
                const int64_t value = static_cast<int64_t>(section_) + delta;
                if (value <= 0 || static_cast<uint64_t>(value) > UINTPTR_MAX)
                {
                    error = "function-table-start-invalid";
                    return false;
                }
                starts[done + index] = static_cast<uint64_t>(value);
            }
            done += chunk;
        }
        return true;
    }

    bool FunctionIndex::Find(uint64_t address, FunctionRange &out) const
    {
        if (!IsValid() || address < firstStart_ || address > lastStart_)
            return false;

        size_t low = 0;
        size_t high = count_;
        while (low < high)
        {
            const size_t mid = low + (high - low) / 2;
            uint64_t start = 0;
            if (!ReadStart(mid, start))
                return false;
            if (start <= address)
                low = mid + 1;
            else
                high = mid;
        }
        if (low == 0)
            return false;

        const size_t entry = low - 1;
        uint64_t start = 0;
        int32_t fdeOffset = 0;
        if (!ReadStart(entry, start) || !ReadFdeOffset(entry, fdeOffset))
            return false;

        const int64_t fdeValue = static_cast<int64_t>(section_) + fdeOffset;
        if (fdeValue <= 0 || static_cast<uint64_t>(fdeValue) > UINTPTR_MAX)
            return false;
        const uint64_t fde = static_cast<uint64_t>(fdeValue);
        if (fde < moduleBase_ || fde >= moduleEnd_)
            return false;

        FunctionRange range;
        if (!ReadFdeRange(start, fde, range) || address < range.Start || address >= range.End)
            return false;
        out = range;
        return true;
    }
} // namespace nextdumper::analysis
