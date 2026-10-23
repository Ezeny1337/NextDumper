#include "EhFrameIndex.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

#include "../../Memory/IMemory.h"

namespace nextdumper::analyzer
{
    namespace
    {
        constexpr uint32_t kPtLoad = 1;
        constexpr uint32_t kPtGnuEhFrame = 0x6474e550;

        // .eh_frame_hdr header: version, then the encodings of its three fields.
        // Only the layout below is decoded; any other encoding falls back to the
        // instruction scan rather than guessing at a format not seen in the field.
        constexpr uint8_t kVersion = 1;
        constexpr uint8_t kFdeCountUdata4 = 0x03;
        constexpr uint8_t kTableSdata4Datarel = 0x3b;
        constexpr size_t kHeaderBytes = 12; // 4 ident + eh_frame_ptr + fde_count
        constexpr size_t kEntryBytes = 8;   // initial_location + fde pointer
        constexpr size_t kMaxProgramHeaders = 1024;
        constexpr uint64_t kMaxProgramHeaderOffset = 1024 * 1024;

        uint16_t ReadU16(const uint8_t *Data)
        {
            uint16_t Value = 0;
            std::memcpy(&Value, Data, sizeof(Value));
            return Value;
        }

        uint32_t ReadU32(const uint8_t *Data)
        {
            uint32_t Value = 0;
            std::memcpy(&Value, Data, sizeof(Value));
            return Value;
        }

        uint64_t ReadU64(const uint8_t *Data)
        {
            uint64_t Value = 0;
            std::memcpy(&Value, Data, sizeof(Value));
            return Value;
        }

        /// One program header's fields this decoder needs, in a class-neutral form.
        struct ProgramView
        {
            uint32_t Type = 0;
            uint64_t Offset = 0;
            uint64_t Vaddr = 0;
            uint64_t Filesz = 0;
            uint64_t Memsz = 0;
        };

        ProgramView ReadProgram(const uint8_t *Data, bool bElf64)
        {
            ProgramView Program;
            Program.Type = ReadU32(Data);
            if (bElf64)
            {
                Program.Offset = ReadU64(Data + 8);
                Program.Vaddr = ReadU64(Data + 16);
                Program.Filesz = ReadU64(Data + 32);
                Program.Memsz = ReadU64(Data + 40);
            }
            else
            {
                Program.Offset = ReadU32(Data + 4);
                Program.Vaddr = ReadU32(Data + 8);
                Program.Filesz = ReadU32(Data + 16);
                Program.Memsz = ReadU32(Data + 20);
            }
            return Program;
        }

        /// Bytes of a segment that are actually present in the file image.
        uint64_t BackedBytes(uint64_t Filesz, uint64_t Memsz)
        {
            if (Filesz == 0)
                return Memsz;
            return Memsz == 0 ? Filesz : std::min(Filesz, Memsz);
        }
    } // namespace

    EhFrameIndex EhFrameIndex::Build(const IMemory &Memory, const ModuleInfo &Module)
    {
        if (!Module.IsValid() || Module.GetBase() == 0 || !Memory.IsAddressReadable(Module.GetBase(), 16))
            return {};

        const uintptr_t Base = Module.GetBase();
        std::array<uint8_t, 64> Header{};
        if (Memory.ReadBytes(Base, Header.data(), 16) != 16 ||
            std::memcmp(Header.data(), "\177ELF", 4) != 0 || Header[5] != 1) // ELFDATA2LSB
            return {};

        const bool bElf64 = Header[4] == 2;
        if (!bElf64 && Header[4] != 1)
            return {};

        const size_t HeaderSize = bElf64 ? 64 : 52;
        if (Memory.ReadBytes(Base, Header.data(), HeaderSize) != HeaderSize)
            return {};

        const uint64_t ProgramOffset = bElf64 ? ReadU64(Header.data() + 0x20) : ReadU32(Header.data() + 0x1c);
        const uint16_t ProgramEntrySize = ReadU16(Header.data() + (bElf64 ? 0x36 : 0x2a));
        const uint16_t ProgramCount = ReadU16(Header.data() + (bElf64 ? 0x38 : 0x2c));
        const size_t ExpectedEntrySize = bElf64 ? 56 : 32;
        if (ProgramEntrySize != ExpectedEntrySize || ProgramCount == 0 ||
            ProgramCount > kMaxProgramHeaders || ProgramOffset < HeaderSize ||
            ProgramOffset > kMaxProgramHeaderOffset || ProgramOffset > UINTPTR_MAX - Base)
            return {};

        const size_t ProgramBytes = static_cast<size_t>(ProgramCount) * ExpectedEntrySize;
        std::vector<uint8_t> Programs(ProgramBytes);
        if (Memory.ReadBytes(Base + static_cast<uintptr_t>(ProgramOffset), Programs.data(), ProgramBytes) != ProgramBytes)
            return {};

        bool bHaveLoad = false;
        uint64_t FirstLoadVaddr = 0;
        bool bHaveEhFrame = false;
        uint64_t EhFrameVaddr = 0;
        uint64_t EhFrameAvailable = 0;
        for (size_t Index = 0; Index < ProgramCount; ++Index)
        {
            const ProgramView Program = ReadProgram(Programs.data() + Index * ExpectedEntrySize, bElf64);
            // The header page is mapped from file offset zero, so that PT_LOAD's
            // virtual address is the one the module base was derived from.
            if (Program.Type == kPtLoad && Program.Offset == 0 && !bHaveLoad)
            {
                FirstLoadVaddr = Program.Vaddr;
                bHaveLoad = true;
            }
            if (Program.Type == kPtGnuEhFrame && !bHaveEhFrame)
            {
                EhFrameVaddr = Program.Vaddr;
                EhFrameAvailable = BackedBytes(Program.Filesz, Program.Memsz);
                bHaveEhFrame = true;
            }
        }

        if (!bHaveLoad || Base < FirstLoadVaddr || !bHaveEhFrame || EhFrameAvailable < kHeaderBytes)
            return {};

        const uint64_t LoadBias = static_cast<uint64_t>(Base) - FirstLoadVaddr;
        if (EhFrameVaddr > UINTPTR_MAX - LoadBias)
            return {};
        const uint64_t Section = LoadBias + EhFrameVaddr;
        const uintptr_t SectionAddress = static_cast<uintptr_t>(Section);
        if (static_cast<uint64_t>(SectionAddress) != Section || !Module.Contains(SectionAddress) ||
            !Memory.IsAddressReadable(SectionAddress, kHeaderBytes))
            return {};

        std::array<uint8_t, kHeaderBytes> TableHeader{};
        if (Memory.ReadBytes(SectionAddress, TableHeader.data(), TableHeader.size()) != TableHeader.size())
            return {};
        if (TableHeader[0] != kVersion || TableHeader[2] != kFdeCountUdata4 || TableHeader[3] != kTableSdata4Datarel)
            return {};

        const uint32_t Count = ReadU32(TableHeader.data() + 8);
        // A single entry has no successor, so it can never yield an end address.
        if (Count < 2 || static_cast<uint64_t>(Count) * kEntryBytes > EhFrameAvailable - kHeaderBytes)
            return {};

        EhFrameIndex Result;
        Result.Memory_ = &Memory;
        Result.Section_ = Section;
        Result.Table_ = Section + kHeaderBytes;
        Result.Count_ = Count;

        uint64_t FirstStart = 0;
        uint64_t LastStart = 0;
        if (!Result.ReadStart(0, FirstStart) || !Result.ReadStart(Count - 1, LastStart) ||
            FirstStart > LastStart || !Module.Contains(static_cast<uintptr_t>(FirstStart)) ||
            !Memory.IsAddressExecutable(static_cast<uintptr_t>(FirstStart), 1) ||
            !Memory.IsAddressExecutable(static_cast<uintptr_t>(LastStart), 1))
            return {};

        Result.FirstStart_ = FirstStart;
        Result.LastStart_ = LastStart;
        return Result;
    }

    bool EhFrameIndex::ReadStart(size_t Index, uint64_t &Start) const
    {
        if (!Memory_ || Index >= Count_)
            return false;
        const uint64_t Offset = static_cast<uint64_t>(Index) * kEntryBytes;
        if (Offset > UINTPTR_MAX - Table_)
            return false;
        int32_t Delta = 0;
        if (Memory_->ReadBytes(static_cast<uintptr_t>(Table_ + Offset), &Delta, sizeof(Delta)) != sizeof(Delta))
            return false;
        const int64_t Value = static_cast<int64_t>(Section_) + Delta;
        if (Value <= 0 || static_cast<uint64_t>(static_cast<uintptr_t>(Value)) != static_cast<uint64_t>(Value))
            return false;
        Start = static_cast<uint64_t>(Value);
        return true;
    }

    bool EhFrameIndex::Find(uint64_t Address, FunctionBounds &Out) const
    {
        if (!IsValid() || Address < FirstStart_ || Address > LastStart_)
            return false;

        size_t Low = 0;
        size_t High = Count_;
        while (Low < High)
        {
            const size_t Mid = Low + (High - Low) / 2;
            uint64_t Start = 0;
            if (!ReadStart(Mid, Start))
                return false;
            if (Start <= Address)
                Low = Mid + 1;
            else
                High = Mid;
        }
        if (Low == 0)
            return false;

        const size_t Entry = Low - 1;
        // The last entry's end is not encoded in the table; the instruction scan
        // still covers it.
        if (Entry + 1 >= Count_)
            return false;

        uint64_t Begin = 0;
        uint64_t Next = 0;
        if (!ReadStart(Entry, Begin) || !ReadStart(Entry + 1, Next) ||
            Begin < FirstStart_ || Begin > LastStart_ || Address < Begin || Next <= Begin)
            return false;

        Out.Start = Begin;
        Out.End = Next;
        return true;
    }

} // namespace nextdumper::analyzer
