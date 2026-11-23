#include "nextdumper/analysis/CodeRanges.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>

namespace nextdumper::analysis
{
    namespace
    {
        constexpr uint32_t kPtLoad = 1;
        constexpr uint32_t kPtArmExidx = 0x70000001;
        constexpr size_t kMaxProgramHeaders = 1024;
        constexpr uint64_t kMaxProgramHeaderOffset = 1024 * 1024;
        constexpr uint64_t kMaxExidxEntries = 4 * 1024 * 1024;

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

        // PREL31：低 31 位为有符号相对位移，目标 = 字段地址 + 位移
        bool Prel31Target(uint32_t value, uint64_t fieldAddress, uint64_t &target)
        {
            int32_t offset = static_cast<int32_t>(value & 0x7FFFFFFFu);
            if ((value & 0x40000000u) != 0)
                offset |= static_cast<int32_t>(0x80000000u);
            const int64_t resolved = static_cast<int64_t>(fieldAddress) + offset;
            if (resolved < 0)
                return false;
            target = static_cast<uint64_t>(resolved);
            return true;
        }

        struct ModeProbe
        {
            CodeMode Mode = CodeMode::Unknown;
            bool Confident = false;
        };

        // 只有命中明确的序言编码才给出确定结论
        // 否则按 Android ARMv7 以 Thumb 为主的事实给出推断，并标记为不可信
        // 由解码与契约校验决定该范围是否可用
        ModeProbe ProbeMode(const MemoryView &memory, uint64_t start, uint64_t end)
        {
            ModeProbe probe;
            if (start + 4 > end)
            {
                probe.Mode = CodeMode::Thumb;
                return probe;
            }
            std::array<uint8_t, 4> raw{};
            if (!memory.ReadBytes(static_cast<uintptr_t>(start), raw.data(), raw.size()).Ok())
            {
                probe.Mode = CodeMode::Thumb;
                return probe;
            }

            const uint32_t word = ReadU32(raw.data());
            const uint16_t half = ReadU16(raw.data());
            // A32：cond=E 的块传送，例如 push {...,lr} 的 E92Dxxxx
            if ((word & 0xFFFF0000u) == 0xE92D0000u || (word & 0x0E000000u) == 0x0A000000u)
            {
                probe.Mode = CodeMode::Arm32;
                probe.Confident = true;
                return probe;
            }
            // Thumb：16 位 push / mov sp / 32 位前缀
            if ((half & 0xFE00u) == 0xB400u || (half & 0xFF80u) == 0xB080u || (half >> 11) >= 0x1Du)
            {
                probe.Mode = CodeMode::Thumb;
                probe.Confident = true;
                return probe;
            }
            probe.Mode = CodeMode::Thumb;
            return probe;
        }

        // 该地址是否落在可执行段内
        // exidx 的填充项与损坏项会解析出段外地址
        // 若直接当作函数起点会生成跨越整个模块的伪区间
        bool IsExecutableAddress(const module::ModuleImage &module, uint64_t address)
        {
            for (const module::ModuleImage::Segment &segment : module.segments)
            {
                if (segment.executable && segment.end > segment.start && address >= segment.start &&
                    address < segment.end)
                    return true;
            }
            return false;
        }

        // 返回包含该地址的可执行段终点，用于约束区间上界
        uint64_t ExecutableLimit(const module::ModuleImage &module, uint64_t address)
        {
            for (const module::ModuleImage::Segment &segment : module.segments)
            {
                if (segment.executable && segment.end > segment.start && address >= segment.start &&
                    address < segment.end)
                    return segment.end;
            }
            return 0;
        }

        void AppendRange(CodeRangeSet &set, uint64_t start, uint64_t end, CodeMode mode, const char *source,
                         bool precise)
        {
            if (start == 0 || end <= start)
                return;
            CodeRange range;
            range.Start = start;
            range.End = end;
            range.Mode = mode;
            range.Source = source;
            range.Precise = precise;
            set.Ranges.push_back(std::move(range));
        }

        // 相邻且同模式的精确范围合并，减少扫描循环次数
        void MergeRanges(CodeRangeSet &set)
        {
            std::sort(set.Ranges.begin(), set.Ranges.end(),
                      [](const CodeRange &left, const CodeRange &right)
                      { return left.Start < right.Start; });
            std::vector<CodeRange> merged;
            for (const CodeRange &range : set.Ranges)
            {
                if (!merged.empty())
                {
                    CodeRange &previous = merged.back();
                    if (previous.Mode == range.Mode && previous.Precise == range.Precise &&
                        previous.Source == range.Source && range.Start <= previous.End)
                    {
                        previous.End = std::max(previous.End, range.End);
                        continue;
                    }
                }
                merged.push_back(range);
            }
            set.Ranges = std::move(merged);
        }
    } // namespace

    CodeRangeSet RecoverCodeRanges(const MemoryView &memory, const module::ModuleImage &module, std::string &error)
    {
        error.clear();
        CodeRangeSet set;
        if (!module.IsValid() || !memory.IsReadable(module.base, 64))
        {
            error = "module-invalid";
            return set;
        }

        std::array<uint8_t, 64> header{};
        if (!memory.ReadBytes(module.base, header.data(), sizeof(header)).Ok() ||
            std::memcmp(header.data(), "\177ELF", 4) != 0 || header[5] != 1)
        {
            error = "elf-header-invalid";
            return set;
        }
        const bool elf64 = header[4] == 2;
        if (!elf64 && header[4] != 1)
        {
            error = "elf-class-unsupported";
            return set;
        }

        const uint64_t programOffset = elf64 ? ReadU64(header.data() + 0x20) : ReadU32(header.data() + 0x1C);
        const uint16_t programEntrySize = ReadU16(header.data() + (elf64 ? 0x36 : 0x2A));
        const uint16_t programCount = ReadU16(header.data() + (elf64 ? 0x38 : 0x2C));
        const size_t expectedEntrySize = elf64 ? 56 : 32;
        if (programEntrySize != expectedEntrySize || programCount == 0 || programCount > kMaxProgramHeaders ||
            programOffset > kMaxProgramHeaderOffset || programOffset > UINTPTR_MAX - module.base)
        {
            error = "program-headers-invalid";
            return set;
        }

        const size_t programBytes = static_cast<size_t>(programCount) * expectedEntrySize;
        std::vector<uint8_t> programs(programBytes);
        if (!memory.ReadBytes(module.base + static_cast<uintptr_t>(programOffset), programs.data(), programBytes).Ok())
        {
            error = "program-headers-unreadable";
            return set;
        }

        bool haveLoad = false;
        uint64_t firstLoadVaddr = 0;
        uint64_t exidxVaddr = 0;
        uint64_t exidxBytes = 0;
        bool haveExidx = false;
        for (size_t index = 0; index < programCount; ++index)
        {
            const ProgramView program = ReadProgram(programs.data() + index * expectedEntrySize, elf64);
            if (program.Type == kPtLoad && program.Offset == 0 && !haveLoad)
            {
                firstLoadVaddr = program.Vaddr;
                haveLoad = true;
            }
            // PT_ARM_EXIDX 在 32 位 ARM 目标上提供 unwind 索引
            if (program.Type == kPtArmExidx && !haveExidx)
            {
                exidxVaddr = program.Vaddr;
                exidxBytes = BackedBytes(program.Filesz, program.Memsz);
                haveExidx = true;
            }
        }
        if (!haveLoad || module.base < firstLoadVaddr)
        {
            error = "load-segment-missing";
            return set;
        }

        const uint64_t loadBias = static_cast<uint64_t>(module.base) - firstLoadVaddr;
        if (haveExidx && exidxBytes >= 8)
            set.Source = "arm-exidx";
        else
            set.Source = "unavailable";

        if (haveExidx)
        {
            if (exidxVaddr > UINTPTR_MAX - loadBias)
            {
                error = "exidx-address-overflow";
                return set;
            }
            const uint64_t table = loadBias + exidxVaddr;
            const uint64_t entries = std::min<uint64_t>(exidxBytes / 8, kMaxExidxEntries);
            // 索引表按函数地址升序排列，每一项的第一个字是函数起点的 PREL31
            // 第二个字是 unwind 描述符（compact 模型或 .ARM.extab 指针）
            // 因此终点只能取下一项的起点，最后一项取所在可执行段的末尾
            // 同时保留 Thumb 标记，供第二遍确定执行模式
            std::vector<std::pair<uint64_t, bool>> starts;
            uint64_t previousStart = 0;
            for (uint64_t index = 0; index < entries; ++index)
            {
                const uint64_t entryAddress = table + index * 8;
                if (entryAddress > UINTPTR_MAX - 8)
                    break;
                uint32_t first = 0;
                if (!memory.ReadBytes(static_cast<uintptr_t>(entryAddress), &first, sizeof(first)).Ok())
                    break;

                uint64_t start = 0;
                if (!Prel31Target(first, entryAddress, start))
                    continue;
                // 最低位为 Thumb 标记：去掉后按 Thumb 解码，避免半字对齐错位
                const bool thumbEntry = (start & 1u) != 0;
                start &= ~uint64_t{1};
                // 全零填充项经 PREL31 解析后落在索引表或段外地址上
                if (!IsExecutableAddress(module, start) || start <= previousStart)
                    continue;
                previousStart = start;
                starts.push_back({start, thumbEntry});
            }

            for (size_t index = 0; index < starts.size(); ++index)
            {
                const uint64_t start = starts[index].first;
                const bool thumbEntry = starts[index].second;
                uint64_t finish = index + 1 < starts.size() ? starts[index + 1].first : ExecutableLimit(module, start);
                if (finish <= start)
                    continue;

                // 32 位 ARM 目标的执行模式需要单独判定；exidx 只提供边界
                CodeMode mode = CodeMode::Arm64;
                bool confident = true;
                if (module.architecture == module::ModuleArchitecture::Arm32)
                {
                    if (thumbEntry)
                    {
                        mode = CodeMode::Thumb;
                    }
                    else
                    {
                        const ModeProbe probe = ProbeMode(memory, start, finish);
                        mode = probe.Mode;
                        confident = probe.Confident;
                    }
                }
                if (!confident)
                    ++set.UnknownModeRanges;
                AppendRange(set, start, finish, mode, "arm-exidx", false);
            }
            set.Precise = false;
        }

        if (set.Ranges.empty())
        {
            const CodeMode fallbackMode =
                module.architecture == module::ModuleArchitecture::Arm64 ? CodeMode::Arm64 : CodeMode::Unknown;
            for (const module::ModuleImage::Segment &segment : module.segments)
            {
                if (!segment.executable || !segment.readable || segment.end <= segment.start)
                    continue;
                AppendRange(set, segment.start, segment.end, fallbackMode, "executable-segment", false);
            }
            if (set.Ranges.empty())
                error = "no-executable-range";
        }

        for (const CodeRange &range : set.Ranges)
        {
            if (range.Mode == CodeMode::Unknown)
                ++set.UnknownModeRanges;
        }
        MergeRanges(set);
        return set;
    }
} // namespace nextdumper::analysis
