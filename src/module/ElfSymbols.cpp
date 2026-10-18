#include "nextdumper/module/ElfSymbols.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>

#include "ElfFile.hpp"
#include "ElfTypes.hpp"

namespace nextdumper::module
{
    namespace
    {
        constexpr size_t kMaxSymbols = 4 * 1024 * 1024;
        std::optional<uintptr_t> Add(uintptr_t base, uint64_t offset)
        {
            if (offset > UINTPTR_MAX || base > UINTPTR_MAX - static_cast<uintptr_t>(offset))
                return std::nullopt;
            return base + static_cast<uintptr_t>(offset);
        }
        // 返回 false 会将未解析的名称判定为未完成状态
        // 它不会擦除已从任意符号表中解析出的名称
        bool DebugSymbols(const memory::IMemorySource &memory, const module::ModuleImage &module,
                          const std::vector<std::string> &names, SymbolQueryResult &result)
        {
            const auto fail = [&](const char *reason)
            { result.diagnostics.push_back(reason); return false; };
            ElfFile file;
            if (!file.Open(module.filePath, module.imageFileOffset, module.fileInode, module.fileDevice))
                return fail("debug-file-unavailable");
            ElfHeader header{};
            if (!file.Read(0, header) || std::memcmp(header.e_ident, "\177ELF", 4) != 0 ||
                header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_ident[EI_CLASS] != kElfClass ||
                header.e_machine != kElfMachine || header.e_shentsize != sizeof(ElfSection) ||
                !header.e_shnum || !file.Contains(header.e_shoff, uint64_t{header.e_shnum} * sizeof(ElfSection)))
                return fail("debug-section-table-unavailable-or-invalid");
            ElfHeader remote{};
            if (!memory.Read(module.base, remote) || std::memcmp(&header, &remote, sizeof(header)) != 0)
                return fail("debug-file-identity-mismatch");
            size_t remaining = 0;
            for (const auto &name : names)
                if (!result.exported.contains(name))
                    ++remaining;
            size_t visited = 0;
            for (uint32_t sectionIndex = 0; sectionIndex < header.e_shnum; ++sectionIndex)
            {
                ElfSection section{};
                if (!file.Read(header.e_shoff + uint64_t{sectionIndex} * sizeof(section), section))
                    return fail("debug-section-unreadable");
                if (section.sh_type != SHT_SYMTAB)
                    continue;
                ElfSection strings{};
                if (section.sh_entsize != sizeof(ElfSymbol) || section.sh_size % sizeof(ElfSymbol) ||
                    section.sh_size / sizeof(ElfSymbol) > kMaxSymbols || section.sh_link >= header.e_shnum ||
                    !file.Contains(section.sh_offset, section.sh_size) ||
                    !file.Read(header.e_shoff + uint64_t{section.sh_link} * sizeof(strings), strings) ||
                    strings.sh_type != SHT_STRTAB || !file.Contains(strings.sh_offset, strings.sh_size))
                    return fail("invalid-debug-symbol-table");
                for (uint64_t index = 0; index < section.sh_size / sizeof(ElfSymbol); ++index)
                {
                    if (++visited > kMaxSymbols)
                        return fail("debug-symbol-limit");
                    ElfSymbol symbol{};
                    if (!file.Read(section.sh_offset + index * sizeof(symbol), symbol))
                        return fail("debug-symbol-unreadable");
                    if (symbol.st_shndx == SHN_UNDEF ||
                        (ELF64_ST_TYPE(symbol.st_info) != STT_OBJECT && ELF64_ST_TYPE(symbol.st_info) != STT_FUNC))
                        continue;
                    if (symbol.st_name >= strings.sh_size)
                        return fail("debug-string-offset-out-of-range");
                    for (const auto &name : names)
                    {
                        if (result.exported.contains(name) || result.debug.contains(name))
                            continue;
                        const size_t length = name.size() + 1;
                        const size_t available = std::min<uint64_t>(length, strings.sh_size - symbol.st_name);
                        std::array<char, 257> text{};
                        if (!file.Read(strings.sh_offset + symbol.st_name, text.data(), available))
                            return fail("debug-string-unreadable");
                        if (available != length)
                        {
                            if (std::memcmp(text.data(), name.data(), available) == 0)
                                return fail("debug-string-not-terminated-in-table");
                            continue;
                        }
                        if (std::memcmp(text.data(), name.c_str(), length) != 0)
                            continue;
                        const auto address = symbol.st_shndx == SHN_ABS ? std::optional<uintptr_t>(symbol.st_value) : Add(module.loadBias, symbol.st_value);
                        if (!address || !module.Contains(*address))
                            return fail("debug-symbol-address-out-of-range");
                        result.debug.emplace(name, *address);
                        result.status[name] = SymbolStatus::Debug;
                        if (--remaining == 0)
                            return true;
                    }
                }
            }
            for (const auto &name : names)
                if (!result.exported.contains(name) && !result.debug.contains(name))
                    result.status[name] = SymbolStatus::Missing;
            return true;
        }
    }

    SymbolQueryResult QueryElfSymbols(const memory::IMemorySource &memory, const module::ModuleImage &module,
                                      const std::vector<std::string> &requested)
    {
        DynamicSymbolTables tables;
        tables.loadBias = module.loadBias;
        const auto relocate = [&](uint64_t address) -> uintptr_t
        {
            if (address <= UINTPTR_MAX && module.Contains(static_cast<uintptr_t>(address)))
                return static_cast<uintptr_t>(address);
            const auto value = Add(module.loadBias, address);
            return value && module.Contains(*value) ? *value : uintptr_t{0};
        };
        bool terminated = false;
        if (module.dynamicAddress && module.dynamicSize <= 1024 * 1024 && module.dynamicSize % sizeof(ElfDynamic) == 0)
        {
            std::vector<ElfDynamic> dynamics(module.dynamicSize / sizeof(ElfDynamic));
            if (memory.ReadBytes(module.dynamicAddress, dynamics.data(), module.dynamicSize).Ok())
                for (const auto &dynamic : dynamics)
                {
                    if (dynamic.d_tag == DT_NULL)
                    {
                        terminated = true;
                        break;
                    }
                    switch (dynamic.d_tag)
                    {
                    case DT_SYMTAB:
                        tables.symbols = relocate(dynamic.d_un.d_ptr);
                        break;
                    case DT_STRTAB:
                        tables.strings = relocate(dynamic.d_un.d_ptr);
                        break;
                    case DT_STRSZ:
                        tables.stringSize = static_cast<size_t>(dynamic.d_un.d_val);
                        break;
                    case DT_SYMENT:
                        tables.symbolEntrySize = static_cast<size_t>(dynamic.d_un.d_val);
                        break;
                    case DT_GNU_HASH:
                        tables.gnuHash = relocate(dynamic.d_un.d_ptr);
                        break;
                    case DT_HASH:
                        tables.sysvHash = relocate(dynamic.d_un.d_ptr);
                        break;
                    default:
                        break;
                    }
                }
        }
        if (!terminated)
            tables.symbols = 0;
        auto result = QueryDynamicElfSymbols(memory, module, tables, requested);
        std::vector<std::string> names;
        for (const auto &[name, status] : result.status)
        {
            (void)status;
            names.push_back(name);
        }
        if (std::any_of(names.begin(), names.end(), [&](const auto &name)
                        { return !result.exported.contains(name); }) &&
            !DebugSymbols(memory, module, names, result))
            for (auto &[name, status] : result.status)
                if (!result.exported.contains(name) && !result.debug.contains(name))
                    status = SymbolStatus::Incomplete;
        return result;
    }
} // namespace nextdumper::module
