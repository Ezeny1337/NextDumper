#include "nextdumper/module/ElfSymbols.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace nextdumper::module
{
    namespace
    {
        constexpr uint32_t kMaxSymbols = 4 * 1024 * 1024;
        struct Symbol32
        {
            uint32_t name, value, size;
            uint8_t info, other;
            uint16_t section;
        };
        struct Symbol64
        {
            uint32_t name;
            uint8_t info, other;
            uint16_t section;
            uint64_t value, size;
        };
        static_assert(sizeof(Symbol32) == 16 && sizeof(Symbol64) == 24);

        class Query
        {
        public:
            Query(const memory::IMemorySource &memory, const module::ModuleImage &module, const DynamicSymbolTables &tables)
                : memory_(memory), module_(module), tables_(tables) {}
            std::string error;
            uintptr_t Find(const std::string &name)
            {
                error.clear();
                if ((module_.pointerWidth != 4 && module_.pointerWidth != 8) ||
                    tables_.symbolEntrySize != (module_.pointerWidth == 4 ? sizeof(Symbol32) : sizeof(Symbol64)) ||
                    !tables_.symbols || !tables_.strings || !tables_.stringSize)
                {
                    error = "invalid-dynamic-symbol-metadata";
                    return 0;
                }
                std::string gnuFailure;
                if (tables_.gnuHash)
                {
                    const auto address = Gnu(name);
                    if (address || error.empty())
                        return address;
                    gnuFailure = error;
                }
                if (tables_.sysvHash)
                {
                    const auto address = SysV(name);
                    if (!address && error.empty())
                        error = gnuFailure;
                    return address;
                }
                if (!tables_.gnuHash)
                    error = "dynamic-hash-table-unavailable";
                return 0;
            }

        private:
            bool Range(uintptr_t address, size_t size) const
            {
                return module_.IsReadable(address, size);
            }
            template <typename T>
            bool Read(uintptr_t base, uint64_t offset, T &value)
            {
                return ReadBytes(base, offset, &value, sizeof(T));
            }
            bool ReadBytes(uintptr_t base, uint64_t offset, void *buffer, size_t size)
            {
                if (offset > UINTPTR_MAX || base > UINTPTR_MAX - static_cast<uintptr_t>(offset) ||
                    !Range(base + static_cast<uintptr_t>(offset), size) ||
                    !memory_.ReadBytes(base + static_cast<uintptr_t>(offset), buffer, size).Ok())
                {
                    error = "dynamic-table-out-of-range-or-unreadable";
                    return false;
                }
                return true;
            }
            uintptr_t Symbol(uint32_t index, const std::string &name)
            {
                if (index >= kMaxSymbols)
                {
                    error = "dynamic-symbol-limit";
                    return 0;
                }
                uint32_t stringOffset;
                uint16_t section;
                uint8_t info;
                uint64_t value;
                if (module_.pointerWidth == 4)
                {
                    Symbol32 s{};
                    if (!Read(tables_.symbols, uint64_t{index} * sizeof(s), s))
                        return 0;
                    stringOffset = s.name;
                    section = s.section;
                    info = s.info;
                    value = s.value;
                }
                else
                {
                    Symbol64 s{};
                    if (!Read(tables_.symbols, uint64_t{index} * sizeof(s), s))
                        return 0;
                    stringOffset = s.name;
                    section = s.section;
                    info = s.info;
                    value = s.value;
                }
                if (section == 0 || ((info & 15) != 1 && (info & 15) != 2))
                    return 0;
                if (stringOffset >= tables_.stringSize)
                {
                    error = "dynamic-string-offset-out-of-range";
                    return 0;
                }
                const size_t length = name.size() + 1;
                const size_t available = std::min(length, tables_.stringSize - stringOffset);
                std::array<char, 257> text{};
                if (!ReadBytes(tables_.strings, stringOffset, text.data(), available))
                    return 0;
                if (available != length)
                {
                    if (std::memcmp(text.data(), name.data(), available) == 0)
                        error = "dynamic-string-not-terminated-in-table";
                    return 0;
                }
                if (std::memcmp(text.data(), name.c_str(), length) != 0)
                    return 0;
                const uint64_t bias = section == 0xFFF1 ? 0 : tables_.loadBias; // SHN_ABS 已是绝对地址。
                if (value > UINTPTR_MAX || bias > UINTPTR_MAX - value || !module_.IsReadable(static_cast<uintptr_t>(bias + value)))
                {
                    error = "dynamic-symbol-address-out-of-range";
                    return 0;
                }
                return static_cast<uintptr_t>(bias + value);
            }
            uintptr_t Gnu(const std::string &name)
            {
                std::array<uint32_t, 4> header{};
                if (!Read(tables_.gnuHash, 0, header))
                    return 0;
                const auto [buckets, first, words, shift] = header;
                if (!buckets || buckets > kMaxSymbols || first >= kMaxSymbols || !words || words > kMaxSymbols || shift >= 32)
                {
                    error = "invalid-gnu-hash-header";
                    return 0;
                }
                uint32_t hash = 5381;
                for (unsigned char c : name)
                    hash = hash * 33 + c;
                const uint32_t bits = module_.pointerWidth * 8;
                uint64_t bloom = 0;
                if (bits == 32)
                {
                    uint32_t word = 0;
                    if (!Read(tables_.gnuHash, 16 + uint64_t{(hash / bits) % words} * 4, word))
                        return 0;
                    bloom = word;
                }
                else if (!Read(tables_.gnuHash, 16 + uint64_t{(hash / bits) % words} * 8, bloom))
                    return 0;
                const uint64_t mask = (uint64_t{1} << (hash % bits)) | (uint64_t{1} << ((hash >> shift) % bits));
                if ((bloom & mask) != mask)
                    return 0;
                const uint64_t bucketOffset = 16 + uint64_t{words} * module_.pointerWidth;
                const uint64_t chainOffset = bucketOffset + uint64_t{buckets} * 4;
                uint32_t index = 0;
                if (!Read(tables_.gnuHash, bucketOffset + uint64_t{hash % buckets} * 4, index) || !index)
                    return 0;
                if (index < first || index >= kMaxSymbols)
                {
                    error = "invalid-gnu-hash-bucket";
                    return 0;
                }
                for (; index < kMaxSymbols; ++index)
                {
                    uint32_t chain = 0;
                    if (!Read(tables_.gnuHash, chainOffset + uint64_t{index - first} * 4, chain))
                        return 0;
                    if ((chain | 1u) == (hash | 1u))
                    {
                        const auto address = Symbol(index, name);
                        if (address || !error.empty())
                            return address;
                    }
                    if (chain & 1)
                        return 0;
                }
                error = "gnu-hash-chain-limit";
                return 0;
            }
            uintptr_t SysV(const std::string &name)
            {
                error.clear();
                std::array<uint32_t, 2> header{};
                if (!Read(tables_.sysvHash, 0, header))
                    return 0;
                const auto [buckets, chains] = header;
                if (!buckets || buckets > kMaxSymbols || !chains || chains > kMaxSymbols)
                {
                    error = "invalid-sysv-hash-header";
                    return 0;
                }
                uint32_t hash = 0;
                for (unsigned char c : name)
                {
                    hash = (hash << 4) + c;
                    const uint32_t high = hash & 0xF0000000u;
                    hash ^= high >> 24;
                    hash &= ~high;
                }
                uint32_t index = 0;
                if (!Read(tables_.sysvHash, 8 + uint64_t{hash % buckets} * 4, index))
                    return 0;
                for (uint32_t steps = 0; index && steps < chains; ++steps)
                {
                    if (index >= chains)
                    {
                        error = "invalid-sysv-hash-chain";
                        return 0;
                    }
                    const auto address = Symbol(index, name);
                    if (address || !error.empty())
                        return address;
                    if (!Read(tables_.sysvHash, 8 + uint64_t{buckets} * 4 + uint64_t{index} * 4, index))
                        return 0;
                }
                if (index)
                    error = "sysv-hash-cycle";
                return 0;
            }
            const memory::IMemorySource &memory_;
            const module::ModuleImage &module_;
            const DynamicSymbolTables &tables_;
        };
    }

    SymbolQueryResult QueryDynamicElfSymbols(const memory::IMemorySource &memory, const module::ModuleImage &module,
                                             const DynamicSymbolTables &tables, const std::vector<std::string> &names)
    {
        SymbolQueryResult result;
        if (names.size() > 64 || std::any_of(names.begin(), names.end(), [](const auto &name)
                                             { return name.empty() || name.size() > 256 || name.find('\0') != std::string::npos; }))
        {
            result.diagnostics.push_back("invalid-symbol-query");
            return result;
        }
        Query query(memory, module, tables);
        for (const auto &name : names)
        {
            if (result.status.contains(name))
                continue;
            const auto address = query.Find(name);
            result.status.emplace(name, address ? SymbolStatus::Exported : query.error.empty() ? SymbolStatus::Missing
                                                                                               : SymbolStatus::Incomplete);
            if (address)
                result.exported.emplace(name, address);
            if (!query.error.empty())
                result.diagnostics.push_back("name=" + name + " reason=" + query.error);
        }
        return result;
    }
} // namespace nextdumper::module
