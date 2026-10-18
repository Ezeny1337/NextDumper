#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "nextdumper/module/ModuleImage.hpp"
#include "nextdumper/memory/MemorySource.hpp"

namespace nextdumper::module
{
    enum class SymbolStatus
    {
        Exported,
        Debug,
        Missing,
        Incomplete
    };
    [[nodiscard]] inline const char *SymbolStatusName(SymbolStatus status)
    {
        switch (status)
        {
        case SymbolStatus::Exported:
            return "exported";
        case SymbolStatus::Debug:
            return "debug";
        case SymbolStatus::Missing:
            return "missing";
        case SymbolStatus::Incomplete:
            return "incomplete";
        }
        return "incomplete";
    }
    struct SymbolQueryResult
    {
        std::unordered_map<std::string, uintptr_t> exported;
        std::unordered_map<std::string, uintptr_t> debug;
        std::vector<std::string> diagnostics;
        std::unordered_map<std::string, SymbolStatus> status;
    };

    struct DynamicSymbolTables
    {
        uintptr_t loadBias = 0;
        uintptr_t symbols = 0;
        uintptr_t strings = 0;
        size_t stringSize = 0;
        size_t symbolEntrySize = 0;
        uintptr_t gnuHash = 0;
        uintptr_t sysvHash = 0;
    };

    [[nodiscard]] SymbolQueryResult QueryDynamicElfSymbols(const memory::IMemorySource &memory,
                                                           const module::ModuleImage &module, const DynamicSymbolTables &tables, const std::vector<std::string> &names);

    // 仅读取被请求的动态符号，缺失的名称可选择性地使用已映射的调试符号表
    // 解析结果中每个被请求的名称最多包含一个条目；不会生成或保留完整的符号映射表
    [[nodiscard]] SymbolQueryResult QueryElfSymbols(const memory::IMemorySource &memory, const module::ModuleImage &module,
                                                    const std::vector<std::string> &names);
} // namespace nextdumper::module
