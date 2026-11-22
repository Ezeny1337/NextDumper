#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "nextdumper/analysis/InstructionDecoder.hpp"
#include "nextdumper/analysis/MemoryView.hpp"
#include "nextdumper/module/ModuleImage.hpp"

namespace nextdumper::analysis
{
    // 一段可解码的代码
    // ARM32 允许同一模块混合 A32 与 Thumb，因此模式与来源随范围一起保存
    struct CodeRange
    {
        uint64_t Start = 0;
        uint64_t End = 0;
        CodeMode Mode = CodeMode::Unknown;
        std::string Source;
        bool Precise = false;
    };

    struct CodeRangeSet
    {
        std::vector<CodeRange> Ranges;
        bool Precise = false;
        std::string Source;
        size_t UnknownModeRanges = 0;
    };

    // 从 ELF 的程序头与符号信息恢复代码范围与执行模式
    // 只读取已映射的必要元数据，不做异常栈展开
    [[nodiscard]] CodeRangeSet RecoverCodeRanges(const MemoryView &memory, const module::ModuleImage &module,
                                                 std::string &error);
} // namespace nextdumper::analysis
