#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "nextdumper/analysis/Instruction.hpp"
#include "nextdumper/module/ModuleImage.hpp"

namespace nextdumper::analysis
{
    // 代码执行状态；同一个 ARM32 模块可以混合 A32 与 Thumb 函数，因此模式属于代码范围而不是模块级属性
    enum class CodeMode : uint8_t
    {
        Unknown,
        Arm64,
        Arm32,
        Thumb,
    };

    [[nodiscard]] inline const char *CodeModeName(CodeMode mode)
    {
        switch (mode)
        {
        case CodeMode::Arm64:
            return "arm64";
        case CodeMode::Arm32:
            return "arm";
        case CodeMode::Thumb:
            return "thumb";
        case CodeMode::Unknown:
            break;
        }
        return "unknown";
    }

    class InstructionDecoder
    {
    public:
        virtual ~InstructionDecoder() = default;

        [[nodiscard]] virtual uint32_t Stride() const = 0;
        [[nodiscard]] virtual int RegisterCount() const = 0;
        [[nodiscard]] virtual uint32_t MaxInstructionBytes() const { return Stride(); }
        [[nodiscard]] virtual bool Decode(const uint8_t *bytes, size_t available,
                                          uintptr_t address, Instruction &out) const = 0;

        [[nodiscard]] virtual size_t ArgumentRegisterCount() const = 0;
        [[nodiscard]] virtual bool IsCallerSaved(int reg) const = 0;
        [[nodiscard]] virtual int ProgramCounter() const = 0;
        [[nodiscard]] virtual int LinkRegister() const = 0;
    };

    // 按执行模式创建解码器；A32 与 Thumb 共用同一 ARM32 目标语义
    [[nodiscard]] std::unique_ptr<InstructionDecoder> CreateInstructionDecoder(module::ModuleArchitecture architecture,
                                                                               CodeMode mode = CodeMode::Unknown);
} // namespace nextdumper::analysis
