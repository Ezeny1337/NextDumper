#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "nextdumper/analysis/Instruction.hpp"
#include "nextdumper/module/ModuleImage.hpp"

namespace nextdumper::analysis
{
    class InstructionDecoder
    {
    public:
        virtual ~InstructionDecoder() = default;

        [[nodiscard]] virtual uint32_t Stride() const = 0;
        [[nodiscard]] virtual int RegisterCount() const = 0;
        [[nodiscard]] virtual bool Decode(const uint8_t *bytes, size_t available,
                                          uintptr_t address, Instruction &out) const = 0;
    };

    [[nodiscard]] std::unique_ptr<InstructionDecoder> CreateInstructionDecoder(module::ModuleArchitecture architecture);
} // namespace nextdumper::analysis
