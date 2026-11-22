#pragma once

#include <memory>

#include "nextdumper/analysis/InstructionDecoder.hpp"

namespace nextdumper::analysis
{
    // 各架构解码器的构造入口，由 CreateInstructionDecoder 统一分派
    [[nodiscard]] std::unique_ptr<InstructionDecoder> CreateArm32Decoder(CodeMode mode);
} // namespace nextdumper::analysis
