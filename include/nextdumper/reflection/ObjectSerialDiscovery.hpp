#pragma once

#include "nextdumper/binding/RuntimeBinding.hpp"
#include "nextdumper/ir/ReflectionIR.hpp"
#include "nextdumper/memory/MemorySource.hpp"
#include "nextdumper/ue/EngineSchema.hpp"

namespace nextdumper::reflection
{
    // 定义捕获之后执行，仅唯一关联且经重新读取验证的候选返回非负 selectedOffset
    [[nodiscard]] binding::ObjectSerialEvidence DiscoverObjectSerial(
        memory::IMemorySource &memory, const binding::RuntimeBinding &binding,
        const ue::EngineSchema &schema, const ir::ReflectionIR &reflection);
} // namespace nextdumper::reflection
