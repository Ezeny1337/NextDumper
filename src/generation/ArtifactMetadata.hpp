#pragma once

#include <iosfwd>

#include "nextdumper/generation/ArtifactWriter.hpp"
#include "GenerationReport.hpp"

namespace nextdumper::generation::detail
{
    // 纯序列化接口，只消费已生成的报告，不触发目标进程读取
    void ManifestJson(std::ostream &stream, const RuntimeContext &context, const ReflectionIR &reflection,
                      const std::string &packageName, const ArtifactProvenance &provenance,
                      const GenerationReport &report, ParseStatus status);
    void DiagnosticsJson(std::ostream &stream, const RuntimeContext &context, const ReflectionIR &reflection,
                         const GenerationReport &report, ParseStatus status);
    void RuntimeJson(std::ostream &stream, const RuntimeContext &context);
    void ReflectionJson(std::ostream &stream, const RuntimeContext &context, const ReflectionIR &reflection,
                        const GenerationReport &report, const CppSymbols &symbols);
} // namespace nextdumper::generation::detail
