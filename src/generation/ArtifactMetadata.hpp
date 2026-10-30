#pragma once

#include <cstdint>
#include <iosfwd>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "nextdumper/generation/ArtifactWriter.hpp"
#include "nextdumper/generation/JsonExport.hpp"
#include "GenerationReport.hpp"

namespace nextdumper::generation::detail
{
    // 纯序列化接口，只消费已生成的报告，不触发目标进程读取
    // fileSizes 记录已写出文件的字节数，manifest.json 自身在写出前无法得知其大小，因此不在其中
    void ManifestJson(std::ostream &stream, const RuntimeContext &context, const ReflectionIR &reflection,
                      const std::string &packageName, const ArtifactProvenance &provenance,
                      const GenerationReport &report, ParseStatus status,
                      const std::map<std::string, uintmax_t> &fileSizes);
    void DiagnosticsJson(std::ostream &stream, const RuntimeContext &context, const ReflectionIR &reflection,
                         const GenerationReport &report, ParseStatus status);
    void RuntimeJson(std::ostream &stream, const RuntimeContext &context);
    void ReflectionIndexJson(std::ostream &stream, const RuntimeContext &context, const ReflectionIR &reflection,
                             const ReflectionPartition &partition, const GenerationReport &report);
    void ReflectionShardJson(std::ostream &stream, const ReflectionIR &reflection,
                             const ReflectionPartition::Shard &shard,
                             const GenerationReport &report, const CppSymbols &symbols);
} // namespace nextdumper::generation::detail
