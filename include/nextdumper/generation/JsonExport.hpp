#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "nextdumper/ir/ReflectionIR.hpp"
#include "nextdumper/generation/CppTypeResolver.hpp"
#include "nextdumper/ue/EngineSchema.hpp"

namespace nextdumper::generation
{
    struct ReflectionIdentity
    {
        std::string_view engine;
        std::string_view profileId;
        std::string_view profileLabel;
        std::string_view versionRange;
        const ::nextdumper::ue::SchemaIdentity *schemaIdentity = nullptr;
    };

    // UE 对象全名形如 "<Kind> /<Root>/<PackagePath>.<ObjectName>"
    // 分片键取 PackagePath 的最后一个分量，/<Root>/ 不参与分片，无法解析时返回空串
    [[nodiscard]] std::string ObjectPackageName(std::string_view fullName);

    struct ReflectionPartition
    {
        struct Shard
        {
            std::string package;
            std::string fileName;
            std::vector<size_t> types;
            std::vector<size_t> enums;
            std::vector<const ir::FunctionIR *> functions;
            size_t properties = 0;
        };
        std::vector<Shard> shards;
    };

    // 按包划分为确定性分片：分片按包名排序，分片内保持 IR 顺序
    [[nodiscard]] ReflectionPartition PartitionReflection(const ir::ReflectionIR &reflection);
    [[nodiscard]] std::string UnassignedPackageName();

    [[nodiscard]] std::string EscapeJson(std::string_view value);
    void WriteSchemaIdentityJson(std::ostream &stream, const ::nextdumper::ue::SchemaIdentity &identity);
    void WriteStatsJson(std::ostream &stream, const ir::ReflectionStats &stats, std::optional<size_t> opaqueFields = std::nullopt);
    void WriteCaptureJson(std::ostream &stream, const ir::CaptureInfo &capture);
    void WritePropertyDiagnosticsJson(std::ostream &stream, const ir::ReflectionIR &reflection);
    void WriteDelegateDiagnosticsJson(std::ostream &stream, const ir::ReflectionIR &reflection);
    void WriteContainerStorageJson(std::ostream &stream, const ir::ReflectionIR &reflection);
    void WriteRuntimeEvidenceJson(std::ostream &stream, const ir::RuntimeEvidence &evidence, bool fullRecords);

    // 索引文件不含任何类型、枚举或函数记录，只描述分片位置与全局证据
    void WriteReflectionIndexJson(std::ostream &stream, const ir::ReflectionIR &reflection, const ReflectionIdentity &identity,
                                  const ReflectionPartition &partition,
                                  const FieldDescriptions *fields = nullptr);
    void WriteReflectionShardJson(std::ostream &stream, const ir::ReflectionIR &reflection,
                                  const ReflectionPartition::Shard &shard,
                                  const FieldDescriptions *fields = nullptr, const CppSymbols *symbols = nullptr);
} // namespace nextdumper::generation
