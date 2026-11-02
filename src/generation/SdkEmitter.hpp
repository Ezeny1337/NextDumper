#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <unordered_map>
#include <vector>

#include "nextdumper/module/ModuleImage.hpp"
#include "nextdumper/ue/EngineSchema.hpp"
#include "GenerationReport.hpp"

namespace nextdumper::generation::detail
{
    using ir::FunctionIR;
    using ir::LayoutRepresentation;
    using ir::ReflectionIR;
    using ir::TypeIR;

    // 只生成内存描述并填写报告，不拥有文件、输出路径或发布事务
    class SdkEmitter
    {
    public:
        // 按 UE 包切分后的头文件内容
        // 每个分片自成一体：自带所需的 include 与前置声明
        struct SdkShard
        {
            std::string package;
            std::string fileName;
            std::vector<size_t> types;
            std::vector<const FunctionIR *> functions;
        };

        SdkEmitter(const module::ModuleImage &module, const ue::EngineSchema &schema, const ReflectionIR &reflection)
            : module_(module), schema_(schema), reflection_(reflection) {}

        void SdkEntry(std::ostream &stream) const;
        void BasicTypes(std::ostream &stream, const CppSymbols &symbols) const;
        void EngineLayouts(std::ostream &stream) const;
        // 头文件索引：只列出各分片的 include，供整体引用
        void TypesEntry(std::ostream &stream, const std::vector<std::string> &shardNames) const;
        void FunctionsEntry(std::ostream &stream, const std::vector<std::string> &shardNames) const;
        // 单个分片：只包含该包的类型，依赖的包通过 include 引入
        void TypeShard(std::ostream &stream, const CppSymbols &symbols, const SdkShard &shard,
                       const std::vector<std::string> &dependencies, GenerationReport &report) const;
        void FunctionShard(std::ostream &stream, const CppSymbols &symbols, const SdkShard &shard,
                           const std::vector<std::string> &dependencies, GenerationReport &report) const;
        void Enums(std::ostream &stream, const CppSymbols &symbols) const;
        [[nodiscard]] std::vector<SdkShard> TypeShards(const CppSymbols &symbols) const;
        [[nodiscard]] std::vector<SdkShard> FunctionShards() const;
        // 分片依赖的包名列表，按包名排序且不含自身
        [[nodiscard]] std::vector<std::string> ShardDependencies(const SdkShard &shard, const CppSymbols &symbols) const;
        [[nodiscard]] std::vector<std::string> FunctionShardDependencies(const SdkShard &shard,
                                                                         const CppSymbols &symbols) const;
        [[nodiscard]] std::unordered_map<uintptr_t, size_t> TypeIndexByAddress() const;
        [[nodiscard]] static std::string PackageOfType(const TypeIR &type);

    private:
        struct FieldGenerationPlan
        {
            LayoutRepresentation representation = LayoutRepresentation::SequentialMembers;
            bool declarationDependencyBlocked = false;
            int32_t initialOffset = 0;
            int32_t size = 0;
            std::vector<FieldDescription> fields;
        };
        [[nodiscard]] FieldGenerationPlan BuildFieldGenerationPlan(const TypeIR &owner,
                                                                   const FunctionIR *function,
                                                                   const std::vector<PropertyIR> &properties,
                                                                   int32_t size,
                                                                   const CppSymbols &symbols) const;
        void WriteFields(std::ostream &stream,
                         const TypeIR &owner,
                         const FunctionIR *function,
                         const FieldGenerationPlan &plan,
                         const CppSymbols &symbols,
                         GenerationReport &report) const;

        const module::ModuleImage &module_;
        const ue::EngineSchema &schema_;
        const ReflectionIR &reflection_;
    };
} // namespace nextdumper::generation::detail
