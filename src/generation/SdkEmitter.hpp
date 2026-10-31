#pragma once

#include <iosfwd>

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
        SdkEmitter(const module::ModuleImage &module, const ue::EngineSchema &schema, const ReflectionIR &reflection)
            : module_(module), schema_(schema), reflection_(reflection) {}

        void SdkEntry(std::ostream &stream) const;
        void BasicTypes(std::ostream &stream, const CppSymbols &symbols) const;
        void EngineLayouts(std::ostream &stream) const;
        void Types(std::ostream &stream, const CppSymbols &symbols, GenerationReport &report) const;
        void Enums(std::ostream &stream, const CppSymbols &symbols) const;
        void Functions(std::ostream &stream, const CppSymbols &symbols, GenerationReport &report) const;

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
