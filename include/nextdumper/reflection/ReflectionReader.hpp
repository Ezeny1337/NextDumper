#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <unordered_set>

#include "nextdumper/ir/ReflectionIR.hpp"
#include "nextdumper/ue/FunctionSemantics.hpp"
#include "nextdumper/ue/ObjectModelReader.hpp"
#include "nextdumper/memory/CaptureMemorySource.hpp"

namespace nextdumper::reflection
{
    using ::nextdumper::binding::RuntimeBinding;
    using ::nextdumper::ir::EnumIR;
    using ::nextdumper::ir::EnumUnderlyingType;
    using ::nextdumper::ir::EnumValueIR;
    using ::nextdumper::ir::FunctionIR;
    using ::nextdumper::ir::ParseStatus;
    using ::nextdumper::ir::PropertyIR;
    using ::nextdumper::ir::PropertyKind;
    using ::nextdumper::ir::ReflectionIR;
    using ::nextdumper::ir::ReflectionStats;
    using ::nextdumper::ir::TypeIR;
    using ::nextdumper::ir::TypeKind;
    using ::nextdumper::ir::TypeReferenceIR;
    using ::nextdumper::memory::IMemorySource;
    using ::nextdumper::ue::AnalyzeFunctionParameters;
    using ::nextdumper::ue::EngineSchema;
    using ::nextdumper::ue::EnumValueMetadata;
    using ::nextdumper::ue::FieldChainResult;
    using ::nextdumper::ue::FieldMetadata;
    using ::nextdumper::ue::FunctionParameterSummary;
    using ::nextdumper::ue::IsFunctionFieldKind;
    using ::nextdumper::ue::IsPropertyFieldKind;
    using ::nextdumper::ue::NormalizeRuntimeFieldName;
    using ::nextdumper::ue::ObjectModelReader;
    using ::nextdumper::ue::ObjectReadResult;
    using ::nextdumper::ue::ObjectReadStatus;
    using ::nextdumper::ue::PropertyMetadata;

    class ReflectionReader
    {
    public:
        ReflectionReader(IMemorySource &memory,
                         const RuntimeBinding &binding,
                         const EngineSchema &schema,
                         uintptr_t moduleBase,
                         uintptr_t moduleEnd,
                         std::function<void(const std::string &)> progress = {},
                         std::function<void(const std::string &)> diagnostic = {});

        [[nodiscard]] ReflectionIR Read();

    private:
        [[nodiscard]] PropertyKind PropertyKindFromName(const std::string &name) const;
        void RecordPropertyDetail(const PropertyMetadata &metadata, PropertyIR &property,
                                  const std::string &reason, bool headerAvailable = true) const;
        [[nodiscard]] std::optional<PropertyIR> ReadProperty(const FieldMetadata &field, ReflectionStats &stats) const;
        [[nodiscard]] TypeReferenceIR ReadTypeReference(const PropertyMetadata &metadata, PropertyIR &property,
                                                        ReflectionStats &stats, std::unordered_set<uintptr_t> &path,
                                                        size_t depth, size_t &remaining) const;
        struct PropertyChain
        {
            std::vector<PropertyIR> properties;
            bool complete = true;
        };
        [[nodiscard]] PropertyChain ReadPropertyChain(uintptr_t first, uintptr_t owner, ReflectionStats &stats,
                                                      std::vector<std::string> &diagnostics) const;
        void ReadProperties(uintptr_t first, TypeIR &type, ReflectionStats &stats) const;
        void ReadFunctionParameters(uintptr_t first, FunctionIR &function, ReflectionStats &stats) const;
        [[nodiscard]] FunctionIR *ReadFunction(uintptr_t address, ReflectionIR &ir) const;
        void ReadFunctions(uintptr_t first, TypeIR &type, ReflectionIR &ir) const;
        void CloseDelegateSignatures(ReflectionIR &ir) const;
        struct ContainerCandidate
        {
            PropertyMetadata metadata;
            TypeReferenceIR reference;
            int priority = 2;
        };
        [[nodiscard]] ::nextdumper::ir::ContainerStorageObservation ReadContainerStorage(const ContainerCandidate &candidate) const;
        void CollectContainerStorage(ReflectionIR &reflection) const;
        [[nodiscard]] std::optional<TypeIR> ReadType(uintptr_t object, TypeKind kind, ReflectionIR &ir) const;
        [[nodiscard]] ReflectionIR ReadAttempt(::nextdumper::memory::CaptureValidation &validation,
                                               ::nextdumper::ir::CaptureInfo::Attempt &details);
        [[nodiscard]] EnumIR ReadEnum(uintptr_t object, ReflectionStats &stats) const;

        ::nextdumper::memory::CaptureMemorySource memory_;
        const EngineSchema &schema_;
        uintptr_t moduleBase_ = 0;
        uintptr_t moduleEnd_ = 0;
        ObjectModelReader objects_;
        std::function<void(const std::string &)> progress_;
        std::function<void(const std::string &)> diagnostic_;
        mutable std::map<uintptr_t, ::nextdumper::ir::DelegateSignatureObservation> delegateSignatures_;
        mutable size_t registryBudgetDiagnostics = 0;
        mutable std::vector<uintptr_t> pendingSignatures_;
        mutable size_t nextSignature_ = 0;
        mutable std::map<uintptr_t, std::pair<uintptr_t, ::nextdumper::ue::FieldChainStatus>> functionChains_;
        mutable std::map<uintptr_t, std::shared_ptr<::nextdumper::ir::ContainerStorageIR>> containerStorage_;
        mutable std::vector<ContainerCandidate> pendingContainers_;
        mutable std::map<uintptr_t, ::nextdumper::ir::ContainerStorageObservation> containerEvidence_;
        mutable std::map<std::string, size_t> containerCandidates_;
        mutable std::map<std::string, size_t> containerNotObserved_;
        mutable std::vector<::nextdumper::ir::ContainerStorageObservation> containerObservations_;
    };
} // namespace nextdumper::reflection
