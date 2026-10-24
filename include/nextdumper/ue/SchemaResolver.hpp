#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "nextdumper/ue/ObjectModelReader.hpp"
#include "nextdumper/ue/SchemaCatalog.hpp"

namespace nextdumper::ue
{
    using ::nextdumper::binding::RuntimeBinding;
    using ::nextdumper::memory::IMemorySource;

    enum class ProbeSampleState
    {
        NotObserved,
        Unreadable,
        Decoded,
        SemanticMismatch,
        SemanticMatch,
    };

    struct SchemaProbeNames
    {
        std::string objectClass = "Object";
        std::string classClass = "Class";
        std::string structClass = "Struct";
        std::string fieldClass = "Field";
        std::string guidStruct = "Guid";
        std::string colorStruct = "Color";
        std::string vectorStruct = "Vector";

        [[nodiscard]] bool operator==(const SchemaProbeNames &other) const = default;
    };

    struct SchemaProbeBootstrap
    {
        std::shared_ptr<const ObjectStoreReader> objects;
        std::vector<std::pair<int32_t, uintptr_t>> objectSamples;
        std::string failure;
        bool readFailed = false;

        [[nodiscard]] bool IsValid() const
        {
            return objects != nullptr && objectSamples.size() >= 2;
        }
    };

    [[nodiscard]] std::shared_ptr<const SchemaProbeBootstrap> CreateSchemaProbeBootstrap(
        const IMemorySource &memory,
        const RuntimeBinding &binding,
        size_t maxSamples = 256);

    enum class SchemaProbeStage
    {
        UObject,
        Struct,
        Field,
        Property,
        Function,
        Enum
    };
    [[nodiscard]] const char *SchemaProbeStageName(SchemaProbeStage stage);

    struct SchemaStageResult
    {
        SchemaProbeStage stage = SchemaProbeStage::UObject;
        std::string sourceProfile;
        std::string selectedLayout;
        bool resolved = false;
        bool evidenceComplete = true;
        bool sampleTruncated = false;
        bool budgetExhausted = false;
        bool readFailed = false;
        bool ambiguous = false;
        size_t rejectedCandidates = 0;
        bool searchComplete = true;
        uint64_t elapsedMs = 0;
        memory::ReadStats readsBefore;
        memory::ReadStats readsAfter;
        std::vector<std::string> evidence;
        std::vector<std::string> failures;

        [[nodiscard]] bool CanReuse() const
        {
            return resolved && evidenceComplete && !budgetExhausted && !readFailed && !ambiguous;
        }
    };

    struct SchemaStageUse
    {
        std::shared_ptr<const SchemaStageResult> result;
        bool reused = false;
    };

    struct SchemaResolutionReport
    {
        bool accepted = false;
        bool addressSpaceChanged = false;
        bool probeLimited = false;
        bool searchComplete = true;
        bool evidenceComplete = true;
        bool sampleTruncated = false;
        bool budgetExhausted = false;
        bool ambiguous = false;
        size_t rejectedCandidates = 0;
        int32_t layoutScore = 0;
        int32_t versionEvidenceScore = 0;
        std::string profileId;
        std::string profileLabel;
        std::string failureStage;
        std::vector<std::string> evidence;
        std::vector<SchemaStageUse> stages;
        std::vector<VersionEvidence> versionEvidence;
        std::vector<std::string> failures;
    };

    using SchemaCandidateSummary = SchemaResolutionReport;

    // 归属于单次顺序执行的 Profile 选择尝试，绝不与反射捕获（Reflection Capture）共享
    class SchemaProbeSession;
    [[nodiscard]] std::shared_ptr<SchemaProbeSession> CreateSchemaProbeSession(
        const IMemorySource &memory, const RuntimeBinding &binding, const SchemaProbeNames &names = {},
        uintptr_t moduleBase = 0, uintptr_t moduleEnd = 0);

    // 在进行任何全模块分析之前，使用与 Schema 选择相同的 UObject/FName 探测逻辑
    [[nodiscard]] bool ValidateBindingObjects(const IMemorySource &memory, const RuntimeBinding &binding,
                                              SchemaResolutionReport &report,
                                              EngineSchema *objectSchema = nullptr);

    struct SchemaSelectionResult
    {
        bool accepted = false;
        bool ambiguous = false;
        bool layoutAmbiguous = false;
        size_t selectedIndex = 0;
        std::string selectionReason = "not-selected";
        std::string versionConfidence = "unknown";
        std::vector<size_t> compatibleIndices;
        std::vector<SchemaCandidateSummary> candidates;
    };

    [[nodiscard]] SchemaSelectionResult SelectSchemaCandidates(std::vector<SchemaCandidateSummary> candidates,
                                                               const std::vector<EngineSchema> &schemas);

    class SchemaResolver
    {
    public:
        SchemaResolver(const IMemorySource &memory,
                       const RuntimeBinding &binding,
                       const EngineProfile &profile,
                       SchemaProbeNames names = {},
                       uintptr_t moduleBase = 0,
                       uintptr_t moduleEnd = 0,
                       std::shared_ptr<SchemaProbeSession> session = {});

        [[nodiscard]] SchemaResolutionReport Resolve(EngineSchema &schema) const;

    private:
        const IMemorySource &memory_;
        const RuntimeBinding &binding_;
        EngineProfile profile_;
        SchemaProbeNames names_;
        uintptr_t moduleBase_ = 0;
        uintptr_t moduleEnd_ = 0;
        std::shared_ptr<SchemaProbeSession> session_;
    };
} // namespace nextdumper::ue
