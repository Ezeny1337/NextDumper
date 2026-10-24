#include "nextdumper/ue/SchemaResolver.hpp"
#include "ProbeContext.hpp"

#include <algorithm>
#include <chrono>

namespace nextdumper::ue
{
    namespace
    {
        std::string DescribeStageLayout(SchemaProbeStage stage, const EngineSchema &s)
        {
            switch (stage)
            {
            case SchemaProbeStage::UObject:
                return "name=" + std::to_string(s.uobject.name) + " class=" + std::to_string(s.uobject.classPointer) +
                       " outer=" + std::to_string(s.uobject.outer) + " flags=" + std::to_string(s.uobject.flags) +
                       " index=" + std::to_string(s.uobject.internalIndex) + " fname_size=" + std::to_string(s.fname.size);
            case SchemaProbeStage::Struct:
                return "super=" + std::to_string(s.ustruct.superStruct) + " size=" + std::to_string(s.ustruct.propertiesSizeOffset) +
                       " lwc=" + std::to_string(s.features.largeWorldCoordinates);
            case SchemaProbeStage::Field:
                return "next=" + std::to_string(s.ufield.next) + " child_properties=" + std::to_string(s.ustruct.childProperties) +
                       " ffield_class=" + std::to_string(s.ffield.classPointer) + " ffield_owner=" + std::to_string(s.ffield.owner);
            case SchemaProbeStage::Property:
                return "array_dim=" + std::to_string(s.property.arrayDim) + " element_size=" + std::to_string(s.property.elementSize) +
                       " flags=" + std::to_string(s.property.propertyFlags) + " offset=" + std::to_string(s.property.offsetInternal) +
                       " subtype_start=" + std::to_string(s.property.subtypeStart);
            case SchemaProbeStage::Function:
                return "children=" + std::to_string(s.ustruct.children) + " next=" + std::to_string(s.ufield.next) +
                       " flags=" + std::to_string(s.ufunction.functionFlags) + " num_params=" + std::to_string(s.ufunction.numParams) +
                       " param_size=" + std::to_string(s.ufunction.paramSize) + " return=" + std::to_string(s.ufunction.returnValueOffset) +
                       " native=" + std::to_string(s.ufunction.nativeFunction);
            case SchemaProbeStage::Enum:
                return "names=" + std::to_string(s.uenum.names) + " cpp_form=" + std::to_string(s.uenum.cppForm) +
                       " flags=" + std::to_string(s.uenum.flags) + " package=" + std::to_string(s.uenum.enumPackage);
            }
            return {};
        }
    }
    const char *SchemaProbeStageName(SchemaProbeStage stage)
    {
        switch (stage)
        {
        case SchemaProbeStage::UObject:
            return "uobject";
        case SchemaProbeStage::Struct:
            return "struct";
        case SchemaProbeStage::Field:
            return "field";
        case SchemaProbeStage::Property:
            return "property";
        case SchemaProbeStage::Function:
            return "function";
        case SchemaProbeStage::Enum:
            return "enum";
        }
        return "unknown";
    }

    std::shared_ptr<SchemaProbeSession> CreateSchemaProbeSession(const IMemorySource &memory, const RuntimeBinding &binding,
                                                                 const SchemaProbeNames &names, uintptr_t moduleBase, uintptr_t moduleEnd)
    {
        return std::make_shared<SchemaProbeSession>(memory, binding, names, moduleBase, moduleEnd);
    }

    bool ValidateBindingObjects(const IMemorySource &memory, const RuntimeBinding &binding, SchemaResolutionReport &report,
                                EngineSchema *objectSchema)
    {
        const SchemaProbeNames names;
        const auto profile = SchemaCatalog::Profiles().front();
        const auto session = CreateSchemaProbeSession(memory, binding, names);
        const schema_probe::SchemaProbeContext probe{memory, binding, profile, names, 0, 0, session->bootstrap, *session};
        EngineSchema schema;
        schema.features = profile.features;
        const bool validated = probe.ResolveUObjectSchema(schema, report) && probe.ValidateUObjectSchema(schema, report);
        if (validated && objectSchema)
            *objectSchema = schema;
        return validated;
    }

    std::shared_ptr<const SchemaProbeBootstrap> CreateSchemaProbeBootstrap(const IMemorySource &memory,
                                                                           const RuntimeBinding &binding,
                                                                           size_t maxSamples)
    {
        auto result = std::make_shared<SchemaProbeBootstrap>();
        const uint64_t failuresBefore = memory.Stats().failures;
        auto objects = std::make_shared<ObjectStoreReader>(memory,
                                                           binding.objectRoot.address,
                                                           binding.objects,
                                                           binding.decode);
        if (!objects->Initialize())
        {
            result->failure = "object store could not be initialized for schema bootstrap";
            result->readFailed = memory.Stats().failures != failuresBefore;
            return result;
        }

        result->objectSamples.reserve(std::min<size_t>(maxSamples, static_cast<size_t>(objects->Count())));
        for (int32_t index = 0; index < objects->Count() && result->objectSamples.size() < maxSamples; ++index)
        {
            const auto object = objects->ReadObject(index);
            if (object.IsValid())
                result->objectSamples.emplace_back(index, object.address);
        }
        if (result->objectSamples.size() < 2)
        {
            result->failure = "not enough live UObject samples for schema bootstrap";
            result->readFailed = memory.Stats().failures != failuresBefore;
            return result;
        }

        result->objects = std::move(objects);
        result->readFailed = memory.Stats().failures != failuresBefore;
        return result;
    }

    SchemaResolver::SchemaResolver(const IMemorySource &memory,
                                   const RuntimeBinding &binding,
                                   const EngineProfile &profile,
                                   SchemaProbeNames names,
                                   uintptr_t moduleBase,
                                   uintptr_t moduleEnd,
                                   std::shared_ptr<SchemaProbeSession> session)
        : memory_(memory),
          binding_(binding),
          profile_(profile),
          names_(std::move(names)),
          moduleBase_(moduleBase),
          moduleEnd_(moduleEnd),
          session_(session ? std::move(session) : CreateSchemaProbeSession(memory, binding, names_, moduleBase, moduleEnd))
    {
    }

    SchemaResolutionReport SchemaResolver::Resolve(EngineSchema &schema) const
    {
        SchemaResolutionReport report;
        const uint64_t addressSpaceGeneration = memory_.AddressSpaceGeneration();
        report.profileId = profile_.id;
        report.profileLabel = profile_.label;
        schema.family = profile_.family;
        schema.layout = profile_.layout;
        schema.profileFeatures = profile_.features;
        schema.features = profile_.features;
        const schema_probe::SchemaProbeContext probe{memory_, binding_, profile_, names_,
                                                     moduleBase_, moduleEnd_, session_->bootstrap, *session_};
        report.evidence.push_back("engine structure profile=" + profile_.id +
                                  " version_range=" + profile_.versionRange +
                                  " use_fproperty=" + std::to_string(schema.features.useFProperty) +
                                  " use_name_pool=" + std::to_string(schema.features.useNamePool) +
                                  " ffield_owner_encoding=" +
                                  std::to_string(schema.features.fFieldOwnerEncoding == FFieldOwnerEncoding::TaggedPointer) +
                                  " large_world_coordinates=" + std::to_string(schema.features.largeWorldCoordinates) +
                                  " layout=" + SchemaLayoutVariantName(schema.layout) +
                                  " enum_tail=" + EnumTailLayoutName(schema.features.enumTailLayout) +
                                  " enum_cpp_form_byte=" + std::to_string(schema.features.enumCppFormIsByte) +
                                  " enum_flags_required=" + std::to_string(schema.features.enumFlagsRequired));
        if (!profile_.IsValid())
        {
            report.failureStage = "profile";
            report.failures.push_back("engine structure profile is invalid");
            return report;
        }

        if (!session_->Matches(memory_, binding_, names_, moduleBase_, moduleEnd_))
        {
            report.addressSpaceChanged = true;
            report.failureStage = "session";
            report.failures.push_back("schema session inputs or address-space generation changed");
            return report;
        }
        const auto resolveStage = [&](SchemaProbeStage stage, const auto &resolve)
        {
            report.failureStage = SchemaProbeStageName(stage);
            if (memory_.AddressSpaceGeneration() != addressSpaceGeneration)
            {
                report.addressSpaceChanged = true;
                report.failures.push_back("remote address-space generation changed before schema stage=" + report.failureStage);
                return false;
            }
            const auto input = SchemaProbeSession::Inputs(stage, schema);
            const auto found = std::find_if(session_->entries.begin(), session_->entries.end(), [&](const auto &entry)
                                            { return entry.result->stage == stage && input == entry.key; });
            if (found != session_->entries.end())
            {
                SchemaProbeSession::Apply(found->output, schema);
                report.stages.push_back({found->result, true});
                report.searchComplete = report.searchComplete && found->result->searchComplete;
                report.evidenceComplete = report.evidenceComplete && found->result->evidenceComplete && !found->result->readFailed;
                report.sampleTruncated = report.sampleTruncated || found->result->sampleTruncated;
                report.budgetExhausted = report.budgetExhausted || found->result->budgetExhausted;
                report.ambiguous = report.ambiguous || found->result->ambiguous;
                report.rejectedCandidates += found->result->rejectedCandidates;
                report.probeLimited = report.probeLimited || found->result->sampleTruncated ||
                                      found->result->budgetExhausted || found->result->readFailed ||
                                      !found->result->evidenceComplete;
                report.versionEvidence.insert(report.versionEvidence.end(), found->versionEvidence.begin(), found->versionEvidence.end());
                return true;
            }
            auto result = std::make_shared<SchemaStageResult>();
            result->stage = stage;
            result->sourceProfile = profile_.id;
            result->readsBefore = memory_.Stats();
            const auto started = std::chrono::steady_clock::now();
            SchemaResolutionReport stageReport;
            result->resolved = resolve(stageReport);
            if (result->resolved)
                result->selectedLayout = DescribeStageLayout(stage, schema);
            const bool usesIndex = stage != SchemaProbeStage::UObject;
            result->evidenceComplete = stageReport.evidenceComplete;
            result->sampleTruncated = stageReport.sampleTruncated || (usesIndex && session_->indexLimited);
            result->budgetExhausted = stageReport.budgetExhausted;
            result->ambiguous = stageReport.ambiguous;
            result->rejectedCandidates = stageReport.rejectedCandidates;
            result->searchComplete = stageReport.searchComplete && !result->sampleTruncated && !result->budgetExhausted;
            result->elapsedMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                          std::chrono::steady_clock::now() - started)
                                                          .count());
            result->readsAfter = memory_.Stats();
            result->readFailed = result->readsAfter.failures != result->readsBefore.failures ||
                                 (usesIndex && session_->indexReadFailed) || session_->bootstrap->readFailed;
            result->evidence = std::move(stageReport.evidence);
            result->failures = std::move(stageReport.failures);
            report.addressSpaceChanged = memory_.AddressSpaceGeneration() != addressSpaceGeneration;
            report.probeLimited = report.probeLimited || stageReport.probeLimited || result->sampleTruncated ||
                                  result->budgetExhausted || result->readFailed || !result->evidenceComplete;
            report.sampleTruncated = report.sampleTruncated || result->sampleTruncated;
            report.budgetExhausted = report.budgetExhausted || result->budgetExhausted;
            report.evidenceComplete = report.evidenceComplete && result->evidenceComplete && !result->readFailed;
            report.ambiguous = report.ambiguous || result->ambiguous;
            report.rejectedCandidates += result->rejectedCandidates;
            report.searchComplete = report.searchComplete && result->searchComplete;
            report.stages.push_back({result, false});
            report.failures.insert(report.failures.end(), result->failures.begin(), result->failures.end());
            report.versionEvidence.insert(report.versionEvidence.end(), stageReport.versionEvidence.begin(), stageReport.versionEvidence.end());
            if (report.addressSpaceChanged)
                report.failures.push_back("remote address-space generation changed during schema stage=" + report.failureStage);
            // 只有完整且成功读取的证据才可以被共享
            // 候选方案预检阶段的拒绝操作不会引发读取失败判定，但真正的证据读取失败仍构成硬性门禁
            if (result->CanReuse() && !report.addressSpaceChanged)
                session_->entries.push_back({input, SchemaProbeSession::Result(stage, schema), result, std::move(stageReport.versionEvidence)});
            return result->resolved && !report.addressSpaceChanged;
        };
        if (!resolveStage(SchemaProbeStage::UObject, [&](auto &r)
                          {
                              if (binding_.objectSchema)
                              {
                                  schema.fname = binding_.objectSchema->fname;
                                  schema.uobject = binding_.objectSchema->uobject;
                                  schema.features.casePreservingName = binding_.objectSchema->features.casePreservingName;
                                  schema.features.outlineNumberName = binding_.objectSchema->features.outlineNumberName;
                                  schema.features.fnameDisplayLayout = binding_.objectSchema->features.fnameDisplayLayout;
                                  r.evidence.push_back("reused binding-validated UObject/FName physical layout; rediscovery=0");
                                  return true;
                              }
                              return probe.ResolveUObjectSchema(schema, r) && probe.ValidateUObjectSchema(schema, r); }))
            return report;
        if (!resolveStage(SchemaProbeStage::Struct, [&](auto &r)
                          { return probe.ResolveStructSchema(schema, r); }))
            return report;
        if (!resolveStage(SchemaProbeStage::Field, [&](auto &r)
                          { return probe.ResolveFieldSchema(schema, r); }))
            return report;
        if (!resolveStage(SchemaProbeStage::Property, [&](auto &r)
                          { return probe.ResolvePropertySchema(schema, r) && probe.ResolvePropertySubtypes(schema, r); }))
            return report;
        if (!resolveStage(SchemaProbeStage::Function, [&](auto &r)
                          { return probe.ResolveFunctionSchema(schema, r); }))
            return report;
        if (!resolveStage(SchemaProbeStage::Enum, [&](auto &r)
                          { return probe.ResolveEnumSchema(schema, r); }))
            return report;

        schema.validation.uobject = true;
        schema.validation.fname = binding_.names.IsValid();
        if (schema.features.useFProperty)
            schema.validation.fields = true;
        schema.validation.profileId = profile_.id;
        schema.validation.profileLabel = profile_.label;
        schema.validation.profileVersionRange = profile_.versionRange;
        schema.validation.familyEvidence = profile_.versionRange;
        if (memory_.AddressSpaceGeneration() != addressSpaceGeneration)
        {
            report.addressSpaceChanged = true;
            report.failureStage = "address-space-generation";
            report.failures.push_back("remote address-space generation changed during schema resolution");
            return report;
        }
        if (!schema.validation.properties || !schema.validation.functions || !schema.validation.enums)
        {
            report.failures.push_back("one or more schema semantic probes failed");
            return report;
        }
        report.accepted = schema.IsReadyForReflection();
        if (report.accepted)
        {
            report.layoutScore = 100;
            if (schema.uobject.outer == schema.uobject.name + schema.fname.size)
                report.layoutScore += 10;
            if (schema.ufield.next == schema.uobject.outer + static_cast<int32_t>(sizeof(uintptr_t)))
                report.layoutScore += 10;
            if (schema.uenum.names >= 0 && schema.uenum.cppForm >= 0)
                report.layoutScore += 5;
            if (schema.features.enumFlagsRequired && schema.uenum.flags >= 0)
                report.layoutScore += 5;
            if (schema.features.enumHasPackage && schema.uenum.enumPackage >= 0)
                report.layoutScore += 5;

            const bool ue5Profile = profile_.family == EngineFamily::UE5FProperty;
            if (schema.features.largeWorldCoordinates)
            {
                if (ue5Profile)
                    report.versionEvidenceScore += 5;
            }
            else
            {
                if (!ue5Profile)
                    report.versionEvidenceScore += 2;
            }
            if (schema.optionalPropertySupport.sampleCount != 0)
            {
                const bool optionalEraProfile = profile_.optionalPropertyAvailable;
                if (optionalEraProfile)
                    report.versionEvidenceScore += 5;
            }
            for (const auto &evidence : report.versionEvidence)
            {
                if (evidence.kind == "f-field-owner-encoding")
                {
                    const std::string expected = schema.profileFeatures.fFieldOwnerEncoding == FFieldOwnerEncoding::TaggedPointer
                                                     ? "tagged-pointer"
                                                     : "explicit-discriminator";
                    if (evidence.observed == expected)
                        report.versionEvidenceScore += 3;
                }
                else if (evidence.kind == "uenum-tail-layout" &&
                         evidence.observed == EnumTailLayoutName(schema.profileFeatures.enumTailLayout))
                    report.versionEvidenceScore += 2;
            }
            report.evidence.push_back("schema scores: layout_score=" + std::to_string(report.layoutScore) +
                                      " version_evidence_score=" + std::to_string(report.versionEvidenceScore));
        }
        return report;
    }
} // namespace nextdumper::ue
