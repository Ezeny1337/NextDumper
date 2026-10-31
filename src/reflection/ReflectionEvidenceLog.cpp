#include "ReflectionEvidenceLog.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>
#include <tuple>
#include <unordered_set>

#include "nextdumper/common/Hex.hpp"
#include "nextdumper/ue/FunctionSemantics.hpp"

namespace nextdumper::reflection::detail
{
    using ir::ParseStatus;
    using ir::PropertyIR;
    using ir::PropertyKind;
    using ir::TypeReferenceIR;
    using ::nextdumper::common::Hex;

    void LogReflectionEvidence(const ir::ReflectionIR &reflection, uintptr_t moduleBase,
                               const std::function<void(const std::string &)> &diagnostic)
    {
        if (!diagnostic)
            return;
        std::unordered_set<uintptr_t> owners;
        const auto logOwner = [&](uintptr_t address, const std::string &name)
        {
            if (owners.insert(address).second)
            {
                std::ostringstream line;
                line << "reflection_owner address=" << Hex(address) << " full_name=" << std::quoted(name);
                diagnostic(line.str());
            }
        };
        std::map<std::string, size_t> entryKinds;
        using EntryKey = std::tuple<uintptr_t, bool, bool, bool>;
        std::map<EntryKey, size_t> entryIds;
        std::map<EntryKey, size_t> entryCounts;
        for (const auto &[address, function] : reflection.functions)
        {
            (void)address;
            ++entryKinds[function.EntryKind()];
            const EntryKey key{function.execEntry, function.entryReadable, function.entryExecutable, function.entryInModule};
            ++entryCounts[key];
        }
        diagnostic("function_entry_summary definitions=" + std::to_string(reflection.functions.size()) +
                   " parsed=" + std::to_string(reflection.stats.parsedFunctions) +
                   " rva_semantics=reflected-exec-entry-not-business-implementation");
        diagnostic("function_entry_defaults class=Function header_readable=1 consistent=1 semantics_valid=1 status=Complete return=65535 default_initializers=0 readable=1 executable=1 in_module=1 native=flags&0x400 native_exec_available=native&&in_module&&executable");
        for (const auto &[kind, count] : entryKinds)
            diagnostic("function_entry_kind kind=" + kind + " count=" + std::to_string(count));
        for (const auto &[key, count] : entryCounts)
        {
            if (count == 1)
                continue;
            const size_t id = entryIds.size();
            entryIds.emplace(key, id);
        }
        std::unordered_set<size_t> loggedEntries;
        const auto logEntry = [&](const EntryKey &key, size_t id)
        {
            if (!loggedEntries.insert(id).second)
                return;
            const auto &[entry, readable, executable, inModule] = key;
            std::ostringstream line;
            line << "exec_entry_context id=" << id << " entry=" << Hex(entry)
                 << " functions=" << entryCounts.at(key);
            if (!readable)
                line << " readable=0";
            if (!executable)
                line << " executable=0";
            if (!inModule)
                line << " in_module=0";
            if (inModule)
                line << " rva=" << Hex(entry - moduleBase);
            diagnostic(line.str());
        };
        diagnostic("delegate_signature_summary total=" + std::to_string(reflection.delegateSignatures.size()) +
                   " exported=" + std::to_string(std::count_if(reflection.delegateSignatures.begin(), reflection.delegateSignatures.end(), [](const auto &item)
                                                               { return item.exported; })));
        std::map<std::string, size_t> definitionStatuses;
        for (const auto &signature : reflection.delegateSignatures)
            ++definitionStatuses[signature.definitionStatus];
        for (const auto &[status, count] : definitionStatuses)
            diagnostic("delegate_signature_definition_status status=" + status + " count=" + std::to_string(count));
        // 签名数量随 delegate 类型增长，逐条输出会淹没其余证据
        // 完整记录在 reflection 分片的 functions 段，这里只保留有界样本
        constexpr size_t kDelegateSignatureSamples = 32;
        size_t delegateSignatureLogged = 0;
        for (const auto &signature : reflection.delegateSignatures)
        {
            if (delegateSignatureLogged >= kDelegateSignatureSamples)
                continue;
            ++delegateSignatureLogged;
            std::ostringstream line;
            line << "delegate_signature address=" << Hex(signature.address) << " outer=" << Hex(signature.outerAddress)
                 << " children_root=" << Hex(signature.childrenRoot)
                 << " exported=" << signature.exported << " owner_exported=" << signature.ownerExported
                 << " found_in_children=" << signature.foundInChildren << " children_root_readable=" << signature.childrenRootReadable
                 << " children_status=" << signature.childrenStatus << " definition_status=" << signature.definitionStatus
                 << " discovery=" << signature.discovery;
            if (!signature.exported)
                line << " full_name=" << std::quoted(signature.fullName) << " class=" << signature.reflectedClass
                     << " outer_class=" << signature.outerClass << " outer_full_name=" << std::quoted(signature.outerFullName)
                     << " outer_readable=" << signature.outerReadable;
            diagnostic(line.str());
        }
        if (reflection.delegateSignatures.size() > delegateSignatureLogged)
            diagnostic("delegate_signature_log_omitted records_omitted=" +
                       std::to_string(reflection.delegateSignatures.size() - delegateSignatureLogged) +
                       " samples=" + std::to_string(delegateSignatureLogged) +
                       " full_records=reflection.json/functions");
        constexpr size_t kPropertyDiagnosticSamples = 8;
        constexpr size_t kPropertyDetailSamples = 8;
        constexpr size_t kPropertyDetailReadSamples = 2;
        std::map<std::string, size_t> propertyDiagnosticSamples;
        std::map<std::string, size_t> propertyDiagnosticOmitted;
        std::map<std::string, size_t> propertyDetailSamples;
        std::map<std::string, size_t> propertyDetailOmitted;
        std::map<std::string, size_t> propertyReadOmitted;
        constexpr size_t kDelegateSamplesPerKind = 32;
        std::map<std::string, size_t> delegateSamples;
        std::map<std::string, size_t> delegateOmitted;
        const auto propertyEvidence = [&](const PropertyIR &property, const std::string &owner, uintptr_t ownerAddress, const char *scope)
        {
            for (const auto &message : property.diagnostics)
            {
                const std::string key = message.substr(0, message.find(' '));
                auto &seen = propertyDiagnosticSamples[key];
                if (seen >= kPropertyDiagnosticSamples)
                {
                    ++propertyDiagnosticOmitted[key];
                    continue;
                }
                ++seen;
                std::ostringstream line;
                line << "property_diagnostic owner=" << std::quoted(owner) << " owner_address=" << Hex(ownerAddress)
                     << " scope=" << scope << " property=" << std::quoted(property.name)
                     << " address=" << Hex(property.address) << " message=" << std::quoted(message);
                diagnostic(line.str());
            }
            for (const auto &detail : property.detailDiagnostics)
            {
                const std::string key = detail.reason + ":" + detail.normalizedClass;
                auto &seen = propertyDetailSamples[key];
                if (seen >= kPropertyDetailSamples)
                {
                    ++propertyDetailOmitted[key];
                    continue;
                }
                ++seen;
                std::ostringstream line;
                line << "property_detail owner=" << std::quoted(owner) << " scope=" << scope
                     << " root=" << std::quoted(property.name) << " root_address=" << Hex(property.address)
                     << " node=" << std::quoted(detail.name) << " address=" << Hex(detail.address)
                     << " class=" << std::quoted(detail.reflectedClass) << " class_address=" << Hex(detail.classAddress)
                     << " next=" << Hex(detail.nextAddress) << " immediate_owner=" << Hex(detail.immediateOwner)
                     << " owner_is_uobject=" << detail.ownerIsUObject << " header_available=" << detail.headerAvailable
                     << " reason=" << detail.reason << " status=" << detail.detailsStatus
                     << " offset=" << detail.offset << " element_size=" << detail.elementSize << " array_dim=" << detail.arrayDim
                     << " flags=" << detail.flags << " reference=" << Hex(detail.referencedAddress) << " secondary=" << Hex(detail.secondaryAddress)
                     << " reference_class=" << std::quoted(detail.referencedClass) << " secondary_class=" << std::quoted(detail.secondaryClass)
                     << " object_class_null=" << detail.objectPropertyClassNull
                     << " object_class_pointer_address=" << Hex(detail.objectPropertyClassPointerAddress)
                     << " bool_field_size=" << static_cast<unsigned int>(detail.boolean.fieldSize)
                     << " bool_byte_offset=" << static_cast<unsigned int>(detail.boolean.byteOffset)
                     << " bool_byte_mask=" << static_cast<unsigned int>(detail.boolean.byteMask)
                     << " bool_field_mask=" << static_cast<unsigned int>(detail.boolean.fieldMask);
                diagnostic(line.str());
                size_t readsEmitted = 0;
                for (const auto &read : detail.reads)
                {
                    if (readsEmitted++ >= kPropertyDetailReadSamples)
                    {
                        ++propertyReadOmitted[key];
                        continue;
                    }
                    diagnostic("property_detail_read node=" + Hex(detail.address) +
                               " member=" + read.member + " selected_offset=" + std::to_string(read.offset) +
                               " address=" + Hex(read.address) + " raw=" + std::to_string(read.rawValue) +
                               " error=" + std::to_string(read.error) + " requested=" + std::to_string(read.requested) +
                               " transferred=" + std::to_string(read.transferred) + " status=" + read.status);
                }
            }
            size_t remaining = 256;
            const auto references = [&](const auto &self, const TypeReferenceIR &reference, const std::string &path, size_t depth) -> void
            {
                if (depth >= 32 || remaining == 0)
                {
                    diagnostic("delegate_reference traversal_limit=1 root=" + Hex(property.address) + " path=" + path);
                    return;
                }
                --remaining;
                if (reference.kind == PropertyKind::Delegate || reference.kind == PropertyKind::MulticastDelegate)
                {
                    const std::string kind = std::string("delegate:") +
                                             ::nextdumper::ir::DelegateStorageKindName(reference.delegateStorage);
                    if (delegateSamples[kind]++ >= kDelegateSamplesPerKind)
                    {
                        ++delegateOmitted[kind];
                    }
                    else
                    {
                        logOwner(ownerAddress, owner);
                        std::ostringstream line;
                        line << "delegate_reference owner=" << Hex(ownerAddress) << " scope=" << scope
                             << " root=" << std::quoted(property.name) << " root_address=" << Hex(property.address)
                             << " path=" << path << " node=" << Hex(reference.metadataAddress)
                             << " class=" << reference.reflectedClass
                             << " storage_kind=" << ::nextdumper::ir::DelegateStorageKindName(reference.delegateStorage)
                             << " signature=" << Hex(reference.referencedObject)
                             << " details_resolved=" << reference.detailsResolved;
                        diagnostic(line.str());
                    }
                }
                if (reference.inner)
                    self(self, *reference.inner, path + ".inner", depth + 1);
                if (reference.key)
                    self(self, *reference.key, path + ".key", depth + 1);
                if (reference.value)
                    self(self, *reference.value, path + ".value", depth + 1);
            };
            references(references, property.type, "type", 0);
        };
        constexpr size_t kConflictSamplesPerKind = 24;
        std::map<std::string, size_t> conflictSamples;
        std::map<std::string, size_t> conflictOmitted;
        for (const auto &type : reflection.types)
        {
            for (const auto &message : type.layoutConflicts)
            {
                const std::string kind = message.substr(0, message.find_first_of(": ="));
                if (conflictSamples[kind]++ >= kConflictSamplesPerKind)
                {
                    ++conflictOmitted[kind];
                    continue;
                }
                diagnostic("type_conflict owner=" + type.fullName + " address=" + Hex(type.address) + " message=" + message);
            }
            for (const auto &property : type.properties)
                propertyEvidence(property, type.fullName, type.address, "type-field");
        }
        std::map<std::string, size_t> normalEntrySamples;
        std::map<std::string, size_t> normalEntryOmitted;
        constexpr size_t kAnomalyEntrySamples = 48;
        std::map<std::string, size_t> anomalyEntrySamples;
        std::map<std::string, size_t> anomalyEntryOmitted;
        diagnostic("function_entry_log_policy normal_samples_per_kind=8 anomaly_samples_per_class=" +
                   std::to_string(kAnomalyEntrySamples) +
                   " full_records=reflection.json/functions");
        for (const auto &[address, function] : reflection.functions)
        {
            const bool normal = !function.referencedAsSignature && function.reflectedClass == "Function" &&
                                function.headerReadable && function.parameterSemanticsConsistent && function.parameterSemanticsValid &&
                                function.status == ParseStatus::Complete && function.layoutConflicts.empty() &&
                                function.entryReadable && function.entryExecutable && function.entryInModule &&
                                function.nativeFlag == ((function.flags & ::nextdumper::ue::kFUNCNative) != 0) &&
                                function.nativeExecRva.has_value() == function.nativeFlag;
            bool emitEntry = true;
            if (normal)
            {
                auto &samples = normalEntrySamples[function.EntryKind()];
                if (samples < 8)
                    ++samples;
                else
                {
                    ++normalEntryOmitted[function.EntryKind()];
                    emitEntry = false;
                }
            }
            else
            {
                std::string kind = function.referencedAsSignature ? "signature" : "anomaly";
                if (!function.headerReadable)
                    kind += ":header-unreadable";
                else if (!function.parameterSemanticsValid || !function.parameterSemanticsConsistent)
                    kind += ":parameter-semantics";
                else if (!function.layoutConflicts.empty())
                    kind += ":layout-conflict";
                else if (!function.entryExecutable || !function.entryInModule)
                    kind += ":entry-unusable";
                else if (function.reflectedClass != "Function")
                    kind += ":class-" + function.reflectedClass;
                if (anomalyEntrySamples[kind]++ >= kAnomalyEntrySamples)
                {
                    ++anomalyEntryOmitted[kind];
                    emitEntry = false;
                }
            }
            if (emitEntry)
            {
                logOwner(function.outerAddress, function.outerFullName);
                const EntryKey key{function.execEntry, function.entryReadable, function.entryExecutable, function.entryInModule};
                std::ostringstream line;
                line << "function_entry address=" << Hex(address) << " owner=" << Hex(function.outerAddress)
                     << " flags=" << Hex(function.flags);
                if (const auto id = entryIds.find(key); id != entryIds.end())
                {
                    logEntry(key, id->second);
                    line << " entry_id=" << id->second;
                }
                else
                {
                    line << " entry=" << Hex(function.execEntry);
                    if (!function.entryReadable)
                        line << " readable=0";
                    if (!function.entryExecutable)
                        line << " executable=0";
                    if (!function.entryInModule)
                        line << " in_module=0";
                    if (function.execEntryRva)
                        line << " rva=" << Hex(*function.execEntryRva);
                }
                line << " name=" << std::quoted(function.name)
                     << " params=" << static_cast<unsigned int>(function.headerNumParams) << '/' << function.headerParamSize;
                if (function.reflectedClass != "Function")
                    line << " class=" << function.reflectedClass;
                if (!function.headerReadable)
                    line << " header_readable=0";
                if (!function.parameterSemanticsConsistent)
                    line << " consistent=0";
                if (!function.parameterSemanticsValid)
                    line << " semantics_valid=0";
                if (function.nativeFlag != ((function.flags & ::nextdumper::ue::kFUNCNative) != 0))
                    line << " native=" << function.nativeFlag;
                if (function.nativeExecRva.has_value() !=
                    (function.nativeFlag && function.entryInModule && function.entryExecutable))
                    line << " native_exec_available=" << function.nativeExecRva.has_value();
                if (function.status != ParseStatus::Complete)
                    line << " status=" << ParseStatusName(function.status);
                if (function.returnValueOffset != 0xFFFFu)
                    line << " return=" << function.returnValueOffset;
                if (function.defaultInitializerCount != 0)
                    line << " default_initializers=" << function.defaultInitializerCount;
                if (!function.parameterSemanticsConsistent)
                    line << " derived_params=" << function.derivedNumParams << '/' << function.derivedParamSize;
                diagnostic(line.str());
            }
            for (const auto &message : function.layoutConflicts)
            {
                const std::string kind = "function:" + message.substr(0, message.find_first_of(": ="));
                if (conflictSamples[kind]++ >= kConflictSamplesPerKind)
                {
                    ++conflictOmitted[kind];
                    continue;
                }
                diagnostic("function_conflict address=" + Hex(address) + " message=" + message);
            }
            for (const auto &property : function.parameters)
                propertyEvidence(property, function.fullName, address, "function-parameter");
            for (const auto &property : function.locals)
                propertyEvidence(property, function.fullName, address, "function-local");
        }
        for (const auto &[kind, count] : normalEntryOmitted)
            diagnostic("function_entry_log_omitted kind=" + kind + " normal_records=" + std::to_string(count) +
                       " samples=" + std::to_string(normalEntrySamples.at(kind)) + " full_records=reflection.json/functions");
        diagnostic("container_storage_probe metadata=all-visited-nodes instance_traversal_validated=0 max_raw_observations=512 max_normal_owners_per_shape=2 exceptional_fields=individual-within-global-budget max_raw_candidates=8192 priority=final-representation-gaps-first sparse_check=conditional-formula-with-recorded-alignment raw_accounting_valid=" +
                   std::to_string(reflection.containerEvidenceAccountingValid));
        for (const auto &[allocator, count] : reflection.containerAllocatorCounts)
            diagnostic("container_allocator_summary allocator=" + allocator + " nodes=" + std::to_string(count));
        for (const auto &[status, count] : reflection.containerHeaderCounts)
            diagnostic("container_header_summary status=" + status + " nodes=" + std::to_string(count));
        for (const auto &[status, count] : reflection.containerElementLayoutCounts)
            diagnostic("container_element_layout_summary status=" + status + " nodes=" + std::to_string(count));
        for (const auto &[kind, count] : reflection.containerStorageCandidates)
            diagnostic("container_storage_candidates class=" + kind + " count=" + std::to_string(count));
        for (const auto &[reason, count] : reflection.containerStorageNotObserved)
            diagnostic("container_storage_not_observed reason=" + reason + " count=" + std::to_string(count));
        std::map<std::string, size_t> rawLogSamples;
        std::map<std::string, size_t> rawLogOmitted;
        for (const auto &observation : reflection.containerStorageObservations)
        {
            if (observation.sampleReason == "normal-shape-representative" &&
                ++rawLogSamples[observation.propertyClass] > 8)
            {
                ++rawLogOmitted[observation.propertyClass];
                continue;
            }
            std::ostringstream line;
            line << "container_storage_candidate property=" << Hex(observation.propertyAddress)
                 << " owner=" << Hex(observation.ownerAddress) << " address=" << Hex(observation.address)
                 << " owner_is_uobject=" << observation.ownerIsUObject
                 << " name=" << std::quoted(observation.propertyName) << " class=" << observation.propertyClass
                 << " member=" << observation.member << " offset=" << observation.offset
                 << " reference_offset=" << observation.referenceOffset << " property_data_end=" << observation.propertyDataEnd
                 << " storage_size=" << observation.storageSize << " inner_size=" << observation.innerSize
                 << " inner_class=" << observation.innerClass << " value_size=" << observation.valueSize
                 << " value_class=" << observation.valueClass << " readable=" << observation.readable
                 << " read_error=" << observation.readError << " requested=" << observation.requested
                 << " transferred=" << observation.transferred
                 << " status=" << observation.status << " basis=" << std::quoted(observation.basis)
                 << " allocator=" << ::nextdumper::ir::ContainerAllocatorKindName(observation.storage.allocator)
                 << " allocator_status=" << observation.storage.allocatorStatus
                 << " header_status=" << observation.storage.headerStatus
                 << " element_layout_status=" << observation.storage.layoutStatus
                 << " layout_id=" << observation.storage.layoutId;
            line << " sample_reason=" << observation.sampleReason;
            if (observation.sparseFormulaMatches)
                line << " sparse_formula_matches=" << *observation.sparseFormulaMatches;
            line << " bytes=" << std::hex << std::setfill('0');
            for (uint8_t byte : observation.bytes)
                line << std::setw(2) << static_cast<unsigned int>(byte);
            diagnostic(line.str());
            for (const auto &flag : observation.flagCandidates)
                diagnostic("container_flag_candidate property=" + Hex(observation.propertyAddress) +
                           " offset=" + std::to_string(flag.offset) + " width=" + std::to_string(flag.width) +
                           " raw=" + std::to_string(flag.raw) + " known_value=" + std::to_string(flag.knownValue) +
                           " basis=" + flag.basis + " width_selected=0");
        }
        for (const auto &[kind, count] : rawLogOmitted)
            diagnostic("container_storage_log_omitted class=" + kind + " normal_records=" + std::to_string(count) +
                       " samples=8 full_records=reflection.json/container_storage_evidence/observations");
        for (const auto &[key, count] : propertyDiagnosticOmitted)
            diagnostic("property_diagnostic_log_omitted reason=" + key + " records_omitted=" + std::to_string(count) +
                       " samples=" + std::to_string(kPropertyDiagnosticSamples) +
                       " full_records=reflection.json/property_diagnostics");
        for (const auto &[key, count] : propertyDetailOmitted)
            diagnostic("property_detail_log_omitted key=" + key + " records_omitted=" + std::to_string(count) +
                       " samples=" + std::to_string(kPropertyDetailSamples) +
                       " full_records=reflection.json/property_diagnostics");
        for (const auto &[key, count] : propertyReadOmitted)
            diagnostic("property_detail_read_log_omitted key=" + key + " records_omitted=" + std::to_string(count) +
                       " samples_per_detail=" + std::to_string(kPropertyDetailReadSamples) +
                       " full_records=reflection.json/property_diagnostics");
        for (const auto &[kind, count] : conflictOmitted)
            diagnostic("conflict_log_omitted kind=" + kind + " records_omitted=" + std::to_string(count) +
                       " samples=" + std::to_string(kConflictSamplesPerKind) +
                       " full_records=reflection.json/types-and-functions");
        for (const auto &[kind, count] : anomalyEntryOmitted)
            diagnostic("function_entry_anomaly_omitted kind=" + kind + " records_omitted=" + std::to_string(count) +
                       " samples=" + std::to_string(kAnomalyEntrySamples) +
                       " full_records=reflection.json/functions");
        for (const auto &[kind, count] : delegateOmitted)
            diagnostic("delegate_reference_log_omitted kind=" + kind + " records_omitted=" + std::to_string(count) +
                       " samples=" + std::to_string(kDelegateSamplesPerKind) +
                       " full_records=reflection.json/property_types");
        for (const auto &enumeration : reflection.enums)
            for (const auto &message : enumeration.diagnostics)
                diagnostic("enum_diagnostic owner=" + enumeration.fullName + " address=" + Hex(enumeration.address) + " message=" + message);
    }

} // namespace nextdumper::reflection::detail
