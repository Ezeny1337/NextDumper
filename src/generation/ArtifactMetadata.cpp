#include "ArtifactMetadata.hpp"
#include "Formatting.hpp"

#include <ostream>

#include "nextdumper/generation/JsonExport.hpp"

namespace nextdumper::generation::detail
{
    using ::nextdumper::app::RuntimeContext;
    using ::nextdumper::binding::NameContainerKind;
    using ::nextdumper::binding::ObjectContainerKind;
    using ::nextdumper::binding::RuntimeBinding;
    using ::nextdumper::ir::ReflectionStats;
    using ::nextdumper::ir::TypeIR;
    using ::nextdumper::ue::EngineSchema;
    using ::nextdumper::ue::FNameDisplayLayout;
    using ::nextdumper::ue::FNameNumberLayout;
    using ::nextdumper::ue::SchemaLayoutVariantName;

    void ManifestJson(std::ostream &stream, const RuntimeContext &context, const ReflectionIR &reflection,
                      const std::string &packageName, const ArtifactProvenance &provenance,
                      const GenerationReport &report, ParseStatus status)
    {
        const ReflectionStats &stats = reflection.stats;
        stream << "{\n";
        stream << "  \"schema_version\": 9,\n";
        stream << "  \"package\": \"" << EscapeJson(packageName) << "\",\n";
        stream << "  \"engine\": \"" << EscapeJson(context.Schema().identity.canonicalVersionRange.empty() ? context.Schema().validation.familyEvidence : context.Schema().identity.canonicalVersionRange) << "\",\n";
        stream << "  \"profile\": {\"id\":\""
               << EscapeJson(context.Schema().validation.profileId) << "\",\"label\":\""
               << EscapeJson(context.Schema().validation.profileLabel) << "\",\"version_range\":\""
               << EscapeJson(context.Schema().validation.profileVersionRange) << "\"},\n";
        stream << "  \"schema_identity\":";
        WriteSchemaIdentityJson(stream, context.Schema().identity);
        stream << ",\n";
        stream << "  \"status\": \"" << ParseStatusName(status) << "\",\n";
        stream << "  \"reflection_status\": \"" << ParseStatusName(reflection.status) << "\",\n";
        stream << "  \"sdk_status\": \"" << ParseStatusName(report.Status()) << "\",\n";
        stream << "  \"artifact_kind\": \"" << (status == ParseStatus::Partial ? "partial" : "complete") << "\",\n";
        stream << "  \"module\": \"" << EscapeJson(context.Module().name) << "\",\n";
        stream << "  \"provenance\":{\"producer_commit\":\"" << EscapeJson(provenance.producerCommit)
               << "\",\"producer_version\":\"" << EscapeJson(provenance.producerVersion)
               << "\",\"producer_worktree_at_configure\":\"" << EscapeJson(provenance.producerWorktree) << '"'
               << ",\"producer_identity_source\":\"cmake-configure\""
               << ",\"run_id\":\"" << EscapeJson(provenance.runId) << "\",\"target_pid\":" << provenance.targetPid
               << ",\"run_timestamp\":\"" << EscapeJson(provenance.runTimestamp) << "\""
               << ",\"address_space_generation\":" << provenance.addressSpaceGeneration
               << ",\"architecture\":\"" << module::ModuleArchitectureName(context.Module().architecture)
               << "\",\"pointer_width\":" << static_cast<unsigned int>(context.Module().pointerWidth)
               << ",\"module_base\":\"" << Hex(context.Module().base) << "\",\"module_end\":\"" << Hex(context.Module().end)
               << "\",\"module_identity\":\"mapped-segments; not a content hash\"},\n";
        stream << "  \"stats\": {\n";
        stream << "    \"object_slots\": " << stats.objectSlots << ",\n";
        stream << "    \"valid_objects\": " << stats.validObjects << ",\n";
        stream << "    \"parsed_types\": " << stats.parsedTypes << ",\n";
        stream << "    \"parsed_enums\": " << stats.parsedEnums << ",\n";
        stream << "    \"parsed_functions\": " << stats.parsedFunctions << ",\n";
        stream << "    \"parsed_properties\": " << stats.parsedProperties << ",\n";
        stream << "    \"unknown_properties\": " << stats.unknownProperties << ",\n";
        stream << "    \"unresolved_type_details\": " << stats.unresolvedTypeDetails << ",\n";
        stream << "    \"layout_conflicts\": " << stats.layoutConflicts << ",\n";
        stream << "    \"skipped_objects\": " << stats.skippedObjects << ",\n";
        stream << "    \"empty_object_slots\": " << stats.emptyObjectSlots << ",\n";
        stream << "    \"object_read_failures\": " << stats.objectReadFailures << ",\n";
        stream << "    \"class_name_read_failures\": " << stats.classNameReadFailures << ",\n";
        stream << "    \"skipped_class_default_objects\": " << stats.skippedClassDefaultObjects << ",\n";
        stream << "    \"skipped_incomplete_objects\": " << stats.skippedIncompleteObjects << ",\n";
        stream << "    \"object_diagnostic_samples_omitted\": " << stats.objectDiagnosticSamplesOmitted << ",\n";
        stream << "    \"failures\": " << stats.failures << ",\n";
        stream << "    \"enum_read_failures\": " << stats.enumReadFailures << ",\n";
        stream << "    \"identity_failures\": " << stats.identityFailures << ",\n";
        stream << "    \"unvisited_objects\": " << stats.unvisitedObjects << ",\n";
        stream << "    \"opaque_fields\": " << report.opaqueFields << ",\n";
        stream << "    \"omitted_fields\": " << report.omittedFields << ",\n";
        stream << "    \"sdk_layout_warnings\": " << report.layoutWarnings << ",\n";
        stream << "    \"sdk_layout_events\": " << report.layoutEvents << "\n";
        stream << "  },\n  \"capture\":";
        WriteCaptureJson(stream, reflection.capture);
        stream << ",\n  \"runtime_value_evidence\":";
        WriteRuntimeEvidenceJson(stream, reflection.runtimeEvidence, false);
        stream << '\n';
        stream << "}\n";
    }

    void DiagnosticsJson(std::ostream &stream, const RuntimeContext &context, const ReflectionIR &reflection,
                         const GenerationReport &report, ParseStatus status)
    {
        stream << "{\n  \"schema_version\": 9,\n  \"status\": \""
               << ParseStatusName(status) << "\",\n";
        stream << "  \"reflection_status\":\"" << ParseStatusName(reflection.status) << "\",\n";
        stream << "  \"sdk_status\":\"" << ParseStatusName(report.Status()) << "\",\n";
        stream << "  \"schema_identity\":";
        WriteSchemaIdentityJson(stream, context.Schema().identity);
        stream << ",\n";
        stream << "  \"summary\": {\"unknown_properties\": " << reflection.stats.unknownProperties
               << ", \"unresolved_type_details\": " << reflection.stats.unresolvedTypeDetails
               << ", \"layout_conflicts\": " << reflection.stats.layoutConflicts
               << ", \"skipped_objects\": " << reflection.stats.skippedObjects
               << ", \"empty_object_slots\": " << reflection.stats.emptyObjectSlots
               << ", \"object_read_failures\": " << reflection.stats.objectReadFailures
               << ", \"class_name_read_failures\": " << reflection.stats.classNameReadFailures
               << ", \"skipped_class_default_objects\": " << reflection.stats.skippedClassDefaultObjects
               << ", \"skipped_incomplete_objects\": " << reflection.stats.skippedIncompleteObjects
               << ", \"object_diagnostic_samples_omitted\": " << reflection.stats.objectDiagnosticSamplesOmitted
               << ", \"enum_read_failures\": " << reflection.stats.enumReadFailures
               << ", \"identity_failures\": " << reflection.stats.identityFailures
               << ", \"unvisited_objects\": " << reflection.stats.unvisitedObjects
               << ", \"opaque_fields\": " << report.opaqueFields << ", \"omitted_fields\": " << report.omittedFields
               << ", \"sdk_layout_warnings\": " << report.layoutWarnings
               << ", \"sdk_layout_events\": " << report.layoutEvents
               << ", \"failures\": " << reflection.stats.failures << "},\n";
        stream << "  \"capture\":";
        WriteCaptureJson(stream, reflection.capture);
        stream << ",\n  \"property_diagnostics\":";
        WritePropertyDiagnosticsJson(stream, reflection);
        stream << ",\n  \"storage_representation_counts\":{";
        bool firstStorage = true;
        for (const auto &[kind, count] : report.storageKinds)
        {
            if (!firstStorage)
                stream << ',';
            firstStorage = false;
            stream << '"' << PropertyStorageKindName(kind) << "\":" << count;
        }
        stream << '}';
        stream << ",\n  \"opaque_fields_by_reason\":{";
        bool firstOpaqueReason = true;
        for (const auto &[reason, count] : report.opaqueReasons)
        {
            if (!firstOpaqueReason)
                stream << ',';
            firstOpaqueReason = false;
            stream << '"' << EscapeJson(reason) << "\":" << count;
        }
        stream << '}';
        stream << ",\n  \"opaque_cpp_representation_failures\":[";
        bool firstRepresentationFailure = true;
        for (const auto &[key, count] : report.cppRepresentationFailures)
        {
            if (!firstRepresentationFailure)
                stream << ',';
            firstRepresentationFailure = false;
            stream << "{\"reason\":\"" << EscapeJson(key.first) << "\",\"property_class\":\""
                   << EscapeJson(key.second) << "\",\"count\":" << count << '}';
        }
        stream << ']';
        stream << ",\n  \"generation_owners\":[";
        bool firstOwner = true;
        for (const auto &[address, owner] : report.owners)
        {
            if (!firstOwner)
                stream << ',';
            firstOwner = false;
            stream << "{\"address\":\"" << Hex(address)
                   << "\",\"scope\":\"" << EscapeJson(owner.scope) << '"'
                   << ",\"initial_cursor\":" << owner.initialCursor;
            if (address == 0)
                stream << ",\"full_name\":\"" << EscapeJson(owner.fullName) << '"';
            if (owner.superAddress != 0)
                stream << ",\"super_address\":\"" << Hex(owner.superAddress)
                       << "\",\"base_size\":" << owner.baseSize;
            stream << '}';
        }
        stream << "],\n  \"generation_report\":{\"total\":" << report.layoutEvents
               << ",\"warnings\":" << report.layoutWarnings
               << ",\"records_omitted\":0,\"record_encoding\":\"reflection-layout-issue-reference-or-emission-event\",\"counts_by_category\":{";
        bool firstCategory = true;
        for (const auto &[category, count] : report.counts)
        {
            if (!firstCategory)
                stream << ',';
            firstCategory = false;
            stream << '"' << EscapeJson(category) << "\":" << count;
        }
        stream << "},\"records\":[";
        for (size_t index = 0; index < report.events.size(); ++index)
        {
            if (index != 0)
                stream << ',';
            const auto &event = report.events[index];
            if (event.layoutIssueIndex)
            {
                stream << "{\"owner\":\"" << Hex(event.ownerAddress)
                       << "\",\"layout_issue_index\":" << *event.layoutIssueIndex << '}';
                continue;
            }
            stream << "{\"severity\":\"" << EscapeJson(event.severity)
                   << "\",\"category\":\"" << EscapeJson(event.category)
                   << "\",\"owner\":\"" << Hex(event.ownerAddress)
                   << "\",\"cursor_source\":\"" << EscapeJson(event.cursorSource)
                   << "\",\"emission_strategy\":\"" << EscapeJson(event.strategy) << '"';
            if (event.severity == "error")
                stream << ",\"message\":\"" << EscapeJson(event.message) << '"';
            if (event.property)
            {
                const auto &property = *event.property;
                stream << ",\"property\":\"" << Hex(property.address) << '"';
            }
            if (event.conflictingAddress != 0)
                stream << ",\"conflicting_address\":\"" << Hex(event.conflictingAddress) << '"';
            if (event.cursorSource != "layout-analysis")
                stream << ",\"cursor_before\":" << event.cursor;
            stream << '}';
        }
        stream << "]},\n  \"opaque_fields\":[";
        for (size_t index = 0; index < report.opaqueDetails.size(); ++index)
        {
            if (index != 0)
                stream << ',';
            const auto &field = report.opaqueDetails[index];
            const auto &property = *field.property;
            const auto &reason = report.fields.at(property.address).type.failureReason;
            stream << "{\"owner\":\"" << Hex(field.ownerAddress) << "\",\"property\":\"" << Hex(property.address)
                   << "\",\"reason\":\"" << EscapeJson(field.reason) << '"';
            if (!reason.empty() && reason != "internals-not-expanded" && reason != "container-internals-not-expanded")
            {
                stream << ",\"failure_path\":\"" << EscapeJson(field.failurePath)
                       << "\",\"failure_node\":";
                if (field.failureNode)
                    stream << '"' << Hex(field.failureNode->metadataAddress) << '"';
                else
                    stream << "null";
            }
            stream << '}';
        }
        stream << "],\n  \"reflection_evidence\":{\"artifact\":\"reflection.json\",\"owner_join_key\":\"types/functions.address\",\"property_join_key\":\"address\",\"generation_types\":\"property.generation.type_id -> generation_types.id\",\"layout_issues\":\"owner.layout_analysis.issues[layout_issue_index]\",\"delegate_signatures\":\"delegate_signatures\",\"container_storage\":\"container_storage_evidence\",\"runtime_values\":\"runtime_value_evidence\"}";
        stream << ",\n  \"runtime_value_evidence\":";
        WriteRuntimeEvidenceJson(stream, reflection.runtimeEvidence, false);
        stream << ",\n";
        stream << "  \"diagnostics\": [";
        for (size_t index = 0; index < reflection.diagnostics.size(); ++index)
        {
            if (index != 0)
                stream << ',';
            stream << "\"" << EscapeJson(reflection.diagnostics[index]) << "\"";
        }
        stream << "],\n";
        stream << "  \"type_conflicts\": [\n";
        size_t conflictCount = 0;
        for (const TypeIR &type : reflection.types)
        {
            for (const std::string &conflict : type.layoutConflicts)
            {
                if (conflictCount++ != 0)
                    stream << ",\n";
                stream << "    {\"type\":\"" << EscapeJson(type.fullName) << "\",\"address\":\"" << Hex(type.address)
                       << "\",\"message\":\""
                       << EscapeJson(conflict) << "\"}";
            }
        }
        stream << "\n  ],\n  \"function_conflicts\": [\n";
        conflictCount = 0;
        for (const auto &[address, function] : reflection.functions)
        {
            for (const std::string &conflict : function.layoutConflicts)
            {
                if (conflictCount++ != 0)
                    stream << ",\n";
                stream << "    {\"function\":\"" << EscapeJson(function.fullName) << "\",\"address\":\"" << Hex(address)
                       << "\",\"message\":\"" << EscapeJson(conflict) << "\"}";
            }
        }
        stream << "\n  ],\n  \"enum_conflicts\": [\n";
        conflictCount = 0;
        for (const auto &enumeration : reflection.enums)
        {
            for (const auto &message : enumeration.diagnostics)
            {
                if (conflictCount++ != 0)
                    stream << ",\n";
                stream << "    {\"enum\":\"" << EscapeJson(enumeration.fullName) << "\",\"address\":\""
                       << Hex(enumeration.address) << "\",\"message\":\"" << EscapeJson(message) << "\"}";
            }
        }
        stream << "\n  ]\n}\n";
    }

    void RuntimeJson(std::ostream &stream, const RuntimeContext &context)
    {
        const RuntimeBinding &binding = context.Binding();
        const EngineSchema &schema = context.Schema();
        stream << "{\n  \"schema_version\": 5,\n";
        stream << "  \"engine\": \"" << EscapeJson(schema.identity.canonicalVersionRange.empty() ? schema.validation.familyEvidence : schema.identity.canonicalVersionRange) << "\",\n";
        stream << "  \"profile\": {\"id\":\"" << EscapeJson(schema.validation.profileId)
               << "\",\"label\":\"" << EscapeJson(schema.validation.profileLabel)
               << "\",\"version_range\":\"" << EscapeJson(schema.validation.profileVersionRange)
               << "\",\"layout\":\"" << SchemaLayoutVariantName(schema.layout) << "\"},\n";
        stream << "  \"schema_identity\":";
        WriteSchemaIdentityJson(stream, schema.identity);
        stream << ",\n";
        stream << "  \"feature_evidence\": {\"observed_large_world_coordinates\":"
               << (schema.features.largeWorldCoordinates ? "true" : "false")
               << ",\"profile_expected_large_world_coordinates\":"
               << (schema.profileFeatures.largeWorldCoordinates ? "true" : "false")
               << ",\"observed_owner_encoding\":\""
               << (schema.features.fFieldOwnerEncoding == ::nextdumper::ue::FFieldOwnerEncoding::TaggedPointer
                       ? "tagged-pointer"
                       : "explicit-discriminator")
               << "\",\"profile_expected_owner_encoding\":\""
               << (schema.profileFeatures.fFieldOwnerEncoding == ::nextdumper::ue::FFieldOwnerEncoding::TaggedPointer
                       ? "tagged-pointer"
                       : "explicit-discriminator")
               << "\",\"use_fproperty\":" << (schema.features.useFProperty ? "true" : "false")
               << ",\"use_name_pool\":" << (schema.features.useNamePool ? "true" : "false")
               << ",\"case_preserving_name\":" << (schema.features.casePreservingName ? "true" : "false")
               << ",\"outline_number_name\":" << (schema.features.outlineNumberName ? "true" : "false")
               << ",\"observed_enum_tail\":\"" << EnumTailLayoutName(schema.features.enumTailLayout)
               << "\",\"profile_expected_enum_tail\":\"" << EnumTailLayoutName(schema.profileFeatures.enumTailLayout)
               << "\",\"optional_property_sample_count\":" << schema.optionalPropertySupport.sampleCount << "},\n";
        stream << "  \"module\": {\"name\":\"" << EscapeJson(context.Module().name)
               << "\",\"base\":\"" << Hex(context.Module().base) << "\",\"end\":\""
               << Hex(context.Module().end) << "\",\"architecture\":\""
               << module::ModuleArchitectureName(context.Module().architecture) << "\",\"pointer_width\":"
               << static_cast<int>(context.Module().pointerWidth) << "},\n";
        stream << "  \"binding\": {\n";
        stream << "    \"object_root\": \"" << Hex(binding.objectRoot.address) << "\",\n";
        stream << "    \"name_root\": \"" << Hex(binding.nameRoot.address) << "\",\n";
        stream << "    \"objects\": {\"kind\":\""
               << (binding.objects.kind == ObjectContainerKind::Chunked ? "chunked" : "fixed")
               << "\",\"objects_offset\":" << binding.objects.objectsOffset
               << ",\"num_elements_offset\":" << binding.objects.numElementsOffset
               << ",\"max_elements_offset\":" << binding.objects.maxElementsOffset
               << ",\"num_chunks_offset\":" << binding.objects.numChunksOffset
               << ",\"max_chunks_offset\":" << binding.objects.maxChunksOffset
               << ",\"elements_per_chunk\":" << binding.objects.elementsPerChunk
               << ",\"item_object_offset\":" << binding.objects.itemObjectOffset
               << ",\"item_stride\":" << binding.objects.itemStride
               << ",\"packed_pointers\":" << (binding.objects.packedPointers ? "true" : "false")
               << ",\"item_index_offset\":" << binding.objects.itemIndexOffset << "},\n";
        stream << "    \"names\": {\"kind\":\""
               << (binding.names.kind == NameContainerKind::Pool ? "pool" : "array") << "\"";
        if (binding.names.kind == NameContainerKind::Pool)
        {
            stream << ",\"blocks_offset\":" << binding.names.pool.blocksOffset
                   << ",\"current_block_from_blocks\":";
            if (binding.names.pool.currentBlockFromBlocks)
                stream << *binding.names.pool.currentBlockFromBlocks;
            else
                stream << "null";
            stream << ",\"byte_cursor_from_blocks\":";
            if (binding.names.pool.byteCursorFromBlocks)
                stream << *binding.names.pool.byteCursorFromBlocks;
            else
                stream << "null";
            stream << ",\"blocks_bit\":" << binding.names.pool.blocksBit
                   << ",\"entry_stride\":" << binding.names.pool.entryStride
                   << ",\"entry_header_offset\":" << binding.names.pool.entryHeaderOffset
                   << ",\"entry_string_offset\":" << binding.names.pool.entryStringOffset
                   << ",\"entry_length_shift\":" << binding.names.pool.entryLengthShift
                   << ",\"entry_wide_mask\":" << binding.names.pool.entryWideMask;
        }
        else
        {
            stream << ",\"chunks_offset\":" << binding.names.array.chunksOffset
                   << ",\"elements_per_chunk\":" << binding.names.array.elementsPerChunk
                   << ",\"entry_index_offset\":" << binding.names.array.entryIndexOffset
                   << ",\"entry_string_offset\":" << binding.names.array.entryStringOffset;
        }
        stream << "}\n  },\n  \"schema\": {\n";
        stream << "    \"uobject\": {\"vtable\":" << schema.uobject.vtable
               << ",\"flags\":" << schema.uobject.flags
               << ",\"internal_index\":" << schema.uobject.internalIndex
               << ",\"class\":" << schema.uobject.classPointer
               << ",\"name\":" << schema.uobject.name << ",\"outer\":" << schema.uobject.outer << "},\n";
        stream << "    \"fname\": {\"comparison_index\":" << schema.fname.comparisonIndex
               << ",\"number\":" << schema.fname.number
               << ",\"display_index\":" << schema.fname.displayIndex
               << ",\"size\":" << schema.fname.size
               << ",\"number_layout\":\""
               << (schema.fname.numberLayout == FNameNumberLayout::Outlined ? "outlined" : "inline")
               << "\",\"display_layout\":\""
               << (schema.fname.displayLayout == FNameDisplayLayout::BeforeNumber
                       ? "before-number"
                   : schema.fname.displayLayout == FNameDisplayLayout::AfterNumber ? "after-number"
                                                                                   : "none")
               << "\"},\n";
        stream << "    \"ffield\": {\"vtable\":" << schema.ffield.vtable
               << ",\"class\":" << schema.ffield.classPointer
               << ",\"owner\":" << schema.ffield.owner << ",\"next\":" << schema.ffield.next
               << ",\"name\":" << schema.ffield.name
               << ",\"editor_only_metadata\":" << schema.ffield.editorOnlyMetadata
               << ",\"owner_encoding\":\"" << (schema.features.fFieldOwnerEncoding == ::nextdumper::ue::FFieldOwnerEncoding::TaggedPointer ? "tagged-pointer" : "explicit-discriminator") << "\"},\n";
        stream << "    \"ffield_class\": {\"name\":" << schema.ffieldClass.name
               << ",\"id\":" << schema.ffieldClass.id
               << ",\"cast_flags\":" << schema.ffieldClass.castFlags
               << ",\"class_flags\":" << schema.ffieldClass.classFlags
               << ",\"super_class\":" << schema.ffieldClass.superClass << "},\n";
        stream << "    \"ufield\": {\"next\":" << schema.ufield.next << "},\n";
        stream << "    \"ustruct\": {\"super\":" << schema.ustruct.superStruct
               << ",\"children\":" << schema.ustruct.children
               << ",\"child_properties\":" << schema.ustruct.childProperties
               << ",\"size\":" << schema.ustruct.propertiesSizeOffset
               << ",\"min_alignment\":" << schema.ustruct.minAlignment
               << ",\"struct_base_chain\":" << schema.ustruct.structBaseChain
               << ",\"tail\":" << schema.ustruct.tail << "},\n";
        stream << "    \"uclass\": {\"cast_flags\":" << schema.uclass.castFlags
               << ",\"class_default_object\":" << schema.uclass.classDefaultObject
               << ",\"implemented_interfaces\":" << schema.uclass.implementedInterfaces << "},\n";
        stream << "    \"property\": {\"array_dim\":" << schema.property.arrayDim
               << ",\"element_size\":" << schema.property.elementSize
               << ",\"flags\":" << schema.property.propertyFlags
               << ",\"offset_internal\":" << schema.property.offsetInternal
               << ",\"base_size\":" << schema.property.baseSize << "},\n";
        stream << "    \"property_tail\": {\"layout\":\""
               << (schema.features.propertyTailLayout == ::nextdumper::ue::PropertyTailLayout::UProperty ? "uproperty" : schema.features.propertyTailLayout == ::nextdumper::ue::PropertyTailLayout::RepNotifyBeforeLinks ? "repnotify-before-links"
                                                                                                                     : schema.features.propertyTailLayout == ::nextdumper::ue::PropertyTailLayout::LinksBeforeRepNotify   ? "links-before-repnotify"
                                                                                                                                                                                                                          : "unknown")
               << "\",\"rep_notify\":" << schema.property.repNotify
               << ",\"property_links\":" << schema.property.propertyLinks
               << ",\"property_links_end\":" << schema.property.propertyLinksEnd
               << ",\"subtype_start\":" << schema.property.subtypeStart << "},\n";
        stream << "    \"property_subtypes\": {\"bool_base\":" << schema.propertySubtypes.boolBase
               << ",\"byte_enum\":" << schema.propertySubtypes.byteEnum
               << ",\"object_class\":" << schema.propertySubtypes.objectClass
               << ",\"interface_class\":" << schema.propertySubtypes.interfaceClass
               << ",\"class_meta_class\":" << schema.propertySubtypes.classMetaClass
               << ",\"struct_type\":" << schema.propertySubtypes.structType
               << ",\"array_inner\":" << schema.propertySubtypes.arrayInner
               << ",\"set_element\":" << schema.propertySubtypes.setElement
               << ",\"map_base\":" << schema.propertySubtypes.mapBase
               << ",\"enum_base\":" << schema.propertySubtypes.enumBase
               << ",\"delegate_signature\":" << schema.propertySubtypes.delegateSignature
               << ",\"field_path_class\":" << schema.propertySubtypes.fieldPathClass
               << ",\"optional_value\":" << schema.propertySubtypes.optionalValue << "},\n";
        stream << "    \"optional_property_support\": {\"present_in_profile\":"
               << (schema.optionalPropertySupport.presentInProfile ? "true" : "false")
               << ",\"sample_count\":" << schema.optionalPropertySupport.sampleCount
               << ",\"selected_offset\":" << schema.optionalPropertySupport.selectedOffset
               << ",\"confidence\":\"" << EscapeJson(schema.optionalPropertySupport.confidence)
               << "\",\"source\":\"" << EscapeJson(schema.optionalPropertySupport.source)
               << "\",\"reason\":\"" << EscapeJson(schema.optionalPropertySupport.reason) << "\"},\n";
        stream << "    \"ufunction\": {\"flags\":" << schema.ufunction.functionFlags
               << ",\"num_params\":" << schema.ufunction.numParams
               << ",\"param_size\":" << schema.ufunction.paramSize
               << ",\"return_value_offset\":" << schema.ufunction.returnValueOffset
               << ",\"native_function\":" << schema.ufunction.nativeFunction << "},\n";
        stream << "    \"uenum\": {\"names\":" << schema.uenum.names
               << ",\"underlying_type\":" << schema.uenum.underlyingType
               << ",\"cpp_form\":" << schema.uenum.cppForm << ",\"flags\":" << schema.uenum.flags
               << ",\"package\":" << schema.uenum.enumPackage
               << ",\"cpp_form_is_byte\":" << (schema.features.enumCppFormIsByte ? "true" : "false")
               << ",\"flags_is_byte\":" << (schema.features.enumFlagsIsByte ? "true" : "false") << "}\n";
        stream << "  }";

        if (!binding.commonObjects.empty())
        {
            stream << ",\n  \"common_objects\": [\n";
            for (size_t i = 0; i < binding.commonObjects.size(); ++i)
            {
                const auto &obj = binding.commonObjects[i];
                stream << "    {\"name\":\"" << EscapeJson(obj.name)
                       << "\",\"address\":\"" << Hex(obj.address)
                       << "\",\"index\":" << obj.index << "}";
                if (i + 1 != binding.commonObjects.size())
                    stream << ",";
                stream << "\n";
            }
            stream << "  ]";
        }

        stream << "\n}\n";
    }

    void ReflectionJson(std::ostream &stream, const RuntimeContext &context, const ReflectionIR &reflection,
                        const GenerationReport &report, const CppSymbols &symbols)
    {
        const auto &validation = context.Schema().validation;
        WriteReflectionJson(stream, reflection, {context.Schema().identity.canonicalVersionRange.empty() ? validation.familyEvidence : context.Schema().identity.canonicalVersionRange, validation.profileId, validation.profileLabel, validation.profileVersionRange, &context.Schema().identity}, &report.fields, &symbols);
    }

} // namespace nextdumper::generation::detail
