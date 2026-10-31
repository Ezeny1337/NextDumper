#include "nextdumper/reflection/ReflectionReader.hpp"
#include "ReflectionEvidenceLog.hpp"
#include "nextdumper/common/Hex.hpp"
#include "nextdumper/ir/ReflectionLayout.hpp"
#include "nextdumper/ue/BoolLayout.hpp"
#include "nextdumper/ue/ContainerLayout.hpp"
#include "nextdumper/ue/StorageLayout.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace nextdumper::reflection
{
    namespace
    {
        using ::nextdumper::common::Hex;

        constexpr size_t kMaxFunctionDefinitions = 2 * 1024 * 1024;

        std::optional<uintptr_t> Add(uintptr_t base, int32_t offset)
        {
            if (offset < 0 || base > UINTPTR_MAX - static_cast<uintptr_t>(offset))
                return std::nullopt;
            return base + static_cast<uintptr_t>(offset);
        }

    } // namespace

    ReflectionReader::ReflectionReader(IMemorySource &memory,
                                       const RuntimeBinding &binding,
                                       const EngineSchema &schema,
                                       uintptr_t moduleBase,
                                       uintptr_t moduleEnd,
                                       std::function<void(const std::string &)> progress,
                                       std::function<void(const std::string &)> diagnostic)
        : memory_(memory, diagnostic),
          schema_(schema),
          moduleBase_(moduleBase),
          moduleEnd_(moduleEnd),
          objects_(memory_, binding, schema),
          progress_(std::move(progress)),
          diagnostic_(std::move(diagnostic))
    {
    }

    PropertyKind ReflectionReader::PropertyKindFromName(const std::string &name) const
    {
        const std::string normalized = NormalizeRuntimeFieldName(name);
        if (normalized == "BoolProperty")
            return PropertyKind::Bool;
        if (normalized == "ByteProperty")
            return PropertyKind::Byte;
        if (normalized == "Int8Property")
            return PropertyKind::Int8;
        if (normalized == "Int16Property")
            return PropertyKind::Int16;
        if (normalized == "IntProperty" || normalized == "Int32Property")
            return PropertyKind::Int32;
        if (normalized == "Int64Property")
            return PropertyKind::Int64;
        if (normalized == "UInt16Property")
            return PropertyKind::UInt16;
        if (normalized == "UInt32Property")
            return PropertyKind::UInt32;
        if (normalized == "UInt64Property")
            return PropertyKind::UInt64;
        if (normalized == "FloatProperty")
            return PropertyKind::Float;
        if (normalized == "DoubleProperty")
            return PropertyKind::Double;
        if (normalized == "NameProperty")
            return PropertyKind::Name;
        if (normalized == "StrProperty")
            return PropertyKind::String;
        if (normalized == "TextProperty")
            return PropertyKind::Text;
        if (normalized == "ObjectProperty" || normalized == "ObjectPtrProperty" || normalized == "ObjectPropertyBase")
            return PropertyKind::Object;
        if (normalized == "SoftObjectProperty")
            return PropertyKind::SoftObject;
        if (normalized == "WeakObjectProperty")
            return PropertyKind::WeakObject;
        if (normalized == "LazyObjectProperty")
            return PropertyKind::LazyObject;
        if (normalized == "ClassProperty" || normalized == "ClassPtrProperty")
            return PropertyKind::Class;
        if (normalized == "SoftClassProperty")
            return PropertyKind::SoftClass;
        if (normalized == "StructProperty")
            return PropertyKind::Struct;
        if (normalized == "EnumProperty")
            return PropertyKind::Enum;
        if (normalized == "ArrayProperty")
            return PropertyKind::Array;
        if (normalized == "SetProperty")
            return PropertyKind::Set;
        if (normalized == "MapProperty")
            return PropertyKind::Map;
        if (normalized == "InterfaceProperty")
            return PropertyKind::Interface;
        if (normalized == "DelegateProperty")
            return PropertyKind::Delegate;
        if (normalized == "MulticastDelegateProperty" || normalized == "MulticastInlineDelegateProperty" ||
            normalized == "MulticastSparseDelegateProperty")
            return PropertyKind::MulticastDelegate;
        if (normalized == "FieldPathProperty")
            return PropertyKind::FieldPath;
        if (normalized == "OptionalProperty")
            return PropertyKind::Optional;
        if (normalized == "Utf8StrProperty" || normalized == "AnsiStrProperty")
            return PropertyKind::String;
        return PropertyKind::Unknown;
    }

    void ReflectionReader::RecordPropertyDetail(const PropertyMetadata &metadata, PropertyIR &property,
                                                const std::string &reason, bool headerAvailable) const
    {
        ::nextdumper::ir::PropertyDetailDiagnostic diagnostic;
        diagnostic.headerAvailable = headerAvailable;
        diagnostic.address = metadata.address;
        diagnostic.classAddress = metadata.classAddress;
        diagnostic.nextAddress = metadata.nextAddress;
        diagnostic.immediateOwner = metadata.ownerAddress;
        diagnostic.ownerIsUObject = metadata.ownerIsUObject;
        diagnostic.name = metadata.name;
        diagnostic.reflectedClass = metadata.className;
        diagnostic.normalizedClass = metadata.normalizedClassName;
        diagnostic.reason = reason;
        diagnostic.detailsStatus = ::nextdumper::ue::PropertyDetailsStatusName(metadata.detailsStatus);
        diagnostic.offset = metadata.offset;
        diagnostic.elementSize = metadata.elementSize;
        diagnostic.arrayDim = metadata.arrayDim;
        diagnostic.flags = metadata.flags;
        diagnostic.referencedAddress = metadata.referencedAddress;
        diagnostic.secondaryAddress = metadata.secondaryAddress;
        diagnostic.boolean = {metadata.boolLayout[0], metadata.boolLayout[1], metadata.boolLayout[2], metadata.boolLayout[3]};
        for (size_t index = 0; index < metadata.detailReadCount; ++index)
        {
            const auto &read = metadata.detailReads[index];
            diagnostic.reads.push_back({read.member, read.offset, read.address, read.rawValue,
                                        static_cast<int32_t>(read.read.error), read.read.requested, read.read.transferred,
                                        ::nextdumper::ue::PropertyDetailsStatusName(read.status)});
        }
        diagnostic.referencedClass = "not-observed";
        diagnostic.secondaryClass = "not-observed";
        diagnostic.objectPropertyClassNull = metadata.objectPropertyClassNull;
        diagnostic.objectPropertyClassPointerAddress = metadata.objectPropertyClassPointerAddress;
        // 仅在已完成读取与基本指针检查后补充类型身份，不尝试解码未知对象句柄
        const auto referenceClass = [&](uintptr_t address, bool secondary) -> std::string
        {
            if (address == 0 || metadata.detailsStatus != PropertyMetadata::DetailsStatus::Complete)
                return "not-observed";
            const auto kind = PropertyKindFromName(metadata.className);
            if (kind == PropertyKind::FieldPath)
            {
                const auto cls = objects_.FieldClass(address);
                return cls ? cls->name : "<invalid-field-class>";
            }
            if (kind == PropertyKind::Map || (!secondary && (kind == PropertyKind::Array || kind == PropertyKind::Set ||
                                                             kind == PropertyKind::Enum || kind == PropertyKind::Optional)))
            {
                const auto field = objects_.Field(address);
                return field ? field->className : "<invalid-field>";
            }
            const auto cls = objects_.ClassName(address);
            return cls ? *cls : "<unreadable>";
        };
        diagnostic.referencedClass = referenceClass(metadata.referencedAddress, false);
        diagnostic.secondaryClass = referenceClass(metadata.secondaryAddress, true);
        property.detailDiagnostics.push_back(std::move(diagnostic));
    }

    TypeReferenceIR ReflectionReader::ReadTypeReference(const PropertyMetadata &metadata, PropertyIR &property,
                                                        ReflectionStats &stats, std::unordered_set<uintptr_t> &path,
                                                        size_t depth, size_t &remaining) const
    {
        TypeReferenceIR result;
        result.metadataAddress = metadata.address;
        result.immediateOwner = metadata.ownerAddress;
        result.ownerIsUObject = metadata.ownerIsUObject;
        result.arrayDim = metadata.arrayDim;
        result.kind = PropertyKindFromName(metadata.className);
        if (result.kind == PropertyKind::Delegate)
            result.delegateStorage = ::nextdumper::ir::DelegateStorageKind::Unicast;
        else if (result.kind == PropertyKind::MulticastDelegate)
            result.delegateStorage = metadata.normalizedClassName == "MulticastSparseDelegateProperty"
                                         ? ::nextdumper::ir::DelegateStorageKind::SparseMulticast
                                     : metadata.normalizedClassName == "MulticastInlineDelegateProperty"
                                         ? ::nextdumper::ir::DelegateStorageKind::InlineMulticast
                                         : ::nextdumper::ir::DelegateStorageKind::UnknownMulticast;
        result.reflectedClass = metadata.className;
        result.elementSize = metadata.elementSize;
        result.referencedObject = metadata.referencedAddress;
        result.secondaryObject = metadata.secondaryAddress;
        const auto containerStorage = [&]
        {
            if (result.kind != PropertyKind::Array && result.kind != PropertyKind::Map && result.kind != PropertyKind::Set)
                return;
            if (const auto found = containerStorage_.find(metadata.address); found != containerStorage_.end())
            {
                result.containerStorage = found->second;
                return;
            }
            ++containerCandidates_[metadata.normalizedClassName];
            ContainerCandidate candidate{metadata, result};
            auto evidence = ReadContainerStorage(candidate);
            auto storage = std::make_shared<::nextdumper::ir::ContainerStorageIR>(evidence.storage);
            result.containerStorage = storage;
            containerStorage_.emplace(metadata.address, std::move(storage));
            // 原始证据 budget 限制的是诊断信息，绝不限制元数据读取
            if (pendingContainers_.size() < 8192)
            {
                candidate.reference = result;
                pendingContainers_.push_back(std::move(candidate));
                containerEvidence_.emplace(metadata.address, std::move(evidence));
            }
            else
                ++containerNotObserved_[metadata.normalizedClassName + ":raw-evidence-queue-budget"];
        };
        if (depth >= 32 || remaining == 0 || !path.insert(metadata.address).second)
        {
            property.diagnostics.push_back("nested property cycle or traversal limit: address=" + Hex(metadata.address));
            RecordPropertyDetail(metadata, property, "cycle-or-traversal-limit");
            ++stats.failures;
            return result;
        }
        --remaining;
        result.detailsResolved = metadata.detailsStatus == PropertyMetadata::DetailsStatus::Complete &&
                                 result.kind != PropertyKind::Unknown && metadata.elementSize > 0;
        if (metadata.detailsStatus != PropertyMetadata::DetailsStatus::Complete)
        {
            // 成员读取失败或必需引用为空时，仅记录证据，不能再以其结果做对象/子属性解引用
            property.diagnostics.push_back("property details status=" + std::to_string(static_cast<int>(metadata.detailsStatus)) +
                                           " address=" + Hex(metadata.address));
            if (metadata.detailsStatus != PropertyMetadata::DetailsStatus::UnsupportedLayout)
                ++stats.failures;
            if (result.kind == PropertyKind::Unknown)
                ++stats.unknownProperties;
            const std::string detailReason = metadata.objectPropertyClassNull
                                                 ? "object-property-class-metadata-null"
                                                 : ::nextdumper::ue::PropertyDetailsStatusName(metadata.detailsStatus);
            RecordPropertyDetail(metadata, property, detailReason);
            containerStorage();
            path.erase(metadata.address);
            return result;
        }
        if (result.kind == PropertyKind::Unknown)
            ++stats.unknownProperties;
        const auto nested = [&](uintptr_t address) -> std::shared_ptr<TypeReferenceIR>
        {
            if (address == 0)
                return {};
            const auto child = objects_.Property(address);
            if (!child)
            {
                ++stats.failures;
                property.diagnostics.push_back("nested property header unreadable: address=" + Hex(address));
                PropertyMetadata missing;
                missing.address = address;
                missing.name = "<unreadable>";
                missing.className = "<unreadable>";
                missing.normalizedClassName = "<unreadable>";
                missing.detailsStatus = PropertyMetadata::DetailsStatus::Unreadable;
                RecordPropertyDetail(missing, property, "nested-header-unreadable", false);
                return {};
            }
            if (schema_.features.useFProperty && (child->ownerIsUObject || child->ownerAddress != metadata.address))
            {
                ++stats.failures;
                property.diagnostics.push_back("nested property owner mismatch: address=" + Hex(address));
                RecordPropertyDetail(*child, property, "nested-owner-mismatch");
                return {};
            }
            return std::make_shared<TypeReferenceIR>(ReadTypeReference(*child, property, stats, path, depth + 1, remaining));
        };
        const auto objectMatches = [&](uintptr_t address, ::nextdumper::ue::DefinitionKind expected)
        {
            if (address == 0)
                return false;
            const auto cls = objects_.Class(address);
            const auto kind = cls ? objects_.DefinitionKindForClass(*cls) : std::nullopt;
            return kind && *kind == expected;
        };
        bool semanticMatch = true;
        bool enclosingContainer = false;
        switch (result.kind)
        {
        case PropertyKind::Object:
        case PropertyKind::Class:
        case PropertyKind::SoftObject:
        case PropertyKind::SoftClass:
        case PropertyKind::WeakObject:
        case PropertyKind::LazyObject:
        case PropertyKind::Interface:
            semanticMatch = objectMatches(result.referencedObject, ::nextdumper::ue::DefinitionKind::Class);
            break;
        case PropertyKind::Struct:
            semanticMatch = objectMatches(result.referencedObject, ::nextdumper::ue::DefinitionKind::Struct);
            break;
        case PropertyKind::Byte:
            semanticMatch = result.referencedObject == 0 || objectMatches(result.referencedObject, ::nextdumper::ue::DefinitionKind::Enum);
            break;
        case PropertyKind::Array:
        case PropertyKind::Set:
        case PropertyKind::Optional:
            result.inner = nested(result.referencedObject);
            enclosingContainer = true;
            semanticMatch = result.inner && result.inner->detailsResolved;
            break;
        case PropertyKind::Map:
            result.key = nested(result.referencedObject);
            result.value = nested(result.secondaryObject);
            enclosingContainer = true;
            semanticMatch = result.key && result.value && result.key->detailsResolved && result.value->detailsResolved;
            break;
        case PropertyKind::Enum:
            result.inner = nested(result.referencedObject);
            semanticMatch = result.inner && result.inner->detailsResolved && result.inner->elementSize == result.elementSize &&
                            objectMatches(result.secondaryObject, ::nextdumper::ue::DefinitionKind::Enum);
            break;
        case PropertyKind::Delegate:
        case PropertyKind::MulticastDelegate:
        {
            const auto cls = objects_.ClassName(result.referencedObject);
            semanticMatch = cls && IsFunctionFieldKind(::nextdumper::ue::FieldKindFromRuntimeName(*cls, false));
            if (semanticMatch && !delegateSignatures_.contains(result.referencedObject))
            {
                if (pendingSignatures_.size() >= kMaxFunctionDefinitions)
                {
                    semanticMatch = false;
                    ++stats.failures;
                    property.diagnostics.push_back("delegate signature worklist budget exhausted: signature=" +
                                                   Hex(result.referencedObject));
                    break;
                }
                ::nextdumper::ir::DelegateSignatureObservation observation;
                observation.address = result.referencedObject;
                observation.reflectedClass = *cls;
                observation.fullName = objects_.FullName(observation.address).value_or("<unreadable>");
                const auto outer = objects_.Outer(observation.address);
                observation.outerReadable = outer.has_value();
                observation.outerAddress = outer.value_or(0);
                observation.outerClass = outer && *outer != 0 ? objects_.ClassName(*outer).value_or("<unreadable>") : "<none>";
                observation.outerFullName = outer && *outer != 0 ? objects_.FullName(*outer).value_or("<unreadable>") : "<none>";
                delegateSignatures_.emplace(observation.address, std::move(observation));
                pendingSignatures_.push_back(result.referencedObject);
            }
            break;
        }
        case PropertyKind::Bool:
            semanticMatch = ::nextdumper::ue::IsValidBoolLayout(metadata.boolLayout, metadata.elementSize);
            break;
        case PropertyKind::FieldPath:
            semanticMatch = metadata.detailsStatus == PropertyMetadata::DetailsStatus::Complete &&
                            objects_.IsValidFieldClass(result.referencedObject);
            break;
        default:
            break;
        }
        result.nodeDetailsResolved = result.detailsResolved && (enclosingContainer
                                                                    ? (result.kind == PropertyKind::Map ? result.key && result.value : result.inner != nullptr)
                                                                    : semanticMatch);
        if (!semanticMatch)
        {
            property.diagnostics.push_back("property type semantics unresolved: address=" + Hex(metadata.address));
            result.detailsResolved = false;
        }
        if (!result.detailsResolved)
        {
            std::string reason = "semantic-mismatch";
            if (result.kind == PropertyKind::Unknown)
                reason = "unknown-property-kind";
            else if (metadata.elementSize <= 0)
                reason = "invalid-element-size";
            else if (metadata.objectPropertyClassNull)
                reason = "object-property-class-metadata-null";
            RecordPropertyDetail(metadata, property, reason);
        }
        if (result.nodeDetailsResolved)
        {
            for (const auto &layout : ::nextdumper::ue::ValueStorageCandidates(result, sizeof(uintptr_t), schema_.fname.size))
                result.valueStorageCandidates.push_back(layout.id);
            if (const auto layout = ::nextdumper::ue::CommonValueStorage(result, sizeof(uintptr_t), schema_.fname.size))
                result.valueStorage = std::make_shared<const ::nextdumper::ir::StorageLayoutIR>(*layout);
        }
        containerStorage();
        path.erase(metadata.address);
        return result;
    }

    std::optional<PropertyIR> ReflectionReader::ReadProperty(const FieldMetadata &field, ReflectionStats &stats) const
    {
        const auto metadata = objects_.Property(field);
        if (!metadata)
            return std::nullopt;
        PropertyIR result;
        result.address = field.address;
        result.name = metadata->name;
        result.reflectedClass = metadata->className;
        result.offset = metadata->offset;
        result.elementSize = metadata->elementSize;
        result.arrayDim = metadata->arrayDim;
        result.flags = metadata->flags;
        result.isParameter = (result.flags & 0x80u) != 0;
        result.isReturnParameter = (result.flags & 0x400u) != 0;
        result.isOutParameter = (result.flags & 0x100u) != 0;
        result.isReferenceParameter = (result.flags & 0x08000000u) != 0;
        result.isConstParameter = (result.flags & 0x2u) != 0;
        result.boolean = {metadata->boolLayout[0], metadata->boolLayout[1], metadata->boolLayout[2], metadata->boolLayout[3]};
        std::unordered_set<uintptr_t> path;
        size_t remaining = 256;
        result.type = ReadTypeReference(*metadata, result, stats, path, 0, remaining);
        result.typeDetailsResolved = result.type.detailsResolved;
        if (!result.typeDetailsResolved)
        {
            ++stats.unresolvedTypeDetails;
            result.status = ParseStatus::Partial;
        }
        ++stats.parsedProperties;
        return result;
    }

    void ReflectionReader::ReadProperties(uintptr_t first, TypeIR &type, ReflectionStats &stats) const
    {
        PropertyChain chain = ReadPropertyChain(first, type.address, stats, type.layoutConflicts);
        type.properties = std::move(chain.properties);
        if (!chain.complete ||
            std::any_of(type.properties.begin(), type.properties.end(), [](const PropertyIR &property)
                        { return property.status != ParseStatus::Complete; }))
            type.status = ParseStatus::Partial;
    }

    ReflectionReader::PropertyChain ReflectionReader::ReadPropertyChain(uintptr_t first, uintptr_t owner,
                                                                        ReflectionStats &stats,
                                                                        std::vector<std::string> &diagnostics) const
    {
        PropertyChain result;
        const FieldChainResult chain = objects_.FieldsWithStatus(first, 65536);
        if (!chain.Complete())
        {
            ++stats.failures;
            result.complete = false;
            diagnostics.push_back("property field chain status=" + std::to_string(static_cast<int>(chain.status)) +
                                  " owner=" + Hex(owner) + " root=" + Hex(first));
        }
        for (const FieldMetadata &field : chain.fields)
        {
            if (!IsPropertyFieldKind(field.kind))
            {
                continue;
            }
            if (schema_.features.useFProperty &&
                (!field.ownerIsUObject || field.ownerAddress != owner))
            {
                ++stats.failures;
                result.complete = false;
                diagnostics.push_back("property owner mismatch: property=" + field.name +
                                      " address=" + Hex(field.address) +
                                      " expected_owner=" + Hex(owner) +
                                      " actual_owner=" + Hex(field.ownerAddress));
                continue;
            }
            const auto property = ReadProperty(field, stats);
            if (property)
                result.properties.push_back(*property);
            else
            {
                ++stats.failures;
                result.complete = false;
                diagnostics.push_back("property header unreadable: property=" + field.name +
                                      " class=" + field.className + " address=" + Hex(field.address));
            }
        }
        return result;
    }

    void ReflectionReader::ReadFunctionParameters(uintptr_t first, FunctionIR &function, ReflectionStats &stats) const
    {
        std::vector<PropertyMetadata> properties;
        const PropertyChain chain = ReadPropertyChain(first, function.address, stats, function.layoutConflicts);
        const std::vector<PropertyIR> &parsedProperties = chain.properties;
        for (const PropertyIR &property : parsedProperties)
        {
            PropertyMetadata metadata;
            metadata.arrayDim = property.arrayDim;
            metadata.elementSize = property.elementSize;
            metadata.offset = property.offset;
            metadata.flags = property.flags;
            properties.push_back(std::move(metadata));
        }

        const FunctionParameterSummary summary = AnalyzeFunctionParameters(
            properties, function.flags, schema_.features.functionDefaultsContinueAfterInitializer);
        function.parameters.clear();
        function.locals.clear();
        const size_t scannedPropertyCount = std::min(summary.scannedPropertyCount, parsedProperties.size());
        for (size_t index = 0; index < scannedPropertyCount; ++index)
        {
            if ((parsedProperties[index].flags & ::nextdumper::ue::kCPFParm) != 0)
                function.parameters.push_back(parsedProperties[index]);
        }
        for (const PropertyIR &property : parsedProperties)
            if ((property.flags & ::nextdumper::ue::kCPFParm) == 0)
                function.locals.push_back(property);
        function.derivedNumParams = summary.count;
        function.derivedParamSize = summary.paramEnd;
        function.defaultInitializerCount = summary.defaultInitializerCount;
        function.parameterSemanticsValid = summary.valid && chain.complete;
        const uint16_t expectedReturnOffset = summary.returnOffset >= 0
                                                  ? static_cast<uint16_t>(summary.returnOffset)
                                                  : std::numeric_limits<uint16_t>::max();
        function.parameterSemanticsConsistent = function.parameterSemanticsValid &&
                                                function.headerNumParams == summary.count &&
                                                function.headerParamSize == summary.paramEnd &&
                                                function.returnValueOffset == expectedReturnOffset;
        if (!function.parameterSemanticsConsistent)
        {
            function.layoutConflicts.push_back("function header parameters do not match derived semantics: header_count=" +
                                               std::to_string(function.headerNumParams) +
                                               " derived_count=" + std::to_string(summary.count) +
                                               " header_size=" + std::to_string(function.headerParamSize) +
                                               " derived_size=" + std::to_string(summary.paramEnd) +
                                               " header_return=" + std::to_string(function.returnValueOffset) +
                                               " derived_return=" + std::to_string(expectedReturnOffset));
            ++stats.layoutConflicts;
        }
        if (!function.layoutConflicts.empty() ||
            std::any_of(function.parameters.begin(), function.parameters.end(), [](const PropertyIR &property)
                        { return property.status != ParseStatus::Complete; }))
            function.status = ParseStatus::Partial;
    }

    FunctionIR *ReflectionReader::ReadFunction(uintptr_t address, ReflectionIR &ir) const
    {
        if (const auto found = ir.functions.find(address); found != ir.functions.end())
            return &found->second;
        if (address == 0 || ir.functions.size() >= kMaxFunctionDefinitions)
        {
            ++ir.stats.failures;
            constexpr size_t kRegistryDiagnosticSamples = 8;
            if (++registryBudgetDiagnostics <= kRegistryDiagnosticSamples)
                ir.diagnostics.push_back("function registry budget or invalid address: address=" + Hex(address));
            return nullptr;
        }
        FunctionIR &function = ir.functions.try_emplace(address).first->second;
        function.address = address;
        // parsedFunctions 表示已进入 IR 的函数数，与 Functions.hpp 和 reflection 分片的记录数保持一致
        ++ir.stats.parsedFunctions;
        const auto fail = [&](const std::string &reason)
        {
            ++ir.stats.failures;
            function.status = ParseStatus::Failed;
            function.layoutConflicts.push_back(reason);
            return &function;
        };
        const auto field = objects_.UField(address);
        if (field)
        {
            function.name = field->name;
            function.reflectedClass = field->className;
            function.fullName = field->className + " " + field->name;
        }
        if (!field || !IsFunctionFieldKind(field->kind))
            return fail("function field header unreadable or not a UFunction");
        const auto classAddress = objects_.Class(address);
        const auto outerAddress = objects_.Outer(address);
        const auto internalIndex = objects_.InternalIndex(address);
        const auto objectFlags = objects_.Flags(address);
        if (!classAddress || !outerAddress || !internalIndex || !objectFlags)
            return fail("function object header unreadable: class_readable=" + std::to_string(classAddress.has_value()) +
                        " outer_readable=" + std::to_string(outerAddress.has_value()) +
                        " index_readable=" + std::to_string(internalIndex.has_value()) +
                        " flags_readable=" + std::to_string(objectFlags.has_value()));
        function.outerAddress = *outerAddress;
        function.objectFlags = *objectFlags;
        const auto fullName = objects_.FullName(address);
        if (fullName)
            function.fullName = *fullName;
        else
        {
            ++ir.stats.failures;
            function.status = ParseStatus::Partial;
            function.layoutConflicts.push_back("function full name could not be resolved; using field identity");
        }
        if (*outerAddress != 0)
        {
            function.outerClass = objects_.ClassName(*outerAddress).value_or("<unreadable>");
            function.outerFullName = objects_.FullName(*outerAddress).value_or("<unreadable>");
        }
        if ((*objectFlags & (::nextdumper::ue::kRFUnavailableDefinition | ::nextdumper::ue::kRFClassDefaultObject)) != 0)
            return fail("function definition unavailable: object_flags=" + std::to_string(*objectFlags));
        const auto slot = objects_.Objects().ReadObject(*internalIndex, true);
        const auto internalFlags = slot.IsValid() ? objects_.Objects().ReadInternalFlags(slot) : std::nullopt;
        if (!slot.IsValid() || slot.address != address || !internalFlags || (*internalFlags & 0x80000000u) != 0 ||
            objects_.InternalIndex(address, true) != internalIndex ||
            objects_.Class(address, true) != classAddress)
        {
            ++ir.stats.identityFailures;
            memory_.Invalidate();
            return fail("function object identity changed or pending construction: index=" + std::to_string(*internalIndex));
        }
        const auto readMember = [&](int32_t offset, auto &value)
        {
            const auto member = Add(address, offset);
            return member && memory_.Read(*member, value);
        };
        if (!readMember(schema_.ufunction.functionFlags, function.flags) ||
            !readMember(schema_.ufunction.numParams, function.headerNumParams) ||
            !readMember(schema_.ufunction.paramSize, function.headerParamSize) ||
            !readMember(schema_.ufunction.returnValueOffset, function.returnValueOffset))
            return fail("function header unreadable: flags_offset=" + std::to_string(schema_.ufunction.functionFlags) +
                        " count_offset=" + std::to_string(schema_.ufunction.numParams) +
                        " size_offset=" + std::to_string(schema_.ufunction.paramSize) +
                        " return_offset=" + std::to_string(schema_.ufunction.returnValueOffset));

        function.headerReadable = true;
        function.numParams = function.headerNumParams;
        function.paramSize = function.headerParamSize;
        function.nativeFlag = (function.flags & ::nextdumper::ue::kFUNCNative) != 0;
        function.entryReadable = readMember(schema_.ufunction.nativeFunction, function.execEntry);
        function.entryInModule = function.entryReadable && function.execEntry >= moduleBase_ && function.execEntry < moduleEnd_;
        function.entryExecutable = function.entryReadable && function.execEntry != 0 &&
                                   memory_.IsExecutable(function.execEntry, sizeof(uintptr_t));
        if (function.entryInModule)
            function.execEntryRva = function.execEntry - moduleBase_;
        if (function.nativeFlag && function.entryInModule && function.entryExecutable)
            function.nativeExecRva = function.execEntryRva;
        if (!function.entryReadable || (function.nativeFlag && !function.entryExecutable))
        {
            ++ir.stats.failures;
            function.status = ParseStatus::Partial;
            function.layoutConflicts.push_back("function exec entry unreadable or invalid: offset=" +
                                               std::to_string(schema_.ufunction.nativeFunction) +
                                               " entry=" + Hex(function.execEntry) +
                                               " native_flag=" + std::to_string(function.nativeFlag));
        }
        const auto parameters = objects_.StructProperties(address);
        if (parameters)
            ReadFunctionParameters(*parameters, function, ir.stats);
        else
        {
            ++ir.stats.failures;
            function.status = ParseStatus::Partial;
            function.layoutConflicts.push_back("function parameter chain root unreadable: offset=" +
                                               std::to_string(schema_.features.useFProperty ? schema_.ustruct.childProperties : schema_.ustruct.children));
        }
        return &function;
    }

    void ReflectionReader::ReadFunctions(uintptr_t first, TypeIR &type, ReflectionIR &ir) const
    {
        const FieldChainResult chain = objects_.UFieldsWithStatus(first, 65536);
        functionChains_[type.address] = {first, chain.status};
        if (!chain.Complete())
        {
            ++ir.stats.failures;
            type.status = ParseStatus::Partial;
            type.layoutConflicts.push_back("function field chain status=" + std::to_string(static_cast<int>(chain.status)) +
                                           " root=" + Hex(first));
        }
        for (const FieldMetadata &field : chain.fields)
        {
            if (!IsFunctionFieldKind(field.kind))
                continue;
            FunctionIR *function = ReadFunction(field.address, ir);
            if (!function)
            {
                type.status = ParseStatus::Partial;
                break;
            }
            function->discoveredFromChildren = true;
            type.functionAddresses.push_back(field.address);
            if (function->status != ParseStatus::Complete)
                type.status = ParseStatus::Partial;
            if (function->outerAddress != type.address)
            {
                ++ir.stats.failures;
                type.status = ParseStatus::Partial;
                type.layoutConflicts.push_back("function Children owner mismatch: address=" + Hex(field.address) +
                                               " actual_outer=" + Hex(function->outerAddress));
            }
        }
    }

    void ReflectionReader::CloseDelegateSignatures(ReflectionIR &ir) const
    {
        auto *performance = memory_.Performance();
        memory::ScopedReadTiming timing(performance ? &performance->delegateClosure : nullptr, 1);
        // 读取一个签名可以在其参数中发现更多签名
        // 应当处理并清空一个有界的待办工作列表，而不是进行递归的函数读取或依赖映射顺序的扫描
        while (nextSignature_ < pendingSignatures_.size())
        {
            FunctionIR *function = ReadFunction(pendingSignatures_[nextSignature_++], ir);
            if (function)
                function->referencedAsSignature = true;
        }
    }

    void ReflectionReader::CollectContainerStorage(ReflectionIR &reflection) const
    {
        std::unordered_map<uintptr_t, const TypeIR *> types;
        for (const auto &type : reflection.types)
            types.emplace(type.address, &type);
        const auto extent = [](const std::shared_ptr<TypeReferenceIR> &node)
        {
            const int64_t size = node ? static_cast<int64_t>(node->elementSize) * node->arrayDim : 0;
            return node && node->elementSize > 0 && node->arrayDim > 0 && size <= INT32_MAX ? static_cast<int32_t>(size) : 0;
        };
        const auto validate = [&](const auto &self, const TypeReferenceIR &reference, size_t depth, size_t &remaining) -> void
        {
            if (depth >= 32 || remaining == 0)
                return;
            --remaining;
            for (const auto &child : {reference.inner, reference.key, reference.value})
                if (child)
                    self(self, *child, depth + 1, remaining);
            const auto found = containerStorage_.find(reference.metadataAddress);
            if (found == containerStorage_.end() ||
                (reference.kind != PropertyKind::Map && reference.kind != PropertyKind::Set))
                return;
            const auto &key = reference.kind == PropertyKind::Map ? reference.key : reference.inner;
            const auto keyAlignment = key ? ::nextdumper::ue::PropertyStorageAlignment(
                                                *key, types, static_cast<int32_t>(sizeof(uintptr_t)), schema_.fname.size)
                                          : std::nullopt;
            const auto valueAlignment = reference.value ? ::nextdumper::ue::PropertyStorageAlignment(
                                                              *reference.value, types, static_cast<int32_t>(sizeof(uintptr_t)), schema_.fname.size)
                                                        : std::nullopt;
            ::nextdumper::ue::ValidateSparseLayout(*found->second, reference.kind, extent(key), extent(reference.value),
                                                   keyAlignment.value_or(0), valueAlignment.value_or(0));
        };
        const auto validateProperties = [&](const auto &properties)
        {
            for (const auto &property : properties)
            {
                size_t remaining = 256;
                validate(validate, property.type, 0, remaining);
            }
        };
        for (const auto &type : reflection.types)
            validateProperties(type.properties);
        for (const auto &[address, function] : reflection.functions)
        {
            (void)address;
            validateProperties(function.parameters);
            validateProperties(function.locals);
        }
        for (const auto &[address, storage] : containerStorage_)
        {
            (void)address;
            ++reflection.containerAllocatorCounts[::nextdumper::ir::ContainerAllocatorKindName(storage->allocator)];
            ++reflection.containerHeaderCounts[storage->headerStatus];
            ++reflection.containerElementLayoutCounts[storage->layoutStatus];
        }
        const auto declarations = ::nextdumper::ir::PlanTypeDeclarations(reflection);
        for (auto &candidate : pendingContainers_)
        {
            const auto &storage = *candidate.reference.containerStorage;
            candidate.priority = !candidate.reference.detailsResolved ||
                                         storage.allocator == ::nextdumper::ir::ContainerAllocatorKind::Unknown ||
                                         (storage.headerStatus != "source-model-and-size-match" &&
                                          storage.headerStatus != "source-model-fits-reflected-extent")
                                     ? 0
                                 : ::nextdumper::ir::HasStorageRepresentationGap(candidate.reference, declarations) ? 1
                                                                                                                    : 2;
        }
        std::stable_sort(pendingContainers_.begin(), pendingContainers_.end(), [](const auto &left, const auto &right)
                         { return left.priority < right.priority; });
        std::map<std::string, std::unordered_set<uintptr_t>> sampleOwners;
        for (const auto &candidate : pendingContainers_)
        {
            const auto &metadata = candidate.metadata;
            auto &observation = containerEvidence_.at(metadata.address);
            observation.storage = *candidate.reference.containerStorage;
            if (containerObservations_.size() >= 512)
            {
                ++containerNotObserved_[metadata.normalizedClassName + ":raw-observation-budget"];
                continue;
            }
            if (candidate.priority == 2)
            {
                const std::string shape = metadata.normalizedClassName + ":" + std::to_string(metadata.elementSize) +
                                          ":" + observation.innerClass + ":" + std::to_string(observation.innerSize) +
                                          ":" + observation.valueClass + ":" + std::to_string(observation.valueSize) +
                                          ":" + observation.storage.layoutId;
                auto &owners = sampleOwners[shape];
                if (owners.size() >= 2 || owners.contains(metadata.ownerAddress))
                {
                    ++containerNotObserved_[metadata.normalizedClassName + ":normal-shape-budget-or-repeated-owner"];
                    continue;
                }
                owners.insert(metadata.ownerAddress);
            }
            observation.sampleReason = candidate.priority == 0   ? "unresolved-or-unsupported-storage"
                                       : candidate.priority == 1 ? "representation-gap"
                                                                 : "normal-shape-representative";
            containerObservations_.push_back(std::move(observation));
        }
        for (const auto &candidate : containerCandidates_)
        {
            const auto &kind = candidate.first;
            const auto expected = candidate.second;
            size_t accounted = std::count_if(containerObservations_.begin(), containerObservations_.end(),
                                             [&](const auto &observation)
                                             { return observation.propertyClass == kind; });
            for (const auto &[reason, count] : containerNotObserved_)
                if (reason.starts_with(kind + ":"))
                    accounted += count;
            if (accounted != expected)
            {
                reflection.containerEvidenceAccountingValid = false;
                reflection.diagnostics.push_back("container evidence accounting mismatch: class=" + kind +
                                                 " candidates=" + std::to_string(expected) +
                                                 " accounted=" + std::to_string(accounted));
            }
        }
        const auto collectLayouts = [&](const auto &self, const TypeReferenceIR &reference, size_t depth, size_t &remaining) -> void
        {
            if (depth >= 32 || !remaining)
                return;
            --remaining;
            if (reference.nodeDetailsResolved)
                for (const auto &layout : ::nextdumper::ue::ValueStorageCandidates(reference, sizeof(uintptr_t), schema_.fname.size))
                    reflection.valueStorageLayouts.try_emplace(layout.id, layout);
            if (reference.valueStorage)
                reflection.valueStorageLayouts.try_emplace(reference.valueStorage->id, *reference.valueStorage);
            for (const auto &child : {reference.inner, reference.key, reference.value})
                if (child)
                    self(self, *child, depth + 1, remaining);
        };
        const auto collectProperties = [&](const auto &properties)
        {
            for (const auto &property : properties)
            {
                size_t remaining = 256;
                collectLayouts(collectLayouts, property.type, 0, remaining);
            }
        };
        for (const auto &type : reflection.types)
            collectProperties(type.properties);
        for (const auto &[address, function] : reflection.functions)
        {
            (void)address;
            collectProperties(function.parameters);
            collectProperties(function.locals);
        }
        pendingContainers_.clear();
        containerEvidence_.clear();
    }

    ::nextdumper::ir::ContainerStorageObservation ReflectionReader::ReadContainerStorage(const ContainerCandidate &candidate) const
    {
        const auto &metadata = candidate.metadata;
        const auto &reference = candidate.reference;
        const auto *element = reference.kind == PropertyKind::Map ? reference.key.get() : reference.inner.get();
        const auto *value = reference.value.get();
        ::nextdumper::ir::ContainerStorageObservation observation;
        observation.propertyAddress = metadata.address;
        observation.ownerAddress = metadata.ownerAddress;
        observation.ownerIsUObject = metadata.ownerIsUObject;
        observation.propertyName = metadata.name;
        observation.propertyClass = metadata.normalizedClassName;
        observation.innerClass = element ? element->reflectedClass : "";
        observation.valueClass = value ? value->reflectedClass : "";
        observation.storageSize = metadata.elementSize;
        observation.propertyDataEnd = schema_.property.subtypeStart;
        observation.referenceOffset = reference.kind == PropertyKind::Array ? schema_.propertySubtypes.arrayInner
                                      : reference.kind == PropertyKind::Map ? schema_.propertySubtypes.mapBase
                                                                            : schema_.propertySubtypes.setElement;
        const auto childExtent = [](const TypeReferenceIR *child)
        {
            const int64_t size = child ? static_cast<int64_t>(child->elementSize) * child->arrayDim : 0;
            return child && child->elementSize > 0 && child->arrayDim > 0 && size <= INT32_MAX ? static_cast<int32_t>(size) : 0;
        };
        observation.innerSize = childExtent(element);
        observation.valueSize = childExtent(value);
        auto &storage = observation.storage;
        constexpr int32_t pointer = static_cast<int32_t>(sizeof(uintptr_t));
        const auto alignPointer = [](int64_t offset)
        { return (offset + pointer - 1) / pointer * pointer; };
        int32_t offset = observation.referenceOffset;
        size_t windowSize = 0;
        if (reference.kind == PropertyKind::Array)
        {
            observation.member = "ArrayFlags";
            observation.basis = "validated-inner-and-property-data-end; source-family-candidates";
            const int64_t dataEnd = schema_.property.subtypeStart;
            const bool afterInner = dataEnd >= 0 && alignPointer(dataEnd) == offset;
            const bool beforeInner = dataEnd >= 0 && dataEnd < offset && alignPointer(dataEnd + 1) == offset;
            const int64_t end = static_cast<int64_t>(offset) + pointer + (afterInner ? 4 : 0);
            if ((afterInner || beforeInner) && schema_.property.subtypeStart <= offset &&
                end - schema_.property.subtypeStart <= 32)
            {
                offset = schema_.property.subtypeStart;
                windowSize = static_cast<size_t>(end - offset);
            }
            else
                observation.status = "unresolved-property-data-end";
            if (!schema_.features.useFProperty)
                observation.status = "flags-not-applicable-to-uproperty";
        }
        else
        {
            const int64_t end = static_cast<int64_t>(offset) + (reference.kind == PropertyKind::Map ? 2 : 1) * pointer;
            observation.member = reference.kind == PropertyKind::Map ? "MapLayout-and-MapFlags" : "SetLayout";
            observation.basis = reference.kind == PropertyKind::Map ? "after-validated-key-value; script-map-layout=24; flags-width=1-or-4"
                                                                    : "after-validated-element; script-set-layout=20; heap-only";
            windowSize = reference.kind == PropertyKind::Map ? (schema_.features.useFProperty ? 28 : 24) : 20;
            if (offset < 0 || end > INT32_MAX)
                observation.status = "candidate-offset-unrepresentable";
            else
                offset = static_cast<int32_t>(end);
        }
        if (metadata.detailsStatus != PropertyMetadata::DetailsStatus::Complete)
            observation.status = "unvalidated-property-references";
        observation.offset = offset;
        observation.requested = windowSize;
        if (observation.status.empty())
        {
            const auto address = Add(metadata.address, offset);
            observation.address = address.value_or(0);
            if (!address || memory_.LimitExceeded() || !memory_.IsReadable(*address, windowSize))
                observation.status = "metadata-window-unreadable-or-budget-exhausted";
            else
            {
                observation.bytes.resize(windowSize);
                const auto read = memory_.ReadBytes(*address, observation.bytes.data(), windowSize);
                observation.readError = static_cast<int32_t>(read.error);
                observation.transferred = read.transferred;
                observation.readable = read.Ok();
                observation.status = read.Ok() ? "metadata-observed" : "metadata-read-failed";
                if (!read.Ok())
                    observation.bytes.clear();
            }
        }
        if (observation.readable && schema_.features.useFProperty)
        {
            const auto flagCandidate = [&](int32_t flagOffset, uint8_t width, const char *basis)
            {
                if (flagOffset < observation.offset)
                    return;
                const size_t index = static_cast<size_t>(flagOffset - observation.offset);
                if (index > observation.bytes.size() || width > observation.bytes.size() - index)
                    return;
                uint32_t raw = 0;
                std::memcpy(&raw, observation.bytes.data() + index, width);
                observation.flagCandidates.push_back({basis, flagOffset, width, raw, raw <= 1});
            };
            if (reference.kind == PropertyKind::Array)
            {
                const int64_t dataEnd = observation.propertyDataEnd;
                // Member 顺序必须符合独立验证过的 Inner 偏移
                if (dataEnd >= 0 && alignPointer(dataEnd) == observation.referenceOffset &&
                    observation.referenceOffset <= INT32_MAX - pointer)
                    flagCandidate(observation.referenceOffset + pointer, 4, "UE4.25-5.2-flags-after-inner");
                if (dataEnd >= 0 && dataEnd < observation.referenceOffset &&
                    alignPointer(dataEnd + 1) == observation.referenceOffset)
                    flagCandidate(observation.propertyDataEnd, 1, "UE5.3+-flags-before-inner");
            }
            else if (reference.kind == PropertyKind::Map && observation.offset <= INT32_MAX - 24)
            {
                flagCandidate(observation.offset + 24, 1, "UE5.3+-script-map-layout-tail");
                flagCandidate(observation.offset + 24, 4, "UE4.25-5.2-script-map-layout-tail");
            }
        }
        if (metadata.detailsStatus != PropertyMetadata::DetailsStatus::Complete)
            storage.allocatorStatus = "unvalidated-property-references";
        else if (!schema_.features.useFProperty || reference.kind == PropertyKind::Set)
        {
            storage.allocator = ::nextdumper::ir::ContainerAllocatorKind::Heap;
            storage.allocatorStatus = "source-defined-heap-only";
        }
        else if (!observation.readable)
            storage.allocatorStatus = observation.status;
        else if (observation.flagCandidates.empty())
            storage.allocatorStatus = "no-source-compatible-flag-offset";
        else
        {
            const uint32_t raw = observation.flagCandidates.front().raw;
            const bool consensus = std::all_of(observation.flagCandidates.begin(), observation.flagCandidates.end(),
                                               [raw](const auto &flag)
                                               { return flag.knownValue && flag.raw == raw; });
            storage.allocatorStatus = consensus ? "source-candidate-value-consensus" : "unknown-flags-or-candidate-disagreement";
            if (consensus)
                storage.allocator = raw == 0 ? ::nextdumper::ir::ContainerAllocatorKind::Heap
                                             : ::nextdumper::ir::ContainerAllocatorKind::MemoryImage;
        }
        if (reference.kind != PropertyKind::Array)
            ::nextdumper::ue::DecodeSparseLayout(observation, reference.kind);
        else
            storage.layoutStatus = "no-element-layout-record";
        const bool memoryImage = storage.allocator == ::nextdumper::ir::ContainerAllocatorKind::MemoryImage;
        const auto header = memoryImage ? ::nextdumper::ue::DescribeMemoryImageContainer(reference.kind, pointer)
                                        : ::nextdumper::ue::DescribeHeapContainer(reference.kind, pointer);
        if (storage.allocator == ::nextdumper::ir::ContainerAllocatorKind::Unknown)
            storage.headerStatus = "allocator-unresolved";
        else if (memoryImage && pointer == 4)
            storage.headerStatus = "android32-memory-image-reflection-unsupported";
        else if (!header || (memoryImage && reference.kind == PropertyKind::Map
                                 ? header->size > metadata.elementSize
                                 : header->size != metadata.elementSize))
            storage.headerStatus = "storage-size-mismatch";
        else if (reference.kind != PropertyKind::Array && !observation.sparseFormulaMatches.value_or(false))
            storage.headerStatus = "element-layout-unvalidated";
        else
        {
            storage.layoutId = header->id;
            storage.headerStatus = memoryImage && reference.kind == PropertyKind::Map && header->size != metadata.elementSize
                                       ? "source-model-fits-reflected-extent"
                                       : "source-model-and-size-match";
        }
        return observation;
    }

    std::optional<TypeIR> ReflectionReader::ReadType(uintptr_t object, TypeKind kind, ReflectionIR &ir) const
    {
        const auto name = objects_.Name(object);
        const auto className = objects_.ClassName(object);
        if (!name || !className)
        {
            ir.diagnostics.push_back("type identity unreadable: address=" + Hex(object) +
                                     " name_readable=" + std::to_string(name.has_value()) +
                                     " class_readable=" + std::to_string(className.has_value()));
            return std::nullopt;
        }
        const auto size = objects_.StructSize(object);
        const auto super = objects_.StructSuper(object);
        if (!size || *size < 0 || !super)
        {
            ir.diagnostics.push_back("type header invalid or unreadable: name=" + *name +
                                     " address=" + Hex(object) +
                                     " size_offset=" + std::to_string(schema_.ustruct.propertiesSizeOffset) +
                                     " size=" + (size ? std::to_string(*size) : "unreadable") +
                                     " super_offset=" + std::to_string(schema_.ustruct.superStruct) +
                                     " super_readable=" + std::to_string(super.has_value()));
            return std::nullopt;
        }

        TypeIR type;
        type.address = object;
        type.superAddress = *super;
        type.kind = kind;
        type.name = *name;
        const auto fullName = objects_.FullName(object);
        type.fullName = fullName ? *fullName : (*className + " " + *name);
        if (!fullName)
        {
            ++ir.stats.failures;
            type.status = ParseStatus::Partial;
            type.layoutConflicts.push_back("type full name could not be resolved");
        }
        type.size = *size;
        if (schema_.ustruct.propertiesSizeOffset >= 0 && schema_.ustruct.propertiesSizeOffset <= INT32_MAX - 4)
        {
            const auto address = Add(object, schema_.ustruct.propertiesSizeOffset + 4);
            std::array<uint8_t, 4> bytes{};
            if (address && memory_.IsReadable(*address, bytes.size()) &&
                memory_.ReadBytes(*address, bytes.data(), bytes.size()).Ok())
            {
                int16_t shortValue = 0;
                int32_t longValue = 0;
                uint32_t raw = 0;
                std::memcpy(&shortValue, bytes.data(), sizeof(shortValue));
                std::memcpy(&longValue, bytes.data(), sizeof(longValue));
                std::memcpy(&raw, bytes.data(), sizeof(raw));
                type.minAlignmentRaw = raw;
                // PropertiesSize 可能排除最终对齐填充
                const auto plausible = [](int32_t value)
                { return value > 0 && (value & (value - 1)) == 0; };
                if (plausible(shortValue) && plausible(longValue) && shortValue == longValue)
                {
                    type.minAlignment = shortValue;
                    type.minAlignmentStatus = "value-consensus-width-unresolved";
                }
                else
                    type.minAlignmentStatus = "value-consensus-unavailable";
            }
            else
                type.minAlignmentStatus = "unreadable";
        }
        const auto properties = objects_.StructProperties(object);
        if (properties)
            ReadProperties(*properties, type, ir.stats);
        else
        {
            ++ir.stats.failures;
            type.status = ParseStatus::Partial;
            type.layoutConflicts.push_back("property chain root unreadable");
        }
        const auto children = objects_.StructChildren(object);
        if (children)
            ReadFunctions(*children, type, ir);
        else
        {
            ++ir.stats.failures;
            type.status = ParseStatus::Partial;
            type.layoutConflicts.push_back("function chain root unreadable");
        }
        if (!type.layoutConflicts.empty())
            type.status = ParseStatus::Partial;
        return type;
    }

    EnumIR ReflectionReader::ReadEnum(uintptr_t object, ReflectionStats &stats) const
    {
        EnumIR result;
        result.address = object;
        const auto name = objects_.Name(object);
        const auto fullName = objects_.FullName(object);
        result.name = name ? *name : "<unreadable>";
        result.fullName = fullName ? *fullName : "Enum " + result.name;
        const auto failure = [&](const std::string &message)
        {
            result.status = ParseStatus::Partial;
            result.diagnostics.push_back(message);
            ++stats.failures;
            ++stats.enumReadFailures;
        };
        if (!name || !fullName)
            failure("enum identity could not be resolved");
        const auto readTail = [&](int32_t offset, bool byte, uint8_t &out)
        {
            const auto address = Add(object, offset);
            if (!address)
                return false;
            if (byte)
                return memory_.Read(*address, out);
            uint32_t value = 0;
            if (!memory_.Read(*address, value) || value > UINT8_MAX)
                return false;
            out = static_cast<uint8_t>(value);
            return true;
        };
        if (schema_.uenum.cppForm < 0 || !readTail(schema_.uenum.cppForm, schema_.features.enumCppFormIsByte, result.cppForm) || result.cppForm > 2)
            failure("enum CppForm is unreadable or invalid");
        if (schema_.features.enumHasFlags &&
            (schema_.uenum.flags < 0 || !readTail(schema_.uenum.flags, schema_.features.enumFlagsIsByte, result.flags)))
            failure("enum flags are unreadable or invalid");
        const auto values = objects_.ReadEnumValues(object);
        result.expectedValues = values.expectedCount;
        for (const EnumValueMetadata &value : values.values)
            result.values.push_back({value.name, value.value});
        if (!values.Complete())
            failure("enum values incomplete: status=" + std::to_string(static_cast<int>(values.status)) +
                    " expected=" + std::to_string(values.expectedCount) + " read=" + std::to_string(values.values.size()));
        return result;
    }

    ReflectionIR ReflectionReader::Read()
    {
        auto *performance = memory_.Performance();
        memory::ScopedReadTiming timing(performance ? &performance->reflectionRead : nullptr, 1);
        ReflectionIR result;
        std::vector<::nextdumper::ir::CaptureInfo::Attempt> history;
        for (uint32_t attempt = 1; attempt <= 2; ++attempt)
        {
            memory::ScopedReadTiming attemptTiming(performance ? &performance->reflectionAttempt : nullptr, 1);
            const auto started = std::chrono::steady_clock::now();
            if (progress_)
                progress_("capture attempt=" + std::to_string(attempt) + " started");
            if (attempt > 1 && !memory_.RefreshAddressSpace())
            {
                result.status = result.types.empty() ? ParseStatus::Failed : ParseStatus::Partial;
                result.capture.observationsStable = false;
                result.diagnostics.push_back("address-space refresh failed before capture retry");
                break;
            }
            memory_.Reset();
            ::nextdumper::memory::CaptureValidation validation;
            ::nextdumper::ir::CaptureInfo::Attempt details;
            result = ReadAttempt(validation, details);
            std::unordered_set<uintptr_t> exportedTypes;
            for (const auto &type : result.types)
                exportedTypes.insert(type.address);
            for (auto &[address, observation] : delegateSignatures_)
            {
                const auto definition = result.functions.find(address);
                observation.exported = definition != result.functions.end() && definition->second.headerReadable;
                observation.ownerExported = exportedTypes.contains(observation.outerAddress);
                observation.foundInChildren = definition != result.functions.end() && definition->second.discoveredFromChildren;
                observation.definitionStatus = definition == result.functions.end() ? "not-read" : ParseStatusName(definition->second.status);
                observation.discovery = observation.foundInChildren ? "children+property-reference" : "property-reference";
                if (const auto chain = functionChains_.find(observation.outerAddress); chain != functionChains_.end())
                {
                    observation.childrenRootReadable = true;
                    observation.childrenRoot = chain->second.first;
                    observation.childrenStatus = static_cast<int32_t>(chain->second.second);
                }
                result.delegateSignatures.push_back(observation);
            }
            result.containerStorageObservations = std::move(containerObservations_);
            result.containerStorageCandidates = containerCandidates_;
            result.containerStorageNotObserved = containerNotObserved_;
            if (diagnostic_)
            {
                memory::ScopedReadTiming evidenceTiming(performance ? &performance->reflectionEvidence : nullptr, 1);
                diagnostic_("reflection_evidence attempt=" + std::to_string(attempt) + " begin");
                detail::LogReflectionEvidence(result, moduleBase_, diagnostic_);
                for (const auto &message : result.diagnostics)
                    diagnostic_("reflection: " + message);
                diagnostic_("reflection_evidence attempt=" + std::to_string(attempt) + " end");
            }
            memory_.CopyReadFailures(validation);
            details.number = attempt;
            details.elapsedMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                          std::chrono::steady_clock::now() - started)
                                                          .count());
            details.observedRanges = validation.observedRanges;
            details.changedRanges = validation.changedRanges;
            details.unreadableRanges = validation.unreadableRanges;
            details.limitExceeded = validation.limitExceeded;
            details.generationChanged = validation.generationChanged;
            details.readFailures = validation.readFailures;
            details.failures = result.stats.failures;
            details.identityFailures = result.stats.identityFailures;
            const size_t diagnosticSamples = std::min<size_t>(result.diagnostics.size(), 32);
            details.diagnostics.assign(result.diagnostics.begin(), result.diagnostics.begin() + diagnosticSamples);
            for (const auto &failure : validation.readFailureSamples)
                details.readFailureSamples.push_back({failure.address, static_cast<int32_t>(failure.error),
                                                      failure.requested, failure.transferred});
            for (const auto &change : validation.changes)
                details.changes.push_back({change.address, change.size, static_cast<int32_t>(change.read.error),
                                           change.read.transferred, change.before, change.after});
            if (details.reason.empty())
                details.reason = !validation.Stable()       ? "observed-bytes-changed-or-unreadable"
                                 : validation.limitExceeded ? "observed-bytes-stable-partial-coverage"
                                                            : "observed-bytes-stable";
            history.push_back(std::move(details));
            if (progress_)
                progress_("capture attempt=" + std::to_string(attempt) + " elapsed_ms=" +
                          std::to_string(history.back().elapsedMs) + " reason=" + history.back().reason);
            result.capture.observationsStable = validation.Stable() && validation.observedRanges != 0 && history.back().coverageComplete;
            result.capture.limitExceeded = validation.limitExceeded;
            result.capture.generationChanged = validation.generationChanged;
            result.capture.observedRanges = validation.observedRanges;
            result.capture.observedBytes = validation.observedBytes;
            result.capture.changedRanges = validation.changedRanges;
            result.capture.unreadableRanges = validation.unreadableRanges;
            result.capture.attempts = attempt;
            result.capture.readFailures = validation.readFailures;
            for (const auto &failure : validation.readFailureSamples)
                result.capture.readFailureSamples.push_back({failure.address, static_cast<int32_t>(failure.error),
                                                             failure.requested, failure.transferred});
            if (!result.capture.observationsStable)
            {
                result.status = result.types.empty() ? ParseStatus::Failed : ParseStatus::Partial;
                result.diagnostics.push_back("capture validation: changed=" + std::to_string(validation.changedRanges) +
                                             " unreadable=" + std::to_string(validation.unreadableRanges) +
                                             " limit_exceeded=" + std::to_string(validation.limitExceeded) +
                                             " generation_changed=" + std::to_string(validation.generationChanged));
                for (uintptr_t address : validation.failedAddresses)
                    result.diagnostics.push_back("capture validation failed at address=" + Hex(address));
                if (!validation.limitExceeded && attempt == 1)
                    continue;
            }
            break;
        }
        result.capture.history = std::move(history);
        result.diagnostics.push_back("capture attempts=" + std::to_string(result.capture.attempts) +
                                     "; consistency covers observed bytes, not an atomic process snapshot");
        for (const auto &failure : result.capture.readFailureSamples)
            result.diagnostics.push_back("capture read failure: address=" + Hex(failure.address) +
                                         " requested=" + std::to_string(failure.requested) +
                                         " transferred=" + std::to_string(failure.transferred) +
                                         " read_error=" + std::to_string(failure.error));
        if (result.capture.readFailures > result.capture.readFailureSamples.size())
            result.diagnostics.push_back("capture read failure samples omitted=" +
                                         std::to_string(result.capture.readFailures - result.capture.readFailureSamples.size()));
        return result;
    }

    ReflectionIR ReflectionReader::ReadAttempt(::nextdumper::memory::CaptureValidation &validation,
                                               ::nextdumper::ir::CaptureInfo::Attempt &details)
    {
        ReflectionIR result;
        result.containerPointerWidth = static_cast<int32_t>(sizeof(uintptr_t));
        delegateSignatures_.clear();
        pendingSignatures_.clear();
        nextSignature_ = 0;
        functionChains_.clear();
        containerStorage_.clear();
        pendingContainers_.clear();
        containerEvidence_.clear();
        containerCandidates_.clear();
        containerNotObserved_.clear();
        containerObservations_.clear();
        ::nextdumper::memory::CaptureObservationScope observe(memory_);
        if (!objects_.Initialize())
        {
            result.status = ParseStatus::Failed;
            ++result.stats.failures;
            result.diagnostics.push_back("reflection object store initialization failed");
            details.reason = "object-store-initialization-failed";
            return result;
        }
        result.stats.objectSlots = objects_.Count();
        details.initialCount = objects_.Count();
        constexpr int32_t maxObjectSlots = 2 * 1024 * 1024;
        constexpr int32_t maxAdditionalSlots = 65536;
        constexpr uint32_t maxTailRounds = 3;
        if (objects_.Count() > maxObjectSlots)
        {
            result.stats.unvisitedObjects = objects_.Count();
            ++result.stats.failures;
            details.reason = "initial-object-slot-budget-exceeded";
            return result;
        }

        constexpr int32_t maxObjectSamplesPerReason = 8;
        const auto recordObjectDiagnostic = [&](int32_t count, const auto &message)
        {
            if (diagnostic_)
                diagnostic_(message());
            if (count <= maxObjectSamplesPerReason)
                result.diagnostics.push_back(message());
            else
                ++result.stats.objectDiagnosticSamplesOmitted;
        };
        const auto objectIdentity = [&](int32_t index, uintptr_t object, const std::string &className,
                                        uint32_t flags)
        {
            const auto name = objects_.Name(object);
            return "index=" + std::to_string(index) + " address=" + Hex(object) +
                   " class=" + className + " name=" + (name ? *name : "<unreadable>") +
                   " flags=" + std::to_string(flags);
        };

        std::unordered_set<uintptr_t> seenTypes;
        std::unordered_map<uintptr_t, std::optional<::nextdumper::ue::DefinitionKind>> classKinds;
        std::unordered_map<std::string, size_t> failureReasons;
        constexpr size_t windowSize = ::nextdumper::ue::ObjectStoreReader::kReadWindowSize;
        std::array<ObjectReadResult, windowSize> objectWindow{};
        std::array<uintptr_t, windowSize> rawClasses{};
        std::array<std::optional<uintptr_t>, windowSize> classWindow{};
        int32_t windowFirst = 0;
        size_t windowCount = 0;
        bool observationLimitReported = false;
        auto lastProgress = std::chrono::steady_clock::now();
        const auto recordFailure = [&](const std::string &reason, int32_t index, uintptr_t address)
        {
            const size_t count = ++failureReasons[reason];
            if (diagnostic_)
                diagnostic_("reflection_object_failure reason=" + reason +
                            " index=" + std::to_string(index) + " address=" + Hex(address));
            if (count <= 8)
                result.diagnostics.push_back("reflection object failure: reason=" + reason +
                                             " index=" + std::to_string(index) + " address=" + Hex(address));
        };
        auto *performance = memory_.Performance();
        const auto validate = [&]()
        {
            const uint64_t before = performance ? performance->captureValidate.nanos : 0;
            auto checked = memory_.Validate();
            if (performance && diagnostic_)
                diagnostic_("memory_investigation phase=capture-validation round=" +
                            std::to_string(performance->captureValidate.calls) +
                            " elapsed_ns=" + std::to_string(performance->captureValidate.nanos - before) +
                            " observed_ranges=" + std::to_string(checked.observedRanges) +
                            " observed_bytes=" + std::to_string(checked.observedBytes));
            return checked;
        };
        std::optional<memory::ScopedReadTiming> enumerationTiming;
        if (performance)
            enumerationTiming.emplace(&performance->reflectionEnumeration, 1);
        for (int32_t index = 0;; ++index)
        {
            if (index == objects_.Count())
            {
                enumerationTiming.reset();
                details.enumeratedCount = index;
                if (progress_)
                    progress_("capture: validating observed bytes; enumerated=" + std::to_string(index));
                CloseDelegateSignatures(result);
                validation = validate();
                const auto boundary = objects_.RefreshObjectCount();
                details.countAddress = boundary.countAddress;
                details.finalCount = boundary.count;
                if (!boundary.valid)
                {
                    details.reason = boundary.reason;
                    ++result.stats.failures;
                    break;
                }
                if (!validation.Stable())
                {
                    details.reason = "observed-bytes-changed-or-unreadable";
                    break;
                }
                if (boundary.count == index)
                {
                    // coverageComplete 描述"每个被访问的对象都参与了稳定性校验"
                    // 预算耗尽使部分字节未冻结，此时枚举虽完整，校验覆盖并不完整
                    details.coverageComplete = !validation.limitExceeded;
                    break;
                }
                result.stats.objectSlots = boundary.count;
                if (details.tailRounds >= maxTailRounds || boundary.count > maxObjectSlots ||
                    boundary.count - details.initialCount > maxAdditionalSlots)
                {
                    result.stats.unvisitedObjects = boundary.count - index;
                    ++result.stats.failures;
                    details.reason = "object-tail-budget-exceeded";
                    break;
                }
                ++details.tailRounds;
                if (progress_)
                    progress_("capture: count grew from=" + std::to_string(index) + " to=" + std::to_string(boundary.count) +
                              "; reading tail round=" + std::to_string(details.tailRounds));
                if (performance)
                    enumerationTiming.emplace(&performance->reflectionEnumeration, 1);
            }
            if (progress_ && index % 256 == 0 && std::chrono::steady_clock::now() - lastProgress >= std::chrono::seconds(1))
            {
                progress_("reflection visited=" + std::to_string(index) + "/" + std::to_string(objects_.Count()) +
                          " types=" + std::to_string(result.stats.parsedTypes));
                lastProgress = std::chrono::steady_clock::now();
            }
            // 观测预算只影响字节冻结范围，读取仍然有效
            // 这里继续枚举并在结束时按已冻结范围校验，未冻结的字节不计入一致性证据
            // 覆盖不完整由 capture.coverageComplete 与 limitExceeded 表达
            if (memory_.LimitExceeded() && !observationLimitReported)
            {
                observationLimitReported = true;
                result.diagnostics.push_back("capture observation budget exhausted at index=" + std::to_string(index) +
                                             "; enumeration continues without freezing further bytes");
            }
            if (index < windowFirst || static_cast<size_t>(index - windowFirst) >= windowCount)
            {
                windowFirst = index;
                windowCount = std::min(objectWindow.size(), static_cast<size_t>(objects_.Count() - index));
                if (!objects_.Objects().ReadObjects(index, {objectWindow.data(), windowCount}))
                    throw std::runtime_error("Reflection object window contract failed");
                classWindow.fill(std::nullopt);
                std::array<::nextdumper::memory::ReadRequest, windowSize> requests{};
                std::array<::nextdumper::memory::ReadResult, windowSize> reads{};
                std::array<size_t, windowSize> owners{};
                size_t count = 0;
                for (size_t slot = 0; slot < windowCount; ++slot)
                {
                    if (!objectWindow[slot].IsValid())
                        continue;
                    const auto address = Add(objectWindow[slot].address, schema_.uobject.classPointer);
                    if (!address)
                        continue;
                    requests[count] = {*address, &rawClasses[slot], sizeof(uintptr_t)};
                    owners[count++] = slot;
                }
                // 本轮已知对象头共用批读，但每个字段仍进入 Capture 的观测和验证
                if (!memory_.ReadBatch({requests.data(), count}, {reads.data(), count}))
                    throw std::runtime_error("Reflection class pointer batch contract failed");
                for (size_t slot = 0; slot < count; ++slot)
                    if (reads[slot].Ok() && rawClasses[owners[slot]])
                        classWindow[owners[slot]] = objects_.DecodeClassPointer(
                            rawClasses[owners[slot]],
                            requests[slot].address);
            }
            const size_t windowIndex = static_cast<size_t>(index - windowFirst);
            const ObjectReadResult objectResult = objectWindow[windowIndex];
            if (!objectResult.IsValid())
            {
                ++result.stats.skippedObjects;
                if (objectResult.status == ObjectReadStatus::Empty)
                {
                    ++result.stats.emptyObjectSlots;
                    recordObjectDiagnostic(result.stats.emptyObjectSlots, [&]
                                           { return "empty object slot: index=" + std::to_string(index) +
                                                    " read_address=" + Hex(objectResult.readAddress); });
                }
                else
                {
                    ++result.stats.objectReadFailures;
                    ++result.stats.failures;
                    recordObjectDiagnostic(result.stats.objectReadFailures, [&]
                                           { return "object slot could not be read: index=" + std::to_string(index) +
                                                    " reason=" + ::nextdumper::ue::ObjectReadStatusName(objectResult.status) +
                                                    " read_address=" + Hex(objectResult.readAddress) +
                                                    " pointer=" + Hex(objectResult.address) +
                                                    " read_error=" + std::to_string(static_cast<int>(objectResult.readError)); });
                }
                continue;
            }
            const uintptr_t object = objectResult.address;
            ++result.stats.validObjects;
            const auto classAddress = classWindow[windowIndex];
            if (!classAddress || !*classAddress)
            {
                ++result.stats.failures;
                recordFailure("class-pointer-unreadable-or-null", index, object);
                continue;
            }
            const auto className = classAddress ? objects_.Name(*classAddress) : std::nullopt;
            if (!className)
            {
                ++result.stats.classNameReadFailures;
                ++result.stats.failures;
                recordObjectDiagnostic(result.stats.classNameReadFailures, [&]
                                       { return "object class name could not be read: index=" + std::to_string(index) +
                                                " address=" + Hex(object); });
                continue;
            }
            auto classification = classKinds.find(*classAddress);
            if (classification == classKinds.end())
            {
                ::nextdumper::memory::CaptureObservationScope observe(memory_);
                classification = classKinds.emplace(*classAddress, objects_.DefinitionKindForClass(*classAddress)).first;
            }
            if (!classification->second)
            {
                ++result.stats.failures;
                ++result.stats.classNameReadFailures;
                recordFailure("class-hierarchy-unresolved", index, object);
                continue;
            }
            const auto kind = *classification->second;
            if (index >= details.initialCount)
            {
                const auto tailIndex = objects_.InternalIndex(object);
                const auto tailFlags = objects_.Flags(object);
                const auto internalFlags = objects_.Objects().ReadInternalFlags(objectResult);
                if (!tailIndex || *tailIndex != index || !tailFlags ||
                    !internalFlags || (*internalFlags & 0x80000000u) != 0 || // PendingConstruction in supported layouts.
                    (*tailFlags & ::nextdumper::ue::kRFUnavailableDefinition) != 0 ||
                    objects_.InternalIndex(object, true) != tailIndex || objects_.Class(object, true) != classAddress ||
                    objects_.Objects().ReadObject(index, true).address != object)
                {
                    ++result.stats.failures;
                    ++result.stats.skippedIncompleteObjects;
                    recordFailure("new-object-not-ready-or-identity-changed", index, object);
                    memory_.Invalidate();
                    continue;
                }
            }
            if (kind == ::nextdumper::ue::DefinitionKind::Other)
                continue;
            ::nextdumper::memory::CaptureObservationScope observe(memory_);
            const auto verifiedObject = objects_.Objects().ReadObject(index, true);
            const auto observedIndex = objects_.InternalIndex(object);
            const auto internalIndex = objects_.InternalIndex(object, true);
            const auto verifiedClass = objects_.Class(object, true);
            if (!verifiedObject.IsValid() || verifiedObject.address != object || !internalIndex || *internalIndex != index ||
                observedIndex != internalIndex ||
                !verifiedClass || *verifiedClass != *classAddress)
            {
                ++result.stats.failures;
                ++result.stats.identityFailures;
                memory_.Invalidate();
                recordObjectDiagnostic(result.stats.identityFailures, [&]
                                       { return "reflection object identity mismatch: index=" + std::to_string(index) +
                                                " address=" + Hex(object); });
                continue;
            }
            const auto objectFlags = objects_.Flags(object);
            if (!objectFlags)
            {
                ++result.stats.failures;
                recordFailure("object-flags-unreadable", index, object);
                continue;
            }
            if ((*objectFlags & ::nextdumper::ue::kRFClassDefaultObject) != 0)
            {
                ++result.stats.skippedClassDefaultObjects;
                ++result.stats.skippedObjects;
                recordObjectDiagnostic(result.stats.skippedClassDefaultObjects, [&]
                                       { return "skipped reflection class default object: " +
                                                objectIdentity(index, object, *className, *objectFlags); });
                continue;
            }
            if ((*objectFlags & ::nextdumper::ue::kRFUnavailableDefinition) != 0)
            {
                ++result.stats.skippedIncompleteObjects;
                ++result.stats.skippedObjects;
                ++result.stats.failures;
                recordObjectDiagnostic(result.stats.skippedIncompleteObjects, [&]
                                       { return "reflection definition is not ready or is being destroyed: " +
                                                objectIdentity(index, object, *className, *objectFlags); });
                continue;
            }
            if (kind == ::nextdumper::ue::DefinitionKind::Enum)
            {
                result.enums.push_back(ReadEnum(object, result.stats));
                ++result.stats.parsedEnums;
                if (index >= details.initialCount)
                    ++details.additionalEnums;
                continue;
            }
            if (!seenTypes.insert(object).second)
                continue;

            const auto type = ReadType(object, kind == ::nextdumper::ue::DefinitionKind::Class ? TypeKind::Class : TypeKind::Struct, result);
            if (!type)
            {
                ++result.stats.failures;
                recordFailure("type-header-unavailable", index, object);
                continue;
            }
            result.types.push_back(*type);
            ++result.stats.parsedTypes;
            if (index >= details.initialCount)
                ++details.additionalTypes;
        }
        enumerationTiming.reset();
        memory::ScopedReadTiming finalizeTiming(performance ? &performance->reflectionFinalize : nullptr, 1);
        if (!details.coverageComplete && details.reason.empty())
            details.reason = "enumeration-coverage-incomplete";
        result.diagnostics.push_back("object enumeration: initial_count=" + std::to_string(details.initialCount) +
                                     " enumerated_count=" + std::to_string(details.enumeratedCount) +
                                     " final_count=" + std::to_string(details.finalCount) +
                                     " tail_rounds=" + std::to_string(details.tailRounds) + " reason=" + details.reason);

        if (result.stats.objectDiagnosticSamplesOmitted != 0)
            result.diagnostics.push_back("object diagnostic samples omitted=" +
                                         std::to_string(result.stats.objectDiagnosticSamplesOmitted) +
                                         "; sample limit per reason=" + std::to_string(maxObjectSamplesPerReason));
        for (const auto &[reason, count] : failureReasons)
            result.diagnostics.push_back("reflection object failure summary: reason=" + reason +
                                         " total=" + std::to_string(count) +
                                         " samples_omitted=" + std::to_string(count > 8 ? count - 8 : 0));

        std::unordered_map<uintptr_t, size_t> enumByAddress;
        for (size_t index = 0; index < result.enums.size(); ++index)
            enumByAddress.emplace(result.enums[index].address, index);
        const auto inferEnumType = [&](const auto &self, const TypeReferenceIR &reference, size_t depth) -> void
        {
            if (depth >= 32)
                return;
            if (reference.kind == PropertyKind::Enum && reference.inner && reference.inner->detailsResolved)
            {
                const auto index = enumByAddress.find(reference.secondaryObject);
                if (index != enumByAddress.end())
                {
                    EnumUnderlyingType underlying = EnumUnderlyingType::Unknown;
                    switch (reference.inner->kind)
                    {
                    case PropertyKind::Int8:
                        underlying = EnumUnderlyingType::Int8;
                        break;
                    case PropertyKind::Byte:
                        underlying = EnumUnderlyingType::UInt8;
                        break;
                    case PropertyKind::Int16:
                        underlying = EnumUnderlyingType::Int16;
                        break;
                    case PropertyKind::UInt16:
                        underlying = EnumUnderlyingType::UInt16;
                        break;
                    case PropertyKind::Int32:
                        underlying = EnumUnderlyingType::Int32;
                        break;
                    case PropertyKind::UInt32:
                        underlying = EnumUnderlyingType::UInt32;
                        break;
                    case PropertyKind::Int64:
                        underlying = EnumUnderlyingType::Int64;
                        break;
                    case PropertyKind::UInt64:
                        underlying = EnumUnderlyingType::UInt64;
                        break;
                    default:
                        break;
                    }
                    EnumIR &enumeration = result.enums[index->second];
                    if (enumeration.underlyingType == EnumUnderlyingType::Unknown)
                        enumeration.underlyingType = underlying;
                    else if (enumeration.underlyingType != underlying)
                    {
                        enumeration.status = ParseStatus::Partial;
                        enumeration.diagnostics.push_back("conflicting enum underlying property types");
                        ++result.stats.layoutConflicts;
                    }
                }
            }
            if (reference.inner)
                self(self, *reference.inner, depth + 1);
            if (reference.key)
                self(self, *reference.key, depth + 1);
            if (reference.value)
                self(self, *reference.value, depth + 1);
        };
        for (const TypeIR &type : result.types)
            for (const PropertyIR &property : type.properties)
                inferEnumType(inferEnumType, property.type, 0);
        for (const auto &[address, function] : result.functions)
        {
            (void)address;
            for (const PropertyIR &parameter : function.parameters)
                inferEnumType(inferEnumType, parameter.type, 0);
            for (const PropertyIR &local : function.locals)
                inferEnumType(inferEnumType, local.type, 0);
        }

        std::unordered_map<std::string, size_t> detailCounts;
        const auto noteDetails = [&](const PropertyIR &property, const std::string &owner, uintptr_t ownerAddress)
        {
            for (const auto &detail : property.detailDiagnostics)
            {
                if (++detailCounts[detail.reason + ":" + detail.normalizedClass] <= 8)
                    result.diagnostics.push_back("property detail failure: owner=" + owner +
                                                 " owner_address=" + Hex(ownerAddress) +
                                                 " root=" + property.name + " property=" + detail.name +
                                                 " property_class=" + detail.reflectedClass +
                                                 " address=" + Hex(detail.address) +
                                                 " reason=" + detail.reason +
                                                 " referenced_address=" + Hex(detail.referencedAddress) +
                                                 " secondary_address=" + Hex(detail.secondaryAddress));
            }
        };
        for (const TypeIR &type : result.types)
            for (const auto &property : type.properties)
                noteDetails(property, type.fullName, type.address);
        for (const auto &[address, function] : result.functions)
        {
            (void)address;
            for (const auto &property : function.parameters)
                noteDetails(property, function.fullName, function.address);
            for (const auto &property : function.locals)
                noteDetails(property, function.fullName, function.address);
        }
        for (const auto &[reason, count] : detailCounts)
            result.diagnostics.push_back("property detail summary: reason_and_class=" + reason + " total=" + std::to_string(count) +
                                         " samples_omitted=" + std::to_string(count > 8 ? count - 8 : 0));

        ::nextdumper::ir::AnalyzeReflectionLayouts(result);
        CollectContainerStorage(result);
        if (result.stats.parsedTypes == 0)
            result.status = ParseStatus::Failed;
        else if (result.stats.failures != 0 || result.stats.unknownProperties != 0 ||
                 result.stats.unresolvedTypeDetails != 0 || result.stats.layoutConflicts != 0)
            result.status = ParseStatus::Partial;
        else
            result.status = ParseStatus::Complete;
        return result;
    }
} // namespace nextdumper::reflection
