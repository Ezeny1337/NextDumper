#include "SdkEmitter.hpp"

#include <algorithm>
#include <initializer_list>
#include <ostream>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "nextdumper/common/Hex.hpp"
#include "nextdumper/generation/JsonExport.hpp"
#include "nextdumper/ir/ReflectionLayout.hpp"
#include "nextdumper/ue/ContainerLayout.hpp"

namespace nextdumper::generation::detail
{
    using ir::EnumIR;
    using ir::EnumUnderlyingType;
    using ir::LayoutIssueKind;
    using ir::PropertyKind;
    using ::nextdumper::common::Hex;

    void SdkEmitter::SdkEntry(std::ostream &stream) const
    {
        stream << "#pragma once\n\n";
        stream << "// Umbrella header for the generated SDK. Include this file only.\n";
        stream << "// These are target-memory descriptions, not native ABI declarations.\n";
        stream << "#include \"BasicTypes.hpp\"\n";
        stream << "#include \"EngineLayouts.hpp\"\n";
        stream << "#include \"Enums.hpp\"\n";
        stream << "#include \"Types.hpp\"\n";
        stream << "#include \"Functions.hpp\"\n";
    }

    void SdkEmitter::BasicTypes(std::ostream &stream, const CppSymbols &symbols) const
    {
        const auto &identity = schema_.identity;
        stream << "#pragma once\n#include <cstddef>\n#include <cstdint>\n#include <optional>\n#include <type_traits>\n#include <utility>\n\n";
        stream << "// For inspection and analysis; reflected offsets and sizes are authoritative.\n";
        stream << "// Declarations are not target-ABI-verified native objects. Do not use sizeof/offsetof as reflection data.\n";
        stream << "// Canonical profile: " << identity.canonicalProfileId << " (" << identity.canonicalVersionRange << ").\n";
        stream << "// Runtime layout: " << identity.layoutProfileId << "; layout confidence: validated.\n";
        stream << "// Engine-version confidence: " << identity.versionConfidence
               << " (selection: " << identity.selectionReason << ").\n";
        stream << "// Layout-compatible profiles:";
        for (const auto &profile : identity.compatibleProfiles)
            stream << " " << profile;
        stream << "\n";
        for (const auto &evidence : identity.evidence)
            stream << "// Version evidence: " << evidence.kind << "=" << evidence.observed
                   << " [" << ::nextdumper::ue::VersionEvidenceStrengthName(evidence.strength) << "]\n";
        stream << "// Capture observations stable: " << (reflection_.capture.observationsStable ? "yes" : "no")
               << "; changed ranges: " << reflection_.capture.changedRanges
               << "; read failures: " << reflection_.capture.readFailures << ".\n";
        stream << "// Target pointer width: " << static_cast<unsigned int>(module_.pointerWidth) << " bytes.\n";
        stream << "namespace NextDumper\n{\n";
        stream << "struct FName { std::uint8_t Data[" << schema_.fname.size << "]; };\n";
        const char *targetPointer = module_.pointerWidth == 8 ? "std::uint64_t" : "std::uint32_t";
        stream << "using TargetAddress = " << targetPointer << ";\n";
        stream << "// Pointer-width words preserve semantic pointees; encoded object handles are not decoded.\n";
        stream << "template <typename SemanticType> struct TTargetPointer { using Pointee = SemanticType; TargetAddress Bits; };\n";
        stream << "// String families share this header shape; their character encoding is distinct and not decoded here.\n";
        stream << "struct FString { TargetAddress Data; std::int32_t Num; std::int32_t Max; };\n";
        stream << "struct FUtf8String { TargetAddress Data; std::int32_t Num; std::int32_t Max; };\n";
        stream << "struct FAnsiString { TargetAddress Data; std::int32_t Num; std::int32_t Max; };\n";
        stream << "// Allocator internals are not selected from a matching total size.\n";
        stream << "// Layout tags describe target offsets, not native C++ instances or verified live values.\n";
        stream << "struct FUnknownContainerLayout {};\n";
        stream << "struct FUnknownValueLayout {};\n";
        for (const auto &[id, layout] : reflection_.valueStorageLayouts)
        {
            stream << "struct " << ValueLayoutCppName(id) << " // " << layout.sourceRange << "\n{\n";
            stream << "    static constexpr std::size_t size = " << layout.size
                   << ";\n    static constexpr std::size_t alignment = " << layout.alignment << ";\n";
            for (const auto &[member, offset] : layout.offsets)
                stream << "    static constexpr std::size_t " << member << " = " << offset << ";\n";
            stream << "};\n";
        }
        for (const auto &[kind, name] : {std::pair{PropertyKind::Array, "FHeapArrayLayout"},
                                         std::pair{PropertyKind::Set, "FHeapSparseSetLayout"}})
            if (const auto layout = ::nextdumper::ue::DescribeHeapContainer(kind, module_.pointerWidth))
            {
                stream << "struct " << name << " // " << layout->id << "\n{\n";
                stream << "    static constexpr std::size_t size = " << layout->size << ";\n";
                stream << "    static constexpr std::size_t alignment = " << layout->alignment << ";\n";
                for (const auto &[member, offset] : layout->offsets)
                    stream << "    static constexpr std::size_t " << member << " = " << offset << ";\n";
                stream << "};\n";
            }
        for (const auto &[kind, name] : {std::pair{PropertyKind::Array, "FMemoryImageArrayLayout"},
                                         std::pair{PropertyKind::Set, "FMemoryImageSparseSetLayout"}})
            if (const auto layout = ::nextdumper::ue::DescribeMemoryImageContainer(kind, module_.pointerWidth))
            {
                stream << "struct " << name << " // candidate encodings: UE4 shift-1 or UE5 packed-offset-40\n{\n";
                stream << "    static constexpr std::size_t size = " << layout->size
                       << ";\n    static constexpr std::size_t alignment = " << layout->alignment << ";\n";
                for (const auto &[member, offset] : layout->offsets)
                    stream << "    static constexpr std::size_t " << member << " = " << offset << ";\n";
                stream << "};\n";
            }
        stream << "template <std::size_t StorageSize> struct TOpaqueStorage { std::uint8_t Data[StorageSize]; };\n";
        stream << "template <typename ElementType, std::size_t StorageSize, typename Layout = FUnknownContainerLayout> struct TArray : TOpaqueStorage<StorageSize> { using Element = ElementType; using StorageLayout = Layout; };\n";
        stream << "template <typename ElementType, std::size_t ElementSize, std::size_t Count> struct TStaticArrayStorage { using Element = ElementType; std::uint8_t Data[ElementSize][Count]; };\n";
        stream << "template <std::size_t StorageSize, typename Layout = FUnknownValueLayout> struct FTextStorage : TOpaqueStorage<StorageSize> { using StorageLayout = Layout; };\n";
        for (const char *wrapper : {"TStructStorage", "TWeakObjectStorage", "TLazyObjectStorage", "TSoftObjectStorage", "TSoftClassStorage", "TDelegateStorage", "TInlineMulticastDelegateStorage", "TSparseMulticastDelegateStorage", "TUnknownMulticastDelegateStorage", "TOptionalStorage"})
            stream << "template <typename Type, std::size_t StorageSize, typename Layout = FUnknownValueLayout> struct " << wrapper << " : TOpaqueStorage<StorageSize> { using SemanticType = Type; using StorageLayout = Layout; };\n";
        stream << "// The ordinary weak pair is descriptive only; object resolution must also validate the serial.\n";
        stream << "template <typename Type, typename Layout> struct TWeakObjectStorage<Type, 8, Layout> { using SemanticType = Type; using StorageLayout = Layout; std::int32_t ObjectIndex; std::int32_t ObjectSerialNumber; };\n";
        stream << "// Delegate wrappers preserve signature and storage form, not callable bindings.\n";
        stream << "// Sparse multicast bindings are external; field bytes do not contain an invocation list.\n";
        stream << "template <typename Signature, typename Layout> struct TSparseMulticastDelegateStorage<Signature, 1, Layout> { using SemanticType = Signature; using StorageLayout = Layout; std::uint8_t Bound; };\n";
        stream << "template <std::size_t StorageSize> struct TFieldPathStorage : TOpaqueStorage<StorageSize> {};\n";
        for (const auto &[address, function] : reflection_.functions)
            if (function.headerReadable && function.referencedAsSignature)
                stream << "struct " << symbols.functions.at(address) << "_Signature; // " << EscapeJson(function.fullName)
                       << " metadata=" << Hex(address) << "\n";
        stream << "struct FScriptInterface { TargetAddress ObjectPointer; TargetAddress InterfacePointer; };\n";
        stream << "// Opaque container storage; StorageSize comes from the reflected field.\n";
        stream << "template <typename ElementType, std::size_t StorageSize, typename Layout = FUnknownContainerLayout> struct TSet : TOpaqueStorage<StorageSize> { using Element = ElementType; using StorageLayout = Layout; };\n";
        stream << "template <typename KeyType, typename ValueType, std::size_t StorageSize, typename Layout = FUnknownContainerLayout> struct TMap : TOpaqueStorage<StorageSize> { using Key = KeyType; using Value = ValueType; using StorageLayout = Layout; };\n";
        stream << "// Field storage and the enum definition may have different widths. Conversions check representability.\n";
        stream << "template <typename EnumType, typename StorageType> struct TEnumStorage\n{\n";
        stream << "    static_assert(std::is_enum_v<EnumType> && std::is_integral_v<StorageType>);\n";
        stream << "    StorageType Value;\n";
        stream << "    std::optional<EnumType> TryGet() const\n    {\n";
        stream << "        using Underlying = std::underlying_type_t<EnumType>;\n";
        stream << "        if (!std::in_range<Underlying>(Value)) return std::nullopt;\n";
        stream << "        return static_cast<EnumType>(static_cast<Underlying>(Value));\n    }\n";
        stream << "    bool TrySet(EnumType value)\n    {\n";
        stream << "        const auto raw = static_cast<std::underlying_type_t<EnumType>>(value);\n";
        stream << "        if (!std::in_range<StorageType>(raw)) return false;\n";
        stream << "        Value = static_cast<StorageType>(raw);\n        return true;\n    }\n};\n";
        stream << "}\n";
    }

    SdkEmitter::FieldGenerationPlan SdkEmitter::BuildFieldGenerationPlan(
        const TypeIR &owner, const FunctionIR *function, const std::vector<PropertyIR> &properties,
        int32_t size, const CppSymbols &symbols) const
    {
        const auto &analysis = function ? function->layout : owner.layout;
        FieldGenerationPlan plan;
        plan.initialOffset = analysis.baseExtentKnown ? analysis.baseExtent : 0;
        plan.size = size;
        plan.representation = function ? analysis.representation : symbols.types.at(owner.address).layout;
        plan.declarationDependencyBlocked = !function && symbols.types.at(owner.address).declarationDependencyBlocked;
        plan.fields.reserve(properties.size());
        for (const PropertyIR &property : properties)
        {
            FieldDescription entry = DescribeField(property, size, symbols, module_.pointerWidth,
                                                   schema_.fname.size);
            entry.layout = plan.representation;
            plan.fields.push_back(std::move(entry));
        }
        return plan;
    }

    void SdkEmitter::WriteFields(std::ostream &stream,
                                 const TypeIR &owner,
                                 const FunctionIR *function,
                                 const FieldGenerationPlan &plan,
                                 const CppSymbols &symbols,
                                 GenerationReport &report) const
    {
        const int32_t size = plan.size;
        const int32_t initialOffset = plan.initialOffset;
        const auto &analysis = function ? function->layout : owner.layout;
        const std::string scope = function ? "function-parameters" : "type-fields";
        const auto opaqueReasonFor = [](const FieldDescription &entry)
        {
            const auto &property = *entry.property;
            if (ir::IsVirtualProperty(property))
                return "virtual-property-no-storage";
            if (!entry.validBounds)
                return "invalid-bounds";
            if (!property.typeDetailsResolved)
                return "unresolved-type-details";
            if (property.type.kind == PropertyKind::Bool && !entry.boolLayout)
                return "invalid-bool-layout";
            if (entry.type.name.empty() && property.type.kind != PropertyKind::Bool)
                return "no-sized-cpp-representation";
            if (entry.type.IsOpaque())
                return entry.type.storage == PropertyStorageKind::PartialContainer ? "container-child-internals-not-expanded" : "internals-not-expanded";
            return "none";
        };
        const auto registerOwner = [&]
        {
            const auto super = function ? symbols.types.end() : symbols.types.find(owner.superAddress);
            report.RegisterOwner({function ? function->address : owner.address,
                                  function ? function->fullName : owner.fullName, scope,
                                  function ? 0 : owner.superAddress,
                                  size, super == symbols.types.end() ? -1 : super->second.size, initialOffset});
        };
        const auto recordOpaque = [&](const FieldDescription &entry)
        {
            registerOwner();
            OpaqueField field;
            field.ownerAddress = function ? function->address : owner.address;
            field.property = entry.property;
            field.reason = opaqueReasonFor(entry);
            report.RecordOpaque(std::move(field));
        };
        // 每个字段只保留一行注释：字段名、反射来源、类型与异常成因
        // 偏移、尺寸、维度由紧随其后的 constexpr 成员表达，不在此重复
        // includeType 仅在无成员声明（offset-description 表示）时为 true，避免与声明行重复
        const auto describe = [&](const FieldDescription &entry, bool includeType)
        {
            const auto &property = *entry.property;
            const char *opaqueReason = opaqueReasonFor(entry);
            stream << "    // " << EscapeJson(property.name) << " metadata=" << Hex(property.address)
                   << " flags=" << Hex(property.flags);
            if (!entry.type.semanticName.empty() && entry.type.semanticName != entry.type.name)
                stream << " semantic=" << EscapeJson(entry.type.semanticName);
            if (includeType && !entry.type.name.empty())
                stream << " type=" << EscapeJson(entry.type.name);
            if (property.status != ParseStatus::Complete)
                stream << " status=" << ParseStatusName(property.status);
            if (std::string_view(opaqueReason) != "none" && std::string_view(opaqueReason) != "internals-not-expanded")
                stream << " opaque_reason=" << opaqueReason;
            if (!entry.type.failureReason.empty() && entry.type.failureReason != "internals-not-expanded" &&
                entry.type.failureReason != "container-internals-not-expanded")
                stream << " cpp_representation_reason=" << EscapeJson(entry.type.failureReason);
            if (function)
            {
                if (property.isReturnParameter)
                    stream << " return";
                if (property.isOutParameter)
                    stream << " out";
                if (property.isReferenceParameter)
                    stream << " reference";
                if (property.isConstParameter)
                    stream << " const";
            }
            stream << '\n';
        };
        for (const auto &entry : plan.fields)
        {
            auto description = entry;
            const auto typeKey = std::tie(entry.type.name, entry.type.semanticName, entry.type.failureReason,
                                          entry.type.failurePath, entry.type.storage, entry.type.semanticsResolved);
            auto type = report.typeIds.find(typeKey);
            if (type == report.typeIds.end())
                type = report.typeIds.emplace(typeKey, report.typeIds.size()).first;
            description.typeId = type->second;
            if (!report.fields.contains(entry.property->address))
                ++report.storageKinds[entry.type.storage];
            report.fields.insert_or_assign(entry.property->address, std::move(description));
        }
        for (size_t issueIndex = 0; issueIndex < analysis.issues.size(); ++issueIndex)
        {
            const auto &issue = analysis.issues[issueIndex];
            registerOwner();
            LayoutEvent event;
            event.category = LayoutIssueKindName(issue.kind);
            event.message = issue.message;
            event.ownerAddress = function ? function->address : owner.address;
            event.conflictingAddress = issue.conflictingAddress;
            event.cursorSource = "layout-analysis";
            event.layoutIssueIndex = issueIndex;
            const auto property = std::find_if(plan.fields.begin(), plan.fields.end(), [&](const FieldDescription &entry)
                                               { return entry.property->address == issue.propertyAddress; });
            if (property != plan.fields.end())
                event.property = property->property;
            const auto conflicting = std::find_if(plan.fields.begin(), plan.fields.end(), [&](const FieldDescription &entry)
                                                  { return entry.property->address == issue.conflictingAddress; });
            if (conflicting != plan.fields.end())
                event.conflictingProperty = conflicting->property->name;
            event.strategy = LayoutRepresentationName(plan.representation);
            if ((issue.kind == LayoutIssueKind::InheritedExtentIntersection ||
                 issue.kind == LayoutIssueKind::VirtualPropertyWithoutOffset) &&
                !issue.affectsCompleteness)
                report.Info(std::move(event));
            else
                report.Warn(std::move(event));
        }
        if (plan.representation == LayoutRepresentation::OffsetDescription)
        {
            registerOwner();
            LayoutEvent event;
            event.category = "offset-description";
            event.message = "fields use explicit offset descriptions; sequential member order is not asserted";
            event.ownerAddress = function ? function->address : owner.address;
            event.strategy = "offset-description";
            event.cursorSource = plan.declarationDependencyBlocked ? "declaration-dependency" : "layout-analysis";
            report.Info(std::move(event));
            stream << "    // Representation: offset-description; reflected order is not asserted.\n";
            stream << "    // Native data size is the reflected type/parameter size; unreflected bytes are not inferred as padding.\n";
            size_t ordinal = 0;
            for (const FieldDescription &entry : plan.fields)
            {
                describe(entry, true);
                const PropertyIR &property = *entry.property;
                const std::string member = SanitizeIdentifier(property.name, "Member_") + "_" + std::to_string(ordinal++);
                if (ir::IsVirtualProperty(property))
                {
                    stream << "    // Virtual property has no useful Offset_Internal and is excluded from physical storage: name="
                           << EscapeJson(property.name) << " symbol=" << member << " flags=" << Hex(property.flags) << "\n";
                    continue;
                }
                if (!entry.validBounds)
                {
                    stream << "    // Field has invalid dimensions or exceeds the reflected extent: symbol="
                           << member << "\n";
                    recordOpaque(entry);
                    continue;
                }
                stream << "    static constexpr std::size_t " << member << "_Offset = " << property.offset << ";\n";
                stream << "    static constexpr std::size_t " << member << "_ElementSize = " << property.elementSize << ";\n";
                stream << "    static constexpr std::size_t " << member << "_ArrayDim = " << property.arrayDim << ";\n";
                if (std::string_view(opaqueReasonFor(entry)) != "none")
                    recordOpaque(entry);
                if (entry.boolLayout)
                {
                    stream << "    static constexpr std::uint8_t " << member << "_FieldSize = "
                           << static_cast<unsigned int>(property.boolean.fieldSize) << ";\n";
                    stream << "    static constexpr std::uint8_t " << member << "_ByteOffset = "
                           << static_cast<unsigned int>(property.boolean.byteOffset) << ";\n";
                    stream << "    static constexpr std::uint8_t " << member << "_ByteMask = "
                           << Hex(property.boolean.byteMask) << ";\n";
                    stream << "    static constexpr std::uint8_t " << member << "_Mask = "
                           << Hex(property.boolean.fieldMask) << ";\n";
                }
            }
            stream << "};\n\n";
            return;
        }

        struct BoolStorage
        {
            int32_t end = 0;
            uint64_t masks = 0;
        };
        std::unordered_map<int32_t, BoolStorage> boolStorage;
        std::vector<const FieldDescription *> ordered;
        ordered.reserve(plan.fields.size());
        for (const FieldDescription &entry : plan.fields)
            ordered.push_back(&entry);
        std::stable_sort(ordered.begin(), ordered.end(), [](const FieldDescription *left, const FieldDescription *right)
                         { return left->property->offset < right->property->offset; });

        int32_t cursor = initialOffset;
        size_t ordinal = 0;
        for (const FieldDescription *entry : ordered)
        {
            describe(*entry, false);
            const PropertyIR &property = *entry->property;
            const int64_t total = static_cast<int64_t>(property.elementSize) * property.arrayDim;
            const int64_t end = static_cast<int64_t>(property.offset) + total;
            const std::string member = SanitizeIdentifier(property.name, "Member_") + "_" + std::to_string(ordinal++);
            if (!entry->validBounds)
            {
                ++report.omittedFields;
                report.Warn("invalid-property-bounds", "field omitted: " + property.name + " address=" + Hex(property.address));
                stream << "    // Field has invalid dimensions or exceeds the reflected size: " << member << "\n";
                continue;
            }

            const bool boolLayout = entry->boolLayout;
            if (boolLayout)
            {
                // ByteOffset 是存储内部的字节位置，不能加到存储起点后再占用整个 FieldSize
                const uint64_t mask = static_cast<uint64_t>(property.boolean.fieldMask) << (property.boolean.byteOffset * 8);
                auto existing = boolStorage.find(property.offset);
                if (existing != boolStorage.end())
                {
                    if (existing->second.end != end || (existing->second.masks & mask) != 0)
                    {
                        stream << "    // Unexpected bool analysis conflict: " << member << "\n";
                    }
                    existing->second.masks |= mask;
                }
                else
                {
                    if (property.offset < cursor)
                    {
                        stream << "    // Unexpected bool interval overlap after layout analysis: " << member << "\n";
                    }
                    if (property.offset > cursor)
                        stream << "    std::uint8_t UnknownData_" << ordinal++ << "[" << Hex(property.offset - cursor) << "];\n";
                    const std::string storageName = "BoolStorage_" + std::to_string(ordinal++);
                    stream << "    std::uint8_t " << storageName << "[" << Hex(static_cast<uint64_t>(total)) << "]; // "
                           << Hex(property.offset) << " (" << Hex(static_cast<uint64_t>(total)) << ")\n";
                    boolStorage.emplace(property.offset, BoolStorage{static_cast<int32_t>(end), mask});
                    cursor = std::max(cursor, static_cast<int32_t>(end));
                }
                stream << "    static constexpr std::size_t " << member << "_Offset = " << property.offset << ";\n";
                stream << "    static constexpr std::size_t " << member << "_ElementSize = " << property.elementSize << ";\n";
                stream << "    static constexpr std::size_t " << member << "_ArrayDim = " << property.arrayDim << ";\n";
                stream << "    static constexpr std::uint8_t " << member << "_FieldSize = "
                       << static_cast<unsigned int>(property.boolean.fieldSize) << ";\n";
                stream << "    static constexpr std::uint8_t " << member << "_ByteOffset = "
                       << static_cast<unsigned int>(property.boolean.byteOffset) << ";\n";
                stream << "    static constexpr std::uint8_t " << member << "_ByteMask = "
                       << Hex(property.boolean.byteMask) << ";\n";
                stream << "    static constexpr std::uint8_t " << member << "_Mask = "
                       << Hex(property.boolean.fieldMask) << ";\n";
                continue;
            }

            if (property.offset < cursor)
                stream << "    // Unexpected field interval overlap after layout analysis: " << member << "\n";
            if (property.offset > cursor)
                stream << "    std::uint8_t UnknownData_" << ordinal++ << "[" << Hex(property.offset - cursor) << "];\n";
            if (entry->type.name.empty())
            {
                stream << "    std::uint8_t " << member << "[" << Hex(static_cast<uint64_t>(total)) << "]; // opaque\n";
                recordOpaque(*entry);
            }
            else
            {
                stream << "    " << entry->type.name << " " << member;
                if (property.arrayDim > 1)
                    stream << "[" << property.arrayDim << "]";
                stream << ";\n";
                if (entry->type.IsOpaque())
                    recordOpaque(*entry);
            }
            stream << "    static constexpr std::size_t " << member << "_Offset = " << property.offset << ";\n";
            stream << "    static constexpr std::size_t " << member << "_ElementSize = " << property.elementSize << ";\n";
            stream << "    static constexpr std::size_t " << member << "_ArrayDim = " << property.arrayDim << ";\n";
            cursor = std::max(cursor, static_cast<int32_t>(end));
        }
        if (cursor < size)
            stream << "    std::uint8_t UnknownTailData[" << Hex(size - cursor) << "];\n";
        stream << "};\n";
        stream << '\n';
    }

    void SdkEmitter::EngineLayouts(std::ostream &stream) const
    {
        const auto writeLayout = [&](const char *name, std::initializer_list<std::pair<const char *, int32_t>> fields)
        {
            stream << "struct " << name << "Layout\n{\n";
            for (const auto &[field, offset] : fields)
                stream << "    static constexpr std::int32_t " << field << " = " << offset << ";\n";
            stream << "};\n\n";
        };

        stream << "#pragma once\n#include <cstdint>\n\n";
        stream << "// Runtime-resolved metadata offsets, not complete native C++ object layouts.\n";
        stream << "// A value of -1 means that the member offset was not resolved for this target.\n";
        stream << "// Layout profile: " << ::nextdumper::ue::SchemaLayoutVariantName(schema_.layout) << ".\n";
        stream << "namespace NextDumper::Engine\n{\n";
        stream << "inline constexpr const char *LayoutProfileId = \"" << EscapeJson(schema_.validation.profileId) << "\";\n";
        stream << "inline constexpr const char *LayoutVariant = \""
               << ::nextdumper::ue::SchemaLayoutVariantName(schema_.layout) << "\";\n";
        stream << "inline constexpr std::uint8_t TargetPointerWidth = "
               << static_cast<unsigned int>(module_.pointerWidth) << ";\n\n";
        stream << "inline constexpr bool UsesFProperty = " << (schema_.features.useFProperty ? "true" : "false") << ";\n";
        stream << "inline constexpr bool UsesNamePool = " << (schema_.features.useNamePool ? "true" : "false") << ";\n";
        stream << "inline constexpr bool CasePreservingName = " << (schema_.features.casePreservingName ? "true" : "false") << ";\n";
        stream << "inline constexpr bool OutlineNumberName = " << (schema_.features.outlineNumberName ? "true" : "false") << ";\n";
        stream << "inline constexpr bool LargeWorldCoordinates = " << (schema_.features.largeWorldCoordinates ? "true" : "false") << ";\n";
        stream << "inline constexpr bool TaggedFFieldOwner = "
               << (schema_.features.fFieldOwnerEncoding == ::nextdumper::ue::FFieldOwnerEncoding::TaggedPointer ? "true" : "false")
               << ";\n\n";
        stream << "inline constexpr bool FNameNumberOutlined = "
               << (schema_.fname.numberLayout == ::nextdumper::ue::FNameNumberLayout::Outlined ? "true" : "false") << ";\n";
        stream << "inline constexpr bool FNameDisplayBeforeNumber = "
               << (schema_.fname.displayLayout == ::nextdumper::ue::FNameDisplayLayout::BeforeNumber ? "true" : "false") << ";\n";
        stream << "inline constexpr bool FNameDisplayAfterNumber = "
               << (schema_.fname.displayLayout == ::nextdumper::ue::FNameDisplayLayout::AfterNumber ? "true" : "false") << ";\n\n";

        writeLayout("FName", {{"Size", schema_.fname.size},
                              {"ComparisonIndex", schema_.fname.comparisonIndex},
                              {"Number", schema_.fname.number},
                              {"DisplayIndex", schema_.fname.displayIndex}});
        writeLayout("UObject", {{"VTable", schema_.uobject.vtable},
                                {"Flags", schema_.uobject.flags},
                                {"InternalIndex", schema_.uobject.internalIndex},
                                {"Class", schema_.uobject.classPointer},
                                {"Name", schema_.uobject.name},
                                {"Outer", schema_.uobject.outer}});
        writeLayout("UField", {{"Next", schema_.ufield.next}});
        if (schema_.family == ::nextdumper::ue::EngineFamily::UE5FProperty)
        {
            writeLayout("FField", {{"VTable", schema_.ffield.vtable},
                                   {"Class", schema_.ffield.classPointer},
                                   {"Owner", schema_.ffield.owner},
                                   {"Next", schema_.ffield.next},
                                   {"Name", schema_.ffield.name},
                                   {"EditorOnlyMetadata", schema_.ffield.editorOnlyMetadata}});
            writeLayout("FFieldClass", {{"Name", schema_.ffieldClass.name},
                                        {"Id", schema_.ffieldClass.id},
                                        {"CastFlags", schema_.ffieldClass.castFlags},
                                        {"ClassFlags", schema_.ffieldClass.classFlags},
                                        {"SuperClass", schema_.ffieldClass.superClass}});
        }
        writeLayout("UStruct", {{"SuperStruct", schema_.ustruct.superStruct},
                                {"Children", schema_.ustruct.children},
                                {"ChildProperties", schema_.ustruct.childProperties},
                                {"PropertiesSize", schema_.ustruct.propertiesSizeOffset},
                                {"MinAlignment", schema_.ustruct.minAlignment},
                                {"StructBaseChain", schema_.ustruct.structBaseChain},
                                {"Tail", schema_.ustruct.tail}});
        writeLayout("UClass", {{"CastFlags", schema_.uclass.castFlags},
                               {"ClassDefaultObject", schema_.uclass.classDefaultObject},
                               {"ImplementedInterfaces", schema_.uclass.implementedInterfaces}});
        writeLayout("UFunction", {{"FunctionFlags", schema_.ufunction.functionFlags},
                                  {"NumParams", schema_.ufunction.numParams},
                                  {"ParamSize", schema_.ufunction.paramSize},
                                  {"ReturnValueOffset", schema_.ufunction.returnValueOffset},
                                  {"NativeFunction", schema_.ufunction.nativeFunction}});
        writeLayout("UEnum", {{"Names", schema_.uenum.names},
                              {"CppForm", schema_.uenum.cppForm},
                              {"Flags", schema_.uenum.flags},
                              {"UnderlyingType", schema_.uenum.underlyingType},
                              {"Package", schema_.uenum.enumPackage}});

        const char *propertyName = schema_.features.useFProperty ? "FProperty" : "UProperty";
        writeLayout(propertyName, {{"ArrayDim", schema_.property.arrayDim},
                                   {"ElementSize", schema_.property.elementSize},
                                   {"PropertyFlags", schema_.property.propertyFlags},
                                   {"OffsetInternal", schema_.property.offsetInternal},
                                   {"BaseSize", schema_.property.baseSize},
                                   {"RepNotify", schema_.property.repNotify},
                                   {"PropertyLinks", schema_.property.propertyLinks},
                                   {"PropertyLinksEnd", schema_.property.propertyLinksEnd},
                                   {"SubtypeStart", schema_.property.subtypeStart}});
        writeLayout("PropertySubtypes", {{"ByteEnum", schema_.propertySubtypes.byteEnum},
                                         {"BoolBase", schema_.propertySubtypes.boolBase},
                                         {"ObjectClass", schema_.propertySubtypes.objectClass},
                                         {"InterfaceClass", schema_.propertySubtypes.interfaceClass},
                                         {"ClassMetaClass", schema_.propertySubtypes.classMetaClass},
                                         {"StructType", schema_.propertySubtypes.structType},
                                         {"ArrayInner", schema_.propertySubtypes.arrayInner},
                                         {"DelegateSignature", schema_.propertySubtypes.delegateSignature},
                                         {"MapBase", schema_.propertySubtypes.mapBase},
                                         {"SetElement", schema_.propertySubtypes.setElement},
                                         {"EnumBase", schema_.propertySubtypes.enumBase},
                                         {"FieldPathClass", schema_.propertySubtypes.fieldPathClass},
                                         {"OptionalValue", schema_.propertySubtypes.optionalValue}});
        stream << "}\n";
    }

    void SdkEmitter::Types(std::ostream &stream, const CppSymbols &symbols, GenerationReport &report) const
    {
        const auto &types = symbols.types;

        stream << "#pragma once\n#include <cstddef>\n#include <cstdint>\n#include \"BasicTypes.hpp\"\n#include \"Enums.hpp\"\n\n";
        stream << "// Sizes and offsets describe target memory, not native C++ layout.\n";
        stream << "namespace NextDumper\n{\n";
        for (const TypeIR &type : reflection_.types)
            stream << "struct " << types.at(type.address).name << ";\n";
        if (!reflection_.types.empty())
            stream << "\n";
        if (std::any_of(types.begin(), types.end(), [](const auto &entry)
                        { return entry.second.declarationDependencyBlocked; }))
            report.Warn("declaration-dependency", "unorderable declaration dependencies use offset descriptions");
        for (size_t typeIndex : symbols.typeOrder)
        {
            const TypeIR &type = reflection_.types[typeIndex];
            const auto &declaration = types.at(type.address);
            const std::string &typeName = declaration.name;
            const auto base = types.find(type.superAddress);
            const bool baseSizeValid = base != types.end() && base->second.size >= 0 && base->second.size <= type.size;
            if (type.superAddress != 0 && !baseSizeValid)
            {
                LayoutEvent event;
                event.severity = "error";
                report.RegisterOwner({type.address, type.fullName, "type-fields", type.superAddress,
                                      type.size,
                                      base == types.end() ? -1 : base->second.size, 0});
                event.category = "missing-base-extent";
                event.message = "base size unavailable: " + type.fullName;
                event.ownerAddress = type.address;
                event.strategy = "offset-description";
                report.Warn(std::move(event));
                stream << "// Base extent is unavailable or inconsistent; fields use explicit target offsets where required.\n";
            }
            stream << "// " << EscapeJson(type.fullName) << " address=" << Hex(type.address) << " status=" << ParseStatusName(type.status) << "\n";
            stream << "// Reflected size: " << Hex(static_cast<uint32_t>(type.size)) << "\n";
            if (type.superAddress != 0 && !declaration.inheritsBase)
                stream << "// Semantic base metadata=" << Hex(type.superAddress)
                       << " name=" << (base == types.end() ? "<unavailable>" : base->second.name)
                       << "; inspect the base separately; its field constants are not inherited.\n";
            stream << "struct " << typeName;
            if (declaration.inheritsBase)
                stream << " : public " << base->second.name;
            stream << "\n{\n";
            stream << "    static constexpr std::size_t ReflectedSize = " << type.size << ";\n";
            FieldGenerationPlan plan = BuildFieldGenerationPlan(type, nullptr, type.properties, type.size, symbols);
            WriteFields(stream, type, nullptr, plan, symbols, report);
        }
        stream << "}\n";
    }

    void SdkEmitter::Functions(std::ostream &stream, const CppSymbols &symbols, GenerationReport &report) const
    {
        stream << "#pragma once\n#include <cstddef>\n#include <cstdint>\n#include \"Types.hpp\"\n\n";
        stream << "namespace NextDumper\n{\n";
        if (reflection_.stats.parsedFunctions == 0)
            stream << "// No UFunction metadata was resolved in this dump.\n";
        stream << "// RVAs describe reflected execution entries, not original C++ business implementations.\n";
        for (const auto &[address, function] : reflection_.functions)
        {
            if (!function.headerReadable)
            {
                stream << "// Unavailable function definition: " << EscapeJson(function.fullName)
                       << " address=" << Hex(address) << "; see the reflection shard and diagnostics.json.\n";
                continue;
            }
            const std::string &functionName = symbols.functions.at(address);
            stream << "// " << EscapeJson(function.fullName) << " address=" << Hex(address)
                   << " exec_entry=" << Hex(function.execEntry) << " flags=" << Hex(function.flags)
                   << " entry_kind=" << function.EntryKind() << " status=" << ParseStatusName(function.status) << "\n";
            stream << "inline constexpr bool " << functionName << "_HasExecEntryRva = "
                   << (function.execEntryRva ? "true" : "false") << ";\n";
            stream << "inline constexpr TargetAddress " << functionName << "_ExecEntryRva = "
                   << Hex(function.execEntryRva.value_or(0)) << ";\n";
            stream << "inline constexpr bool " << functionName << "_HasNativeExecRva = "
                   << (function.nativeExecRva ? "true" : "false") << ";\n";
            stream << "inline constexpr TargetAddress " << functionName << "_NativeExecRva = "
                   << Hex(function.nativeExecRva.value_or(0)) << ";\n";
            stream << "inline constexpr std::size_t " << functionName << "_ParamsSize = " << function.paramSize << ";\n";
            stream << "struct " << functionName << "_Params\n{\n";
            stream << "    static constexpr std::size_t ReflectedSize = " << function.paramSize << ";\n";
            TypeIR owner;
            owner.address = function.outerAddress;
            owner.fullName = function.outerFullName;
            const FieldGenerationPlan plan = BuildFieldGenerationPlan(owner, &function, function.parameters,
                                                                      function.paramSize, symbols);
            WriteFields(stream, owner, &function, plan, symbols, report);
            if (function.referencedAsSignature)
                stream << "struct " << functionName << "_Signature { using Parameters = " << functionName << "_Params; };\n\n";
        }
        stream << "}\n";
    }

    void SdkEmitter::Enums(std::ostream &stream, const CppSymbols &symbols) const
    {
        stream << "#pragma once\n#include <cstdint>\n\nnamespace NextDumper\n{\n";
        if (reflection_.enums.empty())
            stream << "// No UEnum metadata was resolved in this dump.\n";
        for (const EnumIR &enumeration : reflection_.enums)
        {
            const CppEnumInfo &info = symbols.enums.at(enumeration.address);
            stream << "// " << EscapeJson(enumeration.fullName) << " address=" << Hex(enumeration.address)
                   << " status=" << ParseStatusName(enumeration.status) << "\n";
            stream << "enum class " << info.name << " : "
                   << EnumUnderlyingName(info.underlyingType) << "\n{\n";
            for (size_t index = 0; index < enumeration.values.size(); ++index)
            {
                stream << "    " << info.values[index] << " = ";
                if (info.underlyingType == EnumUnderlyingType::UInt64)
                    stream << Hex(static_cast<uint64_t>(enumeration.values[index].value));
                else if (enumeration.values[index].value == INT64_MIN)
                    stream << "(-9223372036854775807LL - 1)";
                else
                    stream << enumeration.values[index].value;
                stream << ",\n";
            }
            stream << "};\n\n";
        }
        stream << "}\n";
    }

} // namespace nextdumper::generation::detail
