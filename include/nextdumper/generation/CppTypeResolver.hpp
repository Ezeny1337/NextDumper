#pragma once

#include <map>
#include <unordered_map>
#include <utility>

#include "nextdumper/ir/ReflectionIR.hpp"

namespace nextdumper::generation
{
    struct CppTypeInfo
    {
        std::string name;
        int32_t size = 0;
        ir::LayoutRepresentation layout = ir::LayoutRepresentation::SequentialMembers;
        bool declarationDependencyBlocked = false;
        bool inheritsBase = false;
        std::map<std::string, std::string> metadataNames;

        [[nodiscard]] std::string MetadataName(const std::string &stem) const
        {
            const auto found = metadataNames.find(stem);
            return found == metadataNames.end() ? stem : found->second;
        }
    };

    struct CppEnumInfo
    {
        std::string name;
        ir::EnumUnderlyingType underlyingType = ir::EnumUnderlyingType::Unknown;
        int32_t size = 0;
        std::vector<std::string> values;
        std::string remoteValues;
        std::string remoteType;
    };

    struct CppSymbols
    {
        std::unordered_map<uintptr_t, CppTypeInfo> types;
        std::unordered_map<uintptr_t, CppEnumInfo> enums;
        std::map<uintptr_t, std::string> functions;
        std::map<std::string, std::string> valueLayouts;
        std::vector<size_t> typeOrder;
    };

    enum class PropertyStorageKind
    {
        Unavailable,
        SizedDescription,
        BoolMask,
        TypedOpaque,
        PartialContainer,
    };

    [[nodiscard]] const char *PropertyStorageKindName(PropertyStorageKind kind);

    struct CppPropertyType
    {
        CppPropertyType(std::string typeName = {}, std::string reason = {})
            : name(std::move(typeName)), failureReason(std::move(reason)) {}
        std::string name;
        std::string failureReason;
        std::string failurePath;
        std::string semanticName;
        PropertyStorageKind storage = PropertyStorageKind::Unavailable;
        bool semanticsResolved = false;
        [[nodiscard]] bool IsOpaque() const { return storage == PropertyStorageKind::TypedOpaque || storage == PropertyStorageKind::PartialContainer; }
    };

    struct FieldDescription
    {
        const ir::PropertyIR *property = nullptr;
        CppPropertyType type;
        size_t typeId = 0;
        bool validBounds = false;
        bool boolLayout = false;
        ir::LayoutRepresentation layout = ir::LayoutRepresentation::SequentialMembers;
    };

    using FieldDescriptions = std::map<uintptr_t, FieldDescription>;

    [[nodiscard]] std::string SanitizeIdentifier(std::string value, const char *fallback);
    [[nodiscard]] std::string ValueLayoutCppName(const std::string &id);
    [[nodiscard]] CppSymbols BuildCppSymbols(const ir::ReflectionIR &reflection);
    [[nodiscard]] const char *EnumUnderlyingName(ir::EnumUnderlyingType type);
    [[nodiscard]] CppPropertyType ResolvePropertyType(const ir::TypeReferenceIR &reference, const CppSymbols &symbols,
                                                      int32_t pointerWidth, int32_t nameSize, size_t depth = 0);
    [[nodiscard]] FieldDescription DescribeField(const ir::PropertyIR &property, int32_t bound,
                                                 const CppSymbols &symbols, int32_t pointerWidth, int32_t nameSize);
} // namespace nextdumper::generation
