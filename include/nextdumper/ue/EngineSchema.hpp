#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nextdumper::ue
{
    enum class EnumTailLayout
    {
        Legacy,
        Flags,
        FlagsDisplayNamePackage,
        FlagsPackageDisplayName,
    };

    enum class FNameNumberLayout
    {
        Inline,
        Outlined,
    };

    enum class FNameDisplayLayout
    {
        None,
        BeforeNumber,
        AfterNumber,
    };

    enum class FFieldOwnerEncoding
    {
        ExplicitBoolean,
        TaggedPointer,
    };

    enum class PropertyTailLayout
    {
        UProperty,
        RepNotifyBeforeLinks,
        LinksBeforeRepNotify,
        Unknown,
    };

    enum class FieldKind
    {
        Unknown,
        UField,
        UFunction,
        UProperty,
        FField,
        FProperty,
    };

    [[nodiscard]] std::string NormalizeRuntimeFieldName(std::string_view name);
    [[nodiscard]] FieldKind FieldKindFromRuntimeName(std::string_view name, bool useFProperty);
    [[nodiscard]] bool IsFunctionFieldKind(FieldKind kind);
    [[nodiscard]] bool IsPropertyFieldKind(FieldKind kind);

    enum class SchemaLayoutVariant
    {
        Unknown,
        UProperty,
        FProperty,
        FPropertyEnumFlags,
        FFieldExplicit,
        FFieldExplicitPackage,
        FFieldTagged,
        FFieldTaggedModern,
    };

    [[nodiscard]] const char *SchemaLayoutVariantName(SchemaLayoutVariant variant);
    [[nodiscard]] const char *EnumTailLayoutName(EnumTailLayout layout);

    enum class VersionEvidenceStrength
    {
        Weak,
        Medium,
        Strong,
    };

    [[nodiscard]] inline const char *VersionEvidenceStrengthName(VersionEvidenceStrength strength)
    {
        switch (strength)
        {
        case VersionEvidenceStrength::Weak:
            return "weak";
        case VersionEvidenceStrength::Medium:
            return "medium";
        case VersionEvidenceStrength::Strong:
            return "strong";
        }
        return "weak";
    }

    struct VersionEvidence
    {
        std::string kind;
        std::string observed;
        VersionEvidenceStrength strength = VersionEvidenceStrength::Weak;
        std::string detail;
    };

    struct SchemaIdentity
    {
        std::string layoutProfileId;
        std::string layoutProfileLabel;
        std::string layoutVersionRange;
        std::string canonicalProfileId;
        std::string canonicalProfileLabel;
        std::string canonicalVersionRange;
        std::string selectionReason = "not-selected";
        std::string versionConfidence = "unknown";
        int32_t layoutScore = 0;
        int32_t versionEvidenceScore = 0;
        std::vector<std::string> compatibleProfiles;
        std::vector<VersionEvidence> evidence;
    };

    enum class EngineFamily
    {
        Unknown,
        UE4UProperty,
        UE4FProperty,
        UE5FProperty,
    };

    struct EngineFeatures
    {
        bool useFProperty = false;
        bool useNamePool = false;
        bool casePreservingName = false;
        bool outlineNumberName = false;
        FNameDisplayLayout fnameDisplayLayout = FNameDisplayLayout::None;
        FFieldOwnerEncoding fFieldOwnerEncoding = FFieldOwnerEncoding::ExplicitBoolean;
        bool functionDefaultsContinueAfterInitializer = false;
        bool enumHasUnderlyingType = false;
        bool enumHasFlags = false;
        bool enumCppFormIsByte = false;
        bool enumFlagsIsByte = false;
        bool enumHasPackage = false;
        bool enumFlagsRequired = false;
        EnumTailLayout enumTailLayout = EnumTailLayout::Legacy;
        bool enumUsesFNameData = false;
        bool enumStoresValues = true;
        bool arrayDimIsByte = false;
        bool largeWorldCoordinates = false;
        bool objectArrayMayPackItem = false;
        PropertyTailLayout propertyTailLayout = PropertyTailLayout::Unknown;

        [[nodiscard]] bool operator==(const EngineFeatures &other) const = default;
    };

    struct FNameSchema
    {
        int32_t comparisonIndex = -1;
        int32_t number = -1;
        int32_t displayIndex = -1;
        int32_t size = -1;
        FNameNumberLayout numberLayout = FNameNumberLayout::Inline;
        FNameDisplayLayout displayLayout = FNameDisplayLayout::None;

        [[nodiscard]] bool operator==(const FNameSchema &other) const = default;
    };

    struct FNamePhysicalLayout
    {
        int32_t size = -1;
        int32_t comparisonIndex = -1;
        int32_t number = -1;
        int32_t displayIndex = -1;
        FNameNumberLayout numberLayout = FNameNumberLayout::Inline;

        [[nodiscard]] bool operator==(const FNamePhysicalLayout &other) const
        {
            return size == other.size && comparisonIndex == other.comparisonIndex && number == other.number &&
                   displayIndex == other.displayIndex && numberLayout == other.numberLayout;
        }
    };

    [[nodiscard]] FNamePhysicalLayout GetFNamePhysicalLayout(const FNameSchema &schema);

    struct UObjectSchema
    {
        int32_t vtable = 0;
        int32_t flags = -1;
        int32_t internalIndex = -1;
        int32_t classPointer = -1;
        int32_t name = -1;
        int32_t outer = -1;

        [[nodiscard]] bool operator==(const UObjectSchema &other) const = default;
    };

    struct UFieldSchema
    {
        int32_t next = -1;

        [[nodiscard]] bool operator==(const UFieldSchema &other) const = default;
    };

    struct FFieldSchema
    {
        int32_t vtable = 0;
        int32_t classPointer = -1;
        int32_t owner = -1;
        int32_t next = -1;
        int32_t name = -1;
        int32_t editorOnlyMetadata = -1;

        [[nodiscard]] bool operator==(const FFieldSchema &other) const = default;
    };

    struct FFieldClassSchema
    {
        int32_t name = -1;
        int32_t id = -1;
        int32_t castFlags = -1;
        int32_t classFlags = -1;
        int32_t superClass = -1;

        [[nodiscard]] bool operator==(const FFieldClassSchema &other) const = default;
    };

    struct UStructSchema
    {
        int32_t superStruct = -1;
        int32_t children = -1;
        int32_t childProperties = -1;
        int32_t propertiesSizeOffset = -1;
        int32_t minAlignment = -1;
        int32_t structBaseChain = -1;
        int32_t tail = -1;

        [[nodiscard]] bool operator==(const UStructSchema &other) const = default;
    };

    struct UClassSchema
    {
        int32_t castFlags = -1;
        int32_t classDefaultObject = -1;
        int32_t implementedInterfaces = -1;

        [[nodiscard]] bool operator==(const UClassSchema &other) const = default;
    };

    struct UFunctionSchema
    {
        int32_t functionFlags = -1;
        int32_t numParams = -1;
        int32_t paramSize = -1;
        int32_t returnValueOffset = -1;
        int32_t nativeFunction = -1;

        [[nodiscard]] bool operator==(const UFunctionSchema &other) const = default;
    };

    struct UEnumSchema
    {
        int32_t names = -1;
        int32_t cppForm = -1;
        int32_t flags = -1;
        int32_t underlyingType = -1;
        int32_t enumPackage = -1;

        [[nodiscard]] bool operator==(const UEnumSchema &other) const = default;
    };

    struct PropertySchema
    {
        int32_t arrayDim = -1;
        int32_t elementSize = -1;
        int32_t propertyFlags = -1;
        int32_t offsetInternal = -1;
        int32_t tailPadding = -1;
        int32_t baseSize = -1;
        int32_t repNotify = -1;
        int32_t propertyLinks = -1;
        int32_t propertyLinksEnd = -1;
        int32_t subtypeStart = -1;

        [[nodiscard]] bool operator==(const PropertySchema &other) const = default;
    };

    struct PropertySubtypesSchema
    {
        int32_t byteEnum = -1;
        int32_t boolBase = -1;
        int32_t objectClass = -1;
        int32_t interfaceClass = -1;
        int32_t classMetaClass = -1;
        int32_t structType = -1;
        int32_t arrayInner = -1;
        int32_t delegateSignature = -1;
        int32_t mapBase = -1;
        int32_t setElement = -1;
        int32_t enumBase = -1;
        int32_t fieldPathClass = -1;
        int32_t optionalValue = -1;

        [[nodiscard]] bool operator==(const PropertySubtypesSchema &other) const = default;
    };

    // 已接受 tail 布局下仍不成立的单个属性对象
    // 布局由多数 owner 确立，这些例外逐条保留
    struct PropertyTailException
    {
        std::string owner;
        std::string propertyName;
        uintptr_t address = 0;
        uintptr_t rawValue = 0;
        int32_t linkIndex = -1;
        std::string reason;

        [[nodiscard]] bool operator==(const PropertyTailException &other) const = default;
    };

    struct PropertyTailEvidence
    {
        size_t samples = 0;
        size_t validSamples = 0;
        size_t validOwners = 0;
        size_t repNotifyHits = 0;
        size_t linkPointerHits = 0;
        std::vector<PropertyTailException> exceptions;

        [[nodiscard]] bool operator==(const PropertyTailEvidence &other) const = default;
    };

    struct OptionalPropertySupport
    {
        bool presentInProfile = false;
        size_t sampleCount = 0;
        int32_t selectedOffset = -1;
        std::string confidence = "none";
        std::string source = "none";
        std::string reason = "not-observed";
    };

    struct SchemaValidation
    {
        bool uobject = false;
        bool fname = false;
        bool fields = false;
        bool structs = false;
        bool properties = false;
        bool functions = false;
        bool enums = false;
        std::string profileId;
        std::string profileLabel;
        std::string profileVersionRange;
        std::string familyEvidence;
        std::string failure;
    };

    struct EngineSchema
    {
        EngineFamily family = EngineFamily::Unknown;
        SchemaLayoutVariant layout = SchemaLayoutVariant::Unknown;
        EngineFeatures profileFeatures;
        EngineFeatures features;
        FNameSchema fname;
        UObjectSchema uobject;
        UFieldSchema ufield;
        FFieldSchema ffield;
        FFieldClassSchema ffieldClass;
        UStructSchema ustruct;
        UClassSchema uclass;
        UFunctionSchema ufunction;
        UEnumSchema uenum;
        PropertySchema property;
        PropertySubtypesSchema propertySubtypes;
        OptionalPropertySupport optionalPropertySupport;
        PropertyTailEvidence propertyTail;
        SchemaIdentity identity;
        SchemaValidation validation;

        [[nodiscard]] bool IsReadyForReflection() const;
        [[nodiscard]] bool HasSameReflectionLayout(const EngineSchema &other) const;
    };
} // namespace nextdumper::ue
