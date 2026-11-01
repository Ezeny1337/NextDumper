#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "nextdumper/ir/RuntimeEvidence.hpp"

namespace nextdumper::ir
{
    enum class ParseStatus
    {
        Complete,
        Partial,
        Failed,
    };

    [[nodiscard]] inline const char *ParseStatusName(ParseStatus status)
    {
        switch (status)
        {
        case ParseStatus::Complete:
            return "Complete";
        case ParseStatus::Partial:
            return "Partial";
        case ParseStatus::Failed:
            return "Failed";
        }
        return "Failed";
    }

    enum class LayoutIssueKind
    {
        InvalidBounds,
        SameOwnerConflict,
        BoolMaskConflict,
        InheritedExtentIntersection,
        KnownInheritedFieldConflict,
        MissingTypeInformation,
        VirtualPropertyWithoutOffset,
    };

    [[nodiscard]] inline const char *LayoutIssueKindName(LayoutIssueKind kind)
    {
        switch (kind)
        {
        case LayoutIssueKind::InvalidBounds:
            return "invalid-bounds";
        case LayoutIssueKind::SameOwnerConflict:
            return "same-owner-conflict";
        case LayoutIssueKind::BoolMaskConflict:
            return "bool-mask-conflict";
        case LayoutIssueKind::InheritedExtentIntersection:
            return "inherited-extent-intersection";
        case LayoutIssueKind::KnownInheritedFieldConflict:
            return "known-inherited-field-conflict";
        case LayoutIssueKind::MissingTypeInformation:
            return "missing-type-information";
        case LayoutIssueKind::VirtualPropertyWithoutOffset:
            return "virtual-property-without-offset";
        }
        return "unknown-layout-issue";
    }

    enum class LayoutRepresentation
    {
        SequentialMembers,
        OffsetDescription,
    };

    [[nodiscard]] inline const char *LayoutRepresentationName(LayoutRepresentation representation)
    {
        return representation == LayoutRepresentation::OffsetDescription ? "offset-description" : "sequential-members";
    }

    struct LayoutIssueIR
    {
        LayoutIssueKind kind = LayoutIssueKind::InvalidBounds;
        uintptr_t propertyAddress = 0;
        uintptr_t conflictingAddress = 0;
        bool affectsCompleteness = true;
        std::string message;
    };

    struct LayoutAnalysisIR
    {
        bool analyzed = false;
        bool typeGraphComplete = false;
        bool baseExtentKnown = false;
        int32_t baseExtent = -1;
        LayoutRepresentation representation = LayoutRepresentation::SequentialMembers;
        std::vector<LayoutIssueIR> issues;
    };

    enum class TypeKind
    {
        Class,
        Struct,
    };

    enum class PropertyKind
    {
        Unknown,
        Bool,
        Byte,
        Int8,
        Int16,
        Int32,
        Int64,
        UInt16,
        UInt32,
        UInt64,
        Float,
        Double,
        Name,
        String,
        Text,
        Object,
        SoftObject,
        WeakObject,
        LazyObject,
        Class,
        SoftClass,
        Struct,
        Enum,
        Array,
        Set,
        Map,
        Interface,
        Delegate,
        MulticastDelegate,
        FieldPath,
        Optional,
    };

    enum class DelegateStorageKind
    {
        None,
        Unicast,
        InlineMulticast,
        SparseMulticast,
        UnknownMulticast,
    };

    [[nodiscard]] inline const char *DelegateStorageKindName(DelegateStorageKind kind)
    {
        switch (kind)
        {
        case DelegateStorageKind::Unicast:
            return "unicast";
        case DelegateStorageKind::InlineMulticast:
            return "inline-multicast";
        case DelegateStorageKind::SparseMulticast:
            return "sparse-multicast";
        case DelegateStorageKind::UnknownMulticast:
            return "unknown-multicast";
        case DelegateStorageKind::None:
            return "none";
        }
        return "none";
    }

    enum class ContainerAllocatorKind
    {
        Unknown,
        Heap,
        MemoryImage,
    };

    [[nodiscard]] inline const char *ContainerAllocatorKindName(ContainerAllocatorKind kind)
    {
        switch (kind)
        {
        case ContainerAllocatorKind::Heap:
            return "heap";
        case ContainerAllocatorKind::MemoryImage:
            return "memory-image";
        case ContainerAllocatorKind::Unknown:
            return "unknown";
        }
        return "unknown";
    }

    struct ContainerStorageIR
    {
        ContainerAllocatorKind allocator = ContainerAllocatorKind::Unknown;
        std::string allocatorStatus = "not-read";
        std::string layoutStatus = "not-read";
        std::string headerStatus = "not-read";
        std::string layoutId;
        int32_t valueOffset = -1;
        int32_t hashNextOffset = -1;
        int32_t hashIndexOffset = -1;
        int32_t setElementSize = -1;
        int32_t elementAlignment = -1;
        int32_t elementStride = -1;
    };

    struct StorageLayoutIR
    {
        std::string id;
        std::string sourceRange;
        int32_t size = 0;
        int32_t alignment = 0;
        std::vector<std::pair<std::string, int32_t>> offsets;
    };

    struct TypeReferenceIR
    {
        uintptr_t metadataAddress = 0;
        uintptr_t immediateOwner = 0;
        bool ownerIsUObject = false;
        int32_t arrayDim = 0;
        PropertyKind kind = PropertyKind::Unknown;
        DelegateStorageKind delegateStorage = DelegateStorageKind::None;
        std::string reflectedClass;
        uintptr_t referencedObject = 0;
        uintptr_t secondaryObject = 0;
        int32_t elementSize = 0;
        bool detailsResolved = false;
        // 即使子项的语义尚未解析，其外围的元数据/标识依然可以是有效的
        bool nodeDetailsResolved = false;
        std::shared_ptr<const ContainerStorageIR> containerStorage;
        // 共识字段描述不代表指针目标或外部绑定已经解析。
        std::shared_ptr<const StorageLayoutIR> valueStorage;
        std::vector<std::string> valueStorageCandidates;
        std::shared_ptr<TypeReferenceIR> inner;
        std::shared_ptr<TypeReferenceIR> key;
        std::shared_ptr<TypeReferenceIR> value;
    };

    struct BoolLayoutIR
    {
        uint8_t fieldSize = 0;
        uint8_t byteOffset = 0;
        uint8_t byteMask = 0;
        uint8_t fieldMask = 0;
    };

    struct PropertyDetailDiagnostic
    {
        bool headerAvailable = true;
        uintptr_t address = 0;
        uintptr_t classAddress = 0;
        uintptr_t nextAddress = 0;
        uintptr_t immediateOwner = 0;
        bool ownerIsUObject = false;
        std::string name;
        std::string reflectedClass;
        std::string normalizedClass;
        std::string reason;
        std::string detailsStatus;
        int32_t offset = 0;
        int32_t elementSize = 0;
        int32_t arrayDim = 0;
        uint64_t flags = 0;
        uintptr_t referencedAddress = 0;
        uintptr_t secondaryAddress = 0;
        std::string referencedClass;
        std::string secondaryClass;
        bool objectPropertyClassNull = false;
        uintptr_t objectPropertyClassPointerAddress = 0;
        BoolLayoutIR boolean;
        struct DetailRead
        {
            std::string member;
            int32_t offset = -1;
            uintptr_t address = 0;
            uintptr_t rawValue = 0;
            int32_t error = 0;
            size_t requested = 0;
            size_t transferred = 0;
            std::string status;
        };
        std::vector<DetailRead> reads;
    };

    struct PropertyIR
    {
        uintptr_t address = 0;
        std::string name;
        std::string reflectedClass;
        int32_t offset = 0;
        int32_t elementSize = 0;
        int32_t arrayDim = 0;
        uint64_t flags = 0;
        bool isParameter = false;
        bool isReturnParameter = false;
        bool isOutParameter = false;
        bool isReferenceParameter = false;
        bool isConstParameter = false;
        bool typeDetailsResolved = true;
        ParseStatus status = ParseStatus::Complete;
        std::vector<std::string> diagnostics;
        TypeReferenceIR type;
        BoolLayoutIR boolean;
        // 仅保留失败节点的事实，嵌套属性受 ReadTypeReference 的遍历预算约束
        std::vector<PropertyDetailDiagnostic> detailDiagnostics;
    };

    struct FunctionIR
    {
        uintptr_t address = 0;
        uintptr_t outerAddress = 0;
        std::string outerFullName;
        std::string outerClass;
        std::string reflectedClass;
        uint32_t objectFlags = 0;
        bool headerReadable = false;
        bool discoveredFromChildren = false;
        bool referencedAsSignature = false;
        uintptr_t execEntry = 0;
        std::optional<uintptr_t> execEntryRva;
        std::optional<uintptr_t> nativeExecRva;
        bool nativeFlag = false;
        bool entryReadable = false;
        bool entryExecutable = false;
        bool entryInModule = false;
        [[nodiscard]] const char *EntryKind() const
        {
            if (!entryReadable)
                return "unreadable";
            if (execEntry == 0)
                return "null";
            if (!entryExecutable)
                return nativeFlag ? "native-non-executable" : "non-native-non-executable";
            if (!entryInModule)
                return nativeFlag ? "native-external" : "non-native-external";
            return nativeFlag ? "native-module-exec" : "non-native-module-exec";
        }
        std::string name;
        std::string fullName;
        uint32_t flags = 0;
        uint8_t numParams = 0;
        uint16_t paramSize = 0;
        uint16_t returnValueOffset = 0xFFFFu;
        uint8_t headerNumParams = 0;
        uint16_t headerParamSize = 0;
        uint32_t derivedNumParams = 0;
        int32_t derivedParamSize = 0;
        uint32_t defaultInitializerCount = 0;
        bool parameterSemanticsValid = false;
        bool parameterSemanticsConsistent = false;
        std::vector<PropertyIR> parameters;
        std::vector<PropertyIR> locals;
        std::vector<std::string> layoutConflicts;
        LayoutAnalysisIR layout;
        ParseStatus status = ParseStatus::Complete;
    };

    struct TypeIR
    {
        uintptr_t address = 0;
        uintptr_t superAddress = 0;
        TypeKind kind = TypeKind::Struct;
        std::string name;
        std::string fullName;
        int32_t size = 0;
        int32_t minAlignment = -1;
        std::optional<uint32_t> minAlignmentRaw;
        std::string minAlignmentStatus = "not-read";
        std::vector<PropertyIR> properties;
        std::vector<uintptr_t> functionAddresses;
        std::vector<std::string> layoutConflicts;
        LayoutAnalysisIR layout;
        ParseStatus status = ParseStatus::Complete;
    };

    struct EnumValueIR
    {
        std::string name;
        int64_t value = 0;
    };

    enum class EnumUnderlyingType
    {
        Unknown,
        Int8,
        UInt8,
        Int16,
        UInt16,
        Int32,
        UInt32,
        Int64,
        UInt64,
    };

    struct EnumIR
    {
        uintptr_t address = 0;
        std::string name;
        std::string fullName;
        EnumUnderlyingType underlyingType = EnumUnderlyingType::Unknown;
        uint8_t cppForm = 0;
        uint8_t flags = 0;
        std::vector<EnumValueIR> values;
        ParseStatus status = ParseStatus::Complete;
        int32_t expectedValues = -1;
        std::vector<std::string> diagnostics;
    };

    struct ReflectionStats
    {
        int32_t objectSlots = 0;
        int32_t validObjects = 0;
        int32_t parsedTypes = 0;
        int32_t parsedEnums = 0;
        int32_t parsedFunctions = 0;
        int32_t parsedProperties = 0;
        int32_t unknownProperties = 0;
        int32_t unresolvedTypeDetails = 0;
        int32_t layoutConflicts = 0;
        // 包含空槽、槽位读取失败、类默认对象和未完成加载的反射定义
        int32_t skippedObjects = 0;
        int32_t emptyObjectSlots = 0;
        int32_t objectReadFailures = 0;
        int32_t classNameReadFailures = 0;
        int32_t skippedClassDefaultObjects = 0;
        int32_t skippedIncompleteObjects = 0;
        int32_t objectDiagnosticSamplesOmitted = 0;
        int32_t failures = 0;
        int32_t enumReadFailures = 0;
        int32_t identityFailures = 0;
        int32_t unvisitedObjects = 0;
    };

    struct CaptureInfo
    {
        bool observationsStable = false;
        bool limitExceeded = false;
        bool generationChanged = false;
        size_t observedRanges = 0;
        size_t observedBytes = 0;
        size_t allocatedBytes = 0;
        size_t changedRanges = 0;
        size_t unreadableRanges = 0;
        uint32_t attempts = 0;
        struct ReadFailure
        {
            uintptr_t address = 0;
            int32_t error = 0;
            size_t requested = 0;
            size_t transferred = 0;
        };
        size_t readFailures = 0;
        std::vector<ReadFailure> readFailureSamples;
        struct Change
        {
            uintptr_t address = 0;
            size_t size = 0;
            int32_t readError = 0;
            size_t transferred = 0;
            std::vector<uint8_t> before;
            std::vector<uint8_t> after;
        };
        struct Attempt
        {
            uint32_t number = 0;
            uint64_t elapsedMs = 0;
            size_t observedRanges = 0;
            size_t changedRanges = 0;
            size_t unreadableRanges = 0;
            bool limitExceeded = false;
            bool generationChanged = false;
            size_t readFailures = 0;
            std::vector<ReadFailure> readFailureSamples;
            int32_t failures = 0;
            int32_t identityFailures = 0;
            std::vector<std::string> diagnostics;
            int32_t initialCount = 0;
            int32_t enumeratedCount = 0;
            int32_t finalCount = -1;
            uint32_t tailRounds = 0;
            int32_t additionalTypes = 0;
            int32_t additionalEnums = 0;
            uintptr_t countAddress = 0;
            bool coverageComplete = false;
            std::string reason;
            std::vector<Change> changes;
        };
        std::vector<Attempt> history;
    };

    struct DelegateSignatureObservation
    {
        uintptr_t address = 0;
        std::string fullName;
        std::string reflectedClass;
        uintptr_t outerAddress = 0;
        std::string outerClass;
        std::string outerFullName;
        bool outerReadable = false;
        bool exported = false;
        bool ownerExported = false;
        bool foundInChildren = false;
        bool childrenRootReadable = false;
        uintptr_t childrenRoot = 0;
        int32_t childrenStatus = -1;
        std::string definitionStatus = "not-read";
        std::string discovery = "property-reference";
    };

    struct ContainerStorageObservation
    {
        uintptr_t propertyAddress = 0;
        uintptr_t ownerAddress = 0;
        bool ownerIsUObject = false;
        std::string propertyName;
        std::string propertyClass;
        std::string innerClass;
        std::string valueClass;
        std::string member;
        std::string basis;
        int32_t referenceOffset = -1;
        int32_t propertyDataEnd = -1;
        int32_t offset = -1;
        uintptr_t address = 0;
        int32_t storageSize = 0;
        int32_t innerSize = 0;
        int32_t valueSize = 0;
        bool readable = false;
        int32_t readError = 0;
        size_t requested = 0;
        size_t transferred = 0;
        std::optional<bool> sparseFormulaMatches;
        ContainerStorageIR storage;
        std::string sampleReason;
        struct FlagCandidate
        {
            std::string basis;
            int32_t offset = -1;
            uint8_t width = 0;
            uint32_t raw = 0;
            bool knownValue = false;
        };
        std::vector<FlagCandidate> flagCandidates;
        std::vector<uint8_t> bytes;
        std::string status;
    };

    struct ReflectionIR
    {
        ParseStatus status = ParseStatus::Failed;
        ReflectionStats stats;
        CaptureInfo capture;
        std::vector<std::string> diagnostics;
        std::vector<TypeIR> types;
        std::vector<EnumIR> enums;
        // 每次捕获尝试中，每个定义仅拥有并生成一次，类型与属性均通过内存地址进行引用
        std::map<uintptr_t, FunctionIR> functions;
        std::vector<DelegateSignatureObservation> delegateSignatures;
        std::vector<ContainerStorageObservation> containerStorageObservations;
        int32_t containerPointerWidth = 0;
        std::map<std::string, size_t> containerAllocatorCounts;
        std::map<std::string, size_t> containerHeaderCounts;
        std::map<std::string, size_t> containerElementLayoutCounts;
        std::map<std::string, size_t> containerStorageCandidates;
        std::map<std::string, size_t> containerStorageNotObserved;
        bool containerEvidenceAccountingValid = true;
        std::map<std::string, StorageLayoutIR> valueStorageLayouts;
        RuntimeEvidence runtimeEvidence;
    };
} // namespace nextdumper::ir
