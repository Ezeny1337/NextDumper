#pragma once

#include "nextdumper/ue/SchemaResolver.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <variant>

namespace nextdumper::ue
{
    // 单次顺序执行的选择尝试独占拥有 Bootstrap, Index 以及可复用的阶段结果
    // 任何条目都绝不可在地址空间代际变更后存活，也绝不可跨越进入反射捕获阶段
    class SchemaProbeSession
    {
    public:
        struct ObjectSample
        {
            int32_t index = -1;
            uintptr_t address = 0;
            uintptr_t classAddress = 0;
            std::string className;
            std::string name;
            uint32_t flags = 0;
        };

        using ObjectKey = std::tuple<FNameSchema, UObjectSchema>;
        using FieldKey = std::tuple<ObjectKey, int32_t, int32_t, bool, FFieldOwnerEncoding>;
        using PropertyKey = std::tuple<ObjectKey, UFieldSchema, FFieldSchema, FFieldClassSchema, UStructSchema,
                                       bool, bool, FFieldOwnerEncoding, bool>;
        using FunctionKey = std::tuple<ObjectKey, UFieldSchema, FFieldSchema, FFieldClassSchema,
                                       int32_t, int32_t, int32_t, bool, FFieldOwnerEncoding,
                                       int32_t, int32_t, int32_t, int32_t, bool>;
        using EnumKey = std::tuple<ObjectKey, UFieldSchema, EngineFamily, EnumTailLayout, bool, bool, bool, bool, bool, bool, bool>;
        using Key = std::variant<std::monostate, ObjectKey, FieldKey, PropertyKey, FunctionKey, EnumKey>;

        struct ObjectResult
        {
            FNameSchema name;
            UObjectSchema object;
            bool casePreserving;
            bool outlined;
            FNameDisplayLayout display;
        };
        struct StructResult
        {
            UStructSchema structure;
            bool lwc;
        };
        struct FieldResult
        {
            UFieldSchema ufield;
            FFieldSchema field;
            FFieldClassSchema fieldClass;
            int32_t children;
            int32_t properties;
        };
        struct PropertyResult
        {
            PropertySchema property;
            PropertySubtypesSchema subtypes;
            OptionalPropertySupport optional;
            PropertyTailLayout tail;
        };
        struct FunctionResult
        {
            UFieldSchema field;
            UFunctionSchema function;
            int32_t children;
        };
        struct EnumResult
        {
            UEnumSchema enumeration;
            EnumTailLayout tail;
            bool cppByte;
            bool flagsByte;
            bool flags;
            bool package;
        };
        using Output = std::variant<ObjectResult, StructResult, FieldResult, PropertyResult, FunctionResult, EnumResult>;
        struct Entry
        {
            Key key;
            Output output;
            std::shared_ptr<const SchemaStageResult> result;
            std::vector<VersionEvidence> versionEvidence;
        };

        SchemaProbeSession(const IMemorySource &memory, const RuntimeBinding &binding, SchemaProbeNames names,
                           uintptr_t moduleBase, uintptr_t moduleEnd)
            : memory_(memory), binding_(binding), names_(std::move(names)), moduleBase_(moduleBase), moduleEnd_(moduleEnd),
              generation_(memory.AddressSpaceGeneration()), bootstrap(CreateSchemaProbeBootstrap(memory, binding)) {}

        bool Matches(const IMemorySource &memory, const RuntimeBinding &binding, const SchemaProbeNames &names,
                     uintptr_t moduleBase, uintptr_t moduleEnd) const
        {
            return &memory == &memory_ && &binding == &binding_ && names == names_ && moduleBase == moduleBase_ &&
                   moduleEnd == moduleEnd_ && generation_ == memory.AddressSpaceGeneration();
        }

        static PropertyKey PropertyInputs(const EngineSchema &s)
        {
            return {{s.fname, s.uobject}, s.ufield, s.ffield, s.ffieldClass, s.ustruct, s.features.useFProperty, s.features.arrayDimIsByte, s.features.fFieldOwnerEncoding, s.layout == SchemaLayoutVariant::FFieldTagged || s.layout == SchemaLayoutVariant::FFieldTaggedModern};
        }

        static Key Inputs(SchemaProbeStage stage, const EngineSchema &s)
        {
            switch (stage)
            {
            case SchemaProbeStage::UObject:
                return std::monostate{}; // 物理 FName 的所有变体均已被探测
            case SchemaProbeStage::Struct:
                return ObjectKey{s.fname, s.uobject};
            case SchemaProbeStage::Field:
                return FieldKey{{s.fname, s.uobject}, s.ustruct.superStruct, s.ustruct.propertiesSizeOffset, s.features.useFProperty, s.features.fFieldOwnerEncoding};
            case SchemaProbeStage::Property:
                return PropertyInputs(s);
            case SchemaProbeStage::Function:
                return FunctionKey{{s.fname, s.uobject}, s.ufield, s.ffield, s.ffieldClass, s.ustruct.superStruct, s.features.useFProperty ? s.ustruct.childProperties : s.ustruct.children, s.ustruct.propertiesSizeOffset, s.features.useFProperty, s.features.fFieldOwnerEncoding, s.property.arrayDim, s.property.elementSize, s.property.propertyFlags, s.property.offsetInternal, s.features.functionDefaultsContinueAfterInitializer};
            case SchemaProbeStage::Enum:
                return EnumKey{{s.fname, s.uobject}, s.ufield, s.family, s.features.enumTailLayout, s.features.enumCppFormIsByte, s.features.enumFlagsIsByte, s.features.enumFlagsRequired, s.features.enumHasPackage, s.features.enumUsesFNameData, s.features.enumStoresValues, s.features.enumHasUnderlyingType};
            }
            return std::monostate{};
        }

        static Output Result(SchemaProbeStage stage, const EngineSchema &s)
        {
            switch (stage)
            {
            case SchemaProbeStage::UObject:
                return ObjectResult{s.fname, s.uobject, s.features.casePreservingName, s.features.outlineNumberName, s.features.fnameDisplayLayout};
            case SchemaProbeStage::Struct:
                return StructResult{s.ustruct, s.features.largeWorldCoordinates};
            case SchemaProbeStage::Field:
                return FieldResult{s.ufield, s.ffield, s.ffieldClass, s.ustruct.children, s.ustruct.childProperties};
            case SchemaProbeStage::Property:
                return PropertyResult{s.property, s.propertySubtypes, s.optionalPropertySupport, s.features.propertyTailLayout};
            case SchemaProbeStage::Function:
                return FunctionResult{s.ufield, s.ufunction, s.ustruct.children};
            case SchemaProbeStage::Enum:
                return EnumResult{s.uenum, s.features.enumTailLayout, s.features.enumCppFormIsByte,
                                  s.features.enumFlagsIsByte, s.features.enumHasFlags, s.features.enumHasPackage};
            }
            return ObjectResult{};
        }

        static void Apply(const Output &output, EngineSchema &s)
        {
            std::visit([&](const auto &r)
                       {
                using T = std::decay_t<decltype(r)>;
                if constexpr (std::is_same_v<T, ObjectResult>)
                { s.fname = r.name; s.uobject = r.object; s.features.casePreservingName = r.casePreserving;
                  s.features.outlineNumberName = r.outlined; s.features.fnameDisplayLayout = r.display; }
                else if constexpr (std::is_same_v<T, StructResult>)
                { s.ustruct = r.structure; s.features.largeWorldCoordinates = r.lwc; s.validation.structs = true; }
                else if constexpr (std::is_same_v<T, FieldResult>)
                { s.ufield = r.ufield; s.ffield = r.field; s.ffieldClass = r.fieldClass;
                  s.ustruct.children = r.children; s.ustruct.childProperties = r.properties; s.validation.fields = true; }
                else if constexpr (std::is_same_v<T, PropertyResult>)
                { s.property = r.property; s.propertySubtypes = r.subtypes; s.optionalPropertySupport = r.optional;
                  s.features.propertyTailLayout = r.tail; s.validation.properties = true; }
                else if constexpr (std::is_same_v<T, FunctionResult>)
                { s.ufield = r.field; s.ufunction = r.function; s.ustruct.children = r.children; s.validation.functions = true; }
                else if constexpr (std::is_same_v<T, EnumResult>)
                { s.uenum = r.enumeration; s.features.enumTailLayout = r.tail; s.features.enumCppFormIsByte = r.cppByte;
                  s.features.enumFlagsIsByte = r.flagsByte; s.features.enumHasFlags = r.flags;
                  s.features.enumHasPackage = r.package; s.validation.enums = true; } }, output);
        }

        const std::vector<ObjectSample> &Objects(const EngineSchema &schema)
        {
            const ObjectKey key{schema.fname, schema.uobject};
            const auto cached = std::find_if(indices_.begin(), indices_.end(), [&](const auto &index)
                                             { return index.key == key; });
            if (cached != indices_.end())
            {
                activeIndex_ = static_cast<size_t>(cached - indices_.begin());
                indexLimited = cached->limited;
                indexReadFailed = cached->readFailed;
                return cached->objects;
            }
            indices_.push_back(Index{key, {}, {}, {}, false, false});
            activeIndex_ = indices_.size() - 1;
            auto &result = indices_.back();
            const auto failuresBefore = memory_.Stats().failures;
            ObjectModelReader model(memory_, binding_, schema);
            if (!model.Initialize())
            {
                result.limited = indexLimited = true;
                result.readFailed = indexReadFailed = memory_.Stats().failures != failuresBefore;
                return result.objects;
            }
            constexpr int32_t limit = 1048576;
            const int32_t count = std::min(model.Count(), limit);
            result.limited = count != model.Count();
            std::unordered_map<uintptr_t, std::optional<std::string>> classes;
            std::array<ObjectReadResult, ObjectStoreReader::kReadWindowSize> window{};
            size_t windowCount = 0;
            int32_t windowFirst = 0;
            for (int32_t index = 0; index < count; ++index)
            {
                if (static_cast<size_t>(index - windowFirst) >= windowCount)
                {
                    windowFirst = index;
                    windowCount = std::min(window.size(), static_cast<size_t>(count - index));
                    if (!model.Objects().ReadObjects(index, {window.data(), windowCount}))
                        throw std::runtime_error("Schema object window contract failed");
                }
                const auto &object = window[static_cast<size_t>(index - windowFirst)];
                if (!object.IsValid())
                {
                    result.limited = result.limited || object.status != ObjectReadStatus::Empty;
                    continue;
                }
                const auto cls = model.Class(object.address);
                const auto name = model.Name(object.address);
                const auto flags = model.Flags(object.address);
                if (!cls || !name || !flags)
                {
                    result.limited = true;
                    continue;
                }
                auto at = classes.find(*cls);
                if (at == classes.end())
                    at = classes.emplace(*cls, model.Name(*cls)).first;
                if (!at->second)
                {
                    result.limited = true;
                    continue;
                }
                result.byAddress.emplace(object.address, result.objects.size());
                result.byName.try_emplace(*name, result.objects.size());
                result.objects.push_back({index, object.address, *cls, *at->second, *name, *flags});
            }
            indexLimited = result.limited;
            result.readFailed = indexReadFailed = memory_.Stats().failures != failuresBefore;
            return result.objects;
        }

        std::optional<uintptr_t> FindNamed(const EngineSchema &schema, const std::string &name)
        {
            (void)Objects(schema);
            const auto &index = indices_[activeIndex_];
            const auto found = index.byName.find(name);
            return found == index.byName.end() ? std::nullopt : std::optional<uintptr_t>(index.objects[found->second].address);
        }

        const ObjectSample *FindObject(const EngineSchema &schema, uintptr_t address)
        {
            (void)Objects(schema);
            const auto &index = indices_[activeIndex_];
            const auto found = index.byAddress.find(address);
            return found == index.byAddress.end() ? nullptr : &index.objects[found->second];
        }

        std::vector<Entry> entries;
        bool indexLimited = false;
        bool indexReadFailed = false;

    private:
        const IMemorySource &memory_;
        const RuntimeBinding &binding_;
        SchemaProbeNames names_;
        uintptr_t moduleBase_;
        uintptr_t moduleEnd_;
        uint64_t generation_;
        struct Index
        {
            ObjectKey key;
            std::vector<ObjectSample> objects;
            std::unordered_map<std::string, size_t> byName;
            std::unordered_map<uintptr_t, size_t> byAddress;
            bool limited;
            bool readFailed;
        };
        std::vector<Index> indices_;
        size_t activeIndex_ = 0;

    public:
        const std::shared_ptr<const SchemaProbeBootstrap> bootstrap;
    };
} // namespace nextdumper::ue
