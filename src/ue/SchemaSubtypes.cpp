#include "ProbeContext.hpp"
#include "PropertyLayout.hpp"
#include "nextdumper/common/Hex.hpp"
#include "nextdumper/ue/BoolLayout.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <iomanip>
#include <sstream>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace nextdumper::ue::schema_probe
{
    namespace
    {
        using ::nextdumper::common::Hex;

        constexpr size_t kMaxSamplesPerKind = 32;
        constexpr size_t kMaxSamplesPerOwner = 4;
        constexpr size_t kMaxProperties = 262144;
        constexpr size_t kMaxDepth = 32;
        constexpr size_t kMaxFrontier = 1024;
        constexpr size_t kMaxReads = 65536;

        // 所有读取器共用此视图，连名称与父类链验证也计入预算
        class ProbeMemory final : public IMemorySource
        {
        public:
            explicit ProbeMemory(const IMemorySource &source) : source_(source) {}
            void ResetBudget(size_t reads)
            {
                remaining_ = reads;
                exhausted_ = false;
            }
            [[nodiscard]] bool Exhausted() const { return exhausted_; }
            [[nodiscard]] bool IsInitialized() const override { return source_.IsInitialized(); }
            [[nodiscard]] pid_t ProcessId() const override { return source_.ProcessId(); }
            [[nodiscard]] std::span<const memory::MemoryRegion> Regions() const override { return source_.Regions(); }
            [[nodiscard]] std::string ProcessName() const override { return source_.ProcessName(); }
            [[nodiscard]] uint64_t AddressSpaceGeneration() const override { return source_.AddressSpaceGeneration(); }
            [[nodiscard]] bool RefreshAddressSpace() override { return false; }
            [[nodiscard]] bool IsReadable(uintptr_t address, size_t size) const override { return source_.IsReadable(address, size); }
            [[nodiscard]] bool IsExecutable(uintptr_t address, size_t size) const override { return source_.IsExecutable(address, size); }
            [[nodiscard]] const ::nextdumper::memory::ReadStats &Stats() const override { return source_.Stats(); }
            [[nodiscard]] ::nextdumper::memory::ReadPerformance *Performance() const override { return source_.Performance(); }
            [[nodiscard]] ::nextdumper::memory::ReadResult ReadBytes(uintptr_t address, void *buffer, size_t size) const override
            {
                if (!Consume())
                    return {::nextdumper::memory::ReadError::ProbeLimit, address, size, 0};
                return source_.ReadBytes(address, buffer, size);
            }
            [[nodiscard]] ::nextdumper::memory::ReadResult ReadFreshBytes(uintptr_t address, void *buffer, size_t size) const override
            {
                if (!Consume())
                    return {::nextdumper::memory::ReadError::ProbeLimit, address, size, 0};
                return source_.ReadFreshBytes(address, buffer, size);
            }
            [[nodiscard]] bool ReadBatch(std::span<const memory::ReadRequest> requests, std::span<memory::ReadResult> results,
                                         bool fresh = false) const override
            {
                if (requests.size() != results.size() || requests.size() > 1024)
                    return false;
                // 预算按逻辑请求扣除，批读不能绕过限制，也不能退化为逐项 syscall。
                const size_t allowed = std::min(remaining_, requests.size());
                remaining_ -= allowed;
                if (allowed != requests.size())
                {
                    exhausted_ = true;
                    for (size_t index = allowed; index < requests.size(); ++index)
                        results[index] = {memory::ReadError::ProbeLimit, requests[index].address, requests[index].size, 0};
                }
                return allowed == 0 || source_.ReadBatch(requests.first(allowed), results.first(allowed), fresh);
            }

        private:
            bool Consume() const
            {
                if (remaining_ == 0)
                {
                    exhausted_ = true;
                    return false;
                }
                --remaining_;
                return true;
            }
            const IMemorySource &source_;
            mutable size_t remaining_ = 8 * 1024 * 1024;
            mutable bool exhausted_ = false;
        };

        enum class Payload
        {
            Bool,
            Byte,
            Object,
            Class,
            Interface,
            Struct,
            Array,
            Set,
            Map,
            Enum,
            Delegate,
            FieldPath,
            Optional,
        };

        struct SubtypeSpec
        {
            const char *name;
            Payload payload;
            int32_t PropertySubtypesSchema::*member;
        };

        constexpr std::array<SubtypeSpec, 13> kSpecs{{
            {"bool_base", Payload::Bool, &PropertySubtypesSchema::boolBase},
            {"byte_enum", Payload::Byte, &PropertySubtypesSchema::byteEnum},
            {"object_class", Payload::Object, &PropertySubtypesSchema::objectClass},
            {"class_meta_class", Payload::Class, &PropertySubtypesSchema::classMetaClass},
            {"interface_class", Payload::Interface, &PropertySubtypesSchema::interfaceClass},
            {"struct_type", Payload::Struct, &PropertySubtypesSchema::structType},
            {"array_inner", Payload::Array, &PropertySubtypesSchema::arrayInner},
            {"set_element", Payload::Set, &PropertySubtypesSchema::setElement},
            {"map_base", Payload::Map, &PropertySubtypesSchema::mapBase},
            {"enum_base", Payload::Enum, &PropertySubtypesSchema::enumBase},
            {"delegate_signature", Payload::Delegate, &PropertySubtypesSchema::delegateSignature},
            {"field_path_class", Payload::FieldPath, &PropertySubtypesSchema::fieldPathClass},
            {"optional_value", Payload::Optional, &PropertySubtypesSchema::optionalValue},
        }};

        std::optional<Payload> PayloadOf(const std::string &name)
        {
            if (name == "BoolProperty")
                return Payload::Bool;
            if (name == "ByteProperty")
                return Payload::Byte;
            if (name == "ObjectProperty" || name == "ObjectPropertyBase" || name == "ObjectPtrProperty" ||
                name == "SoftObjectProperty" || name == "WeakObjectProperty" || name == "LazyObjectProperty")
                return Payload::Object;
            if (name == "ClassProperty" || name == "ClassPtrProperty" || name == "SoftClassProperty")
                return Payload::Class;
            if (name == "InterfaceProperty")
                return Payload::Interface;
            if (name == "StructProperty")
                return Payload::Struct;
            if (name == "ArrayProperty")
                return Payload::Array;
            if (name == "SetProperty")
                return Payload::Set;
            if (name == "MapProperty")
                return Payload::Map;
            if (name == "EnumProperty")
                return Payload::Enum;
            if (name == "DelegateProperty" || name == "MulticastDelegateProperty" ||
                name == "MulticastInlineDelegateProperty" || name == "MulticastSparseDelegateProperty")
                return Payload::Delegate;
            if (name == "FieldPathProperty")
                return Payload::FieldPath;
            if (name == "OptionalProperty")
                return Payload::Optional;
            return std::nullopt;
        }

        struct Sample
        {
            PropertyMetadata metadata;
            uintptr_t rootOwner = 0;
            size_t depth = 0;
            std::string scope;
        };

        struct SampleSet
        {
            std::map<Payload, std::vector<Sample>> byPayload;
            std::vector<Sample> tail;
            std::vector<std::pair<Payload, Sample>> containers;
            std::unordered_set<uintptr_t> visited;
            size_t roots = 0;
            size_t unreadable = 0;
            size_t incompleteChains = 0;
            size_t omitted = 0;
            bool collectionLimit = false;

            void Add(const PropertyMetadata &metadata, uintptr_t owner, size_t depth, const std::string &scope)
            {
                if (depth >= kMaxDepth || visited.size() >= kMaxProperties)
                {
                    collectionLimit = true;
                    return;
                }
                if (!visited.insert(metadata.address).second)
                    return;
                const size_t tailOwnerSamples = static_cast<size_t>(std::count_if(
                    tail.begin(), tail.end(), [owner](const Sample &sample)
                    { return sample.rootOwner == owner; }));
                if (tail.size() < kMaxSamplesPerKind && tailOwnerSamples < kMaxSamplesPerOwner)
                    tail.push_back({metadata, owner, depth, scope});
                const auto payload = PayloadOf(metadata.normalizedClassName);
                if (!payload)
                    return;
                if (*payload == Payload::Array || *payload == Payload::Set || *payload == Payload::Map ||
                    *payload == Payload::Enum || *payload == Payload::Optional)
                {
                    if (containers.size() < kMaxFrontier)
                        containers.push_back({*payload, {metadata, owner, depth, scope}});
                    else
                        collectionLimit = true;
                }
                auto &samples = byPayload[*payload];
                const size_t ownerSamples = static_cast<size_t>(std::count_if(
                    samples.begin(), samples.end(), [&](const Sample &sample)
                    { return sample.rootOwner == owner && sample.metadata.normalizedClassName == metadata.normalizedClassName; }));
                const size_t classSamples = static_cast<size_t>(std::count_if(
                    samples.begin(), samples.end(), [&](const Sample &sample)
                    { return sample.metadata.normalizedClassName == metadata.normalizedClassName; }));
                // 共享基类的变体按类名保留独立预算，不能让 ObjectProperty 占满 Weak/Soft 等证据。
                if (classSamples >= kMaxSamplesPerKind || ownerSamples >= kMaxSamplesPerOwner)
                {
                    ++omitted;
                    return;
                }
                samples.push_back({metadata, owner, depth, scope});
            }
        };

        struct Budget
        {
            ProbeMemory &memory;
            size_t remaining = kMaxReads;
            bool exhausted = false;

            bool Read(uintptr_t object, int32_t offset, void *value, size_t size)
            {
                if (remaining == 0)
                {
                    exhausted = true;
                    return false;
                }
                --remaining;
                const auto address = object != 0 ? Add(object, offset) : std::nullopt;
                return address && memory.IsReadable(*address, size) && memory.ReadBytes(*address, value, size).Ok();
            }

            template <typename T>
            bool Read(uintptr_t object, int32_t offset, T &value)
            {
                return Read(object, offset, &value, sizeof(value));
            }
        };

        bool ValidHeader(const PropertyMetadata &metadata)
        {
            return metadata.arrayDim > 0 && metadata.arrayDim <= 65536 && metadata.elementSize > 0 &&
                   metadata.elementSize <= 0x10000000 && metadata.offset >= 0;
        }

        SampleSet CollectSamples(ObjectModelReader &model, ProbeMemory &memory, const EngineSchema &schema,
                                 SchemaProbeSession &session, SchemaResolutionReport &report)
        {
            SampleSet result;
            std::unordered_map<uintptr_t, std::optional<DefinitionKind>> classifications;
            const auto &objects = session.Objects(schema);
            result.collectionLimit = session.indexLimited;
            size_t skippedNotType = 0;
            size_t skippedFlags = 0;
            size_t skippedPropertyKind = 0;
            size_t skippedOwner = 0;
            size_t visitedObjects = 0;
            for (const auto &object : objects)
            {
                if (result.visited.size() >= kMaxProperties || memory.Exhausted())
                    break;
                ++visitedObjects;
                auto classification = classifications.find(object.classAddress);
                if (classification == classifications.end())
                    classification = classifications.emplace(object.classAddress, model.DefinitionKindForClass(object.classAddress)).first;
                const bool function = IsFunctionFieldKind(FieldKindFromRuntimeName(object.className, false));
                if (!function && (!classification->second || (*classification->second != DefinitionKind::Class &&
                                                              *classification->second != DefinitionKind::Struct)))
                {
                    ++skippedNotType;
                    continue;
                }
                if ((object.flags & (kRFClassDefaultObject | kRFUnavailableDefinition)) != 0)
                {
                    ++skippedFlags;
                    continue;
                }
                const auto first = model.StructProperties(object.address);
                if (!first)
                {
                    ++result.unreadable;
                    continue;
                }
                ++result.roots;
                const auto chain = model.FieldsWithStatus(*first, 4096);
                if (!chain.Complete())
                {
                    result.collectionLimit = result.collectionLimit || chain.status == FieldChainStatus::LimitExceeded;
                    ++result.incompleteChains;
                    continue;
                }
                for (const auto &field : chain.fields)
                {
                    if (result.visited.size() >= kMaxProperties || memory.Exhausted())
                        break;
                    if (!IsPropertyFieldKind(field.kind))
                    {
                        ++skippedPropertyKind;
                        continue;
                    }
                    if (schema.features.useFProperty && (!field.ownerIsUObject || field.ownerAddress != object.address))
                    {
                        ++skippedOwner;
                        continue;
                    }
                    const auto property = model.Property(field);
                    if (!property || !ValidHeader(*property))
                    {
                        ++result.unreadable;
                        continue;
                    }
                    if (!schema.features.useFProperty)
                    {
                        const auto outer = model.Outer(field.address);
                        if (!outer || *outer != object.address)
                            continue;
                    }
                    result.Add(*property, object.address, 0, function ? "function-fields" : "type-fields");
                }
            }
            result.collectionLimit = result.collectionLimit || result.visited.size() >= kMaxProperties || memory.Exhausted();
            report.evidence.push_back("property subtype samples: roots=" + std::to_string(result.roots) +
                                      " unique_properties=" + std::to_string(result.visited.size()) +
                                      " unreadable=" + std::to_string(result.unreadable) +
                                      " incomplete_chains=" + std::to_string(result.incompleteChains) +
                                      " samples_omitted=" + std::to_string(result.omitted) +
                                      " collection_limit=" + std::to_string(result.collectionLimit));
            report.evidence.push_back("property subtype skip reasons: objects=" + std::to_string(objects.size()) +
                                      " visited=" + std::to_string(visitedObjects) +
                                      " skipped_not_type=" + std::to_string(skippedNotType) +
                                      " skipped_flags=" + std::to_string(skippedFlags) +
                                      " skipped_property_kind=" + std::to_string(skippedPropertyKind) +
                                      " skipped_owner=" + std::to_string(skippedOwner) +
                                      " index_limited=" + std::to_string(session.indexLimited));
            return result;
        }

        std::vector<int32_t> PayloadOffsets(const PropertyTailCandidate &tail, Payload payload)
        {
            const int32_t pointerAlignment = static_cast<int32_t>(alignof(uintptr_t));
            const int32_t first = *AlignMember(tail.dataEnd, pointerAlignment);
            std::set<int32_t> offsets;
            if (payload == Payload::Bool)
                offsets.insert(tail.dataEnd);
            else if (payload == Payload::Class)
                offsets.insert(first + static_cast<int32_t>(sizeof(uintptr_t)));
            else
                offsets.insert(first);
            if (payload == Payload::Array && tail.layout != PropertyTailLayout::UProperty)
                offsets.insert(*AlignMember(tail.dataEnd + static_cast<int32_t>(sizeof(uint32_t)), pointerAlignment));
            if (payload == Payload::Optional)
                offsets.insert(tail.completeSize);
            return {offsets.begin(), offsets.end()};
        }

        struct FieldPathCandidate
        {
            int32_t offset = -1;
            std::string basis;
        };

        std::vector<FieldPathCandidate> FieldPathCandidates(const std::vector<PropertyTailCandidate> &tails)
        {
            // FFieldPathProperty::PropertyClass starts at the complete FProperty size,
            // including any ABI tail padding.  Do not turn dataEnd into a scan range.
            // Keep this list structural: scanning neighboring descriptor objects would
            // incorrectly accept their unrelated FField::ClassPrivate pointers.
            std::map<int32_t, std::string> byOffset;
            for (const auto &tail : tails)
            {
                if (tail.completeSize < 0)
                    continue;
                auto &basis = byOffset[tail.completeSize];
                if (!basis.empty())
                    basis += ",";
                basis += std::string("property-tail:") + PropertyTailName(tail.layout) + ":complete-size";
            }

            std::vector<FieldPathCandidate> result;
            result.reserve(byOffset.size());
            for (const auto &[offset, basis] : byOffset)
                result.push_back({offset, basis});
            return result;
        }

        bool ObjectIdentity(ObjectModelReader &model, uintptr_t address)
        {
            if (address == 0)
                return false;
            const auto index = model.InternalIndex(address);
            if (!index || *index < 0 || *index >= model.Count())
                return false;
            const auto object = model.Objects().ReadObject(*index);
            return object.IsValid() && object.address == address;
        }

        bool ObjectKind(ObjectModelReader &model, uintptr_t address, DefinitionKind expected)
        {
            if (!ObjectIdentity(model, address))
                return false;
            const auto classAddress = model.Class(address);
            const auto kind = classAddress ? model.DefinitionKindForClass(*classAddress) : std::nullopt;
            return kind && *kind == expected;
        }

        bool FunctionIdentity(ObjectModelReader &model, uintptr_t address)
        {
            if (!ObjectIdentity(model, address))
                return false;
            const auto className = model.ClassName(address);
            return className && IsFunctionFieldKind(FieldKindFromRuntimeName(*className, false));
        }

        bool ClassDerivesFrom(ObjectModelReader &model, uintptr_t address, const char *name)
        {
            std::unordered_set<uintptr_t> visited;
            for (size_t depth = 0; address != 0 && depth < kMaxDepth && visited.insert(address).second; ++depth)
            {
                const auto currentName = model.Name(address);
                if (!currentName)
                    return false;
                if (*currentName == name)
                    return true;
                const auto super = model.StructSuper(address);
                if (!super)
                    return false;
                address = *super;
            }
            return false;
        }

        std::optional<PropertyMetadata> Child(ObjectModelReader &model, const EngineSchema &schema,
                                              uintptr_t address, uintptr_t owner)
        {
            if (address == 0 || address == owner)
                return std::nullopt;
            const auto property = model.Property(address);
            if (!property || !ValidHeader(*property))
                return std::nullopt;
            if (schema.features.useFProperty)
            {
                if (property->ownerIsUObject || property->ownerAddress != owner)
                    return std::nullopt;
            }
            else
            {
                if (!ObjectIdentity(model, address))
                    return std::nullopt;
                const auto outer = model.Outer(address);
                if (!outer || *outer != owner)
                    return std::nullopt;
            }
            return property;
        }

        bool IntegerProperty(const PropertyMetadata &metadata)
        {
            const auto &name = metadata.normalizedClassName;
            if (name == "ByteProperty" || name == "Int8Property")
                return metadata.elementSize == 1;
            if (name == "Int16Property" || name == "UInt16Property")
                return metadata.elementSize == 2;
            if (name == "IntProperty" || name == "Int32Property" || name == "UInt32Property")
                return metadata.elementSize == 4;
            if (name == "Int64Property" || name == "UInt64Property")
                return metadata.elementSize == 8;
            return false;
        }

        bool TailValid(ObjectModelReader &model, Budget &budget, const EngineSchema &schema,
                       const PropertyTailCandidate &tail, const std::vector<Sample> &samples, SchemaResolutionReport &report)
        {
            std::set<uintptr_t> owners;
            if (samples.size() < 2)
                return false;
            for (const auto &sample : samples)
            {
                owners.insert(sample.rootOwner);
                std::array<uint8_t, 12> name{};
                if (!budget.Read(sample.metadata.address, tail.repNotify, name.data(), static_cast<size_t>(schema.fname.size)))
                {
                    report.evidence.push_back("property subtype tail rejected: layout=" + std::string(PropertyTailName(tail.layout)) +
                                              " sample=" + Hex(sample.metadata.address) + " reason=repnotify-unreadable");
                    return false;
                }
                const auto address = Add(sample.metadata.address, tail.repNotify);
                if (!address || !model.Names().ReadFName(*address))
                {
                    report.evidence.push_back("property subtype tail rejected: layout=" + std::string(PropertyTailName(tail.layout)) +
                                              " sample=" + Hex(sample.metadata.address) + " reason=repnotify-invalid");
                    return false;
                }
                for (int32_t link = 0; link < 4; ++link)
                {
                    uintptr_t value = 0;
                    if (!budget.Read(sample.metadata.address, tail.links + link * static_cast<int32_t>(sizeof(uintptr_t)), value))
                    {
                        report.evidence.push_back("property subtype tail rejected: layout=" + std::string(PropertyTailName(tail.layout)) +
                                                  " sample=" + Hex(sample.metadata.address) + " link=" + std::to_string(link) +
                                                  " reason=property-link-unreadable");
                        return false;
                    }
                    if (value != 0)
                    {
                        const auto field = model.Field(value);
                        if (!field || !IsPropertyFieldKind(field->kind))
                        {
                            report.evidence.push_back("property subtype tail rejected: layout=" + std::string(PropertyTailName(tail.layout)) +
                                                      " sample=" + Hex(sample.metadata.address) + " link=" + std::to_string(link) +
                                                      " raw_value=" + Hex(value) + " reason=property-link-invalid");
                            return false;
                        }
                    }
                }
            }
            return owners.size() >= 2 && !budget.memory.Exhausted();
        }

        struct TailDiagnostics
        {
            size_t samples = 0;
            size_t repNotifyValid = 0;
            size_t linkNonZero = 0;
            size_t linkValid = 0;
            size_t fullyValid = 0;
            size_t owners = 0;
            std::array<int32_t, 8> firstRepNotify{};
            std::array<uintptr_t, 8> firstLinks{};
            size_t captured = 0;
            size_t linkUnreadable = 0;
            size_t linkNotField = 0;
            size_t linkWrongKind = 0;
            std::array<uintptr_t, 4> firstNotField{};
            std::array<uintptr_t, 4> firstWrongKind{};
            size_t notFieldCaptured = 0;
            size_t wrongKindCaptured = 0;
            std::array<std::string, 4> firstWrongKindNames{};
        };

        TailDiagnostics DiagnoseTail(const IMemorySource &memory, const RuntimeBinding &binding, const EngineSchema &schema,
                                     const PropertyTailCandidate &tail, const std::vector<Sample> &samples)
        {
            constexpr size_t kDiagReads = 8192;
            constexpr size_t kCapture = 8;
            TailDiagnostics result;
            ProbeMemory diagMemory(memory);
            diagMemory.ResetBudget(kDiagReads);
            ObjectModelReader diagModel(diagMemory, binding, schema);
            if (!diagModel.Initialize())
                return result;
            Budget budget{diagMemory};
            std::set<uintptr_t> owners;
            for (const auto &sample : samples)
            {
                if (budget.memory.Exhausted())
                    break;
                ++result.samples;
                owners.insert(sample.rootOwner);
                bool sampleValid = true;
                std::array<uint8_t, 12> name{};
                const bool readable = budget.Read(sample.metadata.address, tail.repNotify, name.data(),
                                                  static_cast<size_t>(schema.fname.size));
                int32_t repNotifyValue = 0;
                const auto address = Add(sample.metadata.address, tail.repNotify);
                const bool repNotifyOk = readable && address && diagModel.Names().ReadFName(*address);
                if (repNotifyOk)
                {
                    ++result.repNotifyValid;
                    std::memcpy(&repNotifyValue, name.data(), sizeof(repNotifyValue));
                }
                else
                {
                    sampleValid = false;
                }
                std::array<uintptr_t, 4> links{};
                bool linksOk = true;
                for (int32_t link = 0; link < 4; ++link)
                {
                    uintptr_t value = 0;
                    if (!budget.Read(sample.metadata.address, tail.links + link * static_cast<int32_t>(sizeof(uintptr_t)), value))
                    {
                        linksOk = false;
                        ++result.linkUnreadable;
                        break;
                    }
                    links[static_cast<size_t>(link)] = value;
                    if (value == 0)
                        continue;
                    ++result.linkNonZero;
                    const auto field = diagModel.Field(value);
                    if (!field)
                    {
                        linksOk = false;
                        ++result.linkNotField;
                        if (result.notFieldCaptured < result.firstNotField.size())
                        {
                            result.firstNotField[result.notFieldCaptured] = value;
                            ++result.notFieldCaptured;
                        }
                        continue;
                    }
                    if (!IsPropertyFieldKind(field->kind))
                    {
                        linksOk = false;
                        ++result.linkWrongKind;
                        if (result.wrongKindCaptured < result.firstWrongKind.size())
                        {
                            result.firstWrongKind[result.wrongKindCaptured] = value;
                            result.firstWrongKindNames[result.wrongKindCaptured] = field->className;
                            ++result.wrongKindCaptured;
                        }
                    }
                }
                if (linksOk)
                    ++result.linkValid;
                else
                    sampleValid = false;
                if (sampleValid)
                    ++result.fullyValid;
                if (result.captured < kCapture)
                {
                    result.firstRepNotify[result.captured] = repNotifyValue;
                    result.firstLinks[result.captured] = links[0];
                    ++result.captured;
                }
            }
            result.owners = owners.size();
            return result;
        }

        enum class Observation
        {
            Match,
            Null,
            Unreadable,
            Mismatch
        };

        const char *ObservationName(Observation state)
        {
            switch (state)
            {
            case Observation::Match:
                return "match";
            case Observation::Null:
                return "null-reference";
            case Observation::Unreadable:
                return "unreadable";
            case Observation::Mismatch:
                return "semantic-mismatch";
            }
            return "unknown";
        }

        Observation Verify(ObjectModelReader &model, const EngineSchema &schema, Budget &budget, Payload payload,
                           int32_t offset, const Sample &sample, uintptr_t &first, uintptr_t &second)
        {
            if (payload == Payload::Bool)
            {
                std::array<uint8_t, 4> layout{};
                if (!budget.Read(sample.metadata.address, offset, layout))
                    return Observation::Unreadable;
                first = static_cast<uintptr_t>(layout[0]) | (static_cast<uintptr_t>(layout[1]) << 8) |
                        (static_cast<uintptr_t>(layout[2]) << 16) | (static_cast<uintptr_t>(layout[3]) << 24);
                return IsValidBoolLayout(layout, sample.metadata.elementSize) ? Observation::Match : Observation::Mismatch;
            }
            if (!budget.Read(sample.metadata.address, offset, first))
                return Observation::Unreadable;
            if (payload == Payload::Class || payload == Payload::Map || payload == Payload::Enum)
            {
                const int32_t secondOffset = payload == Payload::Class ? offset - static_cast<int32_t>(sizeof(uintptr_t)) : offset + static_cast<int32_t>(sizeof(uintptr_t));
                if (!budget.Read(sample.metadata.address, secondOffset, second))
                    return Observation::Unreadable;
            }
            if ((first != 0 && !budget.memory.IsReadable(first, sizeof(uintptr_t))) ||
                ((payload == Payload::Class || payload == Payload::Map || payload == Payload::Enum) &&
                 second != 0 && !budget.memory.IsReadable(second, sizeof(uintptr_t))))
                return Observation::Mismatch;
            // 双引用中一个 NULL 不能掩盖另一个非零引用的结构错误
            if (payload == Payload::Class &&
                ((first != 0 && !ObjectKind(model, first, DefinitionKind::Class)) ||
                 (second != 0 && (!ObjectKind(model, second, DefinitionKind::Class) || !ClassDerivesFrom(model, second, "Class")))))
                return Observation::Mismatch;
            std::optional<PropertyMetadata> firstChild;
            if (payload == Payload::Map || payload == Payload::Enum)
            {
                // 双引用先逐项验证，再判断 NULL，后续语义检查复用本轮结果
                if (first != 0)
                {
                    firstChild = Child(model, schema, first, sample.metadata.address);
                    if (!firstChild)
                        return Observation::Mismatch;
                }
                if (second != 0 &&
                    (payload == Payload::Map ? !Child(model, schema, second, sample.metadata.address)
                                             : !ObjectKind(model, second, DefinitionKind::Enum)))
                    return Observation::Mismatch;
            }
            if (first == 0 || ((payload == Payload::Class || payload == Payload::Map || payload == Payload::Enum) && second == 0))
                return Observation::Null;
            bool valid = false;
            switch (payload)
            {
            case Payload::Byte:
                valid = ObjectKind(model, first, DefinitionKind::Enum);
                break;
            case Payload::Object:
                valid = ObjectKind(model, first, DefinitionKind::Class);
                break;
            case Payload::Interface:
                valid = ObjectKind(model, first, DefinitionKind::Class) && ClassDerivesFrom(model, first, "Interface");
                break;
            case Payload::Class:
                valid = true;
                break;
            case Payload::Struct:
                valid = ObjectKind(model, first, DefinitionKind::Struct);
                break;
            case Payload::Delegate:
                valid = FunctionIdentity(model, first);
                break;
            case Payload::FieldPath:
                valid = model.ValidateFieldClass(first).valid;
                break;
            case Payload::Array:
            case Payload::Set:
            case Payload::Optional:
                valid = Child(model, schema, first, sample.metadata.address).has_value();
                break;
            case Payload::Map:
                valid = first != second;
                break;
            case Payload::Enum:
                valid = firstChild && IntegerProperty(*firstChild) && firstChild->elementSize == sample.metadata.elementSize;
                break;
            case Payload::Bool:
                break;
            }
            return valid ? Observation::Match : Observation::Mismatch;
        }

        void ResolveFieldPathSpec(ObjectModelReader &model, ProbeMemory &probeMemory, Budget &budget,
                                  const SubtypeSpec &spec, const std::vector<PropertyTailCandidate> &tails,
                                  const std::vector<Sample> &samples, PropertySubtypesSchema &output,
                                  SchemaResolutionReport &report)
        {
            const auto candidates = FieldPathCandidates(tails);
            std::vector<int32_t> accepted;
            for (const auto &candidate : candidates)
            {
                size_t matches = 0;
                size_t nulls = 0;
                size_t unreadable = 0;
                size_t mismatches = 0;
                std::ostringstream observations;
                std::set<uintptr_t> owners;
                std::set<uintptr_t> rawReferences;
                std::set<std::string> targetClasses;
                std::set<std::string> rejectionReasons;
                for (const auto &sample : samples)
                {
                    uintptr_t rawReference = 0;
                    std::string targetName = "<unobserved>";
                    std::string reason;
                    Observation state = Observation::Unreadable;
                    if (!budget.Read(sample.metadata.address, candidate.offset, rawReference))
                    {
                        reason = "property-class-reference-unreadable";
                        ++unreadable;
                        targetName = "<unreadable>";
                    }
                    else if (rawReference == 0)
                    {
                        reason = "null-reference";
                        state = Observation::Null;
                        ++nulls;
                        targetName = "<null>";
                    }
                    else
                    {
                        const auto validation = model.ValidateFieldClass(rawReference);
                        targetName = validation.targetName.empty() ? "<unreadable>" : validation.targetName;
                        reason = validation.reason;
                        state = validation.valid ? Observation::Match : Observation::Mismatch;
                        if (validation.valid)
                        {
                            ++matches;
                            owners.insert(sample.rootOwner);
                        }
                        else
                            ++mismatches;
                    }
                    rawReferences.insert(rawReference);
                    targetClasses.insert(targetName);
                    rejectionReasons.insert(reason);
                    observations << " {property=" << Hex(sample.metadata.address)
                                 << " owner=" << Hex(sample.rootOwner) << " raw=" << Hex(rawReference)
                                 << " target=" << std::quoted(targetName) << " state=" << ObservationName(state)
                                 << " reason=" << std::quoted(reason) << '}';
                }
                report.evidence.push_back("property class observations: member=" + std::string(spec.name) +
                                          " offset=" + std::to_string(candidate.offset) + " basis=" + candidate.basis +
                                          " rows=" + observations.str());
                const bool valid = matches >= 2 && owners.size() >= 2 && mismatches == 0 && unreadable == 0 &&
                                   !budget.exhausted && !probeMemory.Exhausted();
                if (valid)
                    accepted.push_back(candidate.offset);
                report.evidence.push_back("property class candidate: member=" + std::string(spec.name) + " offset=" + std::to_string(candidate.offset) + " physical_position_deduplicated=1 basis=" + candidate.basis + " samples=" + std::to_string(samples.size()) + " matches=" + std::to_string(matches) + " independent_owners=" + std::to_string(owners.size()) + " raw_references=" + [&rawReferences]
                                          {
                                              std::string values;
                                              for (const auto value : rawReferences)
                                                  values += (values.empty() ? "" : ",") + std::to_string(value);
                                              return values.empty() ? "none" : values; }() + " target_ffield_classes=" + [&targetClasses]
                                          {
                                              std::string values;
                                              for (const auto &value : targetClasses)
                                                  values += (values.empty() ? "" : ",") + value;
                                              return values.empty() ? "none" : values; }() + " observed_rejection_reasons=" + [&rejectionReasons]
                                          {
                                              std::string values;
                                              for (const auto &value : rejectionReasons)
                                                  values += (values.empty() ? "" : ",") + value;
                                              return values.empty() ? "none" : values; }() + " null=" + std::to_string(nulls) + " unreadable=" + std::to_string(unreadable) + " mismatches=" + std::to_string(mismatches) + " accepted=" + std::to_string(valid) + " rejection_reason=" + (valid ? "none" : budget.exhausted || probeMemory.Exhausted() ? "read-budget-exhausted"
                                                                                                                                                                                                                                                             : tails.empty()                                 ? "unresolved-property-tail"
                                                                                                                                                                                                                                                             : samples.empty()                               ? "missing-sample"
                                                                                                                                                                                                                                                             : matches < 2 || owners.size() < 2              ? "insufficient-independent-owner-matches"
                                                                                                                                                                                                                                                             : mismatches != 0                               ? "ffield-class-validation-rejected"
                                                                                                                                                                                                                                                             : unreadable != 0                               ? "property-class-reference-unreadable"
                                                                                                                                                                                                                                                                                                             : "no-consensus"));
            }
            if (accepted.size() == 1 && !budget.exhausted && !probeMemory.Exhausted())
                output.*(spec.member) = accepted.front();
            report.evidence.push_back("property subtype result: member=" + std::string(spec.name) +
                                      " selected_offset=" + std::to_string(output.*(spec.member)) +
                                      " accepted_candidates=" + std::to_string(accepted.size()) +
                                      " candidate_source=property-tail-structure; broad-field-scan=disabled reason=" +
                                      (budget.exhausted || probeMemory.Exhausted() ? "read-budget-exhausted" : tails.empty()     ? "unresolved-property-tail"
                                                                                                           : samples.empty()     ? "missing-sample"
                                                                                                           : accepted.empty()    ? "no-consensus"
                                                                                                           : accepted.size() > 1 ? "ambiguous-candidates"
                                                                                                                                 : "validated"));
        }

        void ResolveOptionalSpec(ObjectModelReader &model, const EngineSchema &schema, ProbeMemory &probeMemory,
                                 Budget &budget, const SubtypeSpec &spec, const std::vector<PropertyTailCandidate> &tails,
                                 const std::vector<Sample> &samples, PropertySubtypesSchema &output,
                                 OptionalPropertySupport &support, SchemaResolutionReport &report)
        {
            support.presentInProfile = schema.layout == SchemaLayoutVariant::FFieldTagged ||
                                       schema.layout == SchemaLayoutVariant::FFieldTaggedModern;
            support.sampleCount = samples.size();
            support.source = "property-tail-complete-size";
            support.selectedOffset = -1;
            support.confidence = "none";
            support.reason = !support.presentInProfile ? "engine-family-has-no-optional-property-sample" : samples.empty() ? "no-optional-property-sample"
                                                                                                       : tails.empty()     ? "unresolved-property-tail"
                                                                                                                           : "no-consensus";

            std::set<int32_t> offsets;
            for (const auto &tail : tails)
            {
                if (tail.completeSize >= 0)
                    offsets.insert(tail.completeSize);
            }
            if (!support.presentInProfile)
            {
                support.source = "none";
                report.evidence.push_back("optional_property_support: present_in_profile=0 sample_count=0 selected_offset=-1 confidence=none source=none reason=engine-family-has-no-optional-property-sample");
                return;
            }

            std::vector<int32_t> accepted;
            for (const auto offset : offsets)
            {
                size_t matches = 0;
                size_t nulls = 0;
                size_t unreadable = 0;
                size_t mismatches = 0;
                std::ostringstream observations;
                std::set<uintptr_t> owners;
                const auto tailForOffset = std::find_if(tails.begin(), tails.end(), [offset](const PropertyTailCandidate &tail)
                                                        { return tail.completeSize == offset; });
                const std::string tailLayout = tailForOffset == tails.end() ? "unknown" : PropertyTailName(tailForOffset->layout);
                const int32_t dataEnd = tailForOffset == tails.end() ? -1 : tailForOffset->dataEnd;
                const int32_t completeSize = tailForOffset == tails.end() ? -1 : tailForOffset->completeSize;

                for (const auto &sample : samples)
                {
                    uintptr_t rawReference = 0;
                    std::string childName = "<unobserved>";
                    std::string childClass = "<unobserved>";
                    uintptr_t childOwner = 0;
                    bool childOwnerIsUObject = false;
                    std::string matchState = "unreadable";
                    std::string rejectionReason = "candidate-read-unreadable";
                    if (!budget.Read(sample.metadata.address, offset, rawReference))
                    {
                        ++unreadable;
                        if (budget.exhausted || probeMemory.Exhausted())
                            rejectionReason = "read-budget-exhausted";
                    }
                    else if (rawReference == 0)
                    {
                        ++nulls;
                        matchState = "null-reference";
                        rejectionReason = "candidate-reference-null";
                    }
                    else
                    {
                        const auto child = model.Property(rawReference);
                        if (!child || !ValidHeader(*child) || !IsPropertyFieldKind(child->kind))
                        {
                            ++mismatches;
                            matchState = "invalid-child-property";
                            rejectionReason = "reference-not-property";
                        }
                        else
                        {
                            childName = child->name;
                            childClass = child->normalizedClassName;
                            childOwner = child->ownerAddress;
                            childOwnerIsUObject = child->ownerIsUObject;
                            const bool ownerValid = schema.features.useFProperty
                                                        ? !child->ownerIsUObject && child->ownerAddress == sample.metadata.address
                                                        : ObjectIdentity(model, rawReference) && model.Outer(rawReference).value_or(0) == sample.metadata.address;
                            if (!ownerValid)
                            {
                                ++mismatches;
                                matchState = "owner-mismatch";
                                rejectionReason = "child-owner-mismatch";
                            }
                            else
                            {
                                ++matches;
                                owners.insert(sample.rootOwner);
                                matchState = "match";
                                rejectionReason = "none";
                            }
                        }
                    }

                    observations << " {property=" << Hex(sample.metadata.address)
                                 << " owner=" << Hex(sample.metadata.ownerAddress) << " root_owner=" << Hex(sample.rootOwner)
                                 << " raw=" << Hex(rawReference) << " child_owner=" << Hex(childOwner)
                                 << " child_owner_is_uobject=" << childOwnerIsUObject
                                 << " child_name=" << std::quoted(childName) << " child_class=" << std::quoted(childClass)
                                 << " state=" << matchState << " reason=" << std::quoted(rejectionReason) << '}';
                }
                report.evidence.push_back("optional observations: offset=" + std::to_string(offset) +
                                          " tail_layout=" + tailLayout + " data_end=" + std::to_string(dataEnd) +
                                          " complete_size=" + std::to_string(completeSize) + " rows=" + observations.str());

                const bool budgetExhausted = budget.exhausted || probeMemory.Exhausted();
                const bool valid = matches != 0 && nulls == 0 && mismatches == 0 && unreadable == 0 && !budgetExhausted;
                if (valid)
                    accepted.push_back(offset);
                const std::string rejection = valid ? "none" : budgetExhausted ? "read-budget-exhausted"
                                                           : tails.empty()     ? "unresolved-property-tail"
                                                           : samples.empty()   ? "missing-optional-property-sample"
                                                           : nulls != 0        ? "candidate-reference-null"
                                                           : mismatches != 0   ? "candidate-child-validation-rejected"
                                                           : unreadable != 0   ? "candidate-read-unreadable"
                                                                               : "no-consensus";
                report.evidence.push_back("optional candidate summary: property_class=OptionalProperty tail_layout=" + tailLayout +
                                          " data_end=" + std::to_string(dataEnd) + " complete_size=" + std::to_string(completeSize) +
                                          " candidate_offset=" + std::to_string(offset) + " samples=" + std::to_string(samples.size()) +
                                          " matches=" + std::to_string(matches) + " independent_owners=" + std::to_string(owners.size()) +
                                          " null=" + std::to_string(nulls) + " unreadable=" + std::to_string(unreadable) +
                                          " mismatches=" + std::to_string(mismatches) + " read_budget_exhausted=" + std::to_string(budgetExhausted) +
                                          " accepted=" + std::to_string(valid) + " rejection_reason=" + rejection);
            }

            if (accepted.size() == 1 && !budget.exhausted && !probeMemory.Exhausted())
            {
                output.*(spec.member) = accepted.front();
                support.selectedOffset = accepted.front();
                support.confidence = samples.size() == 1 ? "limited" : "validated";
                support.reason = samples.size() == 1 ? "validated-single-sample" : "validated";
            }
            else if (accepted.size() > 1)
                support.reason = "ambiguous-candidates";
            else if (budget.exhausted || probeMemory.Exhausted())
                support.reason = "read-budget-exhausted";
            report.evidence.push_back("optional_property_support: present_in_profile=" + std::to_string(support.presentInProfile) +
                                      " sample_count=" + std::to_string(support.sampleCount) +
                                      " selected_offset=" + std::to_string(support.selectedOffset) +
                                      " confidence=" + support.confidence + " source=" + support.source +
                                      " reason=" + support.reason);
            if (support.presentInProfile && support.sampleCount != 0)
                report.versionEvidence.push_back({"optional-property-capability",
                                                  "sample_count=" + std::to_string(support.sampleCount) +
                                                      " selected_offset=" + std::to_string(support.selectedOffset),
                                                  VersionEvidenceStrength::Strong,
                                                  "OptionalProperty child field validated from the property tail"});
        }
        void ResolveSpec(ObjectModelReader &model, const EngineSchema &schema, Budget &budget,
                         const SubtypeSpec &spec, const std::vector<PropertyTailCandidate> &tails,
                         const std::vector<Sample> &samples, PropertySubtypesSchema &output,
                         OptionalPropertySupport &optionalSupport, SchemaResolutionReport &report)
        {
            if (spec.payload == Payload::FieldPath)
            {
                ResolveFieldPathSpec(model, budget.memory, budget, spec, tails, samples, output, report);
                return;
            }
            if (spec.payload == Payload::Optional)
            {
                ResolveOptionalSpec(model, schema, budget.memory, budget, spec, tails, samples, output, optionalSupport, report);
                return;
            }
            std::set<int32_t> offsets;
            for (const auto &tail : tails)
                for (const auto offset : PayloadOffsets(tail, spec.payload))
                    offsets.insert(offset);
            std::vector<int32_t> accepted;
            for (const auto offset : offsets)
            {
                size_t matches = 0;
                size_t nulls = 0;
                size_t unreadable = 0;
                size_t mismatches = 0;
                std::ostringstream observations;
                std::set<uintptr_t> owners;
                for (const auto &sample : samples)
                {
                    uintptr_t first = 0, second = 0;
                    const auto state = Verify(model, schema, budget, spec.payload, offset, sample, first, second);
                    switch (state)
                    {
                    case Observation::Match:
                        ++matches;
                        owners.insert(sample.rootOwner);
                        break;
                    case Observation::Null:
                        ++nulls;
                        if (spec.payload == Payload::Byte)
                            owners.insert(sample.rootOwner);
                        break;
                    case Observation::Unreadable:
                        ++unreadable;
                        break;
                    case Observation::Mismatch:
                        ++mismatches;
                        break;
                    }
                    observations << " {property=" << Hex(sample.metadata.address)
                                 << " owner=" << Hex(sample.metadata.ownerAddress) << " root_owner=" << Hex(sample.rootOwner)
                                 << " raw=" << Hex(first) << " secondary=" << Hex(second)
                                 << " class=" << sample.metadata.normalizedClassName << " name=" << std::quoted(sample.metadata.name)
                                 << " scope=" << sample.scope << " state=" << ObservationName(state) << '}';
                }
                report.evidence.push_back("property subtype observations: member=" + std::string(spec.name) +
                                          " offset=" + std::to_string(offset) + " rows=" + observations.str());
                const size_t positives = matches + (spec.payload == Payload::Byte ? nulls : 0);
                if (positives >= 2 && owners.size() >= 2 && mismatches == 0 && unreadable == 0 &&
                    (spec.payload != Payload::Byte || matches != 0 || offsets.size() == 1) &&
                    !budget.exhausted && !budget.memory.Exhausted())
                    accepted.push_back(offset);
                report.evidence.push_back("property subtype candidate: member=" + std::string(spec.name) +
                                          " offset=" + std::to_string(offset) + " samples=" + std::to_string(samples.size()) +
                                          " matches=" + std::to_string(matches) + " independent_owners=" + std::to_string(owners.size()) +
                                          " null=" + std::to_string(nulls) + " unreadable=" + std::to_string(unreadable) +
                                          " mismatches=" + std::to_string(mismatches) +
                                          " observation_samples_omitted=0" +
                                          " read_budget_exhausted=" + std::to_string(budget.exhausted || budget.memory.Exhausted()));
            }
            if (accepted.size() == 1 && !budget.exhausted && !budget.memory.Exhausted())
                output.*(spec.member) = accepted.front();
            report.evidence.push_back("property subtype result: member=" + std::string(spec.name) +
                                      " selected_offset=" + std::to_string(output.*(spec.member)) +
                                      " accepted_candidates=" + std::to_string(accepted.size()) +
                                      " reason=" + (budget.exhausted || budget.memory.Exhausted() ? "read-budget-exhausted" : tails.empty()     ? "unresolved-property-tail"
                                                                                                                          : samples.empty()     ? "missing-sample"
                                                                                                                          : accepted.empty()    ? "no-consensus"
                                                                                                                          : accepted.size() > 1 ? "ambiguous-candidates"
                                                                                                                                                : "validated"));
        }

        void ExpandChildren(ObjectModelReader &model, const EngineSchema &schema, Budget &budget,
                            const std::vector<PropertyTailCandidate> &tails, SampleSet &samples)
        {
            // 先验证候选父子关系再采样，不使用尚未提交的 subtype 偏移
            for (size_t index = 0; index < samples.containers.size() && !budget.exhausted && !budget.memory.Exhausted(); ++index)
            {
                const auto [payload, sample] = samples.containers[index];
                if (sample.depth + 1 >= kMaxDepth)
                {
                    samples.collectionLimit = true;
                    continue;
                }
                std::set<int32_t> offsets;
                for (const auto &tail : tails)
                    for (auto offset : PayloadOffsets(tail, payload))
                        offsets.insert(offset);
                std::vector<std::pair<uintptr_t, uintptr_t>> children;
                for (auto offset : offsets)
                {
                    uintptr_t first = 0, second = 0;
                    if (Verify(model, schema, budget, payload, offset, sample, first, second) == Observation::Match)
                        children.emplace_back(first, payload == Payload::Map ? second : uintptr_t{0});
                }
                // 两个不同结构候选都通过时不以任意一组孩子扩展采样。
                if (children.size() == 1)
                {
                    for (auto address : {children.front().first, children.front().second})
                    {
                        const auto child = Child(model, schema, address, sample.metadata.address);
                        if (child)
                            samples.Add(*child, sample.rootOwner, sample.depth + 1, "nested-property");
                    }
                }
            }
        }
    } // namespace

    bool SchemaProbeContext::ResolvePropertySubtypes(EngineSchema &schema, SchemaResolutionReport &report) const
    {
        schema.propertySubtypes = {};
        schema.property.baseSize = -1;
        schema.property.repNotify = -1;
        schema.property.propertyLinks = -1;
        schema.property.propertyLinksEnd = -1;
        schema.property.subtypeStart = -1;
        schema.features.propertyTailLayout = PropertyTailLayout::Unknown;
        schema.optionalPropertySupport = {};
        ProbeMemory probeMemory(memory_);
        ObjectModelReader model(probeMemory, binding_, schema);
        if (!model.Initialize())
        {
            report.probeLimited = true;
            report.evidenceComplete = false;
            report.searchComplete = false;
            report.evidence.push_back("property subtype result: reason=object-model-initialization-failed");
            return true;
        }
        auto samples = CollectSamples(model, probeMemory, schema, session_, report);
        if (probeMemory.Exhausted())
        {
            report.probeLimited = true;
            report.budgetExhausted = true;
            report.searchComplete = false;
            report.evidence.push_back("property subtype result: reason=collection-read-budget-exhausted");
            return true;
        }
        probeMemory.ResetBudget(kMaxReads);
        Budget budget{probeMemory};
        std::vector<PropertyTailCandidate> tails;
        for (const auto &candidate : PropertyTails(schema))
        {
            const bool valid = TailValid(model, budget, schema, candidate, samples.tail, report);
            report.evidence.push_back("property subtype tail candidate: layout=" + std::string(PropertyTailName(candidate.layout)) +
                                      " rep_notify=" + std::to_string(candidate.repNotify) + " links=" + std::to_string(candidate.links) +
                                      " data_end=" + std::to_string(candidate.dataEnd) + " complete_size=" + std::to_string(candidate.completeSize) +
                                      " samples=" + std::to_string(samples.tail.size()) + " valid=" + std::to_string(valid));
            // 有界诊断：TailValid 在首个失败处返回，只留下一条证据。这里用独立预算遍历全部
            // 样本，给出 repNotify 与 property-link 各自单独成立的比例，用来区分
            // 「两个字段都错」与「只有一个字段错」。仅统计，不参与判定。
            const TailDiagnostics diag = DiagnoseTail(memory_, binding_, schema, candidate, samples.tail);
            std::string diagLine = "property subtype tail diagnostics: layout=" +
                                   std::string(PropertyTailName(candidate.layout)) +
                                   " samples=" + std::to_string(diag.samples) +
                                   " owners=" + std::to_string(diag.owners) +
                                   " rep_notify_valid=" + std::to_string(diag.repNotifyValid) +
                                   " link_nonzero=" + std::to_string(diag.linkNonZero) +
                                   " links_valid=" + std::to_string(diag.linkValid) +
                                   " fully_valid=" + std::to_string(diag.fullyValid);
            for (size_t index = 0; index < diag.captured; ++index)
            {
                diagLine += " s" + std::to_string(index) + "={rep=" + std::to_string(diag.firstRepNotify[index]) +
                            ",link0=" + Hex(diag.firstLinks[index]) + "}";
            }
            report.evidence.push_back(std::move(diagLine));
            std::string causeLine = "property subtype tail link causes: layout=" +
                                    std::string(PropertyTailName(candidate.layout)) +
                                    " unreadable=" + std::to_string(diag.linkUnreadable) +
                                    " not_field=" + std::to_string(diag.linkNotField) +
                                    " wrong_kind=" + std::to_string(diag.linkWrongKind);
            for (size_t index = 0; index < diag.notFieldCaptured; ++index)
                causeLine += " nf" + std::to_string(index) + "=" + Hex(diag.firstNotField[index]);
            for (size_t index = 0; index < diag.wrongKindCaptured; ++index)
                causeLine += " wk" + std::to_string(index) + "=" + Hex(diag.firstWrongKind[index]) +
                             ":" + diag.firstWrongKindNames[index];
            report.evidence.push_back(std::move(causeLine));
            if (valid)
                tails.push_back(candidate);
        }
        if (budget.exhausted || probeMemory.Exhausted())
        {
            report.probeLimited = true;
            report.budgetExhausted = true;
            report.searchComplete = false;
            report.evidence.push_back("property subtype result: reason=tail-read-budget-exhausted");
            return true;
        }
        if (!tails.empty())
        {
            // 成员顺序存在歧义不会使独立达成一致的偏移量失效
            const auto consensus = [&](int32_t PropertyTailCandidate::*member)
            {
                const int32_t value = tails.front().*member;
                return std::all_of(tails.begin(), tails.end(), [&](const auto &tail)
                                   { return tail.*member == value; })
                           ? value
                           : -1;
            };
            schema.property.baseSize = consensus(&PropertyTailCandidate::completeSize);
            schema.property.repNotify = consensus(&PropertyTailCandidate::repNotify);
            schema.property.propertyLinks = consensus(&PropertyTailCandidate::links);
            schema.property.propertyLinksEnd = consensus(&PropertyTailCandidate::linksEnd);
            schema.property.subtypeStart = consensus(&PropertyTailCandidate::dataEnd);
            if (tails.size() == 1)
                schema.features.propertyTailLayout = tails.front().layout;
        }
        report.evidence.push_back("property tail selection: accepted_candidates=" + std::to_string(tails.size()) +
                                  " selected_layout=" + std::string(PropertyTailName(schema.features.propertyTailLayout)) +
                                  " consensus_complete_size=" + std::to_string(schema.property.baseSize) +
                                  " consensus_rep_notify=" + std::to_string(schema.property.repNotify) +
                                  " consensus_links=" + std::to_string(schema.property.propertyLinks) +
                                  " consensus_links_end=" + std::to_string(schema.property.propertyLinksEnd) +
                                  " consensus_data_end=" + std::to_string(schema.property.subtypeStart) +
                                  " reason=" + (tails.empty() ? "no-validated-tail" : tails.size() == 1 ? "unique-validated-tail"
                                                                                                        : "multiple-validated-tails") +
                                  "; subtype candidates remain constrained to validated tails");
        probeMemory.ResetBudget(4 * kMaxReads);
        Budget expansionBudget{probeMemory};
        expansionBudget.remaining = 4 * kMaxReads;
        ExpandChildren(model, schema, expansionBudget, tails, samples);
        PropertySubtypesSchema resolved;
        bool validationLimit = expansionBudget.exhausted || probeMemory.Exhausted();
        for (const auto &spec : kSpecs)
        {
            probeMemory.ResetBudget(kMaxReads);
            Budget validationBudget{probeMemory};
            std::map<std::string, size_t> classes;
            for (const auto &sample : samples.byPayload[spec.payload])
                ++classes[sample.metadata.normalizedClassName];
            for (const auto &[name, count] : classes)
                report.evidence.push_back("property subtype sample class: member=" + std::string(spec.name) +
                                          " class=" + name + " retained=" + std::to_string(count) +
                                          " sample_limit_per_class=" + std::to_string(kMaxSamplesPerKind));
            ResolveSpec(model, schema, validationBudget, spec, tails, samples.byPayload[spec.payload], resolved,
                        schema.optionalPropertySupport, report);
            validationLimit = validationLimit || validationBudget.exhausted || probeMemory.Exhausted();
        }
        schema.propertySubtypes = resolved;
        // 收集上限限制的是覆盖率范围，而非限定那些已被验证过的有效偏移量
        // 未被观测到的类型保留为 -1，因此数据共享绝不会凭空制造缺失证据
        report.sampleTruncated = samples.collectionLimit || session_.indexLimited;
        report.budgetExhausted = validationLimit;
        report.evidenceComplete = samples.unreadable == 0 && samples.incompleteChains == 0;
        report.searchComplete = !report.sampleTruncated && !validationLimit && report.evidenceComplete;
        report.probeLimited = report.probeLimited || !report.searchComplete;
        if (report.sampleTruncated && !report.budgetExhausted && report.evidenceComplete &&
            schema.optionalPropertySupport.sampleCount == 0 && schema.optionalPropertySupport.selectedOffset < 0)
            schema.optionalPropertySupport.reason = "not-observed-within-sample-budget";
        report.evidence.push_back("property subtype sampling summary: roots=" + std::to_string(samples.roots) +
                                  " unique_properties=" + std::to_string(samples.visited.size()) +
                                  " unreadable=" + std::to_string(samples.unreadable) +
                                  " incomplete_chains=" + std::to_string(samples.incompleteChains) +
                                  " samples_omitted=" + std::to_string(samples.omitted) +
                                  " collection_limit=" + std::to_string(samples.collectionLimit) +
                                  " read_budget_exhausted=" + std::to_string(validationLimit) +
                                  "; scopes=types-functions-recursive-children");
        return true;
    }
} // namespace nextdumper::ue::schema_probe
