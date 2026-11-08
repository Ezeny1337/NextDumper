#include "nextdumper/reflection/ObjectSerialDiscovery.hpp"
#include "RuntimeFieldPlanner.hpp"
#include "RuntimeReadSupport.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

#include "nextdumper/ue/ObjectModelReader.hpp"

namespace nextdumper::reflection
{
    namespace
    {
        using Limits = binding::ObjectSerialDiscoveryLimits;
        using detail::Add;
        using detail::Offset;
        using detail::RuntimeField;
        using detail::RuntimeFieldPlanner;

        struct ReferenceSample
        {
            binding::ObjectSerialSample observation;
            int32_t ownerIndex = -1;
            uintptr_t ownerClass = 0;
            uintptr_t expectedType = 0;
        };

        class Discovery
        {
        public:
            Discovery(memory::IMemorySource &memory, const binding::RuntimeBinding &binding,
                      const ue::EngineSchema &schema, const ir::ReflectionIR &reflection)
                : memory_(memory), binding_(binding), generation_(memory.AddressSpaceGeneration()),
                  capture_(memory), objects_(capture_, binding, schema), fields_(reflection, true) {}

            binding::ObjectSerialEvidence Run()
            {
                if (binding_.objects.itemSerialOffset >= 0)
                {
                    result_.status = "explicit-layout";
                    result_.selectedOffset = binding_.objects.itemSerialOffset;
                    return result_;
                }
                if (!binding_.IsValid() || !objects_.Initialize())
                {
                    result_.status = "object-model-unavailable";
                    return result_;
                }
                result_.objectSlots = objects_.Count();
                result_.itemBytes = static_cast<int32_t>(
                    std::min<size_t>(static_cast<size_t>(binding_.objects.itemStride), Limits::kMaxItemBytes));
                for (int32_t offset = 0; offset <= result_.itemBytes - 4; offset += 4)
                {
                    // 打包指针同样由一个完整的地址宽度字读取，不能把其中的位误认成 serial
                    if (offset < static_cast<int64_t>(binding_.objects.itemObjectOffset) +
                                     static_cast<int64_t>(sizeof(uintptr_t)) &&
                        offset + 4 > binding_.objects.itemObjectOffset)
                        continue;
                    result_.candidates.push_back({offset, 0, 0, 0});
                }
                if (result_.candidates.empty())
                {
                    result_.status = "no-item-candidates";
                    return result_;
                }

                Scan();
                for (const auto &[reason, count] : fields_.Skipped())
                    result_.skipped[reason] += count;
                Score();
                Select();
                const size_t successfulLimit = Limits::kMaxDiagnosticSamples - rejected_.size();
                for (const bool matched : {true, false})
                {
                    for (const auto &sample : samples_)
                    {
                        if (result_.samples.size() == successfulLimit)
                            break;
                        const bool hasMatches = !sample.observation.matchingOffsets.empty();
                        if (hasMatches == matched)
                            result_.samples.push_back(sample.observation);
                    }
                }
                result_.samples.insert(result_.samples.end(), rejected_.begin(), rejected_.end());
                return std::move(result_);
            }

        private:
            bool ShouldStop() const
            {
                return result_.referenceReads >= Limits::kMaxReferenceReads ||
                       samples_.size() >= Limits::kMaxTargetSamples || memory_.AddressSpaceGeneration() != generation_;
            }

            bool Reject(ReferenceSample &sample, const char *reason)
            {
                ++result_.skipped[reason];
                sample.observation.status = reason;
                if (rejected_.size() < Limits::kMaxRejectedDiagnosticSamples &&
                    std::none_of(rejected_.begin(), rejected_.end(),
                                 [reason](const auto &value)
                                 { return value.status == reason; }))
                    rejected_.push_back(sample.observation);
                return false;
            }

            bool HasExpectedType(uintptr_t classAddress, uintptr_t expected) const
            {
                if (!expected)
                {
                    const auto *type = fields_.Type(classAddress);
                    return type && type->kind == ir::TypeKind::Class;
                }
                std::set<uintptr_t> visited;
                for (size_t depth = 0; classAddress && depth < 64 && visited.insert(classAddress).second; ++depth)
                {
                    if (classAddress == expected)
                        return true;
                    const auto *type = fields_.Type(classAddress);
                    if (!type)
                        break;
                    classAddress = type->superAddress;
                }
                return false;
            }

            bool Snapshot(ReferenceSample &sample)
            {
                capture_.Reset();
                {
                    memory::CaptureObservationScope observing(capture_);
                    const auto owner = objects_.Objects().ReadObject(sample.ownerIndex);
                    const auto ownerIndex = objects_.InternalIndex(sample.observation.owner);
                    const auto ownerClass = objects_.Class(sample.observation.owner);
                    const auto flags = objects_.Flags(sample.observation.owner);
                    std::array<int32_t, 2> pair{};
                    if (!owner.IsValid() || owner.address != sample.observation.owner ||
                        !ownerIndex || *ownerIndex != sample.ownerIndex || !ownerClass ||
                        *ownerClass != sample.ownerClass || !flags || (*flags & ue::kRFUnavailableDefinition) != 0 ||
                        !capture_.ReadBytes(sample.observation.reference, pair.data(), sizeof(pair)).Ok() ||
                        pair[0] != sample.observation.targetIndex || pair[1] != sample.observation.serial)
                    {
                        return Reject(sample, "reference-owner-changed-or-unreadable");
                    }
                    const auto target = objects_.Objects().ReadObject(pair[0]);
                    const auto targetIndex = target.IsValid() ? objects_.InternalIndex(target.address) : std::nullopt;
                    const auto targetClass = target.IsValid() ? objects_.Class(target.address) : std::nullopt;
                    if (!target.IsValid() || !targetIndex || *targetIndex != pair[0] || !targetClass ||
                        !HasExpectedType(*targetClass, sample.expectedType) ||
                        (sample.observation.target && target.address != sample.observation.target) ||
                        target.readAddress < static_cast<uintptr_t>(binding_.objects.itemObjectOffset))
                    {
                        return Reject(sample, "target-index-type-or-address-unavailable");
                    }
                    sample.observation.target = target.address;
                    sample.observation.item = target.readAddress - static_cast<uintptr_t>(binding_.objects.itemObjectOffset);
                    sample.observation.itemBytes.resize(static_cast<size_t>(result_.itemBytes));
                    if (!capture_.ReadBytes(sample.observation.item, sample.observation.itemBytes.data(),
                                            sample.observation.itemBytes.size())
                             .Ok())
                    {
                        return Reject(sample, "target-item-unreadable");
                    }
                }
                const auto validation = capture_.Validate();
                if (!validation.Stable() || validation.limitExceeded || validation.readFailures != 0 ||
                    memory_.AddressSpaceGeneration() != generation_)
                {
                    return Reject(sample, "unstable-reference-or-item");
                }
                sample.observation.matchingOffsets.clear();
                sample.observation.status = "stable-reference-and-item";
                for (const auto &candidate : result_.candidates)
                {
                    int32_t value = 0;
                    std::memcpy(&value, sample.observation.itemBytes.data() + candidate.offset, sizeof(value));
                    if (value == sample.observation.serial)
                        sample.observation.matchingOffsets.push_back(candidate.offset);
                }
                return true;
            }

            void ReadField(int32_t index, uintptr_t object, uintptr_t classAddress, const RuntimeField &field)
            {
                const auto &type = field.property->type;
                const auto &layout = type.valueStorage;
                if (!layout || layout->size != type.elementSize || Offset(*layout, "RemoteObjectId") >= 0)
                {
                    ++result_.skipped["reference-layout-unsupported"];
                    return;
                }
                const int32_t weak = Offset(*layout, "ObjectIndex");
                if (weak < 0 || Offset(*layout, "ObjectSerialNumber") != weak + 4 || weak > type.elementSize - 8)
                {
                    ++result_.skipped["reference-pair-offset-unavailable"];
                    return;
                }
                const auto address = Add(object, field.offset);
                const auto pairAddress = address ? Add(*address, static_cast<uint32_t>(weak)) : std::nullopt;
                if (!pairAddress)
                {
                    ++result_.skipped["reference-address-overflow"];
                    return;
                }
                ReferenceSample sample;
                sample.ownerIndex = index;
                sample.ownerClass = classAddress;
                sample.expectedType = type.kind == ir::PropertyKind::Delegate || type.kind == ir::PropertyKind::SoftClass
                                          ? 0
                                          : type.referencedObject;
                sample.observation.owner = object;
                sample.observation.reference = *pairAddress;
                sample.observation.path = field.path;
                std::array<int32_t, 2> pair{};
                ++result_.referenceReads;
                if (!memory_.ReadFreshBytes(*pairAddress, pair.data(), sizeof(pair)).Ok())
                {
                    Reject(sample, "reference-unreadable");
                    return;
                }
                sample.observation.targetIndex = pair[0];
                sample.observation.serial = pair[1];
                if ((pair[0] == -1 || pair[0] == 0) && pair[1] == 0)
                {
                    Reject(sample, "null-reference");
                    return;
                }
                ++result_.nonNullReferences;
                if (pair[0] < 0 || pair[0] >= result_.objectSlots || pair[1] <= 0)
                {
                    Reject(sample, "invalid-reference-pair");
                    return;
                }
                const std::pair key{pair[0], pair[1]};
                const auto seen = seenPairs_.find(key);
                if (seen != seenPairs_.end() &&
                    (seen->second.contains(object) || seen->second.size() >= Limits::kMinOwners))
                {
                    ++result_.skipped["duplicate-target-and-serial"];
                    return;
                }
                if (Snapshot(sample))
                {
                    seenPairs_[key].insert(object);
                    samples_.push_back(std::move(sample));
                }
            }

            void Scan()
            {
                constexpr size_t windowSize = ue::ObjectStoreReader::kReadWindowSize;
                const size_t totalWindows = (static_cast<size_t>(result_.objectSlots) + windowSize - 1) / windowSize;
                const size_t windows = std::min(totalWindows, Limits::kMaxWindows);
                std::map<uintptr_t, size_t> ownersPerClass;
                std::array<ue::ObjectReadResult, windowSize> objects{};
                for (size_t step = 0; step < windows; ++step)
                {
                    if (ShouldStop())
                        break;
                    // 首尾交替的均匀窗口覆盖整个对象表，独立于对象分配顺序和游戏类型
                    const size_t bucket = step % 2 == 0 ? windows - 1 - step / 2 : step / 2;
                    const size_t window = windows == 1 ? 0 : bucket * (totalWindows - 1) / (windows - 1);
                    const int32_t first = static_cast<int32_t>(window * windowSize);
                    const size_t count = std::min(windowSize, static_cast<size_t>(result_.objectSlots - first));
                    if (!objects_.Objects().ReadObjects(first, {objects.data(), count}, true))
                        throw std::runtime_error("Object serial scan batch contract failed");
                    for (size_t at = 0; at < count; ++at)
                    {
                        if (ShouldStop())
                            break;
                        ++result_.scannedSlots;
                        const auto &object = objects[at];
                        if (!object.IsValid())
                        {
                            ++result_.skipped["object-slot:" + std::string(ue::ObjectReadStatusName(object.status))];
                            continue;
                        }
                        const auto classAddress = objects_.Class(object.address, true);
                        if (!classAddress)
                        {
                            ++result_.skipped["owner-class-unavailable"];
                            continue;
                        }
                        const auto flags = objects_.Flags(object.address);
                        if (!flags || (*flags & (ue::kRFUnavailableDefinition | ue::kRFClassDefaultObject)) != 0)
                        {
                            ++result_.skipped["owner-not-ready-or-class-default"];
                            continue;
                        }
                        auto &owners = ownersPerClass[*classAddress];
                        if (owners == Limits::kMaxOwnersPerClass)
                        {
                            ++result_.skipped["owner-per-class-budget"];
                            continue;
                        }
                        ++owners;
                        const auto &fields = fields_.Fields(*classAddress);
                        if (fields.empty())
                            ++result_.skipped["owner-without-supported-fields"];
                        for (const auto &field : fields)
                        {
                            if (ShouldStop())
                                break;
                            ReadField(first + static_cast<int32_t>(at), object.address, *classAddress, field);
                        }
                    }
                }
                result_.scanComplete = result_.scannedSlots == static_cast<size_t>(result_.objectSlots);
                if (result_.referenceReads == Limits::kMaxReferenceReads)
                    ++result_.skipped["reference-read-budget"];
                if (samples_.size() == Limits::kMaxTargetSamples)
                    ++result_.skipped["target-sample-budget"];
                if (!result_.scanComplete && windows < totalWindows)
                    ++result_.skipped["object-window-budget"];
                if (static_cast<size_t>(binding_.objects.itemStride) > Limits::kMaxItemBytes)
                    ++result_.skipped["item-prefix-budget"];
            }

            void Score()
            {
                std::set<int32_t> allTargets;
                for (const auto &sample : samples_)
                    allTargets.insert(sample.observation.targetIndex);
                result_.stableTargets = allTargets.size();
                for (auto &candidate : result_.candidates)
                {
                    std::set<int32_t> targets, serials;
                    std::set<uintptr_t> owners;
                    for (const auto &sample : samples_)
                    {
                        const auto &observation = sample.observation;
                        if (std::find(observation.matchingOffsets.begin(), observation.matchingOffsets.end(),
                                      candidate.offset) == observation.matchingOffsets.end())
                            continue;
                        targets.insert(observation.targetIndex);
                        serials.insert(observation.serial);
                        owners.insert(observation.owner);
                    }
                    candidate.targets = targets.size();
                    candidate.distinctSerials = serials.size();
                    candidate.owners = owners.size();
                }
            }

            void Select()
            {
                if (memory_.AddressSpaceGeneration() != generation_)
                {
                    result_.status = "address-space-changed";
                    return;
                }
                std::vector<int32_t> qualified;
                for (const auto &candidate : result_.candidates)
                    if (candidate.targets >= Limits::kMinDiscoveryTargets &&
                        candidate.distinctSerials >= Limits::kMinDiscoveryTargets && candidate.owners >= Limits::kMinOwners)
                        qualified.push_back(candidate.offset);
                if (qualified.size() != 1)
                {
                    result_.status = qualified.empty() ? (result_.nonNullReferences == 0 ? "no-non-null-references"
                                                                                         : "insufficient-correlated-targets")
                                                       : "ambiguous-offsets";
                    return;
                }
                const int32_t selected = qualified.front();
                std::set<int32_t> targets, serials;
                std::set<uintptr_t> owners;
                for (const auto &sample : samples_)
                {
                    const auto &matches = sample.observation.matchingOffsets;
                    if (std::find(matches.begin(), matches.end(), selected) == matches.end() ||
                        (targets.contains(sample.observation.targetIndex) && owners.contains(sample.observation.owner)))
                        continue;
                    auto verified = sample;
                    if (!Snapshot(verified) ||
                        std::find(verified.observation.matchingOffsets.begin(), verified.observation.matchingOffsets.end(),
                                  selected) == verified.observation.matchingOffsets.end())
                    {
                        ++result_.skipped["confirmation-changed-or-unmatched"];
                        continue;
                    }
                    targets.insert(sample.observation.targetIndex);
                    serials.insert(sample.observation.serial);
                    owners.insert(sample.observation.owner);
                }
                result_.validatedTargets = targets.size();
                const auto boundary = objects_.RefreshObjectCount();
                if (memory_.AddressSpaceGeneration() != generation_)
                    result_.status = "address-space-changed";
                else if (!boundary.valid)
                {
                    result_.status = "object-store-changed-or-unreadable";
                    ++result_.skipped["object-boundary:" + boundary.reason];
                }
                else if (targets.size() < Limits::kMinValidatedTargets ||
                         serials.size() < Limits::kMinValidatedTargets || owners.size() < Limits::kMinOwners)
                    result_.status = "insufficient-confirmed-targets";
                else
                {
                    result_.status = "validated";
                    result_.selectedOffset = selected;
                }
            }

            memory::IMemorySource &memory_;
            const binding::RuntimeBinding &binding_;
            uint64_t generation_ = 0;
            memory::CaptureMemorySource capture_;
            ue::ObjectModelReader objects_;
            RuntimeFieldPlanner fields_;
            binding::ObjectSerialEvidence result_;
            std::map<std::pair<int32_t, int32_t>, std::set<uintptr_t>> seenPairs_;
            std::vector<ReferenceSample> samples_;
            std::vector<binding::ObjectSerialSample> rejected_;
        };
    } // namespace

    binding::ObjectSerialEvidence DiscoverObjectSerial(memory::IMemorySource &memory,
                                                       const binding::RuntimeBinding &binding,
                                                       const ue::EngineSchema &schema,
                                                       const ir::ReflectionIR &reflection)
    {
        return Discovery(memory, binding, schema, reflection).Run();
    }
} // namespace nextdumper::reflection
