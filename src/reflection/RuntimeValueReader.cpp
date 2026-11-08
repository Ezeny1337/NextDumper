#include "RuntimeValueReader.hpp"
#include "RuntimeReadSupport.hpp"

#include "nextdumper/ue/ContainerReader.hpp"
#include "nextdumper/ue/StorageLayout.hpp"

namespace nextdumper::reflection::detail
{
    RuntimeValueReader::RuntimeValueReader(memory::CaptureMemorySource &capture, ue::ObjectModelReader &objects,
                                           const ue::EngineSchema &schema, const module::ModuleImage &module, const ir::ReflectionIR &reflection)
        : capture_(capture), objects_(objects), schema_(schema), pointerWidth_(module.pointerWidth), module_(module)
    {
        for (const auto &[id, layout] : reflection.valueStorageLayouts)
        {
            if (id.starts_with("inline-delegate-"))
                inlineLayouts_.push_back(layout);
            else if (id.starts_with("weak-object-"))
                weakSizes_.insert(layout.size);
        }
    }

    bool RuntimeValueReader::ReadHeader(ir::ValueObservation &value, int32_t size)
    {
        if (size <= 0 || size > 128)
        {
            value.status = "value-header-size-unsupported";
            return false;
        }
        value.bytes.resize(static_cast<size_t>(size));
        if (!capture_.IsReadable(value.address, value.bytes.size()) ||
            !capture_.ReadBytes(value.address, value.bytes.data(), value.bytes.size()).Ok())
        {
            value.bytes.clear();
            value.status = "value-header-unreadable";
            return false;
        }
        return true;
    }

    ir::DelegateBinding RuntimeValueReader::ReadBinding(uintptr_t address, const std::vector<uint8_t> &bytes,
                                                        int32_t weakOffset, int32_t nameOffset, bool remote) const
    {
        ir::DelegateBinding result;
        result.address = address;
        const auto index = Word(bytes, weakOffset, 4);
        const auto serial = Word(bytes, weakOffset + 4, 4);
        if (!index || !serial)
        {
            result.targetStatus = "weak-pair-unreadable";
            return result;
        }
        const uint32_t indexBits = static_cast<uint32_t>(*index);
        const uint32_t serialBits = static_cast<uint32_t>(*serial);
        std::memcpy(&result.objectIndex, &indexBits, sizeof(result.objectIndex));
        std::memcpy(&result.objectSerial, &serialBits, sizeof(result.objectSerial));
        if (nameOffset >= 0)
        {
            const auto nameAddress = Add(address, static_cast<uint32_t>(nameOffset));
            const auto name = nameAddress ? objects_.Names().ReadFName(*nameAddress) : std::nullopt;
            if (!name)
            {
                result.targetStatus = "function-name-unreadable";
                return result;
            }
            result.functionName = *name;
        }
        if (remote)
            result.targetStatus = "remote-object-resolution-not-performed";
        else if (result.objectSerial == 0 && (result.objectIndex == 0 || result.objectIndex == -1))
            result.targetStatus = "null-weak-pair";
        else if (result.objectIndex < 0 || result.objectIndex >= objects_.Count() || result.objectSerial <= 0)
            result.targetStatus = "invalid-weak-pair";
        else
        {
            const auto target = objects_.Objects().ReadObject(result.objectIndex);
            const auto actualSerial = objects_.Objects().ReadSerialNumber(target);
            const auto actualIndex = target.IsValid() ? objects_.InternalIndex(target.address) : std::nullopt;
            if (!actualSerial)
                result.targetStatus = "object-slot-or-serial-unavailable";
            else if (*actualSerial != result.objectSerial)
                result.targetStatus = "stale-serial";
            else if (!actualIndex || *actualIndex != result.objectIndex)
                result.targetStatus = "target-index-mismatch";
            else
            {
                result.target = target.address;
                // serial 匹配只证明采集时的槽位身份，不等于 GC liveness 或可调用性
                result.targetStatus = "slot-index-and-serial-match-not-liveness";
            }
        }
        return result;
    }

    void RuntimeValueReader::ReadInvocation(ir::ValueObservation &value, const std::vector<ir::StorageLayoutIR> &layouts)
    {
        if (layouts.empty())
        {
            value.status = "multicast-source-layout-unselected";
            return;
        }
        const auto smallest = std::min_element(layouts.begin(), layouts.end(),
                                               [](const auto &left, const auto &right)
                                               { return left.size < right.size; });
        if (!ReadHeader(value, smallest->size))
            return;
        const int32_t offset = Offset(layouts.front(), "InvocationList");
        if (offset < 0 || std::any_of(layouts.begin(), layouts.end(), [&](const auto &layout)
                                      { return Offset(layout, "InvocationList") != offset; }))
        {
            value.status = "invocation-list-offset-candidate-disagreement";
            return;
        }
        const auto invocation = Add(value.address, static_cast<uint32_t>(offset));
        const auto array = HeapStorage(ir::PropertyKind::Array, pointerWidth_);
        if (!invocation || !array)
        {
            value.status = "invocation-list-address-invalid";
            return;
        }
        // 外层原始字节不因元素候选分歧而丢失，header 地址单独标识
        value.addresses["InvocationListHeader"] = *invocation;
        const bool tail = std::all_of(layouts.begin(), layouts.end(), [](const auto &layout)
                                      { return layout.id.starts_with("inline-delegate-tail-checked"); });
        struct Probe
        {
            std::string id;
            int32_t stride;
            int32_t name;
            bool remote;
        };
        std::vector<Probe> probes = {{"unicast-local", 8 + schema_.fname.size + (tail ? 12 : 0), 8, false}};
        if (!tail)
            probes.push_back({"unicast-remote", (16 + schema_.fname.size + 7) / 8 * 8, 16, true});
        // FWeakObjectProperty 的 ElementSize 来自 sizeof(FWeakObjectPtr)，不是空值启发式
        // 没有该证据或证据冲突时保留两个结构族，不能用 Shipping 默认值代替
        if (!tail && weakSizes_.size() == 1)
        {
            const bool remote = *weakSizes_.begin() == 16;
            std::erase_if(probes, [remote](const auto &probe)
                          { return probe.remote != remote; });
            value.numbers["ReflectedWeakStorageSize"] = *weakSizes_.begin();
        }
        size_t accepted = 0;
        for (const auto &probe : probes)
        {
            value.numbers[probe.id + ":stride"] = probe.stride;
            auto list = ue::ReadContainerValue(capture_, *invocation, ir::PropertyKind::Array, *array,
                                               pointerWidth_, probe.stride);
            const bool readable = list.status == "allocated-elements-sampled" || list.status == "empty-header-observed";
            std::vector<ir::DelegateBinding> bindings;
            bool valid = readable;
            for (const auto &element : list.elements)
            {
                auto binding = ReadBinding(element.address, element.bytes, 0, probe.name, probe.remote);
                if (binding.targetStatus == "weak-pair-unreadable" || binding.targetStatus == "invalid-weak-pair" ||
                    binding.targetStatus == "function-name-unreadable" || binding.targetStatus == "target-index-mismatch")
                    valid = false;
                bindings.push_back(std::move(binding));
            }
            value.candidateStatuses[probe.id] = valid ? "source-candidate-observed" : list.status + ":binding-check-failed";
            if (!valid)
                continue;
            ++accepted;
            // 空列表不提供 element stride 证据，保留 header，但不选择 ABI
            if (list.count == 0)
            {
                value.container = std::move(list);
                value.bindingsComplete = true;
                value.status = "empty-invocation-header-observed-element-layout-unselected";
                return;
            }
            if (accepted == 1)
            {
                value.bindings = std::move(bindings);
                value.bindingsComplete = list.indicesComplete;
                value.container = std::move(list);
                value.status = "invocation-bindings-observed-source-candidate";
            }
            else
            {
                value.bindings.clear();
                value.bindingsComplete = false;
                value.container.reset();
                value.status = "delegate-element-layout-candidate-disagreement";
            }
        }
        if (!accepted)
            value.status = "invocation-header-or-elements-unreadable";
    }

    void RuntimeValueReader::ReadValue(ir::ValueObservation &value, const ir::TypeReferenceIR &reference)
    {
        if (reference.containerStorage)
        {
            const int64_t stride = reference.inner
                                       ? int64_t{reference.inner->elementSize} * reference.inner->arrayDim
                                       : 0;
            value.container = ue::ReadContainerValue(capture_, value.address, reference.kind,
                                                     *reference.containerStorage, pointerWidth_, stride > 0 && stride <= INT32_MAX ? static_cast<int32_t>(stride) : 0);
            value.layoutId = reference.containerStorage->layoutId;
            value.status = value.container->status;
            return;
        }
        if (!ReadHeader(value, reference.elementSize))
            return;
        const auto layouts = ue::ValueStorageCandidates(reference, pointerWidth_, schema_.fname.size);
        for (const auto &layout : layouts)
            value.layoutCandidates.push_back(layout.id);
        if (reference.kind == ir::PropertyKind::MulticastDelegate &&
            reference.delegateStorage == ir::DelegateStorageKind::InlineMulticast)
        {
            ReadInvocation(value, layouts);
            return;
        }
        const auto layout = ue::CommonValueStorage(reference, pointerWidth_, schema_.fname.size);
        if (!layout)
        {
            value.status = "value-source-layout-unselected-or-alignment-disagreement";
            return;
        }
        value.layoutId = layout->id;
        if (reference.kind == ir::PropertyKind::Text)
        {
            const auto data = Word(value.bytes, Offset(*layout, "TextData"), pointerWidth_);
            const auto flags = Word(value.bytes, Offset(*layout, "Flags"), 4);
            if (!data || !flags || *data > UINTPTR_MAX)
            {
                value.status = "text-header-offset-unresolved";
                return;
            }
            value.addresses["TextData"] = static_cast<uintptr_t>(*data);
            value.numbers["Flags"] = static_cast<int64_t>(*flags);
            uintptr_t vtable = 0;
            if (*data && capture_.Read(static_cast<uintptr_t>(*data), vtable))
            {
                value.addresses["TextDataVTable"] = vtable;
                value.numbers["VTableInModule"] = module_.Contains(vtable);
                value.status = "text-header-and-vtable-observed-display-cache-unresolved";
            }
            else
                value.status = "text-header-observed-text-data-unreadable";
        }
        else if (reference.delegateStorage == ir::DelegateStorageKind::SparseMulticast)
        {
            const auto bound = Word(value.bytes, Offset(*layout, "Bound"), 1);
            if (!bound || *bound > 1)
                value.status = "invalid-sparse-bound-byte";
            else
            {
                value.numbers["Bound"] = static_cast<int64_t>(*bound);
                value.status = "sparse-bound-byte-observed-bindings-external";
            }
        }
        else
        {
            const int32_t weak = Offset(*layout, "ObjectIndex");
            const int32_t name = Offset(*layout, "FunctionName");
            if (weak < 0 || Offset(*layout, "ObjectSerialNumber") != weak + 4 ||
                (reference.kind == ir::PropertyKind::Delegate && name < 0))
            {
                value.status = "weak-or-delegate-offset-candidate-disagreement";
                return;
            }
            const bool remote = std::any_of(layouts.begin(), layouts.end(), [](const auto &candidate)
                                            { return Offset(candidate, "RemoteObjectId") >= 0; });
            value.bindings.push_back(ReadBinding(value.address, value.bytes, weak, name, remote));
            value.bindingsComplete = true;
            value.status = "weak-or-delegate-fields-observed";
        }
    }

    void RuntimeValueReader::ReadSparse(ir::SparseRootEvidence &root)
    {
        if (!root.address)
            return;
        const auto set = ue::DescribeHeapContainer(ir::PropertyKind::Set, pointerWidth_);
        const auto outer = set ? HeapStorage(ir::PropertyKind::Map, pointerWidth_, pointerWidth_, set->size,
                                             pointerWidth_, pointerWidth_)
                               : std::nullopt;
        const auto inner = HeapStorage(ir::PropertyKind::Map, pointerWidth_, schema_.fname.size,
                                       2 * pointerWidth_, 4, pointerWidth_);
        if (!outer || !inner)
        {
            root.status = "sparse-source-map-layout-unavailable";
            return;
        }
        capture_.Reset();
        {
            memory::CaptureObservationScope observing(capture_);
            root.owners = ue::ReadContainerValue(capture_, root.address, ir::PropertyKind::Map, *outer,
                                                 pointerWidth_, 0, {8, 128});
            root.enumerationComplete = root.owners->elementsComplete;
            for (const auto &owner : root.owners->elements)
            {
                const auto object = Word(owner.bytes, 0, pointerWidth_);
                const auto mapAddress = Add(owner.address, static_cast<uint32_t>(outer->valueOffset));
                if (!object || *object > UINTPTR_MAX || !mapAddress)
                {
                    root.enumerationComplete = false;
                    continue;
                }
                const uintptr_t objectAddress = static_cast<uintptr_t>(*object);
                const auto index = objects_.InternalIndex(objectAddress);
                const auto identity = index ? objects_.Objects().ReadObject(*index) : ue::ObjectReadResult{};
                const auto actualClass = objects_.Class(objectAddress);
                const auto flags = objects_.Flags(objectAddress);
                ir::ValueObservation value;
                value.kind = "SparseOwnerMap";
                value.objectAddress = objectAddress;
                value.classAddress = actualClass.value_or(0);
                value.address = *mapAddress;
                if (!index || !identity.IsValid() || identity.address != objectAddress || !actualClass ||
                    !flags || (*flags & ue::kRFUnavailableDefinition) != 0)
                    value.status = "sparse-owner-identity-invalid";
                else
                {
                    value.container = ue::ReadContainerValue(capture_, *mapAddress, ir::PropertyKind::Map,
                                                             *inner, pointerWidth_, 0, {8, 128});
                    value.status = value.container->status;
                }
                root.enumerationComplete = root.enumerationComplete && value.container && value.container->elementsComplete;
                if (value.container)
                {
                    for (const auto &entry : value.container->elements)
                    {
                        ir::ValueObservation delegate;
                        delegate.kind = "SparseDelegate";
                        delegate.objectAddress = objectAddress;
                        delegate.classAddress = value.classAddress;
                        const auto name = objects_.Names().ReadFName(entry.address);
                        const auto pointer = Word(entry.bytes, inner->valueOffset, pointerWidth_);
                        delegate.path = name.value_or("<unreadable>");
                        delegate.address = pointer && *pointer <= UINTPTR_MAX ? static_cast<uintptr_t>(*pointer) : 0;
                        if (!name || !delegate.address)
                            delegate.status = "sparse-name-or-shared-pointer-unreadable";
                        else
                        {
                            for (const auto &layout : inlineLayouts_)
                                delegate.layoutCandidates.push_back(layout.id);
                            ReadInvocation(delegate, inlineLayouts_);
                        }
                        root.enumerationComplete = root.enumerationComplete && delegate.bindingsComplete;
                        root.delegates.push_back(std::move(delegate));
                    }
                }
                root.delegates.push_back(std::move(value));
            }
        }
        root.capture = Capture(capture_.Validate());
        root.enumerationComplete = root.enumerationComplete && root.capture.observationsStable;
        for (auto &value : root.delegates)
            value.capture = root.capture;
        root.status = root.owners->status == "empty-header-observed"        ? "empty-root-observed"
                      : root.owners->status == "allocated-elements-sampled" ? "bounded-sparse-owner-maps-observed"
                                                                            : root.owners->status;
    }

} // namespace nextdumper::reflection::detail
