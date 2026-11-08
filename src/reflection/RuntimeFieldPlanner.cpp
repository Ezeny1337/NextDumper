#include "RuntimeFieldPlanner.hpp"

#include <algorithm>

namespace nextdumper::reflection::detail
{
    using Limits = ir::RuntimeEvidenceLimits;

    const char *RuntimeValueKind(ir::PropertyKind kind)
    {
        switch (kind)
        {
        case ir::PropertyKind::Array:
            return "Array";
        case ir::PropertyKind::Set:
            return "Set";
        case ir::PropertyKind::Map:
            return "Map";
        case ir::PropertyKind::Text:
            return "Text";
        case ir::PropertyKind::WeakObject:
            return "WeakObject";
        case ir::PropertyKind::Delegate:
            return "Delegate";
        case ir::PropertyKind::MulticastDelegate:
            return "MulticastDelegate";
        default:
            return nullptr;
        }
    }

    std::string RuntimeSampleCategory(const ir::TypeReferenceIR &reference)
    {
        const auto *kind = RuntimeValueKind(reference.kind);
        if (!kind)
            return {};
        if (reference.kind != ir::PropertyKind::MulticastDelegate)
            return kind;
        const auto storage = reference.delegateStorage == ir::DelegateStorageKind::InlineMulticast ||
                                     reference.delegateStorage == ir::DelegateStorageKind::SparseMulticast
                                 ? reference.delegateStorage
                                 : ir::DelegateStorageKind::UnknownMulticast;
        return std::string(kind) + ":" + ir::DelegateStorageKindName(storage);
    }

    RuntimeFieldPlanner::RuntimeFieldPlanner(const ir::ReflectionIR &reflection, bool serialReferencesOnly)
        : serialReferencesOnly_(serialReferencesOnly)
    {
        for (const auto &type : reflection.types)
            types_.emplace(type.address, &type);
    }

    const ir::TypeIR *RuntimeFieldPlanner::Type(uintptr_t address) const
    {
        const auto found = types_.find(address);
        return found == types_.end() ? nullptr : found->second;
    }

    const std::vector<RuntimeField> &RuntimeFieldPlanner::Fields(uintptr_t classAddress)
    {
        const auto found = fields_.find(classAddress);
        if (found != fields_.end())
            return found->second;
        auto &fields = fields_[classAddress];
        const auto *type = Type(classAddress);
        if (!type)
            return fields;
        if (cachedFields_ == Limits::kMaxCachedFields)
        {
            ++skipped_["field-plan-cache-budget"];
            return fields;
        }
        const size_t budget = std::min(Limits::kMaxFieldsPerClass, Limits::kMaxCachedFields - cachedFields_);
        size_t remaining = budget;
        std::set<uintptr_t> path;
        Collect(*type, 0, type->name, 0, remaining, path, fields);
        cachedFields_ += fields.size();
        if (!remaining)
            ++skipped_["class-field-expansion-budget"];
        return fields;
    }

    void RuntimeFieldPlanner::Collect(const ir::TypeIR &type, uint64_t base, const std::string &prefix, size_t depth,
                                      size_t &remaining, std::set<uintptr_t> &path, std::vector<RuntimeField> &out)
    {
        if (!remaining)
            return;
        if (depth >= Limits::kMaxDepth || !path.insert(type.address).second)
        {
            ++skipped_["field-plan-cycle-or-depth-limit"];
            return;
        }
        if (type.size > 0)
        {
            for (const auto &property : type.properties)
            {
                if (!remaining)
                    break;
                const auto kind = property.type.kind;
                const bool value = serialReferencesOnly_
                                       ? kind == ir::PropertyKind::WeakObject || kind == ir::PropertyKind::LazyObject ||
                                             kind == ir::PropertyKind::SoftObject || kind == ir::PropertyKind::SoftClass ||
                                             kind == ir::PropertyKind::Delegate
                                       : RuntimeValueKind(kind) != nullptr;
                if (!value && property.type.kind != ir::PropertyKind::Struct)
                    continue;
                // 同一基类字段被多个派生类复用时只计一次，primitive 字段不消耗实例证据预算
                if (!visitedProperties_.contains(property.address))
                {
                    if (visitedProperties_.size() == Limits::kMaxUniqueFieldNodes)
                    {
                        ++skipped_["unique-field-node-budget"];
                        continue;
                    }
                    visitedProperties_.insert(property.address);
                }
                --remaining;
                const uint64_t extent = property.elementSize > 0 && property.arrayDim > 0
                                            ? uint64_t{static_cast<uint32_t>(property.elementSize)} *
                                                  static_cast<uint32_t>(property.arrayDim)
                                            : 0;
                if (!extent || property.offset < 0 || static_cast<uint64_t>(property.offset) > static_cast<uint64_t>(type.size) ||
                    extent > static_cast<uint64_t>(type.size) - static_cast<uint32_t>(property.offset) ||
                    property.status != ir::ParseStatus::Complete || !property.type.nodeDetailsResolved)
                    continue;
                const size_t elements = std::min<size_t>(property.arrayDim, Limits::kMaxStaticElements);
                for (size_t element = 0; element < elements; ++element)
                {
                    if (base > UINT64_MAX - extent - static_cast<uint32_t>(property.offset))
                    {
                        ++skipped_["field-plan-offset-overflow"];
                        break;
                    }
                    const uint64_t offset = base + static_cast<uint32_t>(property.offset) +
                                            element * static_cast<uint32_t>(property.elementSize);
                    const std::string name = prefix + "." + property.name +
                                             (property.arrayDim > 1 ? "[" + std::to_string(element) + "]" : "");
                    if (value)
                    {
                        if (out.size() == Limits::kMaxFieldsPerClass ||
                            out.size() == Limits::kMaxCachedFields - cachedFields_)
                        {
                            ++skipped_["field-plan-output-budget"];
                            remaining = 0;
                            break;
                        }
                        out.push_back({&property, type.address, offset, name});
                    }
                    else
                    {
                        const auto *child = Type(property.type.referencedObject);
                        if (child && child->size == property.elementSize)
                            Collect(*child, offset, name, depth + 1, remaining, path, out);
                    }
                }
            }
        }
        const auto *super = Type(type.superAddress);
        if (super && super->size <= type.size)
            Collect(*super, base, prefix, depth + 1, remaining, path, out);
        path.erase(type.address);
    }
} // namespace nextdumper::reflection::detail
