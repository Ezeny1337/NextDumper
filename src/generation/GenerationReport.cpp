#include "GenerationReport.hpp"

#include <iomanip>
#include <sstream>
#include <string_view>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::generation::detail
{
    using ir::PropertyKind;
    using ::nextdumper::common::Hex;

    void GenerationReport::RegisterOwner(GenerationOwner owner)
    {
        const uintptr_t address = owner.address;
        owners.try_emplace(address, std::move(owner));
    }

    void GenerationReport::LogOwner(uintptr_t address) const
    {
        if (!diagnostic || !loggedOwners.insert(address).second)
            return;
        const auto &context = owners.at(address);
        std::ostringstream line;
        line << "sdk_owner address=" << Hex(address) << " full_name=" << std::quoted(context.fullName)
             << " scope=" << context.scope << " size=" << context.size
             << " super=" << Hex(context.superAddress) << " base_size=" << context.baseSize;
        line << " initial_cursor=" << context.initialCursor;
        diagnostic(line.str());
    }

    void GenerationReport::Record(const LayoutEvent &event) const
    {
        if (!diagnostic)
            return;
        if (++layoutLogSamples[event.category] > 8)
        {
            ++layoutLogOmitted[event.category];
            return;
        }
        LogOwner(event.ownerAddress);
        std::ostringstream line;
        line << "sdk_layout_event owner=" << Hex(event.ownerAddress) << " severity=" << event.severity
             << " category=" << event.category << " strategy=" << event.strategy
             << " cursor_source=" << event.cursorSource;
        if (event.property)
        {
            const auto &property = *event.property;
            line << " property=" << Hex(property.address) << " name=" << std::quoted(property.name)
                 << " offset=" << property.offset << " element_size=" << property.elementSize << " array_dim=" << property.arrayDim;
            if (property.type.kind == PropertyKind::Bool)
                line << " bool=" << static_cast<unsigned int>(property.boolean.fieldSize) << '/'
                     << static_cast<unsigned int>(property.boolean.byteOffset) << '/'
                     << static_cast<unsigned int>(property.boolean.byteMask) << '/'
                     << static_cast<unsigned int>(property.boolean.fieldMask);
        }
        if (event.conflictingAddress != 0)
            line << " conflicting=" << Hex(event.conflictingAddress) << " conflicting_name=" << std::quoted(event.conflictingProperty);
        if (event.cursorSource != "layout-analysis")
            line << " cursor=" << event.cursor;
        if (event.severity == "error")
            line << " message=" << std::quoted(event.message);
        diagnostic(line.str());
    }

    void GenerationReport::RecordOpaque(OpaqueField field)
    {
        ++opaqueFields;
        ++opaqueReasons[field.reason];
        const auto &description = fields.at(field.property->address);
        if (field.reason == "no-sized-cpp-representation")
            ++cppRepresentationFailures[{description.type.failureReason, field.property->reflectedClass}];
        const auto *node = &field.property->type;
        std::string_view path = description.type.failurePath;
        field.failurePath = path.empty() ? "type" : "type." + std::string(path);
        for (size_t depth = 0; node && !path.empty() && depth < 32; ++depth)
        {
            const size_t end = path.find('.');
            const auto member = path.substr(0, end);
            node = member == "inner" ? node->inner.get() : member == "key" ? node->key.get()
                                                       : member == "value" ? node->value.get()
                                                                           : nullptr;
            path = end == std::string_view::npos ? std::string_view{} : path.substr(end + 1);
        }
        if (!path.empty())
            node = nullptr;
        field.failureNode = node;
        bool emit = static_cast<bool>(diagnostic);
        if (emit)
        {
            auto &samples = opaqueLogSamples[field.property->reflectedClass + ":" + field.reason];
            if (samples < 8)
                ++samples;
            else
            {
                ++opaqueLogOmitted[field.property->reflectedClass + ":" + field.reason];
                emit = false;
            }
        }
        if (emit)
        {
            LogOwner(field.ownerAddress);
            const auto &property = *field.property;
            if (loggedTypeIds.insert(description.typeId).second)
            {
                std::ostringstream context;
                context << "sdk_generation_type id=" << description.typeId
                        << " semantic_type=" << std::quoted(description.type.semanticName)
                        << " cpp_type=" << std::quoted(description.type.name)
                        << " storage=" << PropertyStorageKindName(description.type.storage)
                        << " semantics_resolved=" << description.type.semanticsResolved
                        << " reason=" << std::quoted(description.type.failureReason)
                        << " reason_path=" << std::quoted(description.type.failurePath);
                diagnostic(context.str());
            }
            std::ostringstream line;
            line << "sdk_opaque owner=" << Hex(field.ownerAddress) << " property=" << Hex(property.address)
                 << " name=" << std::quoted(property.name) << " offset=" << property.offset
                 << " element_size=" << property.elementSize << " type_id=" << description.typeId;
            if (property.arrayDim != 1)
                line << " array_dim=" << property.arrayDim;
            if (field.reason != "internals-not-expanded")
                line << " reason=" << field.reason;
            if (!description.validBounds)
                line << " valid_bounds=0";
            const auto &reason = description.type.failureReason;
            if (!reason.empty() && reason != "internals-not-expanded" && reason != "container-internals-not-expanded")
            {
                line << " failure_path=" << field.failurePath;
                if (node)
                    line << " failure_node=" << Hex(node->metadataAddress)
                         << " failure_class=" << node->reflectedClass << " failure_size=" << node->elementSize;
                else
                    line << " failure_node_available=0";
            }
            diagnostic(line.str());
        }
        opaqueDetails.push_back(std::move(field));
    }

    void GenerationReport::LogOmitted() const
    {
        if (diagnostic)
            for (const auto &[category, count] : layoutLogOmitted)
                diagnostic("sdk_layout_log_omitted category=" + category + " normal_records=" + std::to_string(count) +
                           " samples=8 full_records=diagnostics.json/generation_report-and-reflection.json/layout_analysis");
        if (diagnostic)
            for (const auto &[kind, count] : opaqueLogOmitted)
                diagnostic("sdk_opaque_log_omitted class=" + kind + " normal_records=" + std::to_string(count) +
                           " samples=" + std::to_string(opaqueLogSamples.at(kind)) +
                           " full_records=reflection.json/property.generation-and-diagnostics.json/opaque_fields");
    }

    std::vector<std::string> GenerationReport::Summaries() const
    {
        std::vector<std::string> result;
        for (const auto &[kind, count] : storageKinds)
            result.push_back("SDK storage summary: representation=" + std::string(PropertyStorageKindName(kind)) +
                             " total=" + std::to_string(count));
        for (const auto &[reason, count] : opaqueReasons)
            result.push_back("SDK opaque summary: reason=" + reason + " total=" + std::to_string(count));
        for (const auto &[key, count] : cppRepresentationFailures)
            result.push_back("SDK C++ representation summary: reason=" + key.first +
                             " property_class=" + key.second + " total=" + std::to_string(count));
        for (const auto &[category, count] : counts)
            result.push_back("SDK layout summary: category=" + category +
                             " total=" + std::to_string(count));
        return result;
    }

} // namespace nextdumper::generation::detail
