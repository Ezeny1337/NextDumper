#pragma once

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "nextdumper/generation/CppTypeResolver.hpp"

namespace nextdumper::generation::detail
{
    using ir::ParseStatus;
    using ir::PropertyIR;

    // 属性和失败节点均为非所有权视图，其生命周期由本次 const ReflectionIR 导出保证
    struct GenerationOwner
    {
        uintptr_t address = 0;
        std::string fullName;
        std::string scope;
        uintptr_t superAddress = 0;
        int32_t size = 0;
        int32_t baseSize = -1;
        int32_t initialCursor = 0;
    };
    struct LayoutEvent
    {
        std::string severity;
        std::string category;
        std::string message;
        uintptr_t ownerAddress = 0;
        const PropertyIR *property = nullptr;
        uintptr_t conflictingAddress = 0;
        std::string conflictingProperty;
        int32_t cursor = 0;
        std::string cursorSource;
        std::string strategy;
        std::optional<size_t> layoutIssueIndex;
    };
    struct OpaqueField
    {
        uintptr_t ownerAddress = 0;
        const PropertyIR *property = nullptr;
        std::string reason;
        std::string failurePath;
        const ::nextdumper::ir::TypeReferenceIR *failureNode = nullptr;
    };
    struct GenerationReport
    {
        size_t opaqueFields = 0;
        size_t omittedFields = 0;
        size_t layoutWarnings = 0;
        size_t layoutEvents = 0;
        std::map<std::string, size_t> opaqueReasons;
        std::map<PropertyStorageKind, size_t> storageKinds;
        std::map<std::pair<std::string, std::string>, size_t> cppRepresentationFailures;
        std::function<void(const std::string &)> diagnostic;
        std::map<uintptr_t, GenerationOwner> owners;
        std::map<std::string, size_t> counts;
        // 非所有权属性视图在 const IR 导出期间保持有效
        std::vector<OpaqueField> opaqueDetails;
        std::vector<LayoutEvent> events;
        FieldDescriptions fields;
        using TypeKey = std::tuple<std::string, std::string, std::string, std::string, PropertyStorageKind, bool>;
        std::map<TypeKey, size_t, std::less<>> typeIds;
        std::set<size_t> loggedTypeIds;
        mutable std::set<uintptr_t> loggedOwners;
        std::map<std::string, size_t> opaqueLogSamples;
        std::map<std::string, size_t> opaqueLogOmitted;
        mutable std::map<std::string, size_t> layoutLogSamples;
        mutable std::map<std::string, size_t> layoutLogOmitted;
        [[nodiscard]] ParseStatus Status() const
        {
            // 有意设计的 Opaque storage 并不是缺失的字段
            return omittedFields == 0 && layoutWarnings == 0 ? ParseStatus::Complete : ParseStatus::Partial;
        }
        void RegisterOwner(GenerationOwner owner);
        void LogOwner(uintptr_t address) const;
        void RecordOpaque(OpaqueField field);
        void Warn(LayoutEvent event)
        {
            event.severity = "error";
            ++layoutEvents;
            ++layoutWarnings;
            Record(event);
            ++counts[event.category];
            events.push_back(std::move(event));
        }
        void Warn(std::string category, std::string message)
        {
            RegisterOwner({0, "<generation>", "generation", 0, 0, -1, 0});
            LayoutEvent event;
            event.category = std::move(category);
            event.message = std::move(message);
            event.strategy = "unchanged-description";
            Warn(std::move(event));
        }
        void Info(LayoutEvent event)
        {
            event.severity = "info";
            ++layoutEvents;
            Record(event);
            ++counts[event.category];
            events.push_back(std::move(event));
        }
        void Record(const LayoutEvent &event) const;
        void LogOmitted() const;
        [[nodiscard]] std::vector<std::string> Summaries() const;
    };
} // namespace nextdumper::generation::detail
