#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "nextdumper/analysis/AnalysisResult.hpp"
#include "nextdumper/binding/RuntimeBinding.hpp"

namespace nextdumper::app
{
    struct NameBindingProposal
    {
        uintptr_t root = 0;
        ::nextdumper::binding::NameContainerLayout layout;
        ::nextdumper::binding::DecodePlan decode;
        bool fullBlockBound = false;
        size_t contractIndex = 0;
        std::string evidence;

        [[nodiscard]] bool IsValid() const;
    };

    struct ObjectBindingProposal
    {
        uintptr_t root = 0;
        ::nextdumper::binding::ObjectContainerLayout layout;
        size_t contractIndex = 0;
        std::string evidence;

        [[nodiscard]] bool IsValid() const;
    };

    struct UObjectBindingProposal
    {
        uintptr_t objectRoot = 0;
        ::nextdumper::binding::UObjectLayoutHint layout;
        std::string evidence;

        [[nodiscard]] bool IsValid() const;
    };

    [[nodiscard]] std::optional<NameBindingProposal> MakeNameBindingProposal(
        const ::nextdumper::analysis::AnalysisResult &result,
        const ::nextdumper::binding::DecodePlan &baseDecode);
    [[nodiscard]] std::optional<ObjectBindingProposal> MakeObjectBindingProposal(
        const ::nextdumper::analysis::AnalysisResult &result);
    [[nodiscard]] std::optional<UObjectBindingProposal> MakeUObjectBindingProposal(
        const ::nextdumper::analysis::AnalysisResult &result,
        uintptr_t objectRoot);
} // namespace nextdumper::app
