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
        uintptr_t objectRoot = 0;
        std::optional<::nextdumper::binding::ObjectContainerLayout> objectLayout;
        size_t contractIndex = 0;
        std::string evidence;

        [[nodiscard]] bool IsValid() const;
    };

    [[nodiscard]] std::optional<NameBindingProposal> MakeNameBindingProposal(
        const ::nextdumper::analysis::AnalysisResult &result,
        const ::nextdumper::binding::DecodePlan &baseDecode);
} // namespace nextdumper::app
