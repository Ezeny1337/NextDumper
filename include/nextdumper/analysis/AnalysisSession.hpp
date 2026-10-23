#pragma once

#include "nextdumper/analysis/AnalysisResult.hpp"
#include "nextdumper/analysis/MemoryView.hpp"
#include "nextdumper/module/ModuleImage.hpp"

namespace nextdumper::analysis
{
    class AnalysisSession
    {
    public:
        AnalysisSession(const MemoryView &memory, const module::ModuleImage &module) noexcept;

        [[nodiscard]] AnalysisResult Run() const;

    private:
        const MemoryView &memory_;
        const module::ModuleImage &module_;
    };
} // namespace nextdumper::analysis
