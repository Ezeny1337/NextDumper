#pragma once

#include <cstdint>
#include <vector>

#include "nextdumper/analysis/AnalysisResult.hpp"
#include "nextdumper/analysis/MemoryView.hpp"
#include "nextdumper/module/ModuleImage.hpp"

namespace nextdumper::analysis
{
    struct AnalysisSessionOptions
    {
        std::vector<uintptr_t> NameRootHints;
    };

    class AnalysisSession
    {
    public:
        AnalysisSession(const MemoryView &memory, const module::ModuleImage &module,
                        AnalysisSessionOptions options = {}) noexcept;

        [[nodiscard]] AnalysisResult Run() const;

    private:
        const MemoryView &memory_;
        const module::ModuleImage &module_;
        AnalysisSessionOptions options_;
    };
} // namespace nextdumper::analysis
