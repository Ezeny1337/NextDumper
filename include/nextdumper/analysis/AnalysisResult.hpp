#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "nextdumper/analysis/Contract.hpp"

namespace nextdumper::analysis
{
    enum class AnalysisStatus : uint8_t
    {
        Failed,
        Unsupported,
        Partial,
        Complete,
    };

    enum class DiagnosticSeverity : uint8_t
    {
        Debug,
        Info,
        Warning,
        Error,
    };

    struct Diagnostic
    {
        DiagnosticSeverity Severity = DiagnosticSeverity::Info;
        std::string Code;
        std::string Message;
    };

    struct AnalysisCoverage
    {
        size_t ModuleSegments = 0;
        size_t ExecutableSegments = 0;
        uint64_t PlannedBytes = 0;
        uint64_t ReadBytes = 0;
        uint64_t ReadFailures = 0;
        uint64_t FunctionCount = 0;
        bool Complete = false;
    };

    struct AnalysisResult
    {
        AnalysisStatus Status = AnalysisStatus::Failed;
        std::string Reason;
        std::vector<Contract> Contracts;
        AnalysisCoverage Coverage;
        std::vector<Diagnostic> Diagnostics;
    };

    [[nodiscard]] const char *AnalysisStatusName(AnalysisStatus status);
    [[nodiscard]] const char *DiagnosticSeverityName(DiagnosticSeverity severity);
} // namespace nextdumper::analysis
