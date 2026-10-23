#pragma once

#include <memory>
#include <chrono>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "nextdumper/app/CompatibilityDiagnosis.hpp"
#include "nextdumper/app/MemoryPerformanceLog.hpp"
#include "nextdumper/compat/GameProfile.hpp"
#include "nextdumper/ir/ReflectionIR.hpp"
#include "nextdumper/app/RuntimeContext.hpp"
#include "nextdumper/generation/ArtifactWriter.hpp"

namespace nextdumper::memory
{
    class RemoteMemorySource;
}

namespace nextdumper::app
{
    using ::nextdumper::generation::ArtifactResult;
    using ::nextdumper::ir::ReflectionIR;
    using ::nextdumper::memory::RemoteMemorySource;

    enum class RuntimeLogLevel
    {
        Debug,
        Info,
        Warning,
        Error,
    };

    enum class RuntimeSessionStatus
    {
        Failed,
        BindingReady,
        SchemaReady,
        ReflectionPartial,
        ReflectionReady,
        ArtifactPartial,
    };

    enum class AnalysisMode
    {
        Off,
        Auto,
        Force,
    };

    struct RuntimeSessionConfig
    {
        std::string packageName;
        std::string outputRoot;
        std::vector<std::string> moduleNames = {"libUnreal.so", "libUE4.so"};
        bool enableMemoryLog = false;
        AnalysisMode analysis = AnalysisMode::Off;
    };

    class RuntimeSession
    {
    public:
        explicit RuntimeSession(RuntimeSessionConfig config);

        [[nodiscard]] RuntimeSessionStatus Run();
        [[nodiscard]] const RuntimeContext &Context() const { return context_; }
        [[nodiscard]] const ReflectionIR &Reflection() const { return reflection_; }
        [[nodiscard]] const std::vector<std::string> &Failures() const { return failures_; }
        [[nodiscard]] const ArtifactResult &Artifacts() const { return artifacts_; }
        [[nodiscard]] const CompatibilityDiagnosis &Diagnosis() const { return diagnosis_; }
        [[nodiscard]] std::string LogPath() const;
        [[nodiscard]] std::string MemoryPerformancePath() const;
        [[nodiscard]] std::string DiagnosisPath() const;

    private:
        void Note(std::string message);
        void Note(RuntimeLogLevel level, std::string message);
        void RecordDiagnosis(DiagnosisDomain domain, std::string code, std::string stage,
                             std::string confidence, std::string summary, std::string nextAction);
        [[nodiscard]] const std::string &RunTimestamp() const;
        [[nodiscard]] bool WriteDiagnosisReport() const;
        [[nodiscard]] bool FlushDiagnostics();
        void WriteMemoryStats(std::string_view event, std::string_view stage,
                              std::string_view status = "running") noexcept;
        void BeginMemoryStage(std::string_view stage);
        [[nodiscard]] RuntimeSessionStatus RunImpl();

        RuntimeSessionConfig config_;
        std::shared_ptr<RemoteMemorySource> memory_;
        std::vector<std::unique_ptr<compat::IGameProfile>> profiles_;
        RuntimeContext context_;
        ReflectionIR reflection_;
        ArtifactResult artifacts_;
        CompatibilityDiagnosis diagnosis_;
        generation::ArtifactProvenance provenance_;
        std::vector<std::string> failures_;
        std::chrono::steady_clock::time_point started_{};
        std::ofstream liveLog_;
        MemoryPerformanceLog memoryLog_;
        bool liveLogFailed_ = false;
        std::string memoryStage_;
        mutable std::string runTimestamp_;
        mutable std::string logPath_;
        std::string memoryPerformancePath_;
        mutable std::string diagnosisPath_;
    };
} // namespace nextdumper::app
