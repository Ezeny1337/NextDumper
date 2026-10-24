#include "nextdumper/app/RuntimeSession.hpp"
#include "nextdumper/BuildInfo.hpp"

#include "nextdumper/memory/ProcessInfo.hpp"

#include <filesystem>
#include <fstream>
#include <exception>
#include <new>
#include <span>
#include <sstream>
#include <utility>
#include <vector>
#include <ctime>

#include "nextdumper/analysis/AnalysisSession.hpp"
#include "nextdumper/analysis/MemoryView.hpp"
#include "nextdumper/binding/CommonObjectCollector.hpp"
#include "nextdumper/binding/BindingBuilder.hpp"
#include "nextdumper/binding/GlobalLocator.hpp"
#include "nextdumper/common/Hex.hpp"
#include "nextdumper/compat/GameProfile.hpp"
#include "nextdumper/memory/ReadDiagnostics.hpp"
#include "nextdumper/memory/RemoteMemorySource.hpp"
#include "nextdumper/module/ModuleCatalog.hpp"
#include "nextdumper/module/ElfSymbols.hpp"
#include "nextdumper/reflection/ReflectionReader.hpp"
#include "nextdumper/reflection/RuntimeInspector.hpp"
#include "nextdumper/ue/SchemaCatalog.hpp"
#include "nextdumper/ue/SchemaResolver.hpp"

namespace nextdumper::app
{
    using ::nextdumper::binding::AddressMeaning;
    using ::nextdumper::binding::BindingBuilder;
    using ::nextdumper::binding::BindingCandidates;
    using ::nextdumper::binding::GlobalLocator;
    using ::nextdumper::binding::LocatedAddress;
    using ::nextdumper::binding::RuntimeBinding;
    using ::nextdumper::generation::ArtifactWriter;
    using ::nextdumper::ir::ParseStatus;
    using ::nextdumper::memory::ReadStats;
    using ::nextdumper::module::ModuleCatalog;
    using ::nextdumper::reflection::ReflectionReader;
    using ::nextdumper::ue::EngineProfile;
    using ::nextdumper::ue::EngineSchema;
    using ::nextdumper::ue::SchemaCandidateSummary;
    using ::nextdumper::ue::SchemaCatalog;
    using ::nextdumper::ue::SchemaLayoutVariantName;
    using ::nextdumper::ue::SchemaResolutionReport;
    using ::nextdumper::ue::SchemaResolver;
    using ::nextdumper::ue::SchemaSelectionResult;

    namespace
    {
        using ::nextdumper::common::Hex;

        const char *AddressMeaningName(AddressMeaning meaning)
        {
            switch (meaning)
            {
            case AddressMeaning::Direct:
                return "direct";
            case AddressMeaning::PointerSlot:
                return "pointer-slot";
            case AddressMeaning::ResolvedValue:
                return "resolved-value";
            }
            return "unknown";
        }

        const char *LevelName(RuntimeLogLevel level)
        {
            switch (level)
            {
            case RuntimeLogLevel::Debug:
                return "DEBUG";
            case RuntimeLogLevel::Info:
                return "INFO";
            case RuntimeLogLevel::Warning:
                return "WARN";
            case RuntimeLogLevel::Error:
                return "ERROR";
            }
            return "INFO";
        }

        const char *SessionStatusName(RuntimeSessionStatus status)
        {
            switch (status)
            {
            case RuntimeSessionStatus::Failed:
                return "failed";
            case RuntimeSessionStatus::BindingReady:
                return "binding-ready";
            case RuntimeSessionStatus::SchemaReady:
                return "schema-ready";
            case RuntimeSessionStatus::ReflectionPartial:
                return "reflection-partial";
            case RuntimeSessionStatus::ReflectionReady:
                return "reflection-ready";
            case RuntimeSessionStatus::ArtifactPartial:
                return "artifact-partial";
            }
            return "failed";
        }

        const char *AnalysisModeName(AnalysisMode mode)
        {
            switch (mode)
            {
            case AnalysisMode::Off:
                return "off";
            case AnalysisMode::Auto:
                return "auto";
            case AnalysisMode::Force:
                return "force";
            }
            return "unknown";
        }

        class AnalysisMemoryView final : public ::nextdumper::analysis::MemoryView
        {
        public:
            explicit AnalysisMemoryView(const memory::IMemorySource &source) : source_(source) {}

            [[nodiscard]] bool IsInitialized() const override { return source_.IsInitialized(); }
            [[nodiscard]] bool IsReadable(uintptr_t address, size_t size) const override
            {
                return source_.IsReadable(address, size);
            }
            [[nodiscard]] bool IsExecutable(uintptr_t address, size_t size) const override
            {
                return source_.IsExecutable(address, size);
            }
            [[nodiscard]] memory::ReadResult ReadBytes(uintptr_t address, void *buffer, size_t size) const override
            {
                return source_.ReadBytes(address, buffer, size);
            }
            [[nodiscard]] std::span<const memory::MemoryRegion> Regions() const override
            {
                return source_.Regions();
            }
            [[nodiscard]] uint64_t AddressSpaceGeneration() const override
            {
                return source_.AddressSpaceGeneration();
            }

        private:
            const memory::IMemorySource &source_;
        };

        struct ProfileExecutionState
        {
            bool failed = false;
            std::string stage;
            std::string error;
        };

        // 将 profile 回调异常转为受控失败，避免被误记为普通内存读取失败。
        template <typename Decoder, typename Result>
        Decoder GuardProfileDecoder(Decoder decoder, Result fallback,
                                    const std::shared_ptr<ProfileExecutionState> &state)
        {
            if (!decoder)
                return decoder;
            return Decoder([decoder = std::move(decoder), fallback, state](auto... arguments) mutable -> Result
                           {
                              if (state->failed)
                                  return fallback;
                              try
                              {
                                  return decoder(arguments...);
                              }
                              catch (const std::exception &error)
                              {
                                  state->failed = true;
                                  state->error = error.what();
                              }
                              catch (...)
                              {
                                  state->failed = true;
                                  state->error = "unknown decoder exception";
                              }
                              return fallback; });
        }

        void GuardProfileDecoders(::nextdumper::binding::DecodePlan &decode,
                                  const std::shared_ptr<ProfileExecutionState> &state)
        {
            decode.objectStorage = GuardProfileDecoder(std::move(decode.objectStorage), uintptr_t{0}, state);
            decode.objectChunk = GuardProfileDecoder(std::move(decode.objectChunk), uintptr_t{0}, state);
            decode.objectPointer = GuardProfileDecoder(std::move(decode.objectPointer), uintptr_t{0}, state);
            decode.objectClass = GuardProfileDecoder(std::move(decode.objectClass), uintptr_t{0}, state);
            decode.objectOuter = GuardProfileDecoder(std::move(decode.objectOuter), uintptr_t{0}, state);
            decode.nameBlocks = GuardProfileDecoder(std::move(decode.nameBlocks), uintptr_t{0}, state);
            decode.nameChunks = GuardProfileDecoder(std::move(decode.nameChunks), uintptr_t{0}, state);
            decode.nameEntry = GuardProfileDecoder(std::move(decode.nameEntry), uintptr_t{0}, state);
            decode.objectCount = GuardProfileDecoder(std::move(decode.objectCount), int32_t{-1}, state);
            decode.objectFlags = GuardProfileDecoder(std::move(decode.objectFlags), int32_t{0}, state);
            decode.objectIndex = GuardProfileDecoder(std::move(decode.objectIndex), int32_t{-1}, state);
            decode.nameIndex = GuardProfileDecoder(std::move(decode.nameIndex), int32_t{-1}, state);
            decode.nameNumber = GuardProfileDecoder(std::move(decode.nameNumber), uint32_t{0}, state);
            decode.nameEntryIndex = GuardProfileDecoder(std::move(decode.nameEntryIndex), uint32_t{0}, state);
            decode.nameHeader = GuardProfileDecoder(std::move(decode.nameHeader), uint16_t{0}, state);
            decode.nameText = GuardProfileDecoder(std::move(decode.nameText), false, state);
        }

        std::string LogTimestamp()
        {
            const std::time_t now = std::time(nullptr);
            const std::tm *local = std::localtime(&now);
            if (local == nullptr)
                return {};
            char buffer[32];
            if (std::strftime(buffer, sizeof(buffer), "%Y%m%d%H%M%S", local) == 0)
                return {};
            return buffer;
        }

    } // namespace

    RuntimeSession::RuntimeSession(RuntimeSessionConfig config) : config_(std::move(config))
    {
        memory_ = std::make_shared<RemoteMemorySource>();
        context_ = RuntimeContext(memory_);
    }

    const std::string &RuntimeSession::RunTimestamp() const
    {
        if (runTimestamp_.empty())
            runTimestamp_ = LogTimestamp();
        return runTimestamp_;
    }

    std::string RuntimeSession::LogPath() const
    {
        if (config_.outputRoot.empty())
            return {};
        if (logPath_.empty())
        {
            const std::string suffix = RunTimestamp();
            const std::string fileName = "NextDumper" + (suffix.empty() ? std::string{} : "_" + suffix) + ".log";
            logPath_ = (std::filesystem::path(config_.outputRoot) / fileName).string();
        }
        return logPath_;
    }

    std::string RuntimeSession::MemoryPerformancePath() const
    {
        return memoryPerformancePath_;
    }

    void RuntimeSession::WriteMemoryStats(std::string_view event, std::string_view stage,
                                          std::string_view status) noexcept
    {
        if (config_.enableMemoryLog && memory_)
            memoryLog_.Write(event, stage, *memory_, module::ModuleArchitectureName(context_.Module().architecture), status);
    }

    void RuntimeSession::BeginMemoryStage(std::string_view stage)
    {
        if (memoryStage_ != stage)
        {
            if (!memoryStage_.empty())
                WriteMemoryStats("stage_end", memoryStage_);
            memory_->ClearReadCache();
            memoryStage_ = stage;
            WriteMemoryStats("stage_start", memoryStage_);
        }
    }

    std::string RuntimeSession::DiagnosisPath() const
    {
        if (config_.outputRoot.empty())
            return {};
        if (diagnosisPath_.empty())
        {
            std::filesystem::path path(LogPath());
            path.replace_extension(".diagnosis.json");
            diagnosisPath_ = path.string();
        }
        return diagnosisPath_;
    }

    bool RuntimeSession::WriteDiagnosisReport() const
    {
        auto *performance = memory_->Performance();
        memory::ScopedReadTiming timing(performance ? &performance->diagnosisOutput : nullptr, 1);
        const std::string path = DiagnosisPath();
        if (path.empty())
            return true;
        std::ofstream report(path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!report.is_open())
            return false;
        report << diagnosis_.ToJson();
        report.flush();
        const bool written = report.good();
        report.close();
        return written && !report.fail();
    }

    void RuntimeSession::RecordDiagnosis(DiagnosisDomain domain, std::string code, std::string stage,
                                         std::string confidence, std::string summary, std::string nextAction)
    {
        diagnosis_.stage = stage;
        diagnosis_.Add({domain, code, stage, confidence, summary, nextAction});
        const RuntimeLogLevel level = domain == DiagnosisDomain::Runtime ? RuntimeLogLevel::Error : RuntimeLogLevel::Warning;
        Note(level, "diagnosis domain=" + std::string(DiagnosisDomainName(domain)) +
                        " code=" + code + " stage=" + stage + " confidence=" + confidence +
                        " summary=" + summary + " next_action=" + nextAction);
    }

    void RuntimeSession::Note(std::string message)
    {
        Note(RuntimeLogLevel::Info, std::move(message));
    }

    void RuntimeSession::Note(RuntimeLogLevel level, std::string message)
    {
        WriteMemoryStats("snapshot", memoryStage_);
        auto *performance = memory_->Performance();
        memory::ScopedReadTiming formatTiming(performance ? &performance->runtimeLogFormat : nullptr, 1);
        // 将目标元数据保持在单个物理日志行中，且不隐藏控制字节
        std::string escaped;
        escaped.reserve(message.size());
        static constexpr char hex[] = "0123456789ABCDEF";
        for (const unsigned char ch : message)
        {
            if (ch < 0x20 || ch == 0x7f)
            {
                escaped += "\\x";
                escaped += hex[ch >> 4];
                escaped += hex[ch & 15];
            }
            else
                escaped += static_cast<char>(ch);
        }
        message = std::move(escaped);
        const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started_).count();
        message = "[" + std::to_string(elapsedMs) + "] " + message;
        formatTiming.Stop();
        if (liveLog_.is_open())
        {
            memory::ScopedReadTiming writeTiming(performance ? &performance->runtimeLogWrite : nullptr, 1);
            liveLog_ << '[' << LevelName(level) << "] " << message << '\n';
            writeTiming.Stop();
            if (level != RuntimeLogLevel::Debug)
            {
                memory::ScopedReadTiming flushTiming(performance ? &performance->runtimeLogFlush : nullptr, 1);
                liveLog_.flush();
            }
            if (!liveLog_.good())
                liveLogFailed_ = true;
        }

        // 非 debug 消息立即输出到控制台
        if (level != RuntimeLogLevel::Debug)
        {
            memory::ScopedReadTiming consoleTiming(performance ? &performance->consoleOutput : nullptr, 1);
            std::printf("[%s] %s\n", LevelName(level), message.c_str());
            std::fflush(stdout);
        }
    }

    bool RuntimeSession::FlushDiagnostics()
    {
        if (config_.outputRoot.empty())
            return true;
        if (liveLog_.is_open())
        {
            auto *performance = memory_->Performance();
            memory::ScopedReadTiming flushTiming(performance ? &performance->runtimeLogFlush : nullptr, 1);
            liveLog_.flush();
            flushTiming.Stop();
            memory::ScopedReadTiming closeTiming(performance ? &performance->runtimeLogClose : nullptr, 1);
            liveLog_.close();
            liveLogFailed_ = liveLogFailed_ || liveLog_.fail();
        }
        else
            liveLogFailed_ = true;
        return !liveLogFailed_;
    }

    RuntimeSessionStatus RuntimeSession::Run()
    {
        RuntimeSessionStatus status = RuntimeSessionStatus::Failed;
        try
        {
            status = RunImpl();
        }
        catch (const std::bad_alloc &)
        {
            std::fprintf(stderr, "Runtime session failed: memory allocation failed\n");
            try
            {
                RecordDiagnosis(DiagnosisDomain::Runtime, "MEMORY_ALLOCATION_FAILED", diagnosis_.stage,
                                "observed", "The runtime session could not allocate required memory.",
                                "Reduce concurrent load and retry; do not change the game profile based on this failure.");
            }
            catch (...)
            {
            }
        }
        catch (const std::exception &error)
        {
            std::fprintf(stderr, "Runtime session exception: %s\n", error.what());
            try
            {
                failures_.push_back(error.what());
                RecordDiagnosis(DiagnosisDomain::Runtime, "RUNTIME_SESSION_EXCEPTION", diagnosis_.stage,
                                "observed", error.what(), "Inspect the failing runtime stage and its preceding diagnostics.");
                Note(RuntimeLogLevel::Error, std::string("Runtime session exception: ") + error.what());
            }
            catch (...)
            {
                std::fprintf(stderr, "Exception details could not be stored\n");
            }
        }
        catch (...)
        {
            std::fprintf(stderr, "Runtime session failed: unknown exception\n");
            try
            {
                RecordDiagnosis(DiagnosisDomain::Runtime, "UNKNOWN_RUNTIME_EXCEPTION", diagnosis_.stage,
                                "observed", "An unknown exception stopped the runtime session.",
                                "Inspect the last completed stage and reproduce with debug logging.");
            }
            catch (...)
            {
            }
        }
        try
        {
            Note(RuntimeLogLevel::Info, "compatibility_diagnosis status=" +
                                            std::string(CompatibilityStatusName(diagnosis_.status)) +
                                            " profile=" + diagnosis_.profileId +
                                            " profile_status=" + diagnosis_.profileStatus +
                                            " stage=" + diagnosis_.stage);
        }
        catch (...)
        {
            std::fprintf(stderr, "Runtime summary could not be serialized\n");
            status = RuntimeSessionStatus::Failed;
        }
        const auto reportOutputFailure = [&](const char *code, const char *summary)
        {
            status = RuntimeSessionStatus::Failed;
            std::fprintf(stderr, "%s\n", summary);
            try
            {
                RecordDiagnosis(DiagnosisDomain::Runtime, code, "diagnostics",
                                "observed", summary, "Check output permissions and free space; generated artifacts are preserved.");
            }
            catch (...)
            {
                std::fprintf(stderr, "Output failure details could not be stored: %s\n", code);
            }
        };
        try
        {
            if (!FlushDiagnostics())
                reportOutputFailure("RUNTIME_LOG_WRITE_FAILED", "Runtime log write or close failed");
        }
        catch (...)
        {
            reportOutputFailure("RUNTIME_LOG_FLUSH_EXCEPTION", "Runtime log could not be flushed");
        }
        if (config_.enableMemoryLog && memoryLog_.Failed())
            reportOutputFailure("MEMORY_LOG_WRITE_FAILED", "Memory performance log could not be fully written");
        try
        {
            diagnosis_.sessionStatus = SessionStatusName(status);
            if (!WriteDiagnosisReport())
            {
                std::fprintf(stderr, "Compatibility diagnosis report could not be written\n");
                status = RuntimeSessionStatus::Failed;
                diagnosis_.sessionStatus = SessionStatusName(status);
            }
        }
        catch (...)
        {
            std::fprintf(stderr, "Compatibility diagnosis report could not be serialized\n");
            status = RuntimeSessionStatus::Failed;
        }
        if (!memoryStage_.empty())
            WriteMemoryStats("stage_end", memoryStage_, SessionStatusName(status));
        WriteMemoryStats("session_end", diagnosis_.stage, SessionStatusName(status));
        if (config_.enableMemoryLog && !memoryLog_.Close())
        {
            reportOutputFailure("MEMORY_LOG_CLOSE_FAILED", "Memory performance log write or close failed");
            try
            {
                diagnosis_.sessionStatus = SessionStatusName(status);
                if (!WriteDiagnosisReport())
                    std::fprintf(stderr, "Final compatibility diagnosis report could not be written\n");
            }
            catch (...)
            {
                std::fprintf(stderr, "Final compatibility diagnosis report could not be serialized\n");
            }
        }
        return status;
    }

    RuntimeSessionStatus RuntimeSession::RunImpl()
    {
        failures_.clear();
        reflection_ = {};
        artifacts_ = {};
        diagnosis_ = {};
        diagnosis_.packageName = config_.packageName;
        provenance_ = {};
        provenance_.producerCommit = kProducerCommit;
        provenance_.producerVersion = kProducerVersion;
        provenance_.producerWorktree = kProducerWorktreeAtConfigure;
        provenance_.runId = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count()) +
                            "-" +
                            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        context_ = RuntimeContext(memory_);
        profiles_.clear();
        started_ = std::chrono::steady_clock::now();
        liveLogFailed_ = false;
        memory_->Reset();
        memory_->EnablePerformance(config_.enableMemoryLog);
        memoryStage_.clear();
        liveLog_.clear();
        logPath_.clear();
        memoryPerformancePath_.clear();
        diagnosisPath_.clear();
        runTimestamp_.clear();
        provenance_.runTimestamp = RunTimestamp();
        if (!config_.outputRoot.empty())
        {
            std::error_code error;
            std::filesystem::create_directories(config_.outputRoot, error);
            if (!error)
                liveLog_.open(LogPath(), std::ios::out | std::ios::trunc);
            liveLogFailed_ = error || !liveLog_.is_open();
            if (liveLogFailed_)
            {
                failures_.push_back("Runtime log open failed" + (error ? ": " + error.message() : std::string{}));
                RecordDiagnosis(DiagnosisDomain::Runtime, "RUNTIME_LOG_OPEN_FAILED", "output",
                                "observed", failures_.back(), "Verify the output directory exists and is writable.");
                return RuntimeSessionStatus::Failed;
            }
            if (config_.enableMemoryLog)
            {
                memoryPerformancePath_ = (std::filesystem::path(config_.outputRoot) /
                                          ("NextDumper_" + provenance_.runTimestamp + "_" + provenance_.runId + ".memory.jsonl"))
                                             .string();
                if (!memoryLog_.Open(memoryPerformancePath_, provenance_, started_))
                {
                    failures_.push_back("Memory performance log open failed: errno=" + std::to_string(memoryLog_.LastError()));
                    RecordDiagnosis(DiagnosisDomain::Runtime, "MEMORY_LOG_OPEN_FAILED", "output",
                                    "observed", failures_.back(), "Verify the output directory exists and is writable.");
                    return RuntimeSessionStatus::Failed;
                }
                WriteMemoryStats("session_start", "output");
            }
        }
        const auto progress = [&](const std::string &message)
        { Note(message); };
        auto stageStart = std::chrono::steady_clock::now();
        auto stageStats = memory_->Stats();
        const auto finishStage = [&](const char *stage)
        {
            const auto now = std::chrono::steady_clock::now();
            const auto stats = memory_->Stats();
            Note("stage=" + std::string(stage) + " elapsed_ms=" +
                 std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now - stageStart).count()) +
                 ::nextdumper::memory::DescribeReadStats(stats, stageStats));
            WriteMemoryStats("checkpoint", stage);
            stageStart = now;
            stageStats = stats;
        };
        Note("=== Runtime Session Started ===");
        Note(RuntimeLogLevel::Debug, "run_provenance producer_commit=" + provenance_.producerCommit +
                                         " producer_version=" + provenance_.producerVersion +
                                         " producer_worktree_at_configure=" + provenance_.producerWorktree +
                                         " identity_source=cmake-configure run_id=" + provenance_.runId +
                                         " run_timestamp=" + provenance_.runTimestamp);
        Note(RuntimeLogLevel::Debug, "diagnostic_encoding=6 owner_contexts=referenced-only exec_entries=bounded-normal-samples-and-all-anomalies opaque_fields=bounded-normal-samples-and-all-gaps opaque_normal_samples_per_class=8 generation_types=shared-context full_records=reflection.json-and-diagnostics.json array_dim_default=1 opaque_reason_default=internals-not-expanded valid_bounds_default=1 container_metadata=all-visited-nodes raw_container_evidence=bounded-samples container_normal_log_samples_per_class=8 optional_runtime_values=independent-bounded-capture layout_info_samples_per_category=8");
        Note("Package=" + config_.packageName + " PID=auto UE=auto");

        diagnosis_.stage = "process-discovery";
        BeginMemoryStage("process-discovery");
        const int pid = memory::ProcessInfo::Find(config_.packageName);
        if (pid <= 0)
        {
            failures_.push_back("target process was not found");
            RecordDiagnosis(DiagnosisDomain::Runtime, "TARGET_PROCESS_NOT_FOUND", "process-discovery",
                            "observed", failures_.back(),
                            "Start the target game and confirm its package name before investigating compatibility.");
            return RuntimeSessionStatus::Failed;
        }
        Note(RuntimeLogLevel::Debug, "Target PID=" + std::to_string(pid));
        provenance_.targetPid = pid;
        diagnosis_.stage = "memory-attach";
        BeginMemoryStage("memory-attach");
        const bool attached = memory_->Initialize(static_cast<pid_t>(pid));
        WriteMemoryStats("backend_init", "memory-attach", attached ? "ready" : "failed");
        if (!attached)
        {
            failures_.push_back("remote memory source initialization failed");
            RecordDiagnosis(DiagnosisDomain::Runtime, "REMOTE_MEMORY_INIT_FAILED", "memory-attach",
                            "observed", failures_.back(),
                            "Check target process access permissions and the memory backend before investigating game layouts.");
            return RuntimeSessionStatus::Failed;
        }
        stageStats = memory_->Stats();

        diagnosis_.stage = "module-discovery";
        BeginMemoryStage("module-discovery");
        module::ModuleImage module;
        if (!ModuleCatalog::Discover(*memory_, config_.moduleNames, module))
        {
            failures_.push_back("Unreal module was not found");
            RecordDiagnosis(DiagnosisDomain::Runtime, "UNREAL_MODULE_NOT_FOUND", "module-discovery",
                            "observed", failures_.back(),
                            "Inspect the target mappings and module name; compatibility has not yet been evaluated.");
            return RuntimeSessionStatus::Failed;
        }
        context_.SetModule(std::move(module));
        diagnosis_.moduleName = context_.Module().name;
        diagnosis_.architecture = module::ModuleArchitectureName(context_.Module().architecture);
        diagnosis_.pointerWidth = context_.Module().pointerWidth;
        Note("Module=" + context_.Module().name + " base=" + Hex(context_.Module().base) +
             " architecture=" + module::ModuleArchitectureName(context_.Module().architecture) +
             " pointer_width=" + std::to_string(context_.Module().pointerWidth));
        Note(RuntimeLogLevel::Debug, "module_identity run_id=" + provenance_.runId +
                                         " pid=" + std::to_string(pid) +
                                         " base=" + Hex(context_.Module().base) +
                                         " end=" + Hex(context_.Module().end) +
                                         " address_space_generation=" + std::to_string(memory_->AddressSpaceGeneration()) +
                                         " identity=mapped-segments-not-content-hash");
        for (const auto &segment : context_.Module().segments)
            Note(RuntimeLogLevel::Debug, "module_segment start=" + Hex(segment.start) +
                                             " end=" + Hex(segment.end) + " file_offset=" + Hex(segment.fileOffset) +
                                             " readable=" + std::to_string(segment.readable) +
                                             " writable=" + std::to_string(segment.writable) +
                                             " executable=" + std::to_string(segment.executable) +
                                             " private=" + std::to_string(segment.privateMapping) + " path=" + segment.path);

        finishStage("module-discovery");
        profiles_ = ::nextdumper::compat::CreateGameProfiles();
        std::vector<compat::IGameProfile *> matchingProfiles;
        bool profileMatcherFailed = false;
        diagnosis_.stage = "profile-selection";
        BeginMemoryStage("profile-selection");
        for (const auto &profile : profiles_)
        {
            if (!profile || profile->Id().empty())
            {
                RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_ID_INVALID", "profile-selection",
                                "observed", "A compiled game profile has an empty identifier.",
                                "Give each compiled profile a stable, non-empty Id().");
                continue;
            }
            try
            {
                if (profile->Matches(config_.packageName, context_.Module()))
                    matchingProfiles.push_back(profile.get());
            }
            catch (const std::exception &error)
            {
                profileMatcherFailed = true;
                RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_MATCH_EXCEPTION", "profile-selection",
                                "observed", std::string("Profile matching threw an exception: ") + error.what(),
                                "Fix the profile matcher; no profile will be selected unless all matchers complete.");
            }
            catch (...)
            {
                profileMatcherFailed = true;
                RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_MATCH_EXCEPTION", "profile-selection",
                                "observed", "Profile matching threw an unknown exception.",
                                "Fix the profile matcher; no profile will be selected unless all matchers complete.");
            }
        }

        compat::IGameProfile *selectedGameProfile = nullptr;
        if (profileMatcherFailed)
        {
            diagnosis_.status = CompatibilityStatus::Inconclusive;
            diagnosis_.profileStatus = "matcher-failed";
            Note(RuntimeLogLevel::Warning, "compatibility_profile selected=none reason=profile-matcher-failed source=identity-decoding");
        }
        else if (matchingProfiles.size() == 1)
        {
            selectedGameProfile = matchingProfiles.front();
            diagnosis_.profileId = std::string(selectedGameProfile->Id());
            diagnosis_.status = CompatibilityStatus::ProfileSelected;
            diagnosis_.profileStatus = "selected";
            Note(RuntimeLogLevel::Info, "compatibility_profile selected=" + diagnosis_.profileId +
                                            " source=compiled-profile");
        }
        else if (matchingProfiles.size() > 1)
        {
            diagnosis_.status = CompatibilityStatus::Inconclusive;
            diagnosis_.profileStatus = "ambiguous";
            RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_MATCH_AMBIGUOUS", "profile-selection",
                            "observed", "More than one compiled profile matches this package and module.",
                            "Make profile match conditions mutually exclusive; the run will use identity decoding.");
        }
        else
        {
            diagnosis_.status = CompatibilityStatus::Inconclusive;
            diagnosis_.profileStatus = "none";
            Note(RuntimeLogLevel::Info, "compatibility_profile selected=none source=identity-decoding");
        }

        ::nextdumper::binding::DecodePlan decode = ::nextdumper::binding::DecodePlan::Identity();
        ::nextdumper::binding::BindingLayoutHints layoutHints;
        BindingCandidates profileCandidates;
        const auto profileExecutionState = std::make_shared<ProfileExecutionState>();
        bool profileHooksValid = selectedGameProfile != nullptr;
        if (selectedGameProfile)
        {
            try
            {
                diagnosis_.stage = "profile-configuration";
                BeginMemoryStage("profile-configuration");
                decode = selectedGameProfile->MakeDecodePlan(*memory_, context_.Module());
                layoutHints = selectedGameProfile->LayoutHints();
                if (!decode.IsValid() || !layoutHints.IsValid())
                {
                    diagnosis_.profileStatus = "configuration-failed";
                    RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_CONFIGURATION_INVALID", "profile-configuration",
                                    "observed", "The selected profile returned an invalid decode plan or layout hint.",
                                    "Check every decode callback and validate any supplied object or name layout.");
                    profileHooksValid = false;
                }
                else
                {
                    GuardProfileDecoders(decode, profileExecutionState);
                    diagnosis_.profileStatus = "active";
                    diagnosis_.stage = "profile-root-location";
                    BeginMemoryStage("profile-root-location");
                    profileCandidates = selectedGameProfile->LocateRoots(
                        *memory_, context_.Module(),
                        [&](const std::string &message)
                        { Note(RuntimeLogLevel::Debug, "profile: " + message); });
                }
            }
            catch (const std::exception &error)
            {
                diagnosis_.profileStatus = "configuration-failed";
                RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_CONFIGURATION_EXCEPTION", diagnosis_.stage,
                                "observed", std::string("Profile configuration threw an exception: ") + error.what(),
                                "Fix the profile hook; the run will continue with identity decoding and automatic layouts.");
                profileHooksValid = false;
            }
            catch (...)
            {
                diagnosis_.profileStatus = "configuration-failed";
                RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_CONFIGURATION_EXCEPTION", diagnosis_.stage,
                                "observed", "Profile configuration threw an unknown exception.",
                                "Fix the profile hook; the run will continue with identity decoding and automatic layouts.");
                profileHooksValid = false;
            }
            if (!profileHooksValid)
            {
                diagnosis_.status = CompatibilityStatus::Inconclusive;
                decode = ::nextdumper::binding::DecodePlan::Identity();
                layoutHints = {};
                if (diagnosis_.profileStatus == "selected")
                    diagnosis_.profileStatus = "configuration-failed";
            }
        }

        diagnosis_.stage = "root-location";
        BeginMemoryStage("root-location");
        GlobalLocator locator(*memory_, context_.Module());
        BindingCandidates candidates = locator.LocateSymbols(
            {"GUObjectArray", "GObjects", "ObjObjects"},
            {"GNameBlocksDebug", "GFNameTableForDebuggerVisualizers_MT", "NamePoolData"}, progress);
        candidates.objectRoots.insert(candidates.objectRoots.end(),
                                      profileCandidates.objectRoots.begin(), profileCandidates.objectRoots.end());
        candidates.nameRoots.insert(candidates.nameRoots.end(),
                                    profileCandidates.nameRoots.begin(), profileCandidates.nameRoots.end());
        Note(RuntimeLogLevel::Debug, "profile_root_candidates objects=" +
                                         std::to_string(profileCandidates.objectRoots.size()) +
                                         " names=" + std::to_string(profileCandidates.nameRoots.size()));
        finishStage("symbol-locator");
        BindingBuilder builder(*memory_);
        const auto bindingProgress = [&](const std::string &message)
        { Note(message.starts_with("binding:") ? RuntimeLogLevel::Info : RuntimeLogLevel::Debug, message); };
        diagnosis_.stage = "binding";
        BeginMemoryStage("binding");
        profileExecutionState->stage = "binding";
        auto binding = builder.Build(candidates, decode, bindingProgress, layoutHints);
        finishStage("symbol-binding");
        const auto discardFailedProfileDecoders = [&]()
        {
            if (!profileHooksValid || !profileExecutionState->failed)
                return false;
            profileHooksValid = false;
            diagnosis_.profileStatus = "decoder-failed-identity-fallback";
            decode = ::nextdumper::binding::DecodePlan::Identity();
            layoutHints = {};
            RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_DECODER_EXCEPTION", profileExecutionState->stage,
                            "observed", std::string("A profile decoder threw an exception: ") + profileExecutionState->error,
                            "Fix the failing profile decoder; the run will retry this binding with identity decoding.");
            return true;
        };
        if (discardFailedProfileDecoders())
            binding = builder.Build(candidates, decode, bindingProgress, layoutHints);

        const auto runAnalysisProbe = [&]()
        {
            Note(RuntimeLogLevel::Info, "analysis_probe status=start mode=" +
                                            std::string(AnalysisModeName(config_.analysis)));
            BeginMemoryStage("analysis-probe");
            AnalysisMemoryView analysisMemory(*memory_);
            ::nextdumper::analysis::AnalysisSession session(analysisMemory, context_.Module());
            const ::nextdumper::analysis::AnalysisResult result = session.Run();
            finishStage("analysis-probe");

            Note(RuntimeLogLevel::Info,
                 "analysis_probe mode=" + std::string(AnalysisModeName(config_.analysis)) +
                     " status=" + ::nextdumper::analysis::AnalysisStatusName(result.Status) +
                     " reason=" + result.Reason +
                     " contracts=" + std::to_string(result.Contracts.size()) +
                     " segments=" + std::to_string(result.Coverage.ModuleSegments) +
                     " executable_segments=" + std::to_string(result.Coverage.ExecutableSegments) +
                     " planned_bytes=" + std::to_string(result.Coverage.PlannedBytes) +
                     " read_bytes=" + std::to_string(result.Coverage.ReadBytes) +
                     " read_failures=" + std::to_string(result.Coverage.ReadFailures) +
                     " functions=" + std::to_string(result.Coverage.FunctionCount) +
                     " scanned_instructions=" + std::to_string(result.Coverage.ScannedInstructions) +
                     " complete=" + std::to_string(result.Coverage.Complete));
            for (const auto &diagnostic : result.Diagnostics)
            {
                RuntimeLogLevel level = RuntimeLogLevel::Info;
                if (diagnostic.Severity == ::nextdumper::analysis::DiagnosticSeverity::Warning)
                    level = RuntimeLogLevel::Warning;
                else if (diagnostic.Severity == ::nextdumper::analysis::DiagnosticSeverity::Error)
                    level = RuntimeLogLevel::Error;
                Note(level, "analysis_diagnostic severity=" +
                                std::string(::nextdumper::analysis::DiagnosticSeverityName(diagnostic.Severity)) +
                                " code=" + diagnostic.Code + " message=" + diagnostic.Message);
            }
        };
        if (config_.analysis == AnalysisMode::Force ||
            (config_.analysis == AnalysisMode::Auto && !binding))
            runAnalysisProbe();

        if (!binding)
        {
            Note("locator_path source=analyzer reason=symbol-binding-incomplete");
            BeginMemoryStage("analyzer-locator");
            candidates = locator.LocateAnalysis(candidates, progress);
            finishStage("analyzer-locator");
            BeginMemoryStage("analyzer-binding");
            profileExecutionState->stage = "binding";
            binding = builder.Build(candidates, decode, bindingProgress, layoutHints);
            finishStage("analyzer-binding");
            if (discardFailedProfileDecoders())
                binding = builder.Build(candidates, decode, bindingProgress, layoutHints);
        }
        else
            Note("locator_path source=symbols validation=complete");
        Note(RuntimeLogLevel::Debug, "Object candidates=" + std::to_string(candidates.objectRoots.size()));
        Note(RuntimeLogLevel::Debug, "Name candidates=" + std::to_string(candidates.nameRoots.size()));
        for (size_t index = 0; index < candidates.objectRoots.size(); ++index)
        {
            const LocatedAddress &candidate = candidates.objectRoots[index];
            Note(RuntimeLogLevel::Debug, "object_candidate[" + std::to_string(index) + "] address=" +
                                             Hex(candidate.address) + " meaning=" + AddressMeaningName(candidate.meaning) +
                                             " confidence=" + std::to_string(candidate.confidence) + " source=" + candidate.source);
        }
        for (size_t index = 0; index < candidates.nameRoots.size(); ++index)
        {
            const LocatedAddress &candidate = candidates.nameRoots[index];
            Note(RuntimeLogLevel::Debug, "name_candidate[" + std::to_string(index) + "] address=" +
                                             Hex(candidate.address) + " meaning=" + AddressMeaningName(candidate.meaning) +
                                             " confidence=" + std::to_string(candidate.confidence) + " source=" + candidate.source);
        }

        if (!binding)
        {
            failures_.push_back("runtime binding failed after symbol and analyzer validation");
            const std::string bindingSummary = failures_.back() +
                                               "; object_root_candidates=" + std::to_string(candidates.objectRoots.size()) +
                                               " name_root_candidates=" + std::to_string(candidates.nameRoots.size());
            if (selectedGameProfile && profileHooksValid)
            {
                diagnosis_.status = CompatibilityStatus::ProfileValidationFailed;
                diagnosis_.profileStatus = "binding-validation-failed";
                RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_BINDING_VALIDATION_FAILED", "binding",
                                "observed", bindingSummary,
                                "Inspect profile root candidates, pointer decoders, and layout hints against the rejected probe evidence.");
            }
            else
            {
                diagnosis_.status = CompatibilityStatus::NeedsInvestigation;
                RecordDiagnosis(DiagnosisDomain::Compatibility, "ROOT_BINDING_NOT_VALIDATED", "binding",
                                "observed", bindingSummary,
                                "Use candidate and probe evidence to inspect root location, object layout, name layout, and value decoding; this does not prove encryption.");
            }
            return RuntimeSessionStatus::Failed;
        }
        context_.CommitBinding(*binding);
        Note(RuntimeLogLevel::Info, "Runtime binding validated");
        Note(RuntimeLogLevel::Info, "compatibility_checkpoint stage=binding status=validated profile=" +
                                        diagnosis_.profileId);
        for (const std::string &evidence : context_.Binding().report.evidence)
            Note(RuntimeLogLevel::Debug, "binding: " + evidence);

        EngineSchema schema;
        EngineProfile selectedProfile;
        SchemaResolutionReport schemaReport;
        SchemaSelectionResult schemaSelection;
        const std::vector<EngineProfile> profiles = SchemaCatalog::Profiles();
        diagnosis_.stage = "schema";
        BeginMemoryStage("schema-resolution");
        Note(RuntimeLogLevel::Info, "Detecting Unreal Engine schema profile...");
        std::vector<EngineSchema> candidateSchemas;
        auto resolveProfiles = [&]()
        {
            schemaSelection = {};
            candidateSchemas.clear();
            candidateSchemas.reserve(profiles.size());
            schemaSelection.candidates.reserve(profiles.size());
            const auto probeSession = ::nextdumper::ue::CreateSchemaProbeSession(
                *memory_, context_.Binding(), {}, context_.Module().base, context_.Module().end);
            for (const EngineProfile &profile : profiles)
            {
                Note("schema: probing profile=" + profile.id);
                EngineSchema candidateSchema;
                const auto profileStart = std::chrono::steady_clock::now();
                const ReadStats profileStatsBefore = memory_->Stats();
                SchemaResolver resolver(*memory_, context_.Binding(), profile, {},
                                        context_.Module().base, context_.Module().end, probeSession);
                SchemaCandidateSummary candidateReport = resolver.Resolve(candidateSchema);
                const ReadStats profileStatsAfter = memory_->Stats();
                Note(RuntimeLogLevel::Debug, "schema_profile id=" + profile.id +
                                                 " elapsed_ms=" +
                                                 std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                                    std::chrono::steady_clock::now() - profileStart)
                                                                    .count()) +
                                                 " probe_limited=" + std::to_string(candidateReport.probeLimited) +
                                                 ::nextdumper::memory::DescribeReadStats(profileStatsAfter, profileStatsBefore));
                const std::string reason = candidateReport.failures.empty()
                                               ? (candidateReport.evidence.empty() ? "none" : candidateReport.evidence.front())
                                               : candidateReport.failures.front();
                Note(RuntimeLogLevel::Debug, "schema_candidate id=" + profile.id +
                                                 " range=" + profile.versionRange +
                                                 " layout=" + SchemaLayoutVariantName(profile.layout) +
                                                 " stage=" + candidateReport.failureStage +
                                                 " accepted=" + std::to_string(candidateReport.accepted) +
                                                 " layout_score=" + std::to_string(candidateReport.layoutScore) +
                                                 " version_evidence_score=" + std::to_string(candidateReport.versionEvidenceScore) +
                                                 " reason=" + reason);
                for (const auto &failure : candidateReport.failures)
                    Note(RuntimeLogLevel::Debug, "schema_candidate_failure profile=" + profile.id + " reason=" + failure);
                for (const auto &use : candidateReport.stages)
                {
                    const auto &stage = *use.result;
                    const std::string prefix = "schema_stage profile=" + profile.id + " id=" +
                                               ::nextdumper::ue::SchemaProbeStageName(stage.stage);
                    Note(use.reused ? RuntimeLogLevel::Debug : RuntimeLogLevel::Info, prefix + " source_profile=" + stage.sourceProfile +
                                                                                          " reused=" + std::to_string(use.reused) + " resolved=" + std::to_string(stage.resolved) +
                                                                                          " evidence_complete=" + std::to_string(stage.evidenceComplete) +
                                                                                          " sample_truncated=" + std::to_string(stage.sampleTruncated) +
                                                                                          " budget_exhausted=" + std::to_string(stage.budgetExhausted) +
                                                                                          " read_failed=" + std::to_string(stage.readFailed) +
                                                                                          " rejected_candidates=" + std::to_string(stage.rejectedCandidates) +
                                                                                          " ambiguous=" + std::to_string(stage.ambiguous) + " search_complete=" + std::to_string(stage.searchComplete) +
                                                                                          " elapsed_ms=" + std::to_string(use.reused ? 0 : stage.elapsedMs) +
                                                                                          (use.reused ? std::string{} : ::nextdumper::memory::DescribeReadStats(stage.readsAfter, stage.readsBefore)) +
                                                                                          (stage.selectedLayout.empty() ? std::string{} : " selected_layout={" + stage.selectedLayout + "}"));
                    if (!use.reused)
                        for (const auto &evidence : stage.evidence)
                            Note(RuntimeLogLevel::Debug, prefix + " evidence=" + evidence);
                    if (!use.reused)
                        for (const auto &failure : stage.failures)
                            Note(RuntimeLogLevel::Debug, prefix + " failure=" + failure);
                }
                for (const auto &evidence : candidateReport.versionEvidence)
                    Note(RuntimeLogLevel::Debug, "schema_version_evidence id=" + profile.id +
                                                     " kind=" + evidence.kind + " observed=" + evidence.observed +
                                                     " strength=" + ::nextdumper::ue::VersionEvidenceStrengthName(evidence.strength) +
                                                     " detail=" + evidence.detail);
                schemaSelection.candidates.push_back(std::move(candidateReport));
                candidateSchemas.push_back(std::move(candidateSchema));
            }

            schemaSelection = ::nextdumper::ue::SelectSchemaCandidates(std::move(schemaSelection.candidates), candidateSchemas);
        };

        bool schemaAddressSpaceRefreshFailed = false;
        bool schemaAddressSpaceUnstable = false;
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            profileExecutionState->stage = "schema";
            resolveProfiles();
            if (profileHooksValid && profileExecutionState->failed)
            {
                failures_.push_back("profile decoder failed during schema validation");
                diagnosis_.status = CompatibilityStatus::ProfileValidationFailed;
                diagnosis_.profileStatus = "decoder-failed";
                RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_DECODER_EXCEPTION", "schema",
                                "observed", std::string("A profile decoder threw an exception: ") + profileExecutionState->error,
                                "Fix the decoder used by schema probes; no schema result from this profile is trusted.");
                return RuntimeSessionStatus::BindingReady;
            }
            bool addressSpaceChanged = false;
            for (const SchemaCandidateSummary &candidate : schemaSelection.candidates)
                addressSpaceChanged = addressSpaceChanged || candidate.addressSpaceChanged;
            if (!addressSpaceChanged)
                break;
            if (attempt != 0)
            {
                schemaAddressSpaceUnstable = true;
                failures_.push_back("remote address space changed again during schema retry");
                diagnosis_.status = CompatibilityStatus::Inconclusive;
                RecordDiagnosis(DiagnosisDomain::Runtime, "ADDRESS_SPACE_UNSTABLE", "schema",
                                "observed", failures_.back(),
                                "Keep the target process stable and retry; compatibility could not be evaluated on a consistent address space.");
                break;
            }
            Note(RuntimeLogLevel::Warning, "Remote address space changed during schema resolution; refreshing and retrying");
            if (!memory_->RefreshAddressSpace())
            {
                schemaAddressSpaceRefreshFailed = true;
                failures_.push_back("remote address-space refresh failed after schema probe invalidation");
                diagnosis_.status = CompatibilityStatus::Inconclusive;
                RecordDiagnosis(DiagnosisDomain::Runtime, "ADDRESS_SPACE_REFRESH_FAILED", "schema",
                                "observed", failures_.back(),
                                "Rerun with a stable target process; no schema result from the invalidated address space is trusted.");
                break;
            }
        }

        finishStage("schema-resolution");
        if (schemaAddressSpaceRefreshFailed || schemaAddressSpaceUnstable)
            return RuntimeSessionStatus::BindingReady;
        const bool schemaAccepted = schemaSelection.accepted;
        if (schemaAccepted)
        {
            schema = std::move(candidateSchemas[schemaSelection.selectedIndex]);
            schemaReport = schemaSelection.candidates[schemaSelection.selectedIndex];
            selectedProfile = profiles[schemaSelection.selectedIndex];
            schema.identity.layoutProfileId = schema.features.useFProperty
                                                  ? (schema.features.fFieldOwnerEncoding == ::nextdumper::ue::FFieldOwnerEncoding::TaggedPointer
                                                         ? "fproperty-tagged-owner"
                                                         : "fproperty-explicit-owner")
                                                  : "uproperty";
            if (schema.features.enumHasFlags)
                schema.identity.layoutProfileId += "-enum-flags";
            schema.identity.layoutProfileLabel = "Validated runtime reflection layout";
            schema.identity.layoutVersionRange = "runtime-observed; compatible profiles listed separately";
            schema.identity.canonicalProfileId = selectedProfile.id;
            schema.identity.canonicalProfileLabel = selectedProfile.label;
            schema.identity.canonicalVersionRange = selectedProfile.versionRange;
            schema.identity.selectionReason = schemaSelection.selectionReason;
            schema.identity.versionConfidence = schemaSelection.versionConfidence;
            schema.identity.layoutScore = schemaReport.layoutScore;
            schema.identity.versionEvidenceScore = schemaReport.versionEvidenceScore;
            schema.identity.evidence = schemaReport.versionEvidence;
            for (const size_t index : schemaSelection.compatibleIndices)
            {
                schema.identity.compatibleProfiles.push_back(profiles[index].id);
                if (index != schemaSelection.selectedIndex)
                    schemaReport.evidence.push_back("compatible profile=" + profiles[index].id);
            }
            if (schemaSelection.ambiguous)
            {
                std::string equivalentProfiles;
                for (const size_t index : schemaSelection.compatibleIndices)
                {
                    equivalentProfiles += " " + profiles[index].id;
                }
                const std::string evidence = "equivalent resolved layouts; canonical=" + selectedProfile.id +
                                             " compatible_profiles=" + equivalentProfiles +
                                             " selection_reason=" + schemaSelection.selectionReason +
                                             " version_confidence=" + schemaSelection.versionConfidence;
                schemaReport.evidence.push_back(evidence);
                Note(RuntimeLogLevel::Debug, evidence);
            }
        }
        else
        {
            schemaReport.profileId = "none";
            schemaReport.failureStage = "selection";
            schemaReport.failures.push_back(schemaSelection.layoutAmbiguous
                                                ? "schema selection is ambiguous across distinct layout variants"
                                                : "schema selection failed: no profile satisfied semantic validation");
            for (const SchemaCandidateSummary &candidate : schemaSelection.candidates)
            {
                const std::string attribution = "profile=" + candidate.profileId +
                                                " stage=" + candidate.failureStage + " ";
                for (const std::string &evidence : candidate.evidence)
                    schemaReport.evidence.push_back(attribution + evidence);
                for (const std::string &failure : candidate.failures)
                    schemaReport.failures.push_back(attribution + failure);
            }
        }
        if (!schemaAccepted)
        {
            const std::string failure = schemaReport.failures.empty()
                                            ? "schema resolution failed without a diagnostic"
                                            : schemaReport.failures.front();
            diagnosis_.status = selectedGameProfile && profileHooksValid
                                    ? CompatibilityStatus::ProfileValidationFailed
                                    : CompatibilityStatus::NeedsInvestigation;
            if (selectedGameProfile && profileHooksValid)
                diagnosis_.profileStatus = "schema-validation-failed";
            RecordDiagnosis(selectedGameProfile && profileHooksValid ? DiagnosisDomain::Profile : DiagnosisDomain::Compatibility,
                            selectedGameProfile && profileHooksValid ? "PROFILE_SCHEMA_VALIDATION_FAILED" : "ENGINE_SCHEMA_NOT_RESOLVED",
                            "schema", "observed", failure,
                            "Review schema-stage evidence and name/object validation first; an unsupported reflection layout is not evidence of encryption.");
            for (size_t index = 1; index < schemaReport.failures.size(); ++index)
                Note(RuntimeLogLevel::Error, schemaReport.failures[index]);
        }
        const ReadStats &memoryStats = memory_->Stats();
        Note(RuntimeLogLevel::Debug, "memory stats" + ::nextdumper::memory::DescribeReadStats(memoryStats));
        if (!schemaAccepted)
        {
            failures_.insert(failures_.end(), schemaReport.failures.begin(), schemaReport.failures.end());
            return RuntimeSessionStatus::BindingReady;
        }
        context_.CommitSchema(std::move(schema));
        Note(RuntimeLogLevel::Info, "compatibility_checkpoint stage=schema status=validated profile=" +
                                        diagnosis_.profileId);
        Note(RuntimeLogLevel::Info, "Engine schema resolved; profile=" + selectedProfile.id +
                                        " range=" + selectedProfile.versionRange +
                                        " source=runtime-schema-probe");

        if (!memory_->RefreshAddressSpace())
        {
            failures_.push_back("address-space refresh failed before reflection capture");
            RecordDiagnosis(DiagnosisDomain::Runtime, "ADDRESS_SPACE_REFRESH_FAILED", "reflection-prepare",
                            "observed", failures_.back(),
                            "Check target process stability and memory-map refresh before changing a game profile.");
            return RuntimeSessionStatus::SchemaReady;
        }
        diagnosis_.stage = "common-objects";
        BeginMemoryStage("common-objects");
        Note(RuntimeLogLevel::Info, "Collecting common object classes...");
        profileExecutionState->stage = "common-objects";
        binding::CommonObjectCollector collector(*memory_, context_.Binding(), context_.Schema());
        std::vector<binding::CommonObjectInfo> commonObjects = collector.Collect();
        if (profileHooksValid && profileExecutionState->failed)
        {
            failures_.push_back("profile decoder failed during common object collection");
            diagnosis_.status = CompatibilityStatus::ProfileValidationFailed;
            diagnosis_.profileStatus = "decoder-failed";
            RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_DECODER_EXCEPTION", "common-objects",
                            "observed", std::string("A profile decoder threw an exception: ") + profileExecutionState->error,
                            "Fix the profile decoder; common-object output from this run is not published.");
            return RuntimeSessionStatus::SchemaReady;
        }
        Note(RuntimeLogLevel::Info, "Found " + std::to_string(commonObjects.size()) + " common object classes");
        for (const auto &obj : commonObjects)
        {
            Note(RuntimeLogLevel::Debug, "common_object: " + obj.name +
                                             " address=" + Hex(obj.address) +
                                             " index=" + std::to_string(obj.index));
        }

        RuntimeBinding updatedBinding = context_.Binding();
        updatedBinding.commonObjects = std::move(commonObjects);
        context_.CommitBinding(std::move(updatedBinding));
        finishStage("common-objects");

        diagnosis_.stage = "reflection";
        BeginMemoryStage("reflection");
        const ReadStats beforeReflection = memory_->Stats();
        profileExecutionState->stage = "reflection";
        ReflectionReader reader(*memory_, context_.Binding(), context_.Schema(),
                                context_.Module().base, context_.Module().end, progress,
                                [&](const std::string &message)
                                { Note(RuntimeLogLevel::Debug, message); });
        reflection_ = reader.Read();
        if (profileHooksValid && profileExecutionState->failed)
        {
            failures_.push_back("profile decoder failed during reflection capture");
            diagnosis_.status = CompatibilityStatus::ProfileValidationFailed;
            diagnosis_.profileStatus = "decoder-failed";
            RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_DECODER_EXCEPTION", "reflection",
                            "observed", std::string("A profile decoder threw an exception: ") + profileExecutionState->error,
                            "Fix the profile decoder; reflection output from this run is not trusted.");
            return RuntimeSessionStatus::SchemaReady;
        }
        finishStage("reflection");
        const ReadStats afterReflection = memory_->Stats();
        Note(RuntimeLogLevel::Debug, "memory stats stage=reflection" +
                                         ::nextdumper::memory::DescribeReadStats(afterReflection, beforeReflection));
        Note(RuntimeLogLevel::Info, "Capture observations_stable=" + std::to_string(reflection_.capture.observationsStable) +
                                        " attempts=" + std::to_string(reflection_.capture.attempts) +
                                        " observed_ranges=" + std::to_string(reflection_.capture.observedRanges) +
                                        " changed_ranges=" + std::to_string(reflection_.capture.changedRanges) +
                                        " unreadable_ranges=" + std::to_string(reflection_.capture.unreadableRanges) +
                                        " limit_exceeded=" + std::to_string(reflection_.capture.limitExceeded) + " atomic_snapshot=0");
        reflection_.diagnostics.push_back("reflection status=" + std::string(ParseStatusName(reflection_.status)));
        if (reflection_.stats.failures != 0)
            reflection_.diagnostics.push_back("reflection failures=" + std::to_string(reflection_.stats.failures));
        if (reflection_.stats.unknownProperties != 0)
            reflection_.diagnostics.push_back("unknown properties=" + std::to_string(reflection_.stats.unknownProperties));
        if (reflection_.stats.unresolvedTypeDetails != 0)
            reflection_.diagnostics.push_back("unresolved type details=" + std::to_string(reflection_.stats.unresolvedTypeDetails));
        if (reflection_.stats.layoutConflicts != 0)
            reflection_.diagnostics.push_back("layout conflicts=" + std::to_string(reflection_.stats.layoutConflicts));
        for (const std::string &diagnostic : reflection_.diagnostics)
            Note(RuntimeLogLevel::Debug, "reflection: " + diagnostic);
        Note(RuntimeLogLevel::Info, "Reflection status=" + std::to_string(static_cast<int>(reflection_.status)) +
                                        " types=" + std::to_string(reflection_.stats.parsedTypes) +
                                        " properties=" + std::to_string(reflection_.stats.parsedProperties) +
                                        " functions=" + std::to_string(reflection_.stats.parsedFunctions) +
                                        " enums=" + std::to_string(reflection_.stats.parsedEnums) +
                                        " unknown_properties=" + std::to_string(reflection_.stats.unknownProperties) +
                                        " unresolved_type_details=" + std::to_string(reflection_.stats.unresolvedTypeDetails) +
                                        " object_slots=" + std::to_string(reflection_.stats.objectSlots) +
                                        " valid_objects=" + std::to_string(reflection_.stats.validObjects) +
                                        " skipped_objects=" + std::to_string(reflection_.stats.skippedObjects) +
                                        " empty_object_slots=" + std::to_string(reflection_.stats.emptyObjectSlots) +
                                        " object_read_failures=" + std::to_string(reflection_.stats.objectReadFailures) +
                                        " class_name_read_failures=" + std::to_string(reflection_.stats.classNameReadFailures) +
                                        " enum_read_failures=" + std::to_string(reflection_.stats.enumReadFailures) +
                                        " identity_failures=" + std::to_string(reflection_.stats.identityFailures) +
                                        " unvisited_objects=" + std::to_string(reflection_.stats.unvisitedObjects) +
                                        " skipped_class_default_objects=" + std::to_string(reflection_.stats.skippedClassDefaultObjects) +
                                        " skipped_incomplete_objects=" + std::to_string(reflection_.stats.skippedIncompleteObjects) +
                                        " object_diagnostic_samples_omitted=" + std::to_string(reflection_.stats.objectDiagnosticSamplesOmitted) +
                                        " failures=" + std::to_string(reflection_.stats.failures));
        if (reflection_.status == ParseStatus::Failed)
        {
            diagnosis_.status = selectedGameProfile && profileHooksValid
                                    ? CompatibilityStatus::ProfileValidationFailed
                                    : CompatibilityStatus::NeedsInvestigation;
            if (selectedGameProfile && profileHooksValid)
                diagnosis_.profileStatus = "reflection-validation-failed";
            RecordDiagnosis(selectedGameProfile && profileHooksValid ? DiagnosisDomain::Profile : DiagnosisDomain::Compatibility,
                            selectedGameProfile && profileHooksValid ? "PROFILE_REFLECTION_FAILED" : "REFLECTION_CAPTURE_FAILED",
                            "reflection", "observed",
                            "Reflection capture failed after object/name binding and schema validation.",
                            "Inspect reflection read failures and identity diagnostics before attributing the failure to game encryption.");
            return RuntimeSessionStatus::SchemaReady;
        }
        if (reflection_.status == ParseStatus::Partial)
        {
            Note(RuntimeLogLevel::Warning, "Reflection is partial; output will be written to a .partial artifact");
            diagnosis_.status = CompatibilityStatus::Inconclusive;
            if (selectedGameProfile && profileHooksValid)
                diagnosis_.profileStatus = "reflection-partial";
            RecordDiagnosis(selectedGameProfile && profileHooksValid ? DiagnosisDomain::Profile : DiagnosisDomain::Compatibility,
                            selectedGameProfile && profileHooksValid ? "PROFILE_REFLECTION_PARTIAL" : "REFLECTION_PARTIAL",
                            "reflection", "observed",
                            "Reflection capture completed with skipped or unreadable definitions.",
                            "Review reflection.json and diagnostics.json to separate unsupported field semantics from transient or inaccessible reads.");
        }
        else
        {
            diagnosis_.status = selectedGameProfile && profileHooksValid
                                    ? CompatibilityStatus::ProfileValidated
                                    : CompatibilityStatus::BaselineCompatible;
            if (selectedGameProfile && profileHooksValid)
                diagnosis_.profileStatus = "validated";
            diagnosis_.stage = "reflection";
            Note(RuntimeLogLevel::Info, "compatibility_assessment status=" +
                                            std::string(CompatibilityStatusName(diagnosis_.status)) +
                                            " profile=" + diagnosis_.profileId);
        }

        diagnosis_.stage = "runtime-value-evidence";
        BeginMemoryStage("runtime-value-evidence");
        const ReadStats beforeValues = memory_->Stats();
        try
        {
            ir::SparseRootEvidence sparseRoot;
            if (context_.Module().IsValid())
            {
                const auto symbols = module::QueryElfSymbols(*memory_, context_.Module(), {sparseRoot.symbol});
                sparseRoot.diagnostics = symbols.diagnostics;
                const auto status = symbols.status.find(sparseRoot.symbol);
                sparseRoot.status = status == symbols.status.end() ? "symbol-query-incomplete" : module::SymbolStatusName(status->second);
                if (const auto at = symbols.exported.find(sparseRoot.symbol); at != symbols.exported.end())
                {
                    sparseRoot.address = at->second;
                    sparseRoot.source = "exported-symbol";
                }
                else if (const auto at = symbols.debug.find(sparseRoot.symbol); at != symbols.debug.end())
                {
                    sparseRoot.address = at->second;
                    sparseRoot.source = "debug-symbol";
                }
                // SparseDelegates 是静态 TMap 本体，不是指针槽，没有符号时不猜测偏移
                if (sparseRoot.address && !context_.Module().IsWritable(sparseRoot.address))
                {
                    sparseRoot.address = 0;
                    sparseRoot.status = "symbol-not-in-writable-segment";
                }
            }
            else
                sparseRoot.status = "elf-image-unavailable-not-queried";
            reflection_.runtimeEvidence = reflection::InspectRuntimeValues(*memory_, context_.Binding(), context_.Schema(),
                                                                           context_.Module(), reflection_, std::move(sparseRoot));
        }
        catch (const std::exception &error)
        {
            // 可选实例采集失败不能丢弃已经完成的反射定义，错误仍写入日志和产物
            reflection_.runtimeEvidence.status = "optional-inspection-failed";
            reflection_.runtimeEvidence.sparse.status = "inspection-aborted";
            Note(RuntimeLogLevel::Warning, "runtime_value_evidence failed: " + std::string(error.what()));
        }
        if (profileHooksValid && profileExecutionState->failed)
        {
            failures_.push_back("profile decoder failed during runtime value inspection");
            diagnosis_.status = CompatibilityStatus::ProfileValidationFailed;
            diagnosis_.profileStatus = "decoder-failed";
            RecordDiagnosis(DiagnosisDomain::Profile, "PROFILE_DECODER_EXCEPTION", "runtime-value-evidence",
                            "observed", std::string("A profile decoder threw an exception: ") + profileExecutionState->error,
                            "Fix the profile decoder; runtime evidence from this run is not trusted.");
            return RuntimeSessionStatus::SchemaReady;
        }
        finishStage("runtime-value-evidence");
        const auto &runtime = reflection_.runtimeEvidence;
        Note(RuntimeLogLevel::Info, "runtime_value_evidence status=" + runtime.status +
                                        " object_slots=" + std::to_string(runtime.objectSlots) + " scanned_slots=" + std::to_string(runtime.scannedSlots) +
                                        " samples=" + std::to_string(runtime.values.size()) + " scan_complete=" + std::to_string(runtime.scanComplete) +
                                        " affects_sdk_completeness=0 atomic_snapshot=0 field_coverage=bounded"
                                        " sampling=storage-category-and-instance-role field_budget=unique-relevant-metadata"
                                        " full_records=reflection.json/runtime_value_evidence");
        for (const auto &[status, count] : runtime.statuses)
            Note(RuntimeLogLevel::Debug, "runtime_value_status status=" + status + " count=" + std::to_string(count));
        for (const auto &[reason, count] : runtime.skipped)
            Note(RuntimeLogLevel::Debug, "runtime_value_skipped reason=" + reason + " count=" + std::to_string(count));
        Note(RuntimeLogLevel::Debug, "sparse_binding_evidence status=" + runtime.sparse.status +
                                         " root=" + Hex(runtime.sparse.address) + " source=" + runtime.sparse.source +
                                         " records=" + std::to_string(runtime.sparse.delegates.size()) +
                                         " enumeration_complete=" + std::to_string(runtime.sparse.enumerationComplete) +
                                         " observations_stable=" + std::to_string(runtime.sparse.capture.observationsStable) +
                                         " full_records=reflection.json/runtime_value_evidence/sparse");
        Note(RuntimeLogLevel::Debug, "memory stats stage=runtime-value-evidence" +
                                         ::nextdumper::memory::DescribeReadStats(memory_->Stats(), beforeValues));
        if (!config_.outputRoot.empty())
        {
            diagnosis_.stage = "artifact-generation";
            BeginMemoryStage("artifact-generation");
            provenance_.addressSpaceGeneration = memory_->AddressSpaceGeneration();
            ArtifactWriter writer(context_, reflection_, config_.outputRoot, config_.packageName, provenance_,
                                  [&](const std::string &message)
                                  { Note(RuntimeLogLevel::Debug, message); });
            {
                auto *performance = memory_->Performance();
                memory::ScopedReadTiming timing(performance ? &performance->artifactGeneration : nullptr, 1);
                artifacts_ = writer.Write();
            }
            finishStage("artifact-generation");
            for (const auto &diagnostic : artifacts_.generationDiagnostics)
                Note(RuntimeLogLevel::Debug, diagnostic);
            if (artifacts_.status == ParseStatus::Failed)
            {
                failures_.push_back(artifacts_.error);
                RecordDiagnosis(DiagnosisDomain::Runtime, "ARTIFACT_WRITE_FAILED", "artifact-generation",
                                "observed", failures_.back(),
                                "Check output permissions and free space; compatibility binding may already be validated.");
                return RuntimeSessionStatus::Failed;
            }
            Note(RuntimeLogLevel::Info, "Artifact status=" + std::string(ParseStatusName(artifacts_.status)) +
                                            " files=" + std::to_string(artifacts_.filesWritten) +
                                            " opaque_fields=" + std::to_string(artifacts_.opaqueFields) +
                                            " reflection_status=" + ParseStatusName(artifacts_.reflectionStatus) +
                                            " sdk_status=" + ParseStatusName(artifacts_.sdkStatus) +
                                            " omitted_fields=" + std::to_string(artifacts_.omittedFields) +
                                            " layout_warnings=" + std::to_string(artifacts_.layoutWarnings) +
                                            " output=" + artifacts_.outputPath.string());
        }
        Note(RuntimeLogLevel::Info, "=== Runtime Session Completed ===");
        if (reflection_.status == ParseStatus::Partial)
            return RuntimeSessionStatus::ReflectionPartial;
        if (artifacts_.status == ParseStatus::Partial)
            return RuntimeSessionStatus::ArtifactPartial;
        return RuntimeSessionStatus::ReflectionReady;
    }
} // namespace nextdumper::app
