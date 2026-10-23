#include "nextdumper/binding/GlobalLocator.hpp"
#include "nextdumper/analyzer/AnalyzerMemoryAdapter.hpp"

#include <algorithm>
#include <chrono>
#include <memory>

#include "nextdumper/common/Hex.hpp"
#include "nextdumper/memory/ReadDiagnostics.hpp"
#include "nextdumper/module/ElfSymbols.hpp"

#include "Architecture/IArchDecoder.h"
#include "UEAnalyzer/UEAnalyzer.h"

namespace nextdumper::binding
{
    namespace
    {
        using ::nextdumper::common::Hex;

        EArch ToAnalyzerArchitecture(module::ModuleArchitecture architecture)
        {
            switch (architecture)
            {
            case module::ModuleArchitecture::Arm32:
                return EArch::Arm32;
            case module::ModuleArchitecture::Arm64:
                return EArch::Arm64;
            case module::ModuleArchitecture::Unknown:
                return EArch::Unknown;
            }
            return EArch::Unknown;
        }

        class LocatorPhases
        {
        public:
            LocatorPhases(const IMemorySource &memory, const std::function<void(const std::string &)> &progress)
                : memory_(memory), progress_(progress), stats_(memory.Stats()) {}
            void Finish(const char *id)
            {
                const auto now = std::chrono::steady_clock::now();
                const auto stats = memory_.Stats();
                if (progress_)
                    progress_("locator_phase id=" + std::string(id) + " elapsed_ms=" +
                              std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now - start_).count()) +
                              memory::DescribeReadStats(stats, stats_));
                start_ = std::chrono::steady_clock::now();
                stats_ = stats;
            }

        private:
            const IMemorySource &memory_;
            const std::function<void(const std::string &)> &progress_;
            memory::ReadStats stats_;
            std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
        };
    } // namespace

    std::vector<LocatedAddress> GlobalLocator::SymbolCandidates(uintptr_t address, const std::string &symbol) const
    {
        if (address == 0)
            return {};
        if (symbol == "GUObjectArray" || symbol == "NamePoolData")
            return {{address, AddressMeaning::Direct, 80, "symbol:" + symbol}};
        return {{address, AddressMeaning::Direct, 70, "symbol:" + symbol + ":direct"},
                {address, AddressMeaning::PointerSlot, 70, "symbol:" + symbol + ":pointer-slot"}};
    }

    BindingCandidates GlobalLocator::LocateSymbols(const std::vector<std::string> &objectSymbols,
                                                   const std::vector<std::string> &nameSymbols,
                                                   const std::function<void(const std::string &)> &progress) const
    {
        BindingCandidates result;
        LocatorPhases phases(memory_, progress);
        {
            phases.Finish("find-elf");
            if (module_.IsValid())
            {
                std::vector<std::string> names = objectSymbols;
                names.insert(names.end(), nameSymbols.begin(), nameSymbols.end());
                const auto symbols = module::QueryElfSymbols(memory_, module_, names);
                const auto append = [&](const auto &requested, auto &out)
                {
                    for (const auto &name : requested)
                    {
                        uintptr_t address = 0;
                        const char *source = "missing";
                        if (const auto at = symbols.exported.find(name); at != symbols.exported.end())
                        {
                            address = at->second;
                            source = "exported";
                        }
                        else if (const auto at = symbols.debug.find(name); at != symbols.debug.end())
                        {
                            address = at->second;
                            source = "debug";
                        }
                        const auto candidates = SymbolCandidates(address, name);
                        out.insert(out.end(), candidates.begin(), candidates.end());
                        if (progress)
                            progress("locator_symbol name=" + name + " source=" + source +
                                     " status=" + (symbols.status.contains(name) ? module::SymbolStatusName(symbols.status.at(name)) : "incomplete") +
                                     " address=" + Hex(address));
                    }
                };
                append(objectSymbols, result.objectRoots);
                append(nameSymbols, result.nameRoots);
                if (progress)
                    for (const auto &diagnostic : symbols.diagnostics)
                        progress("locator_symbol_query status=limited reason=" + diagnostic);
                phases.Finish("symbol-query");
            }
        }
        phases.Finish("symbol-cleanup");
        return result;
    }

    BindingCandidates GlobalLocator::LocateAnalysis(const BindingCandidates &existing,
                                                    const std::function<void(const std::string &)> &progress) const
    {
        BindingCandidates result = existing;
        LocatorPhases phases(memory_, progress);
        const auto analyze = [&]
        {
            analyzer::AnalyzerMemoryAdapter adapter(memory_, module_);
            if (!adapter.Initialize())
            {
                phases.Finish("adapter-failed");
                return;
            }
            const std::unique_ptr<IArchDecoder> decoder = CreateArchDecoder(ToAnalyzerArchitecture(module_.architecture));
            if (!decoder)
            {
                phases.Finish("decoder-failed");
                return;
            }
            phases.Finish("analyzer-initialization");
            analyzer::AnalyzerOptions options;
            options.ThreadMode = analyzer::EThreadMode::Single;
            options.Progress = progress;
            options.PhaseCompleted = [&](const char *id)
            { phases.Finish(id); };
            options.Targets = {analyzer::Targets::Names, analyzer::Targets::GUObjectArray, analyzer::Targets::ObjObjects};
            const auto analysis = analyzer::UEAnalyzer::Analyze(&adapter, decoder.get(), options);
            if (!analysis.IsValid())
            {
                if (progress)
                    progress("locator_analysis status=failed reason=" + analysis.GetError());
                phases.Finish("analysis-failed");
                return;
            }
            const auto append = [](auto &out, const analyzer::LocateResult &located)
            {
                for (const auto &candidate : located.Candidates)
                {
                    if (candidate.Address == 0 || std::any_of(out.begin(), out.end(), [&](const auto &item)
                                                              { return item.address == candidate.Address && item.meaning == AddressMeaning::Direct; }))
                        continue;
                    out.push_back({static_cast<uintptr_t>(candidate.Address), AddressMeaning::Direct,
                                   static_cast<uint8_t>(std::clamp(candidate.Confidence, 0.0f, 1.0f) * 100.0f),
                                   std::string("analyzer:") + located.Target});
                }
            };
            append(result.objectRoots, analysis.Find(analyzer::Targets::GUObjectArray));
            phases.Finish("resolve-GUObjectArray");
            append(result.objectRoots, analysis.Find(analyzer::Targets::ObjObjects));
            phases.Finish("resolve-ObjObjects");
            append(result.nameRoots, analysis.Find(analyzer::Targets::Names));
            phases.Finish("resolve-Names");
        };
        analyze();
        phases.Finish("analyzer-cleanup");
        return result;
    }
} // namespace nextdumper::binding
