#include "nextdumper/binding/GlobalLocator.hpp"

#include <algorithm>
#include <chrono>

#include "nextdumper/common/Hex.hpp"
#include "nextdumper/memory/ReadDiagnostics.hpp"
#include "nextdumper/module/ElfSymbols.hpp"

namespace nextdumper::binding
{
    namespace
    {
        using ::nextdumper::common::Hex;

        RootTarget TargetForSymbol(const std::string &symbol)
        {
            if (symbol == "GUObjectArray" || symbol == "GObjects")
                return RootTarget::GUObjectArray;
            if (symbol == "ObjObjects")
                return RootTarget::ObjObjects;
            if (symbol == "NamePoolData" || symbol == "GNameBlocksDebug" ||
                symbol == "GFNameTableForDebuggerVisualizers_MT")
                return RootTarget::NamePool;
            return RootTarget::Unknown;
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
        const RootTarget target = TargetForSymbol(symbol);
        if (symbol == "GUObjectArray" || symbol == "NamePoolData")
            return {{address, AddressMeaning::Direct, 80, "symbol:" + symbol, target}};
        return {{address, AddressMeaning::Direct, 70, "symbol:" + symbol + ":direct", target},
                {address, AddressMeaning::PointerSlot, 70, "symbol:" + symbol + ":pointer-slot", target}};
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
} // namespace nextdumper::binding
