#pragma once

#include <memory>
#include <string>
#include <vector>

#include "Architecture/IArchDecoder.h"
#include "Memory/IMemory.h"

#include "nextdumper/memory/MemorySource.hpp"
#include "nextdumper/module/ModuleImage.hpp"

namespace nextdumper::analyzer
{
    using ::nextdumper::memory::IMemorySource;

    class AnalyzerMemoryAdapter final : public IMemory
    {
    public:
        AnalyzerMemoryAdapter(IMemorySource &memory, const module::ModuleImage &module);

        bool Initialize() override;
        std::string GetProcessName() const override;
        int GetProcessID() const override;
        bool RefreshMemory() override;
        bool IsMemoryAccessOk() const override;
        bool IsValidAddress(uintptr_t address) const override;
        bool IsAddressReadable(uintptr_t address, size_t size = sizeof(void *)) const override;
        bool IsAddressWriteable(uintptr_t address, size_t size = sizeof(void *)) const override;
        bool IsAddressExecutable(uintptr_t address, size_t size = sizeof(void *)) const override;
        MemRegionInfo GetAddressRegionInfo(uintptr_t address) const override;
        size_t ReadBytes(uintptr_t address, void *buffer, size_t size) const override;
        bool ReadRelocationPointer(uintptr_t slot, uintptr_t &out) const override;
        ModuleInfo GetModuleInfo(const std::string &moduleName) override;
        uintptr_t FindModuleSymbol(const std::string &moduleName, const std::string &symbolName) override;
        ModuleInfo GetUnrealModule() override;
        uintptr_t FindUnrealSymbol(const std::string &symbolName) override;
        uintptr_t FindPatternInRange(uintptr_t start, size_t range, const std::string &pattern,
                                     int step = 0, uint32_t skipCount = 0) const override;
        std::vector<uintptr_t> FindAllPatternInRange(uintptr_t start, size_t range,
                                                     const std::string &pattern, int step = 0,
                                                     size_t maxHits = 0) const override;
        uintptr_t FindAlignedValueInRange(uintptr_t value, int32_t alignment,
                                          uintptr_t start, size_t range) const override;
        std::vector<uintptr_t> FindAllAlignedValuesInRange(uintptr_t value, int32_t alignment,
                                                           uintptr_t start, size_t range,
                                                           size_t maxHits = 0) const override;
        uintptr_t FindRawDataInRange(const void *data, size_t dataSize,
                                     uintptr_t start, size_t range) const override;
        std::vector<uintptr_t> FindAllRawDataInRange(const void *data, size_t dataSize,
                                                     uintptr_t start, size_t range,
                                                     size_t maxHits = 0) const override;

    private:
        void RebuildMaps();
        [[nodiscard]] bool RangeEnd(uintptr_t start, size_t range, uintptr_t &end) const;

        IMemorySource *memory_ = nullptr;
        module::ModuleImage module_;
        ModuleInfo unreal_;
        std::vector<MemRegionInfo> regions_;
    };
} // namespace nextdumper::analyzer
