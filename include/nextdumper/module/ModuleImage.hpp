#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace nextdumper::module
{
    enum class ModuleArchitecture
    {
        Unknown,
        Arm32,
        Arm64,
    };

    [[nodiscard]] inline const char *ModuleArchitectureName(ModuleArchitecture architecture)
    {
        switch (architecture)
        {
        case ModuleArchitecture::Arm32:
            return "ARM32";
        case ModuleArchitecture::Arm64:
            return "ARM64";
        case ModuleArchitecture::Unknown:
            break;
        }
        return "unknown";
    }

    struct ModuleImage
    {
        struct Segment
        {
            uintptr_t start = 0;
            uintptr_t end = 0;
            uint64_t fileOffset = 0;
            bool readable = false;
            bool writable = false;
            bool executable = false;
            bool privateMapping = false;
            std::string path;
        };

        uintptr_t base = 0;
        uintptr_t end = 0;
        std::string name;
        ModuleArchitecture architecture = ModuleArchitecture::Unknown;
        uint8_t pointerWidth = 0;
        std::vector<Segment> segments;
        uintptr_t loadBias = 0;
        uintptr_t dynamicAddress = 0;
        size_t dynamicSize = 0;
        std::string filePath;
        std::string fileDevice;
        uint64_t fileInode = 0;
        uint64_t imageFileOffset = 0;

        [[nodiscard]] bool IsValid() const { return base != 0 && end > base; }
        [[nodiscard]] bool Contains(uintptr_t address) const { return IsValid() && address >= base && address < end; }
        [[nodiscard]] uintptr_t ToRva(uintptr_t address) const { return Contains(address) ? address - base : 0; }
        [[nodiscard]] bool IsReadable(uintptr_t address, size_t size = 1) const;
        [[nodiscard]] bool IsExecutable(uintptr_t address, size_t size = 1) const;
        [[nodiscard]] bool IsWritable(uintptr_t address, size_t size = 1) const;
    };

} // namespace nextdumper::module
