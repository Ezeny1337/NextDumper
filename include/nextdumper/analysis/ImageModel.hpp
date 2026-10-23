#pragma once

#include <cstddef>
#include <cstdint>

#include "nextdumper/analysis/MemoryView.hpp"
#include "nextdumper/module/ModuleImage.hpp"

namespace nextdumper::analysis
{
    class ImageModel
    {
    public:
        ImageModel(const MemoryView &memory, const module::ModuleImage &module) noexcept;

        [[nodiscard]] bool IsValid() const;
        [[nodiscard]] const MemoryView &Memory() const { return memory_; }
        [[nodiscard]] const module::ModuleImage &Module() const { return module_; }
        [[nodiscard]] uintptr_t Base() const { return module_.base; }
        [[nodiscard]] uintptr_t End() const { return module_.end; }
        [[nodiscard]] bool Contains(uintptr_t address) const { return module_.Contains(address); }
        [[nodiscard]] size_t ModuleSegmentCount() const { return module_.segments.size(); }
        [[nodiscard]] size_t ExecutableSegmentCount() const;
        [[nodiscard]] uint64_t ExecutableBytes() const;

    private:
        const MemoryView &memory_;
        const module::ModuleImage &module_;
    };
} // namespace nextdumper::analysis
