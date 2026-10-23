#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "nextdumper/memory/MemorySource.hpp"

namespace nextdumper::analysis
{
    // 分析器只需要只读视图，避免依赖具体的内存后端实现
    class MemoryView
    {
    public:
        virtual ~MemoryView() = default;

        [[nodiscard]] virtual bool IsInitialized() const = 0;
        [[nodiscard]] virtual bool IsReadable(uintptr_t address, size_t size) const = 0;
        [[nodiscard]] virtual bool IsExecutable(uintptr_t address, size_t size) const = 0;
        [[nodiscard]] virtual memory::ReadResult ReadBytes(uintptr_t address, void *buffer, size_t size) const = 0;
        [[nodiscard]] virtual std::span<const memory::MemoryRegion> Regions() const = 0;
        [[nodiscard]] virtual uint64_t AddressSpaceGeneration() const = 0;
    };
} // namespace nextdumper::analysis
