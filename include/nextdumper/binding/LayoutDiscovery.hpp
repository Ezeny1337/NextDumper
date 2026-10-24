#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "nextdumper/memory/MemorySource.hpp"
#include "nextdumper/binding/RuntimeBinding.hpp"

namespace nextdumper::binding
{
    using ::nextdumper::memory::IMemorySource;

    struct LayoutCandidate
    {
        ObjectContainerLayout objects;
        NameContainerLayout names;
        double confidence = 0.0;
        std::string description;
    };

    struct StandardObjectLayoutResult
    {
        std::vector<std::pair<ObjectContainerLayout, double>> Layouts;
        std::vector<std::string> Evidence;
    };

    class ObjectLayoutDiscovery
    {
    public:
        explicit ObjectLayoutDiscovery(const IMemorySource &memory) : memory_(memory) {}

        [[nodiscard]] std::vector<std::pair<ObjectContainerLayout, double>> Discover(
            uintptr_t root,
            const DecodePlan &decode,
            int32_t maxCandidates = 64) const;

        [[nodiscard]] StandardObjectLayoutResult DiscoverStandard(
            uintptr_t root,
            RootTarget target,
            const DecodePlan &decode,
            int32_t maxCandidates = 16) const;

    private:
        [[nodiscard]] bool ReadPointer(uintptr_t address, uintptr_t &value) const;
        [[nodiscard]] bool ReadItemObject(uintptr_t item,
                                          int32_t objectOffset,
                                          bool packed,
                                          const DecodePlan &decode,
                                          uintptr_t &object) const;
        [[nodiscard]] bool DiscoverItemShape(uintptr_t storage,
                                             bool chunked,
                                             bool packed,
                                             int32_t elementsPerChunk,
                                             const DecodePlan &decode,
                                             int32_t &objectOffset,
                                             int32_t &itemStride,
                                             int32_t &indexOffset,
                                             double &confidence) const;

        const IMemorySource &memory_;
    };

    class NameLayoutDiscovery
    {
    public:
        explicit NameLayoutDiscovery(const IMemorySource &memory) : memory_(memory) {}

        [[nodiscard]] std::vector<std::pair<NameContainerLayout, double>> Discover(
            uintptr_t root,
            const DecodePlan &decode,
            int32_t maxCandidates = 32) const;

    private:
        [[nodiscard]] bool ReadPointer(uintptr_t address, uintptr_t &value) const;
        [[nodiscard]] bool ReadPoolEntry(uintptr_t entry,
                                         const NamePoolLayout &layout,
                                         const DecodePlan &decode,
                                         std::string &name) const;

        const IMemorySource &memory_;
    };
} // namespace nextdumper::binding
