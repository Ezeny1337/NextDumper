#pragma once

#include <optional>
#include <vector>

#include "nextdumper/binding/LayoutDiscovery.hpp"
#include "nextdumper/binding/LayoutProbes.hpp"

namespace nextdumper::binding
{
    using ::nextdumper::memory::IMemorySource;

    struct BindingCandidates
    {
        std::vector<LocatedAddress> objectRoots;
        std::vector<LocatedAddress> nameRoots;
    };

    class BindingBuilder
    {
    public:
        explicit BindingBuilder(const IMemorySource &memory) : memory_(memory) {}

        [[nodiscard]] std::optional<RuntimeBinding> Build(const BindingCandidates &candidates,
                                                          const DecodePlan &decode = DecodePlan::Identity(),
                                                          const std::function<void(const std::string &)> &progress = {},
                                                          const BindingLayoutHints &hints = {}) const;

    private:
        struct ResolvedObjectRoot
        {
            uintptr_t address = 0;
            RootTarget target = RootTarget::Unknown;
            int depth = 0;
        };

        [[nodiscard]] std::vector<uintptr_t> ResolveRoots(const std::vector<LocatedAddress> &candidates) const;
        [[nodiscard]] std::vector<ResolvedObjectRoot> ResolveObjectRoots(
            const std::vector<LocatedAddress> &candidates) const;

        const IMemorySource &memory_;
    };
} // namespace nextdumper::binding
