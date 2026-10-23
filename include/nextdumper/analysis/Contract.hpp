#pragma once

#include <cstdint>
#include <vector>

namespace nextdumper::analysis
{
    enum class ContractKind : uint8_t
    {
        NamePool,
        ObjectArray,
    };

    enum class ContractState : uint8_t
    {
        Observed,
        Validated,
        Unsupported,
    };

    enum class EvidenceKind : uint8_t
    {
        GlobalBase,
        Shift,
        Mask,
        ScaleAdd,
        TableLoad,
        EntryLoad,
        HeaderLoad,
        WidthTest,
        TextOffset,
        CallArgument,
    };

    struct EvidenceStep
    {
        EvidenceKind Kind = EvidenceKind::GlobalBase;
        uintptr_t Site = 0;
        uint64_t Value = 0;
    };

    struct Contract
    {
        ContractKind Kind = ContractKind::NamePool;
        uintptr_t Root = 0;
        ContractState State = ContractState::Observed;
        std::vector<EvidenceStep> Evidence;
    };
} // namespace nextdumper::analysis
