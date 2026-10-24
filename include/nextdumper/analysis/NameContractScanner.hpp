#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "nextdumper/analysis/Contract.hpp"
#include "nextdumper/analysis/FunctionIndex.hpp"
#include "nextdumper/analysis/ImageModel.hpp"
#include "nextdumper/analysis/InstructionDecoder.hpp"

namespace nextdumper::analysis
{
    struct NameContractScanOptions
    {
        uint64_t MaxInstructions = 200'000'000;
        size_t MaxContracts = 16;
    };

    struct NameContractScanResult
    {
        std::vector<Contract> Contracts;
        uint64_t Instructions = 0;
        uint64_t FunctionStarts = 0;
        bool BudgetExhausted = false;
        std::string Error;
    };

    [[nodiscard]] NameContractScanResult ScanNameContracts(const ImageModel &image,
                                                           const FunctionIndex &functions,
                                                           const InstructionDecoder &decoder,
                                                           const NameContractScanOptions &options = {});
} // namespace nextdumper::analysis
