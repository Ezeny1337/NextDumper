#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "nextdumper/analysis/Contract.hpp"
#include "nextdumper/analysis/ImageModel.hpp"
#include "nextdumper/analysis/NameDecoderSynthesis.hpp"

namespace nextdumper::analysis
{
    struct ObjectContractScanOptions
    {
        uint64_t MaxScanBytes = 128ull * 1024 * 1024;
        size_t MaxCandidates = 16;
        size_t MaxSamples = 48;
        uint32_t MinCount = 256;
    };

    struct ObjectContractScanResult
    {
        std::vector<Contract> Contracts;
        uint64_t ScannedBytes = 0;
        uint64_t Candidates = 0;
        bool BudgetExhausted = false;
        std::string Error;
        std::string BestRejected;
    };

    [[nodiscard]] ObjectContractScanResult ScanObjectContracts(const ImageModel &image,
                                                               uintptr_t nameRoot,
                                                               const NamePoolFields &nameFields,
                                                               const NameTextDecoder &nameDecoder,
                                                               const ObjectContractScanOptions &options = {});
} // namespace nextdumper::analysis
