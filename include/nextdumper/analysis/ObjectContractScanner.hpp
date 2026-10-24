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
        size_t MaxRejections = 12;
        size_t MaxDeepHeaders = 262144;
    };

    struct ObjectCandidateEvidence
    {
        uintptr_t Root = 0;
        uintptr_t Storage = 0;
        uintptr_t FirstObject = 0;
        int32_t MaxElements = 0;
        int32_t Count = 0;
        int32_t MaxChunks = 0;
        int32_t NumChunks = 0;
        int32_t ElementsPerChunk = 0;
        int32_t ItemStride = 0;
        int32_t ItemIndexOffset = 0;
        bool Fixed = false;
        uint32_t Tested = 0;
        uint32_t Empty = 0;
        uint32_t Shaped = 0;
        uint32_t CoreValid = 0;
        uint32_t NameDecoded = 0;
        uint32_t IndexInRange = 0;
        uint32_t ClassHits = 0;
        uint32_t OuterHits = 0;
        uint32_t FullValid = 0;
        int32_t MaxValidIndex = -1;
        int32_t FailureIndex = -1;
        uintptr_t FailureObject = 0;
        uintptr_t FailureItem = 0;
        std::string Field;
        std::string Stage;
        std::string Detail;
        std::string SampleNames;
        std::string Snapshot;
    };

    struct ObjectContractScanResult
    {
        std::vector<Contract> Contracts;
        std::vector<ObjectCandidateEvidence> Accepted;
        std::vector<ObjectCandidateEvidence> Rejections;
        uint64_t ScannedBytes = 0;
        uint64_t Candidates = 0;
        uint64_t ParentCandidates = 0;
        uint64_t DeepCandidates = 0;
        bool BudgetExhausted = false;
        bool DeepBudgetExhausted = false;
        std::string Error;
        std::string BestRejected;
    };

    [[nodiscard]] ObjectContractScanResult ScanObjectContracts(const ImageModel &image,
                                                               uintptr_t nameRoot,
                                                               const NamePoolFields &nameFields,
                                                               const NameTextDecoder &nameDecoder,
                                                               const ObjectContractScanOptions &options = {});
} // namespace nextdumper::analysis
