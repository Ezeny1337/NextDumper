#pragma once

#include <array>
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
        size_t MaxSeeds = 8;
        size_t MaxSeedRoots = 262144;
        size_t MaxSeedContinuations = 8;
        int32_t MaxSeedCount = 512;
        int32_t MaxSeedContinuation = 65536;
    };

    struct ObjectSeedEvidence
    {
        uintptr_t Root = 0;
        uintptr_t Storage = 0;
        int32_t DeclaredCount = 0;
        int32_t CountOffset = -1;
        int32_t ItemStride = 0;
        int32_t ItemIndexOffset = -1;
        uint32_t PrefixValid = 0;
        uint32_t PrefixTested = 0;
        uint32_t Header0 = 0;
        uint32_t Header4 = 0;
        uint32_t Header8 = 0;
        uint32_t Header12 = 0;
        uint32_t Header16 = 0;
        uint32_t Header20 = 0;
        uint32_t Header24 = 0;
        uint32_t Header28 = 0;
        uint32_t Header32 = 0;
        bool Calibrated = false;
        int32_t NameOffset = -1;
        uint32_t NameHits = 0;
        uint32_t NameUnique = 0;
        int32_t IndexOffset = -1;
        uint32_t IndexHits = 0;
        int32_t ClassOffset = -1;
        uint32_t ClassHits = 0;
        int32_t OuterOffset = -1;
        uint32_t OuterHits = 0;
        std::string CalibrationDetail;
        bool ChunkTable = false;
        int32_t ChunkCount = 0;
        int32_t ElementsPerChunk = 0;
        std::array<int32_t, 8> ChunkValid{};
        std::array<int32_t, 8> ChunkEmpty{};
        std::array<int32_t, 8> ChunkInvalid{};
        std::array<int32_t, 8> ChunkLastValid{};
        int32_t DerivedCount = 0;
        bool HeaderFound = false;
        uintptr_t HeaderRoot = 0;
        int32_t HeaderObjectsOffset = -1;
        int32_t HeaderCountOffset = -1;
        int32_t HeaderMaxChunksOffset = -1;
        int32_t HeaderNumChunksOffset = -1;
        int32_t HeaderMaxElementsOffset = -1;
        int32_t HeaderCount = 0;
        int32_t HeaderMaxElements = 0;
        int32_t HeaderChunks = 0;
        bool ContinuationAttempted = false;
        bool Continued = false;
        int32_t ContinuationStart = 0;
        int32_t ContinuationEnd = 0;
        int32_t FirstInvalidIndex = -1;
        uintptr_t FirstInvalidObject = 0;
        int32_t LastValidIndex = -1;
        uint32_t ValidBeyond = 0;
        uint32_t EmptyBeyond = 0;
        uint32_t InvalidBeyond = 0;
        std::string ContinuationSamples;
        std::string ContinuationSnapshot;
        std::string StopReason;
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
        std::vector<ObjectArrayContract> Contracts;
        std::vector<UObjectLayoutContract> UObjectLayouts;
        std::vector<ObjectCandidateEvidence> Accepted;
        std::vector<ObjectCandidateEvidence> Rejections;
        std::vector<ObjectSeedEvidence> Seeds;
        uint64_t ScannedBytes = 0;
        uint64_t Candidates = 0;
        uint64_t ParentCandidates = 0;
        uint64_t DeepCandidates = 0;
        uint64_t SeedRootsProbed = 0;
        uint64_t SeedCandidates = 0;
        bool BudgetExhausted = false;
        bool DeepBudgetExhausted = false;
        bool SeedBudgetExhausted = false;
        bool ContractsAmbiguous = false;
        std::string Error;
        std::string BestRejected;
    };

    [[nodiscard]] ObjectContractScanResult ScanObjectContracts(const ImageModel &image,
                                                               uintptr_t nameRoot,
                                                               const NamePoolFields &nameFields,
                                                               const NameTextDecoder &nameDecoder,
                                                               const ObjectContractScanOptions &options = {});
} // namespace nextdumper::analysis
