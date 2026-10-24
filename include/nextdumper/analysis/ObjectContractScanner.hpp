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
        size_t MaxSamples = 32;
        size_t MaxSeeds = 8;
        size_t MaxSeedRoots = 262144;
        size_t MaxHeaderCandidates = 64;
        uint64_t MaxHeaderSteps = 8000000;
        uint64_t MaxFullScanItems = 16ull * 65536;
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
    };

    struct ObjectContractScanResult
    {
        std::vector<ObjectArrayContract> Contracts;
        std::vector<UObjectLayoutContract> UObjectLayouts;
        std::vector<ObjectSeedEvidence> Seeds;
        uint64_t ScannedBytes = 0;
        uint64_t Candidates = 0;
        uint64_t SeedRootsProbed = 0;
        uint64_t SeedCandidates = 0;
        bool BudgetExhausted = false;
        bool SeedBudgetExhausted = false;
        bool ContractsAmbiguous = false;
        std::string Error;
    };

    [[nodiscard]] ObjectContractScanResult ScanObjectContracts(const ImageModel &image,
                                                               uintptr_t nameRoot,
                                                               const NamePoolFields &nameFields,
                                                               const NameTextDecoder &nameDecoder,
                                                               const ObjectContractScanOptions &options = {});
} // namespace nextdumper::analysis
