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
        // 仅限制通过存储形态预筛选的唯一根，避免地址顺序截断真实对象存储
        size_t MaxSeedRoots = 1048576;
        size_t MaxHeaderCandidates = 64;
        uint64_t MaxHeaderSteps = 8000000;
        uint64_t MaxFullScanItems = 16ull * 65536;
        // 有界证据上限：只记录前 N 个 store 与每个 store 前 N 个 header
        size_t MaxStoreEvidence = 8;
        size_t MaxHeaderEvidencePerStore = 8;
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

    enum class ObjectHeaderOutcome : uint8_t
    {
        Validated,
        DerivedExceedsCount,
        FullScanRejected,
        BudgetStarved,
    };

    [[nodiscard]] const char *ObjectHeaderOutcomeName(ObjectHeaderOutcome outcome);

    struct ObjectHeaderEvidence
    {
        uintptr_t Base = 0;
        int32_t ObjectsOffset = -1;
        int32_t CountOffset = -1;
        int32_t Count = 0;
        int32_t MaxChunksOffset = -1;
        int32_t MaxChunks = 0;
        int32_t NumChunksOffset = -1;
        int32_t NumChunks = 0;
        int32_t MaxElementsOffset = -1;
        int32_t MaxElements = 0;
        int64_t Capacity = 0;
        uint64_t FullScanBudgetLeft = 0;
        ObjectHeaderOutcome Outcome = ObjectHeaderOutcome::DerivedExceedsCount;
    };

    struct ObjectFullScanEvidence
    {
        bool Scanned = false;
        int64_t Capacity = -1;
        uint64_t Tested = 0;
        uint64_t Valid = 0;
        uint64_t Empty = 0;
        uint64_t Invalid = 0;
        uint64_t InvalidBetweenValid = 0;
        int32_t DerivedCount = 0;
        bool GatesPassed = false;
        std::string GateFailure;
    };

    struct ObjectStoreEvidence
    {
        uintptr_t Root = 0;
        bool Fixed = false;
        uint64_t Order = 0;
        int32_t ItemStride = 0;
        int32_t ItemIndexOffset = -1;
        uint32_t PrefixValid = 0;
        uint32_t PrefixTested = 0;
        int32_t ChunkCount = 0;
        std::vector<uintptr_t> ChunkPointers;
        uint64_t ReferenceCount = 0;
        std::vector<uintptr_t> ReferenceSamples;
        uint64_t FullScanBudgetAtStart = 0;
        uint64_t FullScanCount = 0;
        size_t HeaderCount = 0;
        int32_t MaxHeaderCount = 0;
        std::vector<ObjectHeaderEvidence> Headers;
        std::vector<ObjectFullScanEvidence> FullScans;
        std::string Result;
    };

    struct ObjectContractScanResult
    {
        std::vector<ObjectArrayContract> Contracts;
        std::vector<UObjectLayoutContract> UObjectLayouts;
        std::vector<ObjectSeedEvidence> Seeds;
        std::vector<ObjectStoreEvidence> StoreEvidence;
        uint64_t ScannedBytes = 0;
        uint64_t Candidates = 0;
        uint64_t DiscoveredRoots = 0;
        uint64_t StorageRoots = 0;
        uint64_t RootsSkipped = 0;
        uint64_t SeedRootsProbed = 0;
        uint64_t SeedCandidates = 0;
        uint64_t ChunkStores = 0;
        uint64_t FixedStores = 0;
        uint64_t ChunkNoStorage = 0;
        uint64_t ChunkLayoutUnresolved = 0;
        uint64_t ChunkPrefixFailed = 0;
        uint64_t FixedLayoutUnresolved = 0;
        uint64_t FixedPrefixFailed = 0;
        uint64_t HeaderCandidates = 0;
        uint64_t HeaderValidations = 0;
        uint64_t StoresUnlogged = 0;
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
