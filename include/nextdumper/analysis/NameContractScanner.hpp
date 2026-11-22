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

    struct NameContractRecognitionStats
    {
        uint64_t BaseInstructions = 0;
        uint64_t BlockSlots = 0;
        uint64_t EntryAddresses = 0;
        uint64_t EntrySplitMismatches = 0;
        uint64_t HeaderLoads = 0;
        uint64_t RecordAttempts = 0;
        uint64_t RecordsWithoutHeader = 0;
        uint64_t RejectedBlocksOffset = 0;
        uint64_t RejectedBlocksBit = 0;
        uint64_t RejectedStride = 0;
        uint64_t RejectedHeaderOffset = 0;
        uint64_t RejectedStringOffset = 0;
        uint64_t RejectedLengthShift = 0;
        uint64_t RejectedIdMask = 0;
        uint64_t IncompleteRecords = 0;
        uint64_t ContractLimitHits = 0;

        // 数组族（无长度头的间接数组）识别链的独立计数
        uint64_t ArrayChunkShifts = 0;
        uint64_t ArrayChunkSlots = 0;
        uint64_t ArrayEntrySlots = 0;
        uint64_t ArrayEntryLoads = 0;
        uint64_t ArrayIndexLoads = 0;
        uint64_t ArrayTextBases = 0;
        uint64_t ArrayRecordAttempts = 0;
        uint64_t ArrayRecordsWithoutIndex = 0;
        uint64_t ArrayRecordsWithoutText = 0;
        uint64_t RejectedArrayChunksOffset = 0;
        uint64_t RejectedArrayChunkShift = 0;
        uint64_t RejectedArrayEntryStride = 0;
        uint64_t RejectedArrayIndexOffset = 0;
        uint64_t RejectedArrayStringOffset = 0;
    };

    struct NameContractScanResult
    {
        std::vector<NameStoreContract> Contracts;
        NameContractRecognitionStats Recognition;
        uint64_t Instructions = 0;
        uint64_t FunctionStarts = 0;
        uint64_t FetchedBytes = 0;
        uint64_t DecodedBytes = 0;
        uint64_t SkippedPrefixBytes = 0;
        size_t UnreadableSegments = 0;
        size_t SegmentsWithoutFunctionStart = 0;
        size_t ReadTruncatedSegments = 0;
        size_t DecodeTruncatedSegments = 0;
        size_t ExtentTruncatedSegments = 0;
        bool BudgetExhausted = false;
        std::string Error;

        [[nodiscard]] bool IsComplete() const
        {
            return Error.empty() && !BudgetExhausted && DecodedBytes != 0 && UnreadableSegments == 0 &&
                   SegmentsWithoutFunctionStart == 0 && ReadTruncatedSegments == 0 &&
                   DecodeTruncatedSegments == 0 && ExtentTruncatedSegments == 0 && Recognition.ContractLimitHits == 0;
        }
    };

    [[nodiscard]] NameContractScanResult ScanNameContracts(const ImageModel &image,
                                                           const FunctionIndex &functions,
                                                           const InstructionDecoder &decoder,
                                                           const NameContractScanOptions &options = {});
} // namespace nextdumper::analysis
