#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "nextdumper/analysis/Contract.hpp"
#include "nextdumper/analysis/MemoryView.hpp"
#include "nextdumper/analysis/NameDecoderSynthesis.hpp"

namespace nextdumper::analysis
{
    struct NamePoolValidationOptions
    {
        std::vector<uintptr_t> RootHints;
        size_t MaxSampledBlocks = 64;
        size_t SamplesPerBlock = 4;
    };

    struct NamePoolValidation
    {
        size_t ContractIndex = 0;
        uintptr_t Root = 0;
        bool RootUsable = false;
        bool BoundaryReadable = false;
        bool LayoutConsistent = false;
        uintptr_t BlocksAddress = 0;
        uintptr_t Block0 = 0;
        uint32_t CurrentBlock = 0;
        uint32_t ByteCursor = 0;
        int32_t CurrentBlockOffset = -1;
        int32_t ByteCursorOffset = -1;
        uint32_t BlockSize = 0;
        uint32_t AllocatedBlocks = 0;
        std::string BoundaryDetail;
        size_t ReservedPairs = 0;
        size_t ReservedMatched = 0;
        std::optional<NameTextDecoder> Decoder;
        bool DecoderValidated = false;
        size_t Block0Samples = 0;
        size_t Block0Valid = 0;
        size_t HighBlockSamples = 0;
        size_t HighBlockValid = 0;
        size_t AttemptedRoots = 0;
        std::string Failure;
        std::string FailureDetail;
        std::string FirstEntryHex;

        [[nodiscard]] bool IsValidated() const
        {
            return RootUsable && LayoutConsistent && DecoderValidated;
        }

        [[nodiscard]] bool IsBindable() const
        {
            return IsValidated() && BoundaryReadable;
        }
    };

    [[nodiscard]] NamePoolValidation ValidateNamePool(const MemoryView &memory,
                                                      const Contract &contract,
                                                      size_t contractIndex,
                                                      const NamePoolValidationOptions &options = {});
} // namespace nextdumper::analysis
