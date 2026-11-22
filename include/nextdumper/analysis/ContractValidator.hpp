#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "nextdumper/analysis/Contract.hpp"
#include "nextdumper/analysis/MemoryView.hpp"
#include "nextdumper/decoding/NameTextCodec.hpp"

namespace nextdumper::analysis
{
    using decoding::NameTextCodec;
    using decoding::NameTextFamily;
    using decoding::NameTextFamilyName;

    struct NameValidationOptions
    {
        std::vector<uintptr_t> RootHints;
        size_t MaxSampledBlocks = 64;
        size_t SamplesPerBlock = 4;
        // 数组族按物理槽顺序抽样的条目上限（含首块与其余块）
        size_t MaxSampledEntries = 64;
    };

    struct NameValidation
    {
        size_t ContractIndex = 0;
        uintptr_t Root = 0;
        NameStoreFamily Family = NameStoreFamily::Pool;
        bool RootUsable = false;
        bool LayoutConsistent = false;
        std::string LayoutDetail;
        // 池族：块表指针与首块；数组族：chunk 表指针与首块（槽数组）
        uintptr_t BlocksAddress = 0;
        uintptr_t Block0 = 0;
        // 池族发布边界
        bool BoundaryReadable = false;
        uint32_t CurrentBlock = 0;
        uint32_t ByteCursor = 0;
        int32_t CurrentBlockOffset = -1;
        int32_t ByteCursorOffset = -1;
        uint32_t BlockSize = 0;
        uint32_t AllocatedBlocks = 0;
        std::string BoundaryDetail;
        size_t KnownMatched = 0;
        size_t KnownPlausible = 0;
        size_t KnownWalked = 0;
        std::string KnownNamesPreview;
        std::optional<NameTextCodec> Decoder;
        bool DecoderValidated = false;
        size_t Block0Samples = 0;
        size_t Block0Valid = 0;
        size_t HighBlockSamples = 0;
        size_t HighBlockValid = 0;
        size_t NarrowSamples = 0;
        size_t WideSamples = 0;
        // 数组族：条目自身 Index 是否指向它所在的物理槽
        size_t ElementIndexTested = 0;
        size_t ElementIndexMatched = 0;
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
            return IsValidated();
        }
    };

    [[nodiscard]] NameValidation ValidateNameStore(const MemoryView &memory,
                                                   const NameStoreContract &contract,
                                                   size_t contractIndex,
                                                   const NameValidationOptions &options = {});
} // namespace nextdumper::analysis
