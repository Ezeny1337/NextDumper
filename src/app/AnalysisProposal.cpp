#include "nextdumper/app/AnalysisProposal.hpp"

#include <cstddef>
#include <span>
#include <utility>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::app
{
    namespace
    {
        using ::nextdumper::analysis::AnalysisResult;
        using ::nextdumper::analysis::AnalysisStatus;
        using ::nextdumper::analysis::ContractState;
        using ::nextdumper::analysis::NamePoolFields;
        using ::nextdumper::analysis::NameTextDecoder;
        using ::nextdumper::analysis::NameTextFamilyName;
        using ::nextdumper::binding::DecodePlan;
        using ::nextdumper::binding::NameContainerKind;
        using ::nextdumper::binding::NameContainerLayout;

        std::optional<int32_t> RelativeOffset(int32_t absolute, int32_t blocksOffset)
        {
            const int64_t relative = static_cast<int64_t>(absolute) - static_cast<int64_t>(blocksOffset);
            if (relative < INT32_MIN || relative > INT32_MAX)
                return std::nullopt;
            return static_cast<int32_t>(relative);
        }
    } // namespace

    bool NameBindingProposal::IsValid() const
    {
        return root != 0 && layout.IsValid() && decode.IsValid() &&
               (layout.pool.HasPublicationBoundary() || fullBlockBound);
    }

    bool ObjectBindingProposal::IsValid() const
    {
        return root != 0 && layout.IsValid();
    }

    bool UObjectBindingProposal::IsValid() const
    {
        return objectRoot != 0 && layout.IsValid();
    }

    std::optional<NameBindingProposal> MakeNameBindingProposal(const AnalysisResult &result,
                                                               const DecodePlan &baseDecode)
    {
        if (result.AddressSpaceChanged || result.NameStatus == AnalysisStatus::Ambiguous)
            return std::nullopt;
        for (const auto &validation : result.NameValidations)
        {
            if (!validation.IsBindable() || !validation.Decoder ||
                validation.ContractIndex >= result.NamePools.size())
                continue;
            const auto &contract = result.NamePools[validation.ContractIndex];
            if (!contract.NamePool.Complete())
                continue;

            const NamePoolFields &fields = contract.NamePool;
            std::optional<int32_t> currentOffset;
            std::optional<int32_t> cursorOffset;
            if (validation.BoundaryReadable)
            {
                currentOffset = RelativeOffset(validation.CurrentBlockOffset, fields.BlocksOffset);
                cursorOffset = RelativeOffset(validation.ByteCursorOffset, fields.BlocksOffset);
                if (!currentOffset || !cursorOffset)
                    continue;
            }

            NameBindingProposal proposal;
            proposal.root = validation.Root;
            proposal.layout.kind = NameContainerKind::Pool;
            auto &pool = proposal.layout.pool;
            pool.blocksOffset = fields.BlocksOffset;
            if (currentOffset && cursorOffset)
            {
                pool.currentBlockFromBlocks = *currentOffset;
                pool.byteCursorFromBlocks = *cursorOffset;
            }
            else
            {
                proposal.fullBlockBound = true;
            }
            pool.blocksBit = fields.BlocksBit;
            pool.entryStride = fields.EntryStride;
            pool.entryHeaderOffset = fields.HeaderOffset;
            pool.entryStringOffset = fields.StringOffset;
            pool.entryLengthShift = fields.LengthShift;
            pool.entryWideMask = fields.WideMask;
            if (!proposal.layout.IsValid())
                continue;

            proposal.decode = baseDecode.IsValid() ? baseDecode : DecodePlan::Identity();
            const NameTextDecoder decoder = *validation.Decoder;
            proposal.decode.nameText = [decoder](std::span<uint8_t> bytes, uintptr_t, bool wide)
            {
                if (wide && bytes.size() % sizeof(char16_t) != 0)
                    return false;
                const size_t length = wide ? bytes.size() / sizeof(char16_t) : bytes.size();
                return decoder.Apply(bytes, length, wide);
            };
            if (!proposal.decode.IsValid() || !proposal.IsValid())
                continue;

            proposal.contractIndex = validation.ContractIndex;
            proposal.evidence = "decoder=" + std::string(NameTextFamilyName(decoder.Family)) +
                                " known_names=" + std::to_string(validation.KnownMatched) +
                                " plausible=" + std::to_string(validation.KnownPlausible) + "/" +
                                std::to_string(validation.KnownWalked) +
                                " boundary=" + std::string(proposal.fullBlockBound ? "full-block" : "located");
            if (currentOffset && cursorOffset)
            {
                proposal.evidence += " current_offset=" + std::to_string(*currentOffset) +
                                     " cursor_offset=" + std::to_string(*cursorOffset);
            }
            return proposal;
        }
        return std::nullopt;
    }

    std::optional<ObjectBindingProposal> MakeObjectBindingProposal(const AnalysisResult &result)
    {
        if (result.AddressSpaceChanged || result.ObjectStatus == AnalysisStatus::Ambiguous)
            return std::nullopt;
        for (size_t index = 0; index < result.ObjectArrays.size(); ++index)
        {
            const auto &contract = result.ObjectArrays[index];
            if (contract.State != ContractState::Validated || !contract.ObjectArray.Complete())
                continue;
            const auto &fields = contract.ObjectArray;
            ObjectBindingProposal proposal;
            proposal.root = contract.Root;
            proposal.contractIndex = index;
            if (fields.Fixed)
            {
                proposal.layout.kind = ::nextdumper::binding::ObjectContainerKind::Fixed;
                proposal.layout.objectsOffset = fields.ObjectsOffset;
                proposal.layout.numElementsOffset = fields.NumElementsOffset;
                proposal.layout.itemObjectOffset = fields.ItemObjectOffset;
                proposal.layout.itemStride = fields.ItemStride;
                proposal.layout.itemIndexOffset = fields.ItemIndexOffset;
                proposal.layout.packedPointers = fields.PackedPointers;
            }
            else
            {
                proposal.layout.kind = ::nextdumper::binding::ObjectContainerKind::Chunked;
                proposal.layout.objectsOffset = fields.ObjectsOffset;
                proposal.layout.maxElementsOffset = fields.MaxElementsOffset;
                proposal.layout.numElementsOffset = fields.NumElementsOffset;
                proposal.layout.maxChunksOffset = fields.MaxChunksOffset;
                proposal.layout.numChunksOffset = fields.NumChunksOffset;
                proposal.layout.elementsPerChunk = fields.ElementsPerChunk;
                proposal.layout.itemObjectOffset = fields.ItemObjectOffset;
                proposal.layout.itemStride = fields.ItemStride;
                proposal.layout.itemIndexOffset = fields.ItemIndexOffset;
                proposal.layout.packedPointers = fields.PackedPointers;
            }
            proposal.layout.chunkFieldsValidated = true;
            if (!proposal.IsValid())
                continue;
            proposal.evidence = "object_root=" + common::Hex(contract.Root) +
                                " object_count=" + std::to_string(contract.Observation.Count) +
                                " object_item_stride=" + std::to_string(fields.ItemStride);
            return proposal;
        }
        return std::nullopt;
    }

    std::optional<UObjectBindingProposal> MakeUObjectBindingProposal(const AnalysisResult &result,
                                                                     uintptr_t objectRoot)
    {
        if (objectRoot == 0 || result.AddressSpaceChanged || result.ObjectStatus == AnalysisStatus::Ambiguous ||
            result.UObjectStatus == AnalysisStatus::Ambiguous)
            return std::nullopt;
        for (const auto &contract : result.UObjectLayouts)
        {
            if (contract.ObjectRoot != objectRoot || !contract.UObject.Complete())
                continue;
            UObjectBindingProposal proposal;
            proposal.objectRoot = objectRoot;
            proposal.layout = {contract.UObject.Name, contract.UObject.InternalIndex,
                               contract.UObject.Class, contract.UObject.Outer};
            proposal.evidence = "uobject_offsets=name:" + std::to_string(contract.UObject.Name) +
                                " index:" + std::to_string(contract.UObject.InternalIndex) +
                                " class:" + std::to_string(contract.UObject.Class) +
                                " outer:" + std::to_string(contract.UObject.Outer);
            return proposal.IsValid() ? std::optional<UObjectBindingProposal>(std::move(proposal)) : std::nullopt;
        }
        return std::nullopt;
    }
} // namespace nextdumper::app
