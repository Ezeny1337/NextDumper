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

    std::optional<NameBindingProposal> MakeNameBindingProposal(const AnalysisResult &result,
                                                               const DecodePlan &baseDecode)
    {
        if (result.AddressSpaceChanged || result.NameStatus == AnalysisStatus::Ambiguous ||
            result.ObjectStatus == AnalysisStatus::Ambiguous || result.UObjectStatus == AnalysisStatus::Ambiguous)
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
            for (const auto &objectContract : result.ObjectArrays)
            {
                if (objectContract.State != ContractState::Validated ||
                    !objectContract.ObjectArray.Complete())
                    continue;
                const auto &objectFields = objectContract.ObjectArray;
                ::nextdumper::binding::ObjectContainerLayout objectLayout;
                if (objectFields.Fixed)
                {
                    objectLayout.kind = ::nextdumper::binding::ObjectContainerKind::Fixed;
                    objectLayout.objectsOffset = objectFields.ObjectsOffset;
                    objectLayout.numElementsOffset = objectFields.NumElementsOffset;
                    objectLayout.itemObjectOffset = objectFields.ItemObjectOffset;
                    objectLayout.itemStride = objectFields.ItemStride;
                    objectLayout.itemIndexOffset = objectFields.ItemIndexOffset;
                    objectLayout.packedPointers = objectFields.PackedPointers;
                    objectLayout.chunkFieldsValidated = true;
                }
                else
                {
                    objectLayout.kind = ::nextdumper::binding::ObjectContainerKind::Chunked;
                    objectLayout.objectsOffset = objectFields.ObjectsOffset;
                    objectLayout.maxElementsOffset = objectFields.MaxElementsOffset;
                    objectLayout.numElementsOffset = objectFields.NumElementsOffset;
                    objectLayout.maxChunksOffset = objectFields.MaxChunksOffset;
                    objectLayout.numChunksOffset = objectFields.NumChunksOffset;
                    objectLayout.elementsPerChunk = objectFields.ElementsPerChunk;
                    objectLayout.itemObjectOffset = objectFields.ItemObjectOffset;
                    objectLayout.itemStride = objectFields.ItemStride;
                    objectLayout.itemIndexOffset = objectFields.ItemIndexOffset;
                    objectLayout.packedPointers = objectFields.PackedPointers;
                    objectLayout.chunkFieldsValidated = true;
                }
                if (!objectLayout.IsValid())
                    continue;
                proposal.objectRoot = objectContract.Root;
                proposal.objectLayout = objectLayout;
                for (const auto &uobjectContract : result.UObjectLayouts)
                {
                    if (uobjectContract.ObjectRoot != objectContract.Root || !uobjectContract.UObject.Complete())
                        continue;
                    proposal.uobject = ::nextdumper::binding::UObjectLayoutHint{
                        uobjectContract.UObject.Name, uobjectContract.UObject.InternalIndex,
                        uobjectContract.UObject.Class, uobjectContract.UObject.Outer};
                    proposal.evidence += " uobject_offsets=name:" + std::to_string(uobjectContract.UObject.Name) +
                                         " index:" + std::to_string(uobjectContract.UObject.InternalIndex) +
                                         " class:" + std::to_string(uobjectContract.UObject.Class) +
                                         " outer:" + std::to_string(uobjectContract.UObject.Outer);
                    break;
                }
                proposal.evidence += " object_root=" + common::Hex(objectContract.Root) +
                                     " object_count=" + std::to_string(objectContract.Observation.Count) +
                                     " object_item_stride=" + std::to_string(objectFields.ItemStride);
                break;
            }
            return proposal;
        }
        return std::nullopt;
    }
} // namespace nextdumper::app
