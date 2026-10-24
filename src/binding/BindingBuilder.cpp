#include "nextdumper/binding/BindingBuilder.hpp"

#include <algorithm>

#include "nextdumper/common/Hex.hpp"
#include "nextdumper/ue/SchemaResolver.hpp"

namespace nextdumper::binding
{
    namespace
    {
        using ::nextdumper::common::Hex;

        const char *RootTargetName(RootTarget target)
        {
            switch (target)
            {
            case RootTarget::Unknown:
                return "unknown";
            case RootTarget::GUObjectArray:
                return "guobjectarray";
            case RootTarget::ObjObjects:
                return "objobjects";
            case RootTarget::NamePool:
                return "namepool";
            }
            return "unknown";
        }

        const char *ObjectKindName(ObjectContainerKind kind)
        {
            return kind == ObjectContainerKind::Chunked ? "chunked" : "fixed";
        }

        const char *NameKindName(NameContainerKind kind)
        {
            return kind == NameContainerKind::Pool ? "pool" : "array";
        }

        std::string DescribeObjectLayout(const ObjectContainerLayout &layout)
        {
            return "kind=" + std::string(ObjectKindName(layout.kind)) +
                   " objects_offset=" + std::to_string(layout.objectsOffset) +
                   " count_offset=" + std::to_string(layout.numElementsOffset) +
                   " max_elements_offset=" + std::to_string(layout.maxElementsOffset) +
                   " max_chunks_offset=" + std::to_string(layout.maxChunksOffset) +
                   " num_chunks_offset=" + std::to_string(layout.numChunksOffset) +
                   " elements_per_chunk=" + std::to_string(layout.elementsPerChunk) +
                   " item_object_offset=" + std::to_string(layout.itemObjectOffset) +
                   " item_stride=" + std::to_string(layout.itemStride) +
                   " packed_pointers=" + std::to_string(layout.packedPointers) +
                   " item_index_offset=" + std::to_string(layout.itemIndexOffset) +
                   " chunk_fields_validated=" + std::to_string(layout.chunkFieldsValidated);
        }

        std::string DescribeNameLayout(const NameContainerLayout &layout)
        {
            if (layout.kind == NameContainerKind::Array)
            {
                return "kind=" + std::string(NameKindName(layout.kind)) +
                       " chunks_offset=" + std::to_string(layout.array.chunksOffset) +
                       " elements_per_chunk=" + std::to_string(layout.array.elementsPerChunk) +
                       " entry_index_offset=" + std::to_string(layout.array.entryIndexOffset) +
                       " entry_string_offset=" + std::to_string(layout.array.entryStringOffset);
            }

            return "kind=" + std::string(NameKindName(layout.kind)) +
                   " blocks_offset=" + std::to_string(layout.pool.blocksOffset) +
                   " current_block_from_blocks=" + (layout.pool.currentBlockFromBlocks ? std::to_string(*layout.pool.currentBlockFromBlocks) : "unknown") +
                   " byte_cursor_from_blocks=" + (layout.pool.byteCursorFromBlocks ? std::to_string(*layout.pool.byteCursorFromBlocks) : "unknown") +
                   " publication_boundary=" + std::to_string(layout.pool.HasPublicationBoundary()) +
                   " blocks_bit=" + std::to_string(layout.pool.blocksBit) +
                   " entry_stride=" + std::to_string(layout.pool.entryStride) +
                   " entry_header_offset=" + std::to_string(layout.pool.entryHeaderOffset) +
                   " entry_string_offset=" + std::to_string(layout.pool.entryStringOffset) +
                   " entry_length_shift=" + std::to_string(layout.pool.entryLengthShift) +
                   " entry_wide_mask=" + std::to_string(layout.pool.entryWideMask);
        }
    } // namespace

    std::vector<uintptr_t> BindingBuilder::ResolveRoots(const std::vector<LocatedAddress> &candidates) const
    {
        std::vector<uintptr_t> roots;
        for (const LocatedAddress &candidate : candidates)
        {
            if (candidate.address == 0)
                continue;

            auto add = [&roots](uintptr_t address)
            {
                if (address == 0 || std::find(roots.begin(), roots.end(), address) != roots.end())
                    return;
                roots.push_back(address);
            };

            if (candidate.meaning == AddressMeaning::Direct || candidate.meaning == AddressMeaning::ResolvedValue)
                add(candidate.address);

            if (candidate.meaning == AddressMeaning::PointerSlot || candidate.meaning == AddressMeaning::Direct)
            {
                uintptr_t value = 0;
                if (memory_.Read(candidate.address, value))
                    add(value);
            }
        }
        return roots;
    }

    std::vector<BindingBuilder::ResolvedObjectRoot> BindingBuilder::ResolveObjectRoots(
        const std::vector<LocatedAddress> &candidates) const
    {
        constexpr int kMaxPointerDepth = 3;
        std::vector<ResolvedObjectRoot> roots;
        const auto add = [&roots](uintptr_t address, RootTarget target, int depth)
        {
            if (address == 0 || depth > kMaxPointerDepth)
                return;
            for (ResolvedObjectRoot &root : roots)
            {
                if (root.address != address)
                    continue;
                if (root.target == RootTarget::Unknown && target != RootTarget::Unknown)
                    root.target = target;
                if (depth < root.depth)
                    root.depth = depth;
                return;
            }
            roots.push_back({address, target, depth});
        };

        for (const LocatedAddress &candidate : candidates)
        {
            if (candidate.address == 0)
                continue;
            if (candidate.meaning == AddressMeaning::Direct || candidate.meaning == AddressMeaning::ResolvedValue)
                add(candidate.address, candidate.target, 0);
            if (candidate.meaning == AddressMeaning::PointerSlot || candidate.meaning == AddressMeaning::Direct)
            {
                uintptr_t value = 0;
                if (memory_.Read(candidate.address, value))
                    add(value, candidate.target, 1);
            }
        }

        // analyzer 的 ObjObjects/GUObjectArray 候选可能是指针槽；有限追踪解引用链
        for (size_t index = 0; index < roots.size(); ++index)
        {
            if (roots[index].depth >= kMaxPointerDepth)
                continue;
            uintptr_t value = 0;
            if (!memory_.Read(roots[index].address, value) || value == 0 ||
                !memory_.IsReadable(value, sizeof(uintptr_t)))
                continue;
            add(value, roots[index].target, roots[index].depth + 1);
        }
        return roots;
    }

    std::optional<RuntimeBinding> BindingBuilder::Build(const BindingCandidates &candidates,
                                                        const DecodePlan &decode,
                                                        const std::function<void(const std::string &)> &progress,
                                                        const BindingLayoutHints &hints) const
    {
        if (!decode.IsValid() || !hints.IsValid())
        {
            if (progress)
                progress("binding_validation accepted=0 reason=invalid-decode-plan-or-layout-hint");
            return std::nullopt;
        }

        const uint64_t generation = memory_.AddressSpaceGeneration();
        const auto objectRoots = ResolveObjectRoots(candidates.objectRoots);
        const auto nameRoots = ResolveRoots(candidates.nameRoots);
        if (progress)
            progress("binding_roots candidates_objects=" + std::to_string(candidates.objectRoots.size()) +
                     " candidates_names=" + std::to_string(candidates.nameRoots.size()) +
                     " resolved_objects=" + std::to_string(objectRoots.size()) +
                     " resolved_names=" + std::to_string(nameRoots.size()));
        if (objectRoots.empty() || nameRoots.empty())
        {
            if (progress)
                progress("binding_validation accepted=0 reason=object-or-name-root-unresolved");
            return std::nullopt;
        }

        ObjectLayoutDiscovery objectDiscovery(memory_);
        NameLayoutDiscovery nameDiscovery(memory_);
        ObjectLayoutProbe objectProbe(memory_);
        NameLayoutProbe nameProbe(memory_);
        std::optional<RuntimeBinding> bestBinding;
        double bestObjectScore = -1.0;
        double bestNameScore = -1.0;
        size_t semanticRejections = 0;

        struct NameCandidates
        {
            uintptr_t root;
            std::vector<std::pair<NameContainerLayout, double>> layouts;
            std::vector<LayoutProbeReport> reports;
        };
        std::vector<NameCandidates> discoveredNames;
        for (uintptr_t nameRoot : nameRoots)
        {
            if (progress)
                progress("binding: probing name root=" + Hex(nameRoot));
            NameCandidates group{nameRoot,
                                 hints.names
                                     ? std::vector<std::pair<NameContainerLayout, double>>{{*hints.names, 1.0}}
                                     : nameDiscovery.Discover(nameRoot, decode),
                                 {}};
            for (const auto &[layout, score] : group.layouts)
            {
                (void)score;
                group.reports.push_back(nameProbe.Validate(nameRoot, layout, decode));
            }
            const size_t accepted = static_cast<size_t>(std::count_if(group.reports.begin(), group.reports.end(),
                                                                      [](const LayoutProbeReport &report)
                                                                      { return report.accepted; }));
            if (accepted > 1)
            {
                if (progress)
                    progress("binding: ambiguous name layout at root=" + Hex(nameRoot));
                for (auto &report : group.reports)
                {
                    report.accepted = false;
                    report.failures.push_back("multiple distinct name layouts passed validation");
                }
            }
            if (progress)
            {
                progress("binding_name_root root=" + Hex(nameRoot) +
                         " candidates=" + std::to_string(group.layouts.size()) +
                         " validated=" + std::to_string(accepted) + " ambiguous=" + std::to_string(accepted > 1));
                for (size_t index = 0; index < group.layouts.size(); ++index)
                {
                    const auto &report = group.reports[index];
                    progress("binding_name_candidate root=" + Hex(nameRoot) +
                             " index=" + std::to_string(index) + " " + DescribeNameLayout(group.layouts[index].first) +
                             " score=" + std::to_string(group.layouts[index].second) +
                             " accepted=" + std::to_string(report.accepted) +
                             " tested=" + std::to_string(report.tested) + " valid=" + std::to_string(report.valid));
                    for (const auto &failure : report.failures)
                        progress("binding_name_failure root=" + Hex(nameRoot) +
                                 " index=" + std::to_string(index) + " " + failure);
                    for (const auto &evidence : report.evidence)
                        progress("binding_name_evidence root=" + Hex(nameRoot) +
                                 " index=" + std::to_string(index) + " " + evidence);
                }
            }
            discoveredNames.push_back(std::move(group));
        }

        // 等价根节点必须指代相同的 table slots，而不仅仅是相同的首个 block
        // 解码器回调函数接收的是槽位地址，因此这种机制同样保证了其输入参数的稳定性
        const auto samePool = [](uintptr_t leftRoot, const NamePoolLayout &left,
                                 uintptr_t rightRoot, const NamePoolLayout &right)
        {
            const auto leftAddresses = left.Locate(leftRoot);
            const auto rightAddresses = right.Locate(rightRoot);
            if (!leftAddresses || !rightAddresses)
                return false;
            return leftAddresses->blocks == rightAddresses->blocks &&
                   leftAddresses->currentBlock == rightAddresses->currentBlock &&
                   leftAddresses->byteCursor == rightAddresses->byteCursor &&
                   left.blocksBit == right.blocksBit && left.entryStride == right.entryStride &&
                   left.entryHeaderOffset == right.entryHeaderOffset && left.entryStringOffset == right.entryStringOffset &&
                   left.entryLengthShift == right.entryLengthShift && left.entryWideMask == right.entryWideMask;
        };

        for (const ResolvedObjectRoot &objectRoot : objectRoots)
        {
            if (progress)
                progress("binding: probing object root=" + Hex(objectRoot.address) +
                         " target=" + RootTargetName(objectRoot.target) +
                         " depth=" + std::to_string(objectRoot.depth));
            std::vector<std::pair<ObjectContainerLayout, double>> objectLayouts;
            if (hints.objects)
            {
                objectLayouts = {{*hints.objects, 1.0}};
            }
            else
            {
                if (objectRoot.target != RootTarget::Unknown)
                {
                    const StandardObjectLayoutResult standard =
                        objectDiscovery.DiscoverStandard(objectRoot.address, objectRoot.target, decode);
                    for (const std::string &line : standard.Evidence)
                    {
                        if (progress)
                            progress("binding_object_standard " + line);
                    }
                    objectLayouts = standard.Layouts;
                }
                if (objectLayouts.empty())
                    objectLayouts = objectDiscovery.Discover(objectRoot.address, decode);
            }
            size_t acceptedObjectLayouts = 0;
            for (const auto &[objectLayout, objectScore] : objectLayouts)
            {
                const LayoutProbeReport objectReport = objectProbe.Validate(objectRoot.address, objectLayout, decode);
                if (progress)
                {
                    progress("binding_object_candidate root=" + Hex(objectRoot.address) + " " +
                             DescribeObjectLayout(objectLayout) + " score=" + std::to_string(objectScore) +
                             " accepted=" + std::to_string(objectReport.accepted) +
                             " tested=" + std::to_string(objectReport.tested) + " valid=" + std::to_string(objectReport.valid));
                    for (const auto &failure : objectReport.failures)
                        progress("binding_object_failure root=" + Hex(objectRoot.address) + " " + failure);
                    for (const auto &evidence : objectReport.evidence)
                        progress("binding_object_evidence root=" + Hex(objectRoot.address) + " " + evidence);
                }
                if (!objectReport.accepted)
                    continue;
                ++acceptedObjectLayouts;

                for (const auto &group : discoveredNames)
                {
                    const uintptr_t nameRoot = group.root;
                    const auto &nameLayouts = group.layouts;
                    for (size_t nameIndex = 0; nameIndex < nameLayouts.size(); ++nameIndex)
                    {
                        const auto &[nameLayout, nameScore] = nameLayouts[nameIndex];
                        const auto &nameReport = group.reports[nameIndex];
                        if (!nameReport.accepted)
                            continue;
                        if (nameLayout.kind == NameContainerKind::Pool &&
                            !nameLayout.pool.HasPublicationBoundary() &&
                            !hints.allowFullBlockNameBound)
                            continue;

                        RuntimeBinding binding;
                        binding.objectRoot = LocatedAddress{objectRoot.address, AddressMeaning::ResolvedValue, 90, "runtime-probe", objectRoot.target};
                        binding.nameRoot = LocatedAddress{nameRoot, AddressMeaning::ResolvedValue, 90, "runtime-probe"};
                        binding.objects = objectLayout;
                        binding.names = nameLayout;
                        binding.decode = decode;
                        binding.uobject = hints.uobject;
                        binding.report.staticCandidatesFound = true;
                        binding.report.objectContainerValidated = true;
                        binding.report.nameContainerValidated = true;
                        ue::SchemaResolutionReport semantics;
                        binding.report.semanticValidationPassed = ue::ValidateBindingObjects(memory_, binding, semantics);
                        if (!binding.report.semanticValidationPassed)
                        {
                            ++semanticRejections;
                            if (progress)
                            {
                                progress("binding_semantics status=rejected object_root=" + Hex(objectRoot.address) +
                                         " name_root=" + Hex(nameRoot));
                                for (const auto &failure : semantics.failures)
                                    progress("binding_semantics failure=" + failure);
                                for (const auto &evidence : semantics.evidence)
                                    progress("binding_semantics evidence=" + evidence);
                            }
                            continue;
                        }
                        binding.report.evidence.insert(binding.report.evidence.end(), semantics.evidence.begin(), semantics.evidence.end());
                        binding.report.evidence.push_back("object_root=" + Hex(objectRoot.address));
                        binding.report.evidence.push_back("name_root=" + Hex(nameRoot));
                        binding.report.evidence.push_back("object_layout_candidates=" + std::to_string(objectLayouts.size()));
                        binding.report.evidence.push_back("selected_object_layout: " + DescribeObjectLayout(objectLayout));
                        binding.report.evidence.push_back("object layout score=" + std::to_string(objectScore));
                        binding.report.evidence.push_back("object_probe tested=" + std::to_string(objectReport.tested) +
                                                          " valid=" + std::to_string(objectReport.valid) +
                                                          " confidence=" + std::to_string(objectReport.confidence));
                        binding.report.evidence.push_back("name_layout_candidates=" + std::to_string(nameLayouts.size()));
                        for (size_t candidateIndex = 0; candidateIndex < nameLayouts.size(); ++candidateIndex)
                        {
                            binding.report.evidence.push_back(
                                "name_layout_candidate[" + std::to_string(candidateIndex) + "] score=" +
                                std::to_string(nameLayouts[candidateIndex].second) + " " +
                                DescribeNameLayout(nameLayouts[candidateIndex].first));
                        }
                        binding.report.evidence.push_back("selected_name_layout: " + DescribeNameLayout(nameLayout));
                        binding.report.evidence.push_back("name layout score=" + std::to_string(nameScore));
                        binding.report.evidence.push_back("name_probe tested=" + std::to_string(nameReport.tested) +
                                                          " valid=" + std::to_string(nameReport.valid) +
                                                          " confidence=" + std::to_string(nameReport.confidence));
                        binding.report.evidence.insert(binding.report.evidence.end(), objectReport.evidence.begin(), objectReport.evidence.end());
                        binding.report.evidence.insert(binding.report.evidence.end(), nameReport.evidence.begin(), nameReport.evidence.end());
                        const bool equivalentPool = bestBinding && nameLayout.kind == NameContainerKind::Pool &&
                                                    bestBinding->names.kind == NameContainerKind::Pool &&
                                                    samePool(nameRoot, nameLayout.pool, bestBinding->nameRoot.address,
                                                             bestBinding->names.pool);
                        const bool fullerRoot = equivalentPool && nameLayout.pool.blocksOffset > 0 &&
                                                bestBinding->names.pool.blocksOffset == 0;
                        const bool aliasOfFullRoot = equivalentPool && nameLayout.pool.blocksOffset == 0 &&
                                                     bestBinding->names.pool.blocksOffset > 0;
                        if (!bestBinding || objectScore > bestObjectScore ||
                            (objectScore == bestObjectScore &&
                             (fullerRoot || (!aliasOfFullRoot && nameScore > bestNameScore))))
                        {
                            if (fullerRoot && progress)
                                progress("binding_name_equivalent previous_root=" + Hex(bestBinding->nameRoot.address) +
                                         " selected_root=" + Hex(nameRoot) + " reason=validated-full-root");
                            bestObjectScore = objectScore;
                            bestNameScore = nameScore;
                            bestBinding = std::move(binding);
                        }
                    }
                }
            }
            if (progress)
                progress("binding_object_root root=" + Hex(objectRoot.address) +
                         " target=" + RootTargetName(objectRoot.target) +
                         " depth=" + std::to_string(objectRoot.depth) +
                         " candidates=" + std::to_string(objectLayouts.size()) +
                         " accepted=" + std::to_string(acceptedObjectLayouts) +
                         " rejected=" + std::to_string(objectLayouts.size() - acceptedObjectLayouts));
        }
        if (memory_.AddressSpaceGeneration() != generation)
        {
            if (progress)
                progress("binding_validation accepted=0 reason=address-space-generation-changed");
            return std::nullopt;
        }
        if (bestBinding && progress)
            progress("binding_name_selected root=" + Hex(bestBinding->nameRoot.address) + " " +
                     DescribeNameLayout(bestBinding->names));
        if (progress)
            progress("binding_validation accepted=" + std::to_string(bestBinding.has_value()) +
                     " semantic_rejections=" + std::to_string(semanticRejections));
        return bestBinding;
    }
} // namespace nextdumper::binding
