#include "ProbeContext.hpp"

#include <algorithm>
#include <array>
#include <unordered_set>

namespace nextdumper::ue::schema_probe
{
    std::optional<uintptr_t> SchemaProbeContext::FindObjectByName(const EngineSchema &schema,
                                                                  const std::string &name) const
    {
        if (name.empty())
            return std::nullopt;
        if (!bootstrap_ || !bootstrap_->IsValid())
            return std::nullopt;
        return session_.FindNamed(schema, name);
    }

    bool SchemaProbeContext::FindPointerField(uintptr_t first,
                                              uintptr_t expected,
                                              int32_t minOffset,
                                              int32_t maxOffset,
                                              int32_t &result) const
    {
        if (first == 0 || expected == 0 || minOffset < 0 || maxOffset < minOffset)
            return false;
        for (int32_t offset = minOffset; offset <= maxOffset; offset += static_cast<int32_t>(sizeof(uintptr_t)))
        {
            const auto address = Add(first, offset);
            if (!address)
                continue;
            uintptr_t value = 0;
            if (ReadPointer(memory_, *address, value) && value == expected)
            {
                result = offset;
                return true;
            }
        }
        return false;
    }

    bool SchemaProbeContext::FindInt32Field(uintptr_t object,
                                            int32_t expected,
                                            int32_t minOffset,
                                            int32_t maxOffset,
                                            int32_t &result) const
    {
        if (object == 0 || minOffset < 0 || maxOffset < minOffset)
            return false;
        for (int32_t offset = minOffset; offset <= maxOffset; offset += 4)
        {
            const auto address = Add(object, offset);
            if (!address)
                continue;
            int32_t value = 0;
            if (memory_.Read(*address, value) && value == expected)
            {
                result = offset;
                return true;
            }
        }
        return false;
    }

    bool SchemaProbeContext::ResolveUObjectSchema(EngineSchema &schema, SchemaResolutionReport &report) const
    {
        // 前两个具有不同 InternalIndex 值的存活对象提供了一个保守的 bootstrap 基准
        // 具体的 class/name/outer 语义将在后续进行验证，本阶段绝不接受单个偶然碰巧相等的整数
        if (!bootstrap_ || !bootstrap_->IsValid())
        {
            report.failures.push_back(bootstrap_ && !bootstrap_->failure.empty()
                                          ? bootstrap_->failure
                                          : "schema bootstrap is unavailable");
            return false;
        }

        const auto &samples = bootstrap_->objectSamples;
        const auto &uobjectHint = binding_.uobject;
        const bool hasUObjectHint = uobjectHint.has_value() && uobjectHint->IsValid();
        if (hasUObjectHint)
        {
            report.evidence.push_back("UObject layout hint from analysis name=" +
                                      std::to_string(uobjectHint->name) +
                                      " index=" + std::to_string(uobjectHint->internalIndex) +
                                      " class=" + std::to_string(uobjectHint->classPointer) +
                                      " outer=" + std::to_string(uobjectHint->outer));
        }

        schema.fname.comparisonIndex = 0;
        schema.fname.size = schema.features.outlineNumberName
                                ? (schema.features.casePreservingName ? 0x8 : 0x4)
                                : (schema.features.casePreservingName ? 0xC : 0x8);
        schema.fname.numberLayout = schema.features.outlineNumberName ? FNameNumberLayout::Outlined
                                                                      : FNameNumberLayout::Inline;
        schema.fname.displayLayout = schema.features.fnameDisplayLayout;
        schema.fname.displayIndex = schema.features.casePreservingName
                                        ? (schema.features.outlineNumberName
                                               ? 0x4
                                               : (schema.features.fnameDisplayLayout == FNameDisplayLayout::BeforeNumber ? 0x4 : 0x8))
                                        : -1;
        schema.fname.number = schema.features.outlineNumberName
                                  ? -1
                                  : (schema.features.fnameDisplayLayout == FNameDisplayLayout::BeforeNumber ? 0x8 : 0x4);

        const NameStoreReader bootstrapNames(memory_, binding_.nameRoot.address, binding_.names, binding_.decode,
                                             schema.fname, schema.features);

        // 通过已验证的 name 容器解码候选的 int32 值，以此定位 FName 字段
        // 一个有效的字段必须能在多个互不相关的 UObject 上生成合理的名称，而绝不能仅仅依靠单个可读的索引
        static constexpr const char *knownNames[] = {
            "None", "Object", "Class", "Struct", "Field", "Package", "Function",
            "ScriptStruct", "Guid", "Color", "Vector", "World", "Engine"};
        int32_t bestNameOffset = -1;
        int32_t bestNameScore = 0;
        int32_t bestNameHits = 0;
        int32_t bestKnownHits = 0;
        int32_t bestUniqueHits = 0;
        std::vector<std::string> bestNameSamples;
        for (int32_t offset = 0; offset <= 0x70; offset += 4)
        {
            // FName 在 UE5 的 outline-number 配置下可以只有一个 4 字节的 ComparisonIndex
            // 因此候选必须按 uint32 对齐扫描，完整的 Name/Outer/内存关系验证负责排除半字段误报

            int32_t hits = 0;
            int32_t knownHits = 0;
            std::unordered_set<std::string> uniqueNames;
            std::vector<std::string> candidateSamples;
            for (const auto &[index, object] : samples)
            {
                int32_t rawNameIndex = 0;
                const auto address = Add(object, offset);
                if (!address || !memory_.Read(*address, rawNameIndex))
                    continue;
                rawNameIndex = binding_.decode.nameIndex(rawNameIndex, *address);
                const auto name = bootstrapNames.ReadName(rawNameIndex);
                if (name && !name->empty() && name->size() <= 1024)
                {
                    ++hits;
                    uniqueNames.insert(*name);
                    for (const char *known : knownNames)
                    {
                        if (*name == known)
                        {
                            ++knownHits;
                            break;
                        }
                    }
                    if (candidateSamples.size() < 8)
                    {
                        candidateSamples.push_back("object_index=" + std::to_string(index) +
                                                   " raw_name_index=" + std::to_string(rawNameIndex) +
                                                   " name=" + *name);
                    }
                }
            }
            const int32_t uniqueHits = static_cast<int32_t>(uniqueNames.size());
            // 相比于重复命中一小组已知常量，算法应优先选择具有名称多样性的方案
            // 真正的 UObject::Name 字段应当展现出许多不同的对象名称，包含零值或重复 bookkeeping values 的字段
            // 绝不能仅仅因为这些值能解码为已知名称就胜出
            const int32_t score = uniqueHits * 100 + knownHits * 20 + hits + 10;
            if (hits > 0)
            {
                report.evidence.push_back("UObject::Name candidate offset=" + std::to_string(offset) +
                                          " hits=" + std::to_string(hits) +
                                          " unique_names=" + std::to_string(uniqueHits) +
                                          " known_names=" + std::to_string(knownHits) +
                                          " score=" + std::to_string(score));
            }
            if (score > bestNameScore)
            {
                bestNameScore = score;
                bestNameHits = hits;
                bestKnownHits = knownHits;
                bestUniqueHits = uniqueHits;
                bestNameOffset = offset;
                bestNameSamples = std::move(candidateSamples);
            }
        }
        report.evidence.push_back("UObject::Name best candidate offset=" + std::to_string(bestNameOffset) +
                                  " score=" + std::to_string(bestNameScore) +
                                  " hits=" + std::to_string(bestNameHits) +
                                  " unique_names=" + std::to_string(bestUniqueHits) +
                                  " known_names=" + std::to_string(bestKnownHits));
        for (const std::string &sample : bestNameSamples)
            report.evidence.push_back("UObject::Name sample: " + sample);
        if (bestNameHits < 8 || bestKnownHits < 1 || bestUniqueHits < 8)
        {
            report.failures.push_back("UObject::Name did not decode consistently through the validated name store; valid_names=" +
                                      std::to_string(bestNameHits) + " unique_names=" + std::to_string(bestUniqueHits) +
                                      " known_names=" + std::to_string(bestKnownHits));
            return false;
        }
        if (hasUObjectHint)
            bestNameOffset = uobjectHint->name;
        schema.uobject.name = bestNameOffset;
        report.evidence.push_back("UObject::Name offset=" + std::to_string(bestNameOffset) +
                                  " valid_names=" + std::to_string(bestNameHits) +
                                  " unique_names=" + std::to_string(bestUniqueHits) +
                                  " known_names=" + std::to_string(bestKnownHits));

        struct FNameLayoutCandidate
        {
            int32_t size = 0;
            bool casePreserving = false;
            bool outlineNumber = false;
            FNameDisplayLayout displayLayout = FNameDisplayLayout::None;
            int32_t validObjects = 0;
            int32_t sampleHits = 0;
            int32_t nullHits = 0;
            int32_t comparisonHits = 0;
            int32_t displayHits = 0;
            int32_t displayConsistentHits = 0;
            int32_t displayMismatchHits = 0;
            int32_t displayNoneHits = 0;
            int32_t numberReadable = 0;
            int32_t nonZeroNumberHits = 0;
            int32_t numberIndexHits = 0;
            int32_t uniqueNames = 0;

            [[nodiscard]] FNamePhysicalLayout PhysicalLayout() const
            {
                const int32_t displayIndex = casePreserving
                                                 ? (outlineNumber || displayLayout == FNameDisplayLayout::BeforeNumber ? 0x4 : 0x8)
                                                 : -1;
                const int32_t number = outlineNumber
                                           ? -1
                                           : (displayLayout == FNameDisplayLayout::BeforeNumber ? 0x8 : 0x4);
                return FNamePhysicalLayout{size,
                                           0,
                                           number,
                                           displayIndex,
                                           outlineNumber ? FNameNumberLayout::Outlined : FNameNumberLayout::Inline};
            }
        };
        std::vector<FNameLayoutCandidate> fnameCandidates;
        const std::array<FNameLayoutCandidate, 5> layoutSeeds = {
            FNameLayoutCandidate{0x8, false, false, FNameDisplayLayout::None},
            FNameLayoutCandidate{0xC, true, false, FNameDisplayLayout::BeforeNumber},
            FNameLayoutCandidate{0xC, true, false, FNameDisplayLayout::AfterNumber},
            FNameLayoutCandidate{0x4, false, true, FNameDisplayLayout::None},
            FNameLayoutCandidate{0x8, true, true, FNameDisplayLayout::AfterNumber},
        };
        const std::unordered_set<uintptr_t> sampleObjects = [&samples]()
        {
            std::unordered_set<uintptr_t> result;
            for (const auto &[index, object] : samples)
            {
                (void)index;
                result.insert(object);
            }
            return result;
        }();
        const int32_t pointerSize = static_cast<int32_t>(sizeof(uintptr_t));
        const auto asciiEqualIgnoreCase = [](const std::string &left, const std::string &right)
        {
            if (left.size() != right.size())
                return false;
            for (size_t index = 0; index < left.size(); ++index)
            {
                const auto lower = [](char value)
                {
                    return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value;
                };
                if (lower(left[index]) != lower(right[index]))
                    return false;
            }
            return true;
        };
        struct KnownFieldSpan
        {
            int32_t offset = -1;
            int32_t size = 0;
        };
        std::vector<KnownFieldSpan> knownFieldSpans;
        if (hasUObjectHint)
        {
            knownFieldSpans.push_back({uobjectHint->classPointer, static_cast<int32_t>(sizeof(uintptr_t))});
            knownFieldSpans.push_back({uobjectHint->internalIndex, static_cast<int32_t>(sizeof(int32_t))});
            knownFieldSpans.push_back({uobjectHint->outer, static_cast<int32_t>(sizeof(uintptr_t))});
        }
        const auto overlapsKnownField = [&](int32_t offset, int32_t size)
        {
            for (const KnownFieldSpan &span : knownFieldSpans)
            {
                if (span.offset < 0 || span.size <= 0)
                    continue;
                if (offset < span.offset + span.size && span.offset < offset + size)
                    return true;
            }
            return false;
        };
        for (FNameLayoutCandidate candidate : layoutSeeds)
        {
            if (hasUObjectHint && overlapsKnownField(schema.uobject.name, candidate.size))
                continue;
            const int32_t nameEnd = schema.uobject.name + candidate.size;
            const std::array<int32_t, 2> outerOffsets = {
                (nameEnd + pointerSize - 1) / pointerSize * pointerSize,
                (nameEnd + static_cast<int32_t>(sizeof(int32_t)) + pointerSize - 1) / pointerSize * pointerSize};
            for (size_t outerIndex = 0; outerIndex < outerOffsets.size(); ++outerIndex)
            {
                const int32_t outerOffset = outerOffsets[outerIndex];
                if (outerIndex != 0 && outerOffset == outerOffsets[0])
                    continue;

                int32_t validObjects = 0;
                int32_t sampleHits = 0;
                int32_t nullHits = 0;
                for (const auto &[index, object] : samples)
                {
                    (void)index;
                    const auto address = Add(object, outerOffset);
                    if (!address)
                        continue;
                    uintptr_t value = 0;
                    if (!memory_.Read(*address, value))
                        continue;
                    value = binding_.decode.objectOuter(value, *address);
                    if (value == 0)
                    {
                        ++nullHits;
                        continue;
                    }
                    if (value != object && IsReadablePointer(memory_, value))
                    {
                        ++validObjects;
                        if (sampleObjects.contains(value))
                            ++sampleHits;
                    }
                }

                if (validObjects > candidate.validObjects ||
                    (validObjects == candidate.validObjects && sampleHits > candidate.sampleHits))
                {
                    candidate.validObjects = validObjects;
                    candidate.sampleHits = sampleHits;
                    candidate.nullHits = nullHits;
                }
            }

            FNameSchema candidateSchema;
            candidateSchema.comparisonIndex = 0;
            candidateSchema.size = candidate.size;
            candidateSchema.numberLayout = candidate.outlineNumber ? FNameNumberLayout::Outlined
                                                                   : FNameNumberLayout::Inline;
            candidateSchema.displayLayout = candidate.displayLayout;
            candidateSchema.displayIndex = candidate.casePreserving
                                               ? (candidate.outlineNumber ||
                                                          candidate.displayLayout == FNameDisplayLayout::BeforeNumber
                                                      ? 0x4
                                                      : 0x8)
                                               : -1;
            candidateSchema.number = candidate.outlineNumber
                                         ? -1
                                         : (candidate.displayLayout == FNameDisplayLayout::BeforeNumber ? 0x8 : 0x4);
            EngineFeatures candidateFeatures = schema.features;
            candidateFeatures.casePreservingName = candidate.casePreserving;
            candidateFeatures.outlineNumberName = candidate.outlineNumber;
            candidateFeatures.fnameDisplayLayout = candidate.displayLayout;
            const NameStoreReader candidateNames(memory_, binding_.nameRoot.address, binding_.names,
                                                 binding_.decode, candidateSchema, candidateFeatures);
            std::unordered_set<std::string> candidateNamesSeen;
            for (const auto &[index, object] : samples)
            {
                (void)index;
                const auto address = Add(object, schema.uobject.name);
                if (!address)
                    continue;

                int32_t rawComparisonIndex = 0;
                if (!memory_.Read(*address, rawComparisonIndex))
                    continue;
                rawComparisonIndex = binding_.decode.nameIndex(rawComparisonIndex, *address);
                const auto comparisonName = candidateNames.ReadName(rawComparisonIndex);
                if (comparisonName && !comparisonName->empty())
                {
                    ++candidate.comparisonHits;
                    candidateNamesSeen.insert(*comparisonName);
                }

                if (candidateSchema.displayIndex >= 0)
                {
                    const auto displayAddress = Add(*address, candidateSchema.displayIndex);
                    int32_t rawDisplayIndex = 0;
                    if (displayAddress && memory_.Read(*displayAddress, rawDisplayIndex))
                    {
                        rawDisplayIndex = binding_.decode.nameIndex(rawDisplayIndex, *displayAddress);
                        const auto displayName = candidateNames.ReadName(rawDisplayIndex);
                        if (displayName && !displayName->empty())
                        {
                            ++candidate.displayHits;
                            if (asciiEqualIgnoreCase(*displayName, "None"))
                                ++candidate.displayNoneHits;
                            else if (comparisonName && asciiEqualIgnoreCase(*displayName, *comparisonName))
                                ++candidate.displayConsistentHits;
                            else
                                ++candidate.displayMismatchHits;
                        }
                    }
                }

                if (candidateSchema.number >= 0)
                {
                    const auto numberAddress = Add(*address, candidateSchema.number);
                    uint32_t number = 0;
                    if (numberAddress && memory_.Read(*numberAddress, number))
                    {
                        ++candidate.numberReadable;
                        if (number != 0)
                            ++candidate.nonZeroNumberHits;
                        if (number == static_cast<uint32_t>(index))
                            ++candidate.numberIndexHits;
                    }
                }
            }
            candidate.uniqueNames = static_cast<int32_t>(candidateNamesSeen.size());
            if (candidate.displayMismatchHits > 0)
                continue;
            if (candidate.numberIndexHits * 2 > static_cast<int32_t>(samples.size()))
                continue;
            if (hasUObjectHint)
            {
                if (candidate.comparisonHits < 8)
                    continue;
            }
            else if (candidate.validObjects < 3)
                continue;
            fnameCandidates.push_back(candidate);
        }
        if (fnameCandidates.empty())
        {
            report.failures.push_back("FName layout candidate did not produce a valid UObject::Outer relation");
            return false;
        }
        std::vector<FNameLayoutCandidate> uniqueFNameCandidates;
        for (const FNameLayoutCandidate &candidate : fnameCandidates)
        {
            const auto existing = std::find_if(uniqueFNameCandidates.begin(), uniqueFNameCandidates.end(),
                                               [&](const FNameLayoutCandidate &other)
                                               { return candidate.PhysicalLayout() == other.PhysicalLayout(); });
            if (existing == uniqueFNameCandidates.end())
                uniqueFNameCandidates.push_back(candidate);
            else if (candidate.comparisonHits > existing->comparisonHits ||
                     (candidate.comparisonHits == existing->comparisonHits &&
                      candidate.displayConsistentHits > existing->displayConsistentHits))
                *existing = candidate;
        }
        fnameCandidates = std::move(uniqueFNameCandidates);

        const auto fnameScore = [hasUObjectHint, &schema](const FNameLayoutCandidate &candidate)
        {
            int score = candidate.comparisonHits * 10 + candidate.uniqueNames * 5 +
                        candidate.numberReadable * 4 + candidate.displayConsistentHits * 2;
            if (hasUObjectHint)
            {
                // profile 只做低权重先验；运行时 number/display 证据优先，避免再次出现把 InternalIndex 当 display
                if (candidate.casePreserving == schema.features.casePreservingName)
                    score += 100;
                if (candidate.outlineNumber == schema.features.outlineNumberName)
                    score += 200;
            }
            else
            {
                score += candidate.validObjects * 100 + candidate.sampleHits * 25 +
                         candidate.displayHits + candidate.nullHits;
            }
            return score;
        };
        const auto betterFNameEvidence = [](const FNameLayoutCandidate &left, const FNameLayoutCandidate &right)
        {
            if (left.comparisonHits != right.comparisonHits)
                return left.comparisonHits > right.comparisonHits;
            if (left.uniqueNames != right.uniqueNames)
                return left.uniqueNames > right.uniqueNames;
            if (left.displayConsistentHits != right.displayConsistentHits)
                return left.displayConsistentHits > right.displayConsistentHits;
            if (left.displayMismatchHits != right.displayMismatchHits)
                return left.displayMismatchHits < right.displayMismatchHits;
            if (left.displayNoneHits != right.displayNoneHits)
                return left.displayNoneHits < right.displayNoneHits;
            if (left.displayHits != right.displayHits)
                return left.displayHits > right.displayHits;
            if (left.numberReadable != right.numberReadable)
                return left.numberReadable > right.numberReadable;
            return left.nonZeroNumberHits > right.nonZeroNumberHits;
        };
        std::sort(fnameCandidates.begin(), fnameCandidates.end(), [&](const FNameLayoutCandidate &left, const FNameLayoutCandidate &right)
                  {
                      const int leftScore = fnameScore(left);
                      const int rightScore = fnameScore(right);
                      return leftScore != rightScore ? leftScore > rightScore : betterFNameEvidence(left, right); });
        const auto hasConsistentDisplayEvidence = [](const FNameLayoutCandidate &candidate)
        {
            return candidate.displayConsistentHits > 0 && candidate.displayMismatchHits == 0 &&
                   candidate.displayNoneHits == 0;
        };
        const auto nonCasePreserving = std::find_if(fnameCandidates.begin(), fnameCandidates.end(),
                                                    [](const FNameLayoutCandidate &candidate)
                                                    { return !candidate.casePreserving; });
        const auto casePreserving = std::find_if(fnameCandidates.begin(), fnameCandidates.end(),
                                                 hasConsistentDisplayEvidence);
        if (!hasUObjectHint && nonCasePreserving != fnameCandidates.end() &&
            (casePreserving == fnameCandidates.end() ||
             fnameScore(*nonCasePreserving) >= fnameScore(*casePreserving)))
        {
            const FNameLayoutCandidate selected = *nonCasePreserving;
            fnameCandidates.erase(nonCasePreserving);
            fnameCandidates.insert(fnameCandidates.begin(), selected);
        }
        const auto sameFNameEvidence = [](const FNameLayoutCandidate &left, const FNameLayoutCandidate &right)
        {
            return left.validObjects == right.validObjects && left.sampleHits == right.sampleHits &&
                   left.nullHits == right.nullHits && left.comparisonHits == right.comparisonHits &&
                   left.displayHits == right.displayHits && left.displayConsistentHits == right.displayConsistentHits &&
                   left.displayMismatchHits == right.displayMismatchHits && left.displayNoneHits == right.displayNoneHits &&
                   left.numberReadable == right.numberReadable && left.nonZeroNumberHits == right.nonZeroNumberHits &&
                   left.uniqueNames == right.uniqueNames;
        };
        if (fnameCandidates.size() > 1 && sameFNameEvidence(fnameCandidates[0], fnameCandidates[1]))
        {
            report.ambiguous = true;
            report.failures.push_back("FName layout candidates are ambiguous; top_score=" +
                                      std::to_string(fnameScore(fnameCandidates[0])) +
                                      " distinct_physical_layouts=" + std::to_string(fnameCandidates.size()) +
                                      " evidence_equal=1");
            return false;
        }
        const FNameLayoutCandidate &selectedFNameCandidate = fnameCandidates.front();
        const FNameLayoutCandidate selectedFName = selectedFNameCandidate;
        schema.features.casePreservingName = selectedFName.casePreserving;
        schema.features.outlineNumberName = selectedFName.outlineNumber;
        schema.features.fnameDisplayLayout = selectedFName.displayLayout;
        schema.fname.size = selectedFName.size;
        schema.fname.numberLayout = selectedFName.outlineNumber ? FNameNumberLayout::Outlined
                                                                : FNameNumberLayout::Inline;
        schema.fname.displayLayout = selectedFName.displayLayout;
        schema.fname.displayIndex = selectedFName.casePreserving
                                        ? (selectedFName.outlineNumber || selectedFName.displayLayout == FNameDisplayLayout::BeforeNumber
                                               ? 0x4
                                               : 0x8)
                                        : -1;
        schema.fname.number = selectedFName.outlineNumber
                                  ? -1
                                  : (selectedFName.displayLayout == FNameDisplayLayout::BeforeNumber ? 0x8 : 0x4);
        const NameStoreReader names(memory_, binding_.nameRoot.address, binding_.names, binding_.decode,
                                    schema.fname, schema.features);
        report.evidence.push_back("resolved FName layout; size=" + std::to_string(schema.fname.size) +
                                  " case_preserving=" + std::to_string(schema.features.casePreservingName) +
                                  " outline_number=" + std::to_string(schema.features.outlineNumberName) +
                                  " display_layout=" +
                                  std::to_string(static_cast<int>(schema.features.fnameDisplayLayout)) +
                                  " outer_valid=" + std::to_string(selectedFName.validObjects) +
                                  " outer_samples=" + std::to_string(selectedFName.sampleHits) +
                                  " comparison_hits=" + std::to_string(selectedFName.comparisonHits) +
                                  " display_hits=" + std::to_string(selectedFName.displayHits) +
                                  " display_consistent=" + std::to_string(selectedFName.displayConsistentHits) +
                                  " display_mismatch=" + std::to_string(selectedFName.displayMismatchHits) +
                                  " display_none=" + std::to_string(selectedFName.displayNoneHits) +
                                  " number_readable=" + std::to_string(selectedFName.numberReadable) +
                                  " unique_names=" + std::to_string(selectedFName.uniqueNames) +
                                  " source=" + std::string(hasUObjectHint ? "analysis-constrained" : "candidate"));

        // Class 是一个指针字段，其指向的目标本身就是一个可读的 UObject
        // 评分候选偏移量时，应同时结合指针的有效性以及通过上述定位到的字段解码目标对象名称的能力
        int32_t bestClassOffset = -1;
        int32_t bestClassHits = 0;
        for (int32_t offset = static_cast<int32_t>(sizeof(uintptr_t)); offset <= 0x70; offset += 4)
        {
            int32_t hits = 0;
            for (const auto &[index, object] : samples)
            {
                (void)index;
                const auto address = Add(object, offset);
                if (!address)
                    continue;
                uintptr_t classAddress = 0;
                if (!memory_.Read(*address, classAddress) || !IsReadablePointer(memory_, classAddress))
                    continue;
                const auto classNameAddress = Add(classAddress, bestNameOffset);
                if (!classNameAddress)
                    continue;
                int32_t rawClassName = 0;
                if (!memory_.Read(*classNameAddress, rawClassName))
                    continue;
                rawClassName = binding_.decode.nameIndex(rawClassName, *classNameAddress);
                if (names.ReadName(rawClassName))
                    ++hits;
            }
            if (hits > bestClassHits)
            {
                bestClassHits = hits;
                bestClassOffset = offset;
            }
        }
        if (!hasUObjectHint && bestClassHits < 3)
        {
            report.failures.push_back("UObject::Class did not decode consistently through the validated name store");
            return false;
        }
        schema.uobject.classPointer = hasUObjectHint ? uobjectHint->classPointer : bestClassOffset;

        for (int32_t offset = static_cast<int32_t>(sizeof(uintptr_t)); offset <= 0x80; offset += 4)
        {
            bool matches = true;
            for (const auto &[index, object] : samples)
            {
                const auto address = Add(object, offset);
                if (!address)
                {
                    matches = false;
                    break;
                }
                int32_t value = 0;
                if (!memory_.Read(*address, value) || value != index)
                {
                    matches = false;
                    break;
                }
            }
            if (matches && schema.uobject.internalIndex < 0)
            {
                schema.uobject.internalIndex = offset;
                break;
            }
        }
        if (hasUObjectHint)
            schema.uobject.internalIndex = uobjectHint->internalIndex;

        if (schema.uobject.internalIndex < 0)
        {
            report.failures.push_back("UObject::InternalIndex was not resolved");
            return false;
        }

        if (schema.uobject.classPointer < 0)
        {
            report.failures.push_back("UObject::Class was not resolved");
            return false;
        }

        if (hasUObjectHint)
        {
            schema.uobject.outer = uobjectHint->outer;
            report.evidence.push_back("resolved UObject::Outer from analysis hint offset=" +
                                      std::to_string(uobjectHint->outer));
        }
        else
        {
            // 同时核对标准尾部与可选的四字节对象列表索引布局
            const int32_t nameEnd = schema.uobject.name + schema.fname.size;
            const int32_t firstOuterOffset = ((nameEnd + pointerSize - 1) / pointerSize) * pointerSize;
            const int32_t indexedOuterOffset =
                ((nameEnd + static_cast<int32_t>(sizeof(int32_t)) + pointerSize - 1) / pointerSize) * pointerSize;
            const auto readObjectName = [&](uintptr_t object)
            { return ReadObjectName(memory_, binding_, schema, names, object); };
            struct OuterCandidateEvidence
            {
                int32_t offset = -1;
                size_t validObjects = 0;
                size_t sampleHits = 0;
                size_t nullHits = 0;
            };
            std::vector<OuterCandidateEvidence> outerCandidates;
            const auto inspectOuterCandidate = [&](int32_t offset)
            {
                OuterCandidateEvidence candidate;
                candidate.offset = offset;
                for (const auto &[index, object] : samples)
                {
                    (void)index;
                    const auto address = Add(object, offset);
                    if (!address)
                        continue;
                    uintptr_t value = 0;
                    if (!memory_.Read(*address, value))
                        continue;
                    value = binding_.decode.objectOuter(value, *address);
                    if (value == 0)
                    {
                        ++candidate.nullHits;
                        continue;
                    }
                    if (value == object || !IsReadablePointer(memory_, value) || !readObjectName(value))
                        continue;
                    ++candidate.validObjects;
                    if (sampleObjects.contains(value))
                        ++candidate.sampleHits;
                }
                return candidate;
            };
            const std::array<int32_t, 2> sourceOuterOffsets = {firstOuterOffset, indexedOuterOffset};
            for (const int32_t offset : sourceOuterOffsets)
            {
                if (offset == schema.uobject.classPointer ||
                    std::any_of(outerCandidates.begin(), outerCandidates.end(), [offset](const auto &candidate)
                                { return candidate.offset == offset; }))
                    continue;
                outerCandidates.push_back(inspectOuterCandidate(offset));
            }
            const auto betterOuterEvidence = [](const OuterCandidateEvidence &left, const OuterCandidateEvidence &right)
            {
                if (left.validObjects != right.validObjects)
                    return left.validObjects > right.validObjects;
                return left.sampleHits > right.sampleHits;
            };
            std::sort(outerCandidates.begin(), outerCandidates.end(), betterOuterEvidence);
            for (const auto &candidate : outerCandidates)
            {
                report.evidence.push_back("UObject::Outer source-layout candidate offset=" +
                                          std::to_string(candidate.offset) + " valid_objects=" +
                                          std::to_string(candidate.validObjects) + " sampled_objects=" +
                                          std::to_string(candidate.sampleHits) + " null_objects=" +
                                          std::to_string(candidate.nullHits));
            }
            if (outerCandidates.empty() || outerCandidates.front().validObjects < 3)
            {
                report.failures.push_back("UObject::Outer source-layout candidates were rejected; standard_offset=" +
                                          std::to_string(firstOuterOffset) +
                                          " indexed_offset=" + std::to_string(indexedOuterOffset) +
                                          " best_valid_objects=" +
                                          std::to_string(outerCandidates.empty() ? 0 : outerCandidates.front().validObjects));
                return false;
            }
            if (outerCandidates.size() > 1 &&
                outerCandidates[0].validObjects == outerCandidates[1].validObjects &&
                outerCandidates[0].sampleHits == outerCandidates[1].sampleHits)
            {
                report.ambiguous = true;
                report.failures.push_back("UObject::Outer source-layout candidates are ambiguous; offsets=" +
                                          std::to_string(outerCandidates[0].offset) + "," +
                                          std::to_string(outerCandidates[1].offset) + " valid_objects=" +
                                          std::to_string(outerCandidates[0].validObjects) + " sampled_objects=" +
                                          std::to_string(outerCandidates[0].sampleHits));
                return false;
            }
            const OuterCandidateEvidence &selectedOuter = outerCandidates.front();
            schema.uobject.outer = selectedOuter.offset;
            report.evidence.push_back("resolved UObject::Outer from validated source-layout candidate offset=" +
                                      std::to_string(selectedOuter.offset) +
                                      " object_list_index_candidate=" +
                                      std::to_string(selectedOuter.offset == indexedOuterOffset &&
                                                     indexedOuterOffset != firstOuterOffset));
        }

        int32_t bestFlagsOffset = -1;
        int32_t bestFlagsHits = 0;
        for (int32_t offset = static_cast<int32_t>(sizeof(uintptr_t)); offset <= 0x40; offset += 4)
        {
            int32_t hits = 0;
            for (const auto &[index, object] : samples)
            {
                (void)index;
                const auto address = Add(object, offset);
                if (!address)
                    continue;
                int32_t rawFlags = 0;
                if (!memory_.Read(*address, rawFlags))
                    continue;
                const uint32_t flags = static_cast<uint32_t>(binding_.decode.objectFlags(rawFlags, *address));
                if ((flags & 0xFFFF0000u) == 0 && (flags & 0x1u) != 0)
                    ++hits;
            }
            if (hits > bestFlagsHits)
            {
                bestFlagsHits = hits;
                bestFlagsOffset = offset;
            }
        }
        if (bestFlagsHits >= 3)
            schema.uobject.flags = bestFlagsOffset;
        else
        {
            std::vector<uintptr_t> flagObjects;
            for (int32_t index = 0; index < bootstrap_->objects->Count() && flagObjects.size() < 256; ++index)
            {
                const auto object = bootstrap_->objects->ReadObject(index);
                if (object.IsValid())
                    flagObjects.push_back(object.address);
            }
            for (int32_t offset = static_cast<int32_t>(sizeof(uintptr_t)); offset <= 0x40; offset += 4)
            {
                int32_t hits = 0;
                for (uintptr_t object : flagObjects)
                {
                    const auto address = Add(object, offset);
                    if (!address)
                        continue;
                    int32_t rawFlags = 0;
                    if (!memory_.Read(*address, rawFlags))
                        continue;
                    const uint32_t flags = static_cast<uint32_t>(binding_.decode.objectFlags(rawFlags, *address));
                    if (flags == 0x43u)
                        ++hits;
                }
                if (hits >= 3)
                {
                    schema.uobject.flags = offset;
                    break;
                }
            }
        }
        if (schema.uobject.flags < 0)
        {
            report.failures.push_back("UObject::Flags was not resolved");
            return false;
        }

        report.evidence.push_back("resolved UObject::InternalIndex and UObject::Class bootstrap fields");
        report.evidence.push_back("resolved UObject::Name through name-store cross-validation");
        return true;
    }

    bool SchemaProbeContext::ValidateUObjectSchema(EngineSchema &schema, SchemaResolutionReport &report) const
    {
        if (!bootstrap_ || !bootstrap_->IsValid() || schema.uobject.internalIndex < 0 || schema.uobject.classPointer < 0)
            return false;
        ObjectModelReader model(memory_, binding_, schema);
        if (!model.Initialize())
        {
            report.failures.push_back("object model initialization failed during UObject/name association validation");
            return false;
        }
        size_t valid = 0;
        size_t indexFailures = 0;
        size_t nameFailures = 0;
        size_t classFailures = 0;
        size_t outerFailures = 0;
        size_t classStoreFailures = 0;
        size_t outerStoreFailures = 0;
        size_t classNameFailures = 0;
        size_t metaClassFailures = 0;
        size_t metaStoreFailures = 0;
        size_t metaNameFailures = 0;
        std::unordered_set<std::string> objectNames, classNames;
        const auto inStore = [&](uintptr_t address)
        {
            const auto index = model.InternalIndex(address);
            return index && *index >= 0 && *index < bootstrap_->objects->Count() &&
                   bootstrap_->objects->ReadObject(*index).address == address;
        };
        const size_t extent = static_cast<size_t>(std::max(schema.uobject.outer + static_cast<int32_t>(sizeof(uintptr_t)),
                                                           schema.uobject.name + schema.fname.size));
        for (const auto &[index, address] : bootstrap_->objectSamples)
        {
            const auto internalIndex = model.InternalIndex(address);
            const auto cls = model.Class(address);
            const auto name = model.Name(address);
            const auto outer = model.Outer(address);
            if (!internalIndex || *internalIndex != index)
            {
                ++indexFailures;
                continue;
            }
            if (!name || name->empty())
            {
                ++nameFailures;
                continue;
            }
            if (!cls)
            {
                ++classFailures;
                continue;
            }
            if (!outer)
            {
                ++outerFailures;
                continue;
            }
            if (!memory_.IsReadable(*cls, extent))
            {
                ++classFailures;
                continue;
            }
            if (!inStore(*cls))
            {
                ++classStoreFailures;
                continue;
            }
            if (*outer && (!memory_.IsReadable(*outer, extent) || !inStore(*outer)))
            {
                ++outerStoreFailures;
                continue;
            }
            const auto className = model.Name(*cls);
            if (!className || className->empty())
            {
                ++classNameFailures;
                continue;
            }
            const auto metaClass = model.Class(*cls);
            if (!metaClass)
            {
                ++metaClassFailures;
                continue;
            }
            if (!memory_.IsReadable(*metaClass, extent))
            {
                ++metaClassFailures;
                continue;
            }
            if (!inStore(*metaClass))
            {
                ++metaStoreFailures;
                continue;
            }
            if (model.Name(*metaClass) != std::optional<std::string>("Class"))
            {
                ++metaNameFailures;
                continue;
            }
            ++valid;
            objectNames.insert(*name);
            classNames.insert(*className);
        }
        const size_t tested = bootstrap_->objectSamples.size();
        const bool accepted = valid >= 5 && valid * 5 >= tested * 4 && objectNames.size() >= 3 && classNames.size() >= 2;
        report.evidence.push_back("UObject/name association tested=" + std::to_string(tested) + " valid=" + std::to_string(valid) +
                                  " distinct_names=" + std::to_string(objectNames.size()) + " distinct_classes=" + std::to_string(classNames.size()) +
                                  " stages index=" + std::to_string(indexFailures) +
                                  " name=" + std::to_string(nameFailures) +
                                  " class=" + std::to_string(classFailures) +
                                  " outer=" + std::to_string(outerFailures) +
                                  " cls_store=" + std::to_string(classStoreFailures) +
                                  " outer_store=" + std::to_string(outerStoreFailures) +
                                  " cls_name=" + std::to_string(classNameFailures) +
                                  " meta=" + std::to_string(metaClassFailures) +
                                  " meta_store=" + std::to_string(metaStoreFailures) +
                                  " meta_name=" + std::to_string(metaNameFailures));
        if (!accepted)
            report.failures.push_back("UObject names, class identities and outers did not agree with the object store");
        return accepted;
    }
} // namespace nextdumper::ue::schema_probe
