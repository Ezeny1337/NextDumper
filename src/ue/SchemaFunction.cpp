#include "ProbeContext.hpp"
#include "nextdumper/common/Hex.hpp"
#include "nextdumper/ue/FunctionSemantics.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace nextdumper::ue::schema_probe
{
    using ::nextdumper::common::Hex;

    bool SchemaProbeContext::ResolveFunctionSchema(EngineSchema &schema, SchemaResolutionReport &report) const
    {
        if (!bootstrap_ || !bootstrap_->IsValid())
        {
            report.failures.push_back("schema bootstrap unavailable for function schema");
            return false;
        }
        NameStoreReader names(memory_, binding_.nameRoot.address, binding_.names, binding_.decode,
                              schema.fname, schema.features);

        const auto readObjectName = [&](uintptr_t object)
        { return ReadObjectName(memory_, binding_, schema, names, object); };

        struct FunctionSample
        {
            uintptr_t address = 0;
            FieldKind kind = FieldKind::Unknown;
            std::string className;
            std::string name;
            uint32_t objectFlags = 0;
            bool parameterChainValid = false;
            ProbeSampleState parameterChainState = ProbeSampleState::NotObserved;
            FieldChainStatus chainStatus = FieldChainStatus::Empty;
            std::vector<PropertyMetadata> properties;
        };

        std::vector<FunctionSample> functions;
        ObjectModelReader model(memory_, binding_, schema);
        if (!model.Initialize())
        {
            report.failures.push_back("object model could not be initialized for UFunction parameter validation");
            return false;
        }
        size_t excludedDefaultObjects = 0;
        size_t excludedLoadingObjects = 0;
        size_t functionObjects = 0;
        std::unordered_map<std::string, size_t> classSampleCounts;
        const auto sampleLimitFor = [](const std::string &className)
        {
            return NormalizeRuntimeFieldName(className) == "Function" ? size_t{48} : size_t{16};
        };
        for (const auto &object : session_.Objects(schema))
        {
            if (functions.size() >= 96)
                break;
            const FieldKind kind = FieldKindFromRuntimeName(object.className, false);
            if (!IsFunctionFieldKind(kind))
                continue;
            ++functionObjects;
            // CDO 属于 UFunction 的实例，但它们并不是已被链接的函数定义
            // 采样资格不可依赖于候选的 FunctionFlags 偏移量
            const uint32_t objectFlags = object.flags;
            if ((objectFlags & kRFClassDefaultObject) != 0)
            {
                ++excludedDefaultObjects;
                if (excludedDefaultObjects <= 8)
                    report.evidence.push_back("excluded UFunction CDO address=" + Hex(object.address) +
                                              " class=" + object.className + " object_flags=" + std::to_string(objectFlags));
                continue;
            }
            if ((objectFlags & kRFIncompleteLoad) != 0)
            {
                ++excludedLoadingObjects;
                continue;
            }
            const size_t limit = sampleLimitFor(object.className);
            if (classSampleCounts[object.className] >= limit)
                continue;
            ++classSampleCounts[object.className];
            functions.push_back(FunctionSample{object.address,
                                               kind,
                                               object.className,
                                               object.name,
                                               objectFlags,
                                               false,
                                               ProbeSampleState::NotObserved,
                                               FieldChainStatus::Empty,
                                               {}});
        }
        report.probeLimited = session_.indexLimited;
        const std::string sampleSummary = " samples=" + std::to_string(functions.size()) +
                                          " excluded_cdo=" + std::to_string(excludedDefaultObjects) +
                                          " excluded_loading=" + std::to_string(excludedLoadingObjects) +
                                          " index_limited=" + std::to_string(session_.indexLimited);
        report.evidence.push_back("UFunction sample eligibility;" + sampleSummary);
        report.evidence.push_back("UFunction cdo ratio: function_objects=" + std::to_string(functionObjects) +
                                  " excluded_cdo=" + std::to_string(excludedDefaultObjects) +
                                  " objects=" + std::to_string(session_.Objects(schema).size()) +
                                  " index_limited=" + std::to_string(session_.indexLimited));
        {
            constexpr size_t kFlagProbeObjects = 256;
            std::vector<uintptr_t> probeAddresses;
            for (const auto &object : session_.Objects(schema))
            {
                if (probeAddresses.size() >= kFlagProbeObjects)
                    break;
                if (!IsFunctionFieldKind(FieldKindFromRuntimeName(object.className, false)))
                    continue;
                probeAddresses.push_back(object.address);
            }
            std::string probe;
            for (int32_t offset = 8; offset <= 0x30 && !probeAddresses.empty(); offset += 4)
            {
                size_t flagged = 0;
                for (const uintptr_t address : probeAddresses)
                {
                    const auto at = Add(address, offset);
                    uint32_t value = 0;
                    if (at && memory_.Read(*at, value) && (value & kRFClassDefaultObject) != 0)
                        ++flagged;
                }
                probe += " @" + std::to_string(offset) + "=" +
                         std::to_string(flagged * 100 / probeAddresses.size()) + "%";
            }
            if (!probe.empty())
                report.evidence.push_back("UFunction flags offset probe (cdo rate per offset, objects=" +
                                          std::to_string(probeAddresses.size()) + "):" + probe);
        }
        if (functions.size() < 2)
        {
            report.failures.push_back("not enough UFunction definition samples;" + sampleSummary);
            return false;
        }

        // 通过两个函数对象解析 UField::Next
        // 下一个指针（Next）可能为空，因此在可用时，应利用前两个链表条目中的字段名称来进行解析
        const int32_t nextStart = schema.uobject.outer >= 0
                                      ? schema.uobject.outer + static_cast<int32_t>(sizeof(uintptr_t))
                                      : 0x20;
        for (int32_t offset = nextStart; offset <= 0x100 && schema.ufield.next < 0; offset += 4)
        {
            size_t readable = 0;
            size_t named = 0;
            for (const FunctionSample &sample : functions)
            {
                uintptr_t next = 0;
                const auto address = Add(sample.address, offset);
                if (!address || !memory_.Read(*address, next))
                    continue;
                if (next == 0)
                {
                    ++readable;
                    continue;
                }
                const auto nextName = Add(next, schema.uobject.name);
                if (!IsReadablePointer(memory_, next) || !nextName || !memory_.IsReadable(*nextName, sizeof(int32_t)))
                    continue;
                ++readable;
                if (readObjectName(next))
                    ++named;
            }
            if (readable == functions.size() && named > 0)
                schema.ufield.next = offset;
        }
        if (schema.ufield.next < 0)
        {
            report.failures.push_back("UField::Next was not resolved from UFunction samples; scan_start=" +
                                      std::to_string(nextStart));
            return false;
        }

        // 记录每个函数的参数字段形状
        // 基于 UObject 的字段与 FField 采用不同的 UStruct 属性链表
        // 当前的生效链表是根据已验证的字段系统候选方案动态选择的，而非依赖版本标签
        const int32_t propertyChainOffset = schema.features.useFProperty ? schema.ustruct.childProperties
                                                                         : schema.ustruct.children;
        for (FunctionSample &sample : functions)
        {
            const auto firstAddress = Add(sample.address, propertyChainOffset);
            uintptr_t current = 0;
            if (!firstAddress || !memory_.Read(*firstAddress, current))
            {
                sample.parameterChainState = ProbeSampleState::Unreadable;
                continue;
            }

            if (current == 0)
            {
                sample.parameterChainValid = true;
                sample.parameterChainState = ProbeSampleState::SemanticMatch;
                sample.chainStatus = FieldChainStatus::Empty;
                continue;
            }

            const FieldChainResult chain = model.FieldsWithStatus(current, 256);
            sample.chainStatus = chain.status;
            if (chain.status == FieldChainStatus::LimitExceeded)
            {
                report.sampleTruncated = true;
                report.searchComplete = false;
            }
            bool valid = chain.Complete();
            for (const FieldMetadata &field : chain.fields)
            {
                if (schema.features.useFProperty &&
                    (!field.ownerIsUObject || field.ownerAddress == 0 || field.ownerAddress != sample.address))
                {
                    valid = false;
                    sample.parameterChainState = ProbeSampleState::SemanticMismatch;
                    break;
                }
                if (!IsPropertyFieldKind(field.kind))
                    continue;
                // Parameter semantics consume only the integer header. Subtype payloads
                // belong to the Property stage and must not add Function dependencies or reads.
                PropertyMetadata property;
                static_cast<FieldMetadata &>(property) = field;
                const auto read = [&](int32_t offset, auto &value)
                {
                    const auto address = Add(field.address, offset);
                    return address && memory_.Read(*address, value);
                };
                if (!read(schema.property.arrayDim, property.arrayDim) || !read(schema.property.elementSize, property.elementSize) ||
                    !read(schema.property.propertyFlags, property.flags) || !read(schema.property.offsetInternal, property.offset) ||
                    property.arrayDim <= 0 || property.elementSize <= 0 || property.offset < 0)
                {
                    valid = false;
                    sample.parameterChainState = ProbeSampleState::SemanticMismatch;
                    break;
                }
                sample.properties.push_back(std::move(property));
            }
            sample.parameterChainValid = valid && chain.Complete();
            if (sample.parameterChainValid)
                sample.parameterChainState = ProbeSampleState::SemanticMatch;
            else if (sample.parameterChainState == ProbeSampleState::NotObserved)
                sample.parameterChainState = ProbeSampleState::Unreadable;
        }
        size_t reportedInvalidChains = 0;
        for (const FunctionSample &sample : functions)
        {
            if (!sample.parameterChainValid)
                report.evidenceComplete = false;
            if (!sample.parameterChainValid && reportedInvalidChains < 8)
            {
                report.evidence.push_back("UFunction parameter chain rejected address=" + Hex(sample.address) +
                                          " function=" + sample.name + " class=" + sample.className +
                                          " chain_status=" + std::to_string(static_cast<int>(sample.chainStatus)) +
                                          " sample_state=" + std::to_string(static_cast<int>(sample.parameterChainState)));
                ++reportedInvalidChains;
            }
        }

        // UE 按以下顺序声明 UFunction 自身字段：
        //
        //   EFunctionFlags FunctionFlags;
        //   uint8         NumParms;
        //   uint16        ParmsSize;
        constexpr uint32_t kFunctionFlagEvidenceMask =
            0x00000040u | // FUNC_Net
            0x00000200u | // FUNC_Exec
            0x00000400u | // FUNC_Native
            0x00000800u | // FUNC_Event
            0x00010000u | // FUNC_MulticastDelegate
            0x00020000u | // FUNC_Public
            0x00040000u | // FUNC_Private
            0x00080000u | // FUNC_Protected
            0x00100000u | // FUNC_Delegate
            0x00400000u | // FUNC_HasOutParms
            0x04000000u | // FUNC_BlueprintCallable
            0x08000000u;  // FUNC_BlueprintEvent

        const auto isPlausibleFunctionFlags = [&](uint32_t flags)
        {
            return flags != 0 && flags != 0xCDCDCDCDu &&
                   (flags & kFunctionFlagEvidenceMask) != 0;
        };
        const auto isPlausibleParameterShape = [](uint8_t numParams, uint16_t paramSize)
        {
            // 有参数的函数必须预留参数存储空间，没有参数的函数不能声明一个任意的非零大小
            return (numParams == 0 && paramSize == 0) ||
                   (numParams != 0 && paramSize != 0);
        };

        // PropertiesSize 是字段偏移，而不是 sizeof(UStruct)
        // 这里只把它用作下界锚点，后面的参数链一致性检查才是候选字段的语义验证
        const int32_t pointerSize = static_cast<int32_t>(sizeof(uintptr_t));
        int32_t functionDataStart = schema.ustruct.propertiesSizeOffset >= 0
                                        ? schema.ustruct.propertiesSizeOffset + static_cast<int32_t>(sizeof(int32_t))
                                        : 0;
        functionDataStart = (functionDataStart + 3) & ~3;

        // UFunction::Func 紧跟在固定的参数字段之后，且其前方可能会存在可选的 Event-Graph 或 Live-Coding 成员
        // 将此结构保留为一组源码兼容的偏移量增量布局族，并由可执行指针证据在运行时选择生效的变体
        const std::vector<int32_t> nativeFunctionDeltas =
            pointerSize == 4
                ? std::vector<int32_t>{0x14, 0x1C, 0x20, 0x28}
                : std::vector<int32_t>{0x18, 0x20, 0x28, 0x30, 0x38};

        struct FunctionObservation
        {
            bool readable = false;
            bool flagsPlausible = false;
            uint32_t flags = 0;
            uint8_t numParams = 0;
            uint16_t paramSize = 0;
            uint16_t returnOffset = 0;
            FunctionParameterSummary summary;
            bool shapeMatches = false;
            bool returnMatches = false;
        };
        struct FunctionCandidate
        {
            int32_t offset = -1;
            size_t headerReadable = 0;
            size_t headerReadFailures = 0;
            size_t flagHits = 0;
            size_t shapeHits = 0;
            size_t returnHits = 0;
            size_t flagFailures = 0;
            size_t shapeFailures = 0;
            size_t returnFailures = 0;
            size_t countMismatches = 0;
            size_t sizeMismatches = 0;
            size_t returnMismatches = 0;
            size_t bothMismatches = 0;
            size_t invalidShapes = 0;
            size_t parameterizedSamples = 0;
            size_t returningSamples = 0;
            std::vector<FunctionObservation> observations;
        };
        FunctionCandidate best;
        FunctionCandidate bestObserved;
        size_t equivalentHeaderCandidates = 0;
        size_t parameterChainSamples = 0;
        for (const FunctionSample &sample : functions)
            parameterChainSamples += sample.parameterChainValid ? 1u : 0u;
        for (const auto &[className, count] : classSampleCounts)
            report.evidence.push_back("UFunction sample class=" + className + " count=" + std::to_string(count));

        const size_t minimumHeaderSamples = std::max<size_t>(4, parameterChainSamples / 2);

        const auto betterHeaderCandidate = [](const FunctionCandidate &left, const FunctionCandidate &right)
        {
            if (left.shapeHits != right.shapeHits)
                return left.shapeHits > right.shapeHits;
            if (left.flagHits != right.flagHits)
                return left.flagHits > right.flagHits;
            if (left.returnHits != right.returnHits)
                return left.returnHits > right.returnHits;
            if (left.invalidShapes != right.invalidShapes)
                return left.invalidShapes < right.invalidShapes;
            if (left.bothMismatches != right.bothMismatches)
                return left.bothMismatches < right.bothMismatches;
            if (left.countMismatches != right.countMismatches)
                return left.countMismatches < right.countMismatches;
            if (left.sizeMismatches != right.sizeMismatches)
                return left.sizeMismatches < right.sizeMismatches;
            if (left.headerReadable != right.headerReadable)
                return left.headerReadable > right.headerReadable;
            return false;
        };
        const auto isHardValidHeaderCandidate = [&](const FunctionCandidate &candidate)
        {
            return candidate.offset >= 0 && candidate.headerReadable >= minimumHeaderSamples &&
                   candidate.flagHits == candidate.headerReadable &&
                   candidate.shapeHits == candidate.headerReadable &&
                   candidate.returnHits == candidate.headerReadable &&
                   candidate.invalidShapes == 0 && candidate.countMismatches == 0 &&
                   candidate.sizeMismatches == 0 && candidate.bothMismatches == 0 &&
                   candidate.returnMismatches == 0;
        };
        for (int32_t offset = functionDataStart; offset <= 0x200; offset += 4)
        {
            FunctionCandidate candidate;
            candidate.offset = offset;
            candidate.observations.resize(functions.size());
            for (size_t index = 0; index < functions.size(); ++index)
            {
                const FunctionSample &sample = functions[index];
                if (!sample.parameterChainValid)
                    continue;

                FunctionObservation &observation = candidate.observations[index];
                const auto flagsAddress = Add(sample.address, offset);
                std::array<uint8_t, 10> header{};
                if (!flagsAddress || !memory_.ReadBytes(*flagsAddress, header.data(), header.size()).Ok())
                {
                    ++candidate.headerReadFailures;
                    continue;
                }
                observation.readable = true;
                std::memcpy(&observation.flags, header.data(), sizeof(observation.flags));
                observation.numParams = header[4];
                std::memcpy(&observation.paramSize, header.data() + 6, sizeof(observation.paramSize));
                std::memcpy(&observation.returnOffset, header.data() + 8, sizeof(observation.returnOffset));
                const uint32_t flags = observation.flags;
                const uint8_t numParams = observation.numParams;
                const uint16_t paramSize = observation.paramSize;
                observation.flagsPlausible = isPlausibleFunctionFlags(flags);
                observation.summary = AnalyzeFunctionParameters(
                    sample.properties, flags, schema.features.functionDefaultsContinueAfterInitializer);
                ++candidate.headerReadable;
                if (!observation.flagsPlausible)
                {
                    ++candidate.flagFailures;
                    continue;
                }

                ++candidate.flagHits;
                const FunctionParameterSummary &summary = observation.summary;
                const bool countMatches = summary.valid && summary.count <= 0xFF && numParams == summary.count;
                const bool sizeMatches = summary.valid && summary.paramEnd >= 0 &&
                                         summary.paramEnd <= 0xFFFF && paramSize == summary.paramEnd;
                if (!isPlausibleParameterShape(numParams, paramSize))
                {
                    ++candidate.invalidShapes;
                    ++candidate.shapeFailures;
                }
                else if (countMatches && sizeMatches)
                {
                    observation.shapeMatches = true;
                    ++candidate.shapeHits;
                    candidate.parameterizedSamples += summary.count != 0 ? 1u : 0u;
                    candidate.returningSamples += summary.returnOffset >= 0 ? 1u : 0u;
                }
                else if (!countMatches && !sizeMatches)
                {
                    ++candidate.bothMismatches;
                    ++candidate.shapeFailures;
                }
                else if (!countMatches)
                {
                    ++candidate.countMismatches;
                    ++candidate.shapeFailures;
                }
                else
                {
                    ++candidate.sizeMismatches;
                    ++candidate.shapeFailures;
                }

                const uint16_t expectedReturnOffset = summary.returnOffset >= 0
                                                          ? static_cast<uint16_t>(summary.returnOffset)
                                                          : std::numeric_limits<uint16_t>::max();
                observation.returnMatches = summary.valid && observation.returnOffset == expectedReturnOffset;
                if (observation.returnMatches)
                    ++candidate.returnHits;
                else
                {
                    ++candidate.returnMismatches;
                    ++candidate.returnFailures;
                }
            }

            const auto sameHeaderEvidence = [](const FunctionCandidate &left, const FunctionCandidate &right)
            {
                return left.headerReadable == right.headerReadable && left.shapeHits == right.shapeHits &&
                       left.flagHits == right.flagHits &&
                       left.returnHits == right.returnHits && left.invalidShapes == right.invalidShapes &&
                       left.bothMismatches == right.bothMismatches &&
                       left.countMismatches == right.countMismatches &&
                       left.sizeMismatches == right.sizeMismatches &&
                       left.returnMismatches == right.returnMismatches;
            };
            if (candidate.flagHits >= minimumHeaderSamples || candidate.shapeHits >= minimumHeaderSamples)
                report.evidence.push_back("UFunction header candidate offset=" + std::to_string(offset) +
                                          " readable=" + std::to_string(candidate.headerReadable) +
                                          " flags=" + std::to_string(candidate.flagHits) +
                                          " shapes=" + std::to_string(candidate.shapeHits) +
                                          " returns=" + std::to_string(candidate.returnHits) +
                                          " parameterized=" + std::to_string(candidate.parameterizedSamples) +
                                          " returning=" + std::to_string(candidate.returningSamples) +
                                          " hard_valid=" + std::to_string(isHardValidHeaderCandidate(candidate)));
            if (bestObserved.offset < 0 || betterHeaderCandidate(candidate, bestObserved))
                bestObserved = candidate;

            if (!isHardValidHeaderCandidate(candidate))
            {
                ++report.rejectedCandidates;
                continue;
            }

            if (best.offset < 0 || betterHeaderCandidate(candidate, best))
            {
                best = candidate;
                equivalentHeaderCandidates = 1;
            }
            else if (sameHeaderEvidence(candidate, best))
                ++equivalentHeaderCandidates;
        }

        const FunctionCandidate &diagnosticCandidate = best.offset >= 0 ? best : bestObserved;
        const bool parameterSemanticsComplete = isHardValidHeaderCandidate(best);
        const std::string candidateSummary = " selected_flags=" + std::to_string(diagnosticCandidate.flagHits) +
                                             " header_readable=" + std::to_string(diagnosticCandidate.headerReadable) +
                                             " selected_header_read_failures=" + std::to_string(diagnosticCandidate.headerReadFailures) +
                                             " flag_failures=" + std::to_string(diagnosticCandidate.flagFailures) +
                                             " selected_shapes=" + std::to_string(diagnosticCandidate.shapeHits) +
                                             " selected_returns=" + std::to_string(diagnosticCandidate.returnHits) +
                                             " parameterized_samples=" + std::to_string(diagnosticCandidate.parameterizedSamples) +
                                             " returning_samples=" + std::to_string(diagnosticCandidate.returningSamples) +
                                             " selected_offset=" + std::to_string(diagnosticCandidate.offset) +
                                             " hard_valid=" + std::to_string(isHardValidHeaderCandidate(best)) +
                                             " parameter_chain_offset=" + std::to_string(propertyChainOffset) +
                                             " parameter_semantics=" +
                                             std::string(parameterSemanticsComplete ? "complete" : "partial") +
                                             " property_flags_offset=" + std::to_string(schema.property.propertyFlags) +
                                             sampleSummary;
        if (!parameterSemanticsComplete)
        {
            report.evidence.push_back("UFunction structural layout found but parameter semantics were incomplete;" +
                                      candidateSummary + " count_mismatch=" +
                                      std::to_string(diagnosticCandidate.countMismatches) + " size_mismatch=" +
                                      std::to_string(diagnosticCandidate.sizeMismatches) + " both_mismatch=" +
                                      std::to_string(diagnosticCandidate.bothMismatches) + " invalid_shape=" +
                                      std::to_string(diagnosticCandidate.invalidShapes) + " return_mismatch=" +
                                      std::to_string(diagnosticCandidate.returnMismatches));
            size_t reportedParameters = 0;
            for (size_t sampleIndex = 0; sampleIndex < functions.size() && reportedParameters < 8; ++sampleIndex)
            {
                for (const PropertyMetadata &parameter : functions[sampleIndex].properties)
                {
                    if (reportedParameters >= 8)
                        break;
                    report.evidence.push_back("UFunction parameter sample=" + std::to_string(sampleIndex) +
                                              " name=" + parameter.name + " class=" + parameter.className +
                                              " flags=" + std::to_string(parameter.flags) +
                                              " cpf_parm=" + std::to_string((parameter.flags & kCPFParm) != 0) +
                                              " offset=" + std::to_string(parameter.offset) +
                                              " element_size=" + std::to_string(parameter.elementSize) +
                                              " array_dim=" + std::to_string(parameter.arrayDim));
                    ++reportedParameters;
                }
            }
        }
        if (best.offset < 0 || !parameterSemanticsComplete || equivalentHeaderCandidates > 1)
        {
            report.ambiguous = equivalentHeaderCandidates > 1;
            std::string mismatchSamples;
            std::string returnSamples;
            size_t reportedSamples = 0;
            size_t reportedReturnSamples = 0;
            for (size_t index = 0; index < functions.size() && reportedSamples < 3; ++index)
            {
                const FunctionSample &sample = functions[index];
                if (!sample.parameterChainValid || diagnosticCandidate.offset < 0)
                    continue;
                const FunctionObservation &observation = diagnosticCandidate.observations[index];
                if (!observation.readable || !observation.flagsPlausible || observation.shapeMatches)
                    continue;
                mismatchSamples += " sample_index=" + std::to_string(index) +
                                   " function=" + sample.name + " class=" + sample.className +
                                   " expected_count=" + std::to_string(observation.summary.count) +
                                   " actual_count=" + std::to_string(observation.numParams) +
                                   " expected_size=" + std::to_string(observation.summary.paramEnd) +
                                   " actual_size=" + std::to_string(observation.paramSize);
                ++reportedSamples;
            }
            for (size_t index = 0; index < functions.size() && reportedReturnSamples < 8; ++index)
            {
                const FunctionSample &sample = functions[index];
                if (!sample.parameterChainValid || diagnosticCandidate.offset < 0)
                    continue;
                const FunctionObservation &observation = diagnosticCandidate.observations[index];
                if (observation.readable && observation.flagsPlausible && observation.returnMatches)
                    continue;
                const FunctionParameterSummary &summary = observation.summary;
                const uint16_t expectedReturnOffset = summary.returnOffset >= 0
                                                          ? static_cast<uint16_t>(summary.returnOffset)
                                                          : std::numeric_limits<uint16_t>::max();
                returnSamples += " sample_index=" + std::to_string(index) +
                                 " address=" + Hex(sample.address) +
                                 " function=" + sample.name + " class=" + sample.className +
                                 " object_flags=" + std::to_string(sample.objectFlags) +
                                 " readable=" + std::to_string(observation.readable) +
                                 " flags=" + std::to_string(observation.flags) +
                                 " flags_plausible=" + std::to_string(observation.flagsPlausible) +
                                 " scored=" + std::to_string(observation.readable && observation.flagsPlausible) +
                                 " summary_valid=" + std::to_string(summary.valid) +
                                 " properties=" + std::to_string(sample.properties.size()) +
                                 " derived_count=" + std::to_string(summary.count) +
                                 " actual=" + std::to_string(observation.returnOffset) +
                                 " expected=" + std::to_string(expectedReturnOffset);
                ++reportedReturnSamples;
            }
            report.failures.push_back("UFunction layout candidate was rejected; parameter_chain_samples=" +
                                      std::to_string(parameterChainSamples) + " minimum_header_samples=" +
                                      std::to_string(minimumHeaderSamples) + candidateSummary +
                                      " count_mismatch=" + std::to_string(diagnosticCandidate.countMismatches) +
                                      " size_mismatch=" + std::to_string(diagnosticCandidate.sizeMismatches) +
                                      " both_mismatch=" + std::to_string(diagnosticCandidate.bothMismatches) +
                                      " invalid_shape=" + std::to_string(diagnosticCandidate.invalidShapes) +
                                      " return_mismatch=" + std::to_string(diagnosticCandidate.returnMismatches) +
                                      " equivalent_candidates=" + std::to_string(equivalentHeaderCandidates) +
                                      " return_samples=" + returnSamples +
                                      mismatchSamples);
            return false;
        }
        schema.ufunction.functionFlags = best.offset;
        schema.ufunction.numParams = best.offset + 4;
        schema.ufunction.paramSize = best.offset + 6;
        schema.ufunction.returnValueOffset = best.offset + 8;
        report.evidence.push_back("resolved UFunction::FunctionFlags, NumParms and ParmsSize from multiple samples;" + candidateSummary);

        struct NativeCandidate
        {
            int32_t offset = -1;
            size_t nativeSamples = 0;
            size_t moduleExecutableHits = 0;
            size_t outsideModuleExecutableHits = 0;
            size_t missingHits = 0;
            size_t nonNativeSamples = 0;
            size_t nonNativeModuleExecutableHits = 0;
            size_t nonNativeOutsideModuleExecutableHits = 0;
            size_t nonNativeMissingHits = 0;
            size_t readFailures = 0;
        };
        NativeCandidate bestNative;
        NativeCandidate bestObservedNative;
        size_t equivalentNativeCandidates = 0;
        const size_t requiredNativeSamples = std::max<size_t>(4, parameterChainSamples / 4);
        const auto isModuleAddress = [&](uintptr_t address)
        {
            return moduleBase_ != 0 && moduleEnd_ > moduleBase_ &&
                   address >= moduleBase_ && address < moduleEnd_;
        };
        const auto recordFunctionPointer = [&](uintptr_t value, size_t &moduleHits,
                                               size_t &outsideModuleHits, size_t &missingHits)
        {
            if (value != 0 && memory_.IsExecutable(value, sizeof(uintptr_t)))
            {
                if (isModuleAddress(value))
                    ++moduleHits;
                else
                    ++outsideModuleHits;
            }
            else
                ++missingHits;
        };
        for (const int32_t delta : nativeFunctionDeltas)
        {
            NativeCandidate candidate;
            candidate.offset = best.offset + delta;
            for (size_t index = 0; index < functions.size(); ++index)
            {
                const FunctionSample &sample = functions[index];
                if (!sample.parameterChainValid)
                    continue;
                const FunctionObservation &observation = best.observations[index];
                const auto nativeAddress = Add(sample.address, candidate.offset);
                if (!observation.readable || !observation.flagsPlausible || !nativeAddress)
                    continue;
                const uint32_t flags = observation.flags;
                uintptr_t native = 0;
                if (!memory_.Read(*nativeAddress, native))
                {
                    ++candidate.readFailures;
                    if ((flags & kFUNCNative) != 0)
                    {
                        ++candidate.nativeSamples;
                        ++candidate.missingHits;
                    }
                    else
                    {
                        ++candidate.nonNativeSamples;
                        ++candidate.nonNativeMissingHits;
                    }
                    continue;
                }

                if ((flags & kFUNCNative) != 0)
                {
                    ++candidate.nativeSamples;
                    recordFunctionPointer(native, candidate.moduleExecutableHits,
                                          candidate.outsideModuleExecutableHits, candidate.missingHits);
                }
                else
                {
                    ++candidate.nonNativeSamples;
                    recordFunctionPointer(native, candidate.nonNativeModuleExecutableHits,
                                          candidate.nonNativeOutsideModuleExecutableHits,
                                          candidate.nonNativeMissingHits);
                }
            }

            if (bestObservedNative.offset < 0 ||
                candidate.moduleExecutableHits > bestObservedNative.moduleExecutableHits ||
                (candidate.moduleExecutableHits == bestObservedNative.moduleExecutableHits &&
                 candidate.nativeSamples > bestObservedNative.nativeSamples))
                bestObservedNative = candidate;

            const size_t requiredNativeHits = (candidate.nativeSamples * 3 + 3) / 4;
            const bool hardValid = moduleBase_ != 0 && moduleEnd_ > moduleBase_ &&
                                   candidate.nativeSamples >= requiredNativeSamples &&
                                   candidate.moduleExecutableHits >= requiredNativeHits;
            if (!hardValid)
                continue;

            const auto betterNativeCandidate = [](const NativeCandidate &left, const NativeCandidate &right)
            {
                if (left.moduleExecutableHits != right.moduleExecutableHits)
                    return left.moduleExecutableHits > right.moduleExecutableHits;
                if (left.nativeSamples != right.nativeSamples)
                    return left.nativeSamples > right.nativeSamples;
                if (left.outsideModuleExecutableHits != right.outsideModuleExecutableHits)
                    return left.outsideModuleExecutableHits < right.outsideModuleExecutableHits;
                if (left.missingHits != right.missingHits)
                    return left.missingHits < right.missingHits;
                if (left.nonNativeModuleExecutableHits != right.nonNativeModuleExecutableHits)
                    return left.nonNativeModuleExecutableHits > right.nonNativeModuleExecutableHits;
                if (left.nonNativeOutsideModuleExecutableHits != right.nonNativeOutsideModuleExecutableHits)
                    return left.nonNativeOutsideModuleExecutableHits < right.nonNativeOutsideModuleExecutableHits;
                if (left.nonNativeMissingHits != right.nonNativeMissingHits)
                    return left.nonNativeMissingHits < right.nonNativeMissingHits;
                return false;
            };
            const auto sameNativeEvidence = [](const NativeCandidate &left, const NativeCandidate &right)
            {
                return left.nativeSamples == right.nativeSamples &&
                       left.moduleExecutableHits == right.moduleExecutableHits &&
                       left.outsideModuleExecutableHits == right.outsideModuleExecutableHits &&
                       left.missingHits == right.missingHits &&
                       left.nonNativeSamples == right.nonNativeSamples &&
                       left.nonNativeModuleExecutableHits == right.nonNativeModuleExecutableHits &&
                       left.nonNativeOutsideModuleExecutableHits == right.nonNativeOutsideModuleExecutableHits &&
                       left.nonNativeMissingHits == right.nonNativeMissingHits;
            };
            if (bestNative.offset < 0 || betterNativeCandidate(candidate, bestNative))
            {
                bestNative = candidate;
                equivalentNativeCandidates = 1;
            }
            else if (sameNativeEvidence(candidate, bestNative))
            {
                ++equivalentNativeCandidates;
            }
        }
        const NativeCandidate &diagnosticNative = bestNative.offset >= 0 ? bestNative : bestObservedNative;
        const size_t requiredNativeHits = (diagnosticNative.nativeSamples * 3 + 3) / 4;
        if (bestNative.offset < 0 || bestNative.nativeSamples < requiredNativeSamples ||
            bestNative.moduleExecutableHits < requiredNativeHits || equivalentNativeCandidates > 1)
        {
            report.ambiguous = equivalentNativeCandidates > 1;
            report.failures.push_back("UFunction::ExecFunction was not resolved after header selection; flags_offset=" +
                                      std::to_string(schema.ufunction.functionFlags) +
                                      " native_offset=" + std::to_string(diagnosticNative.offset) +
                                      " native_samples=" + std::to_string(diagnosticNative.nativeSamples) +
                                      " required_native_samples=" + std::to_string(requiredNativeSamples) +
                                      " module_executable_hits=" + std::to_string(diagnosticNative.moduleExecutableHits) +
                                      " required_executable_hits=" + std::to_string(requiredNativeHits) +
                                      " outside_module_executable_hits=" +
                                      std::to_string(diagnosticNative.outsideModuleExecutableHits) +
                                      " missing=" + std::to_string(diagnosticNative.missingHits) +
                                      " non_native_samples=" + std::to_string(diagnosticNative.nonNativeSamples) +
                                      " non_native_module_executable_hits=" +
                                      std::to_string(diagnosticNative.nonNativeModuleExecutableHits) +
                                      " non_native_outside_module_executable_hits=" +
                                      std::to_string(diagnosticNative.nonNativeOutsideModuleExecutableHits) +
                                      " non_native_missing=" + std::to_string(diagnosticNative.nonNativeMissingHits) +
                                      " equivalent_candidates=" + std::to_string(equivalentNativeCandidates) +
                                      " module_base=" + Hex(moduleBase_) +
                                      " module_end=" + Hex(moduleEnd_) + candidateSummary);
            return false;
        }
        schema.ufunction.nativeFunction = bestNative.offset;
        const int32_t nativeTailDelta = bestNative.offset - best.offset;
        report.evidence.push_back("resolved UFunction::ExecFunction from module executable pointers; offset=" +
                                  std::to_string(schema.ufunction.nativeFunction) + " hits=" +
                                  std::to_string(bestNative.moduleExecutableHits) + " native_samples=" +
                                  std::to_string(bestNative.nativeSamples) + " outside_module=" +
                                  std::to_string(bestNative.outsideModuleExecutableHits) + " non_native_samples=" +
                                  std::to_string(bestNative.nonNativeSamples) + " selected_read_failures=" +
                                  std::to_string(bestNative.readFailures));
        report.versionEvidence.push_back({"ufunction-native-tail",
                                          "native_function_offset=" + std::to_string(schema.ufunction.nativeFunction) +
                                              " tail_delta=" + std::to_string(nativeTailDelta),
                                          VersionEvidenceStrength::Medium,
                                          "tail position is build-conditional; does not uniquely identify WITH_LIVE_CODING"});

        // A candidate is evidence only after its UObject identity, outer and complete
        // UField chain agree on multiple independent owners. Invalid scalar contents
        // are rejected before dereference, rather than contaminating read statistics.
        std::vector<uintptr_t> owners;
        for (const char *ownerName : {"KismetSystemLibrary", "Actor", "PlayerController"})
        {
            const auto owner = FindObjectByName(schema, ownerName);
            if (owner && std::find(owners.begin(), owners.end(), *owner) == owners.end())
                owners.push_back(*owner);
        }
        std::vector<int32_t> childrenCandidates;
        size_t rejectedPointers = 0;
        const size_t objectExtent = static_cast<size_t>(std::max({schema.uobject.classPointer + static_cast<int32_t>(sizeof(uintptr_t)),
                                                                  schema.uobject.outer + static_cast<int32_t>(sizeof(uintptr_t)),
                                                                  schema.uobject.name + schema.fname.size,
                                                                  schema.uobject.internalIndex + 4}));
        for (int32_t offset = 0x20; offset <= 0x180; offset += 4)
        {
            size_t matches = 0;
            bool mismatch = false;
            for (const uintptr_t owner : owners)
            {
                uintptr_t child = 0;
                const auto address = Add(owner, offset);
                if (!address || !memory_.IsReadable(*address, sizeof(child)))
                {
                    ++rejectedPointers;
                    mismatch = true;
                    break;
                }
                if (!memory_.Read(*address, child))
                {
                    mismatch = true;
                    break;
                }
                if (child == 0)
                    continue;
                if (!session_.FindObject(schema, child) || !memory_.IsReadable(child, objectExtent))
                {
                    ++rejectedPointers;
                    mismatch = true;
                    break;
                }
                const auto cls = model.Class(child);
                if (!cls || !memory_.IsReadable(*cls, objectExtent))
                {
                    ++rejectedPointers;
                    mismatch = true;
                    break;
                }
                const auto index = model.InternalIndex(child);
                const auto outer = model.Outer(child);
                const auto className = model.Name(*cls);
                if (!index || *index < 0 || *index >= bootstrap_->objects->Count() ||
                    bootstrap_->objects->ReadObject(*index).address != child || !outer || *outer != owner ||
                    !className || (!IsFunctionFieldKind(FieldKindFromRuntimeName(*className, false)) && (schema.features.useFProperty || !IsPropertyFieldKind(FieldKindFromRuntimeName(*className, false)))))
                {
                    mismatch = true;
                    break;
                }
                bool sawFunction = false;
                std::unordered_set<uintptr_t> visited;
                for (uintptr_t node = child; node != 0;)
                {
                    const auto *identity = session_.FindObject(schema, node);
                    const auto nextAddress = Add(node, schema.ufield.next);
                    if (visited.size() >= 4096)
                    {
                        report.sampleTruncated = true;
                        report.searchComplete = false;
                        mismatch = true;
                        break;
                    }
                    if (!identity || !visited.insert(node).second ||
                        !nextAddress || !memory_.IsReadable(*nextAddress, sizeof(uintptr_t)) ||
                        !memory_.IsReadable(node, objectExtent) || !memory_.IsReadable(identity->classAddress, objectExtent))
                    {
                        ++rejectedPointers;
                        mismatch = true;
                        break;
                    }
                    const auto field = model.UField(node);
                    const auto fieldOuter = model.Outer(node);
                    if (!field || !fieldOuter || *fieldOuter != owner || field->classAddress != identity->classAddress ||
                        (!IsFunctionFieldKind(field->kind) && (schema.features.useFProperty || !IsPropertyFieldKind(field->kind))))
                    {
                        mismatch = true;
                        break;
                    }
                    sawFunction = sawFunction || IsFunctionFieldKind(field->kind);
                    node = field->nextAddress;
                }
                if (mismatch || !sawFunction)
                {
                    mismatch = true;
                    break;
                }
                ++matches;
            }
            if (!mismatch && matches >= 2)
                childrenCandidates.push_back(offset);
        }
        report.evidence.push_back("UFunction children validation owners=" + std::to_string(owners.size()) +
                                  " candidates=" + std::to_string(childrenCandidates.size()) +
                                  " rejected_pointers=" + std::to_string(rejectedPointers));
        report.rejectedCandidates += rejectedPointers;
        if (childrenCandidates.size() != 1)
        {
            report.ambiguous = childrenCandidates.size() > 1;
            report.failures.push_back("UStruct::Children requires one candidate validated by multiple class-owned function chains");
            return false;
        }
        schema.ustruct.children = childrenCandidates.front();

        schema.validation.functions = true;
        report.evidence.push_back("resolved UField::Next and UStruct::Children for UFunction reflection; next=" +
                                  std::to_string(schema.ufield.next) + " children=" +
                                  std::to_string(schema.ustruct.children));
        return true;
    }

} // namespace nextdumper::ue::schema_probe
