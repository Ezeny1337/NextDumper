#include "nextdumper/analysis/AnalysisSession.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "nextdumper/analysis/CodeRanges.hpp"
#include "nextdumper/analysis/CodeWindow.hpp"
#include "nextdumper/analysis/FunctionIndex.hpp"
#include "nextdumper/analysis/ImageModel.hpp"
#include "nextdumper/analysis/InstructionDecoder.hpp"
#include "nextdumper/analysis/NameContractScanner.hpp"
#include "nextdumper/analysis/ObjectContractScanner.hpp"
#include "nextdumper/common/Hex.hpp"

namespace nextdumper::analysis
{
    namespace
    {
        const char *ContractStateName(ContractState state)
        {
            switch (state)
            {
            case ContractState::Observed:
                return "observed";
            case ContractState::Validated:
                return "validated";
            case ContractState::Unsupported:
                return "unsupported";
            case ContractState::Ambiguous:
                return "ambiguous";
            }
            return "observed";
        }

        const char *NameKeySourceName(NameTextFamily family)
        {
            switch (family)
            {
            case NameTextFamily::Identity:
                return "none";
            case NameTextFamily::ByteXor:
                return "constant";
            case NameTextFamily::LengthSchedule:
                return "length";
            }
            return "unknown";
        }

        bool SameDomainContract(const NameStoreContract &left, const NameStoreContract &right)
        {
            return left.Root == right.Root && left.SameShape(right);
        }

        bool SameDomainContract(const ObjectArrayContract &left, const ObjectArrayContract &right)
        {
            return left.Root == right.Root && left.ObjectArray == right.ObjectArray;
        }

        bool SameDomainContract(const UObjectLayoutContract &left, const UObjectLayoutContract &right)
        {
            return left.ObjectRoot == right.ObjectRoot && left.UObject == right.UObject &&
                   left.FName.FName == right.FName.FName;
        }

        template <typename T>
        AnalysisStatus DomainStatus(const std::vector<T> &contracts)
        {
            const T *validated = nullptr;
            bool observed = false;
            bool ambiguous = false;
            for (const T &contract : contracts)
            {
                if (contract.State == ContractState::Validated)
                {
                    if (!validated)
                        validated = &contract;
                    else if (!SameDomainContract(*validated, contract))
                        ambiguous = true;
                }
                observed = observed || contract.State == ContractState::Observed;
                ambiguous = ambiguous || contract.State == ContractState::Ambiguous;
            }
            if (validated && !ambiguous)
                return AnalysisStatus::Validated;
            if (ambiguous)
                return AnalysisStatus::Ambiguous;
            if (observed)
                return AnalysisStatus::Observed;
            return AnalysisStatus::Unsupported;
        }
    } // namespace

    const char *NameStoreFamilyName(NameStoreFamily family)
    {
        switch (family)
        {
        case NameStoreFamily::Pool:
            return "pool";
        case NameStoreFamily::Array:
            return "array";
        }
        return "unknown";
    }

    const char *AnalysisStatusName(AnalysisStatus status)
    {
        switch (status)
        {
        case AnalysisStatus::Failed:
            return "failed";
        case AnalysisStatus::Unsupported:
            return "unsupported";
        case AnalysisStatus::Partial:
            return "partial";
        case AnalysisStatus::Observed:
            return "observed";
        case AnalysisStatus::Validated:
            return "validated";
        case AnalysisStatus::Complete:
            return "complete";
        case AnalysisStatus::Ambiguous:
            return "ambiguous";
        }
        return "failed";
    }

    const char *DiagnosticSeverityName(DiagnosticSeverity severity)
    {
        switch (severity)
        {
        case DiagnosticSeverity::Debug:
            return "debug";
        case DiagnosticSeverity::Info:
            return "info";
        case DiagnosticSeverity::Warning:
            return "warning";
        case DiagnosticSeverity::Error:
            return "error";
        }
        return "info";
    }

    AnalysisSession::AnalysisSession(const MemoryView &memory, const module::ModuleImage &module,
                                     AnalysisSessionOptions options) noexcept
        : memory_(memory), module_(module), options_(std::move(options))
    {
    }

    AnalysisResult AnalysisSession::Run() const
    {
        AnalysisResult result;
        const uint64_t addressSpaceGeneration = memory_.AddressSpaceGeneration();

        if (!memory_.IsInitialized())
        {
            result.Status = AnalysisStatus::Failed;
            result.Reason = "memory-not-initialized";
            result.Diagnostics.push_back({DiagnosticSeverity::Error, "ANALYSIS_MEMORY_UNAVAILABLE",
                                          "The analysis session requires an initialized memory view."});
            return result;
        }

        if (!module_.IsValid())
        {
            result.Status = AnalysisStatus::Failed;
            result.Reason = "module-invalid";
            result.Diagnostics.push_back({DiagnosticSeverity::Error, "ANALYSIS_MODULE_INVALID",
                                          "The module base or range is invalid."});
            return result;
        }

        const ImageModel image(memory_, module_);
        result.Coverage.ModuleSegments = image.ModuleSegmentCount();
        result.Coverage.ExecutableSegments = image.ExecutableSegmentCount();
        result.Coverage.ExecutableBytes = image.ExecutableBytes();

        bool imageHeaderReadable = false;
        std::array<uint8_t, 16> header{};
        if (!memory_.IsReadable(module_.base, header.size()))
        {
            result.Status = AnalysisStatus::Partial;
            result.Reason = "image-header-unreadable";
            result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_IMAGE_HEADER_UNREADABLE",
                                          "The module header at the image base is not readable."});
        }
        else
        {
            const auto read = memory_.ReadBytes(module_.base, header.data(), header.size());
            if (!read.Ok())
            {
                result.Status = AnalysisStatus::Partial;
                result.Reason = "image-header-short-read";
                result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_IMAGE_HEADER_SHORT_READ",
                                              "The module header read was incomplete; bytes=" + std::to_string(read.transferred)});
            }
            else if (header[0] != 0x7F || header[1] != 'E' || header[2] != 'L' || header[3] != 'F')
            {
                result.Status = AnalysisStatus::Partial;
                result.Reason = "image-header-not-elf";
                result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_IMAGE_HEADER_NOT_ELF",
                                              "The module header is readable but does not carry an ELF magic."});
            }
            else
            {
                imageHeaderReadable = true;
                result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_IMAGE_HEADER_READ",
                                              "ELF header readable; executable_bytes=" + std::to_string(result.Coverage.ExecutableBytes) +
                                                  " executable_segments=" + std::to_string(result.Coverage.ExecutableSegments)});
            }
        }

        std::string functionError;
        const FunctionIndex functions = FunctionIndex::Build(image, functionError);
        if (functions.IsValid())
        {
            result.Coverage.FunctionCount = functions.Count();
            result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_FUNCTION_INDEX_READY",
                                          "functions=" + std::to_string(functions.Count()) +
                                              " first=" + common::Hex(functions.FirstStart()) +
                                              " last=" + common::Hex(functions.LastStart())});

            FunctionRange firstRange;
            if (functions.Find(functions.FirstStart(), firstRange))
            {
                result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_FUNCTION_RANGE",
                                              "first=[" + common::Hex(firstRange.Start) + "," +
                                                  common::Hex(firstRange.End) + ")"});
            }
            else
            {
                result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_FUNCTION_RANGE_UNAVAILABLE",
                                              "first=" + common::Hex(functions.FirstStart())});
            }

            FunctionRange lastRange;
            if (functions.Find(functions.LastStart(), lastRange))
            {
                result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_FUNCTION_RANGE",
                                              "last=[" + common::Hex(lastRange.Start) + "," +
                                                  common::Hex(lastRange.End) + ")"});
            }
            else
            {
                result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_FUNCTION_RANGE_UNAVAILABLE",
                                              "last=" + common::Hex(functions.LastStart())});
            }
        }
        else
        {
            result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_FUNCTION_INDEX_UNAVAILABLE",
                                          "reason=" + functionError});
        }

        std::string rangeError;
        const CodeRangeSet codeRanges = RecoverCodeRanges(memory_, module_, rangeError);
        if (codeRanges.Ranges.empty())
        {
            result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_CODE_RANGE_UNAVAILABLE",
                                          "reason=" + rangeError});
        }
        else
        {
            result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_CODE_RANGE_READY",
                                          "ranges=" + std::to_string(codeRanges.Ranges.size()) +
                                              " source=" + codeRanges.Source +
                                              " unknown_mode=" + std::to_string(codeRanges.UnknownModeRanges)});
        }
        const CodeMode primaryMode = codeRanges.Ranges.empty() ? CodeMode::Unknown : codeRanges.Ranges.front().Mode;
        const auto decoder = CreateInstructionDecoder(module_.architecture, primaryMode);
        if (!decoder)
        {
            result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_DECODER_UNSUPPORTED",
                                          "architecture=" + std::string(module::ModuleArchitectureName(module_.architecture)) +
                                              " mode=" + CodeModeName(primaryMode)});
        }
        else
        {
            result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_DECODER_READY",
                                          "architecture=" + std::string(module::ModuleArchitectureName(module_.architecture)) +
                                              " mode=" + CodeModeName(primaryMode)});
            if (functions.IsValid())
            {
                FunctionRange firstRange;
                if (functions.Find(functions.FirstStart(), firstRange) &&
                    firstRange.Start <= UINTPTR_MAX && firstRange.End > firstRange.Start)
                {
                    CodeWindow window(image.Memory(), 256);
                    Instruction instruction;
                    uintptr_t at = static_cast<uintptr_t>(firstRange.Start);
                    size_t decoded = 0;
                    size_t other = 0;
                    size_t clobbered = 0;
                    constexpr size_t kSampleLimit = 16;
                    while (decoded < kSampleLimit && at < firstRange.End)
                    {
                        const uint8_t *bytes = window.At(at, 4);
                        if (!bytes || !decoder->Decode(bytes, 4, at, instruction))
                            break;
                        ++decoded;
                        if (instruction.Kind == InstructionKind::Other)
                            ++other;
                        if (instruction.bClobbersAll)
                            ++clobbered;
                        const uint8_t length = instruction.Length ? instruction.Length : 4;
                        if (static_cast<uint64_t>(length) > firstRange.End - at)
                            break;
                        at += length;
                    }
                    result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_DECODER_SAMPLE",
                                                  "decoded=" + std::to_string(decoded) +
                                                      " other=" + std::to_string(other) +
                                                      " clobbered=" + std::to_string(clobbered) +
                                                      " bytes=" + std::to_string(window.BytesFetched())});
                }
            }
        }

        bool objectContractsAmbiguous = false;
        // 代码分析需要解码器与函数索引；缺失时只跳过代码证据，不影响数据阶段
        if (decoder && functions.IsValid())
        {
            NameContractScanOptions options;
            const NameContractScanResult scan = ScanNameContracts(image, functions, codeRanges, options);
            result.Coverage.ScannedInstructions = scan.Instructions;
            result.Coverage.CodeScanFetchedBytes = scan.FetchedBytes;
            result.Coverage.CodeScanDecodedBytes = scan.DecodedBytes;
            result.Coverage.CodeScanComplete = scan.IsComplete();
            result.Coverage.DecodedRanges = scan.DecodedRanges;
            result.Coverage.UnknownModeRanges = scan.UnknownModeRanges;
            const auto &recognition = scan.Recognition;
            result.Diagnostics.push_back(
                {DiagnosticSeverity::Info, "ANALYSIS_CONTRACT_RECOGNITION",
                 "decoded_ranges=" + std::to_string(scan.DecodedRanges) +
                     " unknown_mode_ranges=" + std::to_string(scan.UnknownModeRanges) +
                     " base_instructions=" + std::to_string(recognition.BaseInstructions) +
                     " block_slots=" + std::to_string(recognition.BlockSlots) +
                     " entry_addresses=" + std::to_string(recognition.EntryAddresses) +
                     " entry_split_mismatches=" + std::to_string(recognition.EntrySplitMismatches) +
                     " header_loads=" + std::to_string(recognition.HeaderLoads) +
                     " record_attempts=" + std::to_string(recognition.RecordAttempts) +
                     " records_without_header=" + std::to_string(recognition.RecordsWithoutHeader) +
                     " rejected_blocks_offset=" + std::to_string(recognition.RejectedBlocksOffset) +
                     " rejected_blocks_bit=" + std::to_string(recognition.RejectedBlocksBit) +
                     " rejected_stride=" + std::to_string(recognition.RejectedStride) +
                     " rejected_header_offset=" + std::to_string(recognition.RejectedHeaderOffset) +
                     " rejected_string_offset=" + std::to_string(recognition.RejectedStringOffset) +
                     " rejected_length_shift=" + std::to_string(recognition.RejectedLengthShift) +
                     " rejected_id_mask=" + std::to_string(recognition.RejectedIdMask) +
                     " array_chunk_shifts=" + std::to_string(recognition.ArrayChunkShifts) +
                     " array_chunk_slots=" + std::to_string(recognition.ArrayChunkSlots) +
                     " array_entry_slots=" + std::to_string(recognition.ArrayEntrySlots) +
                     " array_entry_loads=" + std::to_string(recognition.ArrayEntryLoads) +
                     " array_index_loads=" + std::to_string(recognition.ArrayIndexLoads) +
                     " array_text_bases=" + std::to_string(recognition.ArrayTextBases) +
                     " array_record_attempts=" + std::to_string(recognition.ArrayRecordAttempts) +
                     " array_records_without_index=" + std::to_string(recognition.ArrayRecordsWithoutIndex) +
                     " array_records_without_text=" + std::to_string(recognition.ArrayRecordsWithoutText) +
                     " rejected_array_chunks_offset=" + std::to_string(recognition.RejectedArrayChunksOffset) +
                     " rejected_array_chunk_shift=" + std::to_string(recognition.RejectedArrayChunkShift) +
                     " rejected_array_entry_stride=" + std::to_string(recognition.RejectedArrayEntryStride) +
                     " rejected_array_index_offset=" + std::to_string(recognition.RejectedArrayIndexOffset) +
                     " rejected_array_string_offset=" + std::to_string(recognition.RejectedArrayStringOffset) +
                     " incomplete_records=" + std::to_string(recognition.IncompleteRecords) +
                     " contract_limit_hits=" + std::to_string(recognition.ContractLimitHits)});
            if (!scan.Error.empty())
            {
                result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_CONTRACT_SCAN_FAILED",
                                              "reason=" + scan.Error});
            }
            result.NameStores = scan.Contracts;

            NameValidationOptions validationOptions;
            validationOptions.RootHints = options_.NameRootHints;
            for (size_t index = 0; index < result.NameStores.size(); ++index)
            {
                NameStoreContract &contract = result.NameStores[index];
                const NameValidation validation = ValidateNameStore(memory_, contract, index, validationOptions);
                const bool validated = validation.IsValidated();
                const bool isPool = contract.Family == NameStoreFamily::Pool;

                contract.State = validated               ? ContractState::Validated
                                 : validation.RootUsable ? ContractState::Unsupported
                                                         : ContractState::Observed;
                if (validated)
                    contract.Root = validation.Root;
                result.NameValidations.push_back(validation);

                const std::string root = validation.Root != 0 ? common::Hex(validation.Root)
                                         : contract.Root == 0 ? "unresolved"
                                                              : common::Hex(contract.Root);
                const std::string target = "target=NameStore family=" + std::string(NameStoreFamilyName(contract.Family)) +
                                           " root=" + root;
                std::string contractMessage = target;
                if (isPool)
                {
                    const NamePoolFields &fields = contract.NamePool;
                    contractMessage += " blocks_offset=" + std::to_string(fields.BlocksOffset) +
                                       " blocks_bit=" + std::to_string(fields.BlocksBit) +
                                       " entry_stride=" + std::to_string(fields.EntryStride) +
                                       " header_offset=" + std::to_string(fields.HeaderOffset) +
                                       " string_offset=" + std::to_string(fields.StringOffset) +
                                       " length_shift=" + std::to_string(fields.LengthShift) +
                                       " wide_mask=" + std::to_string(fields.WideMask);
                }
                else
                {
                    const NameArrayFields &fields = contract.NameArray;
                    contractMessage += " chunks_offset=" + std::to_string(fields.ChunksOffset) +
                                       " chunk_shift=" + std::to_string(fields.ChunkShift) +
                                       " slot_stride=" + std::to_string(fields.SlotStride) +
                                       " entry_index_offset=" + std::to_string(fields.EntryIndexOffset) +
                                       " string_offset=" + std::to_string(fields.StringOffset);
                }
                contractMessage += " complete=" + std::to_string(contract.Complete()) +
                                   " state=" + ContractStateName(contract.State) +
                                   " evidence_sites=" + std::to_string(contract.Evidence.size());
                result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_CONTRACT", std::move(contractMessage)});

                if (validation.Decoder)
                {
                    const NameTextCodec &decoderValue = *validation.Decoder;
                    result.Diagnostics.push_back(
                        {DiagnosticSeverity::Info, "ANALYSIS_DECODER",
                         "family=" + std::string(NameTextFamilyName(decoderValue.Family)) +
                             " key=" + std::to_string(decoderValue.Key) +
                             " key_source=" + NameKeySourceName(decoderValue.Family) +
                             " known_pairs=" + std::to_string(validation.KnownMatched) +
                             " plausible=" + std::to_string(validation.KnownPlausible) + "/" +
                             std::to_string(validation.KnownWalked) +
                             " consistency=" + std::to_string(validation.KnownMatched) + "/" +
                             std::to_string(validation.KnownMatched) +
                             " samples=" + std::to_string(validation.Block0Valid + validation.HighBlockValid) + "/" +
                             std::to_string(validation.Block0Samples + validation.HighBlockSamples) +
                             " narrow_samples=" + std::to_string(validation.NarrowSamples) +
                             " wide_samples=" + std::to_string(validation.WideSamples) +
                             " walked=" + std::to_string(validation.KnownWalked) +
                             " status=" + (validation.DecoderValidated ? "validated" : "observed")});
                    result.Diagnostics.push_back(
                        {DiagnosticSeverity::Info, "ANALYSIS_KNOWN_NAMES",
                         "target=" + std::string(isPool ? "NamePool" : "NameArray") +
                             " family=" + NameTextFamilyName(decoderValue.Family) +
                             " matched=" + std::to_string(validation.KnownMatched) +
                             " plausible=" + std::to_string(validation.KnownPlausible) + "/" +
                             std::to_string(validation.KnownWalked) +
                             " names=" + validation.KnownNamesPreview});
                }

                std::string validationMessage = target;
                if (!validated)
                    validationMessage += " reason=" + validation.Failure;

                if (!isPool)
                {
                    validationMessage += " chunks=" + common::Hex(validation.BlocksAddress) +
                                         " chunk0=" + common::Hex(validation.Block0) +
                                         " block_size=" + std::to_string(validation.BlockSize);
                }
                else if (validated)
                {
                    if (!validation.BoundaryReadable)
                    {
                        result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_BOUNDARY_UNAVAILABLE",
                                                      target + " " + validation.BoundaryDetail});
                    }
                    validationMessage += " blocks=" + common::Hex(validation.BlocksAddress) +
                                         " block0=" + common::Hex(validation.Block0) +
                                         " current_block=" + std::to_string(validation.CurrentBlock) +
                                         " byte_cursor=" + std::to_string(validation.ByteCursor) +
                                         " block_size=" + std::to_string(validation.BlockSize) +
                                         " allocated_blocks=" + std::to_string(validation.AllocatedBlocks) +
                                         " boundary=" + (validation.BoundaryReadable ? validation.BoundaryDetail : "unavailable") +
                                         " current_offset=" + std::to_string(validation.CurrentBlockOffset) +
                                         " cursor_offset=" + std::to_string(validation.ByteCursorOffset);
                }
                if (validated || !isPool)
                {
                    validationMessage += " known_names=" + std::to_string(validation.KnownMatched) +
                                         " known_plausible=" + std::to_string(validation.KnownPlausible) + "/" +
                                         std::to_string(validation.KnownWalked);
                    if (!isPool)
                        validationMessage += " element_index=" + std::to_string(validation.ElementIndexMatched) + "/" +
                                             std::to_string(validation.ElementIndexTested);
                    validationMessage += " block0_samples=" + std::to_string(validation.Block0Valid) + "/" +
                                         std::to_string(validation.Block0Samples) +
                                         " high_block_samples=" + std::to_string(validation.HighBlockValid) + "/" +
                                         std::to_string(validation.HighBlockSamples);
                }
                validationMessage += " attempts=" + std::to_string(validation.AttemptedRoots);
                if (validated)
                {
                    validationMessage += " state=validated";
                    result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_VALIDATION",
                                                  std::move(validationMessage)});
                }
                else
                {
                    if (!validation.FailureDetail.empty())
                        validationMessage += " detail=" + validation.FailureDetail;
                    if (!validation.LayoutDetail.empty())
                        validationMessage += " layout_detail=" + validation.LayoutDetail;
                    if (isPool)
                    {
                        if (validation.AllocatedBlocks != 0)
                            validationMessage += " allocated_blocks=" + std::to_string(validation.AllocatedBlocks);
                        if (!validation.BoundaryDetail.empty())
                            validationMessage += " boundary=" + validation.BoundaryDetail;
                        if (validation.CurrentBlockOffset >= 0)
                            validationMessage += " current_offset=" + std::to_string(validation.CurrentBlockOffset) +
                                                 " cursor_offset=" + std::to_string(validation.ByteCursorOffset);
                    }
                    if (!validation.FirstEntryHex.empty())
                        validationMessage += " raw_entry0=" + validation.FirstEntryHex;
                    result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_VALIDATION_FAILED",
                                                  std::move(validationMessage)});
                }
            }
        }

        // 数据阶段独立于代码分析
        // 即使解码器或函数索引不可用，内存中的结构证据仍应产生结论，而不是被整体跳过
        {
            NameStoreView dataNameView;
            NameTextCodec dataNameDecoder{};
            if (!result.NameStores.empty())
            {
                size_t selected = result.NameStores.size();
                for (size_t index = 0; index < result.NameStores.size(); ++index)
                {
                    if (result.NameStores[index].State == ContractState::Validated)
                    {
                        selected = index;
                        break;
                    }
                }
                if (selected < result.NameStores.size())
                {
                    dataNameView = NameStoreView::From(result.NameStores[selected]);
                    const auto found = std::find_if(result.NameValidations.begin(), result.NameValidations.end(),
                                                    [&](const NameValidation &validation)
                                                    { return validation.ContractIndex == selected && validation.Decoder.has_value(); });
                    if (found != result.NameValidations.end())
                    {
                        dataNameView.Root = found->Root;
                        dataNameDecoder = *found->Decoder;
                    }
                }
            }
            const ObjectContractScanResult objectScan =
                ScanObjectContracts(image, dataNameView, dataNameDecoder, ObjectContractScanOptions{});
            objectContractsAmbiguous = objectScan.ContractsAmbiguous;
            result.Coverage.DataScanPlannedBytes = objectScan.PlannedBytes;
            result.Coverage.DataScanReadBytes = objectScan.ScannedBytes;
            result.Coverage.ObjectScanComplete = objectScan.IsComplete();
            for (const UObjectLayoutContract &contract : objectScan.UObjectLayouts)
                result.UObjectLayouts.push_back(contract);
            for (const ObjectArrayContract &contract : objectScan.Contracts)
            {
                result.ObjectArrays.push_back(contract);
                const ObjectArrayFields &fields = contract.ObjectArray;
                const ObjectArrayObservation &observation = contract.Observation;
                result.Diagnostics.push_back(
                    {DiagnosticSeverity::Info, "ANALYSIS_OBJECT_CONTRACT",
                     "target=ObjectArray root=" + common::Hex(contract.Root) +
                         " kind=" + std::string(fields.Fixed ? "fixed" : "chunked") +
                         " count=" + std::to_string(observation.Count) +
                         " max_elements=" + std::to_string(observation.MaxElements) +
                         " chunks=" + std::to_string(observation.Chunks) +
                         " elements_per_chunk=" + std::to_string(fields.ElementsPerChunk) +
                         " item_stride=" + std::to_string(fields.ItemStride) +
                         " item_index=" + std::to_string(fields.ItemIndexOffset) +
                         " field_offsets=" + std::to_string(fields.MaxElementsOffset) + "/" +
                         std::to_string(fields.NumElementsOffset) + "/" +
                         std::to_string(fields.MaxChunksOffset) + "/" +
                         std::to_string(fields.NumChunksOffset) +
                         " objects_offset=" + std::to_string(fields.ObjectsOffset) +
                         " state=" + ContractStateName(contract.State)});
            }
            for (const ObjectSeedEvidence &seed : objectScan.Seeds)
            {
                result.Diagnostics.push_back(
                    {DiagnosticSeverity::Info, "ANALYSIS_OBJECT_SEED",
                     "root=" + common::Hex(seed.Root) + " storage=" + common::Hex(seed.Storage) +
                         " declared=" + std::to_string(seed.DeclaredCount) +
                         " stride=" + std::to_string(seed.ItemStride) +
                         " index=" + std::to_string(seed.ItemIndexOffset) +
                         " chunk_size=" + std::to_string(seed.ElementsPerChunk) +
                         " header=" + std::to_string(seed.HeaderFound)});
            }
            for (const ObjectStoreEvidence &storeEvidence : objectScan.StoreEvidence)
            {
                std::string refSlots;
                for (const uintptr_t slot : storeEvidence.ReferenceSamples)
                {
                    if (!refSlots.empty())
                        refSlots += ",";
                    refSlots += common::Hex(slot);
                }
                std::string chunkPointers;
                for (const uintptr_t chunk : storeEvidence.ChunkPointers)
                {
                    if (!chunkPointers.empty())
                        chunkPointers += ",";
                    chunkPointers += common::Hex(chunk);
                }
                result.Diagnostics.push_back(
                    {storeEvidence.Result == "contract" ? DiagnosticSeverity::Info : DiagnosticSeverity::Warning,
                     "ANALYSIS_OBJECT_STORE",
                     "order=" + std::to_string(storeEvidence.Order) +
                         " root=" + common::Hex(storeEvidence.Root) +
                         " mode=" + (storeEvidence.Fixed ? "fixed" : "chunked") +
                         " refs=" + std::to_string(storeEvidence.ReferenceCount) +
                         " ref_slots=" + refSlots +
                         " item_stride=" + std::to_string(storeEvidence.ItemStride) +
                         " item_index=" + std::to_string(storeEvidence.ItemIndexOffset) +
                         " prefix=" + std::to_string(storeEvidence.PrefixValid) + "/" +
                         std::to_string(storeEvidence.PrefixTested) +
                         " chunks=" + std::to_string(storeEvidence.ChunkCount) +
                         " chunk_ptrs=" + chunkPointers +
                         " budget_left=" + std::to_string(storeEvidence.FullScanBudgetAtStart) +
                         " headers=" + std::to_string(storeEvidence.HeaderCount) +
                         " header_evidence=" + std::to_string(storeEvidence.Headers.size()) +
                         " max_count=" + std::to_string(storeEvidence.MaxHeaderCount) +
                         " full_scans=" + std::to_string(storeEvidence.FullScanCount) +
                         " result=" + storeEvidence.Result});
                for (const ObjectFullScanEvidence &scanEvidence : storeEvidence.FullScans)
                {
                    std::string scanMessage =
                        "store=" + common::Hex(storeEvidence.Root) +
                        " capacity=" + std::to_string(scanEvidence.Capacity) +
                        " tested=" + std::to_string(scanEvidence.Tested) +
                        " valid=" + std::to_string(scanEvidence.Valid) +
                        " empty=" + std::to_string(scanEvidence.Empty) +
                        " invalid=" + std::to_string(scanEvidence.Invalid) +
                        " invalid_between=" + std::to_string(scanEvidence.InvalidBetweenValid) +
                        " derived=" + std::to_string(scanEvidence.DerivedCount) +
                        " nonempty_extent=" + std::to_string(scanEvidence.NonEmptyExtent) +
                        " gates=" + (scanEvidence.GatesPassed ? "passed" : "failed");
                    if (!scanEvidence.GatesPassed)
                        scanMessage += " gate_failure=" + scanEvidence.GateFailure;
                    result.Diagnostics.push_back(
                        {scanEvidence.GatesPassed ? DiagnosticSeverity::Info : DiagnosticSeverity::Warning,
                         "ANALYSIS_OBJECT_FULL_SCAN", std::move(scanMessage)});
                }
                for (const ObjectHeaderEvidence &headerEvidence : storeEvidence.Headers)
                {
                    result.Diagnostics.push_back(
                        {DiagnosticSeverity::Info, "ANALYSIS_OBJECT_HEADER",
                         "store=" + common::Hex(storeEvidence.Root) +
                             " base=" + common::Hex(headerEvidence.Base) +
                             " objects_offset=" + std::to_string(headerEvidence.ObjectsOffset) +
                             " count=" + std::to_string(headerEvidence.Count) + "@" +
                             std::to_string(headerEvidence.CountOffset) +
                             " count_at_gate=" + std::to_string(headerEvidence.CountAtGate) +
                             " max_chunks=" + std::to_string(headerEvidence.MaxChunks) + "@" +
                             std::to_string(headerEvidence.MaxChunksOffset) +
                             " num_chunks=" + std::to_string(headerEvidence.NumChunks) + "@" +
                             std::to_string(headerEvidence.NumChunksOffset) +
                             " max_elements=" + std::to_string(headerEvidence.MaxElements) + "@" +
                             std::to_string(headerEvidence.MaxElementsOffset) +
                             " capacity=" + std::to_string(headerEvidence.Capacity) +
                             " budget_left=" + std::to_string(headerEvidence.FullScanBudgetLeft) +
                             " result=" + ObjectHeaderOutcomeName(headerEvidence.Outcome)});
                }
            }
            if (objectScan.SeedRootsProbed > 0)
            {
                result.Diagnostics.push_back(
                    {DiagnosticSeverity::Info, "ANALYSIS_OBJECT_PROBE",
                     "probed=" + std::to_string(objectScan.SeedRootsProbed) +
                         " chunk_no_storage=" + std::to_string(objectScan.ChunkNoStorage) +
                         " chunk_layout_unresolved=" + std::to_string(objectScan.ChunkLayoutUnresolved) +
                         " chunk_prefix_failed=" + std::to_string(objectScan.ChunkPrefixFailed) +
                         " fixed_layout_unresolved=" + std::to_string(objectScan.FixedLayoutUnresolved) +
                         " fixed_prefix_failed=" + std::to_string(objectScan.FixedPrefixFailed)});
            }

            std::string message = "scanned_bytes=" + std::to_string(objectScan.ScannedBytes) +
                                  " planned_bytes=" + std::to_string(objectScan.PlannedBytes) +
                                  " scan_read_failures=" + std::to_string(objectScan.ScanReadFailures) +
                                  " candidates=" + std::to_string(objectScan.Candidates) +
                                  " discovered_roots=" + std::to_string(objectScan.DiscoveredRoots) +
                                  " storage_roots=" + std::to_string(objectScan.StorageRoots) +
                                  " roots_skipped=" + std::to_string(objectScan.RootsSkipped) +
                                  " seed_roots=" + std::to_string(objectScan.SeedRootsProbed) +
                                  " chunk_stores=" + std::to_string(objectScan.ChunkStores) +
                                  " fixed_stores=" + std::to_string(objectScan.FixedStores) +
                                  " header_candidates=" + std::to_string(objectScan.HeaderCandidates) +
                                  " header_validations=" + std::to_string(objectScan.HeaderValidations) +
                                  " header_overflow_stores=" + std::to_string(objectScan.HeaderOverflowStores) +
                                  " full_scan_budget_hits=" + std::to_string(objectScan.FullScanBudgetHits) +
                                  " seed_candidates=" + std::to_string(objectScan.SeedCandidates) +
                                  " seeds=" + std::to_string(objectScan.Seeds.size()) +
                                  " contracts=" + std::to_string(objectScan.Contracts.size()) +
                                  " contracts_omitted=" + std::to_string(objectScan.ContractsOmitted) +
                                  " contracts_ambiguous=" + std::to_string(objectScan.ContractsAmbiguous) +
                                  " uobject_layouts=" + std::to_string(objectScan.UObjectLayouts.size()) +
                                  " name_evidence=" + std::to_string(!dataNameView.Complete() ? 0 : 1) +
                                  " store_evidence=" + std::to_string(objectScan.StoreEvidence.size()) +
                                  " stores_unlogged=" + std::to_string(objectScan.StoresUnlogged) +
                                  " budget_exhausted=" + std::to_string(objectScan.BudgetExhausted) +
                                  " seed_budget_exhausted=" + std::to_string(objectScan.SeedBudgetExhausted) +
                                  " complete=" + std::to_string(result.Coverage.ObjectScanComplete);
            if (!objectScan.Error.empty())
                message += " error=" + objectScan.Error;
            result.Diagnostics.push_back(
                {objectScan.Contracts.empty() || !result.Coverage.ObjectScanComplete
                     ? DiagnosticSeverity::Warning
                     : DiagnosticSeverity::Info,
                 objectScan.Contracts.empty() ? "ANALYSIS_OBJECT_SCAN_EMPTY" : "ANALYSIS_OBJECT_SCAN",
                 std::move(message)});
        }

        result.NameStatus = DomainStatus(result.NameStores);
        result.ObjectStatus = objectContractsAmbiguous ? AnalysisStatus::Ambiguous : DomainStatus(result.ObjectArrays);
        result.UObjectStatus = DomainStatus(result.UObjectLayouts);
        const bool anyValidated = result.NameStatus == AnalysisStatus::Validated ||
                                  result.ObjectStatus == AnalysisStatus::Validated ||
                                  result.UObjectStatus == AnalysisStatus::Validated;
        const bool allValidated = result.NameStatus == AnalysisStatus::Validated &&
                                  result.ObjectStatus == AnalysisStatus::Validated &&
                                  result.UObjectStatus == AnalysisStatus::Validated;
        const bool anyObserved = result.NameStatus == AnalysisStatus::Observed ||
                                 result.ObjectStatus == AnalysisStatus::Observed ||
                                 result.UObjectStatus == AnalysisStatus::Observed;
        const bool anyAmbiguous = result.NameStatus == AnalysisStatus::Ambiguous ||
                                  result.ObjectStatus == AnalysisStatus::Ambiguous ||
                                  result.UObjectStatus == AnalysisStatus::Ambiguous;
        if (allValidated)
        {
            result.Status = AnalysisStatus::Complete;
            result.Reason = "all-domains-validated";
        }
        else if (anyValidated || (anyObserved && anyAmbiguous))
        {
            result.Status = AnalysisStatus::Partial;
            result.Reason = "domain-evidence-incomplete";
        }
        else if (anyObserved)
        {
            result.Status = AnalysisStatus::Observed;
            result.Reason = "domain-contracts-observed";
        }
        else if (anyAmbiguous)
        {
            result.Status = AnalysisStatus::Ambiguous;
            result.Reason = "domain-contracts-ambiguous";
        }
        else if (imageHeaderReadable)
        {
            result.Status = AnalysisStatus::Unsupported;
            result.Reason = "no-domain-contracts";
        }

        if (memory_.AddressSpaceGeneration() != addressSpaceGeneration)
        {
            result.AddressSpaceChanged = true;
            result.Status = AnalysisStatus::Partial;
            result.Reason = "address-space-changed";
            result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_ADDRESS_SPACE_CHANGED",
                                          "Address-space generation changed during analysis; proposals are invalidated."});
        }

        result.Coverage.Complete = imageHeaderReadable && result.Coverage.ObjectScanComplete &&
                                   result.Coverage.CodeScanComplete && !result.AddressSpaceChanged;
        return result;
    }
} // namespace nextdumper::analysis
