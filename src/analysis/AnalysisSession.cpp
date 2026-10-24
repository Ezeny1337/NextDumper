#include "nextdumper/analysis/AnalysisSession.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "nextdumper/analysis/CodeWindow.hpp"
#include "nextdumper/analysis/FunctionIndex.hpp"
#include "nextdumper/analysis/ImageModel.hpp"
#include "nextdumper/analysis/InstructionDecoder.hpp"
#include "nextdumper/analysis/NameContractScanner.hpp"
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
    } // namespace

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
        result.Coverage.PlannedBytes = image.ExecutableBytes();

        bool imageHeaderReadable = false;
        std::array<uint8_t, 16> header{};
        if (!memory_.IsReadable(module_.base, header.size()))
        {
            ++result.Coverage.ReadFailures;
            result.Status = AnalysisStatus::Partial;
            result.Reason = "image-header-unreadable";
            result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_IMAGE_HEADER_UNREADABLE",
                                          "The module header at the image base is not readable."});
        }
        else
        {
            const auto read = memory_.ReadBytes(module_.base, header.data(), header.size());
            result.Coverage.ReadBytes += read.transferred;
            if (!read.Ok())
            {
                ++result.Coverage.ReadFailures;
                result.Status = AnalysisStatus::Partial;
                result.Reason = "image-header-short-read";
                result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_IMAGE_HEADER_SHORT_READ",
                                              "The module header read was incomplete."});
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
                                              "ELF header readable; executable_bytes=" + std::to_string(result.Coverage.PlannedBytes) +
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

        const auto decoder = CreateInstructionDecoder(module_.architecture);
        if (!decoder)
        {
            result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_DECODER_UNSUPPORTED",
                                          "architecture=" + std::string(module::ModuleArchitectureName(module_.architecture))});
        }
        else
        {
            result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_DECODER_READY",
                                          "architecture=" + std::string(module::ModuleArchitectureName(module_.architecture))});
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
                    result.Coverage.ReadBytes += window.BytesFetched();
                    result.Diagnostics.push_back({DiagnosticSeverity::Info, "ANALYSIS_DECODER_SAMPLE",
                                                  "decoded=" + std::to_string(decoded) +
                                                      " other=" + std::to_string(other) +
                                                      " clobbered=" + std::to_string(clobbered) +
                                                      " bytes=" + std::to_string(window.BytesFetched())});
                }
            }
        }

        if (decoder && functions.IsValid())
        {
            NameContractScanOptions options;
            const NameContractScanResult scan = ScanNameContracts(image, functions, *decoder, options);
            result.Coverage.ScannedInstructions = scan.Instructions;
            result.Coverage.Complete = scan.Error.empty() && !scan.BudgetExhausted;
            if (!scan.Error.empty())
            {
                result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_CONTRACT_SCAN_FAILED",
                                              "reason=" + scan.Error});
            }
            for (const Contract &contract : scan.Contracts)
                result.Contracts.push_back(contract);

            NamePoolValidationOptions validationOptions;
            validationOptions.RootHints = options_.NameRootHints;
            size_t validatedContracts = 0;
            for (size_t index = 0; index < result.Contracts.size(); ++index)
            {
                Contract &contract = result.Contracts[index];
                const NamePoolFields &fields = contract.NamePool;
                NamePoolValidation validation;
                validation.ContractIndex = index;
                if (contract.Kind == ContractKind::NamePool)
                    validation = ValidateNamePool(memory_, contract, index, validationOptions);
                else
                    validation.Failure = "contract-kind";

                contract.State = validation.IsValidated() ? ContractState::Validated
                                 : validation.RootUsable  ? ContractState::Unsupported
                                                          : ContractState::Observed;
                if (validation.IsValidated())
                    ++validatedContracts;
                result.NameValidations.push_back(validation);

                const std::string root = validation.Root != 0 ? common::Hex(validation.Root)
                                         : contract.Root == 0 ? "unresolved"
                                                              : common::Hex(contract.Root);
                result.Diagnostics.push_back(
                    {DiagnosticSeverity::Info, "ANALYSIS_CONTRACT",
                     "target=NamePool root=" + root +
                         " blocks_offset=" + std::to_string(fields.BlocksOffset) +
                         " blocks_bit=" + std::to_string(fields.BlocksBit) +
                         " entry_stride=" + std::to_string(fields.EntryStride) +
                         " header_offset=" + std::to_string(fields.HeaderOffset) +
                         " string_offset=" + std::to_string(fields.StringOffset) +
                         " length_shift=" + std::to_string(fields.LengthShift) +
                         " wide_mask=" + std::to_string(fields.WideMask) +
                         " complete=" + std::to_string(fields.Complete()) +
                         " state=" + ContractStateName(contract.State) +
                         " evidence_sites=" + std::to_string(contract.Evidence.size())});

                if (validation.Decoder)
                {
                    const NameTextDecoder &decoderValue = *validation.Decoder;
                    result.Diagnostics.push_back(
                        {DiagnosticSeverity::Info, "ANALYSIS_DECODER",
                         "family=" + std::string(NameTextFamilyName(decoderValue.Family)) +
                             " key=" + std::to_string(decoderValue.Key) +
                             " key_source=" + NameKeySourceName(decoderValue.Family) +
                             " known_pairs=" + std::to_string(validation.ReservedMatched) + "/" +
                             std::to_string(validation.ReservedPairs) +
                             " consistency=" + std::to_string(validation.ReservedMatched) + "/" +
                             std::to_string(validation.ReservedPairs) +
                             " samples=" + std::to_string(validation.Block0Valid + validation.HighBlockValid) + "/" +
                             std::to_string(validation.Block0Samples + validation.HighBlockSamples) +
                             " status=" + (validation.DecoderValidated ? "validated" : "observed")});
                }

                if (validation.IsValidated())
                {
                    if (!validation.BoundaryReadable)
                    {
                        result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_BOUNDARY_UNAVAILABLE",
                                                      "target=NamePool root=" + root + " " + validation.BoundaryDetail});
                    }
                    result.Diagnostics.push_back(
                        {DiagnosticSeverity::Info, "ANALYSIS_VALIDATION",
                         "target=NamePool root=" + root +
                             " blocks=" + common::Hex(validation.BlocksAddress) +
                             " block0=" + common::Hex(validation.Block0) +
                             " current_block=" + std::to_string(validation.CurrentBlock) +
                             " byte_cursor=" + std::to_string(validation.ByteCursor) +
                             " block_size=" + std::to_string(validation.BlockSize) +
                             " allocated_blocks=" + std::to_string(validation.AllocatedBlocks) +
                             " boundary=" + (validation.BoundaryReadable ? validation.BoundaryDetail : "unavailable") +
                             " current_offset=" + std::to_string(validation.CurrentBlockOffset) +
                             " cursor_offset=" + std::to_string(validation.ByteCursorOffset) +
                             " reserved=" + std::to_string(validation.ReservedMatched) + "/" +
                             std::to_string(validation.ReservedPairs) +
                             " block0_samples=" + std::to_string(validation.Block0Valid) + "/" +
                             std::to_string(validation.Block0Samples) +
                             " high_block_samples=" + std::to_string(validation.HighBlockValid) + "/" +
                             std::to_string(validation.HighBlockSamples) +
                             " attempts=" + std::to_string(validation.AttemptedRoots) + " state=validated"});
                }
                else
                {
                    std::string message = "target=NamePool root=" + root +
                                          " reason=" + validation.Failure +
                                          " attempts=" + std::to_string(validation.AttemptedRoots);
                    if (!validation.FailureDetail.empty())
                        message += " detail=" + validation.FailureDetail;
                    if (validation.AllocatedBlocks != 0)
                        message += " allocated_blocks=" + std::to_string(validation.AllocatedBlocks);
                    if (!validation.BoundaryDetail.empty())
                        message += " boundary=" + validation.BoundaryDetail;
                    if (validation.CurrentBlockOffset >= 0)
                        message += " current_offset=" + std::to_string(validation.CurrentBlockOffset) +
                                   " cursor_offset=" + std::to_string(validation.ByteCursorOffset);
                    if (!validation.FirstEntryHex.empty())
                        message += " raw_entry0=" + validation.FirstEntryHex;
                    result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_VALIDATION_FAILED",
                                                  std::move(message)});
                }
            }
            result.Diagnostics.push_back(
                {scan.Contracts.empty() ? DiagnosticSeverity::Warning : DiagnosticSeverity::Info,
                 scan.Contracts.empty() ? "ANALYSIS_CONTRACT_SCAN_EMPTY" : "ANALYSIS_CONTRACT_SCAN",
                 "instructions=" + std::to_string(scan.Instructions) +
                     " function_starts=" + std::to_string(scan.FunctionStarts) +
                     " contracts=" + std::to_string(scan.Contracts.size()) +
                     " budget_exhausted=" + std::to_string(scan.BudgetExhausted)});
            if (scan.BudgetExhausted)
            {
                result.Diagnostics.push_back({DiagnosticSeverity::Warning, "ANALYSIS_CONTRACT_SCAN_BUDGET",
                                              "instruction budget exhausted before the scan completed"});
            }

            if (!result.Contracts.empty())
            {
                result.Status = validatedContracts != 0 ? AnalysisStatus::Validated : AnalysisStatus::Observed;
                result.Reason = validatedContracts != 0 ? "name-contracts-validated" : "name-contracts-observed";
            }
            else if (imageHeaderReadable)
            {
                result.Status = AnalysisStatus::Unsupported;
                result.Reason = "no-name-contracts";
            }
        }
        else if (imageHeaderReadable)
        {
            result.Status = AnalysisStatus::Unsupported;
            result.Reason = "no-name-contracts";
        }

        return result;
    }
} // namespace nextdumper::analysis
