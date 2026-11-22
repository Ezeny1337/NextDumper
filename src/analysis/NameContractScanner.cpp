#include "nextdumper/analysis/NameContractScanner.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <vector>

#include "nextdumper/analysis/CodeRanges.hpp"
#include "nextdumper/analysis/CodeWindow.hpp"

namespace nextdumper::analysis
{
    namespace
    {
        // 分析层按寄存器编号保存角色，上限覆盖 ARM32 的 16 个与 ARM64 的 31 个通用寄存器
        constexpr int kMaxTrackedRegisters = 32;

        enum class RoleKind : uint8_t
        {
            None,
            Input,
            Global,
            BlockIndex,
            BlockSlot,
            BlockPointer,
            EntryIndex,
            Entry,
            Header,
            Length,
            Text,
            ArrayWithin,
            ArrayEntrySlot,
            ArrayEntryPointer,
            ArrayIndexField,
            ArrayText,
        };

        struct Role
        {
            RoleKind Kind = RoleKind::None;
            uintptr_t Global = 0;
            bool PageBase = false;

            int32_t BlocksOffset = -1;
            int32_t BlocksBit = -1;
            int32_t EntryStride = 0;
            int64_t EntryIndexOffset = -1;
            int32_t HeaderOffset = 0;
            int32_t StringOffset = 2;
            int32_t LengthShift = 0;
            uint16_t WideMask = 0;

            uint8_t Shift = 0;
            uint8_t Width = 0;
            uint64_t IdMask = 0;
            int EntryReg = -1;

            uintptr_t GlobalSite = 0;
            uintptr_t ShiftSite = 0;
            uintptr_t BlockSlotSite = 0;
            uintptr_t TableLoadSite = 0;
            uintptr_t EntryIndexSite = 0;
            uintptr_t EntrySite = 0;
            uintptr_t HeaderSite = 0;
            uintptr_t LengthSite = 0;
            uintptr_t TestSite = 0;
            uintptr_t TextSite = 0;
        };

        Role InputRole()
        {
            Role role;
            role.Kind = RoleKind::Input;
            return role;
        }

        uint64_t SingleBitMask(uint8_t width)
        {
            if (width == 0)
                return 0;
            return width >= 64 ? ~uint64_t{0} : (uint64_t{1} << width) - 1;
        }

        bool SameChain(const NameStoreContract &left, const NameStoreContract &right)
        {
            if (left.Root != right.Root || left.Family != right.Family)
                return false;
            if (left.Family == NameStoreFamily::Array)
                return left.NameArray == right.NameArray;

            return left.NamePool.BlocksOffset == right.NamePool.BlocksOffset &&
                   left.NamePool.BlocksBit == right.NamePool.BlocksBit &&
                   left.NamePool.EntryStride == right.NamePool.EntryStride &&
                   left.NamePool.HeaderOffset == right.NamePool.HeaderOffset &&
                   left.NamePool.StringOffset == right.NamePool.StringOffset;
        }

        class Scanner
        {
        public:
            Scanner(const ImageModel &image, const FunctionIndex &functions, const CodeRangeSet &ranges,
                    const NameContractScanOptions &options)
                : image_(image), functions_(functions), ranges_(ranges), options_(options)
            {
            }

            NameContractScanResult Run()
            {
                NameContractScanResult result;
                if (!image_.IsValid() || !functions_.IsValid())
                {
                    result.Error = "image-or-function-index-invalid";
                    return result;
                }

                std::vector<uint64_t> starts;
                if (!functions_.CopyStarts(starts, result.Error))
                    return result;
                std::sort(starts.begin(), starts.end());

                CodeWindow window(image_.Memory());

                for (const CodeRange &range : ranges_.Ranges)
                {
                    if (range.End <= range.Start || range.End > image_.Module().end)
                        continue;
                    if (!image_.Module().IsReadable(static_cast<uintptr_t>(range.Start),
                                                    static_cast<size_t>(range.End - range.Start)))
                    {
                        ++result.UnreadableSegments;
                        continue;
                    }

                    const auto rangeDecoder = CreateInstructionDecoder(image_.Module().architecture, range.Mode);
                    if (!rangeDecoder)
                    {
                        ++result.UnknownModeRanges;
                        continue;
                    }
                    const uint32_t stride = rangeDecoder->Stride();
                    const uint32_t maxBytes = rangeDecoder->MaxInstructionBytes();
                    const int registerCount = rangeDecoder->RegisterCount();
                    if (registerCount <= 0 || registerCount > kMaxTrackedRegisters)
                    {
                        ++result.UnreadableSegments;
                        continue;
                    }
                    roles_.assign(static_cast<size_t>(registerCount), Role{});
                    decoder_ = rangeDecoder.get();
                    ++result.DecodedRanges;

                    auto startAt = std::lower_bound(starts.begin(), starts.end(), range.Start);
                    size_t startIndex = static_cast<size_t>(startAt - starts.begin());
                    if (startIndex >= starts.size() || starts[startIndex] >= range.End)
                    {
                        ++result.SegmentsWithoutFunctionStart;
                        continue;
                    }

                    uintptr_t address = static_cast<uintptr_t>(std::max<uint64_t>(range.Start, starts[startIndex]));
                    if (stride > 1)
                        address &= ~static_cast<uintptr_t>(stride - 1);
                    const uintptr_t coveredStart = address;
                    result.SkippedPrefixBytes += address - range.Start;
                    ResetRoles();
                    functionStart_ = address;

                    while (address < range.End)
                    {
                        while (startIndex < starts.size() && starts[startIndex] < address)
                            ++startIndex;
                        if (startIndex < starts.size() && starts[startIndex] == address)
                        {
                            ResetRoles();
                            functionStart_ = address;
                            ++result.FunctionStarts;
                            ++startIndex;
                        }

                        const uint8_t *bytes = window.At(address, maxBytes);
                        if (!bytes)
                        {
                            ++result.ReadTruncatedSegments;
                            break;
                        }

                        Instruction instruction;
                        if (!decoder_->Decode(bytes, maxBytes, address, instruction))
                        {
                            ++result.DecodeTruncatedSegments;
                            break;
                        }

                        ++result.Instructions;
                        Process(instruction, address);
                        if (result.Instructions >= options_.MaxInstructions)
                            result.BudgetExhausted = true;

                        const uint32_t length = instruction.Length ? instruction.Length : stride;
                        if (length > range.End - address || length < stride)
                        {
                            ++result.ExtentTruncatedSegments;
                            break;
                        }
                        address += length;
                        if (result.BudgetExhausted)
                            break;
                    }
                    if (address > coveredStart)
                        result.DecodedBytes += address - coveredStart;

                    if (result.BudgetExhausted)
                        break;
                }

                result.FetchedBytes = window.BytesFetched();
                result.Recognition = recognition_;
                result.Contracts = std::move(contracts_);
                return result;
            }

        private:
            void ResetRoles()
            {
                for (auto &role : roles_)
                    role = Role{};
                if (roles_.size() > 8)
                {
                    for (size_t index = 0; index < 8; ++index)
                        roles_[index] = InputRole();
                }
            }

            Role CopyRole(int reg) const
            {
                if (reg < 0 || static_cast<size_t>(reg) >= roles_.size())
                    return {};
                return roles_[static_cast<size_t>(reg)];
            }

            void Assign(int reg, const Role &role)
            {
                if (reg >= 0 && static_cast<size_t>(reg) < roles_.size())
                    roles_[static_cast<size_t>(reg)] = role;
            }

            void UpdateArrayEntryAliases(const Role &entry)
            {
                for (auto &role : roles_)
                {
                    if (role.Kind == RoleKind::ArrayEntryPointer && role.EntrySite == entry.EntrySite)
                        role = entry;
                }
            }

            void ClearRoles()
            {
                for (auto &role : roles_)
                    role = Role{};
            }

            void ClearCallerSaved()
            {
                const size_t callerSaved = std::min<size_t>(roles_.size(), 19);
                for (size_t index = 0; index < callerSaved; ++index)
                    roles_[index] = Role{};
                if (roles_.size() > 30)
                    roles_[30] = Role{};
            }

            void Record(const Role &role, uintptr_t site)
            {
                (void)site;
                ++recognition_.RecordAttempts;
                if (role.HeaderSite == 0)
                    ++recognition_.RecordsWithoutHeader;

                if (role.BlocksOffset < 0)
                {
                    ++recognition_.RejectedBlocksOffset;
                    return;
                }
                if (role.BlocksBit < 8 || role.BlocksBit > 24)
                {
                    ++recognition_.RejectedBlocksBit;
                    return;
                }
                if (role.EntryStride != 2 && role.EntryStride != 4)
                {
                    ++recognition_.RejectedStride;
                    return;
                }
                if (role.HeaderOffset < 0 || role.HeaderOffset > 64)
                {
                    ++recognition_.RejectedHeaderOffset;
                    return;
                }
                if (role.StringOffset < role.HeaderOffset + 2 || role.StringOffset > 64)
                {
                    ++recognition_.RejectedStringOffset;
                    return;
                }
                if (role.LengthShift != 0 && (role.LengthShift < 1 || role.LengthShift > 15))
                {
                    ++recognition_.RejectedLengthShift;
                    return;
                }
                if (role.IdMask != 0 && static_cast<int32_t>(std::bit_width(role.IdMask)) != role.BlocksBit)
                {
                    ++recognition_.RejectedIdMask;
                    return;
                }

                NameStoreContract contract;
                contract.Root = role.Global;
                contract.State = ContractState::Observed;
                contract.Family = NameStoreFamily::Pool;
                contract.NamePool.BlocksOffset = role.BlocksOffset;
                contract.NamePool.BlocksBit = role.BlocksBit;
                contract.NamePool.EntryStride = role.EntryStride;
                contract.NamePool.HeaderOffset = role.HeaderOffset;
                contract.NamePool.StringOffset = role.StringOffset;
                contract.NamePool.LengthShift = role.LengthShift;
                contract.NamePool.WideMask = role.WideMask;

                if (role.Global != 0)
                    contract.Evidence.push_back({EvidenceKind::GlobalBase, role.GlobalSite, role.Global});
                else
                    contract.Evidence.push_back({EvidenceKind::UnresolvedRoot, functionStart_, 0});
                contract.Evidence.push_back({EvidenceKind::Shift, role.ShiftSite, static_cast<uint64_t>(role.BlocksBit)});
                contract.Evidence.push_back({EvidenceKind::ScaleAdd, role.BlockSlotSite, 8});
                contract.Evidence.push_back({EvidenceKind::TableLoad, role.TableLoadSite, static_cast<uint64_t>(role.BlocksOffset)});
                contract.Evidence.push_back({EvidenceKind::Mask, role.EntryIndexSite, role.IdMask});
                contract.Evidence.push_back({EvidenceKind::EntryLoad, role.EntrySite, static_cast<uint64_t>(role.EntryStride)});
                contract.Evidence.push_back({EvidenceKind::HeaderLoad, role.HeaderSite, static_cast<uint64_t>(role.HeaderOffset)});
                if (role.LengthShift > 0)
                    contract.Evidence.push_back({EvidenceKind::Shift, role.LengthSite, static_cast<uint64_t>(role.LengthShift)});
                if (role.WideMask != 0)
                    contract.Evidence.push_back({EvidenceKind::WidthTest, role.TestSite, role.WideMask});
                if (role.TextSite != 0)
                    contract.Evidence.push_back({EvidenceKind::TextOffset, role.TextSite, static_cast<uint64_t>(role.StringOffset)});

                const bool complete = contract.NamePool.Complete();
                if (!complete)
                    ++recognition_.IncompleteRecords;
                for (auto &existing : contracts_)
                {
                    if (SameChain(existing, contract))
                    {
                        if (complete && !existing.Complete())
                            existing = std::move(contract);
                        return;
                    }
                }

                if (contracts_.size() < options_.MaxContracts)
                {
                    contracts_.push_back(std::move(contract));
                    return;
                }
                ++recognition_.ContractLimitHits;
                if (!complete)
                    return;
                for (auto &existing : contracts_)
                {
                    if (!existing.Complete())
                    {
                        existing = std::move(contract);
                        return;
                    }
                }
            }

            void RecordArray(const Role &role, uintptr_t site)
            {
                (void)site;
                ++recognition_.ArrayRecordAttempts;
                if (role.EntryIndexOffset < 0)
                {
                    ++recognition_.ArrayRecordsWithoutIndex;
                    return;
                }
                if (role.StringOffset < 0)
                {
                    ++recognition_.ArrayRecordsWithoutText;
                    return;
                }
                if (role.BlocksOffset < 0)
                {
                    ++recognition_.RejectedArrayChunksOffset;
                    return;
                }
                if (role.BlocksBit < 8 || role.BlocksBit > 24)
                {
                    ++recognition_.RejectedArrayChunkShift;
                    return;
                }
                if (role.EntryStride < 4 || role.EntryStride > 64 || role.EntryStride % 4 != 0)
                {
                    ++recognition_.RejectedArrayEntryStride;
                    return;
                }
                if (role.EntryIndexOffset > 64)
                {
                    ++recognition_.RejectedArrayIndexOffset;
                    return;
                }
                if (role.StringOffset < role.EntryIndexOffset + 4 || role.StringOffset > 128)
                {
                    ++recognition_.RejectedArrayStringOffset;
                    return;
                }

                NameStoreContract contract;
                contract.Root = role.Global;
                contract.State = ContractState::Observed;
                contract.Family = NameStoreFamily::Array;
                contract.NameArray = {role.BlocksOffset, role.BlocksBit, role.EntryStride,
                                      static_cast<int32_t>(role.EntryIndexOffset), role.StringOffset};

                if (role.Global != 0)
                    contract.Evidence.push_back({EvidenceKind::GlobalBase, role.GlobalSite, role.Global});
                else
                    contract.Evidence.push_back({EvidenceKind::UnresolvedRoot, functionStart_, 0});
                contract.Evidence.push_back({EvidenceKind::Shift, role.ShiftSite, static_cast<uint64_t>(role.BlocksBit)});
                contract.Evidence.push_back({EvidenceKind::ScaleAdd, role.BlockSlotSite, 8});
                contract.Evidence.push_back({EvidenceKind::TableLoad, role.TableLoadSite, static_cast<uint64_t>(role.BlocksOffset)});
                contract.Evidence.push_back({EvidenceKind::EntryLoad, role.EntrySite, static_cast<uint64_t>(role.EntryStride)});
                contract.Evidence.push_back({EvidenceKind::EntryLoad, role.EntryIndexSite, static_cast<uint64_t>(role.EntryIndexOffset)});
                contract.Evidence.push_back({EvidenceKind::TextOffset, role.TextSite, static_cast<uint64_t>(role.StringOffset)});

                for (const auto &existing : contracts_)
                {
                    if (SameChain(existing, contract))
                        return;
                }
                if (contracts_.size() < options_.MaxContracts)
                {
                    contracts_.push_back(std::move(contract));
                    return;
                }
                if (contract.Complete())
                {
                    for (auto &existing : contracts_)
                    {
                        if (!existing.Complete())
                        {
                            existing = std::move(contract);
                            return;
                        }
                    }
                }
                ++recognition_.ContractLimitHits;
            }

            void Process(const Instruction &instruction, uintptr_t site)
            {
                if (instruction.bClobbersAll)
                {
                    ClearRoles();
                    return;
                }

                switch (instruction.Kind)
                {
                case InstructionKind::SetBase:
                {
                    ++recognition_.BaseInstructions;
                    Role role;
                    role.Kind = RoleKind::Global;
                    role.Global = static_cast<uintptr_t>(instruction.Value);
                    role.PageBase = !instruction.bExactAddress;
                    role.GlobalSite = site;
                    Assign(instruction.Dest, role);
                    return;
                }
                case InstructionKind::AddImmediate:
                {
                    const Role base = CopyRole(instruction.Base);
                    if (base.Kind == RoleKind::Global)
                    {
                        Role role = base;
                        if (role.PageBase)
                        {
                            role.PageBase = false;
                        }
                        if (role.Global > UINTPTR_MAX - instruction.Value)
                        {
                            Assign(instruction.Dest, InputRole());
                            return;
                        }
                        role.Global += static_cast<uintptr_t>(instruction.Value);
                        Assign(instruction.Dest, role);
                        return;
                    }
                    if (base.Kind == RoleKind::Entry)
                    {
                        Role role = base;
                        role.Kind = RoleKind::Text;
                        role.StringOffset = static_cast<int32_t>(std::min<uint64_t>(instruction.Value, 0x7FFFFFFF));
                        role.TextSite = site;
                        Assign(instruction.Dest, role);
                        Record(role, site);
                        return;
                    }
                    if (base.Kind == RoleKind::ArrayEntryPointer)
                    {
                        ++recognition_.ArrayTextBases;
                        Role role = base;
                        role.StringOffset = static_cast<int32_t>(std::min<uint64_t>(instruction.Value, 0x7FFFFFFF));
                        role.TextSite = site;
                        UpdateArrayEntryAliases(role);
                        role.Kind = RoleKind::ArrayText;
                        Assign(instruction.Dest, role);
                        RecordArray(role, site);
                        return;
                    }
                    Assign(instruction.Dest, InputRole());
                    return;
                }
                case InstructionKind::AddShiftedRegister:
                case InstructionKind::AddExtendedRegister:
                {
                    const Role base = CopyRole(instruction.Base);
                    const Role source = CopyRole(instruction.Source);
                    const bool scalesIndex = instruction.Kind == InstructionKind::AddShiftedRegister
                                                 ? instruction.ShiftType == ShiftKind::Lsl
                                                 : (instruction.Extend == ExtendKind::Uxtw || instruction.Extend == ExtendKind::Uxtx ||
                                                    instruction.Extend == ExtendKind::Sxtw || instruction.Extend == ExtendKind::Sxtx);

                    if (scalesIndex && instruction.Shift == 3 &&
                        (base.Kind == RoleKind::Global || base.Kind == RoleKind::Input) &&
                        source.Kind == RoleKind::BlockIndex)
                    {
                        ++recognition_.BlockSlots;
                        ++recognition_.ArrayChunkSlots;
                        Role role;
                        role.Kind = RoleKind::BlockSlot;
                        role.Global = base.Kind == RoleKind::Global ? base.Global : 0;
                        role.GlobalSite = base.GlobalSite;
                        role.BlocksBit = source.BlocksBit;
                        role.Shift = source.Shift;
                        role.BlockSlotSite = site;
                        Assign(instruction.Dest, role);
                        return;
                    }

                    if (instruction.Shift == 0 && base.Kind == RoleKind::BlockPointer &&
                        source.Kind == RoleKind::EntryIndex)
                    {
                        if (base.BlocksBit > 0 && source.BlocksBit > 0 && base.BlocksBit != source.BlocksBit)
                        {
                            ++recognition_.EntrySplitMismatches;
                            Assign(instruction.Dest, InputRole());
                            return;
                        }
                        ++recognition_.EntryAddresses;
                        Role role = base;
                        role.Kind = RoleKind::Entry;
                        role.BlocksBit = source.BlocksBit;
                        role.EntryStride = source.EntryStride;
                        role.IdMask = source.IdMask;
                        role.Shift = source.Shift;
                        role.Width = source.Width;
                        role.EntryIndexSite = source.EntryIndexSite;
                        role.EntrySite = site;
                        role.EntryReg = instruction.Dest;
                        Assign(instruction.Dest, role);
                        return;
                    }

                    if (scalesIndex && instruction.Shift >= 2 && instruction.Shift <= 3 &&
                        base.Kind == RoleKind::BlockPointer && source.Kind == RoleKind::ArrayWithin)
                    {
                        if (base.BlocksBit > 0 && source.BlocksBit > 0 && base.BlocksBit != source.BlocksBit)
                        {
                            ++recognition_.EntrySplitMismatches;
                            Assign(instruction.Dest, InputRole());
                            return;
                        }
                        ++recognition_.ArrayEntrySlots;
                        Role role = base;
                        role.Kind = RoleKind::ArrayEntrySlot;
                        role.Shift = instruction.Shift;
                        role.EntryStride = static_cast<int32_t>(uint32_t{1} << role.Shift);
                        Assign(instruction.Dest, role);
                        return;
                    }

                    Assign(instruction.Dest, InputRole());
                    return;
                }
                case InstructionKind::Load:
                {
                    const Role base = CopyRole(instruction.Base);
                    if (base.Kind == RoleKind::BlockSlot && instruction.AccessWidth == 8)
                    {
                        Role role = base;
                        role.Kind = RoleKind::BlockPointer;
                        role.BlocksOffset = static_cast<int32_t>(instruction.Offset);
                        role.TableLoadSite = site;
                        Assign(instruction.Dest, role);
                        return;
                    }
                    if (base.Kind == RoleKind::Entry && instruction.AccessWidth == 2)
                    {
                        ++recognition_.HeaderLoads;
                        Role role = base;
                        role.Kind = RoleKind::Header;
                        role.HeaderOffset = static_cast<int32_t>(instruction.Offset);
                        role.StringOffset = role.HeaderOffset + 2;
                        role.HeaderSite = site;
                        Assign(instruction.Dest, role);
                        Record(role, site);
                        return;
                    }
                    if (base.Kind == RoleKind::ArrayEntrySlot && instruction.AccessWidth == 8 && instruction.Offset == 0)
                    {
                        ++recognition_.ArrayEntryLoads;
                        Role role = base;
                        role.Kind = RoleKind::ArrayEntryPointer;
                        role.StringOffset = -1;
                        role.EntrySite = site;
                        Assign(instruction.Dest, role);
                        return;
                    }
                    if (base.Kind == RoleKind::ArrayEntryPointer && instruction.AccessWidth == 4)
                    {
                        ++recognition_.ArrayIndexLoads;
                        Role role = base;
                        role.EntryIndexOffset = instruction.Offset;
                        role.EntryIndexSite = site;
                        UpdateArrayEntryAliases(role);
                        role.Kind = RoleKind::ArrayIndexField;
                        Assign(instruction.Dest, role);
                        RecordArray(role, site);
                        return;
                    }
                    Assign(instruction.Dest, InputRole());
                    return;
                }
                case InstructionKind::LoadLiteral:
                case InstructionKind::MoveImmediate:
                    Assign(instruction.Dest, InputRole());
                    return;
                case InstructionKind::MoveRegister:
                case InstructionKind::SignExtend:
                    Assign(instruction.Dest, CopyRole(instruction.Base));
                    return;
                case InstructionKind::LogicalShiftRight:
                case InstructionKind::ArithmeticShiftRight:
                {
                    const Role base = CopyRole(instruction.Base);
                    if (base.Kind == RoleKind::Header)
                    {
                        Role header = base;
                        header.LengthShift = instruction.Shift;
                        header.LengthSite = site;
                        if (header.EntryReg >= 0 && static_cast<size_t>(header.EntryReg) < roles_.size())
                        {
                            roles_[static_cast<size_t>(header.EntryReg)].LengthShift = instruction.Shift;
                            roles_[static_cast<size_t>(header.EntryReg)].LengthSite = site;
                        }
                        Assign(instruction.Base, header);
                        Role length = header;
                        length.Kind = RoleKind::Length;
                        Assign(instruction.Dest, length);
                        Record(header, site);
                        return;
                    }
                    if (base.Kind == RoleKind::Input && instruction.Shift >= 8 && instruction.Shift <= 24)
                    {
                        ++recognition_.ArrayChunkShifts;
                        Role role;
                        role.Kind = RoleKind::BlockIndex;
                        role.BlocksBit = instruction.Shift;
                        role.Shift = instruction.Shift;
                        role.ShiftSite = site;
                        Assign(instruction.Dest, role);
                        return;
                    }
                    Assign(instruction.Dest, InputRole());
                    return;
                }
                case InstructionKind::BitfieldExtract:
                {
                    const Role base = CopyRole(instruction.Base);
                    if (base.Kind == RoleKind::Input && instruction.Shift >= 8 && instruction.Shift <= 24)
                    {
                        ++recognition_.ArrayChunkShifts;
                        Role role;
                        role.Kind = RoleKind::BlockIndex;
                        role.BlocksBit = instruction.Shift;
                        role.Shift = instruction.Shift;
                        role.Width = instruction.BitWidth;
                        role.ShiftSite = site;
                        Assign(instruction.Dest, role);
                        return;
                    }
                    Assign(instruction.Dest, InputRole());
                    return;
                }
                case InstructionKind::BitfieldInsert:
                {
                    const Role base = CopyRole(instruction.Base);
                    if (base.Kind == RoleKind::Input && instruction.Shift <= 2)
                    {
                        Role role;
                        role.Kind = RoleKind::EntryIndex;
                        role.Shift = instruction.Shift;
                        role.Width = instruction.BitWidth;
                        role.IdMask = SingleBitMask(instruction.BitWidth);
                        role.BlocksBit = static_cast<int32_t>(std::bit_width(role.IdMask));
                        role.EntryStride = static_cast<int32_t>(uint32_t{1} << instruction.Shift);
                        role.EntryIndexSite = site;
                        Assign(instruction.Dest, role);
                        return;
                    }
                    Assign(instruction.Dest, InputRole());
                    return;
                }
                case InstructionKind::AndImmediate:
                {
                    const Role base = CopyRole(instruction.Base);
                    if (base.Kind == RoleKind::EntryIndex && base.Shift <= 2 &&
                        instruction.Mask != 0 && (instruction.Mask & ((uint64_t{1} << base.Shift) - 1)) == 0)
                    {
                        Role role = base;
                        role.IdMask = instruction.Mask >> base.Shift;
                        role.BlocksBit = static_cast<int32_t>(std::bit_width(role.IdMask));
                        role.EntryIndexSite = site;
                        Assign(instruction.Dest, role);
                        return;
                    }
                    if (base.Kind == RoleKind::Input && std::has_single_bit(instruction.Mask + 1))
                    {
                        const auto bits = std::bit_width(instruction.Mask);
                        if (bits >= 8 && bits <= 24)
                        {
                            Role role;
                            role.Kind = RoleKind::ArrayWithin;
                            role.BlocksBit = static_cast<int32_t>(bits);
                            role.Shift = 0;
                            Assign(instruction.Dest, role);
                            return;
                        }
                    }
                    Assign(instruction.Dest, InputRole());
                    return;
                }
                case InstructionKind::TestBit:
                {
                    const Role base = CopyRole(instruction.Base);
                    if (base.Kind == RoleKind::Header && instruction.Bit == 0)
                    {
                        Role role = base;
                        role.WideMask = 1;
                        role.TestSite = site;
                        if (role.EntryReg >= 0 && static_cast<size_t>(role.EntryReg) < roles_.size())
                        {
                            roles_[static_cast<size_t>(role.EntryReg)].WideMask = 1;
                            roles_[static_cast<size_t>(role.EntryReg)].TestSite = site;
                        }
                        Assign(instruction.Base, role);
                        Record(role, site);
                    }
                    return;
                }
                case InstructionKind::LoadPair:
                    Assign(instruction.Dest, InputRole());
                    Assign(instruction.Dest2, InputRole());
                    return;
                case InstructionKind::StorePair:
                case InstructionKind::Store:
                case InstructionKind::ConditionalBranch:
                case InstructionKind::Prologue:
                    return;
                case InstructionKind::Call:
                    ClearCallerSaved();
                    return;
                case InstructionKind::Branch:
                case InstructionKind::Return:
                    ClearRoles();
                    return;
                case InstructionKind::Other:
                    if (instruction.Dest >= 0)
                        Assign(instruction.Dest, InputRole());
                    return;
                }
            }

            const ImageModel &image_;
            const FunctionIndex &functions_;
            const CodeRangeSet &ranges_;
            const InstructionDecoder *decoder_ = nullptr;
            NameContractScanOptions options_;
            std::vector<Role> roles_;
            std::vector<NameStoreContract> contracts_;
            NameContractRecognitionStats recognition_;
            uintptr_t functionStart_ = 0;
        };
    } // namespace

    NameContractScanResult ScanNameContracts(const ImageModel &image,
                                             const FunctionIndex &functions,
                                             const CodeRangeSet &ranges,
                                             const NameContractScanOptions &options)
    {
        Scanner scanner(image, functions, ranges, options);
        return scanner.Run();
    }
} // namespace nextdumper::analysis
