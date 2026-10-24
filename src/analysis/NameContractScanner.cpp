#include "nextdumper/analysis/NameContractScanner.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <vector>

#include "nextdumper/analysis/CodeWindow.hpp"

namespace nextdumper::analysis
{
    namespace
    {
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
        };

        struct Role
        {
            RoleKind Kind = RoleKind::None;
            uintptr_t Global = 0;
            bool PageBase = false;

            int32_t BlocksOffset = -1;
            int32_t BlocksBit = -1;
            int32_t EntryStride = 0;
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

        bool SameChain(const NamePoolContract &contract, const Role &role)
        {
            return contract.Root == role.Global &&
                   contract.NamePool.BlocksOffset == role.BlocksOffset &&
                   contract.NamePool.BlocksBit == role.BlocksBit &&
                   contract.NamePool.EntryStride == role.EntryStride &&
                   contract.NamePool.HeaderOffset == role.HeaderOffset &&
                   contract.NamePool.StringOffset == role.StringOffset;
        }

        class Scanner
        {
        public:
            Scanner(const ImageModel &image, const FunctionIndex &functions,
                    const InstructionDecoder &decoder, const NameContractScanOptions &options)
                : image_(image), functions_(functions), decoder_(decoder), options_(options)
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

                roles_.resize(static_cast<size_t>(std::max(1, decoder_.RegisterCount())));
                CodeWindow window(image_.Memory());

                for (const auto &segment : image_.Module().segments)
                {
                    if (!segment.executable || !segment.readable || segment.end <= segment.start)
                        continue;

                    auto startAt = std::lower_bound(starts.begin(), starts.end(),
                                                    static_cast<uint64_t>(segment.start));
                    size_t startIndex = static_cast<size_t>(startAt - starts.begin());
                    if (startIndex >= starts.size() || starts[startIndex] >= segment.end)
                        continue;

                    uintptr_t address = static_cast<uintptr_t>(std::max<uint64_t>(segment.start, starts[startIndex])) & ~uintptr_t{3};
                    ResetRoles();
                    functionStart_ = address;

                    while (address < segment.end)
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

                        const uint8_t *bytes = window.At(address, 4);
                        if (!bytes)
                            break;

                        Instruction instruction;
                        if (!decoder_.Decode(bytes, 4, address, instruction))
                            break;

                        ++result.Instructions;
                        Process(instruction, address);

                        if (result.Instructions >= options_.MaxInstructions)
                        {
                            result.BudgetExhausted = true;
                            break;
                        }

                        const uint32_t length = instruction.Length ? instruction.Length : 4;
                        if (length > UINTPTR_MAX - address || address + length > segment.end)
                            break;
                        address += length;
                    }

                    if (result.BudgetExhausted)
                        break;
                }

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
                if (role.BlocksOffset < 0 || role.BlocksBit < 8 || role.BlocksBit > 24 ||
                    (role.EntryStride != 2 && role.EntryStride != 4) ||
                    role.HeaderOffset < 0 || role.HeaderOffset > 64 ||
                    role.StringOffset < role.HeaderOffset + 2 || role.StringOffset > 64 ||
                    (role.LengthShift != 0 && (role.LengthShift < 1 || role.LengthShift > 15)))
                    return;

                if (role.IdMask != 0 && static_cast<int32_t>(std::bit_width(role.IdMask)) != role.BlocksBit)
                    return;

                NamePoolContract contract;
                contract.Root = role.Global;
                contract.State = ContractState::Observed;
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
                for (auto &existing : contracts_)
                {
                    if (SameChain(existing, role))
                    {
                        if (complete && !existing.NamePool.Complete())
                            existing = std::move(contract);
                        return;
                    }
                }

                if (contracts_.size() < options_.MaxContracts)
                {
                    contracts_.push_back(std::move(contract));
                    return;
                }
                if (!complete)
                    return;
                for (auto &existing : contracts_)
                {
                    if (!existing.NamePool.Complete())
                    {
                        existing = std::move(contract);
                        return;
                    }
                }
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
                    Assign(instruction.Dest, InputRole());
                    return;
                }
                case InstructionKind::AddShiftedRegister:
                case InstructionKind::AddExtendedRegister:
                {
                    const Role base = CopyRole(instruction.Base);
                    const Role source = CopyRole(instruction.Source);
                    const bool scaled = instruction.Shift == 3 &&
                                        (instruction.Kind == InstructionKind::AddShiftedRegister
                                             ? instruction.ShiftType == ShiftKind::Lsl
                                             : (instruction.Extend == ExtendKind::Uxtw || instruction.Extend == ExtendKind::Uxtx));

                    if (scaled && (base.Kind == RoleKind::Global || base.Kind == RoleKind::Input) &&
                        source.Kind == RoleKind::BlockIndex)
                    {
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
                            Assign(instruction.Dest, InputRole());
                            return;
                        }
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
                        Role role = base;
                        role.Kind = RoleKind::Header;
                        role.HeaderOffset = static_cast<int32_t>(instruction.Offset);
                        role.StringOffset = role.HeaderOffset + 2;
                        role.HeaderSite = site;
                        Assign(instruction.Dest, role);
                        Record(role, site);
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
                    Assign(instruction.Dest, CopyRole(instruction.Base));
                    return;
                case InstructionKind::LogicalShiftRight:
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
            const InstructionDecoder &decoder_;
            NameContractScanOptions options_;
            std::vector<Role> roles_;
            std::vector<NamePoolContract> contracts_;
            uintptr_t functionStart_ = 0;
        };
    } // namespace

    NameContractScanResult ScanNameContracts(const ImageModel &image,
                                             const FunctionIndex &functions,
                                             const InstructionDecoder &decoder,
                                             const NameContractScanOptions &options)
    {
        Scanner scanner(image, functions, decoder, options);
        return scanner.Run();
    }
} // namespace nextdumper::analysis
