#include "nextdumper/analysis/InstructionDecoder.hpp"

#include <cstring>

namespace nextdumper::analysis
{
    namespace
    {
        int Register(uint32_t value) { return value == 31 ? -1 : static_cast<int>(value); }

        int64_t Signed(uint64_t value, unsigned bits)
        {
            const uint64_t sign = uint64_t{1} << (bits - 1);
            return (value & sign) ? -static_cast<int64_t>((uint64_t{1} << bits) - value) : static_cast<int64_t>(value);
        }

        uint64_t RotateRight(uint64_t value, unsigned rotation, unsigned width)
        {
            rotation %= width;
            if (rotation == 0)
                return value;
            const uint64_t mask = width == 64 ? ~uint64_t{0} : (uint64_t{1} << width) - 1;
            value &= mask;
            return ((value >> rotation) | (value << (width - rotation))) & mask;
        }

        bool DecodeLogicalImmediate(uint32_t word, bool sf, uint64_t &mask)
        {
            const uint32_t n = (word >> 22) & 1;
            const uint32_t immr = (word >> 16) & 0x3f;
            const uint32_t imms = (word >> 10) & 0x3f;
            if (!sf && n)
                return false;

            const uint32_t combined = (n << 6) | (~imms & 0x3f);
            int len = -1;
            for (int bit = 6; bit >= 0; --bit)
            {
                if (combined & (1u << bit))
                {
                    len = bit;
                    break;
                }
            }
            if (len < 1)
                return false;

            const uint32_t levels = (1u << len) - 1;
            if ((imms & levels) == levels)
                return false;

            const uint32_t s = imms & levels;
            const uint32_t r = immr & levels;
            const uint32_t esize = 1u << len;
            const uint64_t esizeMask = esize == 64 ? ~uint64_t{0} : (uint64_t{1} << esize) - 1;
            const uint64_t element = ((uint64_t{1} << (s + 1)) - 1) & esizeMask;
            const uint64_t rotated = RotateRight(element, r, esize);

            uint64_t result = 0;
            for (uint32_t shift = 0; shift < 64; shift += esize)
                result |= rotated << shift;

            mask = sf ? result : (result & UINT32_MAX);
            return true;
        }

        ShiftKind ShiftFromBits(uint32_t bits)
        {
            switch (bits)
            {
            case 0:
                return ShiftKind::Lsl;
            case 1:
                return ShiftKind::Lsr;
            case 2:
                return ShiftKind::Asr;
            case 3:
                return ShiftKind::Ror;
            }
            return ShiftKind::None;
        }

        ExtendKind ExtendFromBits(uint32_t bits)
        {
            switch (bits)
            {
            case 0:
                return ExtendKind::Uxtb;
            case 1:
                return ExtendKind::Uxth;
            case 2:
                return ExtendKind::Uxtw;
            case 3:
                return ExtendKind::Uxtx;
            case 4:
                return ExtendKind::Sxtb;
            case 5:
                return ExtendKind::Sxth;
            case 6:
                return ExtendKind::Sxtw;
            case 7:
                return ExtendKind::Sxtx;
            }
            return ExtendKind::None;
        }

        class Arm64InstructionDecoder final : public InstructionDecoder
        {
        public:
            [[nodiscard]] uint32_t Stride() const override { return 4; }
            [[nodiscard]] int RegisterCount() const override { return 31; }

            [[nodiscard]] bool Decode(const uint8_t *bytes, size_t available,
                                      uintptr_t address, Instruction &out) const override
            {
                out = {};
                out.Length = 4;
                if (!bytes || available < 4)
                    return false;

                uint32_t word = 0;
                std::memcpy(&word, bytes, sizeof(word));

                const int rd = Register(word & 31);
                const int rn = Register((word >> 5) & 31);
                const bool sf = (word >> 31) != 0;
                out.OperandWidth = sf ? 8 : 4;

                if ((word & 0xfffffc1f) == 0xd65f0000)
                {
                    out.Kind = InstructionKind::Return;
                    return true;
                }
                if ((word & 0xfffffc1f) == 0xd63f0000 || (word & 0xfffffc1f) == 0xd61f0000)
                {
                    out.Kind = (word & 0x00200000) ? InstructionKind::Call : InstructionKind::Branch;
                    out.Base = rn;
                    return true;
                }
                if ((word & 0x7c000000) == 0x14000000)
                {
                    out.Kind = (word >> 31) ? InstructionKind::Call : InstructionKind::Branch;
                    out.Value = address + static_cast<uint64_t>(Signed(word & 0x03ffffff, 26) * 4);
                    return true;
                }
                if ((word & 0x7e000000) == 0x36000000)
                {
                    const uint32_t bit = (((word >> 31) & 1) << 5) | ((word >> 19) & 0x1f);
                    out.Kind = InstructionKind::TestBit;
                    out.Base = Register(word & 31);
                    out.Bit = static_cast<uint8_t>(bit);
                    out.Value = address + static_cast<uint64_t>(Signed((word >> 5) & 0x3fff, 14) * 4);
                    return true;
                }
                if ((word & 0xff000010) == 0x54000000)
                {
                    out.Kind = InstructionKind::ConditionalBranch;
                    out.Value = address + static_cast<uint64_t>(Signed((word >> 5) & 0x7ffff, 19) * 4);
                    return true;
                }
                if ((word & 0x7e000000) == 0x34000000)
                {
                    out.Kind = InstructionKind::ConditionalBranch;
                    out.Base = Register(word & 31);
                    out.Value = address + static_cast<uint64_t>(Signed((word >> 5) & 0x7ffff, 19) * 4);
                    return true;
                }
                if ((word & 0x1f000000) == 0x10000000)
                {
                    const uint64_t immediate = ((word >> 29) & 3) | (uint64_t{(word >> 5) & 0x7ffff} << 2);
                    const bool page = (word >> 31) != 0;
                    out.Kind = InstructionKind::SetBase;
                    out.Dest = rd;
                    out.Value = (page ? address & ~uint64_t{4095} : address) +
                                static_cast<uint64_t>(Signed(immediate, 21) * (page ? 4096 : 1));
                    out.bExactAddress = !page;
                    return true;
                }
                if ((word & 0x1f800000) == 0x11000000)
                {
                    if (word == 0xd10003ff || (word & 0xffc003ff) == 0xd10003ff)
                    {
                        out.Kind = InstructionKind::Prologue;
                        return true;
                    }
                    const uint32_t operation = (word >> 30) & 1;
                    const uint32_t setFlags = (word >> 29) & 1;
                    const uint32_t shift = (word >> 22) & 1;
                    const uint64_t immediate = uint64_t{(word >> 10) & 4095} << (shift ? 12 : 0);
                    out.Dest = rd;
                    out.Base = rn;
                    if (operation == 0 && rn >= 0)
                    {
                        out.Kind = InstructionKind::AddImmediate;
                        out.Value = immediate;
                    }
                    else
                    {
                        // SUB/SUBS/CMP 或基于 SP 的 ADD：标志位与 SP 运算不会使无关的寄存器数据流失效
                        out.Kind = InstructionKind::Other;
                    }
                    (void)setFlags;
                    return true;
                }
                if ((word & 0x1f200000) == 0x0b200000 || (word & 0x1f200000) == 0x0b000000)
                {
                    const bool extended = (word & 0x00200000) != 0;
                    const uint32_t operation = (word >> 30) & 1;
                    const uint32_t setFlags = (word >> 29) & 1;
                    out.Dest = rd;
                    out.Base = rn;
                    out.Source = Register((word >> 16) & 31);
                    if (operation != 0 || setFlags != 0)
                    {
                        out.Kind = InstructionKind::Other;
                        return true;
                    }
                    if (extended)
                    {
                        out.Kind = InstructionKind::AddExtendedRegister;
                        out.Extend = ExtendFromBits((word >> 13) & 7);
                        out.Shift = static_cast<uint8_t>((word >> 10) & 7);
                        out.OperandWidth = (out.Extend == ExtendKind::Uxtx || out.Extend == ExtendKind::Sxtx) ? 8 : 4;
                        return true;
                    }
                    const uint32_t shift = (word >> 10) & 0x3f;
                    if (!sf && shift >= 32)
                    {
                        out.bClobbersAll = true;
                        return true;
                    }
                    out.Kind = InstructionKind::AddShiftedRegister;
                    out.ShiftType = ShiftFromBits((word >> 22) & 3);
                    out.Shift = static_cast<uint8_t>(shift);
                    return true;
                }
                if ((word & 0x7f800000) == 0x53000000)
                {
                    const uint32_t n = (word >> 22) & 1;
                    const uint32_t immr = (word >> 16) & 0x3f;
                    const uint32_t imms = (word >> 10) & 0x3f;
                    if (n != static_cast<uint32_t>(sf))
                    {
                        out.Dest = rd;
                        out.bClobbersAll = true;
                        return true;
                    }
                    if (imms == (sf ? 63u : 31u))
                    {
                        out.Kind = InstructionKind::LogicalShiftRight;
                        out.Dest = rd;
                        out.Base = rn;
                        out.Shift = static_cast<uint8_t>(immr);
                        return true;
                    }
                    if (immr <= imms)
                    {
                        out.Kind = InstructionKind::BitfieldExtract;
                        out.Dest = rd;
                        out.Base = rn;
                        out.Shift = static_cast<uint8_t>(immr);
                        out.BitWidth = static_cast<uint8_t>(imms + 1);
                        return true;
                    }
                    const uint32_t size = sf ? 64u : 32u;
                    out.Kind = InstructionKind::BitfieldInsert;
                    out.Dest = rd;
                    out.Base = rn;
                    out.Shift = static_cast<uint8_t>((size - immr) & (size - 1));
                    out.BitWidth = static_cast<uint8_t>(imms + 1);
                    return true;
                }
                if ((word & 0x1f800000) == 0x12000000)
                {
                    const uint32_t operation = (word >> 29) & 3;
                    if (operation == 0 || operation == 3)
                    {
                        uint64_t mask = 0;
                        if (!DecodeLogicalImmediate(word, sf, mask))
                        {
                            out.Dest = rd;
                            out.bClobbersAll = true;
                            return true;
                        }
                        out.Kind = InstructionKind::AndImmediate;
                        out.Dest = rd;
                        out.Base = rn;
                        out.Mask = mask;
                        return true;
                    }
                    out.Dest = rd;
                    out.bClobbersAll = true;
                    return true;
                }
                if ((word & 0x1f800000) == 0x12800000)
                {
                    const unsigned operation = (word >> 29) & 3;
                    const unsigned shift = ((word >> 21) & 3) * 16;
                    const bool wide = (word >> 31) != 0;
                    if (operation == 1 || (!wide && shift >= 32))
                    {
                        out.bClobbersAll = true;
                        return true;
                    }
                    const uint64_t immediate = uint64_t{(word >> 5) & 65535} << shift;
                    out.Kind = InstructionKind::MoveImmediate;
                    out.Dest = rd;
                    out.Value = operation == 0 ? ~immediate : immediate;
                    if (!wide)
                        out.Value &= UINT32_MAX;
                    out.bComposes = operation == 3;
                    out.ValueMask = (uint64_t{65535} << shift) | (wide ? 0 : uint64_t{UINT32_MAX} << 32);
                    return true;
                }
                if ((word & 0xffe0ffe0) == 0xaa0003e0 || (word & 0xffe0ffe0) == 0x2a0003e0)
                {
                    out.Kind = InstructionKind::MoveRegister;
                    out.Dest = rd;
                    out.Base = Register((word >> 16) & 31);
                    return true;
                }
                if ((word & 0x3b000000) == 0x18000000 && !(word & 0x04000000))
                {
                    const unsigned operation = word >> 30;
                    if (operation == 3)
                        return true;
                    out.Dest = rd;
                    out.AccessWidth = operation == 1 ? 8 : 4;
                    out.bSignExtends = operation == 2;
                    out.Kind = InstructionKind::LoadLiteral;
                    out.Value = address + static_cast<uint64_t>(Signed((word >> 5) & 0x7ffff, 19) * 4);
                    return true;
                }

                if (!(word & 0x04000000) && (word & 0x3a000000) == 0x28000000)
                {
                    const bool wide = (word >> 31) != 0;
                    const unsigned mode = (word >> 23) & 3;
                    out.Kind = ((word >> 22) & 1) ? InstructionKind::LoadPair : InstructionKind::StorePair;
                    out.Dest = Register(word & 31);
                    out.Dest2 = Register((word >> 10) & 31);
                    out.Base = Register((word >> 5) & 31);
                    out.AccessWidth = wide ? 8 : 4;
                    out.Offset = Signed((word >> 15) & 0x7f, 7) * (wide ? 8 : 4);
                    out.bWritesBackBase = mode == 1 || mode == 3;
                    return true;
                }

                const bool scaled = (word & 0x3b000000) == 0x39000000;
                const bool unscaled = (word & 0x3b200000) == 0x38000000;
                if (!(word & 0x04000000) && (scaled || unscaled))
                {
                    const unsigned size = word >> 30;
                    const unsigned operation = (word >> 22) & 3;
                    if (size == 3 && operation >= 2)
                        return true;
                    if (size == 2 && operation == 3)
                    {
                        out.bClobbersAll = true;
                        return true;
                    }
                    out.Kind = operation == 0 ? InstructionKind::Store : InstructionKind::Load;
                    out.Dest = rd;
                    out.Base = rn;
                    out.AccessWidth = static_cast<uint8_t>(1u << size);
                    if (scaled)
                        out.Offset = static_cast<int64_t>((word >> 10) & 4095) << size;
                    else
                    {
                        const unsigned mode = (word >> 10) & 3;
                        out.Offset = mode == 1 ? 0 : Signed((word >> 12) & 511, 9);
                        out.bWritesBackBase = mode == 1 || mode == 3;
                    }
                    return true;
                }
                if ((word & 0xffc003e0) == 0xa98003e0)
                {
                    out.Kind = InstructionKind::Prologue;
                    return true;
                }
                if (word == 0xd503201f || (word & 0xfffffc1f) == 0xd503241f)
                    return true;

                out.bClobbersAll = true;
                return true;
            }
        };
    } // namespace

    std::unique_ptr<InstructionDecoder> CreateInstructionDecoder(module::ModuleArchitecture architecture)
    {
        if (architecture == module::ModuleArchitecture::Arm64)
            return std::make_unique<Arm64InstructionDecoder>();
        return nullptr;
    }
} // namespace nextdumper::analysis
