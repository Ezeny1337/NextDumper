#include "IArchDecoder.h"

#include <cstring>
#include <memory>

namespace
{
    int Register(uint32_t value) { return value == 31 ? -1 : static_cast<int>(value); }

    int64_t Signed(uint64_t value, unsigned bits)
    {
        const uint64_t sign = uint64_t{1} << (bits - 1);
        return (value & sign) ? -static_cast<int64_t>((uint64_t{1} << bits) - value) : static_cast<int64_t>(value);
    }

    class Arm64Decoder final : public IArchDecoder
    {
    public:
        EArch Arch() const override { return EArch::Arm64; }
        uint32_t InstructionStride() const override { return 4; }
        int RegisterCount() const override { return 31; }
        bool CallClobbers(int reg) const override { return (reg >= 0 && reg <= 18) || reg == 30; }

        bool DecodeLocalBytes(const uint8_t *at, size_t available, uint64_t address, NormalizedInsn &out) const override
        {
            out = {};
            out.Length = 4;
            if (!at || available < 4)
                return false;
            uint32_t word;
            std::memcpy(&word, at, sizeof(word));
            const int rd = Register(word & 31), rn = Register((word >> 5) & 31);
            if ((word & 0xfffffc1f) == 0xd65f0000)
            {
                out.Kind = NormalizedInsn::EKind::Return;
                return true;
            }
            if ((word & 0xfffffc1f) == 0xd63f0000 || (word & 0xfffffc1f) == 0xd61f0000)
            {
                out.Kind = (word & 0x00200000) ? NormalizedInsn::EKind::Call : NormalizedInsn::EKind::Branch;
                out.Base = rn;
                return true;
            }
            if ((word & 0x7c000000) == 0x14000000)
            {
                out.Kind = (word >> 31) ? NormalizedInsn::EKind::Call : NormalizedInsn::EKind::Branch;
                out.Value = address + static_cast<uint64_t>(Signed(word & 0x03ffffff, 26) * 4);
                return true;
            }
            if ((word & 0xff000010) == 0x54000000 || (word & 0x7e000000) == 0x34000000 ||
                (word & 0x7e000000) == 0x36000000)
            {
                out.Kind = NormalizedInsn::EKind::Branch;
                return true;
            }
            if ((word & 0x1f000000) == 0x10000000)
            {
                const uint64_t immediate = ((word >> 29) & 3) | (uint64_t{(word >> 5) & 0x7ffff} << 2);
                const bool page = (word >> 31) != 0;
                out.Kind = NormalizedInsn::EKind::SetBase;
                out.Dest = rd;
                out.Value = (page ? address & ~uint64_t{4095} : address) +
                            static_cast<uint64_t>(Signed(immediate, 21) * (page ? 4096 : 1));
                out.bExactAddress = !page;
                return true;
            }
            if ((word & 0x1f800000) == 0x11000000)
            {
                if (word == 0xd10003ff || ((word & 0xffc003ff) == 0xd10003ff))
                {
                    out.Kind = NormalizedInsn::EKind::Prologue;
                    return true;
                }
                out.Dest = rd;
                if ((word >> 31) && !(word & 0x40000000) && rn >= 0)
                {
                    out.Kind = NormalizedInsn::EKind::AddImm;
                    out.Base = rn;
                    out.Value = uint64_t{(word >> 10) & 4095} << ((word & 0x00400000) ? 12 : 0);
                }
                return true;
            }
            if ((word & 0x1f800000) == 0x12800000)
            {
                const unsigned operation = (word >> 29) & 3, shift = ((word >> 21) & 3) * 16;
                const bool wide = (word >> 31) != 0;
                if (operation == 1 || (!wide && shift >= 32))
                    return false;
                const uint64_t immediate = uint64_t{(word >> 5) & 65535} << shift;
                out.Kind = NormalizedInsn::EKind::MoveImm;
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
                out.Dest = rd;
                if (word >> 31)
                {
                    out.Kind = NormalizedInsn::EKind::MoveReg;
                    out.Base = Register((word >> 16) & 31);
                }
                return true;
            }
            if ((word & 0x3b000000) == 0x18000000 && !(word & 0x04000000))
            {
                const unsigned operation = word >> 30;
                if (operation == 3)
                    return true; // PRFM 不写入通用寄存器
                out.Dest = rd;
                out.AccessWidth = operation == 1 ? 8 : 4;
                out.bSignExtends = operation == 2;
                out.Kind = NormalizedInsn::EKind::LoadLiteral;
                out.Value = address + static_cast<uint64_t>(Signed((word >> 5) & 0x7ffff, 19) * 4);
                return true;
            }
            const bool scaled = (word & 0x3b000000) == 0x39000000;
            const bool unscaled = (word & 0x3b200000) == 0x38000000;
            if (!(word & 0x04000000) && (scaled || unscaled))
            {
                const unsigned size = word >> 30, operation = (word >> 22) & 3;
                if (size == 3 && operation >= 2)
                    return true; // PRFM
                if (size == 2 && operation == 3)
                    return false;
                out.Kind = operation == 0 ? NormalizedInsn::EKind::Store : NormalizedInsn::EKind::Load;
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
                out.Kind = NormalizedInsn::EKind::Prologue;
                return true;
            }
            if (word == 0xd503201f || (word & 0xfffffc1f) == 0xd503241f)
                return true; // NOP、BTI。
            // 未建模指令不能保留可能已经失效的地址数据流
            out.bClobbersAll = true;
            return true;
        }
    };
} // namespace

std::unique_ptr<IArchDecoder> CreateArm64Decoder() { return std::make_unique<Arm64Decoder>(); }
