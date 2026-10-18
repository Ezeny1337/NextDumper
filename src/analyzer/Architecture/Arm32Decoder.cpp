#include "IArchDecoder.h"

#include <bit>
#include <cstring>
#include <memory>

namespace
{
    uint32_t Immediate(uint32_t word) { return std::rotr(word & 255u, static_cast<int>(((word >> 8) & 15) * 2)); }
    uint32_t Target(uint32_t address, int64_t offset) { return address + 8u + static_cast<uint32_t>(offset); }

    class Arm32Decoder final : public IArchDecoder
    {
    public:
        EArch Arch() const override { return EArch::Arm32; }
        uint32_t InstructionStride() const override { return 4; }
        int RegisterCount() const override { return 16; }
        bool CallClobbers(int reg) const override { return reg >= 0 && (reg <= 3 || reg == 12 || reg == 14); }

        bool DecodeLocalBytes(const uint8_t *at, size_t available, uint64_t addr, NormalizedInsn &out) const override
        {
            out = {};
            out.Length = 4;
            if (!at || available < 4 || addr > UINT32_MAX)
                return false;
            uint32_t word;
            std::memcpy(&word, at, sizeof(word));
            const uint32_t address = static_cast<uint32_t>(addr);
            const unsigned condition = word >> 28;
            const int rd = static_cast<int>((word >> 12) & 15), rn = static_cast<int>((word >> 16) & 15);
            const uint32_t code = word & 0x0fffffff;
            if ((code & 0x0ffffff0) == 0x012fff10 || (code & 0x0ffffff0) == 0x012fff30)
            {
                const bool call = (code & 0x20) != 0;
                out.Kind = call ? NormalizedInsn::EKind::Call : ((word & 15) == 14 && condition == 14) ? NormalizedInsn::EKind::Return
                                                                                                       : NormalizedInsn::EKind::Branch;
                out.Base = static_cast<int>(word & 15);
                return true;
            }
            if ((word & 0x0e000000) == 0x0a000000)
            {
                const uint32_t immediate = word & 0x00ffffff;
                const int64_t displacement = (immediate & 0x00800000) ? -static_cast<int64_t>(0x01000000 - immediate) * 4 : static_cast<int64_t>(immediate) * 4;
                out.Kind = (word & 0x01000000) || condition == 15 ? NormalizedInsn::EKind::Call : NormalizedInsn::EKind::Branch;
                out.Value = Target(address, displacement + (condition == 15 ? ((word >> 23) & 2) : 0));
                return true;
            }
            if (condition != 14)
            {
                // 条件执行写入无法证明发生，不能建立确定地址
                out.bClobbersAll = true;
                return true;
            }
            if ((code & 0x0fff0000) == 0x092d0000 && (code & 65535))
            {
                out.Kind = NormalizedInsn::EKind::Prologue;
                return true;
            }
            if ((code & 0x0ff00000) == 0x03000000 || (code & 0x0ff00000) == 0x03400000)
            {
                if (rd == 15)
                {
                    out.bClobbersAll = true;
                    return true;
                }
                const bool top = (word & 0x00400000) != 0;
                out.Kind = NormalizedInsn::EKind::MoveImm;
                out.Dest = rd;
                out.Value = uint64_t{((word >> 4) & 0xf000) | (word & 0x0fff)} << (top ? 16 : 0);
                out.bComposes = top;
                out.ValueMask = top ? 0xffff0000 : 0xffff;
                out.bAddressLike = true;
                return true;
            }
            if ((code & 0x0c000000) == 0 && (word & 0x02000000))
            {
                const unsigned operation = (word >> 21) & 15;
                const uint32_t immediate = Immediate(word);
                if (rd == 15 && (operation < 8 || operation > 11))
                {
                    out.bClobbersAll = true;
                    return true;
                }
                out.Dest = rd;
                if (operation == 2 || operation == 4)
                {
                    const int64_t delta = operation == 2 ? -static_cast<int64_t>(immediate) : immediate;
                    if (rn == 15)
                    {
                        out.Kind = NormalizedInsn::EKind::SetBase;
                        out.Value = Target(address, delta);
                        out.bExactAddress = true;
                    }
                    else
                    {
                        out.Kind = NormalizedInsn::EKind::AddImm;
                        out.Base = rn;
                        out.Value = static_cast<uint64_t>(delta);
                    }
                }
                else if (operation == 13 || operation == 15)
                {
                    out.Kind = NormalizedInsn::EKind::MoveImm;
                    out.Value = operation == 15 ? ~immediate : immediate;
                }
                else if (operation >= 8 && operation <= 11)
                    out.Dest = -1;
                return true;
            }
            if ((code & 0x0fe00ff0) == 0x00800000 && rn == 15)
            {
                if (rd == 15)
                {
                    out.bClobbersAll = true;
                    return true;
                }
                out.Kind = NormalizedInsn::EKind::AddImm;
                out.Dest = rd;
                out.Base = static_cast<int>(word & 15);
                out.Value = Target(address, 0);
                return true;
            }
            if ((code & 0x0fe00ff0) == 0x01a00000)
            {
                if (rd == 15 && (word & 15) != 14)
                {
                    out.bClobbersAll = true;
                    return true;
                }
                out.Kind = rd == 15 ? NormalizedInsn::EKind::Return : NormalizedInsn::EKind::MoveReg;
                out.Dest = rd;
                out.Base = static_cast<int>(word & 15);
                return true;
            }
            const bool single = (word & 0x0c000000) == 0x04000000;
            const bool extra = (word & 0x0e000090) == 0x00000090 && ((word >> 5) & 3) != 0;
            if (single || extra)
            {
                const bool load = (word & 0x00100000) != 0, pre = (word & 0x01000000) != 0;
                const bool immediate = single ? !(word & 0x02000000) : (word & 0x00400000) != 0;
                const unsigned kind = (word >> 5) & 3;
                if (extra && !load && kind != 1)
                {
                    out.bClobbersAll = true;
                    return true;
                }
                if (!immediate)
                {
                    out.bClobbersAll = true;
                    return true;
                }
                const uint32_t value = single ? word & 4095 : ((word >> 4) & 0xf0) | (word & 15);
                const int64_t delta = (word & 0x00800000) ? value : -static_cast<int64_t>(value);
                out.Kind = load ? NormalizedInsn::EKind::Load : NormalizedInsn::EKind::Store;
                out.Dest = rd;
                out.Base = rn;
                out.Offset = pre ? delta : 0;
                out.AccessWidth = single ? ((word & 0x00400000) ? 1 : 4) : kind == 2 ? 1
                                                                                     : 2;
                out.bWritesBackBase = !pre || (word & 0x00200000);
                if (load && rd == 15)
                    out.Kind = NormalizedInsn::EKind::Return;
                else if (load && rn == 15 && pre && !out.bWritesBackBase && out.AccessWidth == 4)
                {
                    out.Kind = NormalizedInsn::EKind::LoadLiteral;
                    out.Value = Target(address, delta);
                }
                return true;
            }
            // ARM 模式之外的编码与未知指令均不产生猜测性地址
            out.bClobbersAll = true;
            return true;
        }
    };
} // namespace

std::unique_ptr<IArchDecoder> CreateArm32Decoder() { return std::make_unique<Arm32Decoder>(); }
