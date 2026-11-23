#include "nextdumper/analysis/InstructionDecoder.hpp"

#include <algorithm>
#include <cstring>

namespace nextdumper::analysis
{
    namespace
    {
        // ARM32 的通用寄存器编号固定：r13 为 SP，r14 为 LR，r15 为 PC
        constexpr int kArm32ProgramCounter = 15;
        constexpr int kArm32LinkRegister = 14;

        // 条件码 0xE 为「总是执行」，0xF 进入无条件编码空间
        constexpr uint32_t kConditionAlways = 0xE;
        constexpr uint32_t kConditionUnconditional = 0xF;

        uint16_t ReadHalf(const uint8_t *bytes)
        {
            uint16_t value = 0;
            std::memcpy(&value, bytes, sizeof(value));
            return value;
        }

        uint32_t ReadWord(const uint8_t *bytes)
        {
            uint32_t value = 0;
            std::memcpy(&value, bytes, sizeof(value));
            return value;
        }

        int32_t SignedBits(uint64_t value, unsigned bits)
        {
            const uint64_t sign = uint64_t{1} << (bits - 1);
            if ((value & sign) == 0)
                return static_cast<int32_t>(value);
            return -static_cast<int32_t>((uint64_t{1} << bits) - value);
        }

        uint32_t RotateRight(uint32_t value, unsigned rotation)
        {
            rotation &= 31u;
            if (rotation == 0)
                return value;
            return (value >> rotation) | (value << (32u - rotation));
        }

        // 数据处理的立即数操作数：8 位立即数按 2*rot 循环右移
        bool DecodeArmModifiedImmediate(uint32_t word, uint32_t &value)
        {
            const uint32_t imm8 = word & 0xFFu;
            const uint32_t rotation = ((word >> 8) & 0xFu) * 2u;
            value = RotateRight(imm8, rotation);
            return true;
        }

        ShiftKind ArmShiftKind(uint32_t bits)
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

        // 移位量来自立即数：0 表示不移动；LSR/ASR 的 0 表示移动 32 位
        uint8_t NormalizedArmShift(uint32_t type, uint32_t amount)
        {
            if (type == 0)
                return static_cast<uint8_t>(amount);
            if (amount == 0)
                return 32;
            return static_cast<uint8_t>(amount);
        }

        class Arm32InstructionDecoder final : public InstructionDecoder
        {
        public:
            [[nodiscard]] uint32_t Stride() const override { return 4; }
            [[nodiscard]] int RegisterCount() const override { return 16; }

            // AAPCS32：r0-r3 传参；r0-r3、r12 与 lr 为调用方保存
            [[nodiscard]] size_t ArgumentRegisterCount() const override { return 4; }
            [[nodiscard]] bool IsCallerSaved(int reg) const override
            {
                return (reg >= 0 && reg <= 3) || reg == 12 || reg == kArm32LinkRegister;
            }
            [[nodiscard]] int ProgramCounter() const override { return kArm32ProgramCounter; }
            [[nodiscard]] int LinkRegister() const override { return kArm32LinkRegister; }

            [[nodiscard]] bool Decode(const uint8_t *bytes, size_t available,
                                      uintptr_t address, Instruction &out) const override
            {
                out = {};
                out.Length = 4;
                out.OperandWidth = 4;
                if (!bytes || available < 4)
                    return false;

                const uint32_t word = ReadWord(bytes);
                const uint32_t condition = word >> 28;
                out.bConditional = condition != kConditionAlways;
                if (condition == kConditionUnconditional)
                    return DecodeUnconditional(word, address, out);
                return DecodeConditional(word, address, out);
            }

        private:
            static void Unknown(uint32_t word, Instruction &out)
            {
                // 无法界定写入集合时保守地让整条链失效
                out.Kind = InstructionKind::Other;
                out.bClobbersAll = true;
                (void)word;
            }

            static bool DecodeUnconditional(uint32_t word, uintptr_t address, Instruction &out)
            {
                out.bConditional = false;
                // BLX 立即数：H 位构成目标地址的 bit1，目标始终切换执行状态
                if ((word & 0xFE000000u) == 0xFA000000u)
                {
                    const uint32_t h = (word >> 24) & 0x1u;
                    const int32_t offset = SignedBits(((word & 0x00FFFFFFu) << 2) | (h << 1), 26);
                    out.Kind = InstructionKind::Call;
                    out.Value = address + 8 + static_cast<uint32_t>(offset);
                    out.bSwitchesMode = true;
                    return true;
                }
                // BLX 寄存器与其他无条件杂项
                if ((word & 0x0E000000u) == 0x02000000u ||
                    (word & 0x0E000000u) == 0x0A000000u)
                {
                    Unknown(word, out);
                    return true;
                }
                Unknown(word, out);
                return true;
            }

            static bool DecodeConditional(uint32_t word, uintptr_t address, Instruction &out)
            {
                // 分支与块传送
                if ((word & 0x0E000000u) == 0x0A000000u)
                {
                    if ((word & 0x01000000u) != 0)
                    {
                        // BL：写 LR，目标可能切换模式
                        out.Kind = InstructionKind::Call;
                        out.Value = address + 8 + static_cast<uint32_t>(SignedBits(word & 0x00FFFFFFu, 24) * 4);
                        return true;
                    }
                    const int32_t offset = SignedBits(word & 0x00FFFFFFu, 24) * 4;
                    out.Kind = InstructionKind::Branch;
                    out.Value = address + 8 + static_cast<uint32_t>(offset);
                    out.bConditional = true;
                    return true;
                }
                if ((word & 0x0E000000u) == 0x08000000u)
                {
                    // LDM/STM 一次写多个寄存器，按写入集合未知处理
                    const bool load = (word & 0x00100000u) != 0;
                    if (load)
                    {
                        out.Kind = InstructionKind::Other;
                        out.bClobbersAll = true;
                    }
                    else
                    {
                        out.Kind = InstructionKind::Other;
                        out.Dest = -1;
                    }
                    return true;
                }
                if ((word & 0x0C000000u) == 0x04000000u)
                    return DecodeSingleTransfer(word, address, out);
                if ((word & 0x0C000000u) == 0x00000000u)
                    return DecodeDataProcessingGroup(word, address, out);
                Unknown(word, out);
                return true;
            }

            // 单寄存器加载/存储（含 byte 变体）
            // 基址写回与后变址会影响后续链，因此只有静态立即数偏移的预变址形式才给出可用偏移
            // PC 基址的加载读取指令流之外的字面量池，其槽地址可直接静态求出
            static bool DecodeSingleTransfer(uint32_t word, uintptr_t address, Instruction &out)
            {
                const bool registerOffset = (word & 0x02000000u) != 0;
                const bool preIndexed = (word & 0x01000000u) != 0;
                const bool addOffset = (word & 0x00800000u) != 0;
                const bool byteAccess = (word & 0x00400000u) != 0;
                const bool writeBack = (word & 0x00200000u) != 0;
                const bool load = (word & 0x00100000u) != 0;
                const int base = static_cast<int>((word >> 16) & 0xFu);
                const int dest = static_cast<int>((word >> 12) & 0xFu);

                if (registerOffset)
                {
                    // 寄存器偏移无法给出静态偏移，按未知写入处理
                    Unknown(word, out);
                    return true;
                }

                const uint32_t magnitude = word & 0xFFFu;
                int64_t offset = 0;
                if (preIndexed)
                    offset = addOffset ? static_cast<int64_t>(magnitude) : -static_cast<int64_t>(magnitude);

                if (load && base == kArm32ProgramCounter && preIndexed && !byteAccess)
                {
                    // PC 基址按指令地址 +8 取字面量槽，槽内容是全局变量或常量的地址
                    out.Kind = InstructionKind::LoadLiteral;
                    out.Dest = dest;
                    out.Value = static_cast<uint64_t>(static_cast<int64_t>(address + 8) + offset);
                    out.bExactAddress = true;
                    out.AccessWidth = 4;
                    return true;
                }

                out.Base = base;
                out.Offset = offset;
                out.bWritesBackBase = !preIndexed || writeBack;
                out.AccessWidth = byteAccess ? 1 : 4;
                out.Kind = load ? InstructionKind::Load : InstructionKind::Store;
                if (load)
                {
                    out.Dest = dest;
                    if (dest == kArm32ProgramCounter)
                    {
                        // 载入 PC 结束当前线性控制流
                        out.Kind = InstructionKind::Branch;
                        out.bSwitchesMode = true;
                    }
                }
                else
                {
                    out.Dest = -1;
                }
                return true;
            }

            static bool DecodeDataProcessingGroup(uint32_t word, uintptr_t address, Instruction &out)
            {
                // MOVW / MOVT 与分支交换指令位于同一编码区
                if ((word & 0x0FF00000u) == 0x03000000u ||
                    (word & 0x0FF00000u) == 0x03400000u)
                {
                    const uint32_t immediate = ((word >> 4) & 0xF000u) | (word & 0xFFFu);
                    out.Kind = InstructionKind::MoveImmediate;
                    out.Dest = static_cast<int>((word >> 12) & 0xFu);
                    out.Value = immediate;
                    out.ValueMask = 0xFFFFu;
                    out.bComposes = (word & 0x0FF00000u) == 0x03400000u;
                    return true;
                }
                // BX 与 BLX 寄存器：cond 0001 0010 1111 1111 1111 001? Rm
                if ((word & 0x0FFFFFD0u) == 0x012FFF10u)
                {
                    const int source = static_cast<int>(word & 0xFu);
                    out.Kind = (word & 0x20u) != 0 ? InstructionKind::Call : InstructionKind::Branch;
                    out.Base = source;
                    out.bSwitchesMode = true;
                    return true;
                }
                if ((word & 0x0FBF0FFFu) == 0x010F0000u)
                {
                    // MRS：读取状态寄存器，不改变通用寄存器数据流
                    out.Kind = InstructionKind::Other;
                    out.Dest = -1;
                    return true;
                }
                if ((word & 0x0DB0F000u) == 0x0120F000u)
                {
                    // MSR 与提示指令不改变通用寄存器数据流
                    out.Kind = InstructionKind::Other;
                    out.Dest = -1;
                    return true;
                }
                if ((word & 0x0FE00000u) == 0x00000000u &&
                    (word & 0x000000F0u) == 0x00000090u)
                {
                    // 乘法与乘加：写目标寄存器，不参与地址合成
                    out.Kind = InstructionKind::Other;
                    out.Dest = static_cast<int>((word >> 16) & 0xFu) == kArm32ProgramCounter
                                   ? -1
                                   : static_cast<int>((word >> 16) & 0xFu);
                    return true;
                }
                if ((word & 0x0F8000F0u) == 0x00800090u)
                {
                    // 长乘法：写 Rd 与 RdHi 两个寄存器，按未知写入处理
                    Unknown(word, out);
                    return true;
                }
                if ((word & 0x0E000090u) == 0x00000090u)
                {
                    // 半字与有符号字节访存
                    return DecodeExtraTransfer(word, out);
                }

                const uint32_t opcode = (word >> 21) & 0xFu;
                const uint32_t immediate = (word & 0x02000000u) != 0;
                const int base = static_cast<int>((word >> 16) & 0xFu);
                const int dest = static_cast<int>((word >> 12) & 0xFu);

                // CMP/CMN/TST/TEQ 只写标志位
                if (opcode >= 0x8u && opcode <= 0xBu)
                {
                    out.Kind = InstructionKind::Other;
                    out.Dest = -1;
                    return true;
                }

                // 移位与 MOV：Rd 与操作数是同一寄存器，且允许 Rs 寄存器移位
                if (opcode == 0xDu)
                    return DecodeMoveAndShift(word, address, out);

                switch (opcode)
                {
                case 0x0u: // AND
                case 0xEu: // BIC
                    if (immediate)
                    {
                        uint32_t mask = 0;
                        DecodeArmModifiedImmediate(word, mask);
                        out.Kind = InstructionKind::AndImmediate;
                        out.Dest = dest;
                        out.Base = base;
                        out.Mask = opcode == 0x0u ? mask : ~mask;
                        return true;
                    }
                    break;
                case 0x4u: // ADD / SUB
                    if (immediate)
                    {
                        uint32_t value = 0;
                        DecodeArmModifiedImmediate(word, value);
                        out.Kind = InstructionKind::AddImmediate;
                        out.Dest = dest;
                        out.Base = base;
                        out.Value = value;
                        return true;
                    }
                    if ((word & 0x10u) != 0)
                    {
                        // 移位量来自寄存器，静态不可知
                        out.Kind = InstructionKind::Other;
                        out.Dest = dest;
                        return true;
                    }
                    out.Kind = InstructionKind::AddShiftedRegister;
                    out.Dest = dest;
                    out.Base = base;
                    out.Source = static_cast<int>(word & 0xFu);
                    out.ShiftType = ArmShiftKind((word >> 5) & 0x3u);
                    out.Shift = NormalizedArmShift((word >> 5) & 0x3u, (word >> 7) & 0x1Fu);
                    out.Value = 0;
                    return true;
                case 0xCu: // ORR 与 PC 组合不构成可静态求值的地址
                    break;
                default:
                    break;
                }

                // 其余运算与移位形式不参与地址合成，只写目标寄存器
                out.Kind = InstructionKind::Other;
                out.Dest = dest < kArm32ProgramCounter ? dest : -1;
                return true;
            }

            // MOV 与各类移位：MOV Rd, PC 读取 PC 相对字面量，LSR 直接对应分析层的逻辑右移
            static bool DecodeMoveAndShift(uint32_t word, uintptr_t address, Instruction &out)
            {
                const bool immediate = (word & 0x02000000u) != 0;
                const int dest = static_cast<int>((word >> 12) & 0xFu);
                if (immediate)
                {
                    uint32_t value = 0;
                    DecodeArmModifiedImmediate(word, value);
                    out.Kind = InstructionKind::MoveImmediate;
                    out.Dest = dest;
                    out.Value = value;
                    return true;
                }

                const int source = static_cast<int>(word & 0xFu);
                if (source == kArm32ProgramCounter)
                {
                    // MOV Rd, PC 把 PC 值写入寄存器，得到的是地址而不是内存加载
                    out.Kind = InstructionKind::SetBase;
                    out.Dest = dest;
                    out.Value = address + 8;
                    out.bExactAddress = true;
                    return true;
                }

                const uint32_t shiftType = (word >> 5) & 0x3u;
                const bool registerShift = (word & 0x10u) != 0;
                const uint32_t amount = (word >> 7) & 0x1Fu;
                if (registerShift)
                {
                    // 移位量来自寄存器，静态不可知
                    out.Kind = InstructionKind::Other;
                    out.Dest = dest;
                    return true;
                }
                if (shiftType == 0 && amount == 0)
                {
                    out.Kind = InstructionKind::MoveRegister;
                    out.Dest = dest;
                    out.Base = source;
                    return true;
                }
                if (shiftType == 0)
                {
                    // 左移不改变「值来自哪个槽」的身份，保留为寄存器移动并记录位移
                    out.Kind = InstructionKind::MoveRegister;
                    out.Dest = dest;
                    out.Base = source;
                    out.Shift = static_cast<uint8_t>(amount);
                    out.ShiftType = ShiftKind::Lsl;
                    return true;
                }
                if (shiftType == 1)
                {
                    out.Kind = InstructionKind::LogicalShiftRight;
                    out.Dest = dest;
                    out.Base = source;
                    out.Shift = static_cast<uint8_t>(amount == 0 ? 32 : amount);
                    return true;
                }
                out.Kind = InstructionKind::Other;
                out.Dest = dest;
                return true;
            }

            // 额外加载/存储：立即数形式的高 4 位位于 bit 11..8，低 4 位位于 bit 3..0
            // 寄存器形式复用同一字段存放 Rm，因此必须先按 I 位区分
            static bool DecodeExtraTransfer(uint32_t word, Instruction &out)
            {
                const bool immediateForm = (word & 0x00400000u) != 0;
                const bool preIndexed = (word & 0x01000000u) != 0;
                const bool addOffset = (word & 0x00800000u) != 0;
                const bool writeBack = (word & 0x00200000u) != 0;
                const bool load = (word & 0x00100000u) != 0;
                const uint32_t form = (word >> 5) & 0x3u;
                const int base = static_cast<int>((word >> 16) & 0xFu);
                const int dest = static_cast<int>((word >> 12) & 0xFu);

                if (!immediateForm || form == 0u)
                {
                    // 寄存器偏移或非半字/字节形式：目标写入可用，静态偏移未知
                    out.Kind = InstructionKind::Other;
                    out.Dest = load ? dest : -1;
                    return true;
                }

                const uint32_t magnitude = ((word >> 4) & 0xF0u) | (word & 0xFu);
                const int64_t signedMagnitude = addOffset ? static_cast<int64_t>(magnitude)
                                                          : -static_cast<int64_t>(magnitude);
                // 预变址的偏移直接生效；后变址先访问再调整基址，故不提供静态偏移
                out.Base = base;
                out.Offset = preIndexed ? signedMagnitude : 0;
                out.bWritesBackBase = !preIndexed || writeBack;
                out.AccessWidth = form == 0x1u ? 2 : (form == 0x2u ? 1 : 2);
                out.bSignExtends = form != 0x1u;
                out.Kind = load ? InstructionKind::Load : InstructionKind::Store;
                out.Dest = load ? dest : -1;
                return true;
            }
        };

        class ThumbInstructionDecoder final : public InstructionDecoder
        {
        public:
            // Thumb 以半字为粒度，最大编码长度为一个 32 位指令
            [[nodiscard]] uint32_t Stride() const override { return 2; }
            [[nodiscard]] uint32_t MaxInstructionBytes() const override { return 4; }
            [[nodiscard]] int RegisterCount() const override { return 16; }

            [[nodiscard]] size_t ArgumentRegisterCount() const override { return 4; }
            [[nodiscard]] bool IsCallerSaved(int reg) const override
            {
                return (reg >= 0 && reg <= 3) || reg == 12 || reg == kArm32LinkRegister;
            }
            [[nodiscard]] int ProgramCounter() const override { return kArm32ProgramCounter; }
            [[nodiscard]] int LinkRegister() const override { return kArm32LinkRegister; }

            [[nodiscard]] bool Decode(const uint8_t *bytes, size_t available,
                                      uintptr_t address, Instruction &out) const override
            {
                out = {};
                out.OperandWidth = 4;
                if (!bytes || available < 2)
                    return false;

                const uint16_t first = ReadHalf(bytes);
                // 32 位 Thumb 编码由 0b11101 / 0b11110 / 0b11111 半字前缀标识
                const bool wide = (first >> 11) >= 0x1Du;
                if (!wide)
                {
                    out.Length = 2;
                    return Decode16(first, address, out);
                }
                out.Length = 4;
                if (available < 4)
                {
                    // 已确定为 32 位编码但字节不足：不是合法指令边界
                    return false;
                }
                return Decode32(first, ReadHalf(bytes + 2), address, out);
            }

        private:
            static void Unknown(Instruction &out)
            {
                out.Kind = InstructionKind::Other;
                out.bClobbersAll = true;
            }

            // PC 在 Thumb 指令内的基准为「当前指令地址 + 4」
            static uintptr_t ThumbPc(uintptr_t address) { return address + 4; }

            // T16 依据编码高位的格式编号分派，判定顺序由格式本身决定
            // 16 位 Thumb 按首半字高 4 位分组
            static bool Decode16(uint16_t half, uintptr_t address, Instruction &out)
            {
                switch (half >> 12)
                {
                case 0x0u:
                case 0x1u: // 移位立即数与加减寄存器
                    return Decode16ShiftAdd(half, out);
                case 0x2u:
                case 0x3u: // MOV/CMP/ADD/SUB 立即数
                    return Decode16ImmediateDataProcessing(half, out);
                case 0x4u: // 数据处理寄存器与特殊寄存器，0x4800 起是 PC 相对字面量
                    if ((half & 0x0800u) == 0)
                        return Decode16DataProcessing(half, out);
                    return Decode16LiteralAndRegisterTransfer(half, address, out);
                case 0x5u: // 寄存器偏移访存
                    return Decode16LiteralAndRegisterTransfer(half, address, out);
                case 0x6u:
                case 0x7u: // 立即数偏移的字与字节访存
                case 0x8u: // 立即数偏移的半字访存
                    return Decode16ImmediateTransfer(half, out);
                case 0x9u: // SP 相对访存
                    return Decode16StackRelative(half, out);
                case 0xAu: // ADR 与 SP 加立即数
                    return Decode16Adr(half, address, out);
                case 0xBu: // 压栈弹栈、扩展与条件跳转
                    return Decode16Misc(half, address, out);
                case 0xCu: // 块传送
                    return Decode16BlockTransfer(half, out);
                case 0xDu: // 条件分支
                    return Decode16ConditionalBranch(half, address, out);
                default: // 无条件分支
                    return Decode16UnconditionalBranch(half, address, out);
                }
            }

            // MOV/CMP/ADD/SUB 立即数：操作码在 bit12..11，目标与源同为 bit10..8
            static bool Decode16ImmediateDataProcessing(uint16_t half, Instruction &out)
            {
                const uint32_t opcode = (half >> 11) & 0x3u;
                const int dest = static_cast<int>((half >> 8) & 0x7u);
                const uint32_t immediate = half & 0xFFu;
                switch (opcode)
                {
                case 0x0u:
                    out.Kind = InstructionKind::MoveImmediate;
                    out.Dest = dest;
                    out.Value = immediate;
                    return true;
                case 0x2u:
                    out.Kind = InstructionKind::AddImmediate;
                    out.Dest = dest;
                    out.Base = dest;
                    out.Value = immediate;
                    return true;
                case 0x1u: // CMP 只写标志位
                    out.Kind = InstructionKind::Other;
                    out.Dest = -1;
                    return true;
                default: // SUB 写目标寄存器，必须让既有角色失效
                    out.Kind = InstructionKind::Other;
                    out.Dest = dest;
                    return true;
                }
            }

            // SP 相对访存：偏移以 4 字节为单位
            static bool Decode16StackRelative(uint16_t half, Instruction &out)
            {
                const bool load = (half & 0x0800u) != 0;
                const int dest = static_cast<int>((half >> 8) & 0x7u);
                out.Kind = load ? InstructionKind::Load : InstructionKind::Store;
                out.Base = 13;
                out.Dest = load ? dest : -1;
                out.Offset = static_cast<int64_t>(half & 0xFFu) * 4u;
                out.AccessWidth = 4;
                return true;
            }

            // ADR 取得 PC 相对地址；bit11 置位时是 SP 加立即数
            static bool Decode16Adr(uint16_t half, uintptr_t address, Instruction &out)
            {
                const bool spBased = (half & 0x0800u) != 0;
                const int dest = static_cast<int>((half >> 8) & 0x7u);
                const uint32_t offset = (half & 0xFFu) * 4u;
                if (spBased)
                {
                    out.Kind = InstructionKind::AddImmediate;
                    out.Dest = dest;
                    out.Base = 13;
                    out.Value = offset;
                    return true;
                }
                out.Kind = InstructionKind::SetBase;
                out.Dest = dest;
                out.Value = (ThumbPc(address) & ~uintptr_t{3}) + offset;
                out.bExactAddress = true;
                return true;
            }

            static bool Decode16ConditionalBranch(uint16_t half, uintptr_t address, Instruction &out)
            {
                const uint32_t condition = (half >> 8) & 0xFu;
                if (condition < 0xEu)
                {
                    out.Kind = InstructionKind::ConditionalBranch;
                    out.Value = address + 4 + static_cast<uint32_t>(SignedBits(half & 0xFFu, 8) * 2);
                    return true;
                }
                // 0xDE00 起为 SVC 等系统编码
                out.Kind = InstructionKind::Other;
                out.bClobbersAll = true;
                return true;
            }

            static bool Decode16UnconditionalBranch(uint16_t half, uintptr_t address, Instruction &out)
            {
                if ((half & 0x1000u) != 0)
                {
                    // 0xF000 起是 32 位编码前缀，不构成独立指令
                    Unknown(out);
                    return true;
                }
                out.Kind = InstructionKind::Branch;
                out.Value = address + 4 + static_cast<uint32_t>(SignedBits(half & 0x7FFu, 11) * 2);
                return true;
            }

            static bool Decode16ShiftAdd(uint16_t half, Instruction &out)
            {
                const uint32_t opcode = (half >> 11) & 0x3u;
                const int dest = static_cast<int>(half & 0x7u);
                const int source = static_cast<int>((half >> 3) & 0x7u);
                const uint32_t amount = (half >> 6) & 0x1Fu;
                switch (opcode)
                {
                case 0x1u: // LSR
                    out.Kind = InstructionKind::LogicalShiftRight;
                    out.Dest = dest;
                    out.Base = source;
                    out.Shift = amount == 0 ? 32 : static_cast<uint8_t>(amount);
                    return true;
                case 0x3u: // ADD/SUB 寄存器
                {
                    const bool subtract = (half & 0x0200u) != 0;
                    if (subtract)
                    {
                        out.Kind = InstructionKind::Other;
                        out.Dest = dest;
                        return true;
                    }
                    out.Kind = InstructionKind::AddShiftedRegister;
                    out.Dest = dest;
                    out.Base = source;
                    out.Source = static_cast<int>((half >> 6) & 0x7u);
                    out.Shift = 0;
                    out.ShiftType = ShiftKind::Lsl;
                    return true;
                }
                default: // LSL 与 ASR 不产生地址合成语义
                    out.Kind = InstructionKind::Other;
                    out.Dest = dest;
                    return true;
                }
            }

            static bool Decode16DataProcessing(uint16_t half, Instruction &out)
            {
                // 格式 2：立即数运算
                if ((half & 0x1800u) == 0x0000u)
                {
                    const uint32_t opcode = (half >> 11) & 0x3u;
                    const int dest = static_cast<int>((half >> 8) & 0x7u);
                    const int base = static_cast<int>((half >> 3) & 0x7u);
                    const uint32_t immediate = half & 0xFFu;
                    switch (opcode)
                    {
                    case 0x0u:
                        out.Kind = InstructionKind::MoveImmediate;
                        out.Dest = dest;
                        out.Value = immediate;
                        return true;
                    case 0x2u:
                        out.Kind = InstructionKind::AddImmediate;
                        out.Dest = dest;
                        out.Base = base;
                        out.Value = immediate;
                        return true;
                    default: // CMP 与 SUB 不产生可用的目标值
                        out.Kind = InstructionKind::Other;
                        out.Dest = opcode == 0x1u ? -1 : dest;
                        return true;
                    }
                }

                // 格式 5 之外的数据处理寄存器格式：0x4000 区
                if ((half & 0xFC00u) == 0x4000u)
                {
                    const uint32_t opcode = (half >> 6) & 0xFu;
                    const int dest = static_cast<int>(half & 0x7u);
                    const int source = static_cast<int>((half >> 3) & 0x7u);
                    switch (opcode)
                    {
                    case 0x8u: // TST
                    case 0xAu: // CMP
                    case 0xBu: // CMN
                        out.Kind = InstructionKind::Other;
                        out.Dest = -1;
                        return true;
                    case 0x9u: // NEG
                        out.Kind = InstructionKind::Other;
                        out.Dest = dest;
                        return true;
                    default:
                        out.Kind = InstructionKind::Other;
                        out.Dest = dest;
                        (void)source;
                        return true;
                    }
                }

                // 格式 3：特殊寄存器与分支交换（0x4400 区）
                const int dest = static_cast<int>((half & 0x7u) | ((half >> 4) & 0x8u));
                const int source = static_cast<int>((half >> 3) & 0xFu);
                const uint32_t operation = (half >> 8) & 0x3u;
                if (operation == 0x1u)
                {
                    // BX / BLX 寄存器
                    out.Kind = (half & 0x0080u) != 0 ? InstructionKind::Call : InstructionKind::Branch;
                    out.Base = source;
                    out.bSwitchesMode = true;
                    return true;
                }
                if (operation == 0x2u)
                {
                    out.Kind = InstructionKind::MoveRegister;
                    out.Dest = dest;
                    out.Base = source;
                    return true;
                }
                if (operation == 0x0u)
                {
                    out.Kind = InstructionKind::AddShiftedRegister;
                    out.Dest = dest;
                    out.Base = dest;
                    out.Source = source;
                    out.Shift = 0;
                    out.ShiftType = ShiftKind::Lsl;
                    return true;
                }
                out.Kind = InstructionKind::Other;
                out.Dest = dest;
                return true;
            }

            static bool Decode16LiteralAndRegisterTransfer(uint16_t half, uintptr_t address, Instruction &out)
            {
                // 0x4800：LDR 字面量，PC 相对且 4 字节对齐
                if ((half & 0xF800u) == 0x4800u)
                {
                    const int dest = static_cast<int>((half >> 8) & 0x7u);
                    out.Kind = InstructionKind::LoadLiteral;
                    out.Dest = dest;
                    out.Value = (ThumbPc(address) & ~uintptr_t{3}) + static_cast<uint32_t>(half & 0xFFu) * 4u;
                    out.bExactAddress = true;
                    out.AccessWidth = 4;
                    return true;
                }
                // 0x5000：寄存器偏移访存，偏移量来自寄存器，静态偏移未知
                const bool load = (half & 0x0800u) != 0;
                const int dest = static_cast<int>(half & 0x7u);
                if (load)
                {
                    out.Kind = InstructionKind::Other;
                    out.Dest = dest;
                }
                else
                {
                    out.Kind = InstructionKind::Other;
                    out.Dest = -1;
                }
                return true;
            }

            // 格式 6/7（字与字节）、格式 8（半字）共用立即数偏移结构
            static bool Decode16ImmediateTransfer(uint16_t half, Instruction &out)
            {
                const uint32_t format = half >> 12;
                const bool load = (half & 0x0800u) != 0;
                const bool byteAccess = format == 0x7u;
                const bool halfAccess = format == 0x8u;
                const int dest = static_cast<int>(half & 0x7u);
                const int base = static_cast<int>((half >> 3) & 0x7u);
                const uint32_t scale = byteAccess ? 1u : (halfAccess ? 2u : 4u);

                out.Base = base;
                out.Offset = static_cast<int64_t>((half >> 6) & 0x1Fu) * scale;
                out.AccessWidth = static_cast<uint8_t>(scale);
                out.Kind = load ? InstructionKind::Load : InstructionKind::Store;
                out.Dest = load ? dest : -1;
                return true;
            }

            static bool Decode16Misc(uint16_t half, uintptr_t address, Instruction &out)
            {
                // PUSH：0b1011 0 10 0 M reglist
                if ((half & 0xFE00u) == 0xB400u)
                {
                    out.Kind = InstructionKind::Store;
                    out.Base = 13;
                    return true;
                }
                // POP：0b1011 1 10 0 P reglist
                if ((half & 0xFE00u) == 0xBC00u)
                {
                    // reglist 含 PC 等价于返回；否则为多寄存器弹出
                    if ((half & 0x0100u) != 0)
                    {
                        out.Kind = InstructionKind::Branch;
                        out.bSwitchesMode = true;
                    }
                    else
                    {
                        out.Kind = InstructionKind::Other;
                        out.bClobbersAll = true;
                    }
                    return true;
                }
                // CBZ / CBNZ：0b1011 op 0 i 1 imm5 Rn
                if ((half & 0xF500u) == 0xB100u)
                {
                    const uint32_t nonzero = (half >> 11) & 0x1u;
                    const uint32_t imm = (((half >> 9) & 0x1u) << 6) | (((half >> 3) & 0x1Fu) << 1);
                    out.Kind = InstructionKind::ConditionalBranch;
                    out.Base = static_cast<int>(half & 0x7u);
                    out.Value = address + 4 + imm + (nonzero << 1) * 0u;
                    return true;
                }
                if ((half & 0xFF00u) == 0xB200u)
                {
                    // 扩展指令：写目标寄存器，不参与地址合成
                    out.Kind = InstructionKind::Other;
                    out.Dest = static_cast<int>(half & 0x7u);
                    return true;
                }
                if ((half & 0xFF00u) == 0xBA00u ||
                    (half & 0xFF00u) == 0xBE00u)
                {
                    // 字节反转、断点与提示指令
                    out.Kind = InstructionKind::Other;
                    out.Dest = (half & 0xFF00u) == 0xBA00u ? static_cast<int>(half & 0x7u) : -1;
                    return true;
                }
                // 其余压栈/弹栈组合（含 LR）
                const bool load = (half & 0x0800u) != 0;
                if (load)
                {
                    out.Kind = InstructionKind::Other;
                    out.bClobbersAll = true;
                }
                else
                {
                    out.Kind = InstructionKind::Store;
                    out.Base = 13;
                }
                return true;
            }

            static bool Decode16BlockTransfer(uint16_t half, Instruction &out)
            {
                const bool load = (half & 0x0800u) != 0;
                if (load)
                {
                    // 多寄存器加载写入集合不固定
                    out.Kind = InstructionKind::Other;
                    out.bClobbersAll = true;
                    return true;
                }
                out.Kind = InstructionKind::Store;
                out.Base = static_cast<int>((half >> 8) & 0x7u);
                return true;
            }

            // 32 位 Thumb 按首半字 bit12..11 分组
            // 11101 块传送/双字访存/数据处理寄存器，11110 立即数处理与分支，11111 单寄存器访存
            static bool Decode32(uint16_t first, uint16_t second, uintptr_t address, Instruction &out)
            {
                switch ((first >> 11) & 0x3u)
                {
                case 0x1u:
                    return Decode32RegisterGroup(first, second, out);
                case 0x2u:
                    if ((second & 0x8000u) != 0)
                        return DecodeBranchMisc(first, second, address, out);
                    if ((first & 0x0200u) == 0)
                        return Decode32ImmediateGroup(first, second, out);
                    return Decode32PlainImmediateGroup(first, second, out);
                default:
                    return Decode32SingleTransfer(first, second, address, out);
                }
            }

            // 32 位分支编码：S/J2/J1/imm10/imm11 组合成 25 位有符号位移
            // 目标以「指令地址 + 4」为基准，个别实现按 4 字节对齐
            static bool EmitBranchImmediate(uint16_t first, uint16_t second, uintptr_t address,
                                            InstructionKind kind, bool aligned, Instruction &out)
            {
                const uint32_t s = (first >> 10) & 0x1u;
                const uint32_t j1 = (second >> 13) & 0x1u;
                const uint32_t j2 = (second >> 11) & 0x1u;
                const uint32_t i1 = j1 ^ s ^ 1u;
                const uint32_t i2 = j2 ^ s ^ 1u;
                const uint32_t imm10 = first & 0x03FFu;
                const uint32_t imm11 = second & 0x07FFu;
                const int32_t offset = SignedBits((s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1), 25);
                out.Kind = kind;
                const uintptr_t target = address + 4 + static_cast<uint32_t>(offset);
                out.Value = aligned ? (target & ~uintptr_t{3}) : target;
                if (kind == InstructionKind::Call)
                    out.bSwitchesMode = !aligned;
                return true;
            }

            // 分支与杂项控制：第二个半字 bit15..12 决定具体编码，
            // 0xC 为 BLX 立即数，0xB 为 B.W，0xF 为 BL，0xA 为条件分支
            static bool DecodeBranchMisc(uint16_t first, uint16_t second, uintptr_t address, Instruction &out)
            {
                const uint32_t opcode = (second >> 12) & 0xFu;
                if (opcode == 0xBu)
                    return EmitBranchImmediate(first, second, address, InstructionKind::Branch, false, out);
                if (opcode == 0xFu)
                    return EmitBranchImmediate(first, second, address, InstructionKind::Call, false, out);
                if (opcode == 0xCu)
                    return EmitBranchImmediate(first, second, address, InstructionKind::Call, true, out);
                if ((opcode & 0xEu) == 0xAu)
                {
                    // 条件分支的条件码在首个半字 bit9..6
                    out.Kind = InstructionKind::ConditionalBranch;
                    out.Value = address + 4;
                    out.bConditional = true;
                    return true;
                }
                // MSR/MRS 与提示指令不改变通用寄存器数据流
                out.Kind = InstructionKind::Other;
                out.Dest = -1;
                return true;
            }

            // Thumb 12 位立即数展开：imm12 = i:imm3:imm8
            static uint32_t ExpandThumbImmediate(uint32_t imm12)
            {
                if ((imm12 & 0xC00u) == 0)
                {
                    const uint32_t imm8 = imm12 & 0xFFu;
                    switch ((imm12 >> 8) & 0x3u)
                    {
                    case 0x0u:
                        return imm8;
                    case 0x1u:
                        return imm8 << 16;
                    case 0x2u:
                        return imm8 << 24;
                    default:
                        return imm8 * 0x01010101u;
                    }
                }
                const uint32_t unrotated = 0x80u | (imm12 & 0x7Fu);
                const uint32_t rotation = (imm12 >> 7) & 0x1Fu;
                if (rotation == 0)
                    return unrotated;
                return (unrotated >> rotation) | (unrotated << (32u - rotation));
            }

            // 数据处理寄存器的移位量由 imm3:imm2 组成
            static uint32_t ThumbShiftAmount(uint16_t second)
            {
                return (((second >> 12) & 0x7u) << 2) | ((second >> 6) & 0x3u);
            }

            // 块传送与双字访存会写回多个寄存器，无法静态跟踪其数据流
            static bool Decode32RegisterGroup(uint16_t first, uint16_t second, Instruction &out)
            {
                const uint32_t group = (first >> 7) & 0x7u;
                if (group == 0x1u || group == 0x3u)
                {
                    out.Kind = InstructionKind::Other;
                    out.bClobbersAll = true;
                    return true;
                }
                if (group < 0x4u)
                {
                    Unknown(out);
                    return true;
                }

                const uint32_t opcode = (first >> 5) & 0xFu;
                const int base = static_cast<int>(first & 0xFu);
                const int dest = static_cast<int>((second >> 8) & 0xFu);
                const int source = static_cast<int>(second & 0xFu);
                const ShiftKind type = ArmShiftKind((second >> 4) & 0x3u);
                const uint32_t amount = ThumbShiftAmount(second);
                if (opcode == 0x2u && base == kArm32ProgramCounter)
                {
                    // MOV 寄存器：LSR 形式直接对应块索引的移位语义
                    if (type == ShiftKind::Lsr)
                    {
                        out.Kind = InstructionKind::LogicalShiftRight;
                        out.Dest = dest;
                        out.Base = source;
                        out.Shift = static_cast<uint8_t>(amount == 0 ? 32 : amount);
                        return true;
                    }
                    out.Kind = InstructionKind::MoveRegister;
                    out.Dest = dest;
                    out.Base = source;
                    if (type == ShiftKind::Lsl)
                    {
                        out.Shift = static_cast<uint8_t>(amount);
                        out.ShiftType = ShiftKind::Lsl;
                    }
                    return true;
                }
                if (opcode == 0x8u)
                {
                    out.Kind = InstructionKind::AddShiftedRegister;
                    out.Dest = dest == kArm32ProgramCounter ? -1 : dest;
                    out.Base = base;
                    out.Source = source;
                    out.ShiftType = type;
                    out.Shift = static_cast<uint8_t>(amount);
                    out.Value = 0;
                    return true;
                }
                out.Kind = InstructionKind::Other;
                out.Dest = dest == kArm32ProgramCounter ? -1 : dest;
                return true;
            }

            // 数据处理立即数：AND/ADD/SUB/MOV 共用 12 位展开立即数
            static bool Decode32ImmediateGroup(uint16_t first, uint16_t second, Instruction &out)
            {
                const uint32_t opcode = (first >> 5) & 0xFu;
                const int dest = static_cast<int>((second >> 8) & 0xFu);
                const int base = static_cast<int>(first & 0xFu);
                const uint32_t imm12 = (((first >> 10) & 0x1u) << 11) | (((second >> 12) & 0x7u) << 8) |
                                       (second & 0xFFu);
                const uint32_t value = ExpandThumbImmediate(imm12);
                // Rd 为 PC 时这些编码是 CMP/CMN/TST/TEQ，只写标志位
                if (dest == kArm32ProgramCounter)
                {
                    out.Kind = InstructionKind::Other;
                    out.Dest = -1;
                    return true;
                }
                switch (opcode)
                {
                case 0x0u:
                    out.Kind = InstructionKind::AndImmediate;
                    out.Dest = dest;
                    out.Base = base;
                    out.Mask = value;
                    return true;
                case 0x8u:
                    out.Kind = InstructionKind::AddImmediate;
                    out.Dest = dest;
                    out.Base = base;
                    out.Value = value;
                    return true;
                case 0x2u:
                    if (base == kArm32ProgramCounter)
                    {
                        out.Kind = InstructionKind::MoveImmediate;
                        out.Dest = dest;
                        out.Value = value;
                        return true;
                    }
                    break;
                default:
                    break;
                }
                // 其余运算写 Rd；Rd 为 PC 时不跟踪
                out.Kind = InstructionKind::Other;
                out.Dest = dest == kArm32ProgramCounter ? -1 : dest;
                return true;
            }

            // 二进制立即数：MOVW/MOVT 与位域操作，操作码在 bit8..4
            static bool Decode32PlainImmediateGroup(uint16_t first, uint16_t second, Instruction &out)
            {
                const uint32_t opcode = (first >> 4) & 0x1Fu;
                const int dest = static_cast<int>((second >> 8) & 0xFu);
                const int base = static_cast<int>(first & 0xFu);
                switch (opcode)
                {
                case 0x04u: // MOVW
                case 0x0Cu: // MOVT
                {
                    // imm16 = imm4:i:imm3:imm8
                    const uint32_t immediate = (((first & 0xFu) << 12) | (((first >> 10) & 0x1u) << 11) |
                                                (((second >> 12) & 0x7u) << 8) | (second & 0xFFu));
                    out.Kind = InstructionKind::MoveImmediate;
                    out.Dest = dest;
                    out.Value = immediate;
                    out.ValueMask = 0xFFFFu;
                    out.bComposes = opcode == 0x0Cu;
                    return true;
                }
                case 0x00u: // ADD 立即数
                    out.Kind = InstructionKind::AddImmediate;
                    out.Dest = dest;
                    out.Base = base;
                    out.Value = (((first >> 10) & 0x1u) << 11) | (((second >> 12) & 0x7u) << 8) |
                                (second & 0xFFu);
                    return true;
                case 0x1Cu: // UBFX：取块索引的位域抽取
                    out.Kind = InstructionKind::BitfieldExtract;
                    out.Dest = dest;
                    out.Base = base;
                    out.Shift = static_cast<uint8_t>(ThumbShiftAmount(second));
                    out.BitWidth = static_cast<uint8_t>((second & 0x1Fu) + 1u);
                    return true;
                default:
                    break;
                }
                out.Kind = InstructionKind::Other;
                out.Dest = dest == kArm32ProgramCounter ? -1 : dest;
                return true;
            }

            // 单寄存器访存：bit6..5 为宽度，bit4 为加载位
            static bool Decode32SingleTransfer(uint16_t first, uint16_t second, uintptr_t address,
                                               Instruction &out)
            {
                if ((first & 0xFF00u) != 0xF800u)
                {
                    Unknown(out);
                    return true;
                }
                const int base = static_cast<int>(first & 0xFu);
                const int dest = static_cast<int>((second >> 12) & 0xFu);
                const uint32_t size = (first >> 5) & 0x3u;
                const bool load = (first & 0x0010u) != 0;
                const uint32_t immediate = second & 0xFFFu;
                if (load && base == kArm32ProgramCounter)
                {
                    out.Kind = InstructionKind::LoadLiteral;
                    out.Dest = dest;
                    out.Value = (ThumbPc(address) & ~uintptr_t{3}) + immediate;
                    out.bExactAddress = true;
                    out.AccessWidth = 4;
                    return true;
                }
                if (load && dest == kArm32ProgramCounter)
                {
                    // 目标为 PC 的字节/半字加载属于预取提示，不写通用寄存器
                    out.Kind = InstructionKind::Other;
                    out.Dest = -1;
                    return true;
                }
                out.Kind = load ? InstructionKind::Load : InstructionKind::Store;
                out.Base = base;
                out.Dest = load ? dest : -1;
                out.Offset = static_cast<int64_t>(immediate);
                out.AccessWidth = size == 0x0u ? 1 : (size == 0x1u ? 2 : 4);
                return true;
            }
        };
    } // namespace

    std::unique_ptr<InstructionDecoder> CreateArm32Decoder(CodeMode mode)
    {
        // A32 与 Thumb 共享 32 位目标语义，但编码长度与 PC 规则不同
        if (mode == CodeMode::Thumb)
            return std::make_unique<ThumbInstructionDecoder>();
        if (mode == CodeMode::Arm32)
            return std::make_unique<Arm32InstructionDecoder>();
        return nullptr;
    }
} // namespace nextdumper::analysis
