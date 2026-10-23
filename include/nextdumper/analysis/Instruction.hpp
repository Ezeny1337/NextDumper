#pragma once

#include <cstdint>

namespace nextdumper::analysis
{
    enum class InstructionKind : uint8_t
    {
        Other,
        SetBase,
        AddImmediate,
        AddShiftedRegister,
        AddExtendedRegister,
        LoadLiteral,
        Load,
        Store,
        MoveImmediate,
        MoveRegister,
        LogicalShiftRight,
        BitfieldInsert,
        AndImmediate,
        TestBit,
        Call,
        Branch,
        Return,
        Prologue,
    };

    enum class ShiftKind : uint8_t
    {
        None,
        Lsl,
        Lsr,
        Asr,
        Ror,
    };

    enum class ExtendKind : uint8_t
    {
        None,
        Uxtb,
        Uxth,
        Uxtw,
        Uxtx,
        Sxtb,
        Sxth,
        Sxtw,
        Sxtx,
    };

    struct Instruction
    {
        InstructionKind Kind = InstructionKind::Other;

        int Dest = -1;
        int Base = -1;
        int Source = -1;

        uint64_t Value = 0;
        uint64_t ValueMask = UINT64_MAX;
        uint64_t Mask = 0;
        int64_t Offset = 0;

        uint8_t AccessWidth = 0;
        uint8_t Length = 4;
        uint8_t OperandWidth = 8;
        uint8_t Shift = 0;
        uint8_t Bit = 0;
        uint8_t BitWidth = 0;

        ShiftKind ShiftType = ShiftKind::None;
        ExtendKind Extend = ExtendKind::None;

        bool bSignExtends = false;
        bool bWritesBackBase = false;
        bool bClobbersAll = false;
        bool bExactAddress = false;
        bool bComposes = false;
        bool bAddressLike = false;
    };
} // namespace nextdumper::analysis
