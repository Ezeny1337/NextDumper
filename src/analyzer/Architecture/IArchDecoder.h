#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

/// @brief Supprted Architecture enum.
enum class EArch
{
	Unknown,
	Arm64,
	Arm32,
};

/// @brief Name of an architecture.
inline const char *EArchToString(EArch Arch)
{
	switch (Arch)
	{
	case EArch::Arm64:
		return "ARM64";
	case EArch::Arm32:
		return "ARM32";
	default:
		return "unknown";
	}
}

/// @brief Architecture-neutral view of one instruction.
struct NormalizedInsn
{
	enum class EKind : uint8_t
	{
		Other,	 ///< Unmodelled. Clobbers Dest when Dest >= 0.
		SetBase, ///< Materializes an address into Dest (ADRP page, ADR target).
		AddImm,	 ///< Dest = Base + Value.

		/**
		 * @brief Dest = the pointer-sized word stored in the image at Value.
		 *
		 * A literal load, and deliberately *not* an address computation: what
		 * the word means is decided by what the program does with it next. In
		 * ARM32's PIC idiom the pool word is a displacement, completed by a
		 * following `ADD Rd,PC,Rd`; elsewhere the same instruction loads an
		 * absolute address. Reading it as an address here would fabricate a
		 * global out of every displacement that happens to land in the image.
		 */
		LoadLiteral,

		Load,	  ///< Dest = *(Base + Offset).
		Store,	  ///< *(Base + Offset) = Dest.
		MoveImm,  ///< 立即数赋值，bComposes 时仅替换 ValueMask 覆盖的位
		MoveReg,  ///< Dest = Base. Register-to-register copy.
		Call,	  ///< Clobbers the caller-saved set.
		Branch,	  ///< Control transfer; does not invalidate tracked bases.
		Return,	  ///< Function end; invalidates everything.
		Prologue, ///< Frame setup; marks a likely function entry.
	};

	EKind Kind = EKind::Other; ///< What this instruction does, as modelled here.

	int Dest = -1; ///< Normalized destination register index, -1 when absent.
	int Base = -1; ///< Normalized source/base register index, -1 when absent.

	uint64_t Value = 0;				 ///< SetBase 地址、AddImm 加数或 MoveImm 立即数
	uint64_t ValueMask = UINT64_MAX; ///< MOVK/MOVT 的替换位掩码
	bool bClobbersAll = false;		 ///< 无法可靠判断写寄存器时清空数据流状态
	int64_t Offset = 0;				 ///< Load/Store displacement.

	bool bSignExtends = false; ///< literal 窄值需符号扩展时置位
	uint8_t AccessWidth = 0;   ///< Load/Store size in bytes (4, 8, ...), 0 if n/a.
	uint8_t Length = 4;		   ///< Encoded length, for variable-width targets.

	/// SetBase: Value is the complete address (ADR), not just a page (ADRP).
	bool bExactAddress = false;

	/// MoveImm：按 ValueMask 替换已累计立即数的对应位（MOVK/MOVT）
	bool bComposes = false;

	/// MoveImm: the composed immediate is meant to be an address, not a scalar.
	/// AArch64 builds addresses with ADRP/ADD and uses MOVZ/MOVK only for
	/// constants, so it leaves this false; ARM32 builds them with MOVW/MOVT and
	/// will set it, letting the harvester promote the result to a base.
	bool bAddressLike = false;

	/**
	 * @brief Load/Store: the instruction also updates its base register.
	 *
	 * The pre- and post-indexed forms move Rn as a side effect of the access.
	 * A tracker that misses this keeps believing a base the instruction has
	 * just changed, and every later use of it names an address that was never
	 * computed - so consumers must invalidate Base when this is set.
	 */
	bool bWritesBackBase = false;
};

// 按编码中的访问宽度读取 literal，避免 ARM64 的 32 位 literal 越界或拼入邻接数据
template <typename Memory>
[[nodiscard]] bool ReadLiteralValue(const Memory *memory, const NormalizedInsn &instruction, uint64_t &value)
{
	if (!memory || !instruction.AccessWidth || instruction.AccessWidth > sizeof(value) || instruction.Value > UINTPTR_MAX)
		return false;
	value = 0;
	if (memory->ReadBytes(static_cast<uintptr_t>(instruction.Value), &value, instruction.AccessWidth) != instruction.AccessWidth)
		return false;
	if (instruction.bSignExtends && instruction.AccessWidth < sizeof(value))
	{
		const unsigned bits = instruction.AccessWidth * 8;
		if (value & (uint64_t{1} << (bits - 1)))
			value |= UINT64_MAX << bits;
	}
	return true;
}

/**
 * @brief Global arch decoder layer interface.
 */
class IArchDecoder
{
public:
	virtual ~IArchDecoder() = default;

	/// Which architecture this decoder handles.
	virtual EArch Arch() const = 0;

	/// Fixed instruction size in bytes, or 0 when the target is variable-width
	/// (in which case NormalizedInsn::Length drives the walk).
	virtual uint32_t InstructionStride() const = 0;

	/// How many normalized register indices exist, for sizing tracking state.
	virtual int RegisterCount() const = 0;

	/// True when a call may destroy this register's value.
	virtual bool CallClobbers(int Reg) const = 0;

	/**
	 * @brief Decodes one instruction from a local buffer.
	 *
	 * Reads @p At directly. The bytes must already be in this process's memory -
	 * the decoder never reaches into the target - so a caller working on a live
	 * process must copy them across first, which is what CodeWindow does.
	 *
	 * @param At    Locally readable bytes to decode.
	 * @param Avail How many bytes are readable at At.
	 * @param Addr  Address those bytes live at in the target, for PC-relative forms.
	 * @param Out   Receives the normalized instruction.
	 * @return false when nothing usable was decoded; Out.Length must still be set
	 *         so the walk can advance.
	 */
	virtual bool DecodeLocalBytes(const uint8_t *At, size_t Avail, uint64_t Addr, NormalizedInsn &Out) const = 0;
};

/**
 * @brief Dispatches to the per-architecture factories.
 * @return unique_ptr of decoder or nullptr for an architecture with no decoder.
 */
std::unique_ptr<IArchDecoder> CreateArchDecoder(EArch Arch);

/**
 * @brief Global active arch decoder backend.
 */
inline std::unique_ptr<IArchDecoder> GArchDecoder;
