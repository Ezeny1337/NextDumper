#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

/**
 * @brief One mapped region: a segment of an image, or a line of /proc/pid/maps.
 */
class MemRegionInfo
{
public:
	MemRegionInfo() = default;

	/// @brief Builds a region from known bounds and permissions.
	MemRegionInfo(std::string PathName, uintptr_t Start, uintptr_t End, uint64_t Offset, bool bReadable = false, bool bWriteable = false, bool bExecutable = false)
		: PathName_(std::move(PathName)),
		  Start_(Start),
		  End_(End),
		  Offset_(Offset),
		  bReadable_(bReadable),
		  bWriteable_(bWriteable),
		  bExecutable_(bExecutable)
	{
	}

	/// @brief start address of the region.
	inline uintptr_t GetStart() const { return Start_; }
	/// @brief end address of region.
	inline uintptr_t GetEnd() const { return End_; }
	/// @brief offset of the region.
	inline uint64_t GetOffset() const { return Offset_; }
	/// @brief Byte length `End - Start`
	inline size_t GetSize() const { return End_ > Start_ ? static_cast<size_t>(End_ - Start_) : 0; }
	/// @brief Backing path, or the segment name for an image.
	inline std::string GetPathName() const { return PathName_; }
	/// @brief Region can be read.
	inline bool IsReadable() const { return bReadable_; }
	/// @brief Region can be written.
	inline bool IsWriteable() const { return bWriteable_; }
	/// @brief Region can be executed.
	inline bool IsExecutable() const
	{
		// workaround for android emulators.
#if defined(__i386__) || defined(__x86_64__)
		return bExecutable_ || (bReadable_ && !bWriteable_);
#else
		return bExecutable_;
#endif
	}
	/// @brief Sets the start address.
	inline void SetStart(uintptr_t Start) { Start_ = Start; }
	/// @brief Sets the end address.
	inline void SetEnd(uintptr_t End) { End_ = End; }
	/// @brief Sets the offset.
	inline void SetOffset(uint64_t Offset) { Offset_ = Offset; }
	/// @brief Sets the name.
	inline void SetPathName(std::string PathName) { PathName_ = std::move(PathName); }

	/// @brief Sets all three permission bits at once.
	inline void SetPermissions(bool bReadable, bool bWriteable, bool bExecutable)
	{
		bReadable_ = bReadable;
		bWriteable_ = bWriteable;
		bExecutable_ = bExecutable;
	}

	inline bool operator==(const MemRegionInfo &Rhs) const
	{
		return Start_ == Rhs.Start_ && End_ == Rhs.End_ && Offset_ == Rhs.Offset_ && PathName_ == Rhs.PathName_ &&
			   bReadable_ == Rhs.bReadable_ && bWriteable_ == Rhs.bWriteable_ && bExecutable_ == Rhs.bExecutable_;
	}

	inline bool operator!=(const MemRegionInfo &Rhs) const { return !(*this == Rhs); }

	/**
	 * @brief Writes a human-readable summary of the memory region to a stream.
	 *
	 * @param os Output stream.
	 * @param Seg Memory region to format.
	 * @return The output stream.
	 */
	inline friend std::ostream &operator<<(std::ostream &os, const MemRegionInfo &Seg)
	{
		std::ios_base::fmtflags SavedFlags = os.flags();
		char SavedFill = os.fill();

		constexpr int kAddrW = sizeof(uintptr_t) * 2;
		constexpr int kOffsetW = 8;

		os << std::hex << std::setfill('0')
		   << "0x" << std::setw(kAddrW) << Seg.Start_
		   << " - "
		   << "0x" << std::setw(kAddrW) << Seg.End_
		   << " | 0x" << std::setw(kOffsetW) << Seg.Offset_
		   << " | "
		   << (Seg.bReadable_ ? "R" : "-")
		   << (Seg.bWriteable_ ? "W" : "-")
		   << (Seg.bExecutable_ ? "X" : "-");

		if (!Seg.PathName_.empty())
			os << " | [" << Seg.PathName_ << "]";

		os.flags(SavedFlags);
		os.fill(SavedFill);

		return os;
	}

	/**
	 * @brief Returns a human-readable summary of the memory region.
	 *
	 * @return Formatted memory region information.
	 */
	inline std::string ToString() const
	{
		std::ostringstream ss;
		ss << *this;
		return ss.str();
	}

	/// @brief True when this region describes a real, non-empty mapping.
	inline bool IsValid() const { return End_ > Start_; }

	/// @brief True when Address falls inside this region.
	inline bool Contains(uintptr_t Address) const { return Address >= Start_ && Address < End_; }

private:
	std::string PathName_;
	uintptr_t Start_ = 0;
	uintptr_t End_ = 0;
	uint64_t Offset_ = 0;
	bool bReadable_ = false;
	bool bWriteable_ = false;
	bool bExecutable_ = false;
};

/**
 * @brief One loaded module: its span and its segments.
 */
class ModuleInfo
{
public:
	ModuleInfo() = default;

	/// @brief Builds a module from known bounds and segments.
	ModuleInfo(std::string PathName, uintptr_t Start, uintptr_t End, uintptr_t Base, std::vector<MemRegionInfo> Segments = {})
		: PathName_(std::move(PathName)),
		  Start_(Start),
		  End_(End),
		  Base_(Base)
	{
		SetSegments(std::move(Segments));
	}

	/// @brief Lowest mapped address.
	inline uintptr_t GetStart() const { return Start_; }
	/// @brief One past the highest.
	inline uintptr_t GetEnd() const { return End_; }
	/// @brief Address offsets are measured from; not always the lowest mapping.
	inline uintptr_t GetBase() const { return Base_; }
	/// @brief Byte length `End - Start`
	inline size_t GetSize() const { return End_ > Start_ ? static_cast<size_t>(End_ - Start_) : 0; }
	/// @brief Backing file, informational only.
	inline std::string GetPathName() const { return PathName_; }
	/// @brief Returns the module's segments.
	inline std::vector<MemRegionInfo> GetSegments() const { return Segments_; }

	/// @brief Iterates over the module's segments until the callback returns false.
	inline MemRegionInfo ForEachSegment(const std::function<bool(MemRegionInfo)> &Callback) const
	{
		for (const auto &Segment : Segments_)
		{
			if (Callback && Segment.IsValid() && Callback(Segment))
				return Segment;
		}

		return MemRegionInfo{};
	}

	/// @brief Sets the lowest address.
	inline void SetStart(uintptr_t Start) { Start_ = Start; }
	/// @brief Sets the end bound.
	inline void SetEnd(uintptr_t End) { End_ = End; }
	/// @brief Sets the offset base.
	inline void SetBase(uintptr_t Base) { Base_ = Base; }
	/// @brief Sets the path.
	inline void SetPathName(std::string PathName) { PathName_ = std::move(PathName); }
	/// @brief Replaces the segment list, sorted ascending by start address.
	inline void SetSegments(std::vector<MemRegionInfo> Segments)
	{
		Segments_ = std::move(Segments);
		std::sort(Segments_.begin(), Segments_.end(), [](const MemRegionInfo &A, const MemRegionInfo &B)
				  { return A.GetStart() < B.GetStart(); });
	}

	/// @brief Adds one segment, keeping the list sorted.
	inline void AddSegment(MemRegionInfo Segment)
	{
		const auto At = std::upper_bound(Segments_.begin(), Segments_.end(), Segment.GetStart(), [](uintptr_t Value, const MemRegionInfo &S)
										 { return Value < S.GetStart(); });
		Segments_.insert(At, std::move(Segment));
	}

	inline bool operator==(const ModuleInfo &Rhs) const
	{
		return Start_ == Rhs.Start_ && End_ == Rhs.End_ && Base_ == Rhs.Base_ &&
			   PathName_ == Rhs.PathName_ && Segments_ == Rhs.Segments_;
	}

	inline bool operator!=(const ModuleInfo &Rhs) const { return !(*this == Rhs); }

	/// @brief True when this module has a real span and at least one segment.
	inline bool IsValid() const { return End_ > Start_ && !Segments_.empty(); }

	/// @brief True when Address falls inside the module's span.
	inline bool Contains(uintptr_t Address) const { return Address >= Start_ && Address < End_; }

	/// @brief Converts a runtime address to a file offset relative to this module's base.
	inline uintptr_t AddressToOffset(uintptr_t Address) const
	{
		if (Address == 0 || !IsValid())
			return 0;

		return Address > Base_ ? Address - Base_ : Address;
	}

	/// @brief Converts a relative offset to a runtime address.
	inline uintptr_t OffsetToAddress(uintptr_t Offset) const
	{
		if (!IsValid())
			return 0;

		return Base_ + Offset;
	}

	/**
	 * @brief Finds the memory segment containing an address.
	 *
	 * @param Address Address to look up.
	 * @return Pointer to the containing segment, or nullptr if not found.
	 *
	 * @note The returned pointer is borrowed and remains valid while the segment list is unchanged.
	 */
	inline const MemRegionInfo *FindAddressRegion(uintptr_t Address) const
	{
		const auto At = std::upper_bound(Segments_.begin(), Segments_.end(), Address, [](uintptr_t Value, const MemRegionInfo &S)
										 { return Value < S.GetStart(); });
		if (At == Segments_.begin())
			return nullptr;
		const MemRegionInfo &Candidate = *(At - 1);
		return Candidate.Contains(Address) ? &Candidate : nullptr;
	}

private:
	std::string PathName_;
	uintptr_t Start_ = 0;
	uintptr_t End_ = 0;
	uintptr_t Base_ = 0;
	std::vector<MemRegionInfo> Segments_;
};

/**
 * @brief Global memory layer interface.
 */
class IMemory
{
protected:
	/// @brief Maximum bytes read per scan pass.
	static constexpr size_t kScanChunkBytes = 4u * 1024u * 1024u;

	/// @brief Page step used to advance through unmapped gaps.
	static constexpr size_t kPageStep = 4096u;

	/**
	 * @brief Finds the first aligned occurrence of a pointer value in a range.
	 *
	 * Scans in chunks using the backend's ReadBytes implementation.
	 *
	 * @param Value Pointer-sized value to search for.
	 * @param Alignment Required address alignment.
	 * @param Cur Current start address of the search.
	 * @param End Exclusive end address of the search.
	 * @return First matching address, or 0 if not found.
	 */
	inline uintptr_t BulkFindFirst(uintptr_t Value, int32_t Alignment, uintptr_t Cur, uintptr_t End) const
	{
		std::vector<uint8_t> Buffer;
		const size_t Step = static_cast<size_t>(Alignment);
		if (Alignment <= 0)
			return 0;
		while (Cur <= End && sizeof(uintptr_t) <= End - Cur)
		{
			size_t ChunkSize = std::min(static_cast<size_t>(End - Cur), kScanChunkBytes);
			ChunkSize = (ChunkSize / Step) * Step;
			if (!ChunkSize)
				break;
			Buffer.resize(ChunkSize);
			const size_t Received = ReadBytes(Cur, Buffer.data(), ChunkSize);
			if (Received <= ChunkSize)
			{
				for (size_t Off = 0; Off + sizeof(uintptr_t) <= Received; Off += Step)
				{
					uintptr_t Val;
					std::memcpy(&Val, Buffer.data() + Off, sizeof(uintptr_t));
					if (Val == Value)
						return Cur + Off;
				}
			}
			Cur += ChunkSize;
		}
		return 0;
	}

	/**
	 * @brief Finds aligned occurrences of a pointer value in a range.
	 *
	 * @param Value Pointer-sized value to search for.
	 * @param Alignment Required address alignment.
	 * @param Cur Current start address of the search.
	 * @param End Exclusive end address of the search.
	 * @param Out Receives matching addresses in ascending order.
	 * @param MaxHits Maximum number of matches; 0 returns all matches.
	 */
	inline void BulkFindAll(uintptr_t Value, int32_t Alignment, uintptr_t Cur, uintptr_t End, std::vector<uintptr_t> &Out, size_t MaxHits = 0) const
	{
		std::vector<uint8_t> Buffer;
		const size_t Step = static_cast<size_t>(Alignment);
		if (Alignment <= 0)
			return;
		while (Cur <= End && sizeof(uintptr_t) <= End - Cur)
		{
			size_t ChunkSize = std::min(static_cast<size_t>(End - Cur), kScanChunkBytes);
			ChunkSize = (ChunkSize / Step) * Step;
			if (!ChunkSize)
				break;
			Buffer.resize(ChunkSize);
			const size_t Received = ReadBytes(Cur, Buffer.data(), ChunkSize);
			if (Received <= ChunkSize)
			{
				for (size_t Off = 0; Off + sizeof(uintptr_t) <= Received; Off += Step)
				{
					uintptr_t Val;
					std::memcpy(&Val, Buffer.data() + Off, sizeof(uintptr_t));
					if (Val == Value)
					{
						Out.push_back(Cur + Off);
						if (MaxHits && Out.size() >= MaxHits)
							return;
					}
				}
			}
			Cur += ChunkSize;
		}
	}

public:
	virtual ~IMemory() = default;

	/**
	 * @brief Initializes the memory backend.
	 *
	 * @return true if the backend initialized successfully.
	 */
	virtual bool Initialize() = 0;

	/// @brief Process name at runtime, image path for a file backend.
	virtual std::string GetProcessName() const = 0;

	/// @brief Process id at runtime, 0 for a file backend.
	virtual int GetProcessID() const = 0;

	/// @brief Refresh process memory backend.
	virtual bool RefreshMemory() = 0;

	/// @brief True when the backend is ready to serve reads.
	virtual bool IsMemoryAccessOk() const = 0;

	/// @brief True when Address falls in a mapped region.
	virtual bool IsValidAddress(uintptr_t Address) const = 0;

	/// @brief True when the address can be safely read for @p Size bytes.
	virtual bool IsAddressReadable(uintptr_t Address, size_t Size = sizeof(void *)) const = 0;

	/// @brief True when the address can be safely written for @p Size bytes.
	virtual bool IsAddressWriteable(uintptr_t Address, size_t Size = sizeof(void *)) const = 0;

	/// @brief True when the address can be safely executed for @p Size bytes.
	virtual bool IsAddressExecutable(uintptr_t Address, size_t Size = sizeof(void *)) const = 0;

	/**
	 * @brief Returns the memory region containing an address.
	 *
	 * @param Address Address to look up.
	 * @return Containing region, or an empty region if unmapped.
	 */
	virtual MemRegionInfo GetAddressRegionInfo(uintptr_t Address) const = 0;

	/**
	 * @brief Reads a range of memory.
	 *
	 * @param Address Start address to read from.
	 * @param Buffer Destination buffer.
	 * @param Size Number of bytes to read.
	 * @return n bytes were read successfully.
	 */
	virtual size_t ReadBytes(uintptr_t Address, void *Buffer, size_t Size) const = 0;

	/**
	 * @brief Reads one trivially copyable value.
	 *
	 * @tparam T Value type.
	 * @param Address Address to read from.
	 * @return Read value, or a zero-initialized value if the read fails.
	 */
	template <typename T>
		requires std::is_trivially_copyable_v<T>
	T Read(uintptr_t Address) const
	{
		T Result{};
		if (ReadBytes(Address, &Result, sizeof(T)) != sizeof(T))
			return T{};
		return Result;
	}

	/**
	 * @brief Reads and validates a pointer stored in a relocation slot.
	 *
	 * @param Slot Address of the relocation slot.
	 * @param Out Receives the validated pointer.
	 * @return true if the slot contains a valid non-null address.
	 */
	virtual bool ReadRelocationPointer(uintptr_t Slot, uintptr_t &Out) const = 0;

	/**
	 * @brief Reads a UTF-8 string.
	 *
	 * @param Address Address of the string.
	 * @param Len Maximum number of bytes to read.
	 * @param Decrypt Optional callback used to decrypt the read bytes.
	 * @return String truncated at the first NUL character.
	 */
	inline virtual std::string ReadUTF8(uintptr_t Address, int32_t Len, const std::function<void(char *, int32_t)> &Decrypt = {}) const
	{
		if (Address == 0 || Len <= 0)
			return {};

		const size_t MaxLen = static_cast<size_t>(Len);

		std::string Result(MaxLen, '\0');

		const size_t BytesRead = ReadBytes(Address, Result.data(), MaxLen);
		if (BytesRead == 0)
			return {};

		const size_t ValidBytes = std::min(BytesRead, MaxLen);
		Result.resize(ValidBytes);

		if (Decrypt)
			Decrypt(Result.data(), static_cast<int32_t>(Result.size()));

		// Truncate at NUL if one exists.
		// If the source isn't NUL-terminated, keep all successfully read bytes.
		if (const size_t NullPos = Result.find('\0');
			NullPos != std::string::npos)
		{
			Result.resize(NullPos);
		}

		return Result;
	}

	/**
	 * @brief Reads a UTF-16 string.
	 *
	 * @param Address Address of the string.
	 * @param Len Maximum number of UTF-16 code units to read.
	 * @param Decrypt Optional callback used to decrypt the read code units.
	 * @return String truncated at the first NUL character, or all successfully read code units if no NUL exists.
	 */
	inline virtual std::u16string ReadUTF16(uintptr_t Address, int32_t Len, const std::function<void(char16_t *, int32_t)> &Decrypt = {}) const
	{
		if (Address == 0 || Len <= 0)
			return {};

		const size_t MaxLen = static_cast<size_t>(Len);
		if (MaxLen > SIZE_MAX / sizeof(char16_t))
			return {};

		std::u16string Result(MaxLen, u'\0');

		const size_t BytesToRead = MaxLen * sizeof(char16_t);

		size_t BytesRead = ReadBytes(Address, Result.data(), BytesToRead);
		if (BytesRead < sizeof(char16_t))
			return {};

		// Don't leave a partial UTF-16 code unit at the end.
		BytesRead -= BytesRead % sizeof(char16_t);
		if (BytesRead == 0)
			return {};

		const size_t CodeUnitsRead = BytesRead / sizeof(char16_t);
		Result.resize(CodeUnitsRead);

		if (Decrypt)
			Decrypt(Result.data(), static_cast<int32_t>(Result.size()));

		// Truncate at NUL if one exists.
		if (const size_t NullPos = Result.find(u'\0');
			NullPos != std::u16string::npos)
		{
			Result.resize(NullPos);
		}

		return Result;
	}

	/**
	 * @brief Reads a UTF-32 string.
	 *
	 * @param Address Address of the string.
	 * @param Len Maximum number of UTF-32 code units to read.
	 * @param Decrypt Optional callback used to decrypt the read code units.
	 * @return String truncated at the first NUL character, or all successfully read code units if no NUL exists.
	 */
	inline virtual std::u32string ReadUTF32(uintptr_t Address, int32_t Len, const std::function<void(char32_t *, int32_t)> &Decrypt = {}) const
	{
		if (Address == 0 || Len <= 0)
			return {};

		const size_t MaxLen = static_cast<size_t>(Len);

		if (MaxLen > SIZE_MAX / sizeof(char32_t))
			return {};

		std::u32string Result(MaxLen, U'\0');

		const size_t BytesToRead = MaxLen * sizeof(char32_t);

		size_t BytesRead = ReadBytes(Address, Result.data(), BytesToRead);
		if (BytesRead < sizeof(char32_t))
			return {};

		// Don't leave a partial UTF-32 code unit at the end.
		BytesRead -= BytesRead % sizeof(char32_t);
		if (BytesRead == 0)
			return {};

		const size_t CodeUnitsRead = BytesRead / sizeof(char32_t);
		Result.resize(CodeUnitsRead);

		if (Decrypt)
			Decrypt(Result.data(), static_cast<int32_t>(Result.size()));

		// Truncate at NUL if one exists.
		if (const size_t NullPos = Result.find(U'\0');
			NullPos != std::u32string::npos)
		{
			Result.resize(NullPos);
		}

		return Result;
	}

	/// @brief Finds and caches information about a named module.
	virtual ModuleInfo GetModuleInfo(const std::string &ModuleName) = 0;

	/**
	 * @brief Finds an exported symbol in a module.
	 *
	 * @param ModuleName Module to search.
	 * @param SymbolName Exported symbol name.
	 * @return Runtime symbol address, or 0 if not found.
	 */
	virtual uintptr_t FindModuleSymbol(const std::string &ModuleName, const std::string &SymbolName) = 0;

	/// @brief Returns information about the Unreal Engine module.
	virtual ModuleInfo GetUnrealModule() = 0;

	/**
	 * @brief Finds an exported symbol in the cached Unreal module.
	 *
	 * @param SymbolName Exported symbol name.
	 * @return Runtime symbol address, or 0 if not found.
	 */
	virtual uintptr_t FindUnrealSymbol(const std::string &SymbolName) = 0;

	/**
	 * @brief Writes the Unreal module's mapped image to a file.
	 *
	 * The image is reconstructed from mapped memory, so it reflects any runtime
	 * patching or unpacking the target performed after load.
	 *
	 * @param DestinationPath File or directory path to write to.
	 * @return true on success; false when unsupported on this backend or the write failed.
	 */
	virtual bool DumpUnrealModule(const std::string &DestinationPath)
	{
		((void)DestinationPath);
		return false;
	}

	/**
	 * @brief Splits a range into ordered, non-overlapping readable sub-ranges.
	 *
	 * @param Start Start address of the range.
	 * @param Range Number of bytes to inspect.
	 * @return Readable sub-ranges, or empty if none are readable.
	 */
	virtual std::vector<MemRegionInfo> BuildSegmentsRanges(uintptr_t Start, size_t Range) const
	{
		std::vector<MemRegionInfo> Out;
		if (Range == 0)
			return Out;

		const uintptr_t End = Range > static_cast<size_t>(UINTPTR_MAX - Start)
								  ? UINTPTR_MAX
								  : Start + static_cast<uintptr_t>(Range);
		for (uintptr_t Cursor = Start; Cursor < End;)
		{
			const MemRegionInfo Region = GetAddressRegionInfo(Cursor);
			if (!Region.IsValid())
			{
				// Unmapped here. Step a page and look again rather than giving up:
				// the hole may be a guard page between two readable segments.
				Cursor += kPageStep;
				continue;
			}
			if (!Region.IsReadable())
			{
				Cursor = Region.GetEnd() > Cursor ? Region.GetEnd() : Cursor + kPageStep;
				continue;
			}

			const uintptr_t ClipEnd = std::min(Region.GetEnd(), End);
			if (ClipEnd > Cursor)
				Out.emplace_back(Region.GetPathName(), Cursor, ClipEnd, Region.GetOffset(), Region.IsReadable(), Region.IsWriteable(), Region.IsExecutable());

			Cursor = ClipEnd > Cursor ? ClipEnd : Cursor + kPageStep;
		}
		return Out;
	}

	/**
	 * @brief Finds a byte-pattern match within a range.
	 *
	 * @param Start Start address of the search range.
	 * @param Range Number of bytes to search.
	 * @param Pattern IDA-style pattern, e.g. "48 8B ? ? 89".
	 * @param Step Address step; 0 uses the target's natural step.
	 * @param SkipCount Number of matches to skip before returning.
	 * @return Match address, or 0 if not found.
	 */
	virtual uintptr_t FindPatternInRange(
		uintptr_t Start,
		size_t Range,
		const std::string &Pattern,
		int Step = 0,
		uint32_t SkipCount = 0) const = 0;

	/**
	 * @brief Finds a byte-pattern match within a range.
	 *
	 * @param Signature IDA-style pattern, e.g. "48 8B ? ? 89".
	 * @param Start Start address of the search range.
	 * @param Range Number of bytes to search.
	 * @param Step Address step; 0 uses the target's natural step.
	 * @param MaxHits Maximum number of matches; 0 returns all matches.
	 * @return Match addresses in ascending order.
	 */
	virtual std::vector<uintptr_t> FindAllPatternInRange(
		uintptr_t Start,
		size_t Range,
		const std::string &Pattern,
		int Step = 0,
		size_t MaxHits = 0) const = 0;

	/**
	 * @brief Finds the first aligned occurrence of a pointer-sized value.
	 *
	 * @param Value Pointer-sized value to search for.
	 * @param Alignment Required address alignment.
	 * @param Start Start address of the search range.
	 * @param Range Number of bytes to search.
	 * @return Match address, or 0 if not found.
	 */
	virtual uintptr_t FindAlignedValueInRange(
		uintptr_t Value,
		int32_t Alignment,
		uintptr_t Start,
		size_t Range) const = 0;

	/**
	 * @brief Finds aligned occurrences of a pointer-sized value.
	 *
	 * @param Value Pointer-sized value to search for.
	 * @param Alignment Required address alignment.
	 * @param Start Start address of the search range.
	 * @param Range Number of bytes to search.
	 * @param MaxHits Maximum number of matches; 0 returns all matches.
	 * @return Match addresses in ascending order.
	 */
	virtual std::vector<uintptr_t> FindAllAlignedValuesInRange(
		uintptr_t Value,
		int32_t Alignment,
		uintptr_t Start,
		size_t Range,
		size_t MaxHits = 0) const = 0;

	/**
	 * @brief Finds the first occurrence of a raw byte sequence.
	 *
	 * @param Data Bytes to search for.
	 * @param DataSize Number of bytes in Data.
	 * @param Start Start address of the search range.
	 * @param Range Number of bytes to search.
	 * @return Match address, or 0 if not found.
	 */
	virtual uintptr_t FindRawDataInRange(
		const void *Data,
		size_t DataSize,
		uintptr_t Start,
		size_t Range) const = 0;

	/**
	 * @brief Finds occurrences of a raw byte sequence.
	 *
	 * @param Data Bytes to search for.
	 * @param DataSize Number of bytes in Data.
	 * @param Start Start address of the search range.
	 * @param Range Number of bytes to search.
	 * @param MaxHits Maximum number of matches; 0 returns all matches.
	 * @return Match addresses in ascending order.
	 */
	virtual std::vector<uintptr_t> FindAllRawDataInRange(
		const void *Data,
		size_t DataSize,
		uintptr_t Start,
		size_t Range,
		size_t MaxHits = 0) const = 0;

	/**
	 * @brief Finds a NUL-terminated string within a range.
	 *
	 * @tparam CharType Character type, typically char, char16_t, or char32_t.
	 * @param RefStr NUL-terminated string to search for.
	 * @param Start Start address of the search range.
	 * @param Range Number of bytes to search.
	 * @return Match address, or 0 if not found.
	 */
	template <typename CharType = char>
	uintptr_t FindByStringInRange(
		const CharType *RefStr,
		uintptr_t Start,
		uintptr_t Range) const
	{
		if (!RefStr)
			return 0;
		size_t StrSize = std::char_traits<CharType>::length(RefStr) * sizeof(CharType);
		return FindRawDataInRange(RefStr, StrSize, Start, Range);
	}

	/**
	 * @brief Iterates vtable function pointers until a match is found or the vtable ends.
	 *
	 * @param Vft Vtable address.
	 * @param Callback Called with each function address and index.
	 * @param NumFunctions Maximum number of entries to inspect.
	 * @param StartIndex First vtable index to inspect.
	 * @return Matching function address and index, or {0, -1} if none matched.
	 */
	virtual std::pair<uintptr_t, int32_t> IterateVTableFunctions(
		uintptr_t Vft,
		const std::function<bool(uintptr_t, int32_t)> &Callback,
		int32_t NumFunctions = 0x150,
		int32_t StartIndex = 0x0) const
	{
		if (!Vft)
			return {0, -1};
		for (int32_t i = StartIndex; i < NumFunctions; i++)
		{
			uintptr_t FuncAddr = Read<uintptr_t>(reinterpret_cast<uintptr_t>(Vft + (sizeof(uintptr_t) * i)));
			if (!FuncAddr || !IsAddressReadable(FuncAddr))
				break;
			if (Callback(FuncAddr, i))
				return {FuncAddr, i};
		}
		return {0, -1};
	}
};

/**
 * @brief Global active memory backend.
 */
inline std::unique_ptr<IMemory> GMemory;
