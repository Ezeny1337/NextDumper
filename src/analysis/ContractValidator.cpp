#include "nextdumper/analysis/ContractValidator.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <string_view>
#include <utility>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::analysis
{
    namespace
    {
        constexpr size_t kMaxTextLength = 1024;
        constexpr size_t kMaxEntryBytes = 4096;
        constexpr uint64_t kMaxBlockBytes = 64ull * 1024 * 1024;
        constexpr size_t kMinReservedPairs = 8;
        constexpr size_t kBlock0Samples = 32;
        constexpr size_t kMaxBlockScan = 8192;

        constexpr std::array<std::string_view, 16> kReservedNames = {
            "None", "ByteProperty", "IntProperty", "BoolProperty",
            "FloatProperty", "ObjectProperty", "NameProperty", "DelegateProperty",
            "DoubleProperty", "ArrayProperty", "StructProperty", "VectorProperty",
            "RotatorProperty", "StrProperty", "TextProperty", "InterfaceProperty"};

        struct EntryRead
        {
            uint16_t Header = 0;
            size_t Length = 0;
            bool Wide = false;
            std::vector<uint8_t> Text;
            size_t Size = 0;
        };

        struct SampleOutcome
        {
            size_t Tested = 0;
            size_t Valid = 0;
            std::string Failure;
            std::string Detail;
            uintptr_t Site = 0;
        };

        struct BoundaryCandidate
        {
            int32_t Offset = -1;
            uint32_t CurrentBlock = 0;
            uint32_t ByteCursor = 0;
            int Score = 0;
            bool Standard = false;
        };

        std::optional<uintptr_t> AddOffset(uintptr_t base, int64_t offset)
        {
            if (offset >= 0)
            {
                const uintptr_t value = static_cast<uintptr_t>(offset);
                if (base > UINTPTR_MAX - value)
                    return std::nullopt;
                return base + value;
            }
            const uintptr_t value = static_cast<uintptr_t>(-(offset + 1)) + 1;
            if (base < value)
                return std::nullopt;
            return base - value;
        }

        bool ReadExact(const MemoryView &memory, uintptr_t address, void *buffer, size_t size)
        {
            return memory.ReadBytes(address, buffer, size).Ok();
        }

        std::string HexBytes(const std::vector<uint8_t> &bytes)
        {
            static constexpr char kDigits[] = "0123456789ABCDEF";
            const size_t count = std::min<size_t>(bytes.size(), 16);
            std::string result;
            result.reserve(count * 2 + 2);
            for (size_t index = 0; index < count; ++index)
            {
                result.push_back(kDigits[bytes[index] >> 4]);
                result.push_back(kDigits[bytes[index] & 0x0F]);
            }
            if (bytes.size() > count)
                result += "..";
            return result;
        }

        bool FieldsSane(const NamePoolFields &fields)
        {
            return fields.BlocksOffset >= 8 && fields.BlocksOffset <= 4096 &&
                   fields.BlocksBit >= 1 && fields.BlocksBit <= 24 &&
                   fields.EntryStride >= 1 && fields.EntryStride <= 64 &&
                   fields.HeaderOffset >= 0 && fields.HeaderOffset <= 64 &&
                   fields.StringOffset >= fields.HeaderOffset + 2 && fields.StringOffset <= 128 &&
                   fields.LengthShift >= 1 && fields.LengthShift <= 15 && fields.WideMask != 0;
        }

        bool ReadEntry(const MemoryView &memory, const NamePoolFields &fields, uintptr_t address,
                       EntryRead &out, std::string &failure)
        {
            out = {};
            const auto headerAddress = AddOffset(address, fields.HeaderOffset);
            if (!headerAddress)
            {
                failure = "entry-header-overflow";
                return false;
            }
            if (!ReadExact(memory, *headerAddress, &out.Header, sizeof(out.Header)))
            {
                failure = "entry-header-unreadable";
                return false;
            }
            out.Length = static_cast<size_t>(out.Header >> fields.LengthShift);
            out.Wide = (out.Header & fields.WideMask) != 0;
            if (out.Length > kMaxTextLength)
            {
                failure = "entry-length";
                return false;
            }
            if (out.Length == 0)
                return true;

            const size_t width = out.Wide ? sizeof(uint16_t) : sizeof(uint8_t);
            const size_t textBytes = out.Length * width;
            const auto textAddress = AddOffset(address, fields.StringOffset);
            if (!textAddress)
            {
                failure = "entry-text-overflow";
                return false;
            }
            out.Text.resize(textBytes);
            if (!ReadExact(memory, *textAddress, out.Text.data(), out.Text.size()))
            {
                failure = "entry-text-unreadable";
                return false;
            }
            const size_t rawSize = static_cast<size_t>(fields.StringOffset) + textBytes;
            if (rawSize > kMaxEntryBytes)
            {
                failure = "entry-extent";
                return false;
            }
            const size_t stride = static_cast<size_t>(fields.EntryStride);
            out.Size = (rawSize + stride - 1) / stride * stride;
            return true;
        }

        bool PlausibleText(const std::vector<uint8_t> &bytes, bool wide)
        {
            if (bytes.empty())
                return false;
            if (!wide)
            {
                return std::all_of(bytes.begin(), bytes.end(), [](uint8_t value)
                                   { return value >= 0x20 && value <= 0x7E; });
            }
            if (bytes.size() % sizeof(uint16_t) != 0)
                return false;
            for (size_t offset = 0; offset < bytes.size(); offset += sizeof(uint16_t))
            {
                uint16_t value = 0;
                std::memcpy(&value, bytes.data() + offset, sizeof(value));
                if (value < 0x20 || value == 0x7F || (value >= 0xD800 && value <= 0xDFFF))
                    return false;
            }
            return true;
        }

        bool SampleBlock(const MemoryView &memory, const NamePoolFields &fields, uintptr_t block,
                         uint64_t byteLimit, size_t maxEntries, const NameTextDecoder &decoder,
                         SampleOutcome &out)
        {
            if (block == 0 || maxEntries == 0)
                return true;
            uintptr_t address = block;
            uint64_t consumed = 0;
            for (size_t index = 0; index < maxEntries; ++index)
            {
                if (consumed >= byteLimit)
                    break;
                EntryRead entry;
                std::string failure;
                if (!ReadEntry(memory, fields, address, entry, failure))
                {
                    out.Failure = "sample-read:" + failure;
                    out.Site = address;
                    return false;
                }
                // UE5.6 的编号条目长度为零且具有独立的固定尺寸，当前采样在此停止而不是误判
                if (entry.Length == 0)
                    break;
                if (entry.Size == 0 || entry.Size > byteLimit - consumed)
                {
                    out.Failure = "sample-extent";
                    out.Site = address;
                    return false;
                }
                std::vector<uint8_t> text = entry.Text;
                if (!decoder.Apply(text, entry.Length, entry.Wide))
                {
                    out.Failure = "sample-decoder";
                    out.Detail = "length=" + std::to_string(entry.Length) +
                                 " wide=" + std::to_string(entry.Wide);
                    out.Site = address;
                    return false;
                }
                if (!PlausibleText(text, entry.Wide))
                {
                    out.Failure = "sample-text";
                    out.Detail = "raw=" + HexBytes(entry.Text) + " decoded=" + HexBytes(text);
                    out.Site = address;
                    return false;
                }
                ++out.Tested;
                ++out.Valid;
                consumed += entry.Size;
                address += entry.Size;
            }
            return true;
        }

        bool ReadBlockPointer(const MemoryView &memory, uintptr_t blocksAddress, uint64_t index,
                              uintptr_t &out)
        {
            const auto slot = AddOffset(blocksAddress, static_cast<int64_t>(index) * static_cast<int64_t>(sizeof(uintptr_t)));
            return slot && ReadExact(memory, *slot, &out, sizeof(out)) && out != 0 &&
                   memory.IsReadable(out, sizeof(uint16_t));
        }

        size_t ScanAllocatedBlocks(const MemoryView &memory, uintptr_t blocksAddress, uint64_t maxBlocks)
        {
            size_t count = 0;
            const uint64_t limit = std::min<uint64_t>(maxBlocks, kMaxBlockScan);
            for (uint64_t index = 0; index < limit; ++index)
            {
                uintptr_t block = 0;
                if (!ReadBlockPointer(memory, blocksAddress, index, block))
                    break;
                count = static_cast<size_t>(index) + 1;
            }
            return count;
        }

        std::string DumpWords(const MemoryView &memory, uintptr_t root, int32_t limit)
        {
            std::string result;
            for (int32_t offset = 0; offset + 8 <= limit; offset += 8)
            {
                uint64_t value = 0;
                const auto address = AddOffset(root, offset);
                result += " +" + std::to_string(offset) + "=";
                if (address && ReadExact(memory, *address, &value, sizeof(value)))
                    result += common::Hex(value);
                else
                    result += "unreadable";
            }
            return result;
        }

        std::optional<BoundaryCandidate> DiscoverBoundary(const MemoryView &memory, uintptr_t root,
                                                          uintptr_t blocksAddress,
                                                          const NamePoolFields &fields,
                                                          uint64_t blockSize, uint64_t maxBlocks,
                                                          uint64_t reservedBytes, size_t allocated,
                                                          const NameTextDecoder &decoder)
        {
            const int32_t lastOffset = fields.BlocksOffset - 8;
            if (lastOffset < 0)
                return std::nullopt;
            const uint32_t stride = static_cast<uint32_t>(fields.EntryStride);
            std::vector<BoundaryCandidate> best;
            int bestScore = -1;
            for (int32_t offset = 0; offset <= lastOffset; offset += 4)
            {
                const auto currentAddress = AddOffset(root, offset);
                const auto cursorAddress = AddOffset(root, offset + 4);
                uint32_t current = 0;
                uint32_t cursor = 0;
                if (!currentAddress || !cursorAddress ||
                    !ReadExact(memory, *currentAddress, &current, sizeof(current)) ||
                    !ReadExact(memory, *cursorAddress, &cursor, sizeof(cursor)))
                    continue;
                if (current >= maxBlocks || cursor == 0 || cursor > blockSize || cursor % stride != 0)
                    continue;
                // 只有单一分配块时当前块才会是 0，且发布字节数必须覆盖保留名
                if (current == 0 && (reservedBytes > cursor || allocated > 1))
                    continue;
                if (allocated != 0 && current >= allocated)
                    continue;
                uintptr_t currentBlock = 0;
                if (!ReadBlockPointer(memory, blocksAddress, current, currentBlock))
                    continue;
                EntryRead entry;
                std::string failure;
                if (!ReadEntry(memory, fields, currentBlock, entry, failure))
                    continue;
                if (entry.Length != 0)
                {
                    std::vector<uint8_t> text = entry.Text;
                    if (!decoder.Apply(text, entry.Length, entry.Wide) || !PlausibleText(text, entry.Wide))
                        continue;
                }

                int score = entry.Length > 0 ? 3 : 2;
                if (offset == lastOffset)
                    score += 2;
                if (current > 0)
                    score += 2;
                if (allocated != 0 && static_cast<size_t>(current) + 1 == allocated)
                    score += 2;
                if (score > bestScore)
                {
                    bestScore = score;
                    best.clear();
                }
                if (score == bestScore)
                    best.push_back({offset, current, cursor, score, offset == lastOffset});
            }

            if (best.empty())
                return std::nullopt;
            for (const BoundaryCandidate &candidate : best)
            {
                if (candidate.Standard)
                    return candidate;
            }
            return best.size() == 1 ? std::optional<BoundaryCandidate>(best.front()) : std::nullopt;
        }

        void Fail(NamePoolValidation &validation, std::string code, std::string detail = {})
        {
            validation.Failure = std::move(code);
            validation.FailureDetail = std::move(detail);
        }

        bool ValidateAt(const MemoryView &memory, const Contract &contract, uintptr_t root,
                        const NamePoolValidationOptions &options, NamePoolValidation &validation)
        {
            const NamePoolFields &fields = contract.NamePool;
            validation.Root = root;
            if (!FieldsSane(fields))
            {
                Fail(validation, "layout-fields-invalid");
                return false;
            }
            const auto blocksAddress = AddOffset(root, fields.BlocksOffset);
            if (!blocksAddress)
            {
                Fail(validation, "blocks-table-overflow");
                return false;
            }
            validation.BlocksAddress = *blocksAddress;
            uintptr_t block0 = 0;
            if (!ReadExact(memory, *blocksAddress, &block0, sizeof(block0)) || block0 == 0 ||
                !memory.IsReadable(block0, sizeof(uint16_t)))
            {
                Fail(validation, "block0-unreadable");
                return false;
            }
            validation.Block0 = block0;
            validation.RootUsable = true;

            const uint64_t blockSize = (uint64_t{1} << fields.BlocksBit) * static_cast<uint64_t>(fields.EntryStride);
            const uint64_t maxBlocks = uint64_t{1} << (32 - fields.BlocksBit);
            if (blockSize == 0 || blockSize > kMaxBlockBytes)
            {
                Fail(validation, "block-size-inconsistent", "block_size=" + std::to_string(blockSize));
                return false;
            }
            validation.BlockSize = static_cast<uint32_t>(blockSize);
            validation.LayoutConsistent = true;

            std::vector<KnownName> known;
            uintptr_t entryAddress = block0;
            uint64_t consumed = 0;
            for (size_t index = 0; index < kReservedNames.size(); ++index)
            {
                if (consumed >= blockSize)
                {
                    Fail(validation, "reserved-entry-unpublished", "index=" + std::to_string(index));
                    return false;
                }
                EntryRead entry;
                std::string failure;
                if (!ReadEntry(memory, fields, entryAddress, entry, failure))
                {
                    Fail(validation, "reserved-read", "index=" + std::to_string(index) + " " + failure);
                    return false;
                }
                if (index == 0)
                    validation.FirstEntryHex = HexBytes(entry.Text);
                validation.ReservedPairs = index + 1;
                const std::string_view expected = kReservedNames[index];
                if (entry.Length == 0 || entry.Wide || entry.Length != expected.size() ||
                    entry.Size == 0 || entry.Size > blockSize - consumed)
                {
                    Fail(validation, "reserved-shape",
                         "index=" + std::to_string(index) +
                             " expected=" + std::to_string(expected.size()) +
                             " length=" + std::to_string(entry.Length) +
                             " wide=" + std::to_string(entry.Wide) +
                             " header=" + common::Hex(entry.Header) +
                             " raw=" + HexBytes(entry.Text));
                    return false;
                }
                KnownName item;
                item.Cipher = entry.Text;
                item.Plain = std::string(expected);
                item.Length = entry.Length;
                item.Wide = entry.Wide;
                known.push_back(std::move(item));
                consumed += entry.Size;
                entryAddress += entry.Size;
            }
            validation.ReservedPairs = known.size();
            if (validation.ReservedPairs < kMinReservedPairs)
            {
                Fail(validation, "reserved-pairs-insufficient");
                return false;
            }

            const NameDecoderSynthesisResult synthesis = SynthesizeNameDecoder(known);
            if (!synthesis.IsValid())
            {
                Fail(validation, "decoder-synthesis", synthesis.Detail + " pairs=" + std::to_string(synthesis.Pairs));
                return false;
            }
            validation.Decoder = synthesis.Decoder;
            validation.ReservedMatched = synthesis.Pairs;
            const NameTextDecoder &decoder = *synthesis.Decoder;

            const size_t allocated = ScanAllocatedBlocks(memory, *blocksAddress, maxBlocks);
            if (allocated == 0)
            {
                Fail(validation, "blocks-table-empty");
                return false;
            }
            validation.AllocatedBlocks = static_cast<uint32_t>(allocated);
            const std::optional<BoundaryCandidate> boundary =
                DiscoverBoundary(memory, root, *blocksAddress, fields, blockSize, maxBlocks,
                                 consumed, allocated, decoder);

            SampleOutcome block0Samples;
            if (boundary)
            {
                validation.BoundaryReadable = true;
                validation.CurrentBlock = boundary->CurrentBlock;
                validation.ByteCursor = boundary->ByteCursor;
                validation.CurrentBlockOffset = boundary->Offset;
                validation.ByteCursorOffset = boundary->Offset + 4;
                validation.BoundaryDetail = boundary->Standard ? "standard" : "discovered";
                if (validation.CurrentBlock == 0 && validation.ByteCursor < consumed)
                {
                    Fail(validation, "publication-boundary-behind-reserved",
                         "cursor=" + std::to_string(validation.ByteCursor) +
                             " reserved_bytes=" + std::to_string(consumed));
                    return false;
                }

                const uint64_t block0Limit = validation.CurrentBlock == 0
                                                 ? validation.ByteCursor - consumed
                                                 : blockSize;
                if (!SampleBlock(memory, fields, entryAddress, block0Limit, kBlock0Samples, decoder, block0Samples))
                {
                    Fail(validation, block0Samples.Failure,
                         "block=0 site=" + common::Hex(block0Samples.Site) +
                             (block0Samples.Detail.empty() ? "" : " " + block0Samples.Detail));
                    return false;
                }

                std::vector<uint32_t> blocks;
                const size_t cap = std::max<size_t>(1, options.MaxSampledBlocks);
                if (validation.CurrentBlock <= cap)
                {
                    for (uint32_t block = 1; block <= validation.CurrentBlock; ++block)
                        blocks.push_back(block);
                }
                else
                {
                    for (size_t block = 1; block < cap; ++block)
                        blocks.push_back(static_cast<uint32_t>(block));
                    if (blocks.empty() || blocks.back() != validation.CurrentBlock)
                        blocks.push_back(validation.CurrentBlock);
                }
                for (const uint32_t block : blocks)
                {
                    uintptr_t blockPointer = 0;
                    if (!ReadBlockPointer(memory, *blocksAddress, block, blockPointer))
                    {
                        Fail(validation, "block-pointer-unreadable", "block=" + std::to_string(block));
                        return false;
                    }
                    const uint64_t limit = block == validation.CurrentBlock ? validation.ByteCursor : blockSize;
                    SampleOutcome samples;
                    if (!SampleBlock(memory, fields, blockPointer, limit,
                                     std::max<size_t>(1, options.SamplesPerBlock), decoder, samples))
                    {
                        Fail(validation, samples.Failure,
                             "block=" + std::to_string(block) + " site=" + common::Hex(samples.Site) +
                                 (samples.Detail.empty() ? "" : " " + samples.Detail));
                        return false;
                    }
                    validation.HighBlockSamples += samples.Tested;
                    validation.HighBlockValid += samples.Valid;
                }
            }
            else
            {
                // 无发布边界时不读取额外块，避免把未初始化条目误判为布局失败
                validation.BoundaryDetail = "unavailable" + DumpWords(memory, root, fields.BlocksOffset);
            }
            validation.Block0Samples = block0Samples.Tested;
            validation.Block0Valid = block0Samples.Valid;

            if (validation.HighBlockSamples != validation.HighBlockValid ||
                validation.Block0Samples != validation.Block0Valid ||
                (validation.BoundaryReadable && validation.CurrentBlock != 0 &&
                 validation.HighBlockSamples == 0) ||
                validation.ReservedMatched != validation.ReservedPairs)
            {
                Fail(validation, "sample-consistency");
                return false;
            }
            validation.DecoderValidated = true;
            return true;
        }
    } // namespace

    NamePoolValidation ValidateNamePool(const MemoryView &memory, const Contract &contract,
                                        size_t contractIndex, const NamePoolValidationOptions &options)
    {
        NamePoolValidation result;
        result.ContractIndex = contractIndex;
        if (contract.Kind != ContractKind::NamePool)
        {
            Fail(result, "contract-kind");
            return result;
        }

        std::vector<uintptr_t> roots;
        const auto addRoot = [&roots](uintptr_t value)
        {
            if (value != 0 && std::find(roots.begin(), roots.end(), value) == roots.end())
                roots.push_back(value);
        };
        addRoot(contract.Root);
        for (const uintptr_t hint : options.RootHints)
            addRoot(hint);
        const size_t directRoots = roots.size();
        for (size_t index = 0; index < directRoots; ++index)
        {
            if (contract.NamePool.BlocksOffset > 0 && roots[index] > static_cast<uintptr_t>(contract.NamePool.BlocksOffset))
                addRoot(roots[index] - static_cast<uintptr_t>(contract.NamePool.BlocksOffset));
        }
        if (roots.empty())
        {
            Fail(result, "root-unresolved");
            return result;
        }

        int bestScore = -1;
        for (const uintptr_t root : roots)
        {
            NamePoolValidation attempt;
            attempt.ContractIndex = contractIndex;
            if (ValidateAt(memory, contract, root, options, attempt))
            {
                attempt.AttemptedRoots = roots.size();
                return attempt;
            }
            const int score = (attempt.LayoutConsistent ? 8 : 0) + (attempt.BoundaryReadable ? 4 : 0) +
                              (attempt.RootUsable ? 2 : 0) + static_cast<int>(attempt.ReservedPairs);
            if (score > bestScore)
            {
                bestScore = score;
                result = std::move(attempt);
            }
        }
        result.AttemptedRoots = roots.size();
        if (result.Failure.empty())
            Fail(result, "validation-failed");
        return result;
    }
} // namespace nextdumper::analysis
