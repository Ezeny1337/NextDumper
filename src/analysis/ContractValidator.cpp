#include "nextdumper/analysis/ContractValidator.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "nextdumper/common/Hex.hpp"
#include "nextdumper/common/UeHardcodedNames.hpp"

namespace nextdumper::analysis
{
    namespace
    {
        constexpr size_t kMaxTextLength = 1024;
        constexpr size_t kMaxEntryBytes = 4096;
        constexpr uint64_t kMaxBlockBytes = 64ull * 1024 * 1024;
        constexpr size_t kMinKnownMatches = 8;
        constexpr size_t kBlock0Samples = 32;
        constexpr size_t kMaxBlockScan = 8192;
        constexpr size_t kMaxKnownWalk = 4096;

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
            size_t Narrow = 0;
            size_t Wide = 0;
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

        struct WalkedEntry
        {
            uintptr_t Address = 0;
            EntryRead Entry;
            uint64_t ConsumedBefore = 0;
        };

        struct SequenceMatch
        {
            NameTextCodec Decoder;
            size_t Matched = 0;
            size_t Plausible = 0;
            size_t Walked = 0;
            std::string NamesPreview;
            bool Strong = false;
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

        bool DecodesTo(const EntryRead &entry, const NameTextCodec &decoder,
                       std::string_view expected)
        {
            if (entry.Length == 0 || entry.Wide || entry.Length != expected.size())
                return false;
            std::vector<uint8_t> text = entry.Text;
            if (!decoder.Apply(text.data(), text.size(), entry.Length, entry.Wide))
                return false;
            return std::memcmp(text.data(), expected.data(), expected.size()) == 0;
        }

        std::optional<std::string> DecodePrintable(const EntryRead &entry, const NameTextCodec &decoder)
        {
            if (entry.Length == 0 || entry.Wide)
                return std::nullopt;
            std::vector<uint8_t> text = entry.Text;
            if (!decoder.Apply(text.data(), text.size(), entry.Length, entry.Wide))
                return std::nullopt;
            if (!std::all_of(text.begin(), text.end(), [](uint8_t value)
                             { return value >= 0x20 && value <= 0x7E; }))
                return std::nullopt;
            return std::string(text.begin(), text.end());
        }

        std::optional<SequenceMatch> MatchKnownNames(const std::vector<WalkedEntry> &entries,
                                                     std::vector<std::string> &anchor)
        {
            if (entries.empty())
                return std::nullopt;

            static const auto knownIndex = []
            {
                std::unordered_map<std::string_view, size_t> index;
                for (size_t entry = 0; entry < std::size(common::kUeHardcodedNames); ++entry)
                    index.emplace(common::kUeHardcodedNames[entry], entry);
                return index;
            }();

            std::vector<NameTextCodec> candidates;
            const auto addCandidate = [&](const NameTextCodec &decoder, std::string label)
            {
                if (!DecodesTo(entries.front().Entry, decoder, "None"))
                    return;
                candidates.push_back(decoder);
                anchor.push_back(std::move(label));
            };
            addCandidate(NameTextCodec{}, "identity");
            for (uint32_t key = 1; key <= 0xFFu; ++key)
            {
                const NameTextCodec decoder{NameTextFamily::ByteXor, static_cast<uint8_t>(key)};
                if (DecodesTo(entries.front().Entry, decoder, "None"))
                {
                    candidates.push_back(decoder);
                    anchor.push_back("byte-xor:" + std::to_string(key));
                }
            }
            addCandidate(NameTextCodec{NameTextFamily::LengthSchedule, 0}, "length-schedule");
            if (candidates.empty())
                return std::nullopt;

            const auto familyRank = [](NameTextFamily family)
            {
                switch (family)
                {
                case NameTextFamily::Identity:
                    return 0;
                case NameTextFamily::LengthSchedule:
                    return 1;
                case NameTextFamily::ByteXor:
                    return 2;
                }
                return 3;
            };

            std::optional<SequenceMatch> best;
            int bestRank = 1000;
            for (const NameTextCodec &decoder : candidates)
            {
                SequenceMatch match;
                match.Decoder = decoder;
                match.Walked = entries.size();
                std::vector<uint8_t> seen(knownIndex.size(), 0);
                for (const WalkedEntry &walked : entries)
                {
                    const EntryRead &entry = walked.Entry;
                    if (entry.Length == 0 || entry.Wide)
                        continue;
                    std::vector<uint8_t> text = entry.Text;
                    if (!decoder.Apply(text.data(), text.size(), entry.Length, entry.Wide))
                        continue;
                    if (!std::all_of(text.begin(), text.end(), [](uint8_t value)
                                     { return value >= 0x20 && value <= 0x7E; }))
                        continue;
                    ++match.Plausible;
                    const std::string_view name(reinterpret_cast<const char *>(text.data()), text.size());
                    const auto found = knownIndex.find(name);
                    if (found == knownIndex.end() || seen[found->second] != 0)
                        continue;
                    seen[found->second] = 1;
                    ++match.Matched;
                    if (match.NamesPreview.size() < 200)
                    {
                        if (!match.NamesPreview.empty())
                            match.NamesPreview += ",";
                        match.NamesPreview.append(name.data(), std::min<size_t>(name.size(), 24));
                    }
                }
                match.Strong = match.Matched >= kMinKnownMatches;
                const int rank = familyRank(decoder.Family);
                if (!best || match.Matched > best->Matched ||
                    (match.Matched == best->Matched && match.Plausible > best->Plausible) ||
                    (match.Matched == best->Matched && match.Plausible == best->Plausible && rank < bestRank))
                {
                    best = std::move(match);
                    bestRank = rank;
                }
            }
            return best;
        }

        std::string DescribePrefix(const std::vector<WalkedEntry> &entries,
                                   const NameTextCodec &decoder, size_t limit)
        {
            std::string result;
            const size_t count = std::min(limit, entries.size());
            for (size_t index = 0; index < count; ++index)
            {
                const WalkedEntry &walked = entries[index];
                const EntryRead &entry = walked.Entry;
                result += "@" + std::to_string(walked.ConsumedBefore) +
                          " h=" + common::Hex(entry.Header) +
                          " len=" + std::to_string(entry.Length) +
                          " wide=" + std::to_string(entry.Wide) +
                          " raw=" + HexBytes(entry.Text) + " text=";
                const auto text = DecodePrintable(entry, decoder);
                result += text ? *text : "?";
                result += " | ";
            }
            return result;
        }

        bool SampleBlock(const MemoryView &memory, const NamePoolFields &fields, uintptr_t block,
                         uint64_t byteLimit, size_t maxEntries, const NameTextCodec &decoder,
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
                if (!decoder.Apply(text.data(), text.size(), entry.Length, entry.Wide))
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
                if (entry.Wide)
                    ++out.Wide;
                else
                    ++out.Narrow;
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
                                                          const NameTextCodec &decoder)
        {
            const int32_t standardOffset = fields.BlocksOffset - 8;
            if (standardOffset < 0)
                return std::nullopt;
            const uint32_t stride = static_cast<uint32_t>(fields.EntryStride);
            std::vector<BoundaryCandidate> best;
            int bestScore = -1;
            const auto consider = [&](int32_t offset, uint32_t current, uint32_t cursor) -> bool
            {
                if (current >= maxBlocks || cursor == 0 || cursor > blockSize || cursor % stride != 0)
                    return false;
                // 只有单一分配块时当前块才会是 0，且发布字节数必须覆盖已读取前缀
                if (current == 0 && (reservedBytes > cursor || allocated > 1))
                    return false;
                if (allocated != 0 && current >= allocated)
                    return false;
                uintptr_t currentBlock = 0;
                if (!ReadBlockPointer(memory, blocksAddress, current, currentBlock))
                    return false;
                EntryRead entry;
                std::string failure;
                if (!ReadEntry(memory, fields, currentBlock, entry, failure))
                    return false;
                if (entry.Length != 0)
                {
                    std::vector<uint8_t> text = entry.Text;
                    if (!decoder.Apply(text.data(), text.size(), entry.Length, entry.Wide) || !PlausibleText(text, entry.Wide))
                        return false;
                }

                int score = entry.Length > 0 ? 3 : 2;
                if (offset == standardOffset)
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
                    best.push_back({offset, current, cursor, score, offset == standardOffset});
                return true;
            };
            const auto tryOffset = [&](int32_t offset) -> bool
            {
                const auto address = AddOffset(root, offset);
                std::array<uint32_t, 2> pair{};
                if (!address || !ReadExact(memory, *address, pair.data(), sizeof(pair)))
                    return false;
                return consider(offset, pair[0], pair[1]);
            };

            // 标准位置优先，保持 clean/profile 的快速路径
            if (tryOffset(standardOffset))
            {
                for (const BoundaryCandidate &candidate : best)
                {
                    if (candidate.Standard)
                        return candidate;
                }
            }

            // 商业构建可能把边界移到根对象前后；先扫根前 4KB，再扫 Blocks 数组及尾部
            for (int32_t offset = -0x1000; offset <= -4; offset += 4)
                tryOffset(offset);
            const int64_t windowEnd = std::min<int64_t>(
                static_cast<int64_t>(fields.BlocksOffset) +
                    static_cast<int64_t>(maxBlocks) * static_cast<int64_t>(sizeof(uintptr_t)) + 64,
                int64_t{1} << 20);
            for (int32_t offset = 0; static_cast<int64_t>(offset) <= windowEnd; offset += 4)
                tryOffset(offset);

            if (best.empty())
                return std::nullopt;
            for (const BoundaryCandidate &candidate : best)
            {
                if (candidate.Standard)
                    return candidate;
            }
            return best.size() == 1 ? std::optional<BoundaryCandidate>(best.front()) : std::nullopt;
        }

        void Fail(NameValidation &validation, std::string code, std::string detail = {})
        {
            validation.Failure = std::move(code);
            validation.FailureDetail = std::move(detail);
        }

        bool ValidatePoolAt(const MemoryView &memory, const NameStoreContract &contract, uintptr_t root,
                            const NameValidationOptions &options, NameValidation &validation)
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

            std::vector<WalkedEntry> walked;
            uintptr_t prefixAddress = block0;
            uintptr_t entryAddress = block0;
            uint64_t consumed = 0;
            for (size_t index = 0; index < kMaxKnownWalk && consumed < blockSize; ++index)
            {
                EntryRead entry;
                std::string failure;
                if (!ReadEntry(memory, fields, prefixAddress, entry, failure))
                    break;
                if (entry.Length == 0)
                    break;
                if (entry.Size == 0 || entry.Size > blockSize - consumed)
                    break;
                if (index == 0)
                    validation.FirstEntryHex = HexBytes(entry.Text);
                WalkedEntry item;
                item.Address = prefixAddress;
                item.Entry = std::move(entry);
                item.ConsumedBefore = consumed;
                const size_t size = item.Entry.Size;
                walked.push_back(std::move(item));
                consumed += size;
                prefixAddress += size;
            }
            if (walked.empty())
            {
                Fail(validation, "known-prefix-unreadable");
                return false;
            }

            std::vector<std::string> anchor;
            const std::optional<SequenceMatch> match = MatchKnownNames(walked, anchor);
            if (!match || !match->Strong)
            {
                std::string detail = "anchor=";
                if (anchor.empty())
                    detail += "(none)";
                for (size_t index = 0; index < anchor.size(); ++index)
                {
                    if (index != 0)
                        detail += ",";
                    detail += anchor[index];
                }
                if (match)
                {
                    detail += " family=" + std::string(NameTextFamilyName(match->Decoder.Family)) +
                              " matched=" + std::to_string(match->Matched) +
                              " plausible=" + std::to_string(match->Plausible) + "/" +
                              std::to_string(match->Walked) +
                              " names=" + match->NamesPreview;
                }
                detail += " prefix=" +
                          DescribePrefix(walked, match ? match->Decoder : NameTextCodec{}, 6);
                if (!match || match->Decoder.Family != NameTextFamily::LengthSchedule)
                    detail += " schedule_prefix=" +
                              DescribePrefix(walked, NameTextCodec{NameTextFamily::LengthSchedule, 0}, 6);
                Fail(validation, "known-names", std::move(detail));
                return false;
            }
            if (match->Walked != 0 && match->Plausible * 4 < match->Walked * 3)
            {
                Fail(validation, "known-plausible-ratio",
                     "plausible=" + std::to_string(match->Plausible) + "/" +
                         std::to_string(match->Walked) +
                         " names=" + match->NamesPreview);
                return false;
            }
            validation.Decoder = match->Decoder;
            validation.KnownMatched = match->Matched;
            validation.KnownPlausible = match->Plausible;
            validation.KnownWalked = match->Walked;
            validation.KnownNamesPreview = match->NamesPreview;
            const NameTextCodec &decoder = *validation.Decoder;
            entryAddress = prefixAddress;

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
                validation.BoundaryDetail = boundary->Standard ? "standard" : "extended";
                if (validation.CurrentBlock == 0 && validation.ByteCursor < consumed)
                {
                    Fail(validation, "publication-boundary-behind-reserved",
                         "cursor=" + std::to_string(validation.ByteCursor) +
                             " reserved_bytes=" + std::to_string(consumed));
                    return false;
                }

                const uint64_t block0Limit = validation.CurrentBlock == 0
                                                 ? validation.ByteCursor - consumed
                                                 : blockSize - consumed;
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
                    validation.NarrowSamples += samples.Narrow;
                    validation.WideSamples += samples.Wide;
                }
            }
            else
            {
                // 无发布边界时不读取额外块，避免把未初始化条目误判为布局失败
                validation.BoundaryDetail = "unavailable" + DumpWords(memory, root, fields.BlocksOffset);
                const auto dumpTail = [&](uint64_t slots, const char *label)
                {
                    const int64_t offset = static_cast<int64_t>(fields.BlocksOffset) +
                                           static_cast<int64_t>(slots) *
                                               static_cast<int64_t>(sizeof(uintptr_t));
                    const auto address = AddOffset(root, offset);
                    if (address)
                        validation.BoundaryDetail += std::string(" ") + label + "=" +
                                                     DumpWords(memory, *address, 64);
                };
                // UE 的 FNameMaxBlockBits 为 13，边界字段若在 Blocks 数组之后则位于 8192 个槽之后
                dumpTail(std::min<uint64_t>(maxBlocks, 8192), "tail8k");
                if (maxBlocks > 8192)
                    dumpTail(maxBlocks, "tailmax");
            }
            validation.Block0Samples = block0Samples.Tested;
            validation.Block0Valid = block0Samples.Valid;
            validation.NarrowSamples += block0Samples.Narrow;
            validation.WideSamples += block0Samples.Wide;

            if (validation.HighBlockSamples != validation.HighBlockValid ||
                validation.Block0Samples != validation.Block0Valid ||
                (validation.BoundaryReadable && validation.CurrentBlock != 0 &&
                 validation.HighBlockSamples == 0))
            {
                Fail(validation, "sample-consistency");
                return false;
            }
            validation.DecoderValidated = true;
            return true;
        }

        bool ReadArrayBytes(const MemoryView &memory, uintptr_t base, uint64_t offset, void *buffer, size_t size)
        {
            if (size == 0 || offset > std::min<uint64_t>(UINTPTR_MAX, INT64_MAX))
                return false;
            const auto address = AddOffset(base, static_cast<int64_t>(offset));
            return address && *address <= UINTPTR_MAX - (size - 1) && ReadExact(memory, *address, buffer, size);
        }

        bool ArrayChunkReadable(const MemoryView &memory, uintptr_t chunk, size_t stride)
        {
            return chunk != 0 && stride != 0 && chunk <= UINTPTR_MAX - (stride - 1) &&
                   memory.IsReadable(chunk, stride);
        }

        std::optional<WalkedEntry> ReadArrayEntry(const MemoryView &memory, const NameArrayFields &fields,
                                                  uintptr_t chunk, uint64_t chunkIndex, uint64_t withinChunk,
                                                  NameValidation &validation)
        {
            const uint64_t slotOffset = withinChunk * static_cast<uint64_t>(fields.SlotStride);
            uintptr_t address = 0;
            if (!ReadArrayBytes(memory, chunk, slotOffset, &address, sizeof(address)) || address == 0)
                return std::nullopt;

            uint32_t raw = 0;
            if (!ReadArrayBytes(memory, address, static_cast<uint64_t>(fields.EntryIndexOffset), &raw, sizeof(raw)))
                return std::nullopt;
            ++validation.ElementIndexTested;
            const uint64_t expected = (chunkIndex << fields.ChunkShift) + withinChunk;
            if ((raw >> 1) != expected)
                return std::nullopt;
            ++validation.ElementIndexMatched;

            WalkedEntry walked;
            walked.Address = address;
            walked.ConsumedBefore = slotOffset;
            EntryRead &entry = walked.Entry;
            entry.Wide = (raw & 1u) != 0;
            const size_t width = entry.Wide ? sizeof(uint16_t) : sizeof(uint8_t);
            const size_t stringOffset = static_cast<size_t>(fields.StringOffset);
            const size_t textCapacity = kMaxTextLength * width;
            std::array<uint8_t, kMaxTextLength * sizeof(uint16_t)> text{};
            // 按窗口读取文本并在本地找结尾零：逐字符读会放大远程读取次数，整块读会越过不可读页尾
            constexpr size_t kTextWindow = 64;
            size_t read = 0;
            size_t length = 0;
            bool terminated = false;
            while (!terminated && read < textCapacity)
            {
                const size_t want = std::min(kTextWindow, textCapacity - read);
                if (!ReadArrayBytes(memory, address, stringOffset + read, text.data() + read, want))
                    return std::nullopt;
                for (size_t position = read; position < read + want; position += width)
                {
                    if (text[position] == 0 && (!entry.Wide || text[position + 1] == 0))
                    {
                        length = position / width;
                        terminated = true;
                        break;
                    }
                }
                read += want;
            }
            if (!terminated)
                return std::nullopt;
            entry.Length = length;
            entry.Text.assign(text.data(), text.data() + length * width);
            entry.Size = stringOffset + length * width;
            return walked;
        }

        bool DecodeArraySample(const EntryRead &entry, const NameTextCodec &decoder, NameValidation &validation)
        {
            std::vector<uint8_t> text = entry.Text;
            if (!decoder.Apply(text.data(), text.size(), entry.Length, entry.Wide) || !PlausibleText(text, entry.Wide))
                return false;
            if (entry.Wide)
                ++validation.WideSamples;
            else
                ++validation.NarrowSamples;
            return true;
        }

        bool ValidateArrayAt(const MemoryView &memory, const NameArrayFields &fields, uintptr_t root,
                             const NameValidationOptions &options, NameValidation &validation)
        {
            validation.Root = root;
            const auto chunksAddress = AddOffset(root, fields.ChunksOffset);
            uintptr_t chunk0 = 0;
            if (fields.ChunksOffset < 0 || fields.ChunksOffset > 4096 || !chunksAddress ||
                !ReadArrayBytes(memory, *chunksAddress, 0, &chunk0, sizeof(chunk0)))
            {
                Fail(validation, "array-chunks-unreadable");
                return false;
            }
            if (fields.SlotStride <= 0 || !ArrayChunkReadable(memory, chunk0, static_cast<size_t>(fields.SlotStride)))
            {
                Fail(validation, "array-chunk0-unreadable");
                return false;
            }
            validation.BlocksAddress = *chunksAddress;
            validation.Block0 = chunk0;
            validation.RootUsable = true;

            if (fields.SlotStride < static_cast<int32_t>(sizeof(uintptr_t)) || fields.SlotStride > 64 ||
                fields.SlotStride % 4 != 0 || fields.ChunkShift < 8 || fields.ChunkShift > 24 ||
                fields.EntryIndexOffset < 0 || fields.EntryIndexOffset > 64 ||
                fields.StringOffset < fields.EntryIndexOffset + static_cast<int32_t>(sizeof(uint32_t)) ||
                fields.StringOffset > 128)
            {
                Fail(validation, "layout-fields-invalid");
                return false;
            }
            const size_t stride = static_cast<size_t>(fields.SlotStride);
            const uint64_t slotCount = uint64_t{1} << fields.ChunkShift;
            validation.BlockSize = static_cast<uint32_t>(std::min<uint64_t>(slotCount * stride, UINT32_MAX));
            validation.LayoutConsistent = true;

            std::vector<WalkedEntry> walked;
            const uint64_t knownLimit = std::min<uint64_t>({slotCount, kMaxKnownWalk, 2048});
            for (uint64_t slot = 0; slot < knownLimit; ++slot)
            {
                auto entry = ReadArrayEntry(memory, fields, chunk0, 0, slot, validation);
                if (!entry)
                    break;
                walked.push_back(std::move(*entry));
            }
            if (walked.empty())
            {
                Fail(validation, "array-entry0-unreadable");
                return false;
            }
            validation.FirstEntryHex = HexBytes(walked.front().Entry.Text);

            std::vector<std::string> anchor;
            const std::optional<SequenceMatch> match = MatchKnownNames(walked, anchor);
            if (!match || !match->Strong)
            {
                std::string detail = "anchor=";
                if (anchor.empty())
                    detail += "(none)";
                for (size_t index = 0; index < anchor.size(); ++index)
                {
                    if (index != 0)
                        detail += ",";
                    detail += anchor[index];
                }
                if (match)
                {
                    detail += " family=" + std::string(NameTextFamilyName(match->Decoder.Family)) +
                              " matched=" + std::to_string(match->Matched) +
                              " plausible=" + std::to_string(match->Plausible) + "/" +
                              std::to_string(match->Walked) +
                              " names=" + match->NamesPreview;
                }
                detail += " prefix=" +
                          DescribePrefix(walked, match ? match->Decoder : NameTextCodec{}, 6);
                if (!match || match->Decoder.Family != NameTextFamily::LengthSchedule)
                    detail += " schedule_prefix=" +
                              DescribePrefix(walked, NameTextCodec{NameTextFamily::LengthSchedule, 0}, 6);
                Fail(validation, "known-names", std::move(detail));
                return false;
            }
            if (match->Walked != 0 && match->Plausible * 4 < match->Walked * 3)
            {
                Fail(validation, "known-plausible-ratio",
                     "plausible=" + std::to_string(match->Plausible) + "/" +
                         std::to_string(match->Walked) +
                         " names=" + match->NamesPreview);
                return false;
            }
            validation.Decoder = match->Decoder;
            validation.KnownMatched = match->Matched;
            validation.KnownPlausible = match->Plausible;
            validation.KnownWalked = match->Walked;
            validation.KnownNamesPreview = match->NamesPreview;
            const NameTextCodec &decoder = *validation.Decoder;

            size_t remainingSamples = options.MaxSampledEntries;
            const size_t perChunk = std::min(static_cast<size_t>(slotCount), std::max<size_t>(1, options.SamplesPerBlock));
            // 首块样本沿用前缀数据，通过条件仍由已知名比例决定
            validation.Block0Samples = std::min({walked.size(), perChunk, remainingSamples});
            for (size_t slot = 0; slot < validation.Block0Samples; ++slot)
            {
                if (DecodeArraySample(walked[slot].Entry, decoder, validation))
                    ++validation.Block0Valid;
            }
            remainingSamples -= validation.Block0Samples;

            validation.AllocatedBlocks = 1;
            const uint64_t lastChunk = std::min<uint64_t>(options.MaxSampledBlocks, (UINT32_MAX >> 1) / slotCount);
            for (uint64_t chunkIndex = 1; chunkIndex <= lastChunk; ++chunkIndex)
            {
                uintptr_t chunk = 0;
                if (!ReadArrayBytes(memory, *chunksAddress, chunkIndex * sizeof(uintptr_t), &chunk, sizeof(chunk)) ||
                    !ArrayChunkReadable(memory, chunk, stride))
                    break;
                ++validation.AllocatedBlocks;
                const size_t sampleCount = std::min(perChunk, remainingSamples);
                for (size_t slot = 0; slot < sampleCount; ++slot)
                {
                    uintptr_t entryAddress = 0;
                    if (!ReadArrayBytes(memory, chunk, slot * stride, &entryAddress, sizeof(entryAddress)) ||
                        entryAddress == 0)
                    {
                        // 末尾块只填满一部分，空槽是合法状态而非布局失败
                        break;
                    }
                    ++validation.HighBlockSamples;
                    const auto entry = ReadArrayEntry(memory, fields, chunk, chunkIndex, slot, validation);
                    if (!entry || !DecodeArraySample(entry->Entry, decoder, validation))
                    {
                        Fail(validation, "sample-consistency",
                             "chunk=" + std::to_string(chunkIndex) + " site=" + common::Hex(chunk) +
                                 " slot=" + std::to_string(slot));
                        return false;
                    }
                    ++validation.HighBlockValid;
                }
                remainingSamples -= sampleCount;
            }
            validation.DecoderValidated = true;
            validation.LayoutDetail = "family=array chunks=" + std::to_string(validation.AllocatedBlocks) +
                                      " slots=" + std::to_string(slotCount) + " stride=" + std::to_string(stride);
            return true;
        }

        bool ValidateAt(const MemoryView &memory, const NameStoreContract &contract, uintptr_t root,
                        const NameValidationOptions &options, NameValidation &validation)
        {
            validation.Family = contract.Family;
            return contract.Family == NameStoreFamily::Pool
                       ? ValidatePoolAt(memory, contract, root, options, validation)
                       : ValidateArrayAt(memory, contract.NameArray, root, options, validation);
        }
    } // namespace

    NameValidation ValidateNameStore(const MemoryView &memory, const NameStoreContract &contract,
                                     size_t contractIndex, const NameValidationOptions &options)
    {
        NameValidation result;
        result.ContractIndex = contractIndex;
        result.Family = contract.Family;

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
        const int32_t tableOffset = contract.Family == NameStoreFamily::Pool ? contract.NamePool.BlocksOffset
                                                                             : contract.NameArray.ChunksOffset;
        if (tableOffset > 0)
        {
            for (size_t index = 0; index < directRoots; ++index)
            {
                const auto root = AddOffset(roots[index], -static_cast<int64_t>(tableOffset));
                if (root)
                    addRoot(*root);
            }
        }
        if (roots.empty())
        {
            Fail(result, "root-unresolved");
            return result;
        }

        int bestScore = -1;
        for (const uintptr_t root : roots)
        {
            NameValidation attempt;
            attempt.ContractIndex = contractIndex;
            if (ValidateAt(memory, contract, root, options, attempt))
            {
                attempt.AttemptedRoots = roots.size();
                return attempt;
            }
            const int score = (attempt.LayoutConsistent ? 8 : 0) + (attempt.BoundaryReadable ? 4 : 0) +
                              (attempt.RootUsable ? 2 : 0) + static_cast<int>(attempt.KnownMatched);
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
