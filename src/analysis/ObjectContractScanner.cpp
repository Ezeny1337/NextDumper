#include "nextdumper/analysis/ObjectContractScanner.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::analysis
{
    namespace
    {
        constexpr int32_t kMaxNameBlocks = 8192;
        constexpr int32_t kReadChunkBytes = 64 * 1024;
        constexpr size_t kMaxNameCache = 4096;

        struct FieldLayout
        {
            int32_t maxElements;
            int32_t count;
            int32_t maxChunks;
            int32_t numChunks;
            const char *name;
        };

        constexpr std::array<FieldLayout, 3> kFieldLayouts = {{
            {16, 20, 24, 28, "stock"},
            {24, 28, 32, 36, "plus8"},
            {32, 36, 40, 44, "plus16"},
        }};

        struct FieldValues
        {
            int32_t maxElements = 0;
            int32_t count = 0;
            int32_t maxChunks = 0;
            int32_t numChunks = 0;
        };

        enum class ObjectStage : uint8_t
        {
            Valid,
            ItemUnreadable,
            ObjectEmpty,
            ObjectShape,
            IndexUnreadable,
            IndexMismatch,
            IndexOutOfRange,
            Name,
            CoverageGap,
            InsufficientCore,
        };

        const char *StageName(ObjectStage stage)
        {
            switch (stage)
            {
            case ObjectStage::Valid:
                return "valid";
            case ObjectStage::ItemUnreadable:
                return "item-unreadable";
            case ObjectStage::ObjectEmpty:
                return "object-empty";
            case ObjectStage::ObjectShape:
                return "object-shape";
            case ObjectStage::IndexUnreadable:
                return "index-unreadable";
            case ObjectStage::IndexMismatch:
                return "index-mismatch";
            case ObjectStage::IndexOutOfRange:
                return "index-out-of-range";
            case ObjectStage::Name:
                return "name";
            case ObjectStage::CoverageGap:
                return "coverage-gap";
            case ObjectStage::InsufficientCore:
                return "insufficient-core";
            }
            return "unknown";
        }

        struct ObjectEvaluation
        {
            bool shaped = false;
            bool indexReadable = false;
            bool indexExact = false;
            bool indexInRange = false;
            bool nameDecoded = false;
            bool classHit = false;
            bool outerHit = false;
            int32_t reportedIndex = 0;
            std::string name;
            ObjectStage stage = ObjectStage::Valid;
        };

        struct ShapeResult
        {
            bool fixed = false;
            int32_t stride = 0;
            int32_t indexOffset = 0;
            uint32_t tested = 0;
            uint32_t empty = 0;
            uint32_t shaped = 0;
            uint32_t coreValid = 0;
            uint32_t nameDecoded = 0;
            uint32_t indexInRange = 0;
            uint32_t classHits = 0;
            uint32_t outerHits = 0;
            uint32_t fullValid = 0;
            int32_t maxValidIndex = -1;
            double confidence = 0.0;
            ObjectStage failureStage = ObjectStage::Valid;
            int32_t failureIndex = -1;
            int32_t failureReported = -1;
            uintptr_t failureObject = 0;
            uintptr_t failureItem = 0;
            std::string sampleNames;
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

        bool ReadPointerValue(const MemoryView &memory, uintptr_t address, uintptr_t &value)
        {
            return ReadExact(memory, address, &value, sizeof(value));
        }

        bool ReadInt32Value(const MemoryView &memory, uintptr_t address, int32_t &value)
        {
            return ReadExact(memory, address, &value, sizeof(value));
        }

        bool ReadFieldValues(const MemoryView &memory, uintptr_t header, const FieldLayout &field,
                             FieldValues &values)
        {
            const auto maxAddress = AddOffset(header, field.maxElements);
            const auto countAddress = AddOffset(header, field.count);
            const auto maxChunksAddress = AddOffset(header, field.maxChunks);
            const auto numChunksAddress = AddOffset(header, field.numChunks);
            int32_t maxElements = 0;
            int32_t count = 0;
            int32_t maxChunks = 0;
            int32_t numChunks = 0;
            if (!maxAddress || !countAddress || !maxChunksAddress || !numChunksAddress ||
                !ReadInt32Value(memory, *maxAddress, maxElements) ||
                !ReadInt32Value(memory, *countAddress, count) ||
                !ReadInt32Value(memory, *maxChunksAddress, maxChunks) ||
                !ReadInt32Value(memory, *numChunksAddress, numChunks))
                return false;
            values.maxElements = maxElements;
            values.count = count;
            values.maxChunks = maxChunks;
            values.numChunks = numChunks;
            return true;
        }

        bool ModePossible(const FieldValues &values, const ObjectContractScanOptions &options,
                          bool &fixedPossible, bool &chunkedPossible)
        {
            fixedPossible = false;
            chunkedPossible = false;
            if (values.count < static_cast<int32_t>(options.MinCount) || values.count > 0x08000000 ||
                values.maxElements < values.count || values.maxElements > 0x08000000)
                return false;
            fixedPossible = values.maxChunks >= 0 && values.maxChunks <= 1 &&
                            values.numChunks >= 0 && values.numChunks <= 1;
            chunkedPossible = values.maxChunks > 0 && values.maxChunks <= 0x1000 &&
                              values.numChunks > 0 && values.numChunks <= values.maxChunks;
            return fixedPossible || chunkedPossible;
        }

        bool HasPlausibleHeaderCount(const MemoryView &memory, uintptr_t header,
                                     const ObjectContractScanOptions &options)
        {
            for (const FieldLayout &field : kFieldLayouts)
            {
                const auto countAddress = AddOffset(header, field.count);
                int32_t count = 0;
                if (countAddress && ReadInt32Value(memory, *countAddress, count) &&
                    count >= static_cast<int32_t>(options.MinCount) && count <= 0x08000000)
                    return true;
            }
            return false;
        }

        bool PlausibleObjectHeader(const MemoryView &memory, uintptr_t header,
                                   const ObjectContractScanOptions &options)
        {
            if (!HasPlausibleHeaderCount(memory, header, options))
                return false;
            for (const FieldLayout &field : kFieldLayouts)
            {
                FieldValues values;
                if (!ReadFieldValues(memory, header, field, values))
                    continue;
                bool fixedPossible = false;
                bool chunkedPossible = false;
                if (ModePossible(values, options, fixedPossible, chunkedPossible))
                    return true;
            }
            return false;
        }

        bool IsPrintable(const std::vector<uint8_t> &bytes)
        {
            if (bytes.empty())
                return false;
            return std::all_of(bytes.begin(), bytes.end(), [](uint8_t value)
                               { return value >= 0x20 && value <= 0x7E; });
        }

        bool IsLikelyObject(const MemoryView &memory, uintptr_t object)
        {
            if (object == 0 || !memory.IsReadable(object, sizeof(uintptr_t)))
                return false;
            uintptr_t vtable = 0;
            uintptr_t function = 0;
            return ReadPointerValue(memory, object, vtable) && vtable != 0 &&
                   memory.IsReadable(vtable, sizeof(uintptr_t)) &&
                   ReadPointerValue(memory, vtable, function) && function != 0 &&
                   memory.IsExecutable(function, sizeof(uintptr_t));
        }

        class NameResolver
        {
        public:
            NameResolver(const MemoryView &memory, uintptr_t root, const NamePoolFields &fields,
                         const NameTextDecoder &decoder)
                : memory_(memory), root_(root), fields_(fields), decoder_(decoder)
            {
            }

            bool Resolve(int32_t index, std::string &out)
            {
                if (index < 0 || !fields_.Complete())
                    return false;
                const auto cached = cache_.find(index);
                if (cached != cache_.end())
                {
                    out = cached->second;
                    return true;
                }

                const uint32_t unstable = static_cast<uint32_t>(index);
                const int32_t blockIndex = static_cast<int32_t>(unstable >> fields_.BlocksBit);
                if (blockIndex < 0 || blockIndex >= kMaxNameBlocks)
                    return false;
                const uint32_t within = unstable & ((1u << fields_.BlocksBit) - 1u);
                const auto blocksAddress = AddOffset(root_, fields_.BlocksOffset);
                const auto blockSlot = blocksAddress
                                           ? AddOffset(*blocksAddress, static_cast<int64_t>(blockIndex) * static_cast<int64_t>(sizeof(uintptr_t)))
                                           : std::nullopt;
                uintptr_t block = 0;
                if (!blockSlot || !ReadPointerValue(memory_, *blockSlot, block) || block == 0 ||
                    !memory_.IsReadable(block, sizeof(uint16_t)))
                    return false;
                const auto entry = AddOffset(block, static_cast<int64_t>(within) * fields_.EntryStride);
                const auto headerAddress = entry ? AddOffset(*entry, fields_.HeaderOffset) : std::nullopt;
                uint16_t header = 0;
                if (!headerAddress || !ReadExact(memory_, *headerAddress, &header, sizeof(header)))
                    return false;
                const int32_t length = static_cast<int32_t>(header >> fields_.LengthShift);
                const bool wide = (header & fields_.WideMask) != 0;
                if (length <= 0 || length > 1024 || wide)
                    return false;
                std::vector<uint8_t> text(static_cast<size_t>(length));
                const auto textAddress = entry ? AddOffset(*entry, fields_.StringOffset) : std::nullopt;
                if (!textAddress || !ReadExact(memory_, *textAddress, text.data(), text.size()) ||
                    !decoder_.Apply(text, static_cast<size_t>(length), false) || !IsPrintable(text))
                    return false;
                out.assign(reinterpret_cast<const char *>(text.data()), text.size());
                if (cache_.size() < kMaxNameCache)
                    cache_.emplace(index, out);
                return true;
            }

        private:
            const MemoryView &memory_;
            uintptr_t root_ = 0;
            NamePoolFields fields_;
            NameTextDecoder decoder_;
            std::unordered_map<int32_t, std::string> cache_;
        };

        bool ReadObjectName(const MemoryView &memory, NameResolver &names, uintptr_t object, std::string &out)
        {
            const auto comparisonAddress = AddOffset(object, 24);
            const auto displayAddress = AddOffset(object, 28);
            int32_t comparison = 0;
            int32_t display = 0;
            if (!comparisonAddress || !displayAddress ||
                !ReadInt32Value(memory, *comparisonAddress, comparison) ||
                !ReadInt32Value(memory, *displayAddress, display))
                return false;
            if (names.Resolve(comparison, out))
                return true;
            return display != comparison && names.Resolve(display, out);
        }

        bool ResolveClassName(const MemoryView &memory, NameResolver &names, uintptr_t object,
                              std::string &className)
        {
            for (const int32_t classOffset : {16, 40, 48})
            {
                const auto classAddress = AddOffset(object, classOffset);
                uintptr_t classPointer = 0;
                std::string candidate;
                if (classAddress && ReadPointerValue(memory, *classAddress, classPointer) &&
                    IsLikelyObject(memory, classPointer) &&
                    ReadObjectName(memory, names, classPointer, candidate))
                {
                    className = std::move(candidate);
                    return true;
                }
            }
            return false;
        }

        bool ResolveOuter(const MemoryView &memory, uintptr_t object)
        {
            for (const int32_t outerOffset : {32, 36, 48})
            {
                const auto outerAddress = AddOffset(object, outerOffset);
                uintptr_t outer = 0;
                if (!outerAddress || !ReadPointerValue(memory, *outerAddress, outer))
                    continue;
                if (outer == 0 || IsLikelyObject(memory, outer))
                    return true;
            }
            return false;
        }

        void EvaluateObject(const MemoryView &memory, NameResolver &names, uintptr_t object,
                            int32_t index, int32_t indexOffset, int32_t count, ObjectEvaluation &out)
        {
            out = {};
            if (object == 0)
            {
                out.stage = ObjectStage::ObjectEmpty;
                return;
            }
            if (!IsLikelyObject(memory, object))
            {
                out.stage = ObjectStage::ObjectShape;
                return;
            }
            out.shaped = true;

            int32_t reported = 0;
            const auto indexAddress = AddOffset(object, indexOffset);
            if (indexAddress && ReadInt32Value(memory, *indexAddress, reported))
            {
                out.indexReadable = true;
                out.reportedIndex = reported;
                out.indexExact = reported == index;
                out.indexInRange = reported >= 0 && reported < count;
            }

            if (ReadObjectName(memory, names, object, out.name))
            {
                out.nameDecoded = true;
                std::string className;
                out.classHit = ResolveClassName(memory, names, object, className);
                out.outerHit = ResolveOuter(memory, object);
            }

            if (!out.indexReadable)
            {
                out.stage = ObjectStage::IndexUnreadable;
                return;
            }
            if (!out.indexExact)
            {
                out.stage = out.indexInRange ? ObjectStage::IndexMismatch : ObjectStage::IndexOutOfRange;
                return;
            }
            if (!out.nameDecoded)
            {
                out.stage = ObjectStage::Name;
                return;
            }
            out.stage = ObjectStage::Valid;
        }

        std::string ShortName(const std::string &value)
        {
            constexpr size_t kMaxName = 48;
            if (value.size() <= kMaxName)
                return value;
            return value.substr(0, kMaxName) + "...";
        }

        std::string ObjectSnapshot(const MemoryView &memory, NameResolver &names, uintptr_t object)
        {
            if (object == 0)
                return "object=empty";
            if (!memory.IsReadable(object, sizeof(uintptr_t)))
                return "object=" + common::Hex(object) + " unreadable";

            std::string result = "object=" + common::Hex(object);
            const auto readInt = [&](int32_t offset, int32_t &value)
            {
                const auto address = AddOffset(object, offset);
                return address && ReadInt32Value(memory, *address, value);
            };
            int32_t index12 = 0;
            int32_t index36 = 0;
            const bool has12 = readInt(12, index12);
            const bool has36 = readInt(36, index36);
            result += " idx12=" + (has12 ? std::to_string(index12) : std::string("unreadable"));
            result += " idx36=" + (has36 ? std::to_string(index36) : std::string("unreadable"));

            int32_t name24 = 0;
            int32_t name28 = 0;
            const bool has24 = readInt(24, name24);
            const bool has28 = readInt(28, name28);
            std::string text24;
            std::string text28;
            const bool text24Valid = has24 && names.Resolve(name24, text24);
            const bool text28Valid = has28 && names.Resolve(name28, text28);
            result += " name24=" + std::string(text24Valid ? ShortName(text24) : "-");
            result += " name28=" + std::string(text28Valid ? ShortName(text28) : "-");

            const auto describeClass = [&](int32_t offset)
            {
                const auto address = AddOffset(object, offset);
                uintptr_t classPointer = 0;
                if (!address || !ReadPointerValue(memory, *address, classPointer) || classPointer == 0)
                    return std::string("-");
                if (!IsLikelyObject(memory, classPointer))
                    return common::Hex(classPointer) + ":shape";
                std::string className;
                if (ReadObjectName(memory, names, classPointer, className))
                    return common::Hex(classPointer) + ":" + ShortName(className);
                return common::Hex(classPointer) + ":name";
            };
            result += " class16=" + describeClass(16);
            result += " class40=" + describeClass(40);
            result += " class48=" + describeClass(48);

            const auto describeOuter = [&](int32_t offset)
            {
                const auto address = AddOffset(object, offset);
                uintptr_t outer = 0;
                if (!address || !ReadPointerValue(memory, *address, outer))
                    return std::string("unreadable");
                if (outer == 0)
                    return std::string("null");
                if (IsLikelyObject(memory, outer))
                    return common::Hex(outer) + ":object";
                return common::Hex(outer) + ":invalid";
            };
            result += " outer32=" + describeOuter(32);
            result += " outer36=" + describeOuter(36);
            result += " outer48=" + describeOuter(48);
            return result;
        }

        bool IsInReadableRanges(const std::vector<std::pair<uintptr_t, uintptr_t>> &ranges,
                                uintptr_t address, size_t size)
        {
            if (ranges.empty())
                return true;
            const auto bound = std::lower_bound(ranges.begin(), ranges.end(), address,
                                                [](const auto &range, uintptr_t value)
                                                { return range.first < value; });
            auto it = bound;
            if (it != ranges.begin())
            {
                const auto previous = std::prev(it);
                if (address >= previous->first && address < previous->second)
                    it = previous;
            }
            if (it == ranges.end() || address < it->first || address >= it->second)
                return false;
            if (size > it->second - address)
            {
                const auto next = std::next(it);
                return next != ranges.end() && next->first <= address + size && address + size <= next->second;
            }
            return true;
        }

        uint64_t ShapeScore(const ShapeResult &shape)
        {
            return static_cast<uint64_t>(shape.coreValid) * 1000000ull +
                   static_cast<uint64_t>(shape.nameDecoded) * 10000ull +
                   static_cast<uint64_t>(shape.shaped) * 1000ull +
                   static_cast<uint64_t>(shape.indexInRange) * 100ull +
                   shape.fullValid;
        }

        std::string BuildShapeSamples(const std::vector<std::string> &samples)
        {
            std::string result;
            const size_t count = std::min<size_t>(samples.size(), 4);
            for (size_t index = 0; index < count; ++index)
            {
                if (index != 0)
                    result += ",";
                result += ShortName(samples[index]);
            }
            return result;
        }

        uint64_t EvidenceScore(const ObjectCandidateEvidence &evidence)
        {
            uint64_t score = static_cast<uint64_t>(evidence.CoreValid) * 10000000ull +
                             static_cast<uint64_t>(evidence.NameDecoded) * 100000ull +
                             static_cast<uint64_t>(evidence.Shaped) * 10000ull +
                             static_cast<uint64_t>(evidence.FullValid) * 1000ull +
                             static_cast<uint64_t>(evidence.IndexInRange) * 100ull;
            const bool countPlausible = evidence.Count >= 1024 && evidence.Count <= 1000000 &&
                                        evidence.MaxElements >= evidence.Count &&
                                        (evidence.MaxElements - evidence.Count) <=
                                            std::max<int32_t>(64, evidence.Count / 8);
            if (countPlausible)
                score += 2000000ull;
            if (evidence.NumChunks == 1)
                score += 500000ull;
            return score;
        }

        ObjectCandidateEvidence BuildEvidence(uintptr_t root, uintptr_t storage,
                                              const FieldLayout &field, bool fixed, int32_t perChunk,
                                              const FieldValues &values, const ShapeResult &shape,
                                              const MemoryView &memory)
        {
            ObjectCandidateEvidence evidence;
            evidence.Root = root;
            evidence.Storage = storage;
            evidence.MaxElements = values.maxElements;
            evidence.Count = values.count;
            evidence.MaxChunks = values.maxChunks;
            evidence.NumChunks = values.numChunks;
            evidence.ElementsPerChunk = perChunk;
            evidence.ItemStride = shape.stride;
            evidence.ItemIndexOffset = shape.indexOffset;
            evidence.Fixed = fixed;
            evidence.Tested = shape.tested;
            evidence.Empty = shape.empty;
            evidence.Shaped = shape.shaped;
            evidence.CoreValid = shape.coreValid;
            evidence.NameDecoded = shape.nameDecoded;
            evidence.IndexInRange = shape.indexInRange;
            evidence.ClassHits = shape.classHits;
            evidence.OuterHits = shape.outerHits;
            evidence.FullValid = shape.fullValid;
            evidence.MaxValidIndex = shape.maxValidIndex;
            evidence.FailureIndex = shape.failureIndex;
            evidence.FailureObject = shape.failureObject;
            evidence.FailureItem = shape.failureItem;
            evidence.Field = field.name;
            evidence.Stage = StageName(shape.failureStage);
            evidence.SampleNames = shape.sampleNames;

            uintptr_t firstItem = 0;
            uintptr_t firstObject = 0;
            if (fixed)
            {
                firstItem = storage;
                ReadPointerValue(memory, firstItem, firstObject);
            }
            else
            {
                ReadPointerValue(memory, storage, firstItem);
                if (firstItem != 0)
                    ReadPointerValue(memory, firstItem, firstObject);
            }
            evidence.FirstObject = firstObject;

            if (shape.failureIndex >= 0)
                evidence.Detail = "index=" + std::to_string(shape.failureIndex);
            if (shape.failureReported >= 0)
            {
                if (!evidence.Detail.empty())
                    evidence.Detail += " ";
                evidence.Detail += "reported=" + std::to_string(shape.failureReported);
            }
            if (shape.failureItem != 0)
            {
                if (!evidence.Detail.empty())
                    evidence.Detail += " ";
                evidence.Detail += "item=" + common::Hex(shape.failureItem);
            }
            return evidence;
        }

        std::string CompactEvidence(const ObjectCandidateEvidence &evidence)
        {
            std::string result = "root=" + common::Hex(evidence.Root) +
                                 " count=" + std::to_string(evidence.Count) +
                                 " max=" + std::to_string(evidence.MaxElements) +
                                 " max_chunks=" + std::to_string(evidence.MaxChunks) +
                                 " num_chunks=" + std::to_string(evidence.NumChunks) +
                                 " field=" + evidence.Field +
                                 " mode=" + (evidence.Fixed ? "fixed" : "chunked") +
                                 " per_chunk=" + std::to_string(evidence.ElementsPerChunk) +
                                 " storage=" + common::Hex(evidence.Storage) +
                                 " first_object=" + common::Hex(evidence.FirstObject) +
                                 " stage=" + evidence.Stage +
                                 " core=" + std::to_string(evidence.CoreValid) + "/" +
                                 std::to_string(evidence.Tested - evidence.Empty) +
                                 " shaped=" + std::to_string(evidence.Shaped) +
                                 " names=" + std::to_string(evidence.NameDecoded) +
                                 " in_range=" + std::to_string(evidence.IndexInRange) +
                                 " class_hits=" + std::to_string(evidence.ClassHits) +
                                 " outer_hits=" + std::to_string(evidence.OuterHits) +
                                 " full=" + std::to_string(evidence.FullValid) +
                                 " max_valid_index=" + std::to_string(evidence.MaxValidIndex);
            if (!evidence.Detail.empty())
                result += " detail=" + evidence.Detail;
            if (!evidence.SampleNames.empty())
                result += " samples=" + evidence.SampleNames;
            return result;
        }

        std::optional<Contract> TryCandidate(const MemoryView &memory, NameResolver &names,
                                             uintptr_t pointerAddress, uintptr_t chunkTable,
                                             const ObjectContractScanOptions &options,
                                             std::optional<ObjectCandidateEvidence> &rejected,
                                             std::optional<ObjectCandidateEvidence> &accepted)
        {
            std::optional<ObjectCandidateEvidence> bestRejected;
            for (const FieldLayout &field : kFieldLayouts)
            {
                FieldValues values;
                if (!ReadFieldValues(memory, pointerAddress, field, values))
                    continue;
                bool fixedPossible = false;
                bool chunkedPossible = false;
                if (!ModePossible(values, options, fixedPossible, chunkedPossible))
                    continue;

                struct Mode
                {
                    bool fixed = false;
                    int32_t perChunk = 0;
                };
                std::vector<Mode> modes;
                if (fixedPossible)
                    modes.push_back({true, 0});
                if (chunkedPossible)
                {
                    std::vector<int32_t> elementsPerChunk = {64 * 1024};
                    if (values.maxChunks != 0 && values.maxElements % values.maxChunks == 0)
                    {
                        const int32_t derived = values.maxElements / values.maxChunks;
                        if (derived != elementsPerChunk.front() && derived >= 0x1000 && derived <= 0x200000)
                            elementsPerChunk.push_back(derived);
                    }
                    for (const int32_t perChunk : elementsPerChunk)
                    {
                        if (perChunk <= 0 || values.maxElements % perChunk != 0 ||
                            values.maxElements / perChunk != values.maxChunks ||
                            static_cast<int64_t>(values.numChunks) * perChunk < values.count)
                            continue;
                        modes.push_back({false, perChunk});
                    }
                }

                for (const Mode &mode : modes)
                {
                    std::vector<ShapeResult> shapes;
                    std::optional<ShapeResult> bestFailed;
                    for (const int32_t stride : {24, 16, 8, 32})
                    {
                        for (const int32_t indexOffset : {12, 36})
                        {
                            ShapeResult shape;
                            shape.fixed = mode.fixed;
                            shape.stride = stride;
                            shape.indexOffset = indexOffset;
                            std::vector<std::string> namesSample;
                            const auto recordFailure = [&](ObjectStage stage, int32_t index,
                                                           uintptr_t object, uintptr_t item,
                                                           int32_t reported)
                            {
                                if (shape.failureStage != ObjectStage::Valid)
                                    return;
                                shape.failureStage = stage;
                                shape.failureIndex = index;
                                shape.failureObject = object;
                                shape.failureItem = item;
                                shape.failureReported = reported;
                            };
                            const auto validateIndex = [&](int32_t index)
                            {
                                if (index < 0 || index >= values.count)
                                    return;
                                ++shape.tested;
                                uintptr_t itemAddress = 0;
                                if (mode.fixed)
                                {
                                    const auto address = AddOffset(chunkTable, static_cast<int64_t>(index) * stride);
                                    if (!address)
                                    {
                                        recordFailure(ObjectStage::ItemUnreadable, index, 0, 0, -1);
                                        return;
                                    }
                                    itemAddress = *address;
                                }
                                else
                                {
                                    const int32_t chunkIndex = index / mode.perChunk;
                                    const int32_t within = index % mode.perChunk;
                                    if (chunkIndex >= values.numChunks)
                                    {
                                        recordFailure(ObjectStage::ItemUnreadable, index, 0, 0, -1);
                                        return;
                                    }
                                    const auto chunkSlot = AddOffset(chunkTable, static_cast<int64_t>(chunkIndex) * static_cast<int64_t>(sizeof(uintptr_t)));
                                    uintptr_t chunk = 0;
                                    if (!chunkSlot || !ReadPointerValue(memory, *chunkSlot, chunk) || chunk == 0 ||
                                        !memory.IsReadable(chunk, sizeof(uintptr_t)))
                                    {
                                        recordFailure(ObjectStage::ItemUnreadable, index, 0, 0, -1);
                                        return;
                                    }
                                    const auto address = AddOffset(chunk, static_cast<int64_t>(within) * stride);
                                    if (!address)
                                    {
                                        recordFailure(ObjectStage::ItemUnreadable, index, 0, 0, -1);
                                        return;
                                    }
                                    itemAddress = *address;
                                }
                                uintptr_t object = 0;
                                if (!ReadPointerValue(memory, itemAddress, object))
                                {
                                    recordFailure(ObjectStage::ItemUnreadable, index, 0, itemAddress, -1);
                                    return;
                                }
                                if (object == 0)
                                {
                                    ++shape.empty;
                                    return;
                                }

                                ObjectEvaluation evaluation;
                                EvaluateObject(memory, names, object, index, indexOffset, values.count, evaluation);
                                if (evaluation.shaped)
                                    ++shape.shaped;
                                if (evaluation.nameDecoded)
                                    ++shape.nameDecoded;
                                if (evaluation.indexInRange && !evaluation.indexExact)
                                    ++shape.indexInRange;
                                if (evaluation.classHit)
                                    ++shape.classHits;
                                if (evaluation.outerHit)
                                    ++shape.outerHits;
                                if (evaluation.indexExact && evaluation.nameDecoded)
                                {
                                    ++shape.coreValid;
                                    if (index > shape.maxValidIndex)
                                        shape.maxValidIndex = index;
                                    if (evaluation.classHit && evaluation.outerHit)
                                        ++shape.fullValid;
                                }
                                if (evaluation.nameDecoded && namesSample.size() < 4)
                                    namesSample.push_back(evaluation.name);
                                if (evaluation.stage != ObjectStage::Valid)
                                    recordFailure(evaluation.stage, index, object, itemAddress,
                                                  evaluation.indexReadable ? evaluation.reportedIndex : -1);
                            };

                            constexpr std::array<int32_t, 16> kSamples = {0, 1, 2, 4, 8, 16, 32, 64,
                                                                          128, 256, 512, 1024, 2048, 4096, 8192, 16384};
                            for (const int32_t index : kSamples)
                                validateIndex(index);
                            if (mode.fixed)
                            {
                                const std::array<int32_t, 4> tail = {
                                    values.count - 1, values.count / 2,
                                    values.count / 4, (values.count * 3) / 4};
                                for (const int32_t index : tail)
                                    validateIndex(index);
                            }
                            else
                            {
                                const std::array<int32_t, 8> tail = {
                                    values.count - 1, values.count / 2,
                                    std::min(values.count - 1, mode.perChunk - 1),
                                    std::min(values.count - 1, mode.perChunk),
                                    std::min(values.count - 1, 2 * mode.perChunk - 1),
                                    std::min(values.count - 1, 2 * mode.perChunk),
                                    values.count / 4, (values.count * 3) / 4};
                                for (const int32_t index : tail)
                                    validateIndex(index);
                            }

                            const uint32_t nonEmpty = shape.tested - shape.empty;
                            shape.confidence = nonEmpty > 0
                                                   ? static_cast<double>(shape.coreValid) / nonEmpty
                                                   : 0.0;
                            shape.sampleNames = BuildShapeSamples(namesSample);
                            if (shape.tested != 0 && shape.failureStage == ObjectStage::Valid &&
                                shape.coreValid == 0)
                                shape.failureStage = ObjectStage::ObjectEmpty;
                            const int32_t coverageThreshold = (values.count * 3) / 4;
                            if (shape.coreValid > 0 && shape.failureStage == ObjectStage::Valid &&
                                shape.maxValidIndex < coverageThreshold)
                                shape.failureStage = ObjectStage::CoverageGap;
                            if (shape.coreValid > 0 && shape.failureStage == ObjectStage::Valid &&
                                (shape.coreValid < 8 || shape.confidence < 0.85))
                                shape.failureStage = ObjectStage::InsufficientCore;
                            if (shape.coreValid >= 8 && nonEmpty >= 8 && shape.confidence >= 0.85 &&
                                shape.maxValidIndex >= coverageThreshold)
                            {
                                shapes.push_back(std::move(shape));
                            }
                            else if (shape.tested != 0 &&
                                     (!bestFailed || ShapeScore(shape) > ShapeScore(*bestFailed)))
                            {
                                bestFailed = std::move(shape);
                            }
                        }
                    }
                    if (shapes.empty())
                    {
                        if (bestFailed)
                        {
                            ObjectCandidateEvidence evidence =
                                BuildEvidence(pointerAddress, chunkTable, field, mode.fixed, mode.perChunk,
                                              values, *bestFailed, memory);
                            if (!bestRejected || EvidenceScore(evidence) > EvidenceScore(*bestRejected))
                                bestRejected = std::move(evidence);
                        }
                        continue;
                    }
                    std::sort(shapes.begin(), shapes.end(), [](const ShapeResult &left, const ShapeResult &right)
                              {
                                  if (left.coreValid != right.coreValid)
                                      return left.coreValid > right.coreValid;
                                  if ((left.indexOffset == 12) != (right.indexOffset == 12))
                                      return left.indexOffset == 12;
                                  if (left.indexInRange != right.indexInRange)
                                      return left.indexInRange > right.indexInRange;
                                  if (left.fullValid != right.fullValid)
                                      return left.fullValid > right.fullValid;
                                  return left.confidence > right.confidence; });
                    const ShapeResult &best = shapes.front();
                    Contract contract;
                    contract.Kind = ContractKind::ObjectArray;
                    contract.Root = pointerAddress;
                    contract.State = ContractState::Validated;
                    ObjectArrayFields &fields = contract.ObjectArray;
                    fields.ObjectsOffset = 0;
                    fields.MaxElementsOffset = field.maxElements;
                    fields.NumElementsOffset = field.count;
                    fields.MaxChunksOffset = field.maxChunks;
                    fields.NumChunksOffset = field.numChunks;
                    fields.ElementsPerChunk = mode.fixed ? 0 : mode.perChunk;
                    fields.ItemStride = best.stride;
                    fields.ItemObjectOffset = 0;
                    fields.ItemIndexOffset = best.indexOffset;
                    fields.Fixed = mode.fixed;
                    fields.Count = static_cast<uint32_t>(values.count);
                    fields.MaxElements = static_cast<uint32_t>(values.maxElements);
                    fields.Chunks = static_cast<uint32_t>(values.numChunks);
                    contract.Evidence.push_back({EvidenceKind::TableLoad, pointerAddress, chunkTable});
                    contract.Evidence.push_back({EvidenceKind::EntryLoad, pointerAddress, static_cast<uint64_t>(values.count)});
                    contract.Evidence.push_back({EvidenceKind::ScaleAdd, pointerAddress, static_cast<uint64_t>(best.stride)});
                    if (!fields.Complete())
                        continue;
                    accepted = BuildEvidence(pointerAddress, chunkTable, field, mode.fixed, mode.perChunk,
                                             values, best, memory);
                    accepted->Stage = "core-valid";
                    if (best.failureStage != ObjectStage::Valid)
                        accepted->Detail = "first_failure=" + std::string(StageName(best.failureStage)) +
                                           (accepted->Detail.empty() ? "" : " " + accepted->Detail);
                    return contract;
                }
            }
            if (bestRejected)
                rejected = std::move(bestRejected);
            return std::nullopt;
        }

    } // namespace

    ObjectContractScanResult ScanObjectContracts(const ImageModel &image, uintptr_t nameRoot,
                                                 const NamePoolFields &nameFields,
                                                 const NameTextDecoder &nameDecoder,
                                                 const ObjectContractScanOptions &options)
    {
        ObjectContractScanResult result;
        if (!image.IsValid() || nameRoot == 0 || !nameFields.Complete())
        {
            result.Error = "image-or-name-contract-invalid";
            return result;
        }

        NameResolver names(image.Memory(), nameRoot, nameFields, nameDecoder);
        std::vector<std::pair<uintptr_t, uintptr_t>> readableRanges;
        for (const auto &region : image.Memory().Regions())
        {
            if (region.readable && region.end > region.start)
                readableRanges.emplace_back(region.start, region.end);
        }
        std::sort(readableRanges.begin(), readableRanges.end());

        std::vector<Contract> candidates;
        const auto addRejection = [&](ObjectCandidateEvidence evidence)
        {
            const auto duplicate = std::any_of(result.Rejections.begin(), result.Rejections.end(),
                                               [&](const ObjectCandidateEvidence &existing)
                                               {
                                                   return existing.Root == evidence.Root &&
                                                          existing.Storage == evidence.Storage &&
                                                          existing.Field == evidence.Field &&
                                                          existing.Fixed == evidence.Fixed &&
                                                          existing.ElementsPerChunk == evidence.ElementsPerChunk &&
                                                          existing.ItemStride == evidence.ItemStride &&
                                                          existing.ItemIndexOffset == evidence.ItemIndexOffset;
                                               });
            if (duplicate)
                return;
            result.Rejections.push_back(std::move(evidence));
            std::sort(result.Rejections.begin(), result.Rejections.end(),
                      [](const ObjectCandidateEvidence &left, const ObjectCandidateEvidence &right)
                      { return EvidenceScore(left) > EvidenceScore(right); });
            if (result.Rejections.size() > options.MaxRejections)
                result.Rejections.resize(options.MaxRejections);
        };

        const auto considerPointer = [&](uintptr_t pointerAddress, uintptr_t rawChunkTable)
        {
            if (rawChunkTable == 0 || !IsInReadableRanges(readableRanges, rawChunkTable, sizeof(uintptr_t)) ||
                !image.Memory().IsReadable(rawChunkTable, sizeof(uintptr_t)) ||
                image.Memory().IsExecutable(rawChunkTable, sizeof(uintptr_t)))
                return;
            uintptr_t chunk0 = 0;
            if (!ReadPointerValue(image.Memory(), rawChunkTable, chunk0) || chunk0 == 0 ||
                !image.Memory().IsReadable(chunk0, sizeof(uintptr_t)))
                return;
            ++result.Candidates;
            std::optional<ObjectCandidateEvidence> rejected;
            std::optional<ObjectCandidateEvidence> accepted;
            const auto contract = TryCandidate(image.Memory(), names, pointerAddress, rawChunkTable,
                                               options, rejected, accepted);
            if (contract)
            {
                candidates.push_back(*contract);
                if (accepted)
                    result.Accepted.push_back(std::move(*accepted));
            }
            else if (rejected)
            {
                addRejection(std::move(*rejected));
            }
        };

        std::unordered_set<uintptr_t> deepHolders;
        const auto probeDeeperHeaders = [&](uintptr_t holder)
        {
            if (holder == 0 || image.Contains(holder) ||
                !image.Memory().IsReadable(holder, sizeof(uintptr_t)) ||
                image.Memory().IsExecutable(holder, sizeof(uintptr_t)))
                return;
            if (deepHolders.size() >= options.MaxDeepHeaders)
            {
                result.DeepBudgetExhausted = true;
                return;
            }
            if (!deepHolders.insert(holder).second)
                return;
            ++result.DeepCandidates;
            for (const int32_t offset : {0, 16, 24, 32})
            {
                const auto slot = AddOffset(holder, offset);
                uintptr_t header = 0;
                if (!slot || !ReadPointerValue(image.Memory(), *slot, header) ||
                    header == 0 || header == holder || (header & (sizeof(uintptr_t) - 1)) != 0)
                    continue;
                if (!IsInReadableRanges(readableRanges, header, sizeof(uintptr_t)) ||
                    !image.Memory().IsReadable(header, sizeof(uintptr_t)) ||
                    image.Memory().IsExecutable(header, sizeof(uintptr_t)))
                    continue;
                if (!PlausibleObjectHeader(image.Memory(), header, options))
                    continue;
                uintptr_t objects = 0;
                if (!ReadPointerValue(image.Memory(), header, objects) || objects == 0 ||
                    !image.Memory().IsReadable(objects, sizeof(uintptr_t)) ||
                    image.Memory().IsExecutable(objects, sizeof(uintptr_t)))
                    continue;
                considerPointer(header, objects);
            }
        };

        std::vector<const module::ModuleImage::Segment *> scanSegments;
        for (const auto &segment : image.Module().segments)
        {
            if (segment.readable && segment.writable && segment.end > segment.start)
                scanSegments.push_back(&segment);
        }
        // 名称池和对象全局通常位于同一写段，优先扫描该段以尽早发现对象数组
        std::stable_sort(scanSegments.begin(), scanSegments.end(),
                         [nameRoot](const auto *left, const auto *right)
                         {
                             const bool leftHasName = nameRoot >= left->start && nameRoot < left->end;
                             const bool rightHasName = nameRoot >= right->start && nameRoot < right->end;
                             return leftHasName > rightHasName;
                         });

        std::vector<uint8_t> buffer(kReadChunkBytes);
        for (const auto *segment : scanSegments)
        {
            if (!segment->readable || !segment->writable || segment->end <= segment->start)
                continue;
            if (result.ScannedBytes >= options.MaxScanBytes)
            {
                result.BudgetExhausted = true;
                break;
            }
            const uint64_t segmentBytes = static_cast<uint64_t>(segment->end - segment->start);
            uint64_t offset = 0;
            while (offset < segmentBytes && result.ScannedBytes < options.MaxScanBytes)
            {
                const size_t want = static_cast<size_t>(std::min<uint64_t>(
                    {static_cast<uint64_t>(kReadChunkBytes), segmentBytes - offset,
                     options.MaxScanBytes - result.ScannedBytes}));
                if (want < sizeof(uintptr_t))
                    break;
                const auto chunkAddress = AddOffset(segment->start, static_cast<int64_t>(offset));
                if (!chunkAddress ||
                    !image.Memory().ReadBytes(*chunkAddress, buffer.data(), want).Ok())
                {
                    offset += want;
                    continue;
                }
                result.ScannedBytes += want;
                for (size_t position = 0; position + sizeof(uintptr_t) <= want; position += sizeof(uintptr_t))
                {
                    uintptr_t rawChunkTable = 0;
                    std::memcpy(&rawChunkTable, buffer.data() + position, sizeof(rawChunkTable));
                    if (rawChunkTable < 0x10000)
                        continue;
                    if (!IsInReadableRanges(readableRanges, rawChunkTable, sizeof(uintptr_t)))
                        continue;
                    const auto pointerAddress = AddOffset(*chunkAddress, static_cast<int64_t>(position));
                    if (!pointerAddress)
                        continue;
                    considerPointer(*pointerAddress, rawChunkTable);
                    probeDeeperHeaders(rawChunkTable);

                    // analyzer 的全局可能指向 FUObjectArray 父结构，Objects 位于其成员偏移
                    if (rawChunkTable < 0x10000 ||
                        !IsInReadableRanges(readableRanges, rawChunkTable, sizeof(uintptr_t)) ||
                        !image.Memory().IsReadable(rawChunkTable, sizeof(uintptr_t)) ||
                        image.Memory().IsExecutable(rawChunkTable, sizeof(uintptr_t)))
                        continue;
                    for (const int32_t parentOffset : {0, 16, 24, 32})
                    {
                        const auto parentSlot = AddOffset(rawChunkTable, parentOffset);
                        uintptr_t parentObjects = 0;
                        if (!parentSlot || !ReadPointerValue(image.Memory(), *parentSlot, parentObjects) ||
                            parentObjects == 0 ||
                            !IsInReadableRanges(readableRanges, parentObjects, sizeof(uintptr_t)) ||
                            !image.Memory().IsReadable(parentObjects, sizeof(uintptr_t)) ||
                            image.Memory().IsExecutable(parentObjects, sizeof(uintptr_t)))
                            continue;
                        bool plausibleCount = false;
                        for (const int32_t countOffset : {20, 28, 36})
                        {
                            const auto countAddress = AddOffset(*parentSlot, countOffset);
                            int32_t count = 0;
                            if (countAddress && ReadInt32Value(image.Memory(), *countAddress, count) &&
                                count >= static_cast<int32_t>(options.MinCount) && count <= 0x08000000)
                            {
                                plausibleCount = true;
                                break;
                            }
                        }
                        if (!plausibleCount)
                            continue;
                        ++result.ParentCandidates;
                        considerPointer(*parentSlot, parentObjects);
                    }
                }
                offset += want;
            }
        }

        std::sort(candidates.begin(), candidates.end(), [](const Contract &left, const Contract &right)
                  { return left.ObjectArray.Count > right.ObjectArray.Count; });
        if (candidates.size() > options.MaxCandidates)
            candidates.resize(options.MaxCandidates);
        result.Contracts = std::move(candidates);

        std::sort(result.Accepted.begin(), result.Accepted.end(),
                  [](const ObjectCandidateEvidence &left, const ObjectCandidateEvidence &right)
                  { return EvidenceScore(left) > EvidenceScore(right); });
        if (result.Accepted.size() > options.MaxCandidates)
            result.Accepted.resize(options.MaxCandidates);

        for (ObjectCandidateEvidence &evidence : result.Rejections)
        {
            const uintptr_t sampleObject = evidence.FailureObject != 0 ? evidence.FailureObject
                                                                       : evidence.FirstObject;
            if (sampleObject != 0)
                evidence.Snapshot = ObjectSnapshot(image.Memory(), names, sampleObject);
            else if (evidence.FailureItem != 0)
                evidence.Snapshot = "item=" + common::Hex(evidence.FailureItem) + " object=empty";
        }
        if (!result.Rejections.empty())
            result.BestRejected = CompactEvidence(result.Rejections.front());
        return result;
    }
} // namespace nextdumper::analysis
