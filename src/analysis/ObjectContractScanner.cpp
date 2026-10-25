#include "nextdumper/analysis/ObjectContractScanner.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace nextdumper::analysis
{
    namespace
    {
        constexpr int32_t kElementsPerChunk = 64 * 1024;
        constexpr int32_t kMaxChunks = 8;
        constexpr int32_t kHeaderWindow = 0x60;
        constexpr size_t kReadChunkBytes = 64 * 1024;

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

        bool ReadPointer(const MemoryView &memory, uintptr_t address, uintptr_t &value)
        {
            return ReadExact(memory, address, &value, sizeof(value));
        }

        bool ReadInt32(const MemoryView &memory, uintptr_t address, int32_t &value)
        {
            return ReadExact(memory, address, &value, sizeof(value));
        }

        bool Overlaps(int32_t leftOffset, int32_t leftSize, int32_t rightOffset, int32_t rightSize)
        {
            return leftOffset < rightOffset + rightSize && rightOffset < leftOffset + leftSize;
        }

        bool IsLikelyObject(const MemoryView &memory, uintptr_t object)
        {
            if (object == 0 || !memory.IsReadable(object, sizeof(uintptr_t)))
                return false;
            uintptr_t vtable = 0;
            uintptr_t function = 0;
            return ReadPointer(memory, object, vtable) && vtable != 0 &&
                   memory.IsReadable(vtable, sizeof(uintptr_t)) &&
                   ReadPointer(memory, vtable, function) && function != 0 &&
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

            [[nodiscard]] bool Available() const
            {
                return root_ != 0 && fields_.Complete() && fields_.BlocksBit < 32 &&
                       fields_.LengthShift < 16;
            }

            bool Resolve(int32_t index, std::string &out)
            {
                if (!Available() || index < 0)
                    return false;
                const auto cached = cache_.find(index);
                if (cached != cache_.end())
                {
                    out = cached->second;
                    return true;
                }
                const uint32_t stable = static_cast<uint32_t>(index);
                const int32_t blockIndex = static_cast<int32_t>(stable >> fields_.BlocksBit);
                if (blockIndex < 0 || blockIndex >= 8192)
                    return false;
                const uint32_t within = stable & ((1u << fields_.BlocksBit) - 1u);
                const auto blocks = AddOffset(root_, fields_.BlocksOffset);
                const auto slot = blocks ? AddOffset(*blocks, static_cast<int64_t>(blockIndex) * sizeof(uintptr_t))
                                         : std::nullopt;
                uintptr_t block = 0;
                if (!slot || !ReadPointer(memory_, *slot, block) || block == 0 ||
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
                    !decoder_.Apply(text, text.size(), false) ||
                    !std::all_of(text.begin(), text.end(), [](uint8_t value)
                                 { return value >= 0x20 && value <= 0x7E; }))
                    return false;
                out.assign(reinterpret_cast<const char *>(text.data()), text.size());
                if (cache_.size() < 4096)
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

        bool ReadNameAt(const MemoryView &memory, NameResolver &names, uintptr_t object,
                        int32_t offset, std::string &out)
        {
            const auto address = AddOffset(object, offset);
            int32_t raw = 0;
            return address && ReadInt32(memory, *address, raw) && names.Resolve(raw, out) && !out.empty();
        }

        struct ItemLayout
        {
            int32_t Stride = 0;
            int32_t IndexOffset = -1;

            [[nodiscard]] bool operator==(const ItemLayout &other) const = default;
        };

        struct ObjectSample
        {
            int32_t Index = 0;
            uintptr_t Address = 0;
        };

        struct ScanStats
        {
            uint64_t Tested = 0;
            uint64_t Valid = 0;
            uint64_t Empty = 0;
            uint64_t Invalid = 0;
            uint64_t InvalidBetweenValid = 0;
            uint64_t InvalidSinceValid = 0;
            int32_t DerivedCount = 0;
            std::array<int32_t, kMaxChunks> ChunkValid{};
            std::array<int32_t, kMaxChunks> ChunkEmpty{};
            std::array<int32_t, kMaxChunks> ChunkInvalid{};
            std::array<int32_t, kMaxChunks> ChunkLastValid{};
            std::vector<ObjectSample> Samples;

            ScanStats()
            {
                ChunkLastValid.fill(-1);
            }
        };

        void ScanItems(const MemoryView &memory, uintptr_t storage, const ItemLayout &layout,
                       int32_t baseIndex, int32_t count, size_t chunkIndex, size_t maxSamples,
                       ScanStats &stats)
        {
            const auto recordInvalid = [&]()
            {
                ++stats.Invalid;
                ++stats.InvalidSinceValid;
                if (chunkIndex < stats.ChunkInvalid.size())
                    ++stats.ChunkInvalid[chunkIndex];
            };
            for (int32_t within = 0; within < count; ++within)
            {
                const int32_t index = baseIndex + within;
                const auto item = AddOffset(storage, static_cast<int64_t>(within) * layout.Stride);
                ++stats.Tested;
                uintptr_t object = 0;
                if (!item || !ReadPointer(memory, *item, object))
                {
                    recordInvalid();
                    continue;
                }
                if (object == 0)
                {
                    ++stats.Empty;
                    if (chunkIndex < stats.ChunkEmpty.size())
                        ++stats.ChunkEmpty[chunkIndex];
                    continue;
                }
                int32_t reported = -1;
                const auto indexAddress = AddOffset(object, layout.IndexOffset);
                const bool valid = IsLikelyObject(memory, object) && indexAddress &&
                                   ReadInt32(memory, *indexAddress, reported) && reported == index;
                if (!valid)
                {
                    recordInvalid();
                    continue;
                }
                ++stats.Valid;
                stats.InvalidBetweenValid += std::exchange(stats.InvalidSinceValid, 0);
                if (chunkIndex < stats.ChunkValid.size())
                {
                    ++stats.ChunkValid[chunkIndex];
                    stats.ChunkLastValid[chunkIndex] = index;
                }
                stats.DerivedCount = std::max(stats.DerivedCount, index + 1);
                if (stats.Samples.size() < maxSamples)
                    stats.Samples.push_back({index, object});
            }
        }

        bool PrefixSufficient(const ScanStats &stats)
        {
            const uint64_t nonEmpty = stats.Valid + stats.Invalid;
            return stats.Valid >= 8 && nonEmpty > 0 && stats.Valid * 20 >= nonEmpty * 19;
        }

        std::optional<ScanStats> ValidateLayout(const MemoryView &memory, uintptr_t storage,
                                                const ItemLayout &layout, int32_t baseIndex,
                                                size_t sampleCount)
        {
            ScanStats stats;
            ScanItems(memory, storage, layout, baseIndex, static_cast<int32_t>(sampleCount), 0,
                      sampleCount, stats);
            if (!PrefixSufficient(stats))
                return std::nullopt;
            return stats;
        }

        std::vector<ItemLayout> RecoverLayouts(const MemoryView &memory, uintptr_t storage,
                                               size_t sampleCount)
        {
            std::vector<ItemLayout> layouts;
            for (const int32_t stride : {8, 16, 24, 32})
            {
                std::vector<ObjectSample> live;
                for (size_t index = 0; index < sampleCount; ++index)
                {
                    const auto item = AddOffset(storage, static_cast<int64_t>(index) * stride);
                    uintptr_t object = 0;
                    if (item && ReadPointer(memory, *item, object) && object != 0 &&
                        IsLikelyObject(memory, object))
                        live.push_back({static_cast<int32_t>(index), object});
                }
                if (live.size() < 8)
                    continue;
                for (int32_t indexOffset = 0; indexOffset <= 0x80; indexOffset += 4)
                {
                    bool firstTwoMatch = true;
                    for (size_t index = 0; index < std::min<size_t>(2, live.size()); ++index)
                    {
                        const auto address = AddOffset(live[index].Address, indexOffset);
                        int32_t reported = -1;
                        if (!address || !ReadInt32(memory, *address, reported) ||
                            reported != live[index].Index)
                        {
                            firstTwoMatch = false;
                            break;
                        }
                    }
                    if (!firstTwoMatch)
                        continue;
                    uint64_t valid = 0;
                    for (const ObjectSample &sample : live)
                    {
                        const auto address = AddOffset(sample.Address, indexOffset);
                        int32_t reported = -1;
                        if (address && ReadInt32(memory, *address, reported) && reported == sample.Index)
                            ++valid;
                    }
                    if (valid >= 8 && valid * 20 >= live.size() * 19)
                        layouts.push_back({stride, indexOffset});
                }
            }
            return layouts;
        }

        struct StoreObservation
        {
            uintptr_t Root = 0;
            bool Fixed = false;
            ItemLayout Layout;
            std::vector<uintptr_t> Chunks;
            std::vector<uintptr_t> References;
            ScanStats Prefix;
        };

        std::optional<StoreObservation> ProbeChunkStore(const MemoryView &memory, uintptr_t root,
                                                        const std::vector<uintptr_t> &references,
                                                        size_t sampleCount)
        {
            StoreObservation store;
            store.Root = root;
            store.References = references;
            for (int32_t chunkIndex = 0; chunkIndex < kMaxChunks; ++chunkIndex)
            {
                const auto slot = AddOffset(root, static_cast<int64_t>(chunkIndex) * sizeof(uintptr_t));
                uintptr_t chunk = 0;
                if (!slot || !ReadPointer(memory, *slot, chunk) || chunk == 0 ||
                    (chunk & (sizeof(uintptr_t) - 1)) != 0 ||
                    !memory.IsReadable(chunk, sizeof(uintptr_t)) || memory.IsExecutable(chunk, sizeof(uintptr_t)))
                    break;
                if (store.Chunks.empty())
                {
                    const auto layouts = RecoverLayouts(memory, chunk, sampleCount);
                    if (layouts.size() != 1)
                        return std::nullopt;
                    store.Layout = layouts.front();
                    const auto prefix = ValidateLayout(memory, chunk, store.Layout, 0, sampleCount);
                    if (!prefix)
                        return std::nullopt;
                    store.Prefix = *prefix;
                }
                else
                {
                    auto prefix = ValidateLayout(memory, chunk, store.Layout,
                                                 chunkIndex * kElementsPerChunk, sampleCount);
                    if (!prefix)
                    {
                        ScanStats sparse;
                        ScanItems(memory, chunk, store.Layout, chunkIndex * kElementsPerChunk,
                                  static_cast<int32_t>(sampleCount), 0, sampleCount, sparse);
                        if (sparse.Valid == 0 || sparse.Invalid != 0)
                            break;
                    }
                }
                store.Chunks.push_back(chunk);
            }
            if (store.Chunks.empty())
                return std::nullopt;
            return store;
        }

        std::optional<StoreObservation> ProbeFixedStore(const MemoryView &memory, uintptr_t root,
                                                        const std::vector<uintptr_t> &references,
                                                        size_t sampleCount)
        {
            const auto layouts = RecoverLayouts(memory, root, sampleCount);
            if (layouts.size() != 1)
                return std::nullopt;
            StoreObservation store;
            store.Root = root;
            store.Fixed = true;
            store.Layout = layouts.front();
            store.Chunks = {root};
            store.References = references;
            const auto prefix = ValidateLayout(memory, root, store.Layout, 0, sampleCount);
            if (!prefix)
                return std::nullopt;
            store.Prefix = *prefix;
            return store;
        }

        struct HeaderCandidate
        {
            uintptr_t Root = 0;
            uintptr_t ObjectsAddress = 0;
            uintptr_t CountAddress = 0;
            uintptr_t MaxChunksAddress = 0;
            uintptr_t NumChunksAddress = 0;
            uintptr_t MaxElementsAddress = 0;
            int32_t ObjectsOffset = -1;
            int32_t CountOffset = -1;
            int32_t MaxChunksOffset = -1;
            int32_t NumChunksOffset = -1;
            int32_t MaxElementsOffset = -1;
            int32_t Count = 0;
            int32_t MaxChunks = 0;
            int32_t NumChunks = 0;
            int32_t MaxElements = 0;
        };

        bool SameHeader(const HeaderCandidate &left, const HeaderCandidate &right)
        {
            return left.ObjectsAddress == right.ObjectsAddress && left.CountAddress == right.CountAddress &&
                   left.MaxChunksAddress == right.MaxChunksAddress &&
                   left.NumChunksAddress == right.NumChunksAddress &&
                   left.MaxElementsAddress == right.MaxElementsAddress;
        }

        bool BetterRepresentation(const HeaderCandidate &candidate, const HeaderCandidate &current)
        {
            if (candidate.ObjectsOffset != current.ObjectsOffset)
                return candidate.ObjectsOffset < current.ObjectsOffset;
            return candidate.Root < current.Root;
        }

        bool AddHeader(std::vector<HeaderCandidate> &headers, const HeaderCandidate &candidate,
                       size_t maxCandidates)
        {
            for (HeaderCandidate &existing : headers)
            {
                if (!SameHeader(existing, candidate))
                    continue;
                if (BetterRepresentation(candidate, existing))
                    existing = candidate;
                return true;
            }
            if (headers.size() >= maxCandidates)
                return false;
            headers.push_back(candidate);
            return true;
        }

        std::vector<HeaderCandidate> RecoverHeaders(const MemoryView &memory,
                                                    const StoreObservation &store,
                                                    uint64_t &remainingSteps,
                                                    size_t maxCandidates,
                                                    bool &stepBudgetExhausted,
                                                    bool &candidateOverflow)
        {
            std::vector<HeaderCandidate> headers;
            for (const uintptr_t reference : store.References)
            {
                for (int32_t objectsOffset = 0; objectsOffset <= 64; objectsOffset += 4)
                {
                    if (reference < static_cast<uintptr_t>(objectsOffset))
                        continue;
                    const uintptr_t base = reference - static_cast<uintptr_t>(objectsOffset);
                    if ((base & 3u) != 0 || !memory.IsReadable(base, kHeaderWindow))
                        continue;
                    std::array<int32_t, kHeaderWindow / 4> values{};
                    if (!ReadExact(memory, base, values.data(), sizeof(values)))
                        continue;
                    for (int32_t numChunksOffset = 0; numChunksOffset < kHeaderWindow; numChunksOffset += 4)
                    {
                        if (remainingSteps == 0)
                        {
                            stepBudgetExhausted = true;
                            return headers;
                        }
                        --remainingSteps;
                        const int32_t numChunks = values[numChunksOffset / 4];
                        if ((!store.Fixed && numChunks != static_cast<int32_t>(store.Chunks.size())) ||
                            (store.Fixed && (numChunks < 0 || numChunks > 1)))
                            continue;
                        for (int32_t maxChunksOffset = 0; maxChunksOffset < kHeaderWindow; maxChunksOffset += 4)
                        {
                            const int32_t maxChunks = values[maxChunksOffset / 4];
                            if (maxChunks <= numChunks || maxChunks > 64 ||
                                (store.Fixed && maxChunks > 1))
                                continue;
                            for (int32_t maxElementsOffset = 0; maxElementsOffset < kHeaderWindow;
                                 maxElementsOffset += 4)
                            {
                                if (remainingSteps == 0)
                                {
                                    stepBudgetExhausted = true;
                                    return headers;
                                }
                                --remainingSteps;
                                const int32_t maxElements = values[maxElementsOffset / 4];
                                const int64_t expectedMax = static_cast<int64_t>(maxChunks) * kElementsPerChunk;
                                if (maxElements <= 0 || maxElements > 0x08000000 ||
                                    (!store.Fixed && maxElements != expectedMax))
                                    continue;
                                for (int32_t countOffset = 0; countOffset < kHeaderWindow; countOffset += 4)
                                {
                                    if (remainingSteps == 0)
                                    {
                                        stepBudgetExhausted = true;
                                        return headers;
                                    }
                                    --remainingSteps;
                                    const int32_t count = values[countOffset / 4];
                                    if (count <= 0 || count >= maxElements ||
                                        (!store.Fixed && static_cast<int64_t>(count) >
                                                             static_cast<int64_t>(numChunks) * kElementsPerChunk))
                                        continue;
                                    const std::array<int32_t, 4> offsets = {
                                        countOffset, maxChunksOffset, numChunksOffset, maxElementsOffset};
                                    bool distinct = true;
                                    for (size_t index = 0; index < offsets.size() && distinct; ++index)
                                    {
                                        if (Overlaps(offsets[index], 4, objectsOffset,
                                                     static_cast<int32_t>(sizeof(uintptr_t))))
                                            distinct = false;
                                        for (size_t other = index + 1; other < offsets.size(); ++other)
                                            distinct = distinct && offsets[index] != offsets[other];
                                    }
                                    if (!distinct)
                                        continue;
                                    HeaderCandidate candidate;
                                    candidate.Root = base;
                                    candidate.ObjectsAddress = reference;
                                    candidate.CountAddress = base + countOffset;
                                    candidate.MaxChunksAddress = base + maxChunksOffset;
                                    candidate.NumChunksAddress = base + numChunksOffset;
                                    candidate.MaxElementsAddress = base + maxElementsOffset;
                                    candidate.ObjectsOffset = objectsOffset;
                                    candidate.CountOffset = countOffset;
                                    candidate.MaxChunksOffset = maxChunksOffset;
                                    candidate.NumChunksOffset = numChunksOffset;
                                    candidate.MaxElementsOffset = maxElementsOffset;
                                    candidate.Count = count;
                                    candidate.MaxChunks = maxChunks;
                                    candidate.NumChunks = numChunks;
                                    candidate.MaxElements = maxElements;
                                    if (!AddHeader(headers, candidate, maxCandidates))
                                    {
                                        candidateOverflow = true;
                                        return headers;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return headers;
        }

        uint64_t RequiredScanItems(const StoreObservation &store, int32_t capacity)
        {
            return store.Fixed ? static_cast<uint64_t>(capacity)
                               : store.Chunks.size() * static_cast<uint64_t>(kElementsPerChunk);
        }

        std::optional<ScanStats> ScanFullStore(const MemoryView &memory, const StoreObservation &store,
                                               int32_t capacity, size_t maxSamples,
                                               uint64_t &remainingBudget)
        {
            remainingBudget -= RequiredScanItems(store, capacity);
            ScanStats stats;
            if (store.Fixed)
            {
                ScanItems(memory, store.Root, store.Layout, 0, capacity, 0, maxSamples, stats);
            }
            else
            {
                for (size_t chunkIndex = 0; chunkIndex < store.Chunks.size(); ++chunkIndex)
                {
                    ScanItems(memory, store.Chunks[chunkIndex], store.Layout,
                              static_cast<int32_t>(chunkIndex) * kElementsPerChunk,
                              kElementsPerChunk, chunkIndex, maxSamples, stats);
                }
            }
            if (stats.Valid < 8 || stats.InvalidBetweenValid > stats.Valid || stats.DerivedCount <= 0)
                return std::nullopt;
            return stats;
        }

        struct OffsetStat
        {
            int32_t Offset = -1;
            uint32_t Primary = 0;
            uint32_t Secondary = 0;
            uint32_t Hits = 0;
        };

        struct OffsetSelection
        {
            bool Found = false;
            bool Ambiguous = false;
            OffsetStat Value;
        };

        OffsetSelection SelectOffset(std::vector<OffsetStat> stats, uint32_t minimumHits,
                                     bool requirePositivePrimary = true)
        {
            OffsetSelection selection;
            stats.erase(std::remove_if(stats.begin(), stats.end(), [&](const OffsetStat &stat)
                                       { return stat.Hits < minimumHits ||
                                                (requirePositivePrimary && stat.Primary == 0); }),
                        stats.end());
            if (stats.empty())
                return selection;
            const auto better = [](const OffsetStat &left, const OffsetStat &right)
            {
                if (left.Primary != right.Primary)
                    return left.Primary > right.Primary;
                if (left.Secondary != right.Secondary)
                    return left.Secondary > right.Secondary;
                return left.Offset < right.Offset;
            };
            std::sort(stats.begin(), stats.end(), better);
            const auto sameEvidence = [](const OffsetStat &left, const OffsetStat &right)
            { return left.Primary == right.Primary && left.Secondary == right.Secondary; };
            selection.Found = true;
            selection.Ambiguous = stats.size() > 1 && sameEvidence(stats[0], stats[1]);
            selection.Value = stats.front();
            return selection;
        }

        UObjectLayoutContract CalibrateUObject(const MemoryView &memory, NameResolver &names,
                                               const StoreObservation &store, const HeaderCandidate &header,
                                               const ScanStats &full, ObjectSeedEvidence &seed)
        {
            UObjectLayoutContract contract;
            contract.ObjectRoot = header.Root;
            contract.State = ContractState::Observed;
            contract.UObject.InternalIndex = store.Layout.IndexOffset;
            seed.IndexOffset = store.Layout.IndexOffset;
            seed.IndexHits = static_cast<uint32_t>(full.Samples.size());
            seed.Calibrated = true;
            seed.CalibrationDetail = "samples=" + std::to_string(full.Samples.size());
            if (full.Samples.empty())
                return contract;

            std::vector<OffsetStat> nameStats;
            if (names.Available())
            {
                for (int32_t offset = 0; offset <= 0x70; offset += 4)
                {
                    if (Overlaps(offset, 4, store.Layout.IndexOffset, 4))
                        continue;
                    OffsetStat stat;
                    stat.Offset = offset;
                    std::vector<std::string> unique;
                    for (const ObjectSample &sample : full.Samples)
                    {
                        std::string name;
                        if (!ReadNameAt(memory, names, sample.Address, offset, name))
                            continue;
                        ++stat.Hits;
                        if (std::find(unique.begin(), unique.end(), name) == unique.end())
                            unique.push_back(std::move(name));
                    }
                    stat.Primary = static_cast<uint32_t>(unique.size());
                    stat.Secondary = stat.Hits;
                    if (stat.Hits > 0)
                        nameStats.push_back(stat);
                }
                const OffsetSelection selected = SelectOffset(std::move(nameStats), 8);
                if (selected.Found)
                {
                    seed.NameOffset = selected.Value.Offset;
                    seed.NameHits = selected.Value.Hits;
                    seed.NameUnique = selected.Value.Primary;
                    if (!selected.Ambiguous)
                        contract.UObject.Name = selected.Value.Offset;
                    else
                        contract.State = ContractState::Ambiguous;
                }
            }

            std::vector<OffsetStat> classStats;
            if (contract.UObject.Name >= 0)
            {
                for (int32_t offset = static_cast<int32_t>(sizeof(uintptr_t)); offset <= 0x70;
                     offset += static_cast<int32_t>(sizeof(uintptr_t)))
                {
                    if (Overlaps(offset, static_cast<int32_t>(sizeof(uintptr_t)),
                                 store.Layout.IndexOffset, 4) ||
                        Overlaps(offset, static_cast<int32_t>(sizeof(uintptr_t)), contract.UObject.Name, 8))
                        continue;
                    OffsetStat stat;
                    stat.Offset = offset;
                    for (const ObjectSample &sample : full.Samples)
                    {
                        const auto address = AddOffset(sample.Address, offset);
                        uintptr_t classObject = 0;
                        std::string className;
                        if (address && ReadPointer(memory, *address, classObject) &&
                            IsLikelyObject(memory, classObject) &&
                            ReadNameAt(memory, names, classObject, contract.UObject.Name, className))
                            ++stat.Hits;
                    }
                    stat.Primary = stat.Hits;
                    if (stat.Hits > 0)
                        classStats.push_back(stat);
                }
                const OffsetSelection selected = SelectOffset(std::move(classStats), 3);
                if (selected.Found)
                {
                    seed.ClassOffset = selected.Value.Offset;
                    seed.ClassHits = selected.Value.Hits;
                    if (!selected.Ambiguous)
                        contract.UObject.Class = selected.Value.Offset;
                    else
                        contract.State = ContractState::Ambiguous;
                }
            }

            std::vector<OffsetStat> outerStats;
            for (int32_t offset = static_cast<int32_t>(sizeof(uintptr_t)); offset <= 0x80;
                 offset += static_cast<int32_t>(sizeof(uintptr_t)))
            {
                if (Overlaps(offset, static_cast<int32_t>(sizeof(uintptr_t)),
                             store.Layout.IndexOffset, 4) ||
                    (contract.UObject.Class >= 0 &&
                     Overlaps(offset, static_cast<int32_t>(sizeof(uintptr_t)),
                              contract.UObject.Class, static_cast<int32_t>(sizeof(uintptr_t)))) ||
                    (contract.UObject.Name >= 0 &&
                     Overlaps(offset, static_cast<int32_t>(sizeof(uintptr_t)), contract.UObject.Name, 8)))
                    continue;
                OffsetStat stat;
                stat.Offset = offset;
                for (const ObjectSample &sample : full.Samples)
                {
                    const auto address = AddOffset(sample.Address, offset);
                    uintptr_t outer = 0;
                    if (!address || !ReadPointer(memory, *address, outer))
                        continue;
                    if (outer == 0 || IsLikelyObject(memory, outer))
                    {
                        ++stat.Hits;
                        if (outer != 0)
                            ++stat.Primary;
                    }
                }
                stat.Secondary = stat.Hits;
                if (stat.Hits > 0)
                    outerStats.push_back(stat);
            }
            const OffsetSelection outer = SelectOffset(std::move(outerStats), 3);
            if (outer.Found)
            {
                seed.OuterOffset = outer.Value.Offset;
                seed.OuterHits = outer.Value.Hits;
                if (!outer.Ambiguous)
                    contract.UObject.Outer = outer.Value.Offset;
                else
                    contract.State = ContractState::Ambiguous;
            }
            return contract;
        }

        ObjectSeedEvidence MakeSeedEvidence(const StoreObservation &store,
                                            const HeaderCandidate &header, const ScanStats &full)
        {
            ObjectSeedEvidence seed;
            seed.Root = store.Root;
            seed.Storage = store.Chunks.front();
            seed.DeclaredCount = header.Count;
            seed.CountOffset = header.CountOffset;
            seed.ItemStride = store.Layout.Stride;
            seed.ItemIndexOffset = store.Layout.IndexOffset;
            seed.PrefixValid = static_cast<uint32_t>(store.Prefix.Valid);
            seed.PrefixTested = static_cast<uint32_t>(store.Prefix.Tested);
            seed.ChunkTable = !store.Fixed;
            seed.ChunkCount = static_cast<int32_t>(store.Chunks.size());
            seed.ElementsPerChunk = store.Fixed ? 0 : kElementsPerChunk;
            seed.ChunkValid = full.ChunkValid;
            seed.ChunkEmpty = full.ChunkEmpty;
            seed.ChunkInvalid = full.ChunkInvalid;
            seed.ChunkLastValid = full.ChunkLastValid;
            seed.DerivedCount = full.DerivedCount;
            seed.HeaderFound = true;
            seed.HeaderRoot = header.Root;
            seed.HeaderObjectsOffset = header.ObjectsOffset;
            seed.HeaderCountOffset = header.CountOffset;
            seed.HeaderMaxChunksOffset = header.MaxChunksOffset;
            seed.HeaderNumChunksOffset = header.NumChunksOffset;
            seed.HeaderMaxElementsOffset = header.MaxElementsOffset;
            seed.HeaderCount = header.Count;
            seed.HeaderMaxElements = header.MaxElements;
            seed.HeaderChunks = header.NumChunks;
            return seed;
        }

        struct DiscoveredRoot
        {
            uintptr_t Target = 0;
            bool ChunkLike = false;
            bool FixedLike = false;
            std::vector<uintptr_t> References;
        };

        bool ClassifyStorageRoot(const MemoryView &memory, uintptr_t target,
                                 bool &chunkLike, bool &fixedLike)
        {
            uintptr_t first = 0;
            if (!ReadPointer(memory, target, first) || first < 0x10000)
                return false;
            fixedLike = IsLikelyObject(memory, first);
            if (!fixedLike && memory.IsReadable(first, sizeof(uintptr_t)) &&
                !memory.IsExecutable(first, sizeof(uintptr_t)))
            {
                // chunk table 的首项是 chunk，chunk 的首项才是 UObject；fixed 数组则直接以 UObject 项开始。
                uintptr_t firstItem = 0;
                chunkLike = ReadPointer(memory, first, firstItem) && IsLikelyObject(memory, firstItem);
            }
            return chunkLike || fixedLike;
        }
    } // namespace

    ObjectContractScanResult ScanObjectContracts(const ImageModel &image, uintptr_t nameRoot,
                                                 const NamePoolFields &nameFields,
                                                 const NameTextDecoder &nameDecoder,
                                                 const ObjectContractScanOptions &options)
    {
        ObjectContractScanResult result;
        if (!image.IsValid())
        {
            result.Error = "image-invalid";
            return result;
        }
        const MemoryView &memory = image.Memory();
        NameResolver names(memory, nameRoot, nameFields, nameDecoder);
        std::vector<DiscoveredRoot> roots;
        std::unordered_map<uintptr_t, size_t> rootIndices;
        std::unordered_set<uintptr_t> rejectedRoots;
        std::vector<uint8_t> buffer(kReadChunkBytes);
        uint64_t writableBytes = 0;
        bool processingBudgetExhausted = false;
        for (const auto &segment : image.Module().segments)
        {
            if (!segment.readable || !segment.writable || segment.end <= segment.start)
                continue;
            const uint64_t bytes = segment.end - segment.start;
            writableBytes = bytes > UINT64_MAX - writableBytes ? UINT64_MAX : writableBytes + bytes;
        }
        for (const auto &segment : image.Module().segments)
        {
            if (!segment.readable || !segment.writable || segment.end <= segment.start)
                continue;
            const uint64_t segmentBytes = segment.end - segment.start;
            for (uint64_t offset = 0; offset < segmentBytes && result.ScannedBytes < options.MaxScanBytes;)
            {
                const size_t wanted = static_cast<size_t>(std::min<uint64_t>(
                    {kReadChunkBytes, segmentBytes - offset, options.MaxScanBytes - result.ScannedBytes}));
                if (wanted < sizeof(uintptr_t))
                    break;
                const auto address = AddOffset(segment.start, static_cast<int64_t>(offset));
                if (!address || !memory.ReadBytes(*address, buffer.data(), wanted).Ok())
                {
                    offset += wanted;
                    continue;
                }
                result.ScannedBytes += wanted;
                for (size_t position = 0; position + sizeof(uintptr_t) <= wanted; position += sizeof(uintptr_t))
                {
                    uintptr_t target = 0;
                    std::memcpy(&target, buffer.data() + position, sizeof(target));
                    if (target < 0x10000 || (target & (sizeof(uintptr_t) - 1)) != 0 ||
                        !memory.IsReadable(target, sizeof(uintptr_t)) ||
                        memory.IsExecutable(target, sizeof(uintptr_t)))
                        continue;
                    const auto slot = AddOffset(*address, static_cast<int64_t>(position));
                    if (!slot)
                        continue;
                    ++result.Candidates;
                    const auto existing = rootIndices.find(target);
                    if (existing != rootIndices.end())
                    {
                        roots[existing->second].References.push_back(*slot);
                        continue;
                    }
                    if (rejectedRoots.contains(target))
                        continue;
                    ++result.DiscoveredRoots;
                    bool chunkLike = false;
                    bool fixedLike = false;
                    if (!ClassifyStorageRoot(memory, target, chunkLike, fixedLike))
                    {
                        rejectedRoots.insert(target);
                        continue;
                    }
                    ++result.StorageRoots;
                    if (roots.size() >= options.MaxSeedRoots)
                    {
                        ++result.RootsSkipped;
                        rejectedRoots.insert(target);
                        continue;
                    }
                    rootIndices.emplace(target, roots.size());
                    roots.push_back({target, chunkLike, fixedLike, {*slot}});
                }
                offset += wanted;
            }
        }
        result.BudgetExhausted = writableBytes > options.MaxScanBytes &&
                                 result.ScannedBytes >= options.MaxScanBytes;
        std::sort(roots.begin(), roots.end(), [](const DiscoveredRoot &left, const DiscoveredRoot &right)
                  { return left.Target < right.Target; });

        uint64_t headerStepBudget = options.MaxHeaderSteps;
        uint64_t fullScanBudget = options.MaxFullScanItems;
        for (DiscoveredRoot &root : roots)
        {
            if (processingBudgetExhausted)
                break;
            ++result.SeedRootsProbed;
            std::sort(root.References.begin(), root.References.end());
            root.References.erase(std::unique(root.References.begin(), root.References.end()), root.References.end());
            std::vector<StoreObservation> stores;
            if (root.ChunkLike)
            {
                if (auto chunked = ProbeChunkStore(memory, root.Target, root.References, options.MaxSamples))
                {
                    ++result.ChunkStores;
                    stores.push_back(std::move(*chunked));
                }
            }
            if (root.FixedLike)
            {
                if (auto fixed = ProbeFixedStore(memory, root.Target, root.References, options.MaxSamples))
                {
                    ++result.FixedStores;
                    stores.push_back(std::move(*fixed));
                }
            }

            for (const StoreObservation &store : stores)
            {
                ++result.SeedCandidates;
                bool headerStepExhausted = false;
                bool headerOverflow = false;
                const auto headers = RecoverHeaders(memory, store, headerStepBudget,
                                                    options.MaxHeaderCandidates,
                                                    headerStepExhausted, headerOverflow);
                result.HeaderCandidates += headers.size();
                if (headerOverflow)
                    continue;
                if (headerStepExhausted)
                {
                    result.SeedBudgetExhausted = true;
                    processingBudgetExhausted = true;
                    break;
                }
                struct ValidatedHeader
                {
                    HeaderCandidate Header;
                    ScanStats Full;
                };
                std::vector<ValidatedHeader> validated;
                std::optional<ScanStats> fullStats;
                int32_t scannedCapacity = -1;
                int32_t failedCapacity = -1;
                bool fullScanExhausted = false;
                for (const HeaderCandidate &header : headers)
                {
                    const int32_t scanCapacity = store.Fixed
                                                     ? header.MaxElements
                                                     : static_cast<int32_t>(store.Chunks.size()) * kElementsPerChunk;
                    if (scanCapacity == failedCapacity)
                        continue;
                    if (!fullStats || scannedCapacity != scanCapacity)
                    {
                        const uint64_t required = RequiredScanItems(store, scanCapacity);
                        if (required > fullScanBudget)
                        {
                            if (fullScanBudget == 0)
                            {
                                fullScanExhausted = true;
                                break;
                            }
                            failedCapacity = scanCapacity;
                            continue;
                        }
                        fullStats = ScanFullStore(memory, store, scanCapacity, options.MaxSamples, fullScanBudget);
                        scannedCapacity = scanCapacity;
                        if (!fullStats)
                        {
                            failedCapacity = scanCapacity;
                            continue;
                        }
                    }
                    if (fullStats->DerivedCount > header.Count)
                        continue;
                    validated.push_back({header, *fullStats});
                }
                result.HeaderValidations += validated.size();
                if (fullScanExhausted)
                {
                    result.SeedBudgetExhausted = true;
                    processingBudgetExhausted = true;
                    break;
                }
                if (validated.size() != 1)
                    continue;

                const ValidatedHeader &selected = validated.front();
                ObjectSeedEvidence seed = MakeSeedEvidence(store, selected.Header, selected.Full);
                UObjectLayoutContract uobject =
                    CalibrateUObject(memory, names, store, selected.Header, selected.Full, seed);

                ObjectArrayContract contract;
                contract.Root = selected.Header.Root;
                contract.State = names.Available() ? ContractState::Validated : ContractState::Observed;
                ObjectArrayFields &fields = contract.ObjectArray;
                fields.ObjectsOffset = selected.Header.ObjectsOffset;
                fields.MaxElementsOffset = selected.Header.MaxElementsOffset;
                fields.NumElementsOffset = selected.Header.CountOffset;
                fields.MaxChunksOffset = selected.Header.MaxChunksOffset;
                fields.NumChunksOffset = selected.Header.NumChunksOffset;
                fields.ElementsPerChunk = store.Fixed ? 0 : kElementsPerChunk;
                fields.ItemStride = store.Layout.Stride;
                fields.ItemObjectOffset = 0;
                fields.ItemIndexOffset = store.Layout.IndexOffset;
                fields.Fixed = store.Fixed;
                contract.Observation.Count = static_cast<uint32_t>(selected.Header.Count);
                contract.Observation.MaxElements = static_cast<uint32_t>(selected.Header.MaxElements);
                contract.Observation.Chunks = static_cast<uint32_t>(selected.Header.NumChunks);
                if (!fields.Complete())
                    continue;
                contract.Evidence.push_back({EvidenceKind::TableLoad, contract.Root, store.Root});
                contract.Evidence.push_back({EvidenceKind::EntryLoad, contract.Root,
                                             static_cast<uint64_t>(selected.Header.Count)});
                contract.Evidence.push_back({EvidenceKind::ScaleAdd, contract.Root,
                                             static_cast<uint64_t>(store.Layout.Stride)});
                result.Contracts.push_back(std::move(contract));
                result.UObjectLayouts.push_back(std::move(uobject));
                if (result.Seeds.size() < options.MaxSeeds)
                    result.Seeds.push_back(std::move(seed));
            }
        }

        if (result.RootsSkipped > 0)
            result.SeedBudgetExhausted = true;
        const ObjectArrayContract *validated = nullptr;
        for (const ObjectArrayContract &contract : result.Contracts)
        {
            if (validated && (validated->Root != contract.Root || !(validated->ObjectArray == contract.ObjectArray)))
                result.ContractsAmbiguous = true;
            if (!validated)
                validated = &contract;
        }
        if (result.BudgetExhausted || result.SeedBudgetExhausted)
        {
            for (ObjectArrayContract &contract : result.Contracts)
            {
                if (contract.State == ContractState::Validated)
                    contract.State = ContractState::Observed;
            }
        }
        if (result.Contracts.size() > options.MaxCandidates)
            result.Contracts.resize(options.MaxCandidates);
        return result;
    }
} // namespace nextdumper::analysis
