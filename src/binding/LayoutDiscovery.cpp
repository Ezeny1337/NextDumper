#include "nextdumper/binding/LayoutDiscovery.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <map>
#include <tuple>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::binding
{
    namespace
    {
        using ::nextdumper::common::Hex;

        const char *RootTargetName(RootTarget target)
        {
            switch (target)
            {
            case RootTarget::Unknown:
                return "unknown";
            case RootTarget::GUObjectArray:
                return "guobjectarray";
            case RootTarget::ObjObjects:
                return "objobjects";
            case RootTarget::NamePool:
                return "namepool";
            }
            return "unknown";
        }

        std::optional<uintptr_t> Add(uintptr_t base, uintptr_t offset)
        {
            if (base > UINTPTR_MAX - offset)
                return std::nullopt;
            return base + offset;
        }

        std::optional<uintptr_t> Scaled(uintptr_t base, int32_t index, int32_t stride)
        {
            if (index < 0 || stride <= 0)
                return std::nullopt;
            const uintptr_t uIndex = static_cast<uintptr_t>(index);
            const uintptr_t uStride = static_cast<uintptr_t>(stride);
            if (uIndex != 0 && uStride > UINTPTR_MAX / uIndex)
                return std::nullopt;
            return Add(base, uIndex * uStride);
        }

        bool Overlaps(int32_t leftOffset, int32_t leftSize, int32_t rightOffset, int32_t rightSize)
        {
            return leftOffset < rightOffset + rightSize && rightOffset < leftOffset + leftSize;
        }

        constexpr int32_t kMaxChunkIndex = 0x1000;
        int32_t CountChunkPrefix(const IMemorySource &memory, uintptr_t storage, const DecodePlan &decode)
        {
            constexpr int32_t kWindowChunks = 64;
            int32_t prefix = 0;
            for (int32_t base = 0; base < kMaxChunkIndex; base += kWindowChunks)
            {
                std::array<uintptr_t, kWindowChunks> window{};
                const size_t bytes = static_cast<size_t>(kWindowChunks) * sizeof(uintptr_t);
                const auto windowAddress = Scaled(storage, base, static_cast<int32_t>(sizeof(uintptr_t)));
                if (!windowAddress)
                    break;
                const auto result = memory.ReadBytes(*windowAddress, window.data(), bytes);
                const size_t available = result.transferred >= sizeof(uintptr_t)
                                             ? result.transferred / sizeof(uintptr_t) * sizeof(uintptr_t)
                                             : 0;
                bool stopped = false;
                for (size_t index = 0; index * sizeof(uintptr_t) < available; ++index)
                {
                    if (decode.objectChunk(window[index], *windowAddress + index * sizeof(uintptr_t)) == 0)
                    {
                        stopped = true;
                        break;
                    }
                    prefix = base + static_cast<int32_t>(index) + 1;
                }
                if (stopped || available < bytes)
                    break;
            }
            return std::min(prefix, kMaxChunkIndex);
        }

        bool ReadInt32(const IMemorySource &memory, uintptr_t address, int32_t &value)
        {
            return memory.Read(address, value);
        }

        std::string DescribeRawFields(const IMemorySource &memory, uintptr_t address, int32_t limit = 0x30)
        {
            std::string result;
            for (int32_t offset = 0; offset + static_cast<int32_t>(sizeof(int32_t)) <= limit; offset += 4)
            {
                int32_t value = 0;
                const auto fieldAddress = Add(address, static_cast<uintptr_t>(offset));
                result += " +" + std::to_string(offset) + "=";
                if (fieldAddress && ReadInt32(memory, *fieldAddress, value))
                    result += Hex(static_cast<uint32_t>(value));
                else
                    result += "unreadable";
            }
            return result;
        }

        bool IsReadablePointer(const IMemorySource &memory, uintptr_t pointer)
        {
            return pointer != 0 && memory.IsReadable(pointer, sizeof(uintptr_t));
        }

        bool IsLikelyObject(const IMemorySource &memory, uintptr_t object)
        {
            if (!IsReadablePointer(memory, object))
                return false;
            uintptr_t vtable = 0;
            uintptr_t firstFunction = 0;
            return memory.Read(object, vtable) && IsReadablePointer(memory, vtable) && memory.Read(vtable, firstFunction) &&
                   firstFunction != 0 && memory.IsExecutable(firstFunction, sizeof(uintptr_t));
        }

        // AddSingle/AddRange 先递增 NumElements 再返回索引，调用方随后才填充该槽位；
        // FreeUObjectIndex 只清空槽位，从不回退计数。因此任何已解析对象的槽位必然满足
        // index < NumElements（写入时刻成立，且计数单调不减）。反过来，若在 [count, capacity)
        // 内找到可解析对象，则该 count 不可能是 NumElements。
        // 返回的是采样到的最大已解析下标（-1 表示采样点全空），不是窗口内真实最大值：
        // 采样可能漏判，但不会凭空造出矛盾，所以误判方向只会「漏否决」而不会「假否决」。
        // 返回下标而非直接下结论，是因为调用方必须用「探测之后」重读的 count 比较：
        // 探测期间数组可能继续增长，旧快照会把正常增长误判成矛盾。
        int64_t MaxResolvedIndexAbove(const IMemorySource &memory, const DecodePlan &decode,
                                      uintptr_t storage, int32_t chunkPrefix, int32_t elementsPerChunk,
                                      int32_t stride, bool packed, int32_t objectOffset, int32_t count)
        {
            constexpr int32_t kDenseProbes = 64;
            constexpr int32_t kTailProbes = 8;
            if (chunkPrefix <= 0 || elementsPerChunk <= 0 || count < 0)
                return -1;
            const int64_t capacity = static_cast<int64_t>(chunkPrefix) * elementsPerChunk;
            if (count >= capacity)
                return -1;

            int64_t highest = -1;
            const auto probeIndex = [&](int64_t index)
            {
                if (index < count || index >= capacity)
                    return;
                const int32_t chunkIndex = static_cast<int32_t>(index / elementsPerChunk);
                const int32_t withinChunk = static_cast<int32_t>(index % elementsPerChunk);
                const auto chunkSlot = Scaled(storage, chunkIndex, static_cast<int32_t>(sizeof(uintptr_t)));
                if (!chunkSlot)
                    return;
                uintptr_t rawChunk = 0;
                if (!memory.Read(*chunkSlot, rawChunk))
                    return;
                const uintptr_t chunk = decode.objectChunk(rawChunk, *chunkSlot);
                if (chunk == 0)
                    return;
                const auto item = Scaled(chunk, withinChunk, stride);
                if (!item)
                    return;
                const auto objectSlot = Add(*item, static_cast<uintptr_t>(objectOffset));
                uintptr_t rawObject = 0;
                if (!objectSlot || !memory.Read(*objectSlot, rawObject))
                    return;
                const uintptr_t object = decode.objectPointer(UnpackObjectItemPointer(rawObject, packed), *objectSlot);
                if (object != 0 && IsLikelyObject(memory, object))
                    highest = std::max(highest, index);
            };

            // 密集段抓住紧邻 count 的矛盾；几何与尾段覆盖稀疏空区，
            // 避免 count 远低于真实计数时因一段连续空槽而漏判。总探测数仍有界。
            for (int32_t probe = 0; probe < kDenseProbes; ++probe)
                probeIndex(static_cast<int64_t>(count) + probe);
            for (int64_t step = kDenseProbes; step < capacity; step *= 2)
                probeIndex(static_cast<int64_t>(count) + step);
            for (int32_t probe = 0; probe < kTailProbes; ++probe)
                probeIndex(capacity - 1 - probe);
            return highest;
        }

        // elementsPerChunk 决定了 index -> (chunk, within) 的映射，因此可以只用 item 数据检验：
        // 取 chunk 1 起始处的若干槽位，凡能解析到对象的，其 InternalIndex 必须等于
        // elementsPerChunk + 槽内偏移。若出现不符，则 elementsPerChunk 必错。
        // 窗口内没有可解析对象时返回 false（无法判定，不是反对证据）——本函数只用于否决，
        // 不作为接受依据，所以无法判定时必须放行给下游探针。
        bool ChunkBoundaryContradicted(const IMemorySource &memory, const DecodePlan &decode,
                                       uintptr_t storage, int32_t chunkPrefix, int32_t elementsPerChunk,
                                       int32_t stride, int32_t objectOffset, int32_t indexOffset, bool packed)
        {
            constexpr int32_t kBoundaryProbes = 8;
            if (chunkPrefix < 2 || elementsPerChunk <= 0 || stride <= 0 || indexOffset < 0)
                return false;
            const auto chunkSlot = Scaled(storage, 1, static_cast<int32_t>(sizeof(uintptr_t)));
            if (!chunkSlot)
                return false;
            uintptr_t rawChunk = 0;
            if (!memory.Read(*chunkSlot, rawChunk))
                return false;
            const uintptr_t chunk = decode.objectChunk(rawChunk, *chunkSlot);
            if (chunk == 0)
                return false;
            for (int32_t withinChunk = 0; withinChunk < kBoundaryProbes; ++withinChunk)
            {
                const int32_t index = elementsPerChunk + withinChunk;
                const auto item = Scaled(chunk, withinChunk, stride);
                if (!item)
                    return false;
                const auto objectSlot = Add(*item, static_cast<uintptr_t>(objectOffset));
                uintptr_t rawObject = 0;
                if (!objectSlot || !memory.Read(*objectSlot, rawObject))
                    continue;
                const uintptr_t object = decode.objectPointer(UnpackObjectItemPointer(rawObject, packed), *objectSlot);
                if (object == 0 || !IsLikelyObject(memory, object))
                    continue;
                const auto indexAddress = Add(object, static_cast<uintptr_t>(indexOffset));
                int32_t reported = 0;
                if (!indexAddress || !memory.Read(*indexAddress, reported))
                    continue;
                if (decode.objectIndex(reported, *indexAddress) != index)
                    return true;
            }
            return false;
        }

        void AddUniqueObjectCandidate(std::vector<std::pair<ObjectContainerLayout, double>> &out,
                                      ObjectContainerLayout layout,
                                      double confidence,
                                      int32_t maxCandidates)
        {
            for (const auto &[existing, score] : out)
            {
                // 容量字段偏移也计入身份：仅差 maxElements/maxChunks/numChunks 的候选
                // 在读取器看来是不同的契约，不能互相吞掉
                if (existing.kind == layout.kind && existing.objectsOffset == layout.objectsOffset &&
                    existing.numElementsOffset == layout.numElementsOffset &&
                    existing.maxElementsOffset == layout.maxElementsOffset &&
                    existing.maxChunksOffset == layout.maxChunksOffset &&
                    existing.numChunksOffset == layout.numChunksOffset &&
                    existing.elementsPerChunk == layout.elementsPerChunk &&
                    existing.itemObjectOffset == layout.itemObjectOffset && existing.itemStride == layout.itemStride &&
                    existing.itemIndexOffset == layout.itemIndexOffset && existing.packedPointers == layout.packedPointers)
                    return;
            }
            out.emplace_back(std::move(layout), confidence);
            std::sort(out.begin(), out.end(), [](const auto &left, const auto &right)
                      { return left.second > right.second; });
            if (static_cast<int32_t>(out.size()) > maxCandidates)
                out.resize(static_cast<size_t>(maxCandidates));
        }
    } // namespace

    bool ObjectLayoutDiscovery::ReadPointer(uintptr_t address, uintptr_t &value) const
    {
        return memory_.Read(address, value);
    }

    bool ObjectLayoutDiscovery::ReadItemObject(uintptr_t item,
                                               int32_t objectOffset,
                                               bool packed,
                                               const DecodePlan &decode,
                                               uintptr_t &object) const
    {
        const auto slot = Add(item, static_cast<uintptr_t>(objectOffset));
        if (!slot || !ReadPointer(*slot, object))
            return false;
        object = decode.objectPointer(UnpackObjectItemPointer(object, packed), *slot);
        return object == 0 || IsLikelyObject(memory_, object);
    }

    bool ObjectLayoutDiscovery::DiscoverItemShape(uintptr_t storage,
                                                  bool chunked,
                                                  bool packed,
                                                  int32_t elementsPerChunk,
                                                  const DecodePlan &decode,
                                                  int32_t &objectOffset,
                                                  int32_t &itemStride,
                                                  int32_t &indexOffset,
                                                  double &confidence) const
    {
        uintptr_t firstStorage = storage;
        if (chunked)
        {
            if (!ReadPointer(storage, firstStorage))
                return false;
            firstStorage = decode.objectChunk(firstStorage, storage);
            if (!IsReadablePointer(memory_, firstStorage))
                return false;
        }

        constexpr std::array<int32_t, 8> samples = {1, 4, 8, 20, 50, 100, 250, 500};
        for (int32_t candidateObjectOffset = 0; candidateObjectOffset <= 0x30; candidateObjectOffset += 4)
        {
            for (int32_t candidateStride = 8; candidateStride <= 0x40; candidateStride += 4)
            {
                std::vector<std::pair<int32_t, uintptr_t>> objects;
                for (int32_t index : samples)
                {
                    if (chunked && elementsPerChunk <= 0)
                        continue;
                    const int32_t localIndex = chunked ? index % elementsPerChunk : index;
                    const auto item = Scaled(firstStorage, localIndex, candidateStride);
                    if (!item)
                        continue;
                    uintptr_t object = 0;
                    if (!ReadItemObject(*item, candidateObjectOffset, packed, decode, object) || object == 0)
                        continue;
                    objects.emplace_back(index, object);
                }

                if (objects.size() < 3)
                    continue;

                for (int32_t candidateIndexOffset = 0; candidateIndexOffset <= 0x80 - 4; candidateIndexOffset += 4)
                {
                    size_t matches = 0;
                    for (const auto &[index, object] : objects)
                    {
                        int32_t reported = 0;
                        const auto address = Add(object, static_cast<uintptr_t>(candidateIndexOffset));
                        if (address && ReadInt32(memory_, *address, reported) &&
                            decode.objectIndex(reported, *address) == index)
                            ++matches;
                    }
                    if (matches < 3)
                        continue;

                    objectOffset = candidateObjectOffset;
                    itemStride = candidateStride;
                    indexOffset = candidateIndexOffset;
                    confidence = static_cast<double>(matches) / static_cast<double>(objects.size());
                    return true;
                }
            }
        }
        return false;
    }

    ObjectLayoutDiscoveryResult ObjectLayoutDiscovery::Discover(
        uintptr_t root,
        const DecodePlan &decode,
        int32_t maxCandidates) const
    {
        ObjectLayoutDiscoveryResult result;
        if (root == 0 || maxCandidates <= 0 || !memory_.IsReadable(root, 0x40))
            return result;

        constexpr int32_t headerBytes = 0x40;

        struct Shape
        {
            bool valid = false;
            int32_t objectOffset = -1;
            int32_t stride = -1;
            int32_t indexOffset = -1;
            double confidence = 0;
        };
        std::map<std::tuple<uintptr_t, bool, bool, int32_t>, Shape> shapes;
        const auto shapeFor = [&](uintptr_t storage, bool chunked, bool packed, int32_t elementsPerChunk) -> const Shape &
        {
            const auto key = std::make_tuple(storage, chunked, packed, elementsPerChunk);
            auto [at, inserted] = shapes.try_emplace(key);
            if (inserted)
                at->second.valid = DiscoverItemShape(storage, chunked, packed, elementsPerChunk, decode,
                                                     at->second.objectOffset, at->second.stride,
                                                     at->second.indexOffset, at->second.confidence);
            return at->second;
        };

        constexpr size_t kMaxDiscoveryEvidence = 8;
        size_t chunkEvidence = 0;

        // 每个 storage 的 chunk 表形态只读一次：连续非空前缀数，以及在 header 窗口内
        // 取值等于该前缀数的字段偏移。两者都只依赖 storage，与 count/容量字段无关，
        // 因此可以提到最内层循环之外，避免把偏移枚举乘进组合数。
        struct ChunkFacts
        {
            int32_t prefix = 0;
            std::vector<int32_t> matchingOffsets;
        };
        std::map<uintptr_t, ChunkFacts> chunkFacts;
        const auto chunkFactsFor = [&](uintptr_t storage) -> const ChunkFacts &
        {
            const auto cached = chunkFacts.find(storage);
            if (cached != chunkFacts.end())
                return cached->second;
            ChunkFacts facts;
            facts.prefix = CountChunkPrefix(memory_, storage, decode);
            if (facts.prefix > 0)
            {
                for (int32_t offset = 0; offset <= headerBytes - static_cast<int32_t>(sizeof(int32_t)); offset += 4)
                {
                    int32_t value = 0;
                    if (!ReadInt32(memory_, root + static_cast<uintptr_t>(offset), value))
                        continue;
                    value = decode.objectCount(value, root + static_cast<uintptr_t>(offset));
                    if (value != facts.prefix)
                        continue;
                    facts.matchingOffsets.push_back(offset);
                }
            }
            return chunkFacts.emplace(storage, std::move(facts)).first->second;
        };

        // MaxResolvedIndexAbove 的采样结果只取决于 storage、chunk 几何、item 形状与 count 取值，
        // 与 count/maxElements/maxChunks/numChunks 的偏移无关。缓存后，偏移枚举不会把
        // 采样成本乘进组合数——否则光是 numChunks 偏移的自由枚举就会放大一个数量级。
        std::map<std::tuple<uintptr_t, int32_t, int32_t, int32_t, bool, int32_t>, int64_t> resolvedCache;
        const auto sampledAboveFor = [&](uintptr_t storage, int32_t chunkPrefix, int32_t elementsPerChunk,
                                         const Shape &shape, bool packed, int32_t count) -> int64_t
        {
            const auto key = std::make_tuple(storage, elementsPerChunk, shape.stride, shape.objectOffset, packed, count);
            const auto cached = resolvedCache.find(key);
            if (cached != resolvedCache.end())
                return cached->second;
            const int64_t highest = MaxResolvedIndexAbove(memory_, decode, storage, chunkPrefix, elementsPerChunk,
                                                          shape.stride, packed, shape.objectOffset, count);
            return resolvedCache.emplace(key, highest).first->second;
        };

        for (int32_t pointerOffset = 0; pointerOffset <= headerBytes - static_cast<int32_t>(sizeof(uintptr_t)); pointerOffset += 4)
        {
            uintptr_t rawStorage = 0;
            if (!ReadPointer(root + static_cast<uintptr_t>(pointerOffset), rawStorage))
                continue;
            const uintptr_t storage = decode.objectStorage(rawStorage, root + static_cast<uintptr_t>(pointerOffset));
            if (!IsReadablePointer(memory_, storage))
                continue;

            for (int32_t countOffset = 0; countOffset <= headerBytes - static_cast<int32_t>(sizeof(int32_t)); countOffset += 4)
            {
                int32_t count = 0;
                if (!ReadInt32(memory_, root + static_cast<uintptr_t>(countOffset), count))
                    continue;
                count = decode.objectCount(count, root + static_cast<uintptr_t>(countOffset));
                if (count < 64 || count > 0x08000000)
                    continue;

                const auto &fixedShape = shapeFor(storage, false, false, 0);
                if (fixedShape.valid)
                {
                    ObjectContainerLayout layout;
                    layout.kind = ObjectContainerKind::Fixed;
                    layout.objectsOffset = pointerOffset;
                    layout.numElementsOffset = countOffset;
                    layout.itemObjectOffset = fixedShape.objectOffset;
                    layout.itemStride = fixedShape.stride;
                    layout.itemIndexOffset = fixedShape.indexOffset;
                    AddUniqueObjectCandidate(result.Layouts, std::move(layout), 0.30 + 0.70 * fixedShape.confidence, maxCandidates);
                }

                for (int32_t maxElementsOffset = 0; maxElementsOffset <= headerBytes - static_cast<int32_t>(sizeof(int32_t)); maxElementsOffset += 4)
                {
                    int32_t maxElements = 0;
                    if (!ReadInt32(memory_, root + static_cast<uintptr_t>(maxElementsOffset), maxElements))
                        continue;
                    maxElements = decode.objectCount(maxElements, root + static_cast<uintptr_t>(maxElementsOffset));
                    if (maxElements <= count || maxElements > 0x08000000 || maxElements % 0x1000 != 0)
                        continue;

                    for (int32_t maxChunksOffset = 0; maxChunksOffset <= headerBytes - static_cast<int32_t>(sizeof(int32_t)); maxChunksOffset += 4)
                    {
                        int32_t maxChunks = 0;
                        if (!ReadInt32(memory_, root + static_cast<uintptr_t>(maxChunksOffset), maxChunks))
                            continue;
                        if (maxChunks <= 0 || maxChunks > 0x1000 || maxElements % maxChunks != 0)
                            continue;
                        const int32_t elementsPerChunk = maxElements / maxChunks;
                        // NumChunks 不再是「MaxChunks 的下一个 int32」，而是取窗口内取值等于
                        // chunk 表实测连续非空前缀数的字段；该关系只依赖 chunk 表本身。
                        const ChunkFacts &facts = chunkFactsFor(storage);
                        if (facts.prefix <= 0 || facts.prefix > maxChunks)
                            continue;
                        for (const int32_t numChunksOffset : facts.matchingOffsets)
                        {
                            // 字段必须互不重叠，否则同一段字节会被当成两个语义
                            constexpr int32_t wordSize = static_cast<int32_t>(sizeof(int32_t));
                            constexpr int32_t pointerSize = static_cast<int32_t>(sizeof(uintptr_t));
                            const std::array<int32_t, 5> fieldOffsets = {
                                pointerOffset, countOffset, maxElementsOffset, maxChunksOffset, numChunksOffset};
                            bool distinct = true;
                            for (size_t index = 0; index < fieldOffsets.size() && distinct; ++index)
                            {
                                const int32_t leftSize = index == 0 ? pointerSize : wordSize;
                                for (size_t other = index + 1; other < fieldOffsets.size(); ++other)
                                {
                                    const int32_t rightSize = other == 0 ? pointerSize : wordSize;
                                    distinct = distinct && !Overlaps(fieldOffsets[index], leftSize,
                                                                     fieldOffsets[other], rightSize);
                                }
                            }
                            if (!distinct)
                                continue;

                            for (int packed = 0; packed <= (sizeof(uintptr_t) == 8 ? 1 : 0); ++packed)
                            {
                                const auto &chunkShape = shapeFor(storage, true, packed != 0, elementsPerChunk);
                                if (!chunkShape.valid)
                                    continue;

                                // elementsPerChunk 决定 index -> (chunk, within) 的映射，可用 chunk 1
                                // 起始处对象的 InternalIndex 独立检验；读不到可判定样本时放行给下游探针。
                                if (ChunkBoundaryContradicted(memory_, decode, storage, facts.prefix, elementsPerChunk,
                                                              chunkShape.stride, chunkShape.objectOffset,
                                                              chunkShape.indexOffset, packed != 0))
                                {
                                    if (chunkEvidence < kMaxDiscoveryEvidence)
                                    {
                                        ++chunkEvidence;
                                        result.Evidence.push_back(
                                            "chunked candidate objects=" + std::to_string(pointerOffset) +
                                            " count=" + std::to_string(countOffset) +
                                            " max_elements=" + std::to_string(maxElementsOffset) +
                                            " max_chunks=" + std::to_string(maxChunksOffset) +
                                            " num_chunks=" + std::to_string(numChunksOffset) +
                                            " status=rejected reason=chunk-boundary-contradicted"
                                            " elements_per_chunk=" +
                                            std::to_string(elementsPerChunk));
                                    }
                                    break;
                                }

                                // 计数下界校验：先探测 [count, capacity) 是否已有对象，再重读 count。
                                // 必须用探测后的重读值比较——活进程在探测窗口内仍会分配，
                                // 拿探测前的快照比较会把正常增长判成矛盾。
                                const int64_t highest = sampledAboveFor(
                                    storage, facts.prefix, elementsPerChunk, chunkShape, packed != 0, count);
                                if (highest >= 0)
                                {
                                    int32_t countAfterProbe = 0;
                                    if (!ReadInt32(memory_, root + static_cast<uintptr_t>(countOffset), countAfterProbe))
                                        continue;
                                    countAfterProbe = decode.objectCount(
                                        countAfterProbe, root + static_cast<uintptr_t>(countOffset));
                                    if (highest >= countAfterProbe)
                                    {
                                        if (chunkEvidence < kMaxDiscoveryEvidence)
                                        {
                                            ++chunkEvidence;
                                            result.Evidence.push_back(
                                                "chunked candidate objects=" + std::to_string(pointerOffset) +
                                                " count=" + std::to_string(countOffset) +
                                                " max_elements=" + std::to_string(maxElementsOffset) +
                                                " max_chunks=" + std::to_string(maxChunksOffset) +
                                                " num_chunks=" + std::to_string(numChunksOffset) +
                                                " status=rejected reason=count-boundary-contradicted count=" +
                                                std::to_string(countAfterProbe) +
                                                " resolved_index=" + std::to_string(highest));
                                        }
                                        break;
                                    }
                                }

                                ObjectContainerLayout layout;
                                layout.kind = ObjectContainerKind::Chunked;
                                layout.objectsOffset = pointerOffset;
                                layout.numElementsOffset = countOffset;
                                layout.maxElementsOffset = maxElementsOffset;
                                layout.maxChunksOffset = maxChunksOffset;
                                layout.numChunksOffset = numChunksOffset;
                                layout.elementsPerChunk = elementsPerChunk;
                                layout.itemObjectOffset = chunkShape.objectOffset;
                                layout.itemStride = chunkShape.stride;
                                layout.itemIndexOffset = chunkShape.indexOffset;
                                layout.packedPointers = packed != 0;
                                // 该候选的五个字段位置由 chunk 表实测前缀数与 item 索引一致性判定，
                                // 不依赖引擎声明顺序；下游探针据此跳过固定字段顺序检查，改走数值校验。
                                // 计数下界判据在采样点全空时无法否决，此时本标志仅表示「未发现反证」，
                                // 接受与否仍由下游探针的 valid/confidence 门槛决定。
                                layout.chunkFieldsValidated = true;
                                AddUniqueObjectCandidate(result.Layouts, std::move(layout),
                                                         0.35 + 0.65 * chunkShape.confidence, maxCandidates);
                                if (chunkEvidence < kMaxDiscoveryEvidence)
                                {
                                    ++chunkEvidence;
                                    result.Evidence.push_back(
                                        "chunked candidate objects=" + std::to_string(pointerOffset) +
                                        " count=" + std::to_string(countOffset) +
                                        " max_elements=" + std::to_string(maxElementsOffset) +
                                        " max_chunks=" + std::to_string(maxChunksOffset) +
                                        " num_chunks=" + std::to_string(numChunksOffset) +
                                        " chunk_prefix=" + std::to_string(facts.prefix) +
                                        " elements_per_chunk=" + std::to_string(elementsPerChunk) +
                                        " item_stride=" + std::to_string(chunkShape.stride) +
                                        " status=accepted");
                                }
                            }
                        }
                    }
                }
            }
        }
        return result;
    }

    StandardObjectLayoutResult ObjectLayoutDiscovery::DiscoverStandard(uintptr_t root,
                                                                       RootTarget target,
                                                                       const DecodePlan &decode,
                                                                       int32_t maxCandidates) const
    {
        StandardObjectLayoutResult result;
        if (root == 0 || maxCandidates <= 0)
            return result;

        std::vector<int32_t> chunkOffsets;
        switch (target)
        {
        case RootTarget::ObjObjects:
            chunkOffsets = {0};
            break;
        case RootTarget::GUObjectArray:
            chunkOffsets = {16, 24, 0, 32};
            break;
        case RootTarget::Unknown:
            chunkOffsets = {0, 16, 24};
            break;
        case RootTarget::NamePool:
            return result;
        }

        constexpr int32_t kElementsPerChunk = 64 * 1024;
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
        constexpr std::array<int32_t, 16> kSamples = {0, 1, 2, 4, 8, 16, 32, 64,
                                                      128, 256, 512, 1024, 2048, 4096, 8192, 16384};

        struct Shape
        {
            int32_t stride = 0;
            int32_t indexOffset = 0;
            int32_t tested = 0;
            int32_t empty = 0;
            int32_t valid = 0;
            double confidence = 0.0;
        };

        for (const int32_t chunkOffset : chunkOffsets)
        {
            const auto chunkArray = Add(root, static_cast<uintptr_t>(chunkOffset));
            if (!chunkArray)
                continue;
            const std::string rootPrefix = "root=" + Hex(root) + " target=" + RootTargetName(target) +
                                           " chunk_offset=" + std::to_string(chunkOffset);
            uintptr_t rawObjects = 0;
            if (!ReadPointer(*chunkArray, rawObjects))
            {
                result.Evidence.push_back(rootPrefix + " status=rejected reason=objects-field-unreadable raw=" +
                                          DescribeRawFields(memory_, *chunkArray));
                continue;
            }
            const uintptr_t objects = decode.objectStorage(rawObjects, *chunkArray);
            if (!IsReadablePointer(memory_, objects))
            {
                result.Evidence.push_back(rootPrefix + " objects=" + Hex(objects) +
                                          " status=rejected reason=chunk-table-unreadable raw=" +
                                          DescribeRawFields(memory_, *chunkArray));
                continue;
            }

            for (const FieldLayout &fieldLayout : kFieldLayouts)
            {
                const auto maxAddress = Add(*chunkArray, static_cast<uintptr_t>(fieldLayout.maxElements));
                const auto countAddress = Add(*chunkArray, static_cast<uintptr_t>(fieldLayout.count));
                const auto maxChunksAddress = Add(*chunkArray, static_cast<uintptr_t>(fieldLayout.maxChunks));
                const auto numChunksAddress = Add(*chunkArray, static_cast<uintptr_t>(fieldLayout.numChunks));
                int32_t rawMax = 0;
                int32_t rawCount = 0;
                int32_t rawMaxChunks = 0;
                int32_t rawNumChunks = 0;
                if (!maxAddress || !countAddress || !maxChunksAddress || !numChunksAddress ||
                    !ReadInt32(memory_, *maxAddress, rawMax) || !ReadInt32(memory_, *countAddress, rawCount) ||
                    !ReadInt32(memory_, *maxChunksAddress, rawMaxChunks) ||
                    !ReadInt32(memory_, *numChunksAddress, rawNumChunks))
                {
                    result.Evidence.push_back(rootPrefix + " field_layout=" + fieldLayout.name +
                                              " status=rejected reason=field-unreadable raw=" +
                                              DescribeRawFields(memory_, *chunkArray));
                    continue;
                }
                const int32_t maxElements = decode.objectCount(rawMax, *maxAddress);
                const int32_t count = decode.objectCount(rawCount, *countAddress);
                const int32_t maxChunks = decode.objectCount(rawMaxChunks, *maxChunksAddress);
                const int32_t numChunks = decode.objectCount(rawNumChunks, *numChunksAddress);

                std::string prefix = "root=" + Hex(root) + " target=" + RootTargetName(target) +
                                     " chunk_offset=" + std::to_string(chunkOffset) +
                                     " field_layout=" + fieldLayout.name +
                                     " objects=" + Hex(objects) +
                                     " count=" + std::to_string(count) +
                                     " max_elements=" + std::to_string(maxElements) +
                                     " max_chunks=" + std::to_string(maxChunks) +
                                     " num_chunks=" + std::to_string(numChunks);
                if (count < 64 || count > 0x08000000 || maxElements < count || maxElements > 0x08000000 ||
                    maxChunks <= 0 || maxChunks > 0x1000 || numChunks <= 0 || numChunks > maxChunks)
                {
                    result.Evidence.push_back(prefix + " status=rejected reason=field-relations");
                    continue;
                }

                std::vector<int32_t> elementsPerChunkValues = {kElementsPerChunk};
                if (maxElements % maxChunks == 0)
                {
                    const int32_t derived = maxElements / maxChunks;
                    if (derived != kElementsPerChunk && derived >= 0x1000 && derived <= 0x200000)
                        elementsPerChunkValues.push_back(derived);
                }

                for (const int32_t elementsPerChunk : elementsPerChunkValues)
                {
                    if (elementsPerChunk <= 0 || maxElements % elementsPerChunk != 0 ||
                        maxElements / elementsPerChunk != maxChunks ||
                        static_cast<int64_t>(numChunks) * elementsPerChunk < count)
                        continue;

                    std::vector<Shape> shapes;
                    for (const int32_t stride : {24, 16, 32})
                    {
                        for (const int32_t indexOffset : {12, 36})
                        {
                            Shape shape;
                            shape.stride = stride;
                            shape.indexOffset = indexOffset;
                            const auto validateIndex = [&](int32_t index)
                            {
                                if (index < 0 || index >= count)
                                    return;
                                ++shape.tested;
                                const int32_t chunkIndex = index / elementsPerChunk;
                                const int32_t withinChunk = index % elementsPerChunk;
                                if (chunkIndex >= numChunks)
                                    return;
                                const auto chunkSlot = Scaled(objects, chunkIndex, static_cast<int32_t>(sizeof(uintptr_t)));
                                if (!chunkSlot)
                                    return;
                                uintptr_t rawChunk = 0;
                                if (!ReadPointer(*chunkSlot, rawChunk))
                                    return;
                                const uintptr_t chunk = decode.objectChunk(rawChunk, *chunkSlot);
                                if (chunk == 0 || !memory_.IsReadable(chunk, sizeof(uintptr_t)))
                                    return;
                                const auto itemAddress = Scaled(chunk, withinChunk, stride);
                                if (!itemAddress)
                                    return;
                                uintptr_t rawObject = 0;
                                if (!ReadPointer(*itemAddress, rawObject))
                                    return;
                                const uintptr_t object = decode.objectPointer(rawObject, *itemAddress);
                                if (object == 0)
                                {
                                    ++shape.empty;
                                    return;
                                }
                                if (!IsLikelyObject(memory_, object))
                                    return;
                                const auto indexAddress = Add(object, static_cast<uintptr_t>(indexOffset));
                                int32_t reportedIndex = 0;
                                if (!indexAddress || !ReadInt32(memory_, *indexAddress, reportedIndex) ||
                                    decode.objectIndex(reportedIndex, *indexAddress) != index)
                                    return;

                                const auto classAddress = Add(object, 16);
                                const auto nameAddress = Add(object, 24);
                                const auto displayAddress = Add(object, 28);
                                const auto numberAddress = Add(object, 32);
                                uintptr_t classPointer = 0;
                                int32_t comparisonIndex = 0;
                                int32_t displayIndex = 0;
                                int32_t number = 0;
                                if (!classAddress || !nameAddress || !displayAddress || !numberAddress ||
                                    !ReadPointer(*classAddress, classPointer) ||
                                    !ReadInt32(memory_, *nameAddress, comparisonIndex) ||
                                    !ReadInt32(memory_, *displayAddress, displayIndex) ||
                                    !ReadInt32(memory_, *numberAddress, number))
                                    return;
                                if (classPointer == 0 || !IsLikelyObject(memory_, classPointer))
                                    return;
                                if (comparisonIndex == 0 && displayIndex == 0)
                                    return;
                                const auto classDisplay = Add(classPointer, 28);
                                int32_t classDisplayIndex = 0;
                                if (!classDisplay || !ReadInt32(memory_, *classDisplay, classDisplayIndex))
                                    return;

                                const auto outer32 = Add(object, 32);
                                const auto outer36 = Add(object, 36);
                                bool outerValid = false;
                                for (const auto &outerAddress : {outer36, outer32})
                                {
                                    if (!outerAddress)
                                        continue;
                                    uintptr_t outer = 0;
                                    if (ReadPointer(*outerAddress, outer) && (outer == 0 || IsLikelyObject(memory_, outer)))
                                    {
                                        outerValid = true;
                                        break;
                                    }
                                }
                                if (!outerValid)
                                    return;
                                ++shape.valid;
                            };

                            for (const int32_t index : kSamples)
                                validateIndex(index);
                            const std::array<int32_t, 6> tailSamples = {
                                count - 1, count / 2, std::min(count - 1, elementsPerChunk - 1),
                                std::min(count - 1, elementsPerChunk), std::min(count - 1, 2 * elementsPerChunk - 1),
                                std::min(count - 1, 2 * elementsPerChunk)};
                            for (const int32_t index : tailSamples)
                                validateIndex(index);

                            const int32_t nonEmpty = shape.tested - shape.empty;
                            shape.confidence = nonEmpty > 0 ? static_cast<double>(shape.valid) / nonEmpty : 0.0;
                            if (shape.valid >= 5 && nonEmpty >= 5 && shape.confidence >= 0.80)
                                shapes.push_back(shape);
                        }
                    }

                    prefix += " elements_per_chunk=" + std::to_string(elementsPerChunk);
                    if (shapes.empty())
                    {
                        result.Evidence.push_back(prefix + " status=rejected reason=no-consistent-item-shape");
                        continue;
                    }
                    std::sort(shapes.begin(), shapes.end(), [](const Shape &left, const Shape &right)
                              {
                                  if ((left.indexOffset == 12) != (right.indexOffset == 12))
                                      return left.indexOffset == 12;
                                  if (left.valid != right.valid)
                                      return left.valid > right.valid;
                                  return left.confidence > right.confidence; });
                    const Shape &best = shapes.front();
                    ObjectContainerLayout layout;
                    layout.kind = ObjectContainerKind::Chunked;
                    layout.objectsOffset = chunkOffset;
                    layout.maxElementsOffset = chunkOffset + fieldLayout.maxElements;
                    layout.numElementsOffset = chunkOffset + fieldLayout.count;
                    layout.maxChunksOffset = chunkOffset + fieldLayout.maxChunks;
                    layout.numChunksOffset = chunkOffset + fieldLayout.numChunks;
                    layout.elementsPerChunk = elementsPerChunk;
                    layout.itemObjectOffset = 0;
                    layout.itemStride = best.stride;
                    layout.itemIndexOffset = best.indexOffset;
                    layout.packedPointers = false;
                    layout.chunkFieldsValidated = true;
                    if (!layout.IsValid())
                    {
                        result.Evidence.push_back(prefix + " status=rejected reason=layout-invalid");
                        continue;
                    }
                    AddUniqueObjectCandidate(result.Layouts, layout, 0.90 + 0.10 * best.confidence, maxCandidates);
                    result.Evidence.push_back(prefix + " item_stride=" + std::to_string(best.stride) +
                                              " item_index=" + std::to_string(best.indexOffset) +
                                              " valid=" + std::to_string(best.valid) +
                                              " tested=" + std::to_string(best.tested) +
                                              " empty=" + std::to_string(best.empty) +
                                              " confidence=" + std::to_string(best.confidence) +
                                              " status=accepted");
                }
            }
        }
        return result;
    }

    bool NameLayoutDiscovery::ReadPointer(uintptr_t address, uintptr_t &value) const
    {
        return memory_.Read(address, value);
    }

    bool NameLayoutDiscovery::ReadPoolEntry(uintptr_t entry,
                                            const NamePoolLayout &layout,
                                            const DecodePlan &decode,
                                            std::string &name) const
    {
        uint16_t header = 0;
        const uintptr_t headerAddress = entry + static_cast<uintptr_t>(layout.entryHeaderOffset);
        if (!memory_.Read(headerAddress, header))
            return false;
        header = decode.nameHeader(header, headerAddress);
        const int32_t length = static_cast<int32_t>(header >> layout.entryLengthShift);
        if (length != 4 || (header & layout.entryWideMask) != 0)
            return false;
        std::array<uint8_t, 4> text{};
        const uintptr_t stringAddress = entry + static_cast<uintptr_t>(layout.entryStringOffset);
        if (!memory_.ReadBytes(stringAddress, text.data(), text.size()).Ok() ||
            !decode.nameText(text, stringAddress, false))
            return false;
        name.assign(reinterpret_cast<const char *>(text.data()), text.size());
        return true;
    }

    std::vector<std::pair<NameContainerLayout, double>> NameLayoutDiscovery::Discover(
        uintptr_t root,
        const DecodePlan &decode,
        int32_t maxCandidates) const
    {
        std::vector<std::pair<NameContainerLayout, double>> result;
        if (root == 0 || maxCandidates <= 0 || !memory_.IsReadable(root, 0x100))
            return result;

        for (int32_t pointerOffset = 0; pointerOffset <= 0x100 - static_cast<int32_t>(sizeof(uintptr_t)); pointerOffset += 4)
        {
            uintptr_t raw = 0;
            if (!ReadPointer(root + static_cast<uintptr_t>(pointerOffset), raw))
                continue;

            const uintptr_t target = decode.nameBlocks(raw, root + static_cast<uintptr_t>(pointerOffset));
            if (!IsReadablePointer(memory_, target))
                continue;

            for (int32_t stringOffset : {2, 4, 6, 8})
            {
                for (int32_t headerOffset : {0, 2, 4})
                {
                    if (headerOffset + 2 > stringOffset)
                        continue;
                    for (int32_t shift = 0; shift < 16; ++shift)
                    {
                        if ((static_cast<uint16_t>(4) << shift) == 0)
                            continue;
                        for (int32_t stride : {2, 4})
                        {
                            // 0x10 是 UE 标准块大小，厂商变体只在其不通过校验时才有机会
                            // 每个组合只采用首个通过的候选，重复布局会让下游探针判定为歧义并整体拒绝
                            for (int32_t blocksBit : {0x10, 0x0e, 0x12})
                            {
                                NamePoolLayout pool;
                                pool.blocksOffset = pointerOffset;
                                pool.blocksBit = blocksBit;
                                pool.entryStride = stride;
                                pool.entryHeaderOffset = headerOffset;
                                pool.entryStringOffset = stringOffset;
                                pool.entryLengthShift = shift;
                                pool.entryWideMask = 1;
                                const uintptr_t table = root + static_cast<uintptr_t>(pointerOffset);
                                if (table >= 8 && memory_.IsReadable(table - 8, 8))
                                {
                                    uint32_t block = 0;
                                    uint32_t cursor = 0;
                                    const size_t blockSize = (size_t{1} << pool.blocksBit) * stride;
                                    if (memory_.Read(table - 8, block) && memory_.Read(table - 4, cursor) &&
                                        block < 8192 && cursor <= blockSize && cursor % static_cast<uint32_t>(stride) == 0)
                                    {
                                        pool.currentBlockFromBlocks = -8;
                                        pool.byteCursorFromBlocks = -4;
                                    }
                                }
                                std::string name;
                                if (!ReadPoolEntry(target, pool, decode, name) || name != "None")
                                    continue;
                                NameContainerLayout layout;
                                layout.kind = NameContainerKind::Pool;
                                layout.pool = pool;
                                result.emplace_back(std::move(layout), 0.90);
                                if (static_cast<int32_t>(result.size()) >= maxCandidates)
                                    return result;
                                break;
                            }
                        }
                    }
                }
            }
        }

        for (int32_t chunksOffset = 0; chunksOffset <= 0x100 - static_cast<int32_t>(sizeof(uintptr_t)); chunksOffset += 4)
        {
            const uintptr_t chunksAddress = root + static_cast<uintptr_t>(chunksOffset);
            uintptr_t rawChunk = 0;
            if (!ReadPointer(chunksAddress, rawChunk))
                continue;
            const uintptr_t chunk = decode.nameChunks(rawChunk, chunksAddress);
            if (!IsReadablePointer(memory_, chunk))
                continue;
            uintptr_t rawEntry = 0;
            if (!ReadPointer(chunk, rawEntry))
                continue;
            const uintptr_t entry = decode.nameEntry(rawEntry, chunk);
            if (!IsReadablePointer(memory_, entry))
                continue;

            int32_t stringOffset = -1;
            for (int32_t offset = 0; offset <= 0x20 - 4; offset += 2)
            {
                std::array<uint8_t, 4> text{};
                const uintptr_t stringAddress = entry + static_cast<uintptr_t>(offset);
                if (memory_.ReadBytes(stringAddress, text.data(), text.size()).Ok() &&
                    decode.nameText(text, stringAddress, false) &&
                    std::memcmp(text.data(), "None", 4) == 0)
                {
                    stringOffset = offset;
                    break;
                }
            }
            if (stringOffset < 0)
                continue;

            int32_t indexOffset = -1;
            for (int32_t offset = 0; offset <= stringOffset; offset += 4)
            {
                int32_t indexValue = 0;
                if (!memory_.Read(entry + static_cast<uintptr_t>(offset), indexValue))
                    continue;
                indexValue = static_cast<int32_t>(decode.nameEntryIndex(static_cast<uint32_t>(indexValue), entry + static_cast<uintptr_t>(offset)) >> 1);
                if (indexValue == 0)
                {
                    indexOffset = offset;
                    break;
                }
            }
            if (indexOffset < 0)
                continue;

            NameArrayLayout array;
            array.chunksOffset = chunksOffset;
            array.elementsPerChunk = 0x4000;
            array.entryIndexOffset = indexOffset;
            array.entryStringOffset = stringOffset;
            NameContainerLayout layout;
            layout.kind = NameContainerKind::Array;
            layout.array = array;
            result.emplace_back(std::move(layout), 0.80);
            if (static_cast<int32_t>(result.size()) >= maxCandidates)
                break;
        }
        return result;
    }
} // namespace nextdumper::binding
