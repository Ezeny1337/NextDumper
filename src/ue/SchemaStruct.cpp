#include "ProbeContext.hpp"

#include <array>
#include <cstring>

#include "nextdumper/common/Hex.hpp"

namespace nextdumper::ue::schema_probe
{
    using ::nextdumper::common::Hex;

    bool SchemaProbeContext::ResolveStructSchema(EngineSchema &schema, SchemaResolutionReport &report) const
    {
        const auto guid = FindObjectByName(schema, names_.guidStruct);
        const auto color = FindObjectByName(schema, names_.colorStruct);
        const auto vector = FindObjectByName(schema, names_.vectorStruct);
        if (!guid || !color || !vector)
        {
            report.failures.push_back("reflection samples unavailable: Guid=" + std::string(guid ? "yes" : "no") +
                                      " Color=" + std::string(color ? "yes" : "no") +
                                      " Vector=" + std::string(vector ? "yes" : "no"));
            return false;
        }

        // FVector 的大小由 FLargeWorldCoordinatesReal 决定，而该类型受构建配置影响不能只根据 UE 主版本决定
        // 优先尝试 profile 的预期值，同时保留另一种 ABI变体，避免把 LWC 当成版本事实
        const std::array<int32_t, 2> vectorSizes = schema.features.largeWorldCoordinates
                                                       ? std::array<int32_t, 2>{0x18, 0x0C}
                                                       : std::array<int32_t, 2>{0x0C, 0x18};
        struct StructSizeCandidate
        {
            int32_t offset = -1;
            int32_t vectorSize = 0;
        };
        std::vector<StructSizeCandidate> sizeCandidates;
        for (int32_t offset = 0; offset <= 0x100 - 4; offset += 4)
        {
            for (const int32_t vectorSize : vectorSizes)
            {
                const std::array<std::pair<uintptr_t, int32_t>, 3> knownSizes = {
                    std::pair{*guid, 0x10}, std::pair{*color, 0x04}, std::pair{*vector, vectorSize}};
                bool matches = true;
                for (const auto &[object, expected] : knownSizes)
                {
                    int32_t actual = 0;
                    const auto address = Add(object, offset);
                    if (!address || !memory_.Read(*address, actual) || actual != expected)
                    {
                        matches = false;
                        break;
                    }
                }
                if (matches)
                    sizeCandidates.push_back({offset, vectorSize});
            }
        }
        if (!sizeCandidates.empty())
        {
            if (sizeCandidates.size() > 1)
            {
                report.ambiguous = true;
                report.failures.push_back("UStruct::PropertiesSize candidates are ambiguous across FVector layouts; candidates=" +
                                          std::to_string(sizeCandidates.size()));
                return false;
            }
            schema.ustruct.propertiesSizeOffset = sizeCandidates.front().offset;
            schema.features.largeWorldCoordinates = sizeCandidates.front().vectorSize == 0x18;
            report.evidence.push_back("resolved UStruct::PropertiesSize; offset=" +
                                      std::to_string(schema.ustruct.propertiesSizeOffset) +
                                      " guid_size=16 color_size=4 vector_size=" +
                                      std::to_string(sizeCandidates.front().vectorSize) +
                                      " candidates=" + std::to_string(sizeCandidates.size()));
            report.versionEvidence.push_back({"large-world-coordinates",
                                              sizeCandidates.front().vectorSize == 0x18 ? "FVector.size=24" : "FVector.size=12",
                                              VersionEvidenceStrength::Strong,
                                              "observed from Guid/Color/Vector UStruct::PropertiesSize samples"});
        }
        if (schema.ustruct.propertiesSizeOffset < 0)
        {
            report.failures.push_back("UStruct::PropertiesSize was not resolved from Guid/Color/Vector size variants");
            return false;
        }

        // 源码变体将 int16/int32 的 MinAlignment 置于 PropertiesSize 之后
        // 高位为零的小值无法确立成员宽度
        if (!sizeCandidates.empty())
        {
            const int32_t alignmentOffset = sizeCandidates.front().offset + 4;
            const std::array<std::pair<uintptr_t, int32_t>, 3> alignmentSamples = {
                std::pair{*guid, 16}, std::pair{*color, 4},
                std::pair{*vector, sizeCandidates.front().vectorSize}};
            for (const int32_t width : {2, 4})
            {
                std::string evidence = "UStruct alignment candidate: offset=" + std::to_string(alignmentOffset) +
                                       " width=" + std::to_string(width) +
                                       " selected=0 sample_encoding=address/struct_size/raw/read_error/transferred samples=";
                bool allPlausible = true;
                for (size_t index = 0; index < alignmentSamples.size(); ++index)
                {
                    const auto &[object, size] = alignmentSamples[index];
                    const auto address = Add(object, alignmentOffset);
                    int32_t raw = 0;
                    int16_t shortRaw = 0;
                    std::array<uint8_t, 4> bytes{};
                    const auto read = address && memory_.IsReadable(*address, static_cast<size_t>(width))
                                          ? memory_.ReadBytes(*address, bytes.data(), static_cast<size_t>(width))
                                          : ::nextdumper::memory::ReadResult{
                                                ::nextdumper::memory::ReadError::UnreadableRange,
                                                address.value_or(0), static_cast<size_t>(width), 0};
                    const bool readable = read.Ok();
                    if (width == 2)
                    {
                        std::memcpy(&shortRaw, bytes.data(), sizeof(shortRaw));
                        raw = shortRaw;
                    }
                    else
                        std::memcpy(&raw, bytes.data(), sizeof(raw));
                    const bool plausible = readable && raw > 0 && raw <= size &&
                                           (raw & (raw - 1)) == 0 && size % raw == 0;
                    allPlausible = allPlausible && plausible;
                    if (index != 0)
                        evidence += ",";
                    evidence += Hex(object) + "/" + std::to_string(size) + "/" +
                                (readable ? std::to_string(raw) : "unreadable") + "/" +
                                std::to_string(static_cast<int>(read.error)) + "/" + std::to_string(read.transferred);
                }
                report.evidence.push_back(evidence + " all_plausible=" + std::to_string(allPlausible) +
                                          " basis=after-validated-properties-size; no-independent-width-proof");
            }
        }

        const auto structObject = FindObjectByName(schema, names_.structClass);
        const auto fieldObject = FindObjectByName(schema, names_.fieldClass);
        if (structObject && fieldObject &&
            FindPointerField(*structObject, *fieldObject, static_cast<int32_t>(sizeof(uintptr_t)), 0x100, schema.ustruct.superStruct))
        {
            report.evidence.push_back("resolved UStruct::SuperStruct from Struct -> Field relation; PropertiesSize offset=" +
                                      std::to_string(schema.ustruct.propertiesSizeOffset));
        }
        else
        {
            report.failures.push_back("UStruct::SuperStruct was not resolved");
            return false;
        }

        // Children/ChildProperties 在下一阶段通过链式语义解析
        // 对齐候选仅作为证据保留，绝不作为选定的目标 ABI
        schema.ustruct.children = -1;
        schema.ustruct.childProperties = -1;
        schema.ustruct.minAlignment = -1;
        schema.validation.structs = true;
        report.evidence.push_back(schema.features.useFProperty ? "FProperty struct schema selected" : "UProperty struct schema selected");
        return true;
    }
} // namespace nextdumper::ue::schema_probe
