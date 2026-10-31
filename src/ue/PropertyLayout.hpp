#pragma once

#include <algorithm>
#include <array>
#include <optional>
#include <vector>

#include "nextdumper/ue/EngineSchema.hpp"

namespace nextdumper::ue::schema_probe
{
    struct PropertyTailCandidate
    {
        PropertyTailLayout layout = PropertyTailLayout::UProperty;
        // Offset_Internal 之后、RepNotifyFunc 之前的额外字节数
        int32_t padding = 0;
        int32_t repNotify = -1;
        int32_t links = -1;
        int32_t linksEnd = -1;
        int32_t dataEnd = -1;
        int32_t completeSize = -1;
    };

    inline std::optional<int32_t> AlignMember(int32_t offset, int32_t alignment)
    {
        if (offset < 0 || alignment <= 0 || offset > INT32_MAX - alignment + 1)
            return std::nullopt;
        return (offset + alignment - 1) / alignment * alignment;
    }

    inline const char *PropertyTailName(PropertyTailLayout layout)
    {
        switch (layout)
        {
        case PropertyTailLayout::UProperty:
            return "uproperty";
        case PropertyTailLayout::RepNotifyBeforeLinks:
            return "repnotify-before-links";
        case PropertyTailLayout::LinksBeforeRepNotify:
            return "links-before-repnotify";
        case PropertyTailLayout::Unknown:
            return "unknown";
        }
        return "unknown";
    }

    // Offset_Internal 之后可能存在的额外成员宽度
    // 厂商改造会在尾部插入字段，使 RepNotifyFunc 与链接槽整体后移
    // 判定由 EvaluateTail 依据链接槽能否解析成合法 FProperty 给出，这里只负责枚举有界起点
    inline constexpr std::array<int32_t, 3> kPropertyTailPaddings{0, 8, 16};

    // 已验证 Offset_Internal 吸收了 metadata/IndexInOwner 等前缀差异
    // 逐成员对齐并区分 data-end 与 sizeof，派生 bool 可以使用基类尾部填充
    inline std::vector<PropertyTailCandidate> PropertyTails(const EngineSchema &schema)
    {
        std::vector<PropertyTailCandidate> result;
        if (schema.property.offsetInternal < 0 || schema.property.offsetInternal > 0x120 ||
            (schema.fname.size != 4 && schema.fname.size != 8 && schema.fname.size != 12))
            return result;
        const int32_t pointer = static_cast<int32_t>(sizeof(uintptr_t));
        const int32_t pointerAlignment = static_cast<int32_t>(alignof(uintptr_t));
        const int32_t nameAlignment = static_cast<int32_t>(alignof(uint32_t));
        const int32_t baseAlignment = std::max(pointerAlignment, static_cast<int32_t>(alignof(uint64_t)));
        const int32_t first = schema.property.offsetInternal + static_cast<int32_t>(sizeof(int32_t));
        for (auto order : {PropertyTailLayout::UProperty, PropertyTailLayout::RepNotifyBeforeLinks,
                           PropertyTailLayout::LinksBeforeRepNotify})
        {
            if ((!schema.features.useFProperty && order != PropertyTailLayout::UProperty) ||
                (schema.features.useFProperty && order == PropertyTailLayout::UProperty))
                continue;
            for (const int32_t padding : kPropertyTailPaddings)
            {
                const int32_t start = first + padding;
                if (start > 0x120)
                    continue;
                PropertyTailCandidate candidate;
                candidate.layout = order;
                candidate.padding = padding;
                if (order == PropertyTailLayout::LinksBeforeRepNotify)
                {
                    candidate.links = *AlignMember(start, pointerAlignment);
                    candidate.linksEnd = candidate.links + 4 * pointer;
                    candidate.repNotify = *AlignMember(candidate.linksEnd, nameAlignment);
                    candidate.dataEnd = candidate.repNotify + schema.fname.size;
                }
                else
                {
                    candidate.repNotify = *AlignMember(start, nameAlignment);
                    candidate.links = *AlignMember(candidate.repNotify + schema.fname.size, pointerAlignment);
                    candidate.linksEnd = candidate.links + 4 * pointer;
                    candidate.dataEnd = candidate.linksEnd;
                }
                candidate.completeSize = *AlignMember(candidate.dataEnd, baseAlignment);
                result.push_back(candidate);
            }
        }
        return result;
    }
} // namespace nextdumper::ue::schema_probe
