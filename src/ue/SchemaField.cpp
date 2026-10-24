#include "ProbeContext.hpp"

#include <array>

namespace nextdumper::ue::schema_probe
{
    bool SchemaProbeContext::ResolveFieldSchema(EngineSchema &schema, SchemaResolutionReport &report) const
    {
        if (!schema.features.useFProperty)
        {
            const auto guid = FindObjectByName(schema, names_.guidStruct);
            const auto color = FindObjectByName(schema, names_.colorStruct);
            if (!guid || !color)
            {
                report.failures.push_back("UProperty samples are unavailable");
                return false;
            }

            NameStoreReader names(memory_, binding_.nameRoot.address, binding_.names, binding_.decode,
                                  schema.fname, schema.features);
            const auto readObjectName = [&](uintptr_t object)
            { return ReadObjectName(memory_, binding_, schema, names, object); };

            const auto findChildren = [&](uintptr_t structure) -> std::optional<int32_t>
            {
                size_t readablePointerCandidates = 0;
                size_t namedCandidates = 0;
                std::string candidateNames;
                int32_t selectedOffset = -1;
                for (int32_t offset = 0x20; offset <= 0x100; offset += 4)
                {
                    uintptr_t field = 0;
                    const auto address = Add(structure, offset);
                    if (!address || !memory_.Read(*address, field) || !IsReadablePointer(memory_, field))
                        continue;
                    ++readablePointerCandidates;
                    const auto fieldName = readObjectName(field);
                    if (fieldName && (*fieldName == "A" || *fieldName == "B" || *fieldName == "C" ||
                                      *fieldName == "D" || *fieldName == "R"))
                    {
                        ++namedCandidates;
                        if (candidateNames.empty())
                            candidateNames = " offset=" + std::to_string(offset) + " name=" + *fieldName;
                        if (selectedOffset < 0)
                            selectedOffset = offset;
                    }
                }
                if (selectedOffset < 0)
                    report.evidence.push_back("UProperty Children probe failed; readable_pointer_candidates=" +
                                              std::to_string(readablePointerCandidates) +
                                              " named_candidates=" + std::to_string(namedCandidates) +
                                              " first_candidate=" + (candidateNames.empty() ? "none" : candidateNames));
                else
                    report.evidence.push_back("UProperty Children probe candidate; readable_pointer_candidates=" +
                                              std::to_string(readablePointerCandidates) +
                                              " named_candidates=" + std::to_string(namedCandidates) +
                                              " selected_candidate=" + std::to_string(selectedOffset) +
                                              " first_candidate=" + candidateNames);
                if (selectedOffset >= 0)
                    return selectedOffset;
                if (selectedOffset < 0)
                    report.evidence.push_back("UProperty Children probe failed; no named candidate selected");
                return std::nullopt;
            };

            const auto children = findChildren(*guid);
            if (!children)
            {
                report.failures.push_back("UStruct::Children was not resolved for UProperty");
                return false;
            }
            schema.ustruct.children = *children;

            uintptr_t firstField = 0;
            if (!memory_.Read(*Add(*guid, *children), firstField))
                return false;
            const int32_t nextStart = schema.uobject.outer >= 0
                                          ? schema.uobject.outer + static_cast<int32_t>(sizeof(uintptr_t))
                                          : 0x20;
            for (int32_t offset = nextStart; offset <= 0x80; offset += 4)
            {
                uintptr_t next = 0;
                const auto address = Add(firstField, offset);
                if (!address || !memory_.Read(*address, next))
                    continue;
                const auto nextName = readObjectName(next);
                if (nextName && (*nextName == "B" || *nextName == "C"))
                {
                    schema.ufield.next = offset;
                    break;
                }
            }
            if (schema.ufield.next < 0)
            {
                report.failures.push_back("UField::Next was not resolved");
                return false;
            }
            schema.validation.fields = true;
            report.evidence.push_back("UProperty family does not require FField runtime schema");
            return true;
        }

        const auto guid = FindObjectByName(schema, names_.guidStruct);
        if (!guid)
        {
            report.failures.push_back("FProperty Guid sample is unavailable");
            return false;
        }
        NameStoreReader names(memory_, binding_.nameRoot.address, binding_.names, binding_.decode,
                              schema.fname, schema.features);

        const auto readFieldName = [&](uintptr_t field, int32_t nameOffset)
        { return ReadFieldName(memory_, binding_, names, field, nameOffset); };

        const int32_t pointerSize = static_cast<int32_t>(sizeof(uintptr_t));
        const bool taggedOwner = schema.features.fFieldOwnerEncoding == FFieldOwnerEncoding::TaggedPointer;
        const int32_t ownerStorageSize = taggedOwner ? pointerSize : pointerSize * 2;
        const int32_t fnameSize = schema.fname.size > 0 ? schema.fname.size : pointerSize;
        const std::array<int32_t, 7> nameOffsets = pointerSize == 4
                                                       ? std::array<int32_t, 7>{taggedOwner ? 0x10 : 0x14,
                                                                                taggedOwner ? 0x14 : 0x10, 0x18, 0x20, 0x28, 0x30, 0x38}
                                                       : std::array<int32_t, 7>{taggedOwner ? 0x20 : 0x28,
                                                                                taggedOwner ? 0x28 : 0x20, 0x30, 0x38, 0x18, 0x40, 0x48};
        const std::array<int32_t, 4> classNameOffsets = {0x00, 0x08, 0x10, 0x18};
        constexpr int32_t kMaxFieldOffset = 0x80;
        const auto overlaps = [](int32_t leftOffset, int32_t leftSize, int32_t rightOffset, int32_t rightSize)
        {
            return leftOffset < rightOffset + rightSize && rightOffset < leftOffset + leftSize;
        };
        size_t readableRoots = 0;
        size_t namedRoots = 0;
        size_t chainedRoots = 0;
        size_t classMatches = 0;
        size_t ownerMatches = 0;

        for (int32_t propertiesOffset = 0x20; propertiesOffset <= 0x100; propertiesOffset += 4)
        {
            uintptr_t firstField = 0;
            const auto rootAddress = Add(*guid, propertiesOffset);
            if (!rootAddress || !memory_.Read(*rootAddress, firstField) || !IsReadablePointer(memory_, firstField))
                continue;
            ++readableRoots;

            for (const int32_t nameOffset : nameOffsets)
            {
                const auto firstName = readFieldName(firstField, nameOffset);
                if (!firstName || firstName->size() != 1 || (*firstName)[0] < 'A' || (*firstName)[0] > 'D')
                    continue;
                ++namedRoots;

                // 各字段的语义关系不要求保留 stock 声明顺序或相对位置
                for (int32_t nextOffset = pointerSize; nextOffset <= kMaxFieldOffset; nextOffset += pointerSize)
                {
                    if (overlaps(nextOffset, pointerSize, nameOffset, fnameSize))
                        continue;
                    std::array<uintptr_t, 4> fields{};
                    std::array<bool, 4> seenNames{};
                    uintptr_t field = firstField;
                    bool chainValid = true;
                    for (size_t index = 0; index < fields.size(); ++index)
                    {
                        const auto fieldName = field ? readFieldName(field, nameOffset) : std::nullopt;
                        if (!fieldName || fieldName->size() != 1 || (*fieldName)[0] < 'A' || (*fieldName)[0] > 'D' ||
                            seenNames[static_cast<size_t>((*fieldName)[0] - 'A')])
                        {
                            chainValid = false;
                            break;
                        }
                        seenNames[static_cast<size_t>((*fieldName)[0] - 'A')] = true;
                        fields[index] = field;
                        const auto nextAddress = Add(field, nextOffset);
                        if (!nextAddress || !memory_.Read(*nextAddress, field) ||
                            (index + 1 < fields.size() && !IsReadablePointer(memory_, field)))
                        {
                            chainValid = false;
                            break;
                        }
                    }
                    if (!chainValid || field != 0)
                        continue;
                    ++chainedRoots;

                    for (int32_t classOffset = pointerSize; classOffset <= kMaxFieldOffset; classOffset += pointerSize)
                    {
                        if (overlaps(classOffset, pointerSize, nameOffset, fnameSize) ||
                            overlaps(classOffset, pointerSize, nextOffset, pointerSize))
                            continue;
                        for (const int32_t classNameOffset : classNameOffsets)
                        {
                            uintptr_t commonFieldClass = 0;
                            bool classesValid = true;
                            for (uintptr_t current : fields)
                            {
                                uintptr_t fieldClass = 0;
                                const auto classAddress = Add(current, classOffset);
                                if (!classAddress || !memory_.Read(*classAddress, fieldClass) ||
                                    !IsReadablePointer(memory_, fieldClass) ||
                                    (commonFieldClass != 0 && fieldClass != commonFieldClass))
                                {
                                    classesValid = false;
                                    break;
                                }
                                commonFieldClass = fieldClass;
                                const auto className = readFieldName(fieldClass, classNameOffset);
                                if (!className || !IsPropertyFieldKind(FieldKindFromRuntimeName(*className, true)))
                                {
                                    classesValid = false;
                                    break;
                                }
                            }
                            if (!classesValid)
                                continue;
                            ++classMatches;

                            for (int32_t ownerOffset = pointerSize; ownerOffset <= kMaxFieldOffset; ownerOffset += pointerSize)
                            {
                                if (overlaps(ownerOffset, ownerStorageSize, nameOffset, fnameSize) ||
                                    overlaps(ownerOffset, ownerStorageSize, nextOffset, pointerSize) ||
                                    overlaps(ownerOffset, ownerStorageSize, classOffset, pointerSize))
                                    continue;
                                bool ownersValid = true;
                                for (uintptr_t current : fields)
                                {
                                    uintptr_t rawOwner = 0;
                                    const auto ownerAddress = Add(current, ownerOffset);
                                    if (!ownerAddress || !memory_.Read(*ownerAddress, rawOwner) ||
                                        (taggedOwner && (rawOwner & 1u) == 0) ||
                                        (taggedOwner ? (rawOwner & ~static_cast<uintptr_t>(1)) : rawOwner) != *guid)
                                    {
                                        ownersValid = false;
                                        break;
                                    }
                                    if (!taggedOwner)
                                    {
                                        uint8_t isUObject = 0;
                                        const auto discriminator = Add(*ownerAddress, pointerSize);
                                        if (!discriminator || !memory_.Read(*discriminator, isUObject) || isUObject != 1)
                                        {
                                            ownersValid = false;
                                            break;
                                        }
                                    }
                                }
                                if (!ownersValid)
                                    continue;
                                ++ownerMatches;

                                const auto alignOffset = [](int32_t offset, int32_t alignment)
                                {
                                    return (offset + alignment - 1) / alignment * alignment;
                                };
                                // Id 是 uint64，Android ARM32 与 ARM64 均按其类型对齐，不能使用指针对齐代替
                                const int32_t candidateId = alignOffset(classNameOffset + fnameSize,
                                                                        static_cast<int32_t>(alignof(uint64_t)));
                                const int32_t candidateCastFlags = candidateId + static_cast<int32_t>(sizeof(uint64_t));
                                const int32_t candidateClassFlags = candidateCastFlags + static_cast<int32_t>(sizeof(uint64_t));
                                const int32_t candidateSuperClass = alignOffset(
                                    candidateClassFlags + static_cast<int32_t>(sizeof(uint32_t)), pointerSize);
                                size_t classTailHits = 0;
                                for (uintptr_t current : fields)
                                {
                                    uint64_t id = 0;
                                    uint64_t castFlags = 0;
                                    uint32_t classFlags = 0;
                                    uintptr_t superClass = 0;
                                    uintptr_t fieldClass = 0;
                                    const auto fieldClassAddress = Add(current, classOffset);
                                    if (!fieldClassAddress || !memory_.Read(*fieldClassAddress, fieldClass) ||
                                        !IsReadablePointer(memory_, fieldClass))
                                        continue;
                                    const auto idAddress = Add(fieldClass, candidateId);
                                    const auto castAddress = Add(fieldClass, candidateCastFlags);
                                    const auto flagsAddress = Add(fieldClass, candidateClassFlags);
                                    const auto superAddress = Add(fieldClass, candidateSuperClass);
                                    if (idAddress && castAddress && flagsAddress && superAddress &&
                                        memory_.Read(*idAddress, id) && memory_.Read(*castAddress, castFlags) &&
                                        memory_.Read(*flagsAddress, classFlags) && memory_.Read(*superAddress, superClass) &&
                                        id != 0 && (castFlags & 0x0000000000008000ull) != 0 &&
                                        superClass != 0 && IsReadablePointer(memory_, superClass))
                                        ++classTailHits;
                                }
                                if (classTailHits != fields.size())
                                    continue;

                                schema.ustruct.childProperties = propertiesOffset;
                                schema.ffield.classPointer = classOffset;
                                schema.ffield.owner = ownerOffset;
                                schema.ffield.next = nextOffset;
                                schema.ffield.name = nameOffset;
                                schema.ffieldClass.name = classNameOffset;
                                schema.ffieldClass.id = candidateId;
                                schema.ffieldClass.castFlags = candidateCastFlags;
                                schema.ffieldClass.classFlags = candidateClassFlags;
                                schema.ffieldClass.superClass = candidateSuperClass;
                                schema.validation.fields = true;
                                report.evidence.push_back("resolved FField chain from CoreUObject.Guid properties; child_properties=" +
                                                          std::to_string(propertiesOffset) + " class=" + std::to_string(classOffset) +
                                                          " owner=" + std::to_string(ownerOffset) + " next=" + std::to_string(nextOffset) +
                                                          " name=" + std::to_string(nameOffset) + " class_name=" +
                                                          std::to_string(classNameOffset) + "; four names, classes and owners validated");
                                report.versionEvidence.push_back({"f-field-owner-encoding",
                                                                  taggedOwner ? "tagged-pointer" : "explicit-discriminator",
                                                                  VersionEvidenceStrength::Strong,
                                                                  "observed from FField owner storage and discriminator semantics"});
                                return true;
                            }
                        }
                    }
                }
            }
        }
        report.failures.push_back("UStruct::ChildProperties/FField chain was not resolved; pointer_width=" +
                                  std::to_string(pointerSize) + " owner_mask=" +
                                  std::to_string(taggedOwner) + " readable_roots=" +
                                  std::to_string(readableRoots) + " named_roots=" + std::to_string(namedRoots) +
                                  " four_field_chains=" + std::to_string(chainedRoots) +
                                  " class_matches=" + std::to_string(classMatches) +
                                  " owner_matches=" + std::to_string(ownerMatches));
        return false;
    }

} // namespace nextdumper::ue::schema_probe
