#include "nextdumper/ue/ObjectModelReader.hpp"

#include <unordered_set>
#include <algorithm>
#include <limits>

namespace nextdumper::ue
{
    namespace
    {
        constexpr uint64_t kFPropertyCastFlag = 0x0000000000008000ull;

        std::optional<uintptr_t> Add(uintptr_t base, int32_t offset)
        {
            if (base == 0 || offset < 0)
                return std::nullopt;
            const uintptr_t value = static_cast<uintptr_t>(offset);
            if (base > UINTPTR_MAX - value)
                return std::nullopt;
            return base + value;
        }
    } // namespace

    ObjectModelReader::ObjectModelReader(const IMemorySource &memory,
                                         const RuntimeBinding &binding,
                                         const EngineSchema &schema)
        : memory_(memory),
          binding_(binding),
          schema_(schema),
          objects_(memory, binding.objectRoot.address, binding.objects, binding.decode),
          names_(memory, binding.nameRoot.address, binding.names, binding.decode, schema.fname, schema.features)
    {
    }

    bool ObjectModelReader::Initialize()
    {
        initialized_ = objects_.Initialize();
        return initialized_;
    }

    std::optional<uintptr_t> ObjectModelReader::ReadPointer(uintptr_t address) const
    {
        uintptr_t value = 0;
        if (!memory_.Read(address, value) || value == 0)
            return std::nullopt;
        return value;
    }

    std::optional<std::pair<uintptr_t, bool>> ObjectModelReader::DecodeFieldOwner(uintptr_t field) const
    {
        const auto ownerAddress = Add(field, schema_.ffield.owner);
        if (!ownerAddress)
            return std::nullopt;
        uintptr_t rawOwner = 0;
        if (!memory_.Read(*ownerAddress, rawOwner))
            return std::nullopt;

        uintptr_t owner = rawOwner;
        bool ownerIsUObject = false;
        if (schema_.features.fFieldOwnerEncoding == FFieldOwnerEncoding::TaggedPointer)
        {
            ownerIsUObject = (rawOwner & static_cast<uintptr_t>(1)) != 0;
            owner = rawOwner & ~static_cast<uintptr_t>(1);
        }
        else
        {
            const auto discriminatorAddress = Add(*ownerAddress, static_cast<int32_t>(sizeof(uintptr_t)));
            uint8_t discriminator = 0;
            if (!discriminatorAddress || !memory_.Read(*discriminatorAddress, discriminator) || discriminator > 1)
                return std::nullopt;
            ownerIsUObject = discriminator == 1;
        }
        if (owner == 0 || !IsReadableObject(owner))
            return std::nullopt;
        return std::pair{owner, ownerIsUObject};
    }

    FieldKind ObjectModelReader::ResolveFFieldKind(uintptr_t classAddress, FieldKind fallback) const
    {
        if (fallback != FieldKind::FField || schema_.ffieldClass.superClass < 0)
            return fallback;

        uintptr_t current = classAddress;
        std::unordered_set<uintptr_t> visited;
        bool sawClassTail = false;
        FieldKind nameFallback = fallback;
        for (size_t depth = 0; current != 0 && depth < 32 && visited.insert(current).second; ++depth)
        {
            const auto nameAddress = Add(current, schema_.ffieldClass.name);
            const auto superAddress = Add(current, schema_.ffieldClass.superClass);
            if (!nameAddress || !superAddress)
                break;
            const auto name = names_.ReadFName(*nameAddress);
            uintptr_t superClass = 0;
            if (schema_.ffieldClass.castFlags >= 0)
            {
                const auto castFlagsAddress = Add(current, schema_.ffieldClass.castFlags);
                uint64_t castFlags = 0;
                if (castFlagsAddress && memory_.Read(*castFlagsAddress, castFlags))
                {
                    sawClassTail = true;
                    if ((castFlags & kFPropertyCastFlag) != 0)
                        return FieldKind::FProperty;
                }
            }
            if (name && NormalizeRuntimeFieldName(*name) == "Property")
                nameFallback = FieldKind::FProperty;
            if (!memory_.Read(*superAddress, superClass))
                break;
            current = superClass;
        }
        return sawClassTail ? fallback : nameFallback;
    }

    FieldKind ObjectModelReader::ResolveUFieldKind(uintptr_t classAddress, FieldKind fallback) const
    {
        if (schema_.ustruct.superStruct < 0)
            return fallback;

        uintptr_t current = classAddress;
        std::unordered_set<uintptr_t> visited;
        FieldKind nameFallback = fallback;
        for (size_t depth = 0; current != 0 && depth < 32 && visited.insert(current).second; ++depth)
        {
            const auto className = NameField(current);
            if (className)
            {
                const std::string normalized = NormalizeRuntimeFieldName(*className);
                if (normalized == "Property")
                    nameFallback = FieldKind::UProperty;
                else if (normalized == "Function" || normalized == "DelegateFunction" ||
                         normalized == "SparseDelegateFunction" || normalized == "VerseFunction")
                    return FieldKind::UFunction;
            }
            const auto super = StructSuper(current);
            if (!super || *super == 0)
                break;
            current = *super;
        }
        return nameFallback;
    }

    bool ObjectModelReader::IsReadableObject(uintptr_t object) const
    {
        return object != 0 && memory_.IsReadable(object, sizeof(uintptr_t));
    }

    std::optional<uintptr_t> ObjectModelReader::Class(uintptr_t object, bool fresh) const
    {
        const auto address = Add(object, schema_.uobject.classPointer);
        if (!address)
            return std::nullopt;
        uintptr_t raw = 0;
        const auto read = fresh ? memory_.ReadFreshBytes(*address, &raw, sizeof(raw))
                                : memory_.ReadBytes(*address, &raw, sizeof(raw));
        if (!read.Ok())
            return std::nullopt;
        return DecodeClassPointer(raw, *address);
    }

    std::optional<uintptr_t> ObjectModelReader::Outer(uintptr_t object) const
    {
        const auto address = Add(object, schema_.uobject.outer);
        if (!address)
            return std::nullopt;
        uintptr_t raw = 0;
        if (!memory_.Read(*address, raw))
            return std::nullopt;
        const uintptr_t outer = binding_.decode.objectOuter(raw, *address);
        if (outer != 0 && !IsReadableObject(outer))
            return std::nullopt;
        return outer;
    }

    std::optional<int32_t> ObjectModelReader::InternalIndex(uintptr_t object, bool fresh) const
    {
        const auto address = Add(object, schema_.uobject.internalIndex);
        if (!address)
            return std::nullopt;
        int32_t raw = 0;
        const auto read = fresh ? memory_.ReadFreshBytes(*address, &raw, sizeof(raw))
                                : memory_.ReadBytes(*address, &raw, sizeof(raw));
        if (!read.Ok())
            return std::nullopt;
        return binding_.decode.objectIndex(raw, *address);
    }

    std::optional<uint32_t> ObjectModelReader::Flags(uintptr_t object) const
    {
        const auto address = Add(object, schema_.uobject.flags);
        if (!address)
            return std::nullopt;
        int32_t raw = 0;
        if (!memory_.Read(*address, raw))
            return std::nullopt;
        return static_cast<uint32_t>(binding_.decode.objectFlags(raw, *address));
    }

    std::optional<std::string> ObjectModelReader::NameField(uintptr_t object) const
    {
        const auto address = Add(object, schema_.uobject.name);
        if (!address)
            return std::nullopt;
        return names_.ReadFName(*address);
    }

    std::optional<std::string> ObjectModelReader::Name(uintptr_t object) const
    {
        return NameField(object);
    }

    std::optional<std::string> ObjectModelReader::ClassName(uintptr_t object) const
    {
        const auto classAddress = Class(object);
        if (!classAddress)
            return std::nullopt;
        return NameField(*classAddress);
    }

    std::optional<std::string> ObjectModelReader::FullName(uintptr_t object, size_t maxDepth) const
    {
        const auto name = Name(object);
        const auto className = ClassName(object);
        if (!name || !className)
            return std::nullopt;

        std::vector<std::string> outers;
        std::unordered_set<uintptr_t> visited{object};
        uintptr_t current = object;
        for (size_t depth = 0; depth < maxDepth; ++depth)
        {
            const auto outer = Outer(current);
            if (!outer)
                return std::nullopt;
            if (*outer == 0)
                break;
            if (!visited.insert(*outer).second)
                return std::nullopt;
            const auto outerName = Name(*outer);
            if (!outerName)
                return std::nullopt;
            outers.push_back(*outerName);
            current = *outer;
        }
        if (outers.size() == maxDepth)
            return std::nullopt;

        std::string result = *className + " ";
        for (auto it = outers.rbegin(); it != outers.rend(); ++it)
            result += *it + ".";
        result += *name;
        return result;
    }

    std::optional<ObjectMetadata> ObjectModelReader::Metadata(uintptr_t object) const
    {
        const auto classAddress = Class(object);
        const auto outerAddress = Outer(object);
        const auto index = InternalIndex(object);
        const auto flags = Flags(object);
        const auto name = Name(object);
        const auto className = ClassName(object);
        const auto fullName = FullName(object);
        if (!classAddress || !outerAddress || !index || !flags || !name || !className || !fullName)
            return std::nullopt;
        return ObjectMetadata{object, *classAddress, *outerAddress, *index, *flags, *name, *className, *fullName};
    }

    std::optional<FieldMetadata> ObjectModelReader::Field(uintptr_t field) const
    {
        if (!IsReadableObject(field))
            return std::nullopt;

        if (!schema_.features.useFProperty)
            return UField(field);

        const auto classAddress = Add(field, schema_.ffield.classPointer);
        const auto ownerAddress = Add(field, schema_.ffield.owner);
        const auto nextAddress = Add(field, schema_.ffield.next);
        const auto nameAddress = Add(field, schema_.ffield.name);
        if (!classAddress || !ownerAddress || !nextAddress || !nameAddress)
            return std::nullopt;

        const auto classValue = ReadPointer(*classAddress);
        const auto ownerValue = DecodeFieldOwner(field);
        const auto name = names_.ReadFName(*nameAddress);
        uintptr_t nextValue = 0;
        if (!classValue || !ownerValue || !memory_.Read(*nextAddress, nextValue) || !name)
            return std::nullopt;
        const auto classNameAddress = Add(*classValue, schema_.ffieldClass.name);
        if (!classNameAddress)
            return std::nullopt;
        const auto className = names_.ReadFName(*classNameAddress);
        if (!className)
            return std::nullopt;
        const std::string normalizedClassName = NormalizeRuntimeFieldName(*className);
        const FieldKind kind = ResolveFFieldKind(*classValue, FieldKindFromRuntimeName(*className, true));
        return FieldMetadata{field, *classValue, ownerValue->first, ownerValue->second, nextValue, *name, *className,
                             normalizedClassName, kind};
    }

    std::optional<FieldMetadata> ObjectModelReader::UField(uintptr_t field) const
    {
        if (!IsReadableObject(field))
            return std::nullopt;

        const auto classAddress = Class(field);
        const auto nextAddress = Add(field, schema_.ufield.next);
        const auto nameAddress = Add(field, schema_.uobject.name);
        if (!classAddress || !nextAddress || !nameAddress)
            return std::nullopt;

        uintptr_t nextValue = 0;
        if (!memory_.Read(*nextAddress, nextValue))
            return std::nullopt;
        const auto name = names_.ReadFName(*nameAddress);
        if (!name)
            return std::nullopt;
        const auto className = NameField(*classAddress);
        if (!className)
            return std::nullopt;
        const std::string normalizedClassName = NormalizeRuntimeFieldName(*className);
        return FieldMetadata{field, *classAddress, 0, false, nextValue, *name, *className,
                             normalizedClassName, ResolveUFieldKind(*classAddress, FieldKindFromRuntimeName(*className, false))};
    }

    FieldChainResult ObjectModelReader::FieldsWithStatus(uintptr_t first, size_t maxFields) const
    {
        return ReadFieldChain(first, maxFields, false);
    }

    FieldChainResult ObjectModelReader::UFieldsWithStatus(uintptr_t first, size_t maxFields) const
    {
        return ReadFieldChain(first, maxFields, true);
    }

    FieldChainResult ObjectModelReader::ReadFieldChain(uintptr_t first, size_t maxFields, bool ufield) const
    {
        FieldChainResult result;
        if (first == 0)
            return result;

        std::unordered_set<uintptr_t> visited;
        uintptr_t current = first;
        while (current != 0)
        {
            if (!visited.insert(current).second)
            {
                result.status = FieldChainStatus::CycleDetected;
                return result;
            }
            if (result.fields.size() >= maxFields)
            {
                result.status = FieldChainStatus::LimitExceeded;
                return result;
            }
            const auto field = ufield ? UField(current) : Field(current);
            if (!field)
            {
                result.status = FieldChainStatus::Unreadable;
                return result;
            }
            result.fields.push_back(*field);
            current = field->nextAddress;
        }
        result.status = FieldChainStatus::Complete;
        return result;
    }

    std::optional<PropertyMetadata> ObjectModelReader::Property(uintptr_t field) const
    {
        const auto base = Field(field);
        if (!base)
            return std::nullopt;
        if (!IsPropertyFieldKind(base->kind))
            return std::nullopt;

        const auto arrayDimAddress = Add(field, schema_.property.arrayDim);
        const auto elementSizeAddress = Add(field, schema_.property.elementSize);
        const auto offsetAddress = Add(field, schema_.property.offsetInternal);
        const auto flagsAddress = Add(field, schema_.property.propertyFlags);
        if (!arrayDimAddress || !elementSizeAddress || !offsetAddress || !flagsAddress)
            return std::nullopt;

        PropertyMetadata result;
        static_cast<FieldMetadata &>(result) = *base;
        if (!memory_.Read(*arrayDimAddress, result.arrayDim) ||
            !memory_.Read(*elementSizeAddress, result.elementSize) ||
            !memory_.Read(*offsetAddress, result.offset) ||
            !memory_.Read(*flagsAddress, result.flags))
            return std::nullopt;

        // 分别保留两次引用读取的状态，整体状态保留第一次失败，不能由后一次读取覆盖。
        const auto recordDetail = [&](const PropertyMetadata::DetailRead &detail)
        {
            result.detailReads.at(result.detailReadCount++) = detail;
            if (result.detailsStatus == PropertyMetadata::DetailsStatus::Complete)
                result.detailsStatus = detail.status;
        };

        const auto readOptionalPointer = [&](const char *member, int32_t offset, bool nullable = false) -> uintptr_t
        {
            PropertyMetadata::DetailRead detail;
            detail.member = member;
            detail.offset = offset;
            detail.read = {::nextdumper::memory::ReadError::InvalidArgument, 0, sizeof(uintptr_t), 0};
            if (offset < 0)
            {
                detail.status = PropertyMetadata::DetailsStatus::UnsupportedLayout;
                recordDetail(detail);
                return 0;
            }
            const auto address = Add(field, offset);
            uintptr_t value = 0;
            if (address)
            {
                detail.address = *address;
                detail.read = memory_.ReadBytes(*address, &value, sizeof(value));
            }
            if (!address || !detail.read.Ok())
            {
                detail.status = PropertyMetadata::DetailsStatus::Unreadable;
                recordDetail(detail);
                return 0;
            }
            detail.rawValue = value;
            if (value == 0 && !nullable)
                detail.status = PropertyMetadata::DetailsStatus::NullReference;
            else if (value != 0 && !IsReadableObject(value))
                detail.status = PropertyMetadata::DetailsStatus::InvalidReference;
            recordDetail(detail);
            return value;
        };
        const std::string &propertyClassName = base->normalizedClassName;
        if (propertyClassName == "ObjectProperty" || propertyClassName == "ObjectPropertyBase" || propertyClassName == "ObjectPtrProperty" ||
            propertyClassName == "SoftObjectProperty" || propertyClassName == "WeakObjectProperty" ||
            propertyClassName == "LazyObjectProperty")
        {
            result.referencedAddress = readOptionalPointer("object_class", schema_.propertySubtypes.objectClass);
            result.objectPropertyClassNull = result.referencedAddress == 0 &&
                                             result.detailsStatus == PropertyMetadata::DetailsStatus::NullReference;
            if (result.objectPropertyClassNull && result.detailReadCount != 0)
                result.objectPropertyClassPointerAddress = result.detailReads[result.detailReadCount - 1].address;
        }
        else if (propertyClassName == "InterfaceProperty")
            result.referencedAddress = readOptionalPointer("interface_class", schema_.propertySubtypes.interfaceClass);
        else if (propertyClassName == "ClassProperty" || propertyClassName == "ClassPtrProperty" || propertyClassName == "SoftClassProperty")
            result.referencedAddress = readOptionalPointer("class_meta_class", schema_.propertySubtypes.classMetaClass);
        else if (propertyClassName == "StructProperty")
            result.referencedAddress = readOptionalPointer("struct_type", schema_.propertySubtypes.structType);
        else if (propertyClassName == "ByteProperty")
            result.referencedAddress = readOptionalPointer("byte_enum", schema_.propertySubtypes.byteEnum, true);
        else if (propertyClassName == "BoolProperty")
        {
            const auto address = Add(field, schema_.propertySubtypes.boolBase);
            PropertyMetadata::DetailRead detail;
            detail.member = "bool_layout";
            detail.offset = schema_.propertySubtypes.boolBase;
            detail.read = {::nextdumper::memory::ReadError::InvalidArgument, 0, result.boolLayout.size(), 0};
            if (schema_.propertySubtypes.boolBase < 0)
                detail.status = PropertyMetadata::DetailsStatus::UnsupportedLayout;
            else
            {
                if (address)
                {
                    detail.address = *address;
                    detail.read = memory_.ReadBytes(*address, result.boolLayout.data(), result.boolLayout.size());
                }
                if (!address || !detail.read.Ok())
                    detail.status = PropertyMetadata::DetailsStatus::Unreadable;
            }
            recordDetail(detail);
        }
        else if (propertyClassName == "ArrayProperty")
            result.referencedAddress = readOptionalPointer("array_inner", schema_.propertySubtypes.arrayInner);
        else if (propertyClassName == "SetProperty")
            result.referencedAddress = readOptionalPointer("set_element", schema_.propertySubtypes.setElement);
        else if (propertyClassName == "MapProperty")
        {
            result.referencedAddress = readOptionalPointer("map_key", schema_.propertySubtypes.mapBase);
            const int32_t valueOffset = schema_.propertySubtypes.mapBase >= 0 &&
                                                schema_.propertySubtypes.mapBase <= INT32_MAX - static_cast<int32_t>(sizeof(uintptr_t))
                                            ? schema_.propertySubtypes.mapBase + static_cast<int32_t>(sizeof(uintptr_t))
                                            : -1;
            result.secondaryAddress = readOptionalPointer("map_value", valueOffset);
        }
        else if (propertyClassName == "EnumProperty")
        {
            result.referencedAddress = readOptionalPointer("enum_underlying", schema_.propertySubtypes.enumBase);
            const int32_t enumOffset = schema_.propertySubtypes.enumBase >= 0 &&
                                               schema_.propertySubtypes.enumBase <= INT32_MAX - static_cast<int32_t>(sizeof(uintptr_t))
                                           ? schema_.propertySubtypes.enumBase + static_cast<int32_t>(sizeof(uintptr_t))
                                           : -1;
            result.secondaryAddress = readOptionalPointer("enum_type", enumOffset);
        }
        else if (propertyClassName == "OptionalProperty")
            result.referencedAddress = readOptionalPointer("optional_value", schema_.propertySubtypes.optionalValue);
        else if (propertyClassName == "DelegateProperty" || propertyClassName == "MulticastDelegateProperty" ||
                 propertyClassName == "MulticastInlineDelegateProperty" || propertyClassName == "MulticastSparseDelegateProperty")
            result.referencedAddress = readOptionalPointer("delegate_signature", schema_.propertySubtypes.delegateSignature);
        else if (propertyClassName == "FieldPathProperty")
            result.referencedAddress = readOptionalPointer("field_path_class", schema_.propertySubtypes.fieldPathClass);

        return result;
    }

    std::optional<FieldClassMetadata> ObjectModelReader::FieldClass(uintptr_t address) const
    {
        if (!schema_.features.useFProperty || address == 0 || schema_.fname.size <= 0)
            return std::nullopt;
        const auto nameAddress = Add(address, schema_.ffieldClass.name);
        const auto idAddress = Add(address, schema_.ffieldClass.id);
        const auto castAddress = Add(address, schema_.ffieldClass.castFlags);
        const auto flagsAddress = Add(address, schema_.ffieldClass.classFlags);
        const auto superAddress = Add(address, schema_.ffieldClass.superClass);
        if (!nameAddress || !idAddress || !castAddress || !flagsAddress || !superAddress ||
            !memory_.IsReadable(*nameAddress, static_cast<size_t>(schema_.fname.size)) ||
            !memory_.IsReadable(*idAddress, sizeof(uint64_t)) ||
            !memory_.IsReadable(*castAddress, sizeof(uint64_t)) ||
            !memory_.IsReadable(*flagsAddress, sizeof(uint32_t)) ||
            !memory_.IsReadable(*superAddress, sizeof(uintptr_t)))
            return std::nullopt;
        FieldClassMetadata result;
        const auto name = names_.ReadFName(*nameAddress);
        if (!name || name->empty() || !memory_.Read(*idAddress, result.id) ||
            !memory_.Read(*castAddress, result.castFlags) || !memory_.Read(*flagsAddress, result.classFlags) ||
            !memory_.Read(*superAddress, result.superClass))
            return std::nullopt;
        result.name = *name;
        return result;
    }

    FieldClassValidationResult ObjectModelReader::ValidateFieldClass(uintptr_t address) const
    {
        FieldClassValidationResult result;
        result.address = address;
        if (address == 0)
        {
            result.reason = "null-reference";
            return result;
        }

        std::unordered_set<uintptr_t> visited;
        uint64_t childCastFlags = UINT64_MAX;
        for (size_t depth = 0; address != 0 && depth < 32 && visited.insert(address).second; ++depth)
        {
            const auto metadata = FieldClass(address);
            result.depth = depth + 1;
            if (!metadata)
            {
                result.reason = "ffield-class-identity-unreadable";
                return result;
            }
            if (depth == 0)
                result.targetName = metadata->name;
            if (metadata->id != 0 && (metadata->castFlags & metadata->id) != metadata->id)
            {
                result.reason = "ffield-class-id-not-covered-by-cast-flags";
                return result;
            }
            if ((childCastFlags & metadata->castFlags) != metadata->castFlags)
            {
                result.reason = "ffield-class-parent-cast-flags-not-subset";
                return result;
            }
            if (metadata->superClass == 0)
            {
                result.valid = NormalizeRuntimeFieldName(metadata->name) == "Field";
                result.reason = result.valid ? "validated" : "ffield-class-parent-chain-root-is-not-field";
                return result;
            }
            childCastFlags = metadata->castFlags;
            address = metadata->superClass;
        }
        result.reason = address == 0 ? "ffield-class-parent-chain-ended-before-field" : (visited.find(address) != visited.end() ? "ffield-class-parent-chain-cycle" : "ffield-class-parent-chain-depth-limit");
        return result;
    }

    bool ObjectModelReader::IsValidFieldClass(uintptr_t address) const
    {
        return ValidateFieldClass(address).valid;
    }

    std::optional<DefinitionKind> ObjectModelReader::DefinitionKindForClass(uintptr_t classAddress) const
    {
        if (classAddress == 0)
            return std::nullopt;
        std::unordered_set<uintptr_t> visited;
        uintptr_t current = classAddress;
        for (size_t depth = 0; current != 0 && depth < 64; ++depth)
        {
            if (!visited.insert(current).second)
                return std::nullopt;
            const auto name = Name(current);
            if (!name)
                return std::nullopt;
            if (*name == "Class")
                return DefinitionKind::Class;
            if (*name == "ScriptStruct")
                return DefinitionKind::Struct;
            if (*name == "Enum")
                return DefinitionKind::Enum;
            const auto super = StructSuper(current);
            if (!super)
                return std::nullopt;
            current = *super;
        }
        return current == 0 ? std::optional<DefinitionKind>(DefinitionKind::Other) : std::nullopt;
    }

    std::optional<uintptr_t> ObjectModelReader::StructChildren(uintptr_t structure) const
    {
        const auto address = Add(structure, schema_.ustruct.children);
        if (!address)
            return std::nullopt;
        uintptr_t value = 0;
        if (!memory_.Read(*address, value))
            return std::nullopt;
        if (value != 0 && !IsReadableObject(value))
            return std::nullopt;
        return value;
    }

    std::optional<uintptr_t> ObjectModelReader::StructProperties(uintptr_t structure) const
    {
        const auto address = Add(structure, schema_.features.useFProperty ? schema_.ustruct.childProperties : schema_.ustruct.children);
        if (!address)
            return std::nullopt;
        uintptr_t value = 0;
        if (!memory_.Read(*address, value))
            return std::nullopt;
        if (value != 0 && !IsReadableObject(value))
            return std::nullopt;
        return value;
    }

    std::optional<uintptr_t> ObjectModelReader::StructSuper(uintptr_t structure) const
    {
        const auto address = Add(structure, schema_.ustruct.superStruct);
        if (!address)
            return std::nullopt;

        // 在 UE 5.6 中，UStruct::SuperStruct 明确允许为空
        // 对于根结构/类 而言，一个为空的超类是有效的，并且绝不能与远程读取失败的情况混淆
        uintptr_t value = 0;
        if (!memory_.Read(*address, value))
            return std::nullopt;
        if (value != 0 && !IsReadableObject(value))
            return std::nullopt;
        return value;
    }

    std::optional<int32_t> ObjectModelReader::StructSize(uintptr_t structure) const
    {
        const auto address = Add(structure, schema_.ustruct.propertiesSizeOffset);
        if (!address)
            return std::nullopt;
        int32_t value = 0;
        return memory_.Read(*address, value) ? std::optional<int32_t>(value) : std::nullopt;
    }

    EnumReadResult ObjectModelReader::ReadEnumValues(uintptr_t enumeration, size_t maxValues) const
    {
        EnumReadResult result;
        if (enumeration == 0 || schema_.uenum.names < 0)
            return result;

        const auto dataAddress = Add(enumeration, schema_.uenum.names);
        if (!dataAddress)
            return result;

        uintptr_t data = 0;
        int32_t count = 0;
        int32_t capacity = 0;
        const auto countAddress = Add(*dataAddress, static_cast<int32_t>(sizeof(uintptr_t)));
        const auto capacityAddress = Add(*dataAddress, static_cast<int32_t>(sizeof(uintptr_t) + sizeof(int32_t)));
        if (!memory_.Read(*dataAddress, data) || !countAddress || !capacityAddress ||
            !memory_.Read(*countAddress, count) || !memory_.Read(*capacityAddress, capacity))
            return result;
        result.expectedCount = count;
        if (count < 0 || count > 0x100000 || capacity < count || capacity > 0x100000 || (count > 0 && data == 0))
        {
            result.status = EnumReadStatus::InvalidHeader;
            return result;
        }

        const int32_t nameSize = schema_.fname.size;
        if (nameSize != 4 && nameSize != 8 && nameSize != 12)
        {
            result.status = EnumReadStatus::InvalidHeader;
            return result;
        }
        const int32_t valueOffset = (nameSize + static_cast<int32_t>(alignof(int64_t)) - 1) /
                                    static_cast<int32_t>(alignof(int64_t)) * static_cast<int32_t>(alignof(int64_t));
        const int32_t stride = valueOffset + static_cast<int32_t>(sizeof(int64_t));
        const size_t readCount = std::min(static_cast<size_t>(count), maxValues);
        for (size_t index = 0; index < readCount; ++index)
        {
            const uintptr_t offset = static_cast<uintptr_t>(index) * static_cast<uintptr_t>(stride);
            if (offset > UINTPTR_MAX - data)
                return result;
            const uintptr_t entry = data + offset;
            const auto name = names_.ReadFName(entry);
            int64_t value = 0;
            const auto valueAddress = Add(entry, valueOffset);
            if (!name || !valueAddress || !memory_.Read(*valueAddress, value))
                return result;
            result.values.push_back(EnumValueMetadata{*name, value});
        }
        result.status = readCount == static_cast<size_t>(count) ? EnumReadStatus::Complete : EnumReadStatus::LimitExceeded;
        return result;
    }
} // namespace nextdumper::ue
