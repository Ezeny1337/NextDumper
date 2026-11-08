#include "nextdumper/generation/CppTypeResolver.hpp"
#include "nextdumper/ir/ReflectionLayout.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <string_view>
#include <tuple>
#include <unordered_set>

namespace nextdumper::generation
{
    using ir::EnumUnderlyingType;
    using ir::PropertyKind;

    namespace
    {
        int32_t EnumSize(EnumUnderlyingType type)
        {
            switch (type)
            {
            case EnumUnderlyingType::Int8:
            case EnumUnderlyingType::UInt8:
                return 1;
            case EnumUnderlyingType::Int16:
            case EnumUnderlyingType::UInt16:
                return 2;
            case EnumUnderlyingType::Int32:
            case EnumUnderlyingType::UInt32:
                return 4;
            default:
                return 8;
            }
        }

        EnumUnderlyingType EnumType(const ir::EnumIR &enumeration)
        {
            const auto declared = enumeration.underlyingType;
            if (declared == EnumUnderlyingType::UInt64)
                return declared;
            if (enumeration.values.empty() || declared == EnumUnderlyingType::Unknown)
                return declared;
            int64_t low = enumeration.values.front().value;
            int64_t high = low;
            for (const auto &value : enumeration.values)
            {
                low = std::min(low, value.value);
                high = std::max(high, value.value);
            }
            const bool unsignedType = declared == EnumUnderlyingType::UInt8 || declared == EnumUnderlyingType::UInt16 ||
                                      declared == EnumUnderlyingType::UInt32 || declared == EnumUnderlyingType::UInt64;
            if (unsignedType && low < 0)
                return EnumUnderlyingType::Int64;
            const int32_t initialSize = EnumSize(declared);
            if (unsignedType)
            {
                if (initialSize <= 1 && static_cast<uint64_t>(high) <= UINT8_MAX)
                    return EnumUnderlyingType::UInt8;
                if (initialSize <= 2 && static_cast<uint64_t>(high) <= UINT16_MAX)
                    return EnumUnderlyingType::UInt16;
                if (initialSize <= 4 && static_cast<uint64_t>(high) <= UINT32_MAX)
                    return EnumUnderlyingType::UInt32;
                return EnumUnderlyingType::UInt64;
            }
            if (initialSize <= 1 && low >= INT8_MIN && high <= INT8_MAX)
                return EnumUnderlyingType::Int8;
            if (initialSize <= 2 && low >= INT16_MIN && high <= INT16_MAX)
                return EnumUnderlyingType::Int16;
            if (initialSize <= 4 && low >= INT32_MIN && high <= INT32_MAX)
                return EnumUnderlyingType::Int32;
            return EnumUnderlyingType::Int64;
        }

        std::string ReflectedStringType(std::string_view reflectedClass)
        {
            if (reflectedClass.size() > 1 &&
                (reflectedClass.front() == 'F' || reflectedClass.front() == 'U') &&
                reflectedClass[1] >= 'A' && reflectedClass[1] <= 'Z')
                reflectedClass.remove_prefix(1);
            if (reflectedClass == "Utf8StrProperty")
                return "FUtf8String";
            if (reflectedClass == "AnsiStrProperty")
                return "FAnsiString";
            return "FString";
        }

        std::string UniqueName(std::unordered_set<std::string> &used, std::string stem)
        {
            std::string name = stem;
            size_t suffix = 0;
            while (!used.insert(name).second)
                name = stem + "_" + std::to_string(++suffix);
            return name;
        }

        std::string ChildFailurePath(const char *member, const CppPropertyType &child)
        {
            return child.failurePath.empty() ? member : std::string(member) + "." + child.failurePath;
        }
    } // namespace

    std::string SanitizeIdentifier(std::string value, const char *fallback)
    {
        for (char &character : value)
        {
            const bool valid = (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
                               (character >= '0' && character <= '9') || character == '_';
            if (!valid)
                character = '_';
        }
        static const std::unordered_set<std::string> keywords = {
            "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break", "case", "catch",
            "char", "char8_t", "char16_t", "char32_t", "class", "compl", "concept", "const", "consteval", "constexpr",
            "constinit", "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype", "default", "delete",
            "do", "double", "dynamic_cast", "else", "enum", "explicit", "export", "extern", "false", "float", "for",
            "friend", "goto", "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept", "not", "not_eq",
            "nullptr", "operator", "or", "or_eq", "private", "protected", "public", "register", "reinterpret_cast",
            "requires", "return", "short", "signed", "sizeof", "static", "static_assert", "static_cast", "struct",
            "switch", "template", "this", "thread_local", "throw", "true", "try", "typedef", "typeid", "typename",
            "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq"};
        if (value.empty() || (value.front() >= '0' && value.front() <= '9') || keywords.contains(value))
            value = std::string(fallback) + value;
        return value;
    }

    std::string ValueLayoutCppName(const std::string &id)
    {
        return "FValueLayout_" + SanitizeIdentifier(id, "Unknown");
    }

    CppSymbols BuildCppSymbols(const ir::ReflectionIR &reflection)
    {
        CppSymbols result;
        std::unordered_set<std::string> used = {"FName", "FString", "FUtf8String", "FAnsiString", "FScriptInterface", "TargetAddress", "TTargetPointer", "FUnknownContainerLayout", "FHeapArrayLayout", "FHeapSparseSetLayout", "TArray", "TSet", "TMap", "TEnumStorage", "TOpaqueStorage", "TStructStorage", "TStaticArrayStorage", "FTextStorage", "TWeakObjectStorage", "TLazyObjectStorage", "TSoftObjectStorage", "TSoftClassStorage", "TFieldPathStorage", "TDelegateStorage", "TInlineMulticastDelegateStorage", "TSparseMulticastDelegateStorage", "TUnknownMulticastDelegateStorage", "TOptionalStorage"};
        used.insert({"FUnknownValueLayout", "FMemoryImageArrayLayout", "FMemoryImageSparseSetLayout"});
        // // 在此处保留由 BasicTypes、Remote 及 SDK 聚合器所生成的命名空间级名称
        used.insert({"std", "InRange", "EngineLayout", "detail", "ObjectFlag",
                     "ReadStatus", "ReadResult", "ReadMemoryCallback", "MemoryReader",
                     "DecodeDescriptor", "DecodeSlot", "DecodeSlotName", "NameTextCodec", "NameTextFamily",
                     "PropertyKind", "TypeKind", "DelegateStorageKind", "ContainerAllocatorKind",
                     "BoolLayoutDescriptor", "StorageMemberDescriptor", "ValueStorageDescriptor", "ContainerDescriptor",
                     "ValueDescriptor", "FieldDescriptor", "TypeDescriptor", "EnumValueDescriptor", "EnumDescriptor",
                     "ObjectArrayKind", "ObjectArrayDescriptor", "NameStoreKind", "NameStoreDescriptor",
                     "FNameDescriptor", "ObjectDescriptor", "RuntimeBindingDescriptor", "RuntimeRoots", "RuntimeOptions",
                     "RemoteRuntime", "ObjectHandle", "RemoteObjectView", "RemoteStructView", "RemoteStaticArrayView",
                     "RemoteArrayView", "RemoteSparseContainerView", "RemoteMapEntryView", "ObjectReference", "EnumValue",
                     "WeakObjectReference", "SoftObjectReference", "LazyObjectReference", "InterfaceReference",
                     "DelegateReference", "TextReference", "OpaqueValue", "RemoteValue", "ValueReadResult", "ObjectInfo",
                     "ObjectFlagsFilter", "FieldLookupResult", "ObjectQuery", "ObjectQueryResult", "ObjectLookupResult",
                     "TargetBinding", "AllTypes", "AllTypeCount", "AllEnums", "AllEnumCount", "CreateRuntime"});
        for (const auto &[id, layout] : reflection.valueStorageLayouts)
        {
            (void)layout;
            result.valueLayouts.emplace(id, UniqueName(used, ValueLayoutCppName(id)));
        }
        // 所有声明和引用共用同一个符号表；重名后缀不依赖进程地址
        for (const auto &type : reflection.types)
            result.types.emplace(type.address, CppTypeInfo{UniqueName(used, SanitizeIdentifier(type.name, "Type_")),
                                                           type.size,
                                                           type.layout.representation,
                                                           false,
                                                           false,
                                                           {}});
        for (const auto &enumeration : reflection.enums)
        {
            CppEnumInfo info;
            info.name = UniqueName(used, SanitizeIdentifier(enumeration.name, "Enum_"));
            info.underlyingType = EnumType(enumeration);
            info.size = EnumSize(info.underlyingType);
            std::unordered_set<std::string> valueNames;
            for (const auto &value : enumeration.values)
                info.values.push_back(UniqueName(valueNames, SanitizeIdentifier(value.name, "Value_")));
            result.enums.emplace(enumeration.address, std::move(info));
        }
        std::vector<const ir::FunctionIR *> functions;
        functions.reserve(reflection.functions.size());
        for (const auto &[address, function] : reflection.functions)
        {
            (void)address;
            if (function.headerReadable)
                functions.push_back(&function);
        }
        std::sort(functions.begin(), functions.end(), [](const auto *left, const auto *right)
                  { return std::tie(left->fullName, left->address) < std::tie(right->fullName, right->address); });
        for (const auto *definition : functions)
        {
            const auto &function = *definition;
            const auto owner = result.types.find(function.outerAddress);
            const std::string ownerName = owner == result.types.end() ? function.outerFullName : owner->second.name;
            const std::string stem = SanitizeIdentifier(ownerName + "_" + function.name, "Function_");
            std::string name = stem;
            size_t suffix = 0;
            static constexpr std::array<const char *, 7> endings = {
                "_Params", "_ParamsSize", "_ExecEntryRva", "_HasExecEntryRva", "_NativeExecRva", "_HasNativeExecRva", "_Signature"};
            const auto conflicts = [&]
            {
                return std::any_of(endings.begin(), endings.end(), [&](const char *ending)
                                   { return used.contains(name + ending); });
            };
            while (conflicts())
                name = stem + "_" + std::to_string(++suffix);
            for (const auto &ending : endings)
                used.insert(name + ending);
            result.functions.emplace(function.address, std::move(name));
        }

        for (const auto &type : reflection.types)
        {
            auto &info = result.types.at(type.address);
            const auto reserve = [&](const std::string &stem)
            {
                std::string name = UniqueName(used, stem);
                if (name != stem)
                    info.metadataNames.emplace(stem, std::move(name));
            };
            std::function<void(const ir::TypeReferenceIR &, const std::string &)> reserveValue;
            reserveValue = [&](const ir::TypeReferenceIR &reference, const std::string &stem)
            {
                if (reference.inner)
                    reserveValue(*reference.inner, stem + "_Inner");
                if (reference.key)
                    reserveValue(*reference.key, stem + "_Key");
                if (reference.value)
                    reserveValue(*reference.value, stem + "_Value");
                if (reference.valueStorage && !reference.valueStorage->offsets.empty())
                    reserve(stem + "_StorageMembers");
                reserve(stem);
            };
            for (size_t index = 0; index < type.properties.size(); ++index)
                reserveValue(type.properties[index].type, info.name + "_Field_" + std::to_string(index) + "_Value");
            if (!type.properties.empty())
                reserve(info.name + "_RemoteFields");
            reserve(info.name + "_RemoteType");
        }
        for (const auto &enumeration : reflection.enums)
        {
            auto &info = result.enums.at(enumeration.address);
            info.remoteValues = UniqueName(used, info.name + "_RemoteValues");
            info.remoteType = UniqueName(used, info.name + "_RemoteType");
        }
        const auto declarations = ir::PlanTypeDeclarations(reflection);
        result.typeOrder = declarations.order;
        for (const auto &[address, declaration] : declarations.types)
        {
            auto &info = result.types.at(address);
            info.layout = declaration.representation;
            info.declarationDependencyBlocked = declaration.dependencyBlocked;
            info.inheritsBase = declaration.inheritsBase;
        }
        return result;
    }

    const char *EnumUnderlyingName(EnumUnderlyingType type)
    {
        switch (type)
        {
        case EnumUnderlyingType::Int8:
            return "std::int8_t";
        case EnumUnderlyingType::UInt8:
            return "std::uint8_t";
        case EnumUnderlyingType::Int16:
            return "std::int16_t";
        case EnumUnderlyingType::UInt16:
            return "std::uint16_t";
        case EnumUnderlyingType::Int32:
            return "std::int32_t";
        case EnumUnderlyingType::UInt32:
            return "std::uint32_t";
        case EnumUnderlyingType::UInt64:
            return "std::uint64_t";
        default:
            return "std::int64_t";
        }
    }

    const char *PropertyStorageKindName(PropertyStorageKind kind)
    {
        switch (kind)
        {
        case PropertyStorageKind::Unavailable:
            return "unavailable";
        case PropertyStorageKind::SizedDescription:
            return "sized-description";
        case PropertyStorageKind::BoolMask:
            return "bool-mask";
        case PropertyStorageKind::TypedOpaque:
            return "typed-opaque";
        case PropertyStorageKind::PartialContainer:
            return "partial-container";
        }
        return "unavailable";
    }

    static CppPropertyType ResolveSizedType(const ir::TypeReferenceIR &reference, const CppSymbols &symbols,
                                            int32_t pointerWidth, int32_t nameSize, size_t depth)
    {
        if (!reference.detailsResolved)
            return {{}, "unresolved-type-details"};
        if (reference.elementSize <= 0)
            return {{}, "invalid-element-size"};
        if (depth >= 32)
            return {{}, "type-depth-limit"};
        const auto sized = [&](const std::string &name, int32_t size)
        {
            return reference.elementSize == size ? CppPropertyType{name, {}} : CppPropertyType{{}, "size-mismatch:expected=" + std::to_string(size) + ":observed=" + std::to_string(reference.elementSize)};
        };
        switch (reference.kind)
        {
        case PropertyKind::Int8:
            return sized("std::int8_t", 1);
        case PropertyKind::Int16:
            return sized("std::int16_t", 2);
        case PropertyKind::Int32:
            return sized("std::int32_t", 4);
        case PropertyKind::Int64:
            return sized("std::int64_t", 8);
        case PropertyKind::UInt16:
            return sized("std::uint16_t", 2);
        case PropertyKind::UInt32:
            return sized("std::uint32_t", 4);
        case PropertyKind::UInt64:
            return sized("std::uint64_t", 8);
        case PropertyKind::Bool:
            return sized("std::uint8_t", 1);
        case PropertyKind::Byte:
            if (reference.referencedObject != 0)
            {
                const auto found = symbols.enums.find(reference.referencedObject);
                if (found == symbols.enums.end())
                    return {{}, "missing-enum-symbol"};
                const auto &enumeration = found->second;
                return sized(enumeration.underlyingType == EnumUnderlyingType::UInt8 && enumeration.size == 1
                                 ? enumeration.name
                                 : "TEnumStorage<" + enumeration.name + ", std::uint8_t>",
                             1);
            }
            return sized("std::uint8_t", 1);
        case PropertyKind::Float:
            return sized("float", 4);
        case PropertyKind::Double:
            return sized("double", 8);
        case PropertyKind::Name:
            return sized("FName", nameSize);
        case PropertyKind::String:
            return sized(ReflectedStringType(reference.reflectedClass), pointerWidth + 8);
        case PropertyKind::Object:
        case PropertyKind::Class:
            if (const auto found = symbols.types.find(reference.referencedObject); found != symbols.types.end())
                return sized("TTargetPointer<" + found->second.name + ">", pointerWidth);
            return {{}, "missing-type-symbol"};
        case PropertyKind::Struct:
            if (const auto found = symbols.types.find(reference.referencedObject); found != symbols.types.end())
            {
                if (found->second.size <= 0)
                    return {{}, "invalid-referenced-type-size"};
                if (found->second.layout == ir::LayoutRepresentation::OffsetDescription)
                {
                    if (reference.elementSize != found->second.size)
                        return {{}, "referenced-type-size-disagreement"};
                    CppPropertyType result{"TStructStorage<" + found->second.name + ", " +
                                               std::to_string(reference.elementSize) + ">",
                                           "semantic-declaration-not-storage"};
                    result.semanticName = found->second.name;
                    result.storage = PropertyStorageKind::TypedOpaque;
                    return result;
                }
                return sized(found->second.name, found->second.size);
            }
            return {{}, "missing-type-symbol"};
        case PropertyKind::Enum:
            if (const auto found = symbols.enums.find(reference.secondaryObject); found != symbols.enums.end())
            {
                if (!reference.inner || reference.inner->elementSize != reference.elementSize)
                    return {{}, "invalid-enum-storage"};
                EnumUnderlyingType storage = EnumUnderlyingType::Unknown;
                switch (reference.inner->kind)
                {
                case PropertyKind::Int8:
                    storage = EnumUnderlyingType::Int8;
                    break;
                case PropertyKind::Byte:
                    storage = EnumUnderlyingType::UInt8;
                    break;
                case PropertyKind::Int16:
                    storage = EnumUnderlyingType::Int16;
                    break;
                case PropertyKind::UInt16:
                    storage = EnumUnderlyingType::UInt16;
                    break;
                case PropertyKind::Int32:
                    storage = EnumUnderlyingType::Int32;
                    break;
                case PropertyKind::UInt32:
                    storage = EnumUnderlyingType::UInt32;
                    break;
                case PropertyKind::Int64:
                    storage = EnumUnderlyingType::Int64;
                    break;
                case PropertyKind::UInt64:
                    storage = EnumUnderlyingType::UInt64;
                    break;
                default:
                    return {{}, "invalid-enum-storage"};
                }
                const auto inner = ResolvePropertyType(*reference.inner, symbols, pointerWidth, nameSize, depth + 1);
                if (inner.name.empty())
                {
                    CppPropertyType result{{}, "inner:" + inner.failureReason};
                    result.failurePath = ChildFailurePath("inner", inner);
                    return result;
                }
                if (storage == found->second.underlyingType && found->second.size == reference.elementSize)
                    return {found->second.name, {}};
                return {"TEnumStorage<" + found->second.name + ", " + inner.name + ">", {}};
            }
            return {{}, "missing-enum-symbol"};
        case PropertyKind::Interface:
            if (symbols.types.contains(reference.referencedObject))
                return sized("FScriptInterface", pointerWidth * 2);
            return {{}, "missing-type-symbol"};
        default:
            return {{}, "unsupported-property-kind"};
        }
    }

    CppPropertyType ResolvePropertyType(const ir::TypeReferenceIR &reference, const CppSymbols &symbols,
                                        int32_t pointerWidth, int32_t nameSize, size_t depth)
    {
        if (depth >= 32)
            return {{}, "type-depth-limit"};
        CppPropertyType result = ResolveSizedType(reference, symbols, pointerWidth, nameSize, depth);
        result.semanticsResolved = reference.detailsResolved;
        if (result.semanticName.empty())
            result.semanticName = result.name.empty() ? reference.reflectedClass : result.name;
        if (!result.name.empty())
        {
            const auto enumeration = symbols.enums.find(reference.kind == PropertyKind::Byte ? reference.referencedObject : reference.secondaryObject);
            if ((reference.kind == PropertyKind::Byte || reference.kind == PropertyKind::Enum) && enumeration != symbols.enums.end())
                result.semanticName = enumeration->second.name;
            if (reference.kind == PropertyKind::Object || reference.kind == PropertyKind::Class)
                result.semanticName = symbols.types.at(reference.referencedObject).name + "*";
            if (result.storage == PropertyStorageKind::Unavailable)
                result.storage = PropertyStorageKind::SizedDescription;
            return result;
        }
        if ((!reference.detailsResolved && !reference.nodeDetailsResolved) || reference.elementSize <= 0)
            return result;
        const std::string size = std::to_string(reference.elementSize);
        const auto object = symbols.types.find(reference.referencedObject);
        const std::string target = object == symbols.types.end() ? "void" : object->second.name;
        const auto opaque = [&](const std::string &wrapper, const std::string &semantic, const std::string &argument = "",
                                const std::string &layout = "")
        {
            const auto layoutName = reference.valueStorage ? symbols.valueLayouts.find(reference.valueStorage->id)
                                                           : symbols.valueLayouts.end();
            if (reference.valueStorage && layout.empty() && layoutName == symbols.valueLayouts.end())
            {
                result.name.clear();
                result.failureReason = "value-storage-layout-unavailable";
                result.storage = PropertyStorageKind::Unavailable;
                return;
            }
            const std::string valueLayout = layoutName != symbols.valueLayouts.end() ? ", " + layoutName->second : "";
            result.name = wrapper + "<" + argument + size + (layout.empty() ? valueLayout : layout) + ">";
            result.semanticName = semantic;
            result.storage = PropertyStorageKind::TypedOpaque;
            result.failureReason = "internals-not-expanded";
        };
        const auto containerLayout = [&]() -> std::string
        {
            const auto &storage = reference.containerStorage;
            if (!storage || (storage->headerStatus != "source-model-and-size-match" &&
                             storage->headerStatus != "source-model-fits-reflected-extent"))
                return {};
            if (reference.kind == PropertyKind::Array && storage->layoutId == "heap-array-p" + std::to_string(pointerWidth))
                return ", FHeapArrayLayout";
            if ((reference.kind == PropertyKind::Map || reference.kind == PropertyKind::Set) &&
                storage->layoutId == "heap-sparse-set-p" + std::to_string(pointerWidth))
                return ", FHeapSparseSetLayout";
            if (reference.kind == PropertyKind::Array && storage->layoutId == "memory-image-array-p" + std::to_string(pointerWidth))
                return ", FMemoryImageArrayLayout";
            if ((reference.kind == PropertyKind::Map || reference.kind == PropertyKind::Set) &&
                storage->layoutId == "memory-image-sparse-set-p" + std::to_string(pointerWidth))
                return ", FMemoryImageSparseSetLayout";
            return {};
        };
        const auto child = [&](const std::shared_ptr<ir::TypeReferenceIR> &node)
        {
            CppPropertyType type = node ? ResolvePropertyType(*node, symbols, pointerWidth, nameSize, depth + 1)
                                        : CppPropertyType{{}, "missing-child-type"};
            if (node && type.name.empty() && node->elementSize > 0)
            {
                // 保留已知的子项分类与反射范围，同时不对内部结构的有效性做任何断言
                type.name = "TOpaqueStorage<" + std::to_string(node->elementSize) + ">";
                type.semanticName = node->reflectedClass.empty() ? "Unknown" : node->reflectedClass;
                type.storage = PropertyStorageKind::TypedOpaque;
            }
            if (node && !type.name.empty() && node->arrayDim > 1)
            {
                if (static_cast<int64_t>(node->elementSize) * node->arrayDim > INT32_MAX)
                    return CppPropertyType{{}, "invalid-child-storage-size"};
                type.name = "TStaticArrayStorage<" + type.name + ", " + std::to_string(node->elementSize) +
                            ", " + std::to_string(node->arrayDim) + ">";
                type.semanticName += "[" + std::to_string(node->arrayDim) + "]";
                type.storage = PropertyStorageKind::TypedOpaque;
                type.failureReason = type.failureReason.empty() ? "static-array-storage-not-expanded"
                                                                : "static-array-storage-not-expanded:" + type.failureReason;
            }
            if (node && node->arrayDim <= 0)
                type = {{}, "invalid-child-array-dim"};
            return type;
        };
        switch (reference.kind)
        {
        case PropertyKind::Text:
            opaque("FTextStorage", "FText");
            break;
        case PropertyKind::WeakObject:
            if (object == symbols.types.end())
            {
                result.failureReason = "missing-type-symbol";
                break;
            }
            opaque("TWeakObjectStorage", "TWeakObjectPtr<" + target + ">", target + ", ");
            if (reference.elementSize == 8)
            {
                result.storage = PropertyStorageKind::SizedDescription;
                result.failureReason.clear();
            }
            break;
        case PropertyKind::LazyObject:
            if (object == symbols.types.end())
            {
                result.failureReason = "missing-type-symbol";
                break;
            }
            opaque("TLazyObjectStorage", "TLazyObjectPtr<" + target + ">", target + ", ");
            break;
        case PropertyKind::SoftObject:
            if (object == symbols.types.end())
            {
                result.failureReason = "missing-type-symbol";
                break;
            }
            opaque("TSoftObjectStorage", "TSoftObjectPtr<" + target + ">", target + ", ");
            break;
        case PropertyKind::SoftClass:
            if (object == symbols.types.end())
            {
                result.failureReason = "missing-type-symbol";
                break;
            }
            opaque("TSoftClassStorage", "TSoftClassPtr<" + target + ">", target + ", ");
            break;
        case PropertyKind::FieldPath:
            opaque("TFieldPathStorage", reference.reflectedClass);
            break;
        case PropertyKind::Delegate:
        case PropertyKind::MulticastDelegate:
        {
            const auto signature = symbols.functions.find(reference.referencedObject);
            if (signature == symbols.functions.end())
            {
                result.failureReason = "missing-signature-symbol";
                break;
            }
            const std::string tag = signature->second + "_Signature";
            const char *wrapper = "TUnknownMulticastDelegateStorage";
            switch (reference.delegateStorage)
            {
            case ir::DelegateStorageKind::Unicast:
                wrapper = "TDelegateStorage";
                break;
            case ir::DelegateStorageKind::InlineMulticast:
                wrapper = "TInlineMulticastDelegateStorage";
                break;
            case ir::DelegateStorageKind::SparseMulticast:
                wrapper = "TSparseMulticastDelegateStorage";
                break;
            default:
                break;
            }
            opaque(wrapper,
                   reference.reflectedClass + "<" + tag + ">", tag + ", ");
            if (reference.delegateStorage == ir::DelegateStorageKind::SparseMulticast && reference.elementSize == 1)
            {
                result.storage = PropertyStorageKind::SizedDescription;
                result.failureReason.clear();
            }
            break;
        }
        case PropertyKind::Array:
        case PropertyKind::Set:
        case PropertyKind::Optional:
        {
            const auto inner = child(reference.inner);
            if (inner.name.empty())
            {
                result.failureReason = "inner:" + inner.failureReason;
                result.failurePath = ChildFailurePath("inner", inner);
                break;
            }
            const std::string wrapper = reference.kind == PropertyKind::Array ? "TArray" : reference.kind == PropertyKind::Set ? "TSet"
                                                                                                                               : "TOptionalStorage";
            opaque(wrapper, wrapper + "<" + inner.semanticName + ">", inner.name + ", ", containerLayout());
            result.storage = inner.IsOpaque() ? PropertyStorageKind::PartialContainer : PropertyStorageKind::TypedOpaque;
            result.failureReason = inner.IsOpaque() ? "inner:" + inner.failureReason : "container-internals-not-expanded";
            if (inner.IsOpaque())
                result.failurePath = ChildFailurePath("inner", inner);
            break;
        }
        case PropertyKind::Map:
        {
            const auto key = child(reference.key);
            const auto value = child(reference.value);
            if (key.name.empty() || value.name.empty())
            {
                result.failureReason = key.name.empty() ? "key:" + key.failureReason : "value:" + value.failureReason;
                result.failurePath = key.name.empty() ? ChildFailurePath("key", key) : ChildFailurePath("value", value);
                break;
            }
            opaque("TMap", "TMap<" + key.semanticName + ", " + value.semanticName + ">", key.name + ", " + value.name + ", ", containerLayout());
            result.storage = key.IsOpaque() || value.IsOpaque() ? PropertyStorageKind::PartialContainer : PropertyStorageKind::TypedOpaque;
            result.failureReason = key.IsOpaque() ? "key:" + key.failureReason : value.IsOpaque() ? "value:" + value.failureReason
                                                                                                  : "container-internals-not-expanded";
            if (key.IsOpaque() || value.IsOpaque())
                result.failurePath = key.IsOpaque() ? ChildFailurePath("key", key) : ChildFailurePath("value", value);
            break;
        }
        default:
            break;
        }
        return result;
    }

    FieldDescription DescribeField(const ir::PropertyIR &property, int32_t bound,
                                   const CppSymbols &symbols, int32_t pointerWidth, int32_t nameSize)
    {
        FieldDescription result;
        result.property = &property;
        result.type.semanticName = property.reflectedClass;
        result.type.semanticsResolved = property.typeDetailsResolved;
        int64_t end = 0;
        result.validBounds = !ir::IsVirtualProperty(property) && ir::IsValidPropertyBounds(property, bound, end);
        result.boolLayout = ir::IsValidPropertyBoolLayout(property);
        if (property.type.elementSize != property.elementSize)
            result.type.failureReason = "property-type-size-disagreement";
        else if (property.type.kind == PropertyKind::Bool)
        {
            result.type.semanticName = "bool";
            result.type.semanticsResolved = property.typeDetailsResolved;
            result.type.storage = result.boolLayout ? PropertyStorageKind::BoolMask : PropertyStorageKind::Unavailable;
            if (!result.boolLayout)
                result.type.failureReason = "invalid-bool-layout";
        }
        else
            result.type = ResolvePropertyType(property.type, symbols, pointerWidth, nameSize);
        return result;
    }
} // namespace nextdumper::generation
