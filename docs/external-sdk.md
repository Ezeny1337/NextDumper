# 外部内存 SDK

生成的 `sdk/SDK.hpp` 在布局声明之外提供只读外部访问器。它不链接进目标进程，也不调用 Unreal 函数。消费者提供精确的目标内存读取回调和目标模块基址；SDK 根据本次 dump 验证过的绑定、反射类型和字段描述完成对象查找与值读取。

生成头文件兼容 C++17，无需链接 NextDumper 运行库或增加第三方依赖。SDK 使用生成目标对应宽度的 `NextDumper::TargetAddress`，并在初始化时检查绑定宽度；地址不能转换或解引用为消费者进程中的本地指针。

## 接口

`sdk/SDK.hpp` 是聚合入口，包含以下运行时文件：

- `Remote.hpp` 是外部读取器的聚合头文件。
- `Remote/Memory.hpp` 定义读取回调和读取状态。
- `Remote/Metadata.hpp` 定义绑定与反射描述；`Remote/Views.hpp` 定义对象和值视图；`Remote/Runtime.hpp` 声明读取运行时。
- `Remote/NameTextCodec.hpp` 与 `Remote/DecodeDescriptor.hpp` 提供共享的内置名称算法和解码能力描述。
- `Remote/detail/` 按核心、对象、名称、字段、标量、引用和容器职责保存运行时的 inline 实现。
- `Binding.hpp` 保存已验证的 UE 根地址 RVA、对象/名称容器布局、UObject/FName 布局和解码规则。
- `Metadata.hpp` 汇总生成的类型与枚举描述。
- `Types/*.hpp` 提供类型字段描述及原有布局声明。

使用 `SDK.hpp` 或 `Remote.hpp` 时无需直接包含 `Remote/` 下的文件。发布 SDK 时需保留整个生成目录，使相对包含路径保持有效。

`runtime.json` 是本次目标进程的诊断快照，不是 SDK 的配置输入。其绝对地址只对捕获时的进程会话有效；消费者应使用生成的绑定、当前模块基址和本会话读取结果。

读取回调返回实际传输字节数；失败返回负值。`MemoryReader` 按 `maxTransferBytes` 拆分较大请求，并且只有完整读取才会交付成功结果。传输长度、地址溢出和容器计数均在 SDK 内检查。

## 接入读取后端

把消费者现有的读取接口适配到 `ReadMemoryCallback`。后端的句柄、进程标识、线程上下文或内核设备状态放在 `context` 中；SDK 不要求特定的读取库或进程管理方式。回调返回实际传输字节数，失败返回负值。若后端只返回布尔值，只有在它保证完整读取时才把成功转换为请求长度。`maxTransferBytes` 设置为后端单次调用的上限；没有单次长度限制时可以使用默认值。

```cpp
#include "sdk/SDK.hpp"

#include <cstdint>

struct ConsumerBackend
{
    void *handle;
    std::int64_t (*read)(void *, std::uint64_t, void *, std::size_t);
    std::size_t maxTransferBytes;
};

// 将消费者自己的读取接口和目标/会话句柄适配到此签名。
std::int64_t ConsumerRead(
    void *handle,
    std::uint64_t address,
    void *buffer,
    std::size_t size);

static std::int64_t ReadTargetMemory(
    void *opaque,
    NextDumper::TargetAddress address,
    void *buffer,
    std::size_t size)
{
    auto &backend = *static_cast<ConsumerBackend *>(opaque);
    if (!backend.read)
        return -1;
    return backend.read(backend.handle, static_cast<std::uint64_t>(address), buffer, size);
}

// 将读取后端句柄绑定到当前目标进程或会话。
ConsumerBackend backend{consumerHandle, &ConsumerRead, consumerReadLimit};
auto runtime = NextDumper::CreateRuntime(
    {&backend, &ReadTargetMemory, backend.maxTransferBytes},
    static_cast<NextDumper::TargetAddress>(moduleBase));

const auto initialized = runtime.Initialize(expectedModuleName);
if (initialized != NextDumper::ReadStatus::Ok)
{
    // 初始化成功前不要使用对象或字段视图。
}
```

示例中的后端名称仅用于说明。应按消费者自己的 API 映射回调参数和返回值；SDK 不要求特定的句柄类型、进程标识、权限级别或传输方式。

## 解码与运行时能力

`TargetBinding.decoding` 保存本次目标所需的算法与参数。Dumper 和生成 SDK 使用同一份 C++17 算法实现；消费者无需复制解码代码或修改绑定标记。

| 名称算法 | 参数 | 适用条件 |
| --- | --- | --- |
| `Identity` | 无，`Key` 为 0 | 名称文本无需变换 |
| `ByteXor` | 单字节 `Key` | 对名称字节逐项 XOR |
| `LengthSchedule` | 无，`Key` 为 0 | 必须由 NamePool 条目头取得真实字符数 |

SDK 在完整读取名称字节后执行解码，再转换字符并缓存结果。名称算法不会应用到 `FString`、普通字符串或业务字段。旧式 GNames 缺少条目长度，不能使用 `LengthSchedule`。

`ByteXor` 的键在被验证的名称字节间保持一致，不证明它跨进程会话恒定。需要从当前会话读取密钥的算法应使用自定义回调；导出采集时的数值不能代替密钥获取规则。初始化名称校验失败时，应拒绝使用该绑定。

`DecodeDescriptor::IsSupported(namePool, chunkedObjects)` 可在不读内存的情况下检查解码能力。必要位置仍依赖自定义回调时，`Initialize()` 返回 `Unsupported`；未知算法、非法参数或未定义的解码位置标志位返回 `InvalidArgument`。Dumper 的自定义回调不会被序列化成 SDK 可执行代码。

`manifest.json`、`diagnostics.json` 和 `runtime.json` 均提供 `external_runtime`：

| 字段 | 含义 |
| --- | --- |
| `status` | `supported` 或 `unsupported`，范围为本次绑定及其必要解码 |
| `decoding.name_text` | 算法、参数、参数来源与选择来源；`default` 为默认 identity，`explicit` 为显式配置，`analysis` 为自动分析 |
| `decoding.name_text.analysis_validation` | Analysis 已知名称匹配数、遍历条目数和窄/宽字符样本数；非 Analysis 来源为 `null` |
| `decoding.custom_slots` | Dumper 中仍使用自定义回调的位置 |
| `capture_validation` | 本次采集时对象、名称和语义绑定的验证结果 |
| `required_inputs` | 无法以模块 RVA 导出的根地址，消费者需通过当前会话的 `RuntimeRoots` 提供 |
| `unsupported` | 不支持的位置与原因，例如 `custom-decoder-not-exported` |

已知名称匹配使用窄字符；额外采样分别记录窄/宽字符数量。`wide_samples` 为 0 表示没有宽字符采样证据，不代表所有宽字符名称已经验证。

`external_runtime.status` 与 `reflection_status`、`sdk_status` 独立。反射 `Partial` 的产物可以支持已完整描述的字段；反射 `Complete` 也不能证明外部运行时具备自定义解码。`supported` 不代替当前会话的初始化检查，也不保证所有属性种类都支持值读取。

生成头文件的绑定结构会随读取契约更新，升级产物时应整套替换 `sdk/`。JSON 读取器仅接受对应的新 schema，不提供旧格式兼容。

## 对象查询

`FindFirstUClassObject("World")` 查找名为 `World` 的 UClass 元对象，包括蓝图生成类等 UClass 派生元类。生成 SDK 需要包含 `Class /Script/CoreUObject.Class` 的类型描述。此接口查找类的反射对象，不查找该类的实例。

对象查询扫描原始 UObject 数组，不会默认排除 Class Default Object（CDO）、archetype 或其他对象模板，也不保证对象当前可用于游戏逻辑。

- `FindFirstObjectOfType(classFullName)` 返回扫描顺序中的第一个类型匹配项。
- `FindObjectsOfType(classFullName, maxResults, includeDerived)` 返回多个匹配项。
- `FindFirstObject(query)` 和 `FindObjects(query, maxResults)` 支持组合对象名、类名和完整名条件。
- 类型名使用 `TypeDescriptor::fullName` 格式，可先用 `FindType` 查询。启用派生类匹配时，基类必须有类型描述；缺少父类描述会使结果状态变为 `Incomplete`。
- `maxResults` 限制返回对象数；实际扫描数量由 `RuntimeOptions::maxObjectsPerSearch` 限制。若匹配项不足，查询仍可能扫描整个允许范围。

所有对象查找接口都可接收 `ObjectFlagsFilter`。`requireAll` 中的位必须全部存在，`excludeAny` 中任一位存在都会排除对象；空过滤器不读取 flags。指定过滤条件但绑定中没有 flags 偏移时，查询返回 `Unsupported`；扫描期间 flags 读取失败时，查询标记为 `Incomplete` 并跳过该对象。

```cpp
NextDumper::ObjectFlagsFilter excludeTemplates;
excludeTemplates.excludeAny = NextDumper::ObjectFlag::ClassDefaultObject |
                              NextDumper::ObjectFlag::ArchetypeObject;
const auto worldResult = runtime.FindFirstObjectOfType(
    "Class /Script/Engine.World", true, excludeTemplates);
```

过滤 CDO 或 archetype 仍不能保证结果是当前活动 World。`FindFirst...` 按对象数组顺序返回第一个匹配项，不保证名称唯一，也不代表当前活动的 World 或其他全局实例；需要消歧时使用完整对象名。

## 反射字段

`FindType` 返回生成 SDK 中的类或结构描述，包含大小、父类完整名、父类描述是否已生成，以及直接声明的字段。`FindField` 会沿可用的父类描述查找字段，并返回 `FieldLookupResult`：

- `Ok`：找到字段。
- `NotFound`：完整描述的继承链中没有该字段。
- `Incomplete`：字段或父类描述不完整、继承链循环或达到深度上限。

`FieldDescriptor` 提供字段偏移、元素大小、静态数组长度和 `ValueDescriptor`。后者描述属性种类、引用类型和容器元素类型。可用这些信息检查 `Health` 等候选字段及其存储形式；不需要解析 `runtime.json` 或反射 JSON。

遍历某个类型直接声明的字段：

```cpp
const auto *playerStateType = runtime.FindType("Class /Script/Engine.PlayerState");
for (std::size_t index = 0; playerStateType && index < playerStateType->fieldCount; ++index)
{
    const auto &field = playerStateType->fields[index];
    // field.name, field.offset, field.elementSize, field.arrayDim, field.type
}
```

## 读取字段与容器

下面示例展示通用读取流程：检查 `Health` 的反射描述，再沿对象字段和数组读取实例。类名、字段名及对象关系仅为示例，实际路径应以目标游戏的反射产物为准。

```cpp
NextDumper::ObjectFlagsFilter excludeTemplates;
excludeTemplates.excludeAny = NextDumper::ObjectFlag::ClassDefaultObject |
                              NextDumper::ObjectFlag::ArchetypeObject;
const auto worldResult = runtime.FindFirstObjectOfType(
    "Class /Script/Engine.World", true, excludeTemplates);
const auto *playerStateType = runtime.FindType("Class /Script/Engine.PlayerState");
const auto healthLookup = runtime.FindField(playerStateType, "Health");
const auto *healthField = healthLookup.field;

if (worldResult.object && healthLookup.Ok() && healthField->validBounds && healthField->type &&
    healthField->type->kind == NextDumper::PropertyKind::Float)
{
    NextDumper::RemoteObjectView gameState;
    if (runtime.ReadField(*worldResult.object, "GameState", gameState) == NextDumper::ReadStatus::Ok)
    {
        NextDumper::RemoteArrayView playerArray;
        if (runtime.ReadField(gameState, "PlayerArray", playerArray) == NextDumper::ReadStatus::Ok)
        {
            for (std::int32_t index = 0; index < playerArray.count; ++index)
            {
                NextDumper::RemoteObjectView playerState;
                if (runtime.ReadElement(playerArray, index, playerState) != NextDumper::ReadStatus::Ok)
                    continue;

                float health = 0.0f;
                if (runtime.ReadField(playerState, healthField->name, health) != NextDumper::ReadStatus::Ok)
                    continue;
            }
        }
    }
}
```

标量可直接读入 C++ 类型；对象、结构体、数组、静态数组元素及 map 键/值也支持类型化读取。复杂结果仍可通过 `ValueReadResult` 访问完整 variant 和状态。

SDK 只提供结构描述和通用读取，不判断本地玩家，也不解释 `Health`、坐标或玩家列表等游戏语义。完整遍历时检查查询状态：`LimitExceeded` 表示达到结果或扫描上限，`Incomplete` 表示部分对象或元数据不可读。

对象引用行为：

- `RemoteObjectView` 使用已验证的对象句柄。
- 空引用返回 `ReadStatus::Empty`；非空但无法解析或验证的引用返回 `InvalidReference`。
- 需要保留弱引用索引和 serial，或普通对象指针原始地址时，分别读取为 `WeakObjectReference` 或 `ObjectReference`。

容器行为：

- 已验证布局的 `TArray`、`TSet` 和 `TMap` 可按视图逐项读取，SDK 不会复制整个远程容器。
- `TSet` 使用 `RemoteSparseContainerView` 遍历已分配 slot。
- `TMap` 的 slot 返回 `RemoteMapEntryView`，再读取 key/value。
- 读取后端可按地址读取，也可在适配层批量取数；批量接口必须能报告每个请求的完整传输状态。

## 支持边界

有充分反射与布局依据时，SDK 支持读取：

- 布尔值、整数、浮点数、枚举、`FName`、`FString` 及 UTF-8/ANSI 字符串。
- 普通对象和类指针、serial 校验后的弱引用、软对象路径、接口及单播委托。
- 内嵌结构体、静态/动态数组，以及布局已验证的 set/map。

以下数据保持受限或未解析：

- `ObjectPtrProperty` 等编码对象句柄不会按普通指针解析。
- `FText` 仅返回已识别的外层数据指针和 flags，不解析文本历史或显示字符串。
- 惰性对象返回对象索引、serial、tag、remote id 和 GUID，但这些信息不代表对象仍存活。
- 多播委托、FieldPath、Optional、自定义属性或证据不足的容器返回受限 opaque 数据。
- 未验证平台元素布局的冻结 MemoryImage 容器不提供元素读取。

`Unsupported`、`InvalidHeader`、`InvalidReference`、`LimitExceeded` 和 `StaleObject` 都表示读取未成功。

## 根地址与生命周期

- 根地址位于模块映像时，`Binding.hpp` 保存 RVA，并在初始化时按模块基址重定位。
- 根地址位于模块映像外时，SDK 不保存采集时的绝对地址；消费者可在已从授权来源取得根地址后，通过 `RuntimeRoots` 显式提供。
- 若绑定需要尚未导出的自定义解码器，`Initialize` 返回 `Unsupported`，不会把编码值当作普通指针。
- 直接构造 `RemoteRuntime` 时，类型/枚举描述及其嵌套数组必须至少与 runtime 同寿命。手工构造描述时，只有确认父类信息完整才将 `superTypeResolved` 设为 `true`。`CreateRuntime` 使用生成 SDK 中的静态描述。
- RVA 只适用于生成该 SDK 的同一目标模块构建。模块名和根/名称校验不能证明二进制完全相同，应为目标版本选择对应产物。
- 读取不是原子快照；游戏对象和容器可能在读取期间变化。
- `RemoteRuntime` 不可复制或移动，也不保证并发访问。读取器上下文及对象、字段、容器视图只在创建它们的 runtime 和目标会话存活期间有效。进程身份、模块基址或地址空间变化后应重建 runtime；不要跨会话保存视图或目标地址。
