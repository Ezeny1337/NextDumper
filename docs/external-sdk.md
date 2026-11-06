# 外部内存 SDK

生成的 `sdk/SDK.hpp` 在布局声明之外提供只读外部访问器。它不链接进目标进程，也不调用 Unreal 函数。消费者提供精确的目标内存读取回调和目标模块基址；SDK 根据本次 dump 验证过的绑定、反射类型和字段描述完成对象查找与值读取。

生成头文件兼容 C++17，无需链接 NextDumper 运行库或增加第三方依赖。SDK 使用生成目标对应宽度的 `NextDumper::TargetAddress`，并在初始化时检查绑定宽度；地址不能转换或解引用为消费者进程中的本地指针。

## 接口

`sdk/SDK.hpp` 是聚合入口，包含以下运行时文件：

- `Remote.hpp` 是外部读取器的聚合头文件。
- `Remote/Memory.hpp` 定义读取回调和读取状态；`Remote/Metadata.hpp` 定义绑定与反射描述；`Remote/Views.hpp` 定义对象和值视图；`Remote/Runtime.hpp` 声明读取运行时。
- `Remote/detail/` 按核心、对象、名称、字段、标量、引用和容器职责保存运行时的 inline 实现。
- `Binding.hpp` 保存已验证的 UE 根地址 RVA、对象/名称容器布局和 UObject/FName 布局。
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

`FindFirstUClassObject("World")` 按名称查找第一个 `UClass` 元对象，包括反射出的蓝图生成类等 UClass 派生元类；该操作要求生成 SDK 包含 `Class /Script/CoreUObject.Class` 的类型描述。它查找类的反射对象，不查找该类的实例。

`FindFirstObjectOfType(classFullName)` 查找第一个类实例；`FindObjectsOfType(classFullName, maxResults, includeDerived)` 查找多个实例。类名使用 `TypeDescriptor::fullName` 格式，可先用 `FindType` 查看生成元数据中的完整类名；启用派生类匹配时，该基类必须有类型描述。匹配过程沿生成的父类描述检查，遇到缺失的父类描述会在结果状态中报告 `Incomplete`。`FindFirstObject` 适用于组合对象名、类名或完整名条件的通用查询。

两个 `FindFirst...` 接口都按对象数组顺序返回第一个匹配项，不保证名称唯一，也不代表当前活动的 World 或其他全局实例。短类名可能重复；需要消歧时，用完整对象名和通用 `FindFirstObject` 查询。

`FindType` 返回生成 SDK 中的类/结构描述，包含大小、父类完整名、父类类型描述是否已生成，以及该类型直接声明的字段；`FindField` 会继续沿已解析的父类查找字段。`FieldDescriptor` 提供字段偏移、元素大小、静态数组长度和 `ValueDescriptor`，后者包含属性种类、引用类型和容器元素类型。消费者可据此发现诸如 `Health` 的候选字段及其类型，不需要解析 `runtime.json` 或反射 JSON 才能取得结构信息。

要浏览某个类型直接声明的字段，可遍历描述数组；继承字段可由 `FindField` 查找，也可沿已解析的 `superFullName` 继续检查：

```cpp
const auto *playerStateType = runtime.FindType("Class /Script/Engine.PlayerState");
for (std::size_t index = 0; playerStateType && index < playerStateType->fieldCount; ++index)
{
    const auto &field = playerStateType->fields[index];
    // field.name, field.offset, field.elementSize, field.arrayDim, field.type
}
```

下面示例展示完整的通用调用链：通过反射描述检查 `Health` 字段及类型，再沿目标对象的字段和数组读取实例。示例中的类名、字段名和关系仅作说明，必须根据具体游戏产出的元数据确定实际路径。标量字段可直接读入 C++ 类型；对象、结构体、数组、静态数组、数组元素和 map 键/值也可用相应输出类型直接读取，避免手动检查 `RemoteValue` 的 variant。

```cpp
const auto worldResult = runtime.FindFirstObjectOfType("Class /Script/Engine.World");
const auto *playerStateType = runtime.FindType("Class /Script/Engine.PlayerState");
const auto *healthField = runtime.FindField(playerStateType, "Health");

if (worldResult.object && healthField && healthField->validBounds && healthField->type &&
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

SDK 提供结构描述和通用读取操作，不判断哪个对象是本地玩家，也不推断 `Health`、坐标或玩家列表的游戏语义。需要完整遍历时应检查查询状态；`LimitExceeded` 表示结果达到上限，`Incomplete` 表示部分对象或继承信息不可读。

对象、弱对象和接口字段读入 `RemoteObjectView` 时，会使用已验证的对象视图；空引用返回 `ReadStatus::Empty`，非空但无法解析/验证的引用返回 `InvalidReference`。需要保留弱对象索引和 serial，或普通对象指针的原始地址时，可分别读入 `WeakObjectReference` 或 `ObjectReference`。复杂字段也可继续通过 `ValueReadResult` 获取完整的 variant 和状态。

对已验证布局的 `TSet` 和 `TMap`，使用 `RemoteSparseContainerView` 遍历已分配 slot；map slot 返回 `RemoteMapEntryView`，其 key/value 可以直接按类型读入，也可使用 `ReadMapKey` 和 `ReadMapValue` 获取 `ValueReadResult`。SDK 不会一次性复制整个远程容器。

读取后端可以提供单地址读取，也可以在自己的适配层聚合读取请求。只有能为每个请求准确报告完整传输状态的后端，才适合作为精确读取实现；仅有整个批次成功标记的批量接口不能证明其中每个字段都完整。

## 支持边界

有充分反射与布局依据时，SDK 可读取布尔值、整数、浮点数、枚举、`FName`、`FString`/UTF-8/ANSI 字符串、普通对象和类指针、serial 校验后的弱引用、软对象路径、接口、单播委托、内嵌结构体、静态数组、动态数组以及布局已验证的 set/map。`ObjectPtrProperty` 等编码对象句柄不会当作普通指针解析。

对 `FText`，SDK 返回已识别的外层数据指针和 flags；文本历史和显示字符串仍保持未解析。惰性对象会返回对象索引、serial、tag、remote id 和 GUID，不会据此断言对象仍存活。多播委托、FieldPath、Optional、厂商自定义属性或布局证据不足的容器以受限 opaque 字节及状态返回。尚未验证平台元素布局的冻结 MemoryImage 容器不提供元素读取。`ReadStatus::Unsupported`、`InvalidHeader`、`InvalidReference`、`LimitExceeded` 和 `StaleObject` 不应被当作成功读取。

如果根对象位于模块映像中，`Binding.hpp` 保存其 RVA，并在初始化时根据模块基址重定位。根地址不在模块映像内时，SDK 不会保存本次进程的绝对地址；只有在消费者已从授权来源获得根地址时，才可通过 `RuntimeRoots` 显式提供。若生成绑定包含尚未导出的自定义解码器，`Initialize` 返回 `Unsupported`，避免把编码值误读为普通指针。若直接使用 `RemoteRuntime` 构造函数，类型/枚举描述及其嵌套数组必须至少与 runtime 同寿命；手工构造类型描述时，只有确认父类类型信息完整才将 `superTypeResolved` 设为 `true`。`CreateRuntime` 使用生成 SDK 中的静态描述。

RVA 适用于生成该 SDK 的同一目标模块构建。模块名检查和运行时根/名称校验不能证明二进制完全相同；消费者应为目标版本选择对应产物。读取过程不是原子快照，游戏对象和容器可能在读取期间变化。

`RemoteRuntime` 不可复制或移动，且不提供并发访问保证。读取器上下文及其返回的对象、字段和容器视图只在创建它们的 runtime 与目标会话存活期间有效。消费者检测到进程身份、模块基址或目标地址空间发生变化时，应重建 runtime；不要跨会话保存视图或目标地址。
