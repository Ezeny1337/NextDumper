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

`RemoteRuntime::FindFirstObject` 可按完整对象名、类完整名、类名或对象名查找对象。标量字段可以直接读入目标 C++ 类型；复杂字段通过 `ValueReadResult` 返回对应的远程视图。

```cpp
NextDumper::ObjectQuery query;
query.className = "World";
const auto world = runtime.FindFirstObject(query);
if (world.status == NextDumper::ReadStatus::Ok && world.object)
{
    float timeSeconds = 0.0f;
    const auto status = runtime.ReadField(*world.object, "TimeSeconds", timeSeconds);
}
```

对 `TArray`，读取字段后检查 `RemoteArrayView`，再通过 `ReadElement` 按索引读取。对已验证布局的 `TSet` 和 `TMap`，使用 `RemoteSparseContainerView` 遍历已分配 slot；map slot 返回 `RemoteMapEntryView`，其 key/value 分别由 `ReadMapKey` 和 `ReadMapValue` 读取。SDK 不会一次性复制整个远程容器。

读取后端可以提供单地址读取，也可以在自己的适配层聚合读取请求。只有能为每个请求准确报告完整传输状态的后端，才适合作为精确读取实现；仅有整个批次成功标记的批量接口不能证明其中每个字段都完整。

## 支持边界

有充分反射与布局依据时，SDK 可读取布尔值、整数、浮点数、枚举、`FName`、`FString`/UTF-8/ANSI 字符串、普通对象和类指针、serial 校验后的弱引用、软对象路径、接口、单播委托、内嵌结构体、静态数组、动态数组以及布局已验证的 set/map。`ObjectPtrProperty` 等编码对象句柄不会当作普通指针解析。

对 `FText`，SDK 返回已识别的外层数据指针和 flags；文本历史和显示字符串仍保持未解析。惰性对象会返回对象索引、serial、tag、remote id 和 GUID，不会据此断言对象仍存活。多播委托、FieldPath、Optional、厂商自定义属性或布局证据不足的容器以受限 opaque 字节及状态返回。尚未验证平台元素布局的冻结 MemoryImage 容器不提供元素读取。`ReadStatus::Unsupported`、`InvalidHeader`、`InvalidReference`、`LimitExceeded` 和 `StaleObject` 不应被当作成功读取。

如果根对象位于模块映像中，`Binding.hpp` 保存其 RVA，并在初始化时根据模块基址重定位。根地址不在模块映像内时，SDK 不会保存本次进程的绝对地址；只有在消费者已从授权来源获得根地址时，才可通过 `RuntimeRoots` 显式提供。若生成绑定包含尚未导出的自定义解码器，`Initialize` 返回 `Unsupported`，避免把编码值误读为普通指针。若直接使用 `RemoteRuntime` 构造函数，类型/枚举描述及其嵌套数组必须至少与 runtime 同寿命；`CreateRuntime` 使用生成 SDK 中的静态描述。

RVA 适用于生成该 SDK 的同一目标模块构建。模块名检查和运行时根/名称校验不能证明二进制完全相同；消费者应为目标版本选择对应产物。读取过程不是原子快照，游戏对象和容器可能在读取期间变化。

`RemoteRuntime` 不可复制或移动，且不提供并发访问保证。读取器上下文及其返回的对象、字段和容器视图只在创建它们的 runtime 与目标会话存活期间有效。消费者检测到进程身份、模块基址或目标地址空间发生变化时，应重建 runtime；不要跨会话保存视图或目标地址。
