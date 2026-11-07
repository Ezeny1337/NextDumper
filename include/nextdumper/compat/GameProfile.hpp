#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "nextdumper/binding/BindingBuilder.hpp"
#include "nextdumper/module/ModuleImage.hpp"

namespace nextdumper::memory
{
    class IMemorySource;
}

namespace nextdumper::compat
{
    using ::nextdumper::binding::BindingCandidates;
    using ::nextdumper::binding::BindingLayoutHints;
    using ::nextdumper::binding::DecodePlan;
    using ::nextdumper::memory::IMemorySource;
    using ::nextdumper::module::ModuleImage;

    using ProfileDiagnostic = std::function<void(const std::string &)>;

    class IGameProfile
    {
    public:
        virtual ~IGameProfile() = default;

        // Id 必须返回稳定的非空字符串
        [[nodiscard]] virtual std::string_view Id() const = 0;
        [[nodiscard]] virtual bool Matches(std::string_view packageName,
                                           const ModuleImage &module) const = 0;

        // 仅通过只读内存接口和模块映像生成目标专用根候选
        [[nodiscard]] virtual BindingCandidates LocateRoots(
            const IMemorySource &memory,
            const ModuleImage &module,
            const ProfileDiagnostic &diagnostic) const
        {
            (void)memory;
            (void)module;
            (void)diagnostic;
            return {};
        }

        // 解码规则和自定义回调会随 RuntimeBinding 存活到本次 RuntimeSession 结束
        [[nodiscard]] virtual DecodePlan MakeDecodePlan(
            const IMemorySource &memory,
            const ModuleImage &module) const
        {
            (void)memory;
            (void)module;
            return DecodePlan::Identity();
        }

        // 提示会替代对应容器的自动布局发现，但仍必须通过相同的运行时探针
        [[nodiscard]] virtual BindingLayoutHints LayoutHints() const { return {}; }
    };

    // 新增编译期 profile 时，在 src/compat/GameProfiles.cpp 中注册其工厂实例
    [[nodiscard]] std::vector<std::unique_ptr<IGameProfile>> CreateGameProfiles();
} // namespace nextdumper::compat
