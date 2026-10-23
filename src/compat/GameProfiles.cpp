#include "nextdumper/compat/GameProfile.hpp"

namespace nextdumper::compat
{
    namespace
    {
        // 示例 profile：展示如何声明只读段的单字节 XOR 键
        // Matches 恒为 false，绝不参与实际选择，替换为稳定的包名/模块识别规则后才会生效
        class TencentAceProfile final : public IGameProfile
        {
        public:
            [[nodiscard]] std::string_view Id() const override { return "tencent-ace-example"; }

            [[nodiscard]] bool Matches(std::string_view, const ModuleImage &) const override
            {
                return false;
            }

            // ACE/TP 样本的 .rodata 与 .text 在离线文件层面使用 XOR-0xE2
            // 运行时内存已由游戏自身解密，这里只作为离线分析工具的键
            [[nodiscard]] std::optional<uint8_t> RodataXorKey() const override
            {
                return 0xE2;
            }
        };
    } // namespace

    std::vector<std::unique_ptr<IGameProfile>> CreateGameProfiles()
    {
        std::vector<std::unique_ptr<IGameProfile>> profiles;
        profiles.push_back(std::make_unique<TencentAceProfile>());
        return profiles;
    }
} // namespace nextdumper::compat
