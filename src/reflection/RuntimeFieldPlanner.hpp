#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "nextdumper/ir/ReflectionIR.hpp"

namespace nextdumper::reflection::detail
{
    [[nodiscard]] const char *RuntimeValueKind(ir::PropertyKind kind);
    [[nodiscard]] std::string RuntimeSampleCategory(const ir::TypeReferenceIR &reference);

    struct RuntimeField
    {
        const ir::PropertyIR *property = nullptr;
        uintptr_t owner = 0;
        uint64_t offset = 0;
        std::string path;
    };

    // 只消费 const IR，不读取进程，继承和嵌套结构共用元数据节点预算
    // 缓存中的 PropertyIR 指针由本次检查的 ReflectionIR 保持存活
    class RuntimeFieldPlanner
    {
    public:
        explicit RuntimeFieldPlanner(const ir::ReflectionIR &reflection, bool serialReferencesOnly = false);
        [[nodiscard]] const ir::TypeIR *Type(uintptr_t address) const;
        [[nodiscard]] const std::vector<RuntimeField> &Fields(uintptr_t classAddress);
        [[nodiscard]] const std::map<std::string, size_t> &Skipped() const { return skipped_; }

    private:
        void Collect(const ir::TypeIR &type, uint64_t base, const std::string &prefix, size_t depth,
                     size_t &remaining, std::set<uintptr_t> &path, std::vector<RuntimeField> &out);

        std::unordered_map<uintptr_t, const ir::TypeIR *> types_;
        std::unordered_map<uintptr_t, std::vector<RuntimeField>> fields_;
        std::unordered_set<uintptr_t> visitedProperties_;
        std::map<std::string, size_t> skipped_;
        size_t cachedFields_ = 0;
        bool serialReferencesOnly_ = false;
    };
} // namespace nextdumper::reflection::detail
