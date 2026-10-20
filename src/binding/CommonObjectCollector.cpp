#include "nextdumper/binding/CommonObjectCollector.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <unordered_map>

namespace nextdumper::binding
{
    CommonObjectCollector::CommonObjectCollector(const IMemorySource &memory,
                                                 const RuntimeBinding &binding,
                                                 const EngineSchema &schema)
        : objects_(memory, binding, schema)
    {
    }

    std::vector<CommonObjectInfo> CommonObjectCollector::Collect()
    {
        std::vector<CommonObjectInfo> result;

        if (!objects_.Initialize())
            return result;

        const std::vector<std::string> commonClasses = {
            "Engine",
            "World",
            "GameInstance",
            "LocalPlayer",
            "PlayerController",
            "GameViewportClient",
            "Console",
            "CheatManager"};

        const int32_t count = objects_.Count();
        std::array<ue::ObjectReadResult, ue::ObjectStoreReader::kReadWindowSize> window{};
        size_t windowCount = 0;
        int32_t windowFirst = 0;
        std::unordered_map<uintptr_t, std::optional<std::string>> classes;
        for (int32_t index = 0; index < count; ++index)
        {
            if (static_cast<size_t>(index - windowFirst) >= windowCount)
            {
                windowFirst = index;
                windowCount = std::min(window.size(), static_cast<size_t>(count - index));
                if (!objects_.Objects().ReadObjects(index, {window.data(), windowCount}))
                    throw std::runtime_error("Common object window contract failed");
            }
            const auto &object = window[static_cast<size_t>(index - windowFirst)];
            if (!object.IsValid())
                continue;

            const auto cls = objects_.Class(object.address);
            if (!cls)
                continue;
            auto className = classes.find(*cls);
            if (className == classes.end())
                className = classes.emplace(*cls, objects_.Name(*cls)).first;
            if (!className->second || *className->second != "Class")
                continue;
            const auto name = objects_.Name(object.address);
            if (name && std::find(commonClasses.begin(), commonClasses.end(), *name) != commonClasses.end())
                result.push_back({*name, object.address, index});
        }

        return result;
    }
} // namespace nextdumper::binding
