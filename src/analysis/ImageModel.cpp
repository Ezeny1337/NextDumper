#include "nextdumper/analysis/ImageModel.hpp"

namespace nextdumper::analysis
{
    ImageModel::ImageModel(const MemoryView &memory, const module::ModuleImage &module) noexcept
        : memory_(memory), module_(module)
    {
    }

    bool ImageModel::IsValid() const
    {
        return memory_.IsInitialized() && module_.IsValid();
    }

    size_t ImageModel::ExecutableSegmentCount() const
    {
        size_t count = 0;
        for (const auto &segment : module_.segments)
        {
            if (segment.executable && segment.end > segment.start)
                ++count;
        }
        return count;
    }

    uint64_t ImageModel::ExecutableBytes() const
    {
        uint64_t total = 0;
        for (const auto &segment : module_.segments)
        {
            if (segment.executable && segment.end > segment.start)
                total += static_cast<uint64_t>(segment.end - segment.start);
        }
        return total;
    }
} // namespace nextdumper::analysis
