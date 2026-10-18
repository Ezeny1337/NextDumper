#pragma once

#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>

#include "nextdumper/generation/ArtifactWriter.hpp"

namespace nextdumper::memory
{
    class RemoteMemorySource;
}

namespace nextdumper::app
{
    // 由会话线程独占，FILE 的所有权在 Close 或析构时释放
    class MemoryPerformanceLog
    {
    public:
        MemoryPerformanceLog() = default;
        ~MemoryPerformanceLog();
        MemoryPerformanceLog(const MemoryPerformanceLog &) = delete;
        MemoryPerformanceLog &operator=(const MemoryPerformanceLog &) = delete;

        [[nodiscard]] bool Open(const std::string &path, const generation::ArtifactProvenance &provenance,
                                std::chrono::steady_clock::time_point started) noexcept;
        void Write(std::string_view event, std::string_view stage, const memory::RemoteMemorySource &memory,
                   std::string_view architecture, std::string_view status = "running") noexcept;
        [[nodiscard]] bool Close() noexcept;
        [[nodiscard]] bool Failed() const { return failed_; }
        [[nodiscard]] int LastError() const { return error_; }

    private:
        std::FILE *file_ = nullptr;
        generation::ArtifactProvenance provenance_;
        std::chrono::steady_clock::time_point started_{};
        std::chrono::steady_clock::time_point lastSnapshot_{};
        bool failed_ = false;
        int error_ = 0;
    };
}
