#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <sys/types.h>

namespace nextdumper::memory
{
    struct ReadPerformance;
    struct MemoryRegion
    {
        uintptr_t start = 0;
        uintptr_t end = 0;
        uint64_t fileOffset = 0;
        uint64_t inode = 0;
        std::string device;
        std::string path;
        bool readable = false;
        bool writable = false;
        bool executable = false;
        bool privateMapping = false;
    };

    struct ProcessIdentity
    {
        pid_t pid = 0;
        uint64_t startTime = 0;
        std::string name;
    };

    // 持有 proc 目录，避免后续元数据查询指向复用同一 PID 的进程
    class ProcessInfo
    {
    public:
        ProcessInfo() = default;
        ~ProcessInfo();
        ProcessInfo(const ProcessInfo &) = delete;
        ProcessInfo &operator=(const ProcessInfo &) = delete;

        [[nodiscard]] bool Open(pid_t pid);
        void Close();
        [[nodiscard]] bool Alive() const;
        [[nodiscard]] bool ReadRegions(std::vector<MemoryRegion> &regions) const;
        [[nodiscard]] const ProcessIdentity &Identity() const { return identity_; }
        [[nodiscard]] int LastError() const { return error_; }
        void SetPerformance(ReadPerformance *performance);
        [[nodiscard]] bool HasPidfd() const { return lifetime_ >= 0; }
        [[nodiscard]] static pid_t Find(const std::string &name);

    private:
        [[nodiscard]] bool ReadStartTime(uint64_t &value) const;
        [[nodiscard]] bool ReadFile(const char *name, size_t limit, std::string &text) const;
        int directory_ = -1;
        int lifetime_ = -1;
        ProcessIdentity identity_;
        mutable int error_ = 0;
        // 非拥有指针，读取会话负责生命周期，且只在所属线程访问
        ReadPerformance *performance_ = nullptr;
    };

    [[nodiscard]] bool ContainsRange(std::span<const MemoryRegion> regions, uintptr_t address, size_t size,
                                     bool executable = false);
} // namespace nextdumper::memory
