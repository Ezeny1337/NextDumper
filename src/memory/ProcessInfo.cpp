#include "nextdumper/memory/ProcessInfo.hpp"
#include "nextdumper/memory/ReadPerformance.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sstream>
#include <string_view>
#include <sys/syscall.h>
#include <unistd.h>

namespace nextdumper::memory
{
    namespace
    {
        template <typename T>
        bool Number(std::string_view text, T &value, int base = 10)
        {
            const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
            return !text.empty() && result.ec == std::errc{} && result.ptr == text.data() + text.size();
        }

        void CloseDescriptor(int &fd)
        {
            if (fd >= 0 && close(fd) != 0)
                std::fprintf(stderr, "Process descriptor close failed: errno=%d\n", errno);
            // Linux 的 close 即使返回 EINTR 也不能重试，以免关闭已复用的描述符
            fd = -1;
        }
    }

    ProcessInfo::~ProcessInfo() { Close(); }

    void ProcessInfo::SetPerformance(ReadPerformance *performance)
    {
        performance_ = performance;
#if defined(SYS_pidfd_open)
        if (performance_)
            performance_->pidfdCompiled = true;
#endif
    }

    void ProcessInfo::Close()
    {
        CloseDescriptor(lifetime_);
        CloseDescriptor(directory_);
        identity_ = {};
    }

    bool ProcessInfo::ReadFile(const char *name, size_t limit, std::string &text) const
    {
        text.clear();
        if (performance_)
            ++performance_->procOpenCalls;
        const int fd = openat(directory_, name, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
        {
            error_ = errno;
            return false;
        }
        std::array<char, 8192> buffer{};
        bool ok = true;
        unsigned interruptions = 0;
        for (;;)
        {
            if (performance_)
                ++performance_->procReadCalls;
            const ssize_t count = read(fd, buffer.data(), buffer.size());
            if (count < 0 && errno == EINTR && interruptions++ < 3)
                continue;
            if (count < 0)
            {
                error_ = errno;
                ok = false;
                break;
            }
            if (count == 0)
                break;
            if (static_cast<size_t>(count) > limit - text.size())
            {
                error_ = EOVERFLOW;
                ok = false;
                break;
            }
            try
            {
                text.append(buffer.data(), static_cast<size_t>(count));
            }
            catch (...)
            {
                int owned = fd;
                if (performance_)
                    ++performance_->procCloseCalls;
                CloseDescriptor(owned);
                throw;
            }
        }
        if (performance_)
            ++performance_->procCloseCalls;
        if (close(fd) != 0)
        {
            error_ = errno;
            ok = false;
        }
        return ok;
    }

    bool ProcessInfo::ReadStartTime(uint64_t &value) const
    {
        std::string text;
        if (!ReadFile("stat", 64 * 1024, text))
            return false;
        const size_t end = text.rfind(')');
        if (end == std::string::npos || end + 2 >= text.size())
        {
            error_ = EINVAL;
            return false;
        }
        std::istringstream input(text.substr(end + 2));
        std::string field;
        for (unsigned index = 3; index <= 22; ++index)
        {
            if (!(input >> field))
            {
                error_ = EINVAL;
                return false;
            }
            if (index == 3 && (field == "Z" || field == "X"))
            {
                error_ = ESRCH;
                return false;
            }
        }
        if (!Number(field, value))
        {
            error_ = EINVAL;
            return false;
        }
        return true;
    }

    bool ProcessInfo::Open(pid_t pid)
    {
        Close();
        error_ = 0;
        if (pid <= 0)
        {
            error_ = EINVAL;
            return false;
        }
        const std::string path = "/proc/" + std::to_string(pid);
        directory_ = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory_ < 0)
        {
            error_ = errno;
            return false;
        }
        identity_.pid = pid;
        if (!ReadStartTime(identity_.startTime))
        {
            Close();
            return false;
        }
#if defined(SYS_pidfd_open)
        // pidfd 仅用于生命周期观察，不改变 process_vm_readv 的 PID 契约
        if (performance_)
            ++performance_->pidfdOpenCalls;
        lifetime_ = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
        if (performance_)
            performance_->pidfdOpenError = lifetime_ < 0 ? errno : 0;
#endif
        std::string name;
        if (!ReadFile("cmdline", 64 * 1024, name))
        {
            Close();
            return false;
        }
        identity_.name = name.substr(0, name.find('\0'));
        uint64_t confirmed = 0;
        if (!ReadStartTime(confirmed) || confirmed != identity_.startTime || !Alive())
        {
            if (confirmed != identity_.startTime)
                error_ = ESRCH;
            Close();
            return false;
        }
        return true;
    }

    bool ProcessInfo::Alive() const
    {
        if (performance_)
            ++performance_->lifecycleCalls;
        if (directory_ < 0)
        {
            if (performance_)
                ++performance_->lifecycleInvalidDescriptor;
            error_ = ESRCH;
            return false;
        }
        if (lifetime_ >= 0)
        {
            ScopedReadTiming timing(performance_ ? &performance_->lifecyclePoll : nullptr);
            pollfd descriptor{lifetime_, POLLIN, 0};
            int result;
            unsigned interruptions = 0;
            do
            {
                if (performance_)
                    ++performance_->lifecyclePollSyscalls;
                result = poll(&descriptor, 1, 0);
            } while (result < 0 && errno == EINTR && interruptions++ < 3);
            if (result == 0)
                return true;
            error_ = result < 0 ? errno : ESRCH;
            return false;
        }
        ScopedReadTiming timing(performance_ ? &performance_->lifecycleStat : nullptr);
        uint64_t startTime = 0;
        if (!ReadStartTime(startTime) || startTime != identity_.startTime)
        {
            if (error_ == 0 || startTime != identity_.startTime)
                error_ = ESRCH;
            return false;
        }
        return true;
    }

    bool ProcessInfo::ReadRegions(std::vector<MemoryRegion> &regions) const
    {
        std::string text;
        if (!Alive() || !ReadFile("maps", 32 * 1024 * 1024, text))
            return false;
        std::vector<MemoryRegion> parsed;
        std::istringstream input(text);
        std::string line;
        while (std::getline(input, line))
        {
            if (parsed.size() >= 262144 || line.size() > 64 * 1024)
            {
                error_ = EOVERFLOW;
                return false;
            }
            std::istringstream fields(line);
            std::string range, permissions, offset, inode;
            MemoryRegion region;
            if (!(fields >> range >> permissions >> offset >> region.device >> inode))
            {
                error_ = EINVAL;
                return false;
            }
            const auto dash = range.find('-');
            if (dash == std::string::npos || permissions.size() != 4 ||
                !Number(std::string_view(range).substr(0, dash), region.start, 16) ||
                !Number(std::string_view(range).substr(dash + 1), region.end, 16) ||
                !Number(offset, region.fileOffset, 16) || !Number(inode, region.inode) ||
                region.start >= region.end || (!parsed.empty() && region.start < parsed.back().end) ||
                (permissions[0] != 'r' && permissions[0] != '-') ||
                (permissions[1] != 'w' && permissions[1] != '-') ||
                (permissions[2] != 'x' && permissions[2] != '-') ||
                (permissions[3] != 'p' && permissions[3] != 's'))
            {
                error_ = EINVAL;
                return false;
            }
            std::getline(fields, region.path);
            const size_t first = region.path.find_first_not_of(' ');
            region.path = first == std::string::npos ? std::string{} : region.path.substr(first);
            region.readable = permissions[0] == 'r';
            region.writable = permissions[1] == 'w';
            region.executable = permissions[2] == 'x';
            region.privateMapping = permissions[3] == 'p';
            parsed.push_back(std::move(region));
        }
        if (parsed.empty() || !Alive())
        {
            if (parsed.empty())
                error_ = EINVAL;
            return false;
        }
        regions = std::move(parsed);
        return true;
    }

    pid_t ProcessInfo::Find(const std::string &name)
    {
        if (name.empty() || name.size() > 4096 || name.find('\0') != std::string::npos)
            return 0;
        DIR *directory = opendir("/proc");
        if (!directory)
            return 0;
        pid_t found = 0;
        try
        {
            size_t visited = 0;
            for (;;)
            {
                errno = 0;
                const dirent *entry = readdir(directory);
                if (!entry || ++visited > 1024 * 1024)
                {
                    if (errno != 0 || visited > 1024 * 1024)
                        found = 0;
                    break;
                }
                pid_t pid = 0;
                if (!Number(std::string_view(entry->d_name), pid) || pid <= 0)
                    continue;
                ProcessInfo process;
                if (process.Open(pid) && process.Identity().name == name)
                {
                    // 多个精确匹配目标不应由目录枚举顺序决定
                    if (found != 0)
                    {
                        found = 0;
                        break;
                    }
                    found = pid;
                }
            }
        }
        catch (...)
        {
            if (closedir(directory) != 0)
                std::fprintf(stderr, "Process directory close failed: errno=%d\n", errno);
            throw;
        }
        if (closedir(directory) != 0)
        {
            std::fprintf(stderr, "Process directory close failed: errno=%d\n", errno);
            return 0;
        }
        return found;
    }

    bool ContainsRange(std::span<const MemoryRegion> regions, uintptr_t address, size_t size, bool executable)
    {
        if (!address || !size || address > UINTPTR_MAX - (size - 1))
            return false;
        const uintptr_t last = address + size - 1;
        auto at = std::upper_bound(regions.begin(), regions.end(), address,
                                   [](uintptr_t value, const MemoryRegion &region)
                                   { return value < region.start; });
        if (at == regions.begin())
            return false;
        --at;
        for (;;)
        {
            if (at == regions.end() || address < at->start || address >= at->end ||
                !at->readable || (executable && !at->executable))
                return false;
            if (last < at->end)
                return true;
            address = at->end;
            ++at;
        }
    }
} // namespace nextdumper::memory
