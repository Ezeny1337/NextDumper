#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace nextdumper::module
{
    // 仅访问普通 ELF 或 APK 中已校验的 STORED entry，不解压、不读取目标内存
    class ElfFile
    {
    public:
        ElfFile() = default;
        ~ElfFile();
        ElfFile(const ElfFile &) = delete;
        ElfFile &operator=(const ElfFile &) = delete;
        [[nodiscard]] bool Open(const std::string &path, uint64_t imageOffset,
                                uint64_t inode, const std::string &device);
        [[nodiscard]] bool Read(uint64_t offset, void *output, size_t size) const;
        template <typename T>
        [[nodiscard]] bool Read(uint64_t offset, T &value) const
        {
            return Read(offset, &value, sizeof(T));
        }
        [[nodiscard]] bool Contains(uint64_t offset, uint64_t size) const
        {
            return offset <= size_ && size <= size_ - offset;
        }
        [[nodiscard]] uint64_t Size() const { return size_; }
        [[nodiscard]] const std::string &EntryName() const { return entryName_; }

    private:
        [[nodiscard]] bool RawRead(uint64_t offset, void *output, size_t size) const;
        [[nodiscard]] bool LocateEntry(uint64_t dataOffset);
        int fd_ = -1;
        uint64_t fileSize_ = 0;
        uint64_t base_ = 0;
        uint64_t size_ = 0;
        std::string entryName_;
        mutable std::array<uint8_t, 64 * 1024> cache_{};
        mutable uint64_t cacheOffset_ = 0;
        mutable size_t cacheSize_ = 0;
    };
} // namespace nextdumper::module
