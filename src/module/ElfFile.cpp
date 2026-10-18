#include "ElfFile.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <string_view>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <vector>

namespace nextdumper::module
{
    namespace
    {
        uint16_t U16(const uint8_t *bytes) { return uint16_t(bytes[0]) | (uint16_t(bytes[1]) << 8); }
        uint32_t U32(const uint8_t *bytes) { return uint32_t(U16(bytes)) | (uint32_t(U16(bytes + 2)) << 16); }
        uint64_t U64(const uint8_t *bytes) { return uint64_t(U32(bytes)) | (uint64_t(U32(bytes + 4)) << 32); }
        bool Device(const std::string &text, unsigned &majorNumber, unsigned &minorNumber)
        {
            const auto colon = text.find(':');
            if (colon == std::string::npos)
                return false;
            const auto parse = [](std::string_view part, unsigned &value)
            {
                const auto result = std::from_chars(part.data(), part.data() + part.size(), value, 16);
                return !part.empty() && result.ec == std::errc{} && result.ptr == part.data() + part.size();
            };
            return parse(std::string_view(text).substr(0, colon), majorNumber) &&
                   parse(std::string_view(text).substr(colon + 1), minorNumber);
        }
    }

    ElfFile::~ElfFile()
    {
        if (fd_ >= 0 && close(fd_) != 0)
            std::fprintf(stderr, "ELF file close failed: errno=%d\n", errno);
    }

    bool ElfFile::RawRead(uint64_t offset, void *output, size_t size) const
    {
        static_assert(sizeof(off_t) >= 8);
        if (fd_ < 0 || !output || offset > fileSize_ || size > fileSize_ - offset ||
            offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max()))
            return false;
        auto *bytes = static_cast<uint8_t *>(output);
        unsigned interruptions = 0;
        while (size)
        {
            const size_t wanted = std::min<size_t>(size, 1024 * 1024);
            const ssize_t count = pread(fd_, bytes, wanted, static_cast<off_t>(offset));
            if (count < 0 && errno == EINTR && interruptions++ < 3)
                continue;
            if (count <= 0)
                return false;
            bytes += count;
            offset += static_cast<size_t>(count);
            size -= static_cast<size_t>(count);
        }
        return true;
    }

    bool ElfFile::LocateEntry(uint64_t dataOffset)
    {
        const size_t tailSize = static_cast<size_t>(std::min<uint64_t>(fileSize_, 65535 + 22));
        if (tailSize < 22)
            return false;
        std::vector<uint8_t> tail(tailSize);
        if (!Read(fileSize_ - tailSize, tail.data(), tail.size()))
            return false;
        for (size_t index = tail.size() - 22;; --index)
        {
            const uint8_t *end = tail.data() + index;
            if (U32(end) == 0x06054b50 && U16(end + 20) == tail.size() - index - 22)
            {
                if (U16(end + 4) || U16(end + 6) || U16(end + 8) != U16(end + 10))
                    return false;
                uint64_t entries = U16(end + 10), length = U32(end + 12), start = U32(end + 16);
                const uint64_t eocd = fileSize_ - tailSize + index;
                uint64_t directoryEnd = eocd;
                if (entries == 0xffff || length == 0xffffffff || start == 0xffffffff)
                {
                    std::array<uint8_t, 20> locator{};
                    std::array<uint8_t, 56> record{};
                    if (eocd < locator.size() || !Read(eocd - locator.size(), locator.data(), locator.size()) ||
                        U32(locator.data()) != 0x07064b50 || U32(locator.data() + 4) || U32(locator.data() + 16) != 1)
                        return false;
                    const uint64_t offset = U64(locator.data() + 8);
                    if (offset > eocd - locator.size() || record.size() > eocd - locator.size() - offset ||
                        !Read(offset, record.data(), record.size()) || U32(record.data()) != 0x06064b50 ||
                        U64(record.data() + 4) < 44 || U64(record.data() + 4) > eocd - locator.size() - offset - 12 ||
                        U32(record.data() + 16) || U32(record.data() + 20) ||
                        U64(record.data() + 24) != U64(record.data() + 32))
                        return false;
                    entries = U64(record.data() + 32);
                    length = U64(record.data() + 40);
                    start = U64(record.data() + 48);
                    directoryEnd = offset;
                }
                if (entries > 1024 * 1024 || start > directoryEnd || length > directoryEnd - start ||
                    length > 64 * 1024 * 1024)
                    return false;
                uint64_t cursor = start;
                for (uint64_t entry = 0; entry < entries; ++entry)
                {
                    std::array<uint8_t, 46> header{};
                    if (cursor > start + length || header.size() > start + length - cursor ||
                        !Read(cursor, header.data(), header.size()) || U32(header.data()) != 0x02014b50)
                        return false;
                    const uint16_t nameSize = U16(header.data() + 28), extraSize = U16(header.data() + 30), comment = U16(header.data() + 32);
                    const uint64_t suffix = uint64_t{nameSize} + extraSize + comment;
                    if (suffix > start + length - cursor - header.size())
                        return false;
                    const uint64_t next = cursor + header.size() + suffix;
                    uint64_t localOffset = U32(header.data() + 42), compressed = U32(header.data() + 20);
                    uint64_t unpacked = U32(header.data() + 24), disk = U16(header.data() + 34);
                    if (localOffset == 0xffffffff || compressed == 0xffffffff || unpacked == 0xffffffff || disk == 0xffff)
                    {
                        std::vector<uint8_t> extra(extraSize);
                        if (!Read(cursor + header.size() + nameSize, extra.data(), extra.size()))
                            return false;
                        bool found = false;
                        for (size_t position = 0; position < extra.size();)
                        {
                            if (extra.size() - position < 4)
                                return false;
                            const uint16_t id = U16(extra.data() + position), bytes = U16(extra.data() + position + 2);
                            position += 4;
                            if (bytes > extra.size() - position)
                                return false;
                            if (id == 1)
                            {
                                size_t used = 0;
                                const auto wide = [&](uint64_t &value)
                                {
                                    if (value != 0xffffffff)
                                        return true;
                                    if (bytes - used < 8)
                                        return false;
                                    value = U64(extra.data() + position + used);
                                    used += 8;
                                    return true;
                                };
                                if (!wide(unpacked) || !wide(compressed) || !wide(localOffset))
                                    return false;
                                if (disk == 0xffff)
                                {
                                    if (bytes - used < 4)
                                        return false;
                                    disk = U32(extra.data() + position + used);
                                }
                                found = true;
                                break;
                            }
                            position += bytes;
                        }
                        if (!found)
                            return false;
                    }
                    if (disk)
                        return false;
                    if (U16(header.data() + 10) == 0 && !(U16(header.data() + 8) & 0x2041) && compressed == unpacked &&
                        localOffset < start)
                    {
                        std::array<uint8_t, 30> local{};
                        if (!Read(localOffset, local.data(), local.size()) || U32(local.data()) != 0x04034b50)
                            return false;
                        const uint64_t prefix = local.size() + U16(local.data() + 26) + U16(local.data() + 28);
                        if (prefix > start - localOffset)
                            return false;
                        const uint64_t data = localOffset + prefix;
                        if (data == dataOffset)
                        {
                            if (U16(local.data() + 8) != 0 || U16(local.data() + 6) != U16(header.data() + 8) ||
                                U16(local.data() + 26) != nameSize || !nameSize || nameSize > 4096 || unpacked > start - data)
                                return false;
                            if (!(U16(local.data() + 6) & 8))
                            {
                                if (U32(local.data() + 14) != U32(header.data() + 16))
                                    return false;
                                uint64_t localCompressed = U32(local.data() + 18), localUnpacked = U32(local.data() + 22);
                                if (localCompressed == 0xffffffff || localUnpacked == 0xffffffff)
                                {
                                    std::vector<uint8_t> extra(U16(local.data() + 28));
                                    if (extra.empty() || !Read(localOffset + local.size() + nameSize, extra.data(), extra.size()))
                                        return false;
                                    bool found = false;
                                    for (size_t position = 0; position < extra.size();)
                                    {
                                        if (extra.size() - position < 4)
                                            return false;
                                        const uint16_t id = U16(extra.data() + position), bytes = U16(extra.data() + position + 2);
                                        position += 4;
                                        if (bytes > extra.size() - position)
                                            return false;
                                        if (id == 1)
                                        {
                                            size_t used = 0;
                                            if (localUnpacked == 0xffffffff)
                                            {
                                                if (bytes < 8)
                                                    return false;
                                                localUnpacked = U64(extra.data() + position);
                                                used = 8;
                                            }
                                            if (localCompressed == 0xffffffff)
                                            {
                                                if (bytes - used < 8)
                                                    return false;
                                                localCompressed = U64(extra.data() + position + used);
                                            }
                                            found = true;
                                            break;
                                        }
                                        position += bytes;
                                    }
                                    if (!found)
                                        return false;
                                }
                                if (localCompressed != compressed || localUnpacked != unpacked)
                                    return false;
                            }
                            std::string name(nameSize, '\0'), localName(nameSize, '\0');
                            if (!Read(cursor + header.size(), name.data(), name.size()) ||
                                !Read(localOffset + local.size(), localName.data(), localName.size()) ||
                                name != localName || name.find('\0') != std::string::npos)
                                return false;
                            entryName_ = std::move(name);
                            base_ = data;
                            size_ = unpacked;
                            cacheSize_ = 0;
                            return true;
                        }
                    }
                    cursor = next;
                }
                return false;
            }
            if (index == 0)
                break;
        }
        return false;
    }

    bool ElfFile::Open(const std::string &path, uint64_t imageOffset, uint64_t inode, const std::string &device)
    {
        if (fd_ >= 0 || path.empty() || path.find('\0') != std::string::npos)
            return false;
        fd_ = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        struct stat info{};
        unsigned majorNumber = 0, minorNumber = 0;
        if (fd_ < 0 || fstat(fd_, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 ||
            (inode && static_cast<uint64_t>(info.st_ino) != inode) ||
            (!device.empty() && (!Device(device, majorNumber, minorNumber) ||
                                 major(info.st_dev) != majorNumber || minor(info.st_dev) != minorNumber)))
            return false;
        fileSize_ = static_cast<uint64_t>(info.st_size);
        size_ = fileSize_;
        if (imageOffset && !LocateEntry(imageOffset))
            return false;
        std::array<uint8_t, 4> magic{};
        return size_ <= 1024ULL * 1024 * 1024 && Read(0, magic) && std::memcmp(magic.data(), "\177ELF", 4) == 0;
    }

    bool ElfFile::Read(uint64_t offset, void *output, size_t size) const
    {
        if (!Contains(offset, size) || !output)
            return false;
        if (offset >= cacheOffset_ && offset - cacheOffset_ <= cacheSize_ && size <= cacheSize_ - (offset - cacheOffset_))
        {
            std::memcpy(output, cache_.data() + (offset - cacheOffset_), size);
            return true;
        }
        if (size > cache_.size())
            return RawRead(base_ + offset, output, size);
        cacheOffset_ = offset;
        cacheSize_ = 0;
        const size_t count = static_cast<size_t>(std::min<uint64_t>(cache_.size(), size_ - offset));
        if (!RawRead(base_ + offset, cache_.data(), count))
            return false;
        cacheSize_ = count;
        std::memcpy(output, cache_.data(), size);
        return true;
    }
} // namespace nextdumper::module
