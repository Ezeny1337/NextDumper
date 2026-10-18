#include "nextdumper/module/ModuleCatalog.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

#include "ElfFile.hpp"
#include "ElfTypes.hpp"

namespace nextdumper::module
{
    namespace
    {
        bool Named(const std::string &path, const std::string &name)
        {
            return path == name || (path.size() > name.size() && path.ends_with(name) &&
                                    path[path.size() - name.size() - 1] == '/');
        }

        bool Image(const IMemorySource &memory, const memory::MemoryRegion &mapping,
                   const std::string &name, ModuleImage &out)
        {
            ElfHeader header{};
            if (!memory.Read(mapping.start, header) || std::memcmp(header.e_ident, "\177ELF", 4) != 0 ||
                header.e_ident[EI_CLASS] != kElfClass || header.e_ident[EI_DATA] != ELFDATA2LSB ||
                header.e_ident[EI_VERSION] != EV_CURRENT || header.e_version != EV_CURRENT ||
                header.e_machine != kElfMachine || (header.e_type != ET_DYN && header.e_type != ET_EXEC) ||
                header.e_ehsize != sizeof(header) || header.e_phentsize != sizeof(ElfProgram) ||
                !header.e_phnum || header.e_phnum > 1024 || header.e_phoff < sizeof(header) ||
                header.e_phoff > 1024 * 1024 || header.e_phoff > UINTPTR_MAX - mapping.start)
                return false;
            std::vector<ElfProgram> programs(header.e_phnum);
            const size_t programBytes = programs.size() * sizeof(ElfProgram);
            if (!memory.ReadBytes(mapping.start + static_cast<uintptr_t>(header.e_phoff), programs.data(), programBytes).Ok())
                return false;
            const auto first = std::find_if(programs.begin(), programs.end(), [](const auto &program)
                                            { return program.p_type == PT_LOAD && program.p_offset == 0 && program.p_filesz >= sizeof(ElfHeader); });
            if (first == programs.end() || first->p_vaddr > mapping.start ||
                header.e_phoff > first->p_filesz || programBytes > first->p_filesz - header.e_phoff)
                return false;
            ModuleImage candidate;
            candidate.name = name;
            candidate.base = mapping.start;
            candidate.loadBias = mapping.start - static_cast<uintptr_t>(first->p_vaddr);
            candidate.pointerWidth = sizeof(uintptr_t);
            candidate.architecture = sizeof(uintptr_t) == 8 ? ModuleArchitecture::Arm64 : ModuleArchitecture::Arm32;
            candidate.filePath = mapping.path;
            if (candidate.filePath.ends_with(" (deleted)"))
                candidate.filePath.resize(candidate.filePath.size() - 10);
            candidate.fileDevice = mapping.device;
            candidate.fileInode = mapping.inode;
            candidate.imageFileOffset = mapping.fileOffset;
            if (!Named(candidate.filePath, name))
            {
                ElfFile file;
                if (!mapping.fileOffset || !file.Open(candidate.filePath, mapping.fileOffset, mapping.inode, mapping.device) ||
                    !Named(file.EntryName(), name))
                    return false;
            }
            for (const auto &program : programs)
            {
                if (program.p_type != PT_LOAD && program.p_type != PT_DYNAMIC)
                    continue;
                if (program.p_memsz > 2ULL * 1024 * 1024 * 1024)
                    return false;
                if (program.p_vaddr > UINTPTR_MAX - candidate.loadBias)
                    return false;
                const uintptr_t start = candidate.loadBias + static_cast<uintptr_t>(program.p_vaddr);
                if (program.p_memsz > UINTPTR_MAX - start || program.p_filesz > program.p_memsz ||
                    program.p_offset > UINT64_MAX - program.p_filesz)
                    return false;
                const uintptr_t end = start + static_cast<uintptr_t>(program.p_memsz);
                if (program.p_type == PT_DYNAMIC)
                {
                    if (candidate.dynamicAddress || !program.p_memsz || program.p_memsz > 1024 * 1024 ||
                        program.p_memsz % sizeof(ElfDynamic))
                        return false;
                    candidate.dynamicAddress = start;
                    candidate.dynamicSize = static_cast<size_t>(program.p_memsz);
                    continue;
                }
                if (program.p_align > 1 && ((program.p_align & (program.p_align - 1)) != 0 ||
                                            program.p_vaddr % program.p_align != program.p_offset % program.p_align))
                    return false;
                candidate.end = std::max(candidate.end, end);
                for (const auto &region : memory.Regions())
                {
                    if (region.end <= start)
                        continue;
                    if (region.start >= end)
                        break;
                    if (region.inode && (region.inode != mapping.inode || region.device != mapping.device))
                        return false;
                    const uintptr_t low = std::max(start, region.start), high = std::min(end, region.end);
                    const uint64_t delta = low - region.start;
                    if (region.fileOffset > UINT64_MAX - delta)
                        return false;
                    const uint64_t imageDelta = low - start;
                    if (imageDelta < program.p_filesz && region.inode)
                    {
                        if (program.p_offset > UINT64_MAX - mapping.fileOffset ||
                            imageDelta > UINT64_MAX - mapping.fileOffset - program.p_offset ||
                            region.fileOffset + delta != mapping.fileOffset + program.p_offset + imageDelta)
                            return false;
                    }
                    if (candidate.segments.size() >= 16384)
                        return false;
                    candidate.segments.push_back({low, high, region.fileOffset + delta, region.readable,
                                                  region.writable, region.executable, region.privateMapping, region.path});
                }
            }
            std::sort(candidate.segments.begin(), candidate.segments.end(), [](const auto &left, const auto &right)
                      { return left.start < right.start; });
            for (size_t index = 1; index < candidate.segments.size(); ++index)
                if (candidate.segments[index].start < candidate.segments[index - 1].end)
                    return false;
            if (candidate.dynamicAddress && std::none_of(candidate.segments.begin(), candidate.segments.end(),
                                                         [&](const auto &segment)
                                                         { return segment.readable && candidate.dynamicAddress >= segment.start &&
                                                                  candidate.dynamicAddress < segment.end && candidate.dynamicSize <= segment.end - candidate.dynamicAddress; }))
                return false;
            if (!candidate.IsValid() || candidate.end - candidate.base > 2ULL * 1024 * 1024 * 1024 ||
                candidate.segments.empty() ||
                std::none_of(candidate.segments.begin(), candidate.segments.end(), [](const auto &segment)
                             { return segment.executable; }))
                return false;
            out = std::move(candidate);
            return true;
        }
    }

    bool ModuleCatalog::Discover(IMemorySource &memory, const std::vector<std::string> &names, ModuleImage &out)
    {
        out = {};
        if (!memory.IsInitialized() || names.size() > 64)
            return false;
        for (const auto &name : names)
        {
            if (name.empty() || name.size() > 4096 || name.find('\0') != std::string::npos)
                continue;
            for (const auto &mapping : memory.Regions())
            {
                if (!mapping.readable || mapping.end - mapping.start < sizeof(ElfHeader))
                    continue;
                std::string path = mapping.path;
                if (path.ends_with(" (deleted)"))
                    path.resize(path.size() - 10);
                if (!Named(path, name) && !path.ends_with(".apk") && !path.ends_with(".zip"))
                    continue;
                if (Image(memory, mapping, name, out))
                    return true;
            }
        }
        return false;
    }
} // namespace nextdumper::module
