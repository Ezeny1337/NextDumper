#pragma once

#include <cstdint>
#include <elf.h>
#include <type_traits>

namespace nextdumper::module
{
    using ElfHeader = std::conditional_t<sizeof(uintptr_t) == 8, Elf64_Ehdr, Elf32_Ehdr>;
    using ElfProgram = std::conditional_t<sizeof(uintptr_t) == 8, Elf64_Phdr, Elf32_Phdr>;
    using ElfDynamic = std::conditional_t<sizeof(uintptr_t) == 8, Elf64_Dyn, Elf32_Dyn>;
    using ElfSection = std::conditional_t<sizeof(uintptr_t) == 8, Elf64_Shdr, Elf32_Shdr>;
    using ElfSymbol = std::conditional_t<sizeof(uintptr_t) == 8, Elf64_Sym, Elf32_Sym>;
    inline constexpr unsigned char kElfClass = sizeof(uintptr_t) == 8 ? ELFCLASS64 : ELFCLASS32;
    inline constexpr uint16_t kElfMachine = sizeof(uintptr_t) == 8 ? EM_AARCH64 : EM_ARM;
} // namespace nextdumper::module
