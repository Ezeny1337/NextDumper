#pragma once

#include <cstdint>
#include <string>

namespace nextdumper::generation::detail
{
    inline std::string Hex(uint64_t value)
    {
        constexpr char digits[] = "0123456789ABCDEF";
        char buffer[2 + sizeof(value) * 2];
        char *at = buffer + sizeof(buffer);
        // uint64_t 最多 16 位十六进制数字，连同前缀始终落在固定缓冲区内
        do
        {
            *--at = digits[value & 15];
            value >>= 4;
        } while (value);
        *--at = 'x';
        *--at = '0';
        return {at, buffer + sizeof(buffer)};
    }

} // namespace nextdumper::generation::detail
