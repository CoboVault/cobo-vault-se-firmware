//
// This file is Scalar tooling base on schnorrkel
// https://github.com/w3f/schnorrkel.git
//
//

#include "scalars.h"

void divide_scalar_bytes_by_cofactor(uint8_t *scalar, size_t scalar_len)
{
    uint8_t low = 0;

    for (int i = scalar_len - 1; i >= 0; i--)
    {
        uint8_t r = scalar[i] & (0x07); // 0b00000111
        scalar[i] >>= 3;
        scalar[i] += low;
        low = r << 5;
    }
}

void multiply_scalar_bytes_by_cofactor(uint8_t *scalar, size_t scalar_len)
{
    uint8_t high = 0;

    for (int i = 0; i < scalar_len; i++)
    {
        uint8_t r = scalar[i] & (0xE0); // 0b11100000
        scalar[i] <<= 3;
        scalar[i] += high;
        high = r >> 5;
    }
}
