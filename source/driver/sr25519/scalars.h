//
// This file is Scalar tooling base on schnorrkel
// https://github.com/w3f/schnorrkel.git
//
//

#ifndef __SR25519_SCALARS_H__
#define __SR25519_SCALARS_H__

#include <stdint.h>
#include <stdlib.h>

void divide_scalar_bytes_by_cofactor(uint8_t *scalar, size_t scalar_len);
void multiply_scalar_bytes_by_cofactor(uint8_t *scalar, size_t scalar_len);

#endif
