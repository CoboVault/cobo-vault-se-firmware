/*************************************************************************************************
Copyright (c) 2020 Cobo

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
in the file COPYING.  If not, see <http://www.gnu.org/licenses/>.
**************************************************************************************************/
/** Avoid duplicate definitions */
#ifndef EIP2333_H
#define EIP2333_H

/** Avoid duplicate definitions */
#ifdef EIP2333_GLOBAL
#define EIP2333_EXT
#else
#define EIP2333_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#define EIP2333_IKM_LEN 128
#define EIP2333_INFO_LEN 128
    /** Variable declarations */

    /** Function declarations */
    EIP2333_EXT bool derive_master_SK(uint8_t *seed, uint32_t seed_len, uint8_t *key);
    EIP2333_EXT bool derive_child_SK(uint8_t *parent_sk, uint32_t index, uint8_t *child_sk);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
