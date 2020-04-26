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
#ifndef TLV_H
#define TLV_H

/** Avoid duplicate definitions */
#ifdef TLV_GLOBAL
#define TLV_EXT
#else
#define TLV_EXT	extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>	//memcpy...
#include "mason_errno.h"

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif    /* __cplusplus */

/** Macro definitions*/
#define TLV_MAX					10

/** Variable declarations */
typedef struct
{
	uint16_t T;
	uint16_t L;
	const char *pV;
}stTLVType, *pstTLVType;
TLV_EXT stTLVType stTLV[TLV_MAX];
TLV_EXT volatile uint16_t tlvLen;

/** Function declarations */
uint32_t tlv_get_tag(pstTLVType pstTLV, const char *stream, uint32_t index);
uint32_t tlv_get_len(pstTLVType pstTLV, const char* stream, uint32_t index);
uint32_t tlv_get_value(pstTLVType pstTLV, const char* stream, uint32_t index);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
