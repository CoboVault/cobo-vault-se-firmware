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
#ifndef BIP44_H
#define BIP44_H

/** Avoid duplicate definitions */
#ifdef BIP44_GLOBAL
#define BIP44_EXT
#else
#define BIP44_EXT	extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>	//memcpy...
#include <ctype.h>

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif    /* __cplusplus */

/** Macro definitions*/
#define SF_VB_INT_MNET_PUB		0x0488B21E
#define SF_VB_INT_MNET_PRV		0x0488ADE4
#define SF_VB_INT_TNET_PUB		0x043587CF
#define SF_VB_INT_TNET_PRV		0x04358394
#define SF_VB_BUF_MNET_PUB		(0x04, 0x88, 0xB2, 0x1E)
#define SF_VB_BUF_MNET_PRV		(0x04, 0x88, 0xAD, 0xE4)
#define SF_VB_BUF_TNET_PUB		(0x04, 0x35, 0x87, 0xCF)
#define SF_VB_BUF_TNET_PRV		(0x04, 0x35, 0x83, 0x94)


/** Variable declarations */
typedef struct
{
	uint32_t verBytes;
	uint32_t value[5];
	uint8_t depth;
}stHDPathType;

/** Function declarations */
BIP44_EXT bool bip44_str_to_hdpath(uint8_t *pStr, uint32_t strLen, stHDPathType *pstHDPath);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
