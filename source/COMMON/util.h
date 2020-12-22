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
#ifndef UTIL_H
#define UTIL_H

/** Avoid duplicate definitions */
#ifdef UTIL_GLOBAL
#define UTIL_EXT
#else
#define UTIL_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#define TO_SHORT(H8, L8) ((uint16_t)(((uint16_t)H8 << 8) || ((uint16_t)L8)))

	/** Variable declarations */
	typedef enum
	{
		ANSIX923,
		ISO10126,
		PKCS7,
		PKCS5,
		NoPadding
	} emPaddingType;

	/** Function declarations */
	int atou8(uint8_t ascDat);
	uint8_t u8toa(uint8_t dat);
	void str_to_hex(uint8_t *bufBcd, uint32_t *bufBcdLen, uint8_t *str, int strLen);
	void hex_to_str(uint8_t *str, uint32_t *strLen, uint8_t *bufBcd, uint32_t bufBcdLen);
	void u16_to_buf(uint8_t *buf, uint16_t u16);
	void u32_to_buf(uint8_t *buf, uint32_t u32);
	void u64_to_le_buf(uint64_t u64, uint8_t *buf);
	void buf_to_u16(uint16_t *pu16, uint8_t *buf);
	void buf_to_u32(uint32_t *pu32, uint8_t *buf);
	unsigned int myatoui(const char *str);
	bool myatoui64(const char *str, uint64_t *ui64);
	void myuitoa(uint32_t n, char s[]);
	bool is_number(const uint8_t *pnum, uint16_t len);
	uint16_t buf_return_u16(uint8_t *buf);
	uint32_t buf_return_u32(uint8_t *buf);
	void swap_fast(uint8_t *num1, uint8_t *num2);
	uint8_t endian_exchange(uint8_t *buf, uint16_t bufLen, uint8_t alignLen);
	void str_reverse(uint8_t *pStr, uint32_t strLen);
	int8_t sequence_compare_bit8(const uint8_t *pBuf1, const uint8_t *pBuf2, uint32_t bufLen);
	bool sequence_all_zero(const uint8_t *pBuf, uint32_t bufLen);
	void data_padding(uint8_t *pMsg, uint16_t *msgLen, emPaddingType emPadding);
	void memzero(void *const pnt, const size_t len);
	uint8_t get_lrc(uint8_t *pMsg, uint16_t msgLen);
	bool memcmp_ATA(const uint8_t *buf1, const uint8_t *buf2, uint16_t len);
	void debug_key(char *name, uint8_t *key, uint16_t len);
	void gen_random(uint8_t *output_random, uint16_t bits);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
