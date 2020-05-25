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
#define MASON_UTIL_GLOBAL

/** Header file reference */
#include "mason_util.h"
#include "RipeMD160.h"
#include "mason_storage.h"
#include <hrng.h>

/** Function implementations */
/**
 * @functionname: u16_to_buf
 * @description: 
 * @para: 
 * @return: 
 */
void u16_to_buf(uint8_t *buf, uint16_t u16)
{
	buf[0] = (uint8_t)(u16 >> 8);
	buf[1] = (uint8_t)(u16);
}
/**
 * @functionname: u32_to_buf
 * @description: 
 * @para: 
 * @return: 
 */
void u32_to_buf(uint8_t *buf, uint32_t u32)
{
	buf[0] = (uint8_t)(u32 >> 24);
	buf[1] = (uint8_t)(u32 >> 16);
	buf[2] = (uint8_t)(u32 >> 8);
	buf[3] = (uint8_t)(u32);
}
/**
 * @functionname: buf_to_u16
 * @description: 
 * @para: 
 * @return: 
 */
void buf_to_u16(uint16_t *pu16, uint8_t *buf)
{
	*pu16 = (uint16_t)buf[0] << 8;
	*pu16 |= (uint16_t)buf[1];
}
/**
 * @functionname: buf_to_u32
 * @description: 
 * @para: 
 * @return: 
 */
void buf_to_u32(uint32_t *pu32, uint8_t *buf)
{
	*pu32 = (uint32_t)buf[0] << 24;
	*pu32 |= (uint32_t)buf[1] << 16;
	*pu32 |= (uint32_t)buf[2] << 8;
	*pu32 |= (uint32_t)buf[3];
}
/**
 * @functionname: swap_fast
 * @description: 
 * @para: 
 * @return: 
 */
void swap_fast(uint8_t *num1, uint8_t *num2)
{
	if (!(*num1 ^ *num2))
	{
		return;
	}
	*num1 ^= *num2;
	*num2 ^= *num1;
	*num1 ^= *num2;
}
/**
 * @functionname: str_reverse
 * @description: 
 * @para: 
 * @return: 
 */
void str_reverse(uint8_t *pStr, uint32_t strLen)
{
	uint32_t start = 0;
	uint32_t end = strLen - 1;

	while (start < end)
	{
		swap_fast(pStr + start++, pStr + end--);
	}
}
/**
 * @functionname: sequence_compare_bit8
 * @description: 
 * @para: 
 * @return: 
 */
int8_t sequence_compare_bit8(const uint8_t *pBuf1, const uint8_t *pBuf2, uint32_t bufLen)
{
	uint32_t i = 0;

	for (i = 0; i < bufLen; i++)
	{
		if (pBuf1[i] != pBuf2[i])
		{
			return (pBuf1[i] > pBuf2[i] ? 1 : -1);
		}
	}

	return 0;
}
/**
 * @functionname: sequence_all_zero
 * @description: 
 * @para: 
 * @return: 
 */
bool sequence_all_zero(const uint8_t *pBuf, uint32_t bufLen)
{
	uint32_t i = 0;
	uint8_t OR = 0x00;

	for (i = 0; (0x00 == OR) && (i < bufLen); i++)
	{
		OR |= pBuf[i];
	}

	return ((i == bufLen) && (0x00 == OR));
}
/**
 * @functionname: data_padding
 * @description: 
 * @para: 
 * @return: 
 */
void data_padding(uint8_t *pMsg, uint16_t *msgLen, emPaddingType emPadding)
{
	uint16_t paddingLen = 8 - ((*msgLen) & 7);

	switch (emPadding)
	{
	case ANSIX923:
	{
		break;
	}
	case ISO10126:
	{
		break;
	}
	case PKCS7:
	{
		memset(pMsg + *msgLen, 0x00, paddingLen); //PKCS7Padding
		*msgLen += paddingLen;
		break;
	}
	case PKCS5:
	{
		memset(pMsg + *msgLen, paddingLen, paddingLen); //PKCS5Padding
		*msgLen += paddingLen;
		break;
	}
	case NoPadding:
	{
		break;
	}
	default:
		break;
	}
}
/**
 * @functionname: zeromemory
 * @description: 
 * @para: 
 * @return: 
 */
void zeromemory(void *src, size_t len)
{
	memset(src, 0, len);
}
/**
 * @functionname: memcmp_ATA
 * @description: 
 * @para: 
 * @return: 
 */
/**memcmp Anti-timing-attack*/
bool memcmp_ATA(const uint8_t *buf1, const uint8_t *buf2, uint16_t len)
{
	uint16_t i = 0;
	bool bIsDiff = false;

	for (i = 0; i < len; i++)
	{
		bIsDiff |= (buf1[i] ^ buf2[i]);
	}

	return bIsDiff;
}
/**
 * @functionname: get_lrc
 * @description: 
 * @para: 
 * @return: 
 */
uint8_t get_lrc(uint8_t *pMsg, uint16_t msgLen)
{
	uint8_t lrc = 0x00;
	uint16_t i = 0;

	for (i = 0; i < msgLen; i++)
	{
		lrc ^= pMsg[i];
	}

	return lrc;
}
/**
 * @functionname: debug_key
 * @description: 
 * @para: 
 * @return: 
 */
void debug_key(char *name, uint8_t *key, uint16_t len)
{
	int i = 0;
	printf("%s : ", name);
	for (i = 0; i < len; i++)
	{
		// printf("\\x%02X", key[i]);
		printf("%02X ", key[i]);
	}
	printf("\n");
}
/**
 * @functionname: gen_random
 * @description: 
 * @para: 
 * @return: 
 */
void gen_random(uint8_t *output_random, uint16_t bits)
{
	uint16_t bytes = bits >> 3;
	int i = 0;

	hrng_initial();
	for (i = 0; i < bytes; i++)
	{
		output_random[i] = get_hrng8();
	}
}
