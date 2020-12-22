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
#define UTIL_GLOBAL

/** Header file reference */
#include "util.h"
#include "hrng.h"

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
 * @functionname: u64_to_le_buf
 * @description: 
 * @para: 
 * @return: 
 */
//covert uint64 to buff using Little Endian
void u64_to_le_buf(uint64_t u64, uint8_t *buf)
{
	buf[7] = (uint8_t)(u64 >> 56);
	buf[6] = (uint8_t)(u64 >> 48);
	buf[5] = (uint8_t)(u64 >> 40);
	buf[4] = (uint8_t)(u64 >> 32);
	buf[3] = (uint8_t)(u64 >> 24);
	buf[2] = (uint8_t)(u64 >> 16);
	buf[1] = (uint8_t)(u64 >> 8);
	buf[0] = (uint8_t)(u64);
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
 * @functionname: myatoui
 * @description: 
 * @para: 
 * @return: 
 */
unsigned int myatoui(const char *str)
{
	unsigned int n = 0;

	while (!isdigit(*str))
		++str;

	while (isdigit(*str))
	{
		int c;
		c = *str - '0';
		/* compare with n and MAX/10 , if n>MAX/10 (also consider of n=MAX/10) , data will overflow */
		if ((n > UINT_MAX / 10) || ((n == UINT_MAX / 10) && (c >= UINT_MAX % 10)))
		{
			return UINT_MAX;
		}
		n = n * 10 + c;
		++str;
	}
	return n;
}
/**
 * @functionname: myatoui64
 * @description: 
 * @para: 
 * @return: 
 */
bool myatoui64(const char *str, uint64_t *ui64)
{
	uint64_t n = 0;

	while (!isdigit(*str))
		++str;

	while (isdigit(*str))
	{
		uint64_t c;
		c = *str - '0';
		/* compare with n and MAX/10 , if n>MAX/10 (also consider of n=MAX/10) , data will overflow */
		if ((n > ULLONG_MAX / 10) || ((n == ULLONG_MAX / 10) && (c > ULLONG_MAX % 10)))
		{
			return false;
		}
		n = n * 10 + c;
		++str;
	}
	*ui64 = n;
	return true;
}
/**
 * @functionname: myuitoa
 * @description: 
 * @para: 
 * @return: 
 */
/* uitoa:  convert n to characters in s */
void myuitoa(uint32_t n, char s[])
{
	int i = 0;
	do
	{						   /* generate digits in reverse order */
		s[i++] = n % 10 + '0'; /* get next digit */
	} while ((n /= 10) > 0);   /* delete it */
	s[i] = '\0';
	str_reverse((uint8_t *)s, strlen(s));
}

/**
 * @functionname: is_number
 * @description: 
 * @para: 
 * @return: 
 */
bool is_number(const uint8_t *pnum, uint16_t len)
{
	uint16_t index = 0;
	while ((index < len) && isdigit(pnum[index]))
	{
		index++;
	}
	return ((0 != index) && (index >= len));
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
 * @functionname: memzero
 * @description: 
 * @para: 
 * @return: 
 */
void memzero(void *const pnt, const size_t len)
{
	memset(pnt, 0, len);
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
