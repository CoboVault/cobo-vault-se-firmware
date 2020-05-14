/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

/*
#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif
*/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "base58.h"

#include  "sha256.h"

static bool sha256(void *pDigest, const void *pDataIn, size_t DataLen);


bool (*b58_sha256_impl)(void *, const void *, size_t) = sha256;

static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1
};

typedef uint64_t b58_maxint_t;
typedef uint32_t b58_almostmaxint_t;
#define b58_almostmaxint_bits (sizeof(b58_almostmaxint_t) * 8)
static const b58_almostmaxint_t b58_almostmaxint_mask = ((((b58_maxint_t)1) << b58_almostmaxint_bits) - 1);


static bool sha256(void *pDigest, const void *pDataIn, size_t DataLen)
{
	SHA256_hash((UINT8 *)pDataIn, (UINT32)DataLen, (UINT8 *)pDigest);
	return true;
}

bool b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz)
{
	size_t binsz = *binszp;
	const unsigned char *b58u = (void *)b58;
	unsigned char *binu = bin;
	size_t outisz = (binsz + sizeof(b58_almostmaxint_t) - 1) / sizeof(b58_almostmaxint_t);
	b58_almostmaxint_t *outi = NULL;
	b58_maxint_t t;
	size_t i, j;
	uint8_t bytesleft = binsz % sizeof(b58_almostmaxint_t);
	b58_almostmaxint_t zeromask = bytesleft ? (b58_almostmaxint_mask << (bytesleft * 8)) : 0;
	unsigned zerocount = 0;

	outi = (b58_almostmaxint_t *)calloc(outisz, sizeof(b58_almostmaxint_t));
	if (NULL == outi)
	{
		*binszp = 0;
		return false;
	}

	if (!b58sz)
		b58sz = strlen(b58);

	for (i = 0; i < outisz; ++i)
	{
		outi[i] = 0;
	}

	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
		++zerocount;

	for (; i < b58sz; ++i)
	{
		b58_almostmaxint_t c;
		if (b58u[i] & 0x80)
		{
			// High-bit set on invalid digit
			if (NULL != outi)
			{
				free(outi);
			}
			return false;
		}
		if (b58digits_map[b58u[i]] == -1)
		{
			// Invalid base58 digit
			if (NULL != outi)
			{
				free(outi);
			}
			return false;
		}
		c = (unsigned)b58digits_map[b58u[i]];
		for (j = outisz; j--;)
		{
			t = ((b58_maxint_t)outi[j]) * 58 + c;
			c = t >> b58_almostmaxint_bits;
			outi[j] = t & b58_almostmaxint_mask;
		}
		if (c)
		{
			// Output number too big (carry to the next int32)
			if (NULL != outi)
			{
				free(outi);
			}
			return false;
		}
		if (outi[0] & zeromask)
		{
			// Output number too big (last int32 filled too far)
			if (NULL != outi)
			{
				free(outi);
			}
			return false;
		}
	}

	j = 0;
	if (bytesleft)
	{
		for (i = bytesleft; i > 0; --i)
		{
			*(binu++) = (outi[0] >> (8 * (i - 1))) & 0xff;
		}
		++j;
	}

	for (; j < outisz; ++j)
	{
		for (i = sizeof(*outi); i > 0; --i)
		{
			*(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
		}
	}

	// Count canonical base58 byte count
	binu = bin;
	for (i = 0; i < binsz; ++i)
	{
		if (binu[i])
			break;
		--*binszp;
	}
	*binszp += zerocount;

	if (NULL != outi)
	{
		free(outi);
	}

	return true;
}

static bool my_dblsha256(void *hash, const void *data, size_t datasz)
{
	uint8_t buf[0x20];
	return b58_sha256_impl(buf, data, datasz) && b58_sha256_impl(hash, buf, sizeof(buf));
}

int b58check(const void *bin, size_t binsz, const char *base58str, size_t b58sz)
{
	unsigned char buf[32];
	const uint8_t *binc = bin;
	unsigned i;
	if (binsz < 4)
		return -4;
	if (!my_dblsha256(buf, bin, binsz - 4))
		return -2;
	if (memcmp(&binc[binsz - 4], buf, 4))
		return -1;

	// Check number of zeros is correct AFTER verifying checksum (to avoid possibility of accessing base58str beyond the end)
	for (i = 0; binc[i] == '\0' && base58str[i] == '1'; ++i)
	{
	} // Just finding the end of zeros, nothing to do in loop
	if (binc[i] == '\0' || base58str[i] == '1')
		return -3;

	return binc[0];
}

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz)
{
	const uint8_t *bin = data;
	int carry;
	size_t i, j, high, zcount = 0;
	size_t size;
	uint8_t *buf = NULL;
	size = (binsz - zcount) * 138 / 100 + 1;

	buf = (uint8_t *)calloc(size, sizeof(uint8_t));
	if (NULL == buf)
	{
		*b58sz = 0;
		return false;
	}

	while (zcount < binsz && !bin[zcount])
	{
		++zcount;
	}
	memset(buf, 0, size);

	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
			if (!j)
			{
				// Otherwise j wraps to maxint which is > high
				break;
			}
		}
	}

	for (j = 0; j < size && !buf[j]; ++j)
		;

	if (*b58sz <= zcount + size - j)
	{
		*b58sz = zcount + size - j + 1;
		if (NULL != buf)
		{
			free(buf);
		}
		return false;
	}

	if (zcount)
	{
		memset(b58, '1', zcount);
	}
	for (i = zcount; j < size; ++i, ++j)
	{
		b58[i] = b58digits_ordered[buf[j]];
	}
	b58[i] = '\0';
	*b58sz = i + 1;

	if (NULL != buf)
	{
		free(buf);
	}

	return true;
}

bool b58check_enc(char *b58c, size_t *b58c_sz, uint8_t *verPrefix, size_t prefixsz, 
		const void *data, size_t datasz, uint8_t *suffix, size_t suffixsz)
{
	uint8_t *buf = NULL;
	uint8_t *hash = NULL;
	
	if (NULL == verPrefix)
	{
		prefixsz = 0;
	}
	if (NULL == suffix)
	{
		suffixsz = 0;
	}
	buf = (uint8_t *)calloc((prefixsz + datasz + suffixsz + 0x20), sizeof(uint8_t));
	if (NULL == buf)
	{
		*b58c_sz = 0;
		return false;
	}
	hash = &buf[prefixsz + datasz + suffixsz];
	
	if (NULL != verPrefix)
	{
		memcpy(&buf[0], verPrefix, prefixsz);
	}
	memcpy(&buf[prefixsz], data, datasz);
	if (NULL != suffix)
	{
		memcpy(&buf[prefixsz+datasz], suffix, suffixsz);
	}
	if (!my_dblsha256(hash, buf, prefixsz + datasz + suffixsz))
	{
		*b58c_sz = 0;
		if (NULL != buf)
		{
			free(buf);
		}
		return false;
	}

	if (!b58enc(b58c, b58c_sz, buf, prefixsz + datasz + suffixsz + 4))
	{
		if (NULL != buf)
		{
			free(buf);
		}
		return false;
	}

	if (NULL != buf)
	{
		free(buf);
	}

	return true;
}
