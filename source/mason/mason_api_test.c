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
#define MASON_API_TEST_GLOBAL

/** Header file reference */
#include "mason_api_test.h"
#include "mason_debug.h"
#include "base58.h"
#include "coin_util.h"
#include "hmac.h"

/** Function implementations */
/**
 * @functionname: mason_test_base58
 * @description: 
 * @para: 
 * @return: 
 */
MASON_API_TEST_EXT emRetType mason_test_base58(void)
{
	emRetType emRet = ERT_OK;
	uint8_t *key = (uint8_t *)"\x1E\x99\x42\x3A\x4E\xD2\x76\x08\xA1\x5A\x26\x16\xA2\xB0\xE9\xE5\x2C\xED\x33\x0A\xC5\x30\xED\xCC\x32\xC8\xFF\xC6\xA5\x26\xAE\xDD";
	size_t keysz = strlen((const char*)key);
	char buf[100] = {0x00};
	size_t lenbuf = sizeof(buf);
	uint8_t *keyWIF = (uint8_t *)"5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn";
	size_t keyWIFsz = strlen((const char*)keyWIF);
	
	printf("%s() start...\n", __FUNCTION__);
	
	dump_data("Key hex:", key, keysz);

	if (b58check_enc(buf, &lenbuf, B58_PREFIX_PRIKEY_WIF, 1, key, keysz, NULL, 0))
	{
		dump_data_printable("Key WIF:", (uint8_t *)buf, lenbuf);
	}

	lenbuf = sizeof(buf);
	if (b58check_enc(buf, &lenbuf, B58_PREFIX_PRIKEY_WIF, 1, 
			key, keysz, B58_SUFFIX_WIF_COMPRESSED, 1))
	{
		dump_data_printable("Key WIF-compressed:", (uint8_t *)buf, lenbuf);
	}

	lenbuf = sizeof(buf);
	if(b58tobin(buf, &lenbuf, (const char*)keyWIF, keyWIFsz))
	{
		dump_data("Key hex:", (uint8_t*)buf, lenbuf);
	}
	
	return emRet;
}
/**
 * @functionname: mason_test_hmac
 * @description: 
 * @para: 
 * @return: 
 */
MASON_API_TEST_EXT emRetType mason_test_hmac(void)
{
	uint8_t key[16] = {	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
						0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
	uint8_t plain[24] = {	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
							0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
							0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}; // plain_cbc = 0x000102030405060708090A0B0C0D0E0F1011121314151617;
	uint8_t result[64] = {0x00};

	printf("%s() start...\n", __FUNCTION__);

	hmac_sha256(plain, sizeof(plain), key, sizeof(key), result);

	printf("hmac_sha256\n");
	dump_data("plain:", plain, sizeof(plain));
	dump_data("key:", key, sizeof(key));
	dump_data("result:", result, sizeof(result));

	hmac_sha512(plain, sizeof(plain), key, sizeof(key), result);

	printf("hmac_sha512\n");
	dump_data("plain:", plain, sizeof(plain));
	dump_data("key:", key, sizeof(key));
	dump_data("result:", result, sizeof(result));
	
	return ERT_OK;
}
/**
 * @functionname: mason_api_test
 * @description: 
 * @para: 
 * @return: 
 */
MASON_API_TEST_EXT emRetType mason_api_test(void)
{
	emRetType emRet = ERT_OK;

	printf("%s() start...\n", __FUNCTION__);
	//mason_test_base58();
	//mason_test_hmac();

	return emRet;
}

