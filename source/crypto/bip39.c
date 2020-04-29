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
#define BIP39_GLOBAL

/** Header file reference */
#include "bip39.h"
#include "crypto_api.h"
#include "stdio.h"
#include <wdt.h>

/** Function implementations */
/**
* @functionname: 
* @description: 
* @para:
* @return:
* @notice:pPassword is HMAC's key; pSalt is HMAC's text
*		BIP39:
*		To create a binary seed from the mnemonic, we use the PBKDF2 function 
*		with a mnemonic sentence (in UTF-8 NFKD) used as the password 
*		and the string "mnemonic" + passphrase (again in UTF-8 NFKD) used as the salt. 
*		The iteration count is set to 2048 and HMAC-SHA512 is used as the pseudo-random function. 
*		The length of the derived key is 512 bits (= 64 bytes).
*/
void PBKDF2_HMAC_SHA512(uint8_t *pPassword, uint32_t passwordLen,
						uint8_t *pSalt, uint32_t saltLen,
						uint32_t iterC, uint8_t *pOut, int32_t outLen)
{
	uint32_t i, j;
	uint8_t *pKey = pPassword;
	uint32_t keyLen = passwordLen;
	char *pPassphrase_prefix = PASSPHRASE_PREFIX;
	uint8_t *pText;
	uint32_t textLen = 0;

	uint8_t bufSHA512Key[SHA512_LEN];
	uint8_t bufSHA512[SHA512_LEN];
	uint8_t bufSHA512Tmp[SHA512_LEN];
	uint32_t I = 1;
	uint8_t bufI[4] = {0x00};
	uint32_t outOffset = 0;

	memset(bufSHA512, 0x00, SHA512_LEN);
	memset(bufSHA512Tmp, 0x00, SHA512_LEN);
	textLen = strlen(pPassphrase_prefix);
	pText = (uint8_t *)calloc(textLen + saltLen + 4, sizeof(uint8_t));
	if (NULL == pText)
	{
		return;
	}
	memcpy(pText, pPassphrase_prefix, textLen);
	if (saltLen > 0)
	{
		memcpy(pText + textLen, pSalt, saltLen);
		textLen += saltLen;
	}

	if (keyLen > 128)
	{
		sha512_api(pKey, keyLen, bufSHA512Key);
		pKey = bufSHA512Key;
		keyLen = SHA512_LEN;
	}
	while (outLen > 0)
	{
		bufI[0] = (uint8_t)((I >> 24) & 0xff);
		bufI[1] = (uint8_t)((I >> 16) & 0xff);
		bufI[2] = (uint8_t)((I >> 8) & 0xff);
		bufI[3] = (uint8_t)(I & 0xff);
		// u32_to_buf(bufI, I);
		memcpy(pText + textLen, bufI, 4);

		hmac_sha512_api(pText, textLen + 4, pKey, keyLen, bufSHA512Tmp);
		memcpy(bufSHA512, bufSHA512Tmp, SHA512_LEN);
		for (i = 1; i < iterC; i++)
		{
			// feed_dog();
			wdt_feed();
			hmac_sha512_api(bufSHA512Tmp, SHA512_LEN, pKey, keyLen, bufSHA512Tmp);
			for (j = 0; j < SHA512_LEN; j++)
			{
				bufSHA512[j] ^= bufSHA512Tmp[j];
			}
		}
		memcpy(pOut + outOffset, bufSHA512, outLen >= SHA512_LEN ? SHA512_LEN : outLen);
		outOffset += SHA512_LEN;
		outLen -= SHA512_LEN;
		I++;
	}
	if (NULL != pText)
	{
		free(pText);
	}

	return;
}

/**
* @functionname: 
* @description: 
* @para:
* @return:
* @notice: pMnemonic -> password;pPassphrase -> salt
* @notice: seed output from BIP39 is BIP32 input seed
*/
void bip39_gen_seed_with_mnomonic(uint8_t *pMnemonic, uint32_t mnemonicLen,
								  uint8_t *pPassphrase, uint32_t passphraseLen,
								  uint8_t *pSeed, int32_t seedLen)
{
	PBKDF2_HMAC_SHA512(pMnemonic, mnemonicLen, pPassphrase, passphraseLen,
					   2048, pSeed, seedLen);
}
