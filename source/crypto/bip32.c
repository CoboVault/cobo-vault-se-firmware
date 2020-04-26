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
#define BIP32_GLOBAL

/** Header file reference */
#include "bip32.h"
#include "crypto_api.h"

/** Variable definitions */
BIP32_EXT const uint8_t gcu8_secp256k1_n[32] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
	0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}; //ECC_secp256k1_n

/** Function implementations */
/**
 * @functionname: all_zero
 * @description: 
 * @para: 
 * @return: 
 */
bool all_zero(const uint8_t *pBuf, uint32_t bufLen)
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
* @functionname: bip32_check_key_valid
* @description: 
* @para:
* @return:
*/
bool bip32_check_key_valid(uint8_t *pKey, uint32_t keyLen)
{
	if (32 != keyLen)
	{
		return false;
	}

	if (all_zero(pKey, keyLen))
	{
		return false;
	}

	if (memcmp(pKey, gcu8_secp256k1_n, keyLen) >= 0)
	{
		return false;
	}

	return true;
}

/**
 * @functionname: bip32_pubkey_compress
 * @description: 
 * @para: 
 * @return: 
 */
void bip32_pubkey_compress(uint8_t *pPubKeyX, uint8_t *pPubKeyY, uint8_t *pPubKeyC)
{
	if (pPubKeyY[31] & 0x01)
	{
		pPubKeyC[0] = 0x03;
	}
	else
	{
		pPubKeyC[0] = 0x02;
	}
	memcpy(pPubKeyC + 1, pPubKeyX, 32);
}

/**
* @functionname: bip32_get_pubkey
* @description: 
* @para:
* @return:
*/
void bip32_get_pubkey(uint8_t *pPriKey, uint8_t *pPubKeyX, uint8_t *pPubKeyY)
{

	return;
}

/**
* @functionname: bip32_get_compressd_pubkey
* @description: 
* @para: 
* @return: 
*/
void bip32_get_compressd_pubkey(uint8_t *pPriKey, uint8_t *pPubKeyC)
{
	uint8_t *pPri = pPriKey;
	uint8_t *pPubC = pPubKeyC;
	uint8_t bufPubKey[PUBKEY_LEN] = {0x00};

	bip32_get_pubkey(pPri, bufPubKey, bufPubKey+32);
	bip32_pubkey_compress(bufPubKey, bufPubKey+32, pPubC);

	return;
}

/**
* @functionname: bip32_gen_root_seed
* @description: 
* @para:
* @return:
* @notice: pSeed is HMAC_SHA512 text ; HMAC_SHA512 key:"Bitcoin seed"
* @notice: BIP39's output is BIP32's input
*/
void bip32_gen_root_seed(uint8_t *pSeed, uint32_t seedLen,
						 uint8_t *pKey, uint32_t keyLen, 
						 uint8_t *pRootSeed)
{
	uint8_t *pDefaultKey = (uint8_t *)"Bitcoin seed";
	uint32_t defaultKeyLen = strlen((const char *)pDefaultKey);

	if ((NULL == pKey) || (0 == keyLen))
	{
		pKey = pDefaultKey;
		keyLen = defaultKeyLen;
	}
	hmac_sha512_api(pSeed, seedLen, pKey, keyLen, pRootSeed);
}

/**
* @functionname: 
* @description: 
* @para:
* @return:
*/
bool bip32_gen_master_key(uint8_t *pSeed, uint32_t seedLen,
						  uint8_t *pKey, uint32_t keyLen, 
						  uint8_t *pPrvKey, uint8_t *pChainCode)
{
	uint8_t bufRootSeed[64] = {0};

	bip32_gen_root_seed(pSeed, seedLen, pKey, keyLen, bufRootSeed);

	if (bip32_check_key_valid(bufRootSeed, 32))
	{
		return false;
	}
	memcpy(pPrvKey, bufRootSeed, 32);
	memcpy(pChainCode, bufRootSeed + 32, 32);

	return true;
}
