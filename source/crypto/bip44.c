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
#define BIP44_GLOBAL

/** Header file reference */
#include "bip44.h"
#include "crypto_api.h"

/** Function implementations */
/**
 * @functionname: bip44_str_to_hdpath
 * @description: 
 * @para: 
 * @return: 
 */
BIP44_EXT bool bip44_str_to_hdpath(uint8_t *pStr, uint32_t strLen, stHDPathType *pstHDPath)
{
	char cSlash = '/';
	char cApostrophe = '\'';
	uint32_t index = 0;
	uint32_t count = 0;
	uint8_t *pStrTmp = NULL;

	/*HDPath "m/2147483647'/2147483647'/2147483647'/2147483647'/2147483647'...*/
	if ((NULL == pStr) || (('m' != pStr[0]) && ('M' != pStr[0])) || (0 == strLen) || (strLen > 61))
	{
		return false;
	}

	pStrTmp = (uint8_t *)calloc(strLen + 1, sizeof(uint8_t));
	if (NULL == pStrTmp)
	{
		return false;
	}
	memcpy(pStrTmp, pStr, strLen);
	pStrTmp[strLen] = '\0';

	if ('m' == pStrTmp[0])
	{
		pstHDPath->verBytes = SF_VB_INT_MNET_PRV;
	}
	else if ('M' == pStrTmp[0])
	{
		pstHDPath->verBytes = SF_VB_INT_MNET_PUB;
	}
	pstHDPath->depth = 0;
	index++;

	while ((index < strLen) && (cSlash == pStrTmp[index++])) // m/*********
	{
		while (!isdigit(pStrTmp[index]))
		{
			index++;
		} /* non-digit should be skipped */
		if (index >= strLen)
		{
			if (NULL != pStrTmp)
			{
				free(pStrTmp);
			}
			return false;
		}
		pstHDPath->value[pstHDPath->depth] = myatoui((const char *)pStrTmp + index);
		count = 0;
		while (isdigit(pStrTmp[index])) /* non-digit should be skipped */
		{
			index++;
			if (count++ > 10)
			{
				if (NULL != pStrTmp)
				{
					free(pStrTmp);
				}
				return false;
			}
		}
		if (cApostrophe == pStrTmp[index])
		{
			index++;
			pstHDPath->value[pstHDPath->depth] += 0x80000000;
		}
		pstHDPath->depth++;
	}

	if (NULL != pStrTmp)
	{
		free(pStrTmp);
	}

	return true;
}

/**
* @functionname: bip44_gen_key_fingerprint
* @description: 
* @para:
* @return:
*/
void bip44_gen_key_fingerprint(uint8_t *pPubKeyC,
							   uint8_t *pFingerPrint, uint8_t fingerPrintLen)
{
	uint8_t hash256[SHA256_LEN] = {0};
	uint8_t RPMD160[RPMD160_LEN] = {0};

	sha256_api(pPubKeyC, 33, hash256);

	ripeMD160_api(hash256, SHA256_LEN, RPMD160);

	memcpy(pFingerPrint, RPMD160, fingerPrintLen);
}

/**
* @functionname: bip44_gen_child_number
* @description: 
* @para:
* @return:
*/
void bip44_gen_child_number(uint8_t *pChildNum, uint32_t u32ChildNum)
{
	u32_to_buff(u32ChildNum, pChildNum);
}
