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
#define MASON_ISP_GLOBAL

/** Header file reference */
#include "mason_iap.h"
#include "common.h"
#include "mason_util.h"
#include "eflash.h"
#include "sha2.h"
#include "mason_hdw.h"
#include "crypto_api.h"

/** Function implementations */
/**
 * @functionname: mason_iap_pack_verify_process
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_iap_pack_verify_process(emFwPackTypeType emFwPackType, uint8_t *pBin, uint32_t binLen)
{
	emRetType emRet = ERT_OK;
	static SHA256_CTX sha256ctx;
	uint8_t *PckHash = NULL;

	switch (emFwPackType)
	{
	case E_PACK_FIRST:
	{
		sha256_Init(&sha256ctx);
	}
	case E_PACK_CONTINUE:
	case E_PACK_LAST:
	{
		uint8_t blk_sha256_buf[SHA256_LEN] = {0};
		uint8_t *blkHash = NULL;
		sha256_api(pBin, (binLen-8), blk_sha256_buf);
		blkHash = pBin + binLen - 8;
		if (memcmp_ATA(blkHash, blk_sha256_buf, 8))
		{
			return ERT_IAP_fileDigest;
		}

		sha256_Update(&sha256ctx, pBin, binLen);
		break;
	}
	case E_PACK_HDR:
	{
		uint8_t bufSHA256[SHA256_LEN] = {0};
		sha256_Final(&sha256ctx, bufSHA256);

		PckHash = pBin + 32;
		if (memcmp_ATA(PckHash, bufSHA256, SHA256_LEN))
		{
			emRet = ERT_IAP_fileDigest;
		}

		//k1 verify
		if (ERT_OK == emRet)
		{
			uint8_t *Sign = pBin + 64;
			uint8_t public_key[PUB_KEY_LEN] = {0};
			if (ERT_OK == mason_storage_read((uint8_t *)public_key, PUB_KEY_LEN, FLASH_ADDR_WEB_AUTH_PUB_KEY_64B))
			{
				//hash again
				sha256_api(PckHash, SHA256_LEN, bufSHA256);
				if (!ecdsa_verify(CRYPTO_CURVE_SECP256K1, bufSHA256, public_key, Sign))
				{
					emRet = ERT_IAP_fileDigest;
				}
			}
			else
			{
				emRet = ERT_IAP_FAIL;
			}
		}
		break;
	}
	default:
		break;
	}

	return emRet;
}
