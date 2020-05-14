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
#define STONE_ISP_GLOBAL

/** Header file reference */
#include "mason_iap.h"
#include "common.h"
#include "mason_util.h"
#include "eflash.h"
#include "sha256.h"
#include "mason_hdw.h"
#include "crypto_api.h"

/** Function declarations */
typedef void (*funcptr)(void);

/** Function implementations */
/**
 * @functionname: set_vect_to
 * @description: 
 * @para: FLASH_ADDR_BOOT1_START, FLASH_ADDR_BOOT2_START, FLASH_ADDR_APP_START
 * @return: 
 */
__inline void set_vect_to(uint32_t addr)
{
	// uint32_t i = 0;

	// for (i = 0; i < 48; i++)
	// {
	//     *((uint32_t *)(0x68000000 + (i << 2))) = *(__IO uint32_t *)(addr + (i << 2));
	// }
	REG_MPUCR |= 0x1;
	REG_MPUVectorOffset = addr;
}
/**
 * @functionname: jump_to
 * @description: 
 * @para: 
 * @return: 
 */
static void jump_to(uint32_t addr)
{
	//REG_MPUCR |= 0x1;
	//REG_MPUVectorOffset = addr;

	_delay_ms(10);

	__set_MSP(*(UINT32 *)(addr));
	(*(funcptr) * (UINT32 *)(addr + Reset_Handler_offset))();
}
/**
 * @functionname: mason_iap_run
 * @description: 
 * @para: 
 * @return: 
 */
static void mason_iap_run(uint32_t addr)
{
	set_vect_to(addr);
	jump_to(addr);
}
/**
 * @functionname: mason_iap_run_app
 * @description: 
 * @para: 
 * @return: 
 */
STONE_ISP_EXT void mason_iap_run_app(void)
{
	mason_iap_run(FLASH_ADDR_APP_START);
}
/**
 * @functionname: mason_iap_run_boot
 * @description: 
 * @para: 
 * @return: 
 */
STONE_ISP_EXT void mason_iap_run_boot(void)
{
	mason_iap_run(OFF_MASK(eflash_read_word(FLASH_ADDR_BOOT_ADDR_4B)));
}
/**
 * @functionname: mason_iap_check_app_exsit
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_iap_check_app_exsit(void)
{
	return mason_storage_check_flag(FLASH_ADDR_APP_EXIST_4B, FLAG_APP_EXIST);
}
/**
 * @functionname: mason_iap_write_page_safe
 * @description: 
 * @para: 
 * @return: 
 */
int mason_iap_write_page_safe(uint32_t addr, uint8_t buf[], uint32_t bufLen)
{
	uint32_t i = 0;
	UINT32 data;
	UINT32 writeAddr = addr, readAddr = addr;
	uint8_t bufRead[PAGE_SIZE] = {0};

	if (addr % PAGE_SIZE)
	{
		return -1;
	}

	eflash_erase_page(addr);

	for (i = 0; i < bufLen; i += 4)
	{
		data = (buf[i + 3] << 24) | (buf[i + 2] << 16) | (buf[i + 1] << 8) | (buf[i]);
		eflash_write_word(writeAddr, data);
		writeAddr += 4;
	}

	for (i = 0; i < bufLen; i++)
	{
		bufRead[i] = eflash_read_byte(readAddr++);
	}

	if (memcmp_ATA(bufRead, buf, bufLen))
	{
		return -2;
	}

	return 0;
}
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
		SHA256_init(&sha256ctx);
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

		SHA256_update(&sha256ctx, pBin, binLen);
		break;
	}
	case E_PACK_HDR:
	{
		uint8_t bufSHA256[SHA256_LEN] = {0};
		SHA256_final(bufSHA256, &sha256ctx);

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
