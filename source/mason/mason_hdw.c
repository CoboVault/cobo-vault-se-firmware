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
#define MASON_HDW_GLOBAL

/** Header file reference */
#include "mason_hdw.h"
#include "version_def.h"
#include "util.h"
#include "crypto_api.h"

/** Variable definitions */
MASON_HDW_EXT volatile emHDWStatusType gemHDWStatus = E_HDWS_CHIP;

MASON_HDW_EXT const volatile stHDWStatusType gstHDWStatus[] =
	{
		{E_HDWS_CHIP, "\xFF\xFF\xFF\xFF"},
		{E_HDWS_FACTORY, "FATY"},
		{E_HDWS_ATTACK, "ATAK"},
		{E_HDWS_EMPTY, "COBO"},
		{E_HDWS_WALLET, "WLET"},
};
MASON_HDW_EXT volatile uint8_t gDebugSwitchOn = 0;

MASON_HDW_EXT volatile emHDWSwitchType gemHDWSwitch = E_HDWM_MNEMONIC;

/** Function implementations */
/**
 * @functionname: mason_get_mode
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_get_mode(volatile stHDWStatusType *status)
{
	mason_storage_read((uint8_t *)status, sizeof(stHDWStatusType), FLASH_ADDR_CHIP_MODE_WITH_CHECKSUM_12B);

	if (status->emHDWStatus != E_HDWS_ATTACK && status->emHDWStatus != E_HDWS_EMPTY && status->emHDWStatus != E_HDWS_WALLET && status->emHDWStatus != E_HDWS_CHIP && status->emHDWStatus != E_HDWS_FACTORY)
	{
		*status = gstHDWStatus[HDW_STATUS_CHIP];
	}

	return true;
}
/**
 * @functionname: mason_set_mode
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_set_mode(uint8_t type)
{
	stHDWStatusType status;
	if (type >= HDW_STATUS_MAX)
	{
		return false;
	}
	status = gstHDWStatus[type];
	return mason_storage_write_buffer((uint8_t *)&status, sizeof(status), FLASH_ADDR_CHIP_MODE_WITH_CHECKSUM_12B);
}
/**
 * @functionname: mason_set_appvercode
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_set_appvercode(void)
{
	emRetType ret = ERT_OK;
	uint32_t vercode = 0;
	if (ERT_OK == mason_get_appvercode(&vercode))
	{
		if (vercode == VERSION_BCD)
		{
			return ERT_OK;
		}
	}

	if (ERT_OK != (ret = mason_storage_write_flag_safe(FLASH_ADDR_APP_VERCODE_4B, VERSION_BCD)))
	{
		return ret;
	}
	uint32_t verhash = 0;
	uint8_t bufVerCode[4] = {0x00};
	u32_to_buf(bufVerCode, VERSION_BCD);
	uint8_t sha256_buf[SHA256_LEN] = {0};
	sha256_api(bufVerCode, 4, sha256_buf);
	buf_to_u32(&verhash, sha256_buf);
	return mason_storage_write_flag_safe(FLASH_ADDR_APP_VERCODE_4B + 4, verhash);
}
/**
 * @functionname: mason_get_appvercode
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_get_appvercode(uint32_t *vercode)
{
	uint32_t vercodeflash = 0;
	vercodeflash = mason_storage_read_flag(FLASH_ADDR_APP_VERCODE_4B);

	uint32_t verhashflash = 0;
	verhashflash = mason_storage_read_flag(FLASH_ADDR_APP_VERCODE_4B + 4);

	uint8_t bufVerCode[4] = {0x00};
	u32_to_buf(bufVerCode, vercodeflash);

	uint8_t sha256_buf[SHA256_LEN] = {0};
	sha256_api(bufVerCode, 4, sha256_buf);

	uint32_t vercode_hash = 0;
	buf_to_u32(&vercode_hash, sha256_buf);

	if (vercode_hash != verhashflash)
	{
		return ERT_VerConflict;
	}

	*vercode = vercodeflash;
	return ERT_OK;
}
/**
* @functionname: mason_HDW_gen_sha256
* @description: 
* @para:
* @return:
*/
void mason_HDW_gen_sha256(uint8_t *pText, uint32_t textLen, uint8_t *pCheckSum, uint8_t checkSumLen)
{
	UINT8 bufSHA256[SHA256_LEN] = {0};

	sha256_api(pText, textLen, bufSHA256);

	if (checkSumLen > SHA256_LEN)
	{
		checkSumLen = SHA256_LEN;
	}
	memcpy(pCheckSum, bufSHA256, checkSumLen);
}

/**
* @functionname: mason_HDW_check_sha256
* @description: 
* @para:
* @return:
*/
bool mason_HDW_check_sha256(uint8_t *pText, uint32_t textLen, uint8_t *pCheckSum)
{
	uint8_t bufCheckSum[CHECKSUM_LEN];

	mason_HDW_gen_sha256(pText, textLen, bufCheckSum, CHECKSUM_LEN);

	if (0 != memcmp_ATA(pCheckSum, bufCheckSum, CHECKSUM_LEN))
	{
		memcpy(pCheckSum, bufCheckSum, CHECKSUM_LEN);
		return false;
	}

	return true;
}

/**
* @functionname: mason_HDW_gen_sha256sha256
* @description:  SHA256 twice
* @para:
* @return:
*/
void mason_HDW_gen_sha256sha256(uint8_t *pText, uint32_t textLen,
								uint8_t *pCheckSum, uint8_t checkSumLen)
{
	UINT8 bufSHA256[SHA256_LEN] = {0};

	sha256_api(pText, textLen, bufSHA256);
	sha256_api(bufSHA256, SHA256_LEN, bufSHA256);

	if (checkSumLen > SHA256_LEN)
	{
		checkSumLen = SHA256_LEN;
	}
	memcpy(pCheckSum, bufSHA256, checkSumLen);
}

/**
* @functionname: mason_HDW_check_sha256sha256
* @description: 
* @para: 
* @return: 
*/
bool mason_HDW_check_sha256sha256(uint8_t *pText, uint32_t textLen, uint8_t *pCheckSum)
{
	uint8_t bufCheckSum[CHECKSUM_LEN];

	mason_HDW_gen_sha256sha256(pText, textLen, bufCheckSum, CHECKSUM_LEN);

	if (0 != memcmp_ATA(pCheckSum, bufCheckSum, CHECKSUM_LEN))
	{
		memcpy(pCheckSum, bufCheckSum, CHECKSUM_LEN);
		return false;
	}

	return true;
}
