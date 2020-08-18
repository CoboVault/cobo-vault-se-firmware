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
#include "sha256.h"
#include "mason_util.h"

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
 * @functionname: mason_HDW_set_status
 * @description: 
 * @para: 
 * @return: 
 */
MASON_HDW_EXT emRetType mason_HDW_set_status(const volatile stHDWStatusType stHDWStatus)
{
	emRetType emRet = ERT_OK;

	return emRet;
}
/**
 * @functionname: mason_get_mode
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_get_mode(volatile stHDWStatusType *status)
{
	mason_storage_read((uint8_t *)status, sizeof(stHDWStatusType), FLASH_ADDR_CHIP_MODE_WITH_CHECKSUM_12B);

	if (status->emHDWStatus != E_HDWS_ATTACK
		&& status->emHDWStatus != E_HDWS_EMPTY
		&& status->emHDWStatus != E_HDWS_WALLET
		&& status->emHDWStatus != E_HDWS_CHIP
		&& status->emHDWStatus != E_HDWS_FACTORY)
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
bool mason_set_appvercode(void)
{
	uint32_t vercode = VERSION_BCD;
	return mason_storage_write_buffer((uint8_t *)&vercode, sizeof(uint32_t), FLASH_ADDR_APP_VERCODE_4B);
}
/**
 * @functionname: mason_get_appvercode
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_get_appvercode(uint32_t *vercode)
{
	return mason_storage_read((uint8_t *)vercode, sizeof(uint32_t), FLASH_ADDR_APP_VERCODE_4B);
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

	SHA256_hash(pText, textLen, bufSHA256);

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

	SHA256_hash(pText, textLen, bufSHA256);
	SHA256_hash(bufSHA256, SHA256_LEN, bufSHA256);

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
