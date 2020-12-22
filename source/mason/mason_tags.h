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
#ifndef MASON_TAGS_H
#define MASON_TAGS_H

/** Avoid duplicate definitions */
#ifdef MASON_TAGS_GLOBAL
#define MASON_TAGS_EXT
#else
#define MASON_TAGS_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h> //memcpy...

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#define TLV_T_CMD						0x0001
#define TLV_T_RESPONSE					0x0002
#define TLV_T_ERR_MSG					0x0003
#define TLV_T_MSG_TYPE					0x0004

#define TLV_T_ANDROID_STATUS			0x0101
#define TLV_T_FW_STATUS					0x0102
#define TLV_T_SY_FW_VER					0x0103
#define TLV_T_SY_ALG_VER				0x0104
#define TLV_T_BOOT_VER_NAME				0x0105
#define TLV_T_APP_VER_NAME				0x0106
#define TLV_T_FLASH_ADDR				0x0107
#define TLV_T_FLASH_DATA				0x0108
#define TLV_T_UPDATE_PACK				0x0109
#define TLV_T_UPDATE_PACK_TYPE			0x010A
#define TLV_T_UPDATE_PACK_CKM			0x010B
#define TLV_T_UPDATE_FILE_CKM			0x010C
#define TLV_T_COMPILE_TIME				0x010D
#define TLV_T_COMPILE_DATE				0x010E
#define TLV_T_APP_VER_CODE				0x010F
#define TLV_T_BOOT_VER_CODE				0x0110
#define TLV_T_SN						0x0111
#define TLV_T_TAMPER_CNT				0x0112
#define TLV_T_TAMPER_TIME_MAX			0x0113
#define TLV_T_POWERUP_CNT				0x0114
#define TLV_T_FW_UPDATE_CNT				0x0115
#define TLV_T_FW_NAME					0x0116
#define TLV_T_JUST_CHECK_VERSION        0x0117
#define TLV_T_BOOT_TYPE                 0x0118

#define TLV_T_JUMP_TO					0x01FF

#define TLV_T_ENTROPY_BITS				0x0201
#define TLV_T_ENTROPY					0x0202
#define TLV_T_MNEMONIC					0x0203
#define TLV_T_PASSPHRASE				0x0204
#define TLV_T_HDW_TYPE					0x0205
#define TLV_T_COIN_TYPE					0x0206
#define TLV_T_HD_PATH					0x0207
#define TLV_T_HDP_DEPTH					0x0208
#define TLV_T_ADDRESS					0x0209
#define TLV_T_EXT_KEY					0x020A
#define TLV_T_MASTER_KEY_FP				0x020B
#define TLV_T_SECURITY_SWITCH			0x020F
#define TLV_T_HDW_SWITCH			    0x0210
#define TLV_T_ACCOUNT   			    0x0211

#define TLV_T_DES_KEY					0x0301
#define TLV_T_PRVKEY					0x0302
#define TLV_T_PUBKEY					0x0303
#define TLV_T_CHAINCODE					0x0304
#define TLV_T_PLAIN_MSG					0x0305
#define TLV_T_ENCRYPT_MSG				0x0306
#define TLV_T_HASH						0x0307
#define TLV_T_SIGNATURE					0x0308
#define TLV_T_CHECKSUM					0x0309
#define TLV_T_DES_IV					0x030A
#define TLV_T_NEED_CKM					0x030B
#define TLV_T_PUBKEYC					0x030C
#define TLV_T_CURVE_TYPE                0x030D
#define TLV_T_NEXT_SIGN                 0x030E
#define TLV_T_HASH_FUNC                 0x030F

#define TLV_T_USRPWD_NEW                0x0401
#define TLV_T_USRPWD_CUR                0x0402
#define TLV_T_USRFING                   0x0403
#define TLV_T_TOKEN                     0x0404
#define TLV_T_RETURN_TOKEN              0x0405
#define TLV_T_MESSAGE                   0x0406
#define TLV_T_MESSAGE_SIGN              0x0407
#define TLV_T_SETTINGS_TYPE             0x0408
#define TLV_T_SETTINGS_VALUE            0x0409

#define TLV_T_WR_RD						0x0701	//0:write; non-0:read
#define TLV_T_UPDATE_KEY				0x0702

#define TLV_T_DEBUG_SWITCH				0x0800
#define TLV_T_COM_TEST_DATA				0x0801
#define TLV_T_MNEMONIC_LEN				0x0802
#define TLV_T_BIP39_SEED				0x0803
#define TLV_T_READ_DATA_LEN				0x0804
#define TLV_T_GPIO_STATUS				0x0805
#define TLV_T_GPIO_SET					0x0806
#define TLV_T_BIP32_SEED				0x0807
#define TLV_T_BIP32_KEY					0x0808
#define TLV_T_ACTIVE_TAMPER				0x0809
#define TLV_T_PASSIVE_TAMPER			0x080A
#define TLV_T_SLIP39_MASTER_SEED		0x080B
#define TLV_T_SLIP39_ID				    0x080C
#define TLV_T_SLIP39_EXPONENT			0x080D
#define TLV_T_ETH2_WITHDRAWAL_KEY		0x080E
#define TLV_T_ETH2_SIGN_KEY             0x080F

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
