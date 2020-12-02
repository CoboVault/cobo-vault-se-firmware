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
#ifndef MASON_STORAGE_H
#define MASON_STORAGE_H

/** Avoid duplicate definitions */
#ifdef MASON_STORAGE_GLOBAL
#define MASON_STORAGE_EXT
#else
#define MASON_STORAGE_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mason_errno.h"
#include "mason_flash_partition.h"

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
// 0x38000 para area, program data -- 1 page
#define FLASH_ADDR_PARAM_BASE				FLASH_ADDR_PARAM_START
#define FLASH_ADDR_BOOT_ADDR_4B				FLASH_ADDR_PARAM_BASE
#define FLASH_ADDR_APP_EXIST_4B				(FLASH_ADDR_BOOT_ADDR_4B+4)
#define FLASH_ADDR_APP_UPGRADED_4B			(FLASH_ADDR_APP_EXIST_4B+4)
#define FLASH_ADDR_APP_TEST_4B      		(FLASH_ADDR_APP_UPGRADED_4B+4)

#define FLASH_ADDR_SN_LEN_4B                (FLASH_ADDR_APP_TEST_4B)
#define SN_LEN_SIZE                         4
#define FLASH_ADDR_SN_28B                   (FLASH_ADDR_SN_LEN_4B + SN_LEN_SIZE)
#define SN_SIZE                             28

#define FLASH_ADDR_ROOT_3DES_KEY_AND_IV_WITH_CHECKSUM_36B        (FLASH_ADDR_SN_28B + SN_SIZE)
#define ROOT_3DES_SIZE                                           36

#define FLASH_ADDR_CHIP_MODE_WITH_CHECKSUM_12B                   (FLASH_ADDR_ROOT_3DES_KEY_AND_IV_WITH_CHECKSUM_36B + ROOT_3DES_SIZE)
#define CHIP_MODE_SIZE                                           12

#define FLASH_ADDR_APP_VERCODE_4B           (FLASH_ADDR_CHIP_MODE_WITH_CHECKSUM_12B + CHIP_MODE_SIZE)
#define APP_VERCODE_SIZE                    16

// 0x38200 mnemonic, entropy -- 1 page
#define FLASH_ADDR_WALLET_START             (FLASH_ADDR_PARAM_START + PAGE_SIZE)
#define FLASH_ADDR_MNEMONIC                 (FLASH_ADDR_WALLET_START)
#define MNEMONIC_SIZE                       256

#define FLASH_ADDR_ENTROPY                  (FLASH_ADDR_MNEMONIC + MNEMONIC_SIZE)
#define ENTROPY_SIZE                        40

// 0x38400 seed, update-key, web-auth-keys -- 1 page
#define FLASH_ADDR_SEED_72B                 (FLASH_ADDR_MNEMONIC + PAGE_SIZE)
#define SEED_SIZE                           72

#define FLASH_ADDR_UPDATE_KEY_258B          (FLASH_ADDR_SEED_72B + SEED_SIZE)
#define UPDATE_KEY_SIZE                     258

#define FLASH_ADDR_WEB_AUTH_PRI_KEY_32B     (FLASH_ADDR_UPDATE_KEY_258B + UPDATE_KEY_SIZE+2)
#define WEB_AUTH_PRI_KEY_SIZE               32
#define FLASH_ADDR_WEB_AUTH_PUB_KEY_64B     (FLASH_ADDR_WEB_AUTH_PRI_KEY_32B + WEB_AUTH_PRI_KEY_SIZE)
#define WEB_AUTH_PUB_KEY_SIZE               64

// 0x38600 update-key-512B -- 1 page
#define FLASH_ADDR_UPDATE_KEY_512B          (FLASH_ADDR_SEED_72B + PAGE_SIZE)
#define UPDATE_KEY_512B_SIZE                PAGE_SIZE

// 0x38800 seedFromEntropy, slip39 seed, id, e -- 1 page
#define FLASH_ADDR_SEED_FROM_ENTROPY        (FLASH_ADDR_UPDATE_KEY_512B + PAGE_SIZE)
#define SEED_FROM_ENTROPY_SIZE              72

#define FLASH_ADDR_SLIP39_MASTER_SEED       (FLASH_ADDR_SEED_FROM_ENTROPY + SEED_FROM_ENTROPY_SIZE)
#define SLIP39_MASTER_SEED_SIZE             76

#define FLASH_ADDR_SLIP39_DEC_SEED          (FLASH_ADDR_SLIP39_MASTER_SEED + SLIP39_MASTER_SEED_SIZE)
#define SLIP39_DEC_SEED_SIZE                72

// 0x39200 usr data area
#define FLASH_ADDR_USRDATA_START            (FLASH_ADDR_PARAM_START + PAGE_SIZE*9)
#define FLASH_ADDR_USRPWD                   (FLASH_ADDR_USRDATA_START)
#define USRPWD_SIZE                         44

#define FLASH_ADDR_USRFING                  (FLASH_ADDR_USRPWD+USRPWD_SIZE)
#define USRFING_SIZE                        76

#define FLASH_ADDR_USRPWD_COUNT             (FLASH_ADDR_USRFING+USRFING_SIZE)
#define USRPWD_COUNT_SIZE                   12

#define FLASH_ADDR_USRSETTINGS              (FLASH_ADDR_USRPWD_COUNT+USRPWD_COUNT_SIZE)
#define USRSETTINGS_SIZE                    44

#define FLASH_ADDR_PU_CNT_4B				(FLASH_ADDR_MAX-4)

    /** Function declarations */
    MASON_STORAGE_EXT emRetType mason_storage_encryption(uint8_t nType, uint8_t *pIn, uint16_t len, uint8_t *pOut);
    MASON_STORAGE_EXT emRetType mason_storage_read(uint8_t *pBuf, uint32_t bufLen, uint32_t addr);
    MASON_STORAGE_EXT uint32_t
    mason_storage_read_flag(uint32_t addr);
    MASON_STORAGE_EXT emRetType
    mason_storage_write_flag(uint32_t addr, uint32_t u32Flag);
    MASON_STORAGE_EXT emRetType
    mason_storage_write_flag_safe(uint32_t addr, uint32_t u32Flag);
    MASON_STORAGE_EXT bool
    mason_storage_check_flag(uint32_t addr, uint32_t u32Flag);

    bool mason_storage_write_buffer(uint8_t *buffer, uint32_t len, uint32_t addr);
    bool mason_storage_write_buffer_in_one_page(uint8_t *buffer, uint32_t len, uint32_t addr);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
