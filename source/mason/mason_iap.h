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
#ifndef MASON_ISP_H
#define MASON_ISP_H

/** Avoid duplicate definitions */
#ifdef MASON_ISP_GLOBAL
#define MASON_ISP_EXT
#else
#define MASON_ISP_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h> //memcpy...
#include "mason_errno.h"
#include "mason_flash_partition.h"
#include "mason_storage.h"

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#define FLAG_MASK (0x8F3D945A) //just random value
#define ADD_MASK(X) (FLAG_MASK ^ (X))
#define OFF_MASK(X) (FLAG_MASK ^ (X))

#define FLAG_BOOT_ADDR1 ADD_MASK(FLASH_ADDR_BOOT1_START)
#define FLAG_BOOT_ADDR2 ADD_MASK(FLASH_ADDR_BOOT2_START)
#define FLAG_APP_EXIST ADD_MASK(0x3FF307FC) //just random value
#define FLAG_APP_NOT_EXIST (~FLAG_APP_EXIST)
#define FLAG_APP_UPGRADED ADD_MASK(0x2812A242) //just random value
#define FLAG_APP_NO_UPGRAD (~FLAG_APP_UPGRADED)

	/** Variable declarations */
	typedef enum
	{
		E_PACK_FIRST = 0x00,
		E_PACK_CONTINUE,
		E_PACK_LAST,
		E_PACK_HDR,
		E_PACK_ERR
	} emFwPackTypeType;
	//MASON_HDW_EXT volatile emFwPackTypeType emFwPackType;

	/** Function declarations */
	MASON_ISP_EXT bool mason_iap_check_app_exsit(void);
	MASON_ISP_EXT void mason_iap_run_app(void);
	MASON_ISP_EXT void mason_iap_run_boot(void);

	__inline emRetType
	mason_iap_set_app_not_exist(void)
	{
		return mason_storage_write_flag_safe(FLASH_ADDR_APP_EXIST_4B, FLAG_APP_NOT_EXIST);
	}

	__inline emRetType
	mason_iap_set_app_exist(void)
	{
		return mason_storage_write_flag_safe(FLASH_ADDR_APP_EXIST_4B, FLAG_APP_EXIST);
	}

	__inline emRetType
	mason_iap_set_app_upgraded(void)
	{
		return mason_storage_write_flag_safe(FLASH_ADDR_APP_UPGRADED_4B, FLAG_APP_UPGRADED);
	}

	__inline emRetType
	mason_iap_set_app_not_upgrade(void)
	{
		return mason_storage_write_flag_safe(FLASH_ADDR_APP_UPGRADED_4B, FLAG_APP_NOT_EXIST);
	}

	emRetType
	mason_iap_pack_verify_process(emFwPackTypeType emFwPackType, uint8_t *pBin, uint32_t binLen);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
