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
#ifndef MASON_FLASH_PARTTITION_H
#define MASON_FLASH_PARTTITION_H

/** Avoid duplicate definitions */
#ifdef MASON_FLASH_PARTTITION_GLOBAL
#define MASON_FLASH_PARTTITION_EXT
#else
#define MASON_FLASH_PARTTITION_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>	//memcpy...
#include "mason_errno.h"
#include "eflash.h"

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#ifndef FLASH_PAGE_SIZE
#define FLASH_PAGE_SIZE								PAGE_SIZE
#endif

#define FLASH_ADDR_START							EFLASH_BASE_ADDR
#define FLASH_ADDR_MAX								0x00040000
#define Reset_Handler_offset						0x00000004

#define OFFSET(X)									((X) - FLASH_ADDR_START)

#define FLASH_ADDR_SELECTOR_START					FLASH_ADDR_START
#define SELECTOR_SIZE								0x00000800
#define FLASH_ADDR_BOOT1_START						(FLASH_ADDR_SELECTOR_START+SELECTOR_SIZE)
#define BOOT1_SIZE									0x00009C00
#define FLASH_ADDR_BOOT2_START						(FLASH_ADDR_BOOT1_START+BOOT1_SIZE)
#define BOOT2_SIZE									0x00009C00
#define FLASH_ADDR_APP_START						(FLASH_ADDR_BOOT2_START+BOOT2_SIZE)
#define APP_SIZE									0x00024000
#define FLASH_ADDR_PARAM_START						(FLASH_ADDR_APP_START+APP_SIZE) // 0x38000
#define PARAM_SIZE									0x00008000
#define FLASH_ADDR_END								(FLASH_ADDR_PARAM_START+PARAM_SIZE)

#if FLASH_ADDR_END>FLASH_ADDR_MAX
#error "flash out of range!"
#endif

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
