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
#ifndef STONE_HDW_H
#define STONE_HDW_H

/** Avoid duplicate definitions */
#ifdef STONE_HDW_GLOBAL
#define STONE_HDW_EXT
#else
#define STONE_HDW_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h> //memcpy...
#include "mason_errno.h"
#include "mason_iap.h"

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#define PRV_KEY_LEN 32
#define PUB_KEY_LEN 64
#define SHA256_LEN 32
#define SHA512_LEN 64
#define RPMD160_LEN 20
#define HASH_LEN SHA256_LEN
#define MD5_LEN 16
#define SIG_LEN 64
#define CHECKSUM_LEN 4
#define SEED_LEN SHA512_LEN
#define DES3_KEY_LEN 24
#define DES3_IV_LEN 8

/* macro below mapped to gstHDWStatus value*/
#define HDW_STATUS_CHIP 0
#define HDW_STATUS_FACTORY 1
#define HDW_STATUS_ATTACK 2
#define HDW_STATUS_EMPTY 3
#define HDW_STATUS_WALLET 4
#define HDW_STATUS_MAX 5
#define HDW_STATUS_SYMBOL_CHIP (uint8_t *)("\xFF\xFF\xFF\xFF")
#define HDW_STATUS_SYMBOL_FACTORY (uint8_t *)("FATY")
#define HDW_STATUS_SYMBOL_ATTACK (uint8_t *)("ATAK")
#define HDW_STATUS_SYMBOL_EMPTY (uint8_t *)("COBO")
#define HDW_STATUS_SYMBOL_WALLET (uint8_t *)("WLET")
#define HDW_STATUS_SYMBOL_

	/** Variable definitions */
	STONE_HDW_EXT volatile uint8_t gDebugSwitchOn;
	typedef enum
	{
		E_HDWS_CHIP = 0x00,
		E_HDWS_FACTORY = 0xFA,
		E_HDWS_ATTACK = 0xA0,
		E_HDWS_EMPTY = 0xCB,
		E_HDWS_WALLET = 0x88,
		E_HDWS_BOOT = 0xB0,
		E_HDWS_UNKNOWN = 0xFF,
		E_HDWS_MAX = 0x7FFFFFFF
	} emHDWStatusType;
	STONE_HDW_EXT volatile emHDWStatusType gemHDWStatus;

	typedef struct
	{
		emHDWStatusType emHDWStatus;
		char pSymbol[4];
	} stHDWStatusType;
	STONE_HDW_EXT const volatile stHDWStatusType gstHDWStatus[];

	/** Function declarations */
	STONE_HDW_EXT emRetType mason_HDW_set_status(const volatile stHDWStatusType stHDWStatus);
	void mason_HDW_gen_sha256(uint8_t *pText, uint32_t textLen, uint8_t *pCheckSum, uint8_t checkSumLen);
	bool mason_HDW_check_sha256(uint8_t *pText, uint32_t textLen, uint8_t *pCheckSum);
	void mason_HDW_gen_sha256sha256(uint8_t *pText, uint32_t textLen, uint8_t *pCheckSum, uint8_t checkSumLen);
	bool mason_HDW_check_sha256sha256(uint8_t *pText, uint32_t textLen, uint8_t *pCheckSum);
	bool mason_get_mode(volatile stHDWStatusType *status);
	bool mason_set_mode(uint8_t type);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
