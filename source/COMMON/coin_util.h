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
#ifndef COIN_UTIL_H
#define COIN_UTIL_H

/** Avoid duplicate definitions */
#ifdef COIN_UTIL_GLOBAL
#define COIN_UTIL_EXT
#else
#define COIN_UTIL_EXT	extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>	//memcpy...

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif    /* __cplusplus */

/** Macro definitions*/
/** Base58 Check version prefix*/
#define B58_PREFIX_BTC_ADDR             (uint8_t*)"\x00"      //1
#define B58_PREFIX_BTC_P2SH_ADDR        (uint8_t*)"\x05"      //3
#define B58_PREFIX_BTC_TESTNET_ADDR     (uint8_t*)"\x6F"      //m or n
#define B58_PREFIX_PRIKEY_WIF           (uint8_t*)"\x80"      //5, K or L
#define B58_PREFIX_BIP38_ENC_PRIKEY     (uint8_t*)"\x01\x42"  //6P
#define B58_PREFIX_BIP32_EXT_PUBKEY     (uint8_t*)"\x04\x88\xB2\x1E"  //xpub
#define B58_SUFFIX_WIF_COMPRESSED		(uint8_t*)"\x01"

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
