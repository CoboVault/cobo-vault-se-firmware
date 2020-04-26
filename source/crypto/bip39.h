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
#ifndef BIP39_H
#define BIP39_H

/** Avoid duplicate definitions */
#ifdef BIP39_GLOBAL
#define BIP39_EXT
#else
#define BIP39_EXT	extern
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
#define PASSPHRASE_PREFIX		("mnemonic")					//BIP39

/** Function declarations */
void bip39_gen_seed_with_mnomonic(uint8_t *pMnemonic, uint32_t mnemonicLen, 
		uint8_t *pPassphrase, uint32_t passphraseLen, 
		uint8_t *pSeed, int32_t seedLen);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
