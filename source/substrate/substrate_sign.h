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
#ifndef SUBSTRATE_SIGN_H
#define SUBSTRATE_SIGN_H

#include "sr25519.h"
#include "mason_key.h"

#define SURI_DEPTH 10
#define MAX_SURI_PATH_LEN 120

typedef struct
{
    sr25519_chain_code cc;
    bool is_hard;
} suri_path_item_t;

typedef struct
{
    suri_path_item_t item[SURI_DEPTH];
    uint8_t depth;
} suri_path_t;

bool substrate_derive_extpubkey(uint8_t *suri, uint32_t suri_len, extended_key_t *extpublic);
bool substrate_sign(uint8_t *suri, uint32_t suri_len, uint8_t *message, uint32_t message_len,
                    sr25519_signature signature, uint16_t *sign_len, public_key_t *pubkey);
#endif
