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
#ifndef MASON_KEY_H_
#define MASON_KEY_H_

/** Header file reference */
#include <stdint.h>
#include <stdbool.h>
#include <mason_util.h>
#include <crypto_api.h>

/** Macro definitions*/
#define PRIVATE_KEY_LEN 32
#define PUBLIC_KEY_LEN 64
#define COMPRESSED_PUBLIC_KEY_LEN 33
#define CHAINCODE_LEN 32

/** Variable definitions */
enum key_version_e
{
    KEY_VERSION_MAINNET_PUBLIC = 0x0488B21E,
    KEY_VERSION_MAINNET_PRIVATE = 0x0488ADE4,
    KEY_VERSION_TESTNET_PUBLIC = 0x043587CF,
    KEY_VERSION_TESTNET_PRIVATE = 0x04358394
};

/*private key*/
typedef struct private_key_s
{
    uint8_t data[PRIVATE_KEY_LEN];
    uint16_t len;
} private_key_t;

/*public key*/
typedef struct public_key_s
{
    uint8_t data[PUBLIC_KEY_LEN];
    uint16_t len;
} public_key_t;

/* compressed pub key*/
typedef struct compressed_public_key_s
{
    uint8_t data[COMPRESSED_PUBLIC_KEY_LEN];
} compressed_public_key_t;

/* chain code*/
typedef struct chaincode_s
{
    uint8_t data[CHAINCODE_LEN];
} chaincode_t;

typedef struct extended_key_s
{
    uint8_t version[4];
    uint8_t depth;
    uint8_t fingerprint[4];
    uint8_t child_number[4];
    uint8_t chaincode[CHAINCODE_LEN];
    uint8_t key[COMPRESSED_PUBLIC_KEY_LEN];
    uint8_t checksum[4];
} __attribute__((packed)) extended_key_t;


/** Function declarations */
bool ckd_private_to_public(
    private_key_t *parent_private_key,
    chaincode_t *parent_chaincode,
    uint32_t index,
    public_key_t *child_public_key,
    chaincode_t *child_chaincode);

bool ckd_private_to_private(
    crypto_curve_t curve,
    private_key_t *parent_private_key,
    chaincode_t *parent_chaincode,
    uint32_t index,
    private_key_t *child_private_key,
    chaincode_t *child_chaincode);

void private_key_to_public_key(
    crypto_curve_t curve,
    private_key_t *private_key,
    public_key_t *public_key);

void public_key_to_compressed_public_key(
    public_key_t *public_key,
    compressed_public_key_t *compressed_public_key);

void private_key_to_compressed_public_key(
    crypto_curve_t curve,
    private_key_t *private_key,
    compressed_public_key_t *compressed_public_key);

void private_key_to_fingerprint(
    crypto_curve_t curve,
    private_key_t *private_key,
    uint8_t *fingerprint,
    uint16_t fingerprint_len);

#endif
