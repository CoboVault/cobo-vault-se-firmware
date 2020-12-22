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
#ifndef MASON_WALLET_H
#define MASON_WALLET_H

/** Header file reference */
#include <stdint.h>
#include <stdbool.h>
#include <mason_key.h>
#include <mason_errno.h>
#include <crypto_api.h>

/** Variable declarations */
enum SupportEntropyBits
{
    Entropy128Bits = 128,
    Entropy192Bits = 192,
    Entropy224Bits = 224,
    Entropy256Bits = 256
};

#define MAX_MNEMONIC_SIZE 240
#define MAX_ENTROPY_SIZE 32
#define MAX_HDPATH_SIZE 121
#define MAX_PASSPHRASE_SIZE (128 * 4)
#define MAX_SLIP39_SEED_SIZE 32

typedef struct mnemonic_s
{
    uint32_t size;
    uint8_t data[MAX_MNEMONIC_SIZE];
} mnemonic_t;

typedef struct entropy_s
{
    uint32_t size;
    uint8_t data[MAX_ENTROPY_SIZE];
} entropy_t;

typedef struct wallet_seed_s
{
    uint32_t length;
    uint8_t data[SHA512_LEN];
} wallet_seed_t;

typedef struct wallet_slip39_master_seed_s
{
    uint32_t data_size;
    uint8_t data[SHA512_LEN];
    uint16_t id;
    uint16_t e;
} wallet_slip39_master_seed_t;

#define MAX_WALLET_SEGMENTS 10

typedef struct wallet_path_s
{
    uint32_t version;
    uint32_t segments[MAX_WALLET_SEGMENTS];
    uint8_t num_of_segments;
} wallet_path_t;

#define MAX_UPDATE_KEY_LEN 510

typedef struct update_key_s
{
    uint16_t len;
    uint8_t key[MAX_UPDATE_KEY_LEN];
} update_key_t;

extern wallet_seed_t passphrase_seedFromEntropy;
extern wallet_seed_t passphrase_slip39_seed;
/** Function declarations */
bool mason_generate_entropy(uint8_t *output_entropy, uint16_t bits, bool need_checksum);
bool mason_create_bip39_wallet(uint8_t *mnemonic, uint16_t mnemonic_len, uint8_t *entropy, uint16_t entropy_len);
bool mason_create_slip39_wallet(uint8_t *slip39_seed_data, uint16_t slip39_seed_len, uint16_t slip39_id, uint8_t slip39_e);
bool mason_change_wallet_passphrase(uint8_t *passphrase, uint16_t passphrase_len);
bool mason_delete_wallet(void);

bool mason_seedFromEntropy_read(wallet_seed_t *seed);
bool mason_slip39_master_seed_read(wallet_slip39_master_seed_t *seed);
bool mason_slip39_dec_seed_read(wallet_seed_t *seed);

bool mason_update_key_load(update_key_t *update_key);
bool mason_update_key_save(const update_key_t *update_key);
bool mason_wallet_path_is_pub(char *string, uint16_t len);
bool mason_wallet_path_is_priv(char *string, uint16_t len);
bool mason_parse_wallet_path_from_string(char *string, uint16_t len, wallet_path_t *wallet_path);

bool mason_valid_wallet_path(wallet_path_t *wallet_path);

emRetType mason_verify_mnemonic(char *mnemonic_str, uint16_t len);
emRetType mason_verify_slip39_seed(uint8_t *slip39_seed_data, uint16_t slip39_seed_len, uint16_t slip39_id);

bool mason_bip32_generate_master_key_from_root_seed(
    crypto_curve_t curve_type,
    private_key_t *private_key,
    chaincode_t *chaincode);

bool mason_bip32_derive_keys(
    wallet_path_t *wallet_path,
    crypto_curve_t curve,
    private_key_t *private_key,
    chaincode_t *chaincode,
    extended_key_t *extended_key);

bool mason_bip32_derive_master_key_fingerprint(crypto_curve_t curve, uint8_t *fingerprint, uint16_t fingerprint_len);

bool mason_eth2_derive_deposit_SK(uint32_t account, private_key_t *withdrawal_key, private_key_t *sign_key);
#endif
