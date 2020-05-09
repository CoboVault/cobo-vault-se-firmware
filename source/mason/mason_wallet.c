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
#include <mason_wallet.h>
#include <hrng.h>
#include <stdint.h>
#include <sha256.h>
#include <crypto_api.h>
#include <bip39.h>
#include <mason_storage.h>
#include <string.h>
#include <stdio.h>
#include <bip44.h>
#include <secp256.h>

/** Function implementations */
/**
 * @functionname: is_entropy_bits_support
 * @description: 
 * @para: 
 * @return: 
 */
bool is_entropy_bits_support(uint16_t bits)
{
    return (bits == Entropy128Bits) 
        || (bits == Entropy192Bits) 
        || (bits == Entropy224Bits) 
        || (bits == Entropy256Bits);
}
/**
 * @functionname: mason_generate_entropy
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_generate_entropy(uint8_t *output_entropy, uint16_t bits, bool need_checksum)
{
    uint16_t bytes = bits >> 3;
    int i = 0;
    uint8_t sha256_buf[32] = {0x00};

    if (!is_entropy_bits_support(bits))
    {
        return false;
    }

    hrng_initial();
    for (i = 0; i < bytes; i++)
    {
        output_entropy[i] = get_hrng8();
    }

    if (!need_checksum)
    {
        return true;
    }

    SHA256_hash(output_entropy, bytes, sha256_buf);

    output_entropy[bytes] = sha256_buf[0];

    return true;
}
/**
 * @functionname: mason_create_wallet
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_create_wallet(uint8_t *mnemonic, uint16_t mnemonic_len)
{
    mnemonic_t mnemonic_data;
    bool is_succeed = false;

    if ((0 == mnemonic_len) || (mnemonic_len > MAX_MNEMONIC_SIZE))
    {
        return false;
    }

    mnemonic_data.size = mnemonic_len;
    memcpy(mnemonic_data.data, mnemonic, mnemonic_len);

    is_succeed = mason_wallet_setup(&mnemonic_data, NULL, 0);

    if (!is_succeed)
    {
        return false;
    }

    return mason_mnemonic_write(&mnemonic_data);
}
/**
 * @functionname: mason_mnemonic_read
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_mnemonic_read(mnemonic_t *mnemonic)
{
    if (ERT_OK != mason_storage_read((void *)mnemonic, sizeof(mnemonic_t), FLASH_ADDR_MNOMONIC_512B))
    {
        return false;
    }

    if (mnemonic->size > sizeof(mnemonic->data))
    {
        return false;
    }

    return true;
}
/**
 * @functionname: mason_mnemonic_write
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_mnemonic_write(mnemonic_t *mnemonic)
{
    bool is_succeed = false;
    is_succeed = mason_storage_write_buffer((uint8_t *)mnemonic, sizeof(*mnemonic), FLASH_ADDR_MNOMONIC_512B);
    return is_succeed;
}
/**
 * @functionname: mason_seed_read
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_seed_read(wallet_seed_t *seed)
{
    bool is_succeed = false;
    is_succeed = (ERT_OK == mason_storage_read((uint8_t *)seed, sizeof(wallet_seed_t), FLASH_ADDR_SEED_72B));
    return is_succeed;
}
/**
 * @functionname: mason_seed_write
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_seed_write(wallet_seed_t *seed)
{
    bool is_succeed = false;
    is_succeed = mason_storage_write_buffer((uint8_t *)seed, sizeof(wallet_seed_t), FLASH_ADDR_SEED_72B);
    return is_succeed;
}
/**
 * @functionname: mason_change_wallet_passphrase
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_change_wallet_passphrase(uint8_t *passphrase, uint16_t passphrase_len)
{
    mnemonic_t mnemonic;

    if (passphrase_len > MAX_PASSPHRASE_SIZE)
    {
        return false;
    }

    if (!mason_mnemonic_read(&mnemonic))
    {
        return false;
    }

    return mason_wallet_setup(&mnemonic, passphrase, passphrase_len);
}
/**
 * @functionname: mason_wallet_setup
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_wallet_setup(mnemonic_t *mnemonic, uint8_t *passphrase, uint16_t passphrase_len)
{
    bool is_succeed = false;
    wallet_seed_t seed;
    bip39_gen_seed_with_mnomonic(mnemonic->data, mnemonic->size, passphrase, passphrase_len, seed.data, SHA512_LEN);
    seed.length = SHA512_LEN;
    is_succeed = mason_seed_write(&seed);
    return is_succeed;
}
/**
 * @functionname: mason_delete_wallet
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_delete_wallet(void)
{
    uint8_t seed_buf[SHA512_LEN] = {0x00};
    mnemonic_t mnemonic_data;
    bool is_succeed = false;

    mnemonic_data.size = 0x00;
    memset(mnemonic_data.data, 0, MAX_MNEMONIC_SIZE);

    is_succeed = mason_storage_write_buffer((uint8_t *)&mnemonic_data, sizeof(mnemonic_data), FLASH_ADDR_MNOMONIC_512B);

    if (!is_succeed)
    {
        return false;
    }

    is_succeed = mason_storage_write_buffer(seed_buf, SHA512_LEN, FLASH_ADDR_SEED_72B);
    return is_succeed;
}
/**
 * @functionname: mason_update_key_load
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_update_key_load(update_key_t *update_key)
{
    bool is_succeed = false;
    emRetType emRet = ERT_OK;

    emRet = mason_storage_read((uint8_t *)update_key, sizeof(update_key_t), FLASH_ADDR_UPDATE_KEY_512B);
    is_succeed = (emRet == ERT_OK) && update_key->len < MAX_UPDATE_KEY_LEN;
    return is_succeed;
}
/**
 * @functionname: mason_update_key_save
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_update_key_save(const update_key_t *update_key)
{
    bool is_succeed = false;
    is_succeed = mason_storage_write_buffer((uint8_t *)update_key, sizeof(update_key_t), FLASH_ADDR_UPDATE_KEY_512B);
    return is_succeed;
}
/**
 * @functionname: mason_parse_wallet_path_from_string
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_parse_wallet_path_from_string(char *string, uint16_t len, wallet_path_t *wallet_path)
{
    stHDPathType hd_path;
    bool is_succeed = false;
    int i = 0;

    if (len > (MAX_HDPATH_SIZE + 1))
    {
        return false;
    }

    is_succeed = bip44_str_to_hdpath((uint8_t *)string, len, &hd_path);

    if (!is_succeed)
    {
        return false;
    }

    wallet_path->version = hd_path.verBytes;

    wallet_path->num_of_segments = hd_path.depth;
    for (i = 0; i < wallet_path->num_of_segments; i++)
    {
        wallet_path->segments[i] = hd_path.value[i];
    }
    return true;
}
/**
 * @functionname: mason_valid_wallet_path
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_valid_wallet_path(wallet_path_t *wallet_path)
{
    if (wallet_path->segments[0] < 0x80000000)
    {
        return false;
    }

    if (wallet_path->segments[1] < 0x80000000)
    {
        return false;
    }

    if (wallet_path->segments[2] < 0x80000000)
    {
        return false;
    }

    if (wallet_path->num_of_segments < 3)
    {
        return false;
    }

    return true;
}
/**
 * @functionname: mason_verify_menonic
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_verify_menonic(char *menonic_str, uint16_t len)
{
    mnemonic_t menonic;
    bool is_succeed = false;
    is_succeed = (mason_storage_read((uint8_t *)&menonic, sizeof(menonic), FLASH_ADDR_MNOMONIC_512B) == ERT_OK);
    if (!is_succeed)
    {
        return false;
    }

    if (len != menonic.size)
    {
        return false;
    }

    if (memcmp_ATA((uint8_t *)menonic_str, menonic.data, len))
    {
        return false;
    }

    return true;
}
/**
 * @functionname: mason_bip32_generate_master_key_from_root_seed
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_bip32_generate_master_key_from_root_seed(
    crypto_curve_t curve_type,
    private_key_t *private_key,
    chaincode_t *chaincode)
{
    uint8_t hash[SHA512_LEN];
    uint8_t secp256k1_key[] = "Bitcoin seed";
    uint8_t secp256r1_key[] = "Nist256p1 seed";
    uint8_t ed25519_key[] = "ed25519 seed";
    uint16_t key_len;
    uint8_t *key;
    wallet_seed_t seed;

    switch (curve_type)
    {
    case CRYPTO_CURVE_SECP256R1:
        key = secp256r1_key;
        break;
    case CRYPTO_CURVE_ED25519:
        key = ed25519_key;
        break;
    case CRYPTO_CURVE_SECP256K1:
        key = secp256k1_key;
        break;
    default:
        return false;
    }

    key_len = strlen((char *)key);

    if (!mason_seed_read(&seed))
    {
        return false;
    }

    while (true)
    {
        hmac_sha512_api(seed.data, seed.length, key, key_len, hash);
        memcpy(private_key->data, hash, PRIVATE_KEY_LEN);
        memcpy(chaincode->data, hash + PRIVATE_KEY_LEN, CHAINCODE_LEN);

        if (is_valid_private_key(curve_type, private_key->data))
        {
            break;
        }
        else
        {
            memcpy(seed.data, hash, SHA512_LEN);
            seed.length = SHA512_LEN;
        }
    }

    return true;
}
/**
 * @functionname: sha256sha256
 * @description: 
 * @para: 
 * @return: 
 */
static void sha256sha256(uint8_t *data, size_t len, uint8_t *digest)
{
    uint8_t checksum[SHA256_LEN];
    sha256_api(data, len, checksum);
    sha256_api(checksum, SHA256_LEN, digest);
}
/**
 * @functionname: mason_bip32_derive_keys
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_bip32_derive_keys(
    wallet_path_t *wallet_path,
    crypto_curve_t curve,
    private_key_t *private_key,
    chaincode_t *chaincode,
    extended_key_t *extended_key)
{
    private_key_t parent_private_key;
    chaincode_t parent_chaincode;
    private_key_t child_private_key;
    public_key_t child_public_key;
    chaincode_t child_chaincode;
    compressed_public_key_t child_compressed_public_key;
    uint8_t fingerprint[4] = {0x00};
    uint8_t checksum[SHA256_LEN];
    uint8_t i = 0;

    memset(extended_key->fingerprint, 0x00, 4);

    if (!mason_bip32_generate_master_key_from_root_seed(
            curve,
            &parent_private_key,
            &parent_chaincode))
    {
        return false;
    }
    /*
    debug_key("MASTER_PRIVATE_KEY", parent_private_key.data, PRIVATE_KEY_LEN);
    debug_key("MASTER_CHAINCODE", parent_chaincode.data, CHAINCODE_LEN);
    */

    for (i = 0; i < wallet_path->num_of_segments; i++)
    {
        private_key_to_fingerprint(curve, &parent_private_key, fingerprint, sizeof(fingerprint));
        ckd_private_to_private(
            curve,
            &parent_private_key,
            &parent_chaincode,
            wallet_path->segments[i],
            &child_private_key,
            &child_chaincode);

        private_key_to_public_key(curve, &child_private_key, &child_public_key);
        parent_private_key = child_private_key;
        parent_chaincode = child_chaincode;
        /*
        printf("Derived %d ------\n", i);
        debug_key("PRIVATE_KEY", child_private_key.data, PRIVATE_KEY_LEN);
        debug_key("CHAINCODE", child_chaincode.data, CHAINCODE_LEN);
        debug_key("DERIVED_PUBLIC_KEY", child_public_key.data, PUBLIC_KEY_LEN);
        debug_key("Fingerprint", fingerprint, 4);
        */
    }

    *private_key = child_private_key;
    *chaincode = child_chaincode;

    u32_to_buf(extended_key->version, wallet_path->version);
    extended_key->depth = wallet_path->num_of_segments;
    memcpy(extended_key->fingerprint, fingerprint, sizeof(fingerprint));
    u32_to_buf(extended_key->child_number, wallet_path->segments[wallet_path->num_of_segments - 1]);
    memcpy(extended_key->chaincode, chaincode, CHAINCODE_LEN);
    if (wallet_path->version == KEY_VERSION_MAINNET_PUBLIC 
     || wallet_path->version == KEY_VERSION_TESTNET_PUBLIC)
    {
        private_key_to_compressed_public_key(curve, &child_private_key, &child_compressed_public_key);
        memcpy(extended_key->key, child_compressed_public_key.data, COMPRESSED_PUBLIC_KEY_LEN);
    }
    else
    {
        extended_key->key[0] = 0x00;
        memcpy(extended_key->key + 1, child_private_key.data, PRIVATE_KEY_LEN);
    }

    sha256sha256((uint8_t *)extended_key, sizeof(extended_key_t) - sizeof(extended_key->checksum), checksum);
    memcpy(extended_key->checksum, checksum, 4);

    return true;
}
