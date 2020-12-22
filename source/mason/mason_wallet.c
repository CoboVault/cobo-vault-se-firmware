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
#include <crypto_api.h>
#include <bip39.h>
#include <mason_storage.h>
#include <string.h>
#include <stdio.h>
#include <bip44.h>
#include <secp256.h>
#include <mason_hdw.h>
#include <slip39_encrypt.h>
#include "eip2333.h"
#include "util.h"

/** Variable definitions */
wallet_seed_t passphrase_seed = {0};
wallet_seed_t passphrase_seedFromEntropy = {0};
wallet_seed_t passphrase_slip39_seed = {0};

/** Function declarations */
static bool mason_wallet_setup(mnemonic_t *mnemonic, entropy_t *entropy, uint8_t *passphrase, uint16_t passphrase_len, wallet_seed_t *seed, wallet_seed_t *seedFromEntropy);
static bool mason_mnemonic_read(mnemonic_t *mnemonic);
static bool mason_mnemonic_write(mnemonic_t *mnemonic);
static bool mason_entropy_read(entropy_t *entropy);
static bool mason_entropy_write(entropy_t *entropy);
static bool mason_seed_read(wallet_seed_t *seed);
static bool mason_seed_write(wallet_seed_t *seed);
bool mason_seedFromEntropy_read(wallet_seed_t *seed);
static bool mason_seedFromEntropy_write(wallet_seed_t *seed);

/** Function implementations */
/**
 * @functionname: is_entropy_bits_support
 * @description: 
 * @para: 
 * @return: 
 */
bool is_entropy_bits_support(uint16_t bits)
{
    return (bits == Entropy128Bits) || (bits == Entropy192Bits) || (bits == Entropy224Bits) || (bits == Entropy256Bits);
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

    sha256_api(output_entropy, bytes, sha256_buf);

    output_entropy[bytes] = sha256_buf[0];

    return true;
}
/**
 * @functionname: mason_mnemonic_read
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_mnemonic_read(mnemonic_t *mnemonic)
{
    if (ERT_OK != mason_storage_read((void *)mnemonic, sizeof(mnemonic_t), FLASH_ADDR_MNEMONIC))
    {
        return false;
    }

    if ((0 == mnemonic->size) || (mnemonic->size > sizeof(mnemonic->data)))
    {
        memset(mnemonic, 0, sizeof(mnemonic_t));
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
static bool mason_mnemonic_write(mnemonic_t *mnemonic)
{
    bool is_succeed = false;
    is_succeed = mason_storage_write_buffer((uint8_t *)mnemonic, sizeof(mnemonic_t), FLASH_ADDR_MNEMONIC);
    return is_succeed;
}
/**
 * @functionname: mason_entropy_read
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_entropy_read(entropy_t *entropy)
{
    if (ERT_OK != mason_storage_read((void *)entropy, sizeof(entropy_t), FLASH_ADDR_ENTROPY))
    {
        return false;
    }

    if ((0 == entropy->size) || (entropy->size > sizeof(entropy->data)))
    {
        memset(entropy, 0, sizeof(entropy_t));
        return false;
    }

    return true;
}
/**
 * @functionname: mason_entropy_write
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_entropy_write(entropy_t *entropy)
{
    bool is_succeed = false;
    is_succeed = mason_storage_write_buffer((uint8_t *)entropy, sizeof(entropy_t), FLASH_ADDR_ENTROPY);
    return is_succeed;
}
/**
 * @functionname: mason_seed_read
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_seed_read(wallet_seed_t *seed)
{
    if (ERT_OK != mason_storage_read((uint8_t *)seed, sizeof(wallet_seed_t), FLASH_ADDR_SEED_72B))
    {
        return false;
    }

    if ((0 == seed->length) || (seed->length > sizeof(seed->data)))
    {
        memset(seed, 0, sizeof(wallet_seed_t));
        return false;
    }

    return true;
}
/**
 * @functionname: mason_seed_write
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_seed_write(wallet_seed_t *seed)
{
    bool is_succeed = false;
    is_succeed = mason_storage_write_buffer((uint8_t *)seed, sizeof(wallet_seed_t), FLASH_ADDR_SEED_72B);
    return is_succeed;
}
/**
 * @functionname: mason_seedFromEntropy_read
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_seedFromEntropy_read(wallet_seed_t *seed)
{
    if (ERT_OK != mason_storage_read((uint8_t *)seed, sizeof(wallet_seed_t), FLASH_ADDR_SEED_FROM_ENTROPY))
    {
        return false;
    }

    if ((0 == seed->length) || (seed->length > sizeof(seed->data)))
    {
        memset(seed, 0, sizeof(wallet_seed_t));
        return false;
    }

    return true;
}
/**
 * @functionname: mason_seedFromEntropy_write
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_seedFromEntropy_write(wallet_seed_t *seed)
{
    bool is_succeed = false;
    is_succeed = mason_storage_write_buffer((uint8_t *)seed, sizeof(wallet_seed_t), FLASH_ADDR_SEED_FROM_ENTROPY);
    return is_succeed;
}
/**
 * @functionname: mason_slip39_master_seed_read
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_slip39_master_seed_read(wallet_slip39_master_seed_t *seed)
{
    if (ERT_OK != mason_storage_read((uint8_t *)seed, sizeof(wallet_slip39_master_seed_t), FLASH_ADDR_SLIP39_MASTER_SEED))
    {
        return false;
    }

    if ((0 == seed->data_size) || (seed->data_size > sizeof(seed->data)))
    {
        memset(seed, 0, sizeof(wallet_slip39_master_seed_t));
        return false;
    }

    return true;
}
/**
 * @functionname: mason_slip39_master_seed_write
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_slip39_master_seed_write(wallet_slip39_master_seed_t *seed)
{
    bool is_succeed = false;
    is_succeed = mason_storage_write_buffer((uint8_t *)seed, sizeof(wallet_slip39_master_seed_t), FLASH_ADDR_SLIP39_MASTER_SEED);
    return is_succeed;
}
/**
 * @functionname: mason_slip39_dec_seed_read
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_slip39_dec_seed_read(wallet_seed_t *seed)
{
    if (ERT_OK != mason_storage_read((uint8_t *)seed, sizeof(wallet_seed_t), FLASH_ADDR_SLIP39_DEC_SEED))
    {
        return false;
    }

    if ((0 == seed->length) || (seed->length > sizeof(seed->data)))
    {
        memset(seed, 0, sizeof(wallet_seed_t));
        return false;
    }

    return true;
}
/**
 * @functionname: mason_slip39_dec_seed_write
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_slip39_dec_seed_write(wallet_seed_t *seed)
{
    bool is_succeed = false;
    is_succeed = mason_storage_write_buffer((uint8_t *)seed, sizeof(wallet_seed_t), FLASH_ADDR_SLIP39_DEC_SEED);
    return is_succeed;
}
/**
 * @functionname: mason_create_bip39_wallet
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_create_bip39_wallet(uint8_t *mnemonic, uint16_t mnemonic_len, uint8_t *entropy, uint16_t entropy_len)
{
    mnemonic_t mnemonic_data = {0};
    entropy_t entropy_data = {0};
    wallet_seed_t seed = {0};
    wallet_seed_t seedFromEntropy = {0};
    wallet_slip39_master_seed_t slip39_m_seed = {0};
    wallet_seed_t slip39_d_seed = {0};
    bool is_succeed = false;

    if ((0 == mnemonic_len) || (mnemonic_len > MAX_MNEMONIC_SIZE))
    {
        return false;
    }
    if ((0 == entropy_len) || (entropy_len > MAX_ENTROPY_SIZE) || !is_entropy_bits_support(entropy_len << 3))
    {
        return false;
    }

    mnemonic_data.size = mnemonic_len;
    memcpy(mnemonic_data.data, mnemonic, mnemonic_len);

    entropy_data.size = entropy_len;
    memcpy(entropy_data.data, entropy, entropy_len);

    do
    {
        is_succeed = mason_wallet_setup(&mnemonic_data, &entropy_data, NULL, 0, &seed, &seedFromEntropy);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_seed_write(&seed);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_seedFromEntropy_write(&seedFromEntropy);
        if (!is_succeed)
        {
            break;
        }

        memset(&passphrase_seed, 0, sizeof(wallet_seed_t));
        memset(&passphrase_seedFromEntropy, 0, sizeof(wallet_seed_t));
        memset(&passphrase_slip39_seed, 0, sizeof(wallet_seed_t));
        gemHDWSwitch = E_HDWM_MNEMONIC;

        is_succeed = mason_mnemonic_write(&mnemonic_data);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_entropy_write(&entropy_data);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_slip39_master_seed_write(&slip39_m_seed);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_slip39_dec_seed_write(&slip39_d_seed);
        if (!is_succeed)
        {
            break;
        }
    } while (0);

    memset(&seed, 0, sizeof(wallet_seed_t));
    memset(&seedFromEntropy, 0, sizeof(wallet_seed_t));
    memset(&mnemonic_data, 0, sizeof(mnemonic_t));
    memset(&entropy_data, 0, sizeof(entropy_t));
    return is_succeed;
}
/**
 * @functionname: mason_create_slip39_wallet
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_create_slip39_wallet(uint8_t *slip39_seed_data, uint16_t slip39_seed_len, uint16_t slip39_id, uint8_t slip39_e)
{
    mnemonic_t mnemonic_data = {0};
    entropy_t entropy_data = {0};
    wallet_seed_t seed = {0};
    wallet_seed_t seedFromEntropy = {0};
    wallet_slip39_master_seed_t slip39_m_seed = {0};
    wallet_seed_t slip39_d_seed = {0};
    bool is_succeed = false;

    if ((0 == slip39_seed_len) || (slip39_seed_len > MAX_SLIP39_SEED_SIZE))
    {
        return false;
    }
    memcpy(slip39_m_seed.data, slip39_seed_data, slip39_seed_len);
    slip39_m_seed.e = slip39_e;
    slip39_m_seed.id = slip39_id;
    slip39_m_seed.data_size = slip39_seed_len;

    //decrypt get slip39_dec_seed
    slip39_decrypt(slip39_seed_data, slip39_seed_len, NULL, slip39_e, slip39_id, slip39_d_seed.data);
    slip39_d_seed.length = slip39_seed_len;

    do
    {
        is_succeed = mason_slip39_master_seed_write(&slip39_m_seed);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_slip39_dec_seed_write(&slip39_d_seed);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_seed_write(&seed);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_seedFromEntropy_write(&seedFromEntropy);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_mnemonic_write(&mnemonic_data);
        if (!is_succeed)
        {
            break;
        }

        is_succeed = mason_entropy_write(&entropy_data);
        if (!is_succeed)
        {
            break;
        }

        memset(&passphrase_seed, 0, sizeof(wallet_seed_t));
        memset(&passphrase_seedFromEntropy, 0, sizeof(wallet_seed_t));
        memset(&passphrase_slip39_seed, 0, sizeof(wallet_seed_t));
        gemHDWSwitch = E_HDWM_MNEMONIC;
    } while (0);

    memset(&slip39_m_seed, 0, sizeof(wallet_slip39_master_seed_t));
    memset(&slip39_d_seed, 0, sizeof(wallet_seed_t));
    return is_succeed;
}
/**
 * @functionname: mason_change_bip39_wallet_passphrase
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_change_bip39_wallet_passphrase(uint8_t *passphrase, uint16_t passphrase_len)
{
    bool is_succeed = false;
    mnemonic_t mnemonic = {0};
    entropy_t entropy = {0};
    wallet_seed_t seed = {0};
    wallet_seed_t seedFromEntropy = {0};
    wallet_slip39_master_seed_t slip39_m_seed = {0};
    wallet_seed_t slip39_d_seed = {0};

    if (passphrase_len > MAX_PASSPHRASE_SIZE)
    {
        return false;
    }

    do
    {
        is_succeed = mason_mnemonic_read(&mnemonic);
        if (!is_succeed)
        {
            break;
        }

        if (mason_entropy_read(&entropy) && is_entropy_bits_support(entropy.size << 3))
        {
            is_succeed = mason_wallet_setup(&mnemonic, &entropy, passphrase, passphrase_len, &seed, &seedFromEntropy);
        }
        else
        {
            is_succeed = mason_wallet_setup(&mnemonic, NULL, passphrase, passphrase_len, &seed, NULL);
        }

        if (!is_succeed)
        {
            break;
        }

        if (0 == passphrase_len || NULL == passphrase)
        {
            is_succeed = mason_seed_write(&seed);
            if (!is_succeed)
            {
                break;
            }

            mason_seedFromEntropy_write(&seedFromEntropy);

            memset(&passphrase_seed, 0, sizeof(wallet_seed_t));
            memset(&passphrase_seedFromEntropy, 0, sizeof(wallet_seed_t));
            gemHDWSwitch = E_HDWM_MNEMONIC;
        }
        else
        {
            memcpy(&passphrase_seed, &seed, sizeof(wallet_seed_t));
            memcpy(&passphrase_seedFromEntropy, &seedFromEntropy, sizeof(wallet_seed_t));
            gemHDWSwitch = E_HDWM_PASSPHRASE;
        }

        memset(&passphrase_slip39_seed, 0, sizeof(wallet_seed_t));
        mason_slip39_master_seed_write(&slip39_m_seed);
        mason_slip39_dec_seed_write(&slip39_d_seed);

    } while (0);

    memset(&seed, 0, sizeof(wallet_seed_t));
    memset(&seedFromEntropy, 0, sizeof(wallet_seed_t));
    memset(&mnemonic, 0, sizeof(mnemonic_t));
    memset(&entropy, 0, sizeof(entropy_t));

    return is_succeed;
}
/**
 * @functionname: mason_change_slip39_wallet_passphrase
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_change_slip39_wallet_passphrase(uint8_t *passphrase, uint16_t passphrase_len)
{
    bool is_succeed = false;
    mnemonic_t mnemonic = {0};
    entropy_t entropy = {0};
    wallet_seed_t seed = {0};
    wallet_seed_t seedFromEntropy = {0};
    wallet_slip39_master_seed_t slip39_m_seed = {0};

    if (passphrase_len > MAX_PASSPHRASE_SIZE)
    {
        return false;
    }

    do
    {
        is_succeed = mason_slip39_master_seed_read(&slip39_m_seed);
        if (!is_succeed)
        {
            break;
        }

        if (0 == passphrase_len || NULL == passphrase)
        {
            memset(&passphrase_slip39_seed, 0, sizeof(wallet_seed_t));
            gemHDWSwitch = E_HDWM_MNEMONIC;
        }
        else
        {
            wallet_seed_t pass_seed = {0};
            // decrpty get pass_seed
            char passphrase_str[MAX_PASSPHRASE_SIZE + 1] = {0};
            memcpy(passphrase_str, passphrase, passphrase_len);
            slip39_decrypt(slip39_m_seed.data, slip39_m_seed.data_size, passphrase_str, (uint8_t)slip39_m_seed.e, slip39_m_seed.id, pass_seed.data);
            pass_seed.length = slip39_m_seed.data_size;

            memcpy(&passphrase_slip39_seed, &pass_seed, sizeof(wallet_seed_t));
            gemHDWSwitch = E_HDWM_PASSPHRASE;
        }

        mason_seed_write(&seed);
        mason_seedFromEntropy_write(&seedFromEntropy);
        mason_mnemonic_write(&mnemonic);
        mason_entropy_write(&entropy);
        memset(&passphrase_seed, 0, sizeof(wallet_seed_t));
        memset(&passphrase_seedFromEntropy, 0, sizeof(wallet_seed_t));

    } while (0);

    memset(&slip39_m_seed, 0, sizeof(wallet_slip39_master_seed_t));
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
    bool is_succeed = false;
    wallet_slip39_master_seed_t slip39_seed = {0};
    if (mason_slip39_master_seed_read(&slip39_seed))
    {
        is_succeed = mason_change_slip39_wallet_passphrase(passphrase, passphrase_len);
    }
    else
    {
        is_succeed = mason_change_bip39_wallet_passphrase(passphrase, passphrase_len);
    }
    return is_succeed;
}
/**
 * @functionname: mason_wallet_setup
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_wallet_setup(mnemonic_t *mnemonic, entropy_t *entropy, uint8_t *passphrase, uint16_t passphrase_len, wallet_seed_t *seed, wallet_seed_t *seedFromEntropy)
{
    bip39_gen_seed_with_mnemonic(mnemonic->data, mnemonic->size, passphrase, passphrase_len, seed->data, SHA512_LEN);
    seed->length = SHA512_LEN;

    if (entropy && entropy->size)
    {
        bip39_gen_seed_with_entropy(entropy->data, entropy->size, passphrase, passphrase_len, seedFromEntropy->data, SHA512_LEN);
        seedFromEntropy->length = SHA512_LEN;
    }
    return true;
}
/**
 * @functionname: mason_delete_wallet
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_delete_wallet(void)
{
    mnemonic_t mnemonic_data = {0};
    entropy_t entropy_data = {0};
    wallet_seed_t seed = {0};
    wallet_seed_t seedFromEntropy = {0};
    wallet_slip39_master_seed_t slip39_m_seed = {0};
    wallet_seed_t slip39_d_seed = {0};
    bool is_succeed = false;

    is_succeed = mason_storage_write_buffer((uint8_t *)&mnemonic_data, sizeof(mnemonic_t), FLASH_ADDR_MNEMONIC);
    if (!is_succeed)
    {
        return false;
    }

    is_succeed = mason_storage_write_buffer((uint8_t *)&entropy_data, sizeof(entropy_t), FLASH_ADDR_ENTROPY);
    if (!is_succeed)
    {
        return false;
    }

    is_succeed = mason_storage_write_buffer((uint8_t *)&seed, sizeof(wallet_seed_t), FLASH_ADDR_SEED_72B);
    if (!is_succeed)
    {
        return false;
    }

    is_succeed = mason_storage_write_buffer((uint8_t *)&seedFromEntropy, sizeof(wallet_seed_t), FLASH_ADDR_SEED_FROM_ENTROPY);
    if (!is_succeed)
    {
        return false;
    }

    is_succeed = mason_storage_write_buffer((uint8_t *)&slip39_m_seed, sizeof(wallet_slip39_master_seed_t), FLASH_ADDR_SLIP39_MASTER_SEED);
    if (!is_succeed)
    {
        return false;
    }

    is_succeed = mason_storage_write_buffer((uint8_t *)&slip39_d_seed, sizeof(wallet_seed_t), FLASH_ADDR_SLIP39_DEC_SEED);
    if (!is_succeed)
    {
        return false;
    }

    gemHDWSwitch = E_HDWM_MNEMONIC;
    memset(&passphrase_seed, 0, sizeof(wallet_seed_t));
    memset(&passphrase_seedFromEntropy, 0, sizeof(wallet_seed_t));
    memset(&passphrase_slip39_seed, 0, sizeof(wallet_seed_t));
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
 * @functionname: mason_wallet_path_is_pub
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_wallet_path_is_pub(char *string, uint16_t len)
{
    if ((NULL == string) || ('M' != string[0]) || (0 == len) || (len > MAX_HDPATH_SIZE))
    {
        return false;
    }

    return true;
}
/**
 * @functionname: mason_wallet_path_is_priv
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_wallet_path_is_priv(char *string, uint16_t len)
{
    if ((NULL == string) || ('m' != string[0]) || (0 == len) || (len > MAX_HDPATH_SIZE))
    {
        return false;
    }

    return true;
}
/**
 * @functionname: mason_parse_wallet_path_from_string
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_parse_wallet_path_from_string(char *string, uint16_t len, wallet_path_t *wallet_path)
{
    stHDPathType hd_path = {0};
    bool is_succeed = false;
    int i = 0;

    if (len > MAX_HDPATH_SIZE)
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
 * @functionname: mason_verify_mnemonic
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_verify_mnemonic(char *mnemonic_str, uint16_t len)
{
    emRetType emRet = ERT_Verify_Init;
    mnemonic_t mnemonic = {0};

    do
    {
        if (ERT_OK != mason_storage_read((uint8_t *)&mnemonic, sizeof(mnemonic), FLASH_ADDR_MNEMONIC))
        {
            emRet = ERT_VerifyValueFail;
            break;
        }

        if (len != mnemonic.size)
        {
            emRet = ERT_VerifyLenFail;
            break;
        }

        if (memcmp_ATA((uint8_t *)mnemonic_str, mnemonic.data, len))
        {
            emRet = ERT_VerifyValueFail;
            break;
        }

        emRet = ERT_Verify_Success;
    } while (0);

    memset(&mnemonic, 0, sizeof(mnemonic_t));
    return emRet;
}
/**
 * @functionname: mason_verify_slip39_seed
 * @description: 
 * @para: 
 * @return: 
 */
emRetType mason_verify_slip39_seed(uint8_t *slip39_seed_data, uint16_t slip39_seed_len, uint16_t slip39_id)
{
    emRetType emRet = ERT_Verify_Init;
    wallet_slip39_master_seed_t slip39_m_seed = {0};

    do
    {
        if (!mason_slip39_master_seed_read(&slip39_m_seed))
        {
            emRet = ERT_VerifyValueFail;
            break;
        }

        if ((0 == slip39_seed_len) || (slip39_seed_len > MAX_SLIP39_SEED_SIZE) || (slip39_seed_len != slip39_m_seed.data_size))
        {
            emRet = ERT_VerifyLenFail;
            break;
        }

        if (slip39_id != slip39_m_seed.id)
        {
            emRet = ERT_VerifyValueFail;
            break;
        }

        if (memcmp_ATA(slip39_seed_data, slip39_m_seed.data, slip39_seed_len))
        {
            emRet = ERT_VerifyValueFail;
            break;
        }
        emRet = ERT_Verify_Success;
    } while (0);

    memset(&slip39_m_seed, 0, sizeof(wallet_slip39_master_seed_t));
    return emRet;
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
    uint16_t key_len;
    uint8_t *key;
    wallet_seed_t seed = {0};

    switch (curve_type)
    {
    case CRYPTO_CURVE_SECP256R1:
        key = secp256r1_key;
        break;
    case CRYPTO_CURVE_SECP256K1:
        key = secp256k1_key;
        break;
    default:
        return false;
    }

    key_len = strlen((char *)key);

    if ((E_HDWM_PASSPHRASE == gemHDWSwitch) && (passphrase_slip39_seed.length))
    {
        // PASSPHRASE slip39 seed
        memcpy(&seed, &passphrase_slip39_seed, sizeof(wallet_seed_t));
    }
    else if ((E_HDWM_PASSPHRASE == gemHDWSwitch) && (SHA512_LEN == passphrase_seed.length))
    {
        // PASSPHRASE bip39 seed
        memcpy(&seed, &passphrase_seed, sizeof(wallet_seed_t));
    }
    else if (mason_slip39_dec_seed_read(&seed))
    {
        // MNEMONIC slip39 seed
    }
    else if (mason_seed_read(&seed) && (SHA512_LEN == seed.length))
    {
        // MNEMONIC bip39 seed
    }
    else
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

    memset(&seed, 0, sizeof(wallet_seed_t));
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
    private_key_t parent_private_key = {0};
    chaincode_t parent_chaincode = {0};
    private_key_t child_private_key;
    public_key_t child_public_key = {0};
    chaincode_t child_chaincode;
    compressed_public_key_t child_compressed_public_key = {0};
    uint8_t fingerprint[4] = {0x00};
    uint8_t checksum[SHA256_LEN] = {0};
    uint8_t i = 0;

    memset(extended_key->fingerprint, 0x00, 4);

    if (!mason_bip32_generate_master_key_from_root_seed(
            curve,
            &parent_private_key,
            &parent_chaincode))
    {
        return false;
    }

    child_private_key = parent_private_key;
    child_chaincode = parent_chaincode;
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
    }

    *private_key = child_private_key;
    *chaincode = child_chaincode;

    u32_to_buf(extended_key->version, wallet_path->version);
    extended_key->depth = wallet_path->num_of_segments;
    memcpy(extended_key->fingerprint, fingerprint, sizeof(fingerprint));
    if (wallet_path->num_of_segments)
    {
        u32_to_buf(extended_key->child_number, wallet_path->segments[wallet_path->num_of_segments - 1]);
    }
    memcpy(extended_key->chaincode, chaincode, CHAINCODE_LEN);
    if (wallet_path->version == KEY_VERSION_MAINNET_PUBLIC || wallet_path->version == KEY_VERSION_TESTNET_PUBLIC)
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

    memset(&parent_private_key, 0, sizeof(private_key_t));
    memset(&parent_chaincode, 0, sizeof(chaincode_t));
    memset(&child_private_key, 0, sizeof(private_key_t));
    memset(&child_chaincode, 0, sizeof(chaincode_t));
    return true;
}
/**
 * @functionname: mason_bip32_derive_master_key_fingerprint
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_bip32_derive_master_key_fingerprint(crypto_curve_t curve, uint8_t *fingerprint, uint16_t fingerprint_len)
{
    private_key_t master_private_key;
    chaincode_t master_chaincode;
    if (!mason_bip32_generate_master_key_from_root_seed(
            curve,
            &master_private_key,
            &master_chaincode))
    {
        return false;
    }

    private_key_to_fingerprint(curve, &master_private_key, fingerprint, fingerprint_len);

    memset(&master_private_key, 0, sizeof(private_key_t));
    memset(&master_chaincode, 0, sizeof(chaincode_t));
    return true;
}
/**
 * @functionname: mason_eip2333_derive_master_SK
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_eip2333_derive_master_SK(private_key_t *private_key)
{
    wallet_seed_t seed = {0};

    if ((E_HDWM_PASSPHRASE == gemHDWSwitch) && (passphrase_slip39_seed.length))
    {
        // PASSPHRASE slip39 seed
        memcpy(&seed, &passphrase_slip39_seed, sizeof(wallet_seed_t));
    }
    else if ((E_HDWM_PASSPHRASE == gemHDWSwitch) && (SHA512_LEN == passphrase_seed.length))
    {
        // PASSPHRASE bip39 seed
        memcpy(&seed, &passphrase_seed, sizeof(wallet_seed_t));
    }
    else if (mason_slip39_dec_seed_read(&seed))
    {
        // MNEMONIC slip39 seed
    }
    else if (mason_seed_read(&seed) && (SHA512_LEN == seed.length))
    {
        // MNEMONIC bip39 seed
    }
    else
    {
        return false;
    }

    if (seed.length < 32)
    {
        return false;
    }

    derive_master_SK(seed.data, seed.length, private_key->data);
    private_key->len = PRIVATE_KEY_LEN;
    memset(&seed, 0, sizeof(wallet_seed_t));
    return true;
}
/**
 * @functionname: mason_eip2333_derive_SK
 * @description: 
 * @para: 
 * @return: 
 */
static bool mason_eip2333_derive_SK(wallet_path_t *wallet_path, private_key_t *private_key)
{
    private_key_t parent_key = {0};
    private_key_t child_sk = {0};
    if (!mason_eip2333_derive_master_SK(&parent_key))
    {
        return false;
    }

    memmove(&child_sk, &parent_key, sizeof(private_key_t));

    for (uint8_t i = 0; i < wallet_path->num_of_segments; i++)
    {
        if (!derive_child_SK(parent_key.data, wallet_path->segments[i], child_sk.data))
        {
            return false;
        }
        child_sk.len = SHA256_LEN;
        memmove(&parent_key, &child_sk, sizeof(private_key_t));
    }
    memmove(private_key, &child_sk, sizeof(private_key_t));

    return true;
}
/**
 * @functionname: mason_eth2_derive_deposit_SK
 * @description: 
 * @para: 
 * @return: 
 */
bool mason_eth2_derive_deposit_SK(uint32_t account, private_key_t *withdrawal_key, private_key_t *sign_key)
{
    wallet_path_t path = {0};
    char path_str[MAX_HDPATH_SIZE + 1] = "m/12381/3600/";
    char account_str[12] = {0};
    myuitoa(account, account_str);
    strcat(path_str, account_str);
    char *use = "/0";
    strcat(path_str, use);

    mason_parse_wallet_path_from_string(path_str, strlen(path_str), &path);

    if (!mason_eip2333_derive_SK(&path, withdrawal_key))
    {
        return false;
    }
    if (!derive_child_SK(withdrawal_key->data, 0, sign_key->data))
    {
        return false;
    }
    sign_key->len = PRIVATE_KEY_LEN;
    return true;
}
