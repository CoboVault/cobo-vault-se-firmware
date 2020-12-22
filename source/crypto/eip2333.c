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
#define EIP2333_GLOBAL

/** Header file reference */
#include "eip2333.h"
#include "crypto_api.h"
#include "hkdf.h"
#include "util.h"
#include "sha2.h"
#include "rsa_keygen.h"

/** Function implementations */
/**
 * @functionname: bignum_mod
 * @description: 
 * @para: 
 * @return: 
 */
void bignum_mod_r(uint8_t *ikm, uint8_t *sk)
{
    UINT32 ikm_data[12] = {0};
    UINT32 ikm_digital = 12;
    for (uint32_t i = 0; i < ikm_digital; i++)
    {
        uint8_t digital[4] = {0};
        memmove(digital, &ikm[i * 4], 4);
        buf_to_u32(&ikm_data[ikm_digital - (i + 1)], digital);
    }

    // 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    UINT32 bls_curve_order[8] = {0x00000001, 0xFFFFFFFF, 0xFFFE5BFE, 0x53BDA402, 0x09A1D805, 0x3339D808, 0x299D7D48, 0x73EDA753};
    UINT32 order_digital = 8;

    UINT32 sk_data[8] = {0};
    MATH_G_STR math_glb_str;

    NN_Mod_variable_initial((MATH_G_STR *)(&math_glb_str), ikm_digital);
    enable_module(BIT_PKI);
    NN_Mod((MATH_G_STR *)(&math_glb_str), sk_data, ikm_data, ikm_digital, bls_curve_order, order_digital);

    for (uint32_t i = 0; i < order_digital; i++)
    {
        uint8_t digital[4] = {0};
        u32_to_buf(digital, sk_data[i]);
        memmove(&sk[(order_digital - (i + 1)) * 4], digital, 4);
    }
}

/**
 * @functionname: HKDF_mod_r
 * @description: 
 * @para: 
 * @return: 
 */
bool HKDF_mod_r(uint8_t *ikm_in, uint32_t ikm_in_len, uint8_t *info_in, uint32_t info_in_len, uint8_t *sk)
{
    uint8_t salt[SHA256_LEN] = "BLS-SIG-KEYGEN-SALT-";
    uint32_t salt_len = strlen((char *)salt);
    uint8_t ikm[EIP2333_IKM_LEN + 1] = {0};
    uint32_t ikm_len = 0;
    uint8_t info[EIP2333_INFO_LEN + 2] = {0};
    uint32_t info_len = 0;
    uint8_t L_bytes[2] = {0};
    uint16_t L = 48;
    uint8_t okm[48] = {0};

    if (ikm_in_len > EIP2333_IKM_LEN)
    {
        return false;
    }
    if (info_in_len > EIP2333_INFO_LEN)
    {
        return false;
    }
    uint8_t ikm_0[1] = {0};
    memmove(ikm, ikm_in, ikm_in_len);
    memmove(ikm + ikm_in_len, ikm_0, 1);
    ikm_len = ikm_in_len + 1;

    u16_to_buf(L_bytes, L);
    memmove(info, info_in, info_in_len);
    memmove(info + info_in_len, L_bytes, 2);
    info_len = info_in_len + 2;

    uint8_t mod_sk[SHA256_LEN] = {0};
    uint8_t zero_sk[SHA256_LEN] = {0};
    while (!memcmp_ATA(mod_sk, zero_sk, SHA256_LEN))
    {
        sha256_api(salt, salt_len, salt);
        salt_len = SHA256_LEN;
        if (hkdf(salt, salt_len, ikm, ikm_len, info, info_len, okm, L))
        {
            return false;
        }
        bignum_mod_r(okm, mod_sk);
    }
    memmove(sk, mod_sk, SHA256_LEN);
    return true;
}
/**
 * @functionname: IKM_to_lamport_SK
 * @description: 
 * @para: 
 * @return: 
 */
void flip_bits_256(uint8_t *input, uint8_t *output)
{
    uint16_t i = 0;
    while (i < 32)
    {
        output[i] = input[i] ^ 0xFF;
        i++;
    }
}
/**
 * @functionname: IKM_to_lamport_SK
 * @description: 
 * @para: 
 * @return: 
 */
bool IKM_to_lamport_SK(uint8_t *ikm, uint32_t ikm_len, uint8_t *salt, uint32_t salt_len, uint8_t *okm, uint32_t *okm_len)
{
    uint16_t K = 32;
    uint16_t n = 255;
    uint16_t L = K * n;
    if (hkdf(salt, salt_len, ikm, ikm_len, NULL, 0, okm, L))
    {
        return false;
    }

    *okm_len = L;
    return true;
}
/**
 * @functionname: parent_SK_to_lamport_PK
 * @description: 
 * @para: 
 * @return: 
 */
bool parent_SK_to_lamport_PK(uint8_t *parent_sk, uint32_t index, uint8_t *lamport_pk)
{
    uint8_t salt[4] = {0};
    uint32_t salt_len = 4;
    u32_to_buf(salt, index);
    uint16_t K = 32;
    uint16_t n = 255;

    SHA256_CTX ctx;
    sha256_Init(&ctx);

    uint8_t digest[SHA256_LEN] = {0};

    uint8_t lamport_0_1_bytes[32 * 255] = {0};
    uint32_t lamport_0_1_len = 0;
    if (!IKM_to_lamport_SK(parent_sk, SHA256_LEN, salt, salt_len, lamport_0_1_bytes, &lamport_0_1_len))
    {
        return false;
    }

    for (int i = 0; i < n; i++)
    {
        sha256_api(&lamport_0_1_bytes[i * K], K, digest);
        sha256_Update(&ctx, digest, SHA256_LEN);
    }

    uint8_t not_ikm[SHA256_LEN] = {0};
    flip_bits_256(parent_sk, not_ikm);
    if (!IKM_to_lamport_SK(not_ikm, SHA256_LEN, salt, salt_len, lamport_0_1_bytes, &lamport_0_1_len))
    {
        return false;
    }

    for (int i = 0; i < n; i++)
    {
        sha256_api(&lamport_0_1_bytes[i * K], K, digest);
        sha256_Update(&ctx, digest, SHA256_LEN);
    }

    sha256_Final(&ctx, digest);
    memmove(lamport_pk, digest, SHA256_LEN);
    return true;
}
/**
 * @functionname: derive_master_SK
 * @description: 
 * @para: 
 * @return: 
 */
EIP2333_EXT bool derive_master_SK(uint8_t *seed, uint32_t seed_len, uint8_t *key)
{
    return HKDF_mod_r(seed, seed_len, NULL, 0, key);
}
/**
 * @functionname: derive_child_SK
 * @description: 
 * @para: 
 * @return: 
 */
EIP2333_EXT bool derive_child_SK(uint8_t *parent_sk, uint32_t index, uint8_t *child_sk)
{
    // index range 0~0x100000000
    uint8_t lamport_pk[SHA256_LEN] = {0};
    if (parent_SK_to_lamport_PK(parent_sk, index, lamport_pk))
    {
        return HKDF_mod_r(lamport_pk, SHA256_LEN, NULL, 0, child_sk);
    }
    else
    {
        return false;
    }
}
