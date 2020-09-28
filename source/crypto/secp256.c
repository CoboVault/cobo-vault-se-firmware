#include <secp256.h>
#include <wdt.h>
#include <stdio.h>
#include <rsa_keygen.h>
#include <ecdsa.h>
#include <util.h>

const UINT32 SECP256K1_CURVE_LENGTH = 8;
UINT32 SECP256K1_P[8] = {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
UINT32 SECP256K1_a[8] = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
UINT32 SECP256K1_b[8] = {0x00000007, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
UINT32 SECP256K1_N[8] = {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
UINT32 SECP256K1_G_BaseX[8] = {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E};
UINT32 SECP256K1_G_BaseY[8] = {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77};

const UINT32 SECP256R1_CURVE_LENGTH = 8;
UINT32 SECP256R1_P[8] = {0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xffffffff};
UINT32 SECP256R1_a[8] = {0xfffffffc, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xffffffff};
UINT32 SECP256R1_b[8] = {0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0, 0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8};
UINT32 SECP256R1_N[8] = {0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000, 0xffffffff};
UINT32 SECP256R1_G_BaseX[8] = {0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81, 0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2};
UINT32 SECP256R1_G_BaseY[8] = {0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357, 0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2};

static ECC_G_STR secp256k1_ecc_g_str;
static MATH_G_STR secp256k1_math_g_str;
static ECC_G_STR secp256r1_ecc_g_str;
static MATH_G_STR secp256r1_math_g_str;

/**
 * @functionname: secp256k1_init
 * @description: 
 * @para: 
 * @return: 
 */
void secp256k1_init()
{
    ECC_para_initial(
        &secp256k1_ecc_g_str,
        SECP256K1_CURVE_LENGTH,
        SECP256K1_P,
        SECP256K1_a,
        SECP256K1_b,
        SECP256K1_N,
        SECP256K1_G_BaseX,
        SECP256K1_G_BaseY);
}
/**
 * @functionname: secp256r1_init
 * @description: 
 * @para: 
 * @return: 
 */
void secp256r1_init()
{
    ECC_para_initial(
        &secp256r1_ecc_g_str,
        SECP256R1_CURVE_LENGTH,
        SECP256R1_P,
        SECP256R1_a,
        SECP256R1_b,
        SECP256R1_N,
        SECP256R1_G_BaseX,
        SECP256R1_G_BaseY);
}
/**
 * @functionname: ecc_utils_buffer_to_ecc_array
 * @description: 
 * @para: 
 * @return: 
 */
void ecc_utils_buffer_to_ecc_array(uint8_t *buffer, uint32_t *ecc_array, uint32_t ecc_array_len)
{
    int i = 0;
    uint8_t *ecc_array_p;
    ecc_array_p = (uint8_t *)ecc_array;
    for (i = 0; i < ecc_array_len * sizeof(uint32_t); i++)
    {
        ecc_array_p[i] = buffer[ecc_array_len * sizeof(uint32_t) - 1 - i];
    }
}
/**
 * @functionname: ecc_utils_ecc_array_to_buffer
 * @description: 
 * @para: 
 * @return: 
 */
void ecc_utils_ecc_array_to_buffer(uint32_t *ecc_array, uint32_t ecc_array_len, uint8_t *buffer)
{
    int i = 0;
    uint8_t *ecc_array_p;
    ecc_array_p = (uint8_t *)ecc_array;
    for (i = 0; i < ecc_array_len * sizeof(uint32_t); i++)
    {
        buffer[ecc_array_len * sizeof(uint32_t) - 1 - i] = ecc_array_p[i];
    }
}
/**
 * @functionname: secp256k1_private_key_to_public_key
 * @description: 
 * @para: 
 * @return: 
 */
bool secp256k1_private_key_to_public_key(uint8_t *private_key, uint8_t *public_key_x, uint8_t *public_key_y)
{
    bool is_succeed = false;
    uint32_t ecc_private_key[8] = {0};
    uint32_t ecc_public_key_x[8] = {0};
    uint32_t ecc_public_key_y[8] = {0};

    ecc_utils_buffer_to_ecc_array(private_key, ecc_private_key, 8);

    enable_module(BIT_PKI);
    is_succeed = (0 == ECC_PM(
                           &secp256k1_ecc_g_str,
                           // private_key,
                           ecc_private_key,
                           SECP256K1_G_BaseX,
                           SECP256K1_G_BaseY,
                           ecc_public_key_x,
                           ecc_public_key_y));

    ecc_utils_ecc_array_to_buffer(ecc_public_key_x, 8, public_key_x);
    ecc_utils_ecc_array_to_buffer(ecc_public_key_y, 8, public_key_y);
    return is_succeed;
}
/**
 * @functionname: secp256r1_private_key_to_public_key
 * @description: 
 * @para: 
 * @return: 
 */
bool secp256r1_private_key_to_public_key(uint8_t *private_key, uint8_t *public_key_x, uint8_t *public_key_y)
{
    bool is_succeed = false;
    uint32_t ecc_private_key[8] = {0};
    uint32_t ecc_public_key_x[8] = {0};
    uint32_t ecc_public_key_y[8] = {0};

    ecc_utils_buffer_to_ecc_array(private_key, ecc_private_key, 8);

    enable_module(BIT_PKI);
    is_succeed = (0 == ECC_PM(
                           &secp256r1_ecc_g_str,
                           ecc_private_key,
                           SECP256R1_G_BaseX,
                           SECP256R1_G_BaseY,
                           ecc_public_key_x,
                           ecc_public_key_y));

    ecc_utils_ecc_array_to_buffer(ecc_public_key_x, 8, public_key_x);
    ecc_utils_ecc_array_to_buffer(ecc_public_key_y, 8, public_key_y);
    return is_succeed;
}
/**
 * @functionname: secp256k1_add_mod
 * @description: 
 * @para: 
 * @return: 
 */
void secp256k1_add_mod(uint8_t *a, uint8_t *b, uint8_t *output)
{
    uint32_t ecc_a[SECP256K1_CURVE_LENGTH];
    uint32_t ecc_b[SECP256K1_CURVE_LENGTH];
    uint32_t ecc_sum[SECP256K1_CURVE_LENGTH];
    uint8_t sum_len = 0;

    ecc_utils_buffer_to_ecc_array(a, ecc_a, SECP256K1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(b, ecc_b, SECP256K1_CURVE_LENGTH);
    enable_module(BIT_PKI);
    ECC_mod_add_sub(
        ecc_a, SECP256K1_CURVE_LENGTH,
        ecc_b, SECP256K1_CURVE_LENGTH,
        SECP256K1_N, SECP256K1_CURVE_LENGTH,
        ecc_sum,
        &sum_len,
        0x02);
    ecc_utils_ecc_array_to_buffer(ecc_sum, SECP256K1_CURVE_LENGTH, output);
}
/**
 * @functionname: secp256r1_add_mod
 * @description: 
 * @para: 
 * @return: 
 */
void secp256r1_add_mod(uint8_t *a, uint8_t *b, uint8_t *output)
{
    uint32_t ecc_a[SECP256R1_CURVE_LENGTH];
    uint32_t ecc_b[SECP256R1_CURVE_LENGTH];
    uint32_t ecc_sum[SECP256R1_CURVE_LENGTH];
    uint8_t sum_len = 0;

    ecc_utils_buffer_to_ecc_array(a, ecc_a, SECP256R1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(b, ecc_b, SECP256R1_CURVE_LENGTH);
    enable_module(BIT_PKI);
    ECC_mod_add_sub(
        ecc_a, SECP256R1_CURVE_LENGTH,
        ecc_b, SECP256R1_CURVE_LENGTH,
        SECP256R1_N, SECP256R1_CURVE_LENGTH,
        ecc_sum,
        &sum_len,
        0x02);
    ecc_utils_ecc_array_to_buffer(ecc_sum, SECP256R1_CURVE_LENGTH, output);
}
/**
 * @functionname: secp256k1_generate_valid_key
 * @description: 
 * @para: 
 * @return: 
 */
bool secp256k1_generate_valid_key(
    uint8_t *i_left,
    uint8_t *parent_private_key,
    uint8_t *result_key)
{
    uint8_t zero_buf[SECP256K1_CURVE_LENGTH * 4] = {0};
    uint8_t secp256k1_n[SECP256K1_CURVE_LENGTH * 4] = {0};

    ecc_utils_ecc_array_to_buffer(SECP256K1_N, SECP256K1_CURVE_LENGTH, secp256k1_n);

    if (memcmp(i_left, secp256k1_n, SECP256K1_CURVE_LENGTH * 4) >= 0)
    {
        return false;
    }

    secp256k1_add_mod(i_left, parent_private_key, result_key);

    if (memcmp(result_key, zero_buf, SECP256K1_CURVE_LENGTH * 4) == 0)
    {
        return false;
    }

    return true;
}
/**
 * @functionname: secp256r1_generate_valid_key
 * @description: 
 * @para: 
 * @return: 
 */
bool secp256r1_generate_valid_key(
    uint8_t *i_left,
    uint8_t *parent_private_key,
    uint8_t *result_key)
{
    uint8_t zero_buf[SECP256R1_CURVE_LENGTH * 4] = {0};
    uint8_t secp256r1_n[SECP256R1_CURVE_LENGTH * 4] = {0};

    ecc_utils_ecc_array_to_buffer(SECP256R1_N, SECP256R1_CURVE_LENGTH, secp256r1_n);

    if (memcmp(i_left, secp256r1_n, SECP256R1_CURVE_LENGTH * 4) >= 0)
    {
        return false;
    }

    secp256r1_add_mod(i_left, parent_private_key, result_key);

    if (memcmp(result_key, zero_buf, SECP256R1_CURVE_LENGTH * 4) == 0)
    {
        return false;
    }

    return true;
}
/**
 * @functionname: secp256k1_ecdsa_sign
 * @description: 
 * @para: 
 * @return: 
 */
bool secp256k1_ecdsa_sign(
    uint8_t *hash,
    uint16_t hash_len,
    uint8_t *key,
    uint8_t *signature)
{
    uint32_t ecc_hash[SECP256K1_CURVE_LENGTH] = {0};
    uint32_t ecc_key[SECP256K1_CURVE_LENGTH] = {0};
    uint32_t ecc_signature_r[SECP256K1_CURVE_LENGTH] = {0};
    uint32_t ecc_signature_s[SECP256K1_CURVE_LENGTH] = {0};

    NN_AssignZero(ecc_signature_r, SECP256K1_CURVE_LENGTH);
    NN_AssignZero(ecc_signature_s, SECP256K1_CURVE_LENGTH);

    ecc_utils_buffer_to_ecc_array(hash, ecc_hash, SECP256K1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(key, ecc_key, SECP256K1_CURVE_LENGTH);

    enable_module(BIT_PKI);
    if (ECDSA_sign(
            &secp256k1_ecc_g_str,
            &secp256k1_math_g_str,
            ecc_hash,
            ecc_key,
            ecc_signature_r,
            ecc_signature_s))
    {
        //printf("SIGNED FAILED\n");
        return false;
    }

    ecc_utils_ecc_array_to_buffer(ecc_signature_r, SECP256K1_CURVE_LENGTH, signature);
    ecc_utils_ecc_array_to_buffer(ecc_signature_s, SECP256K1_CURVE_LENGTH, signature + sizeof(ecc_signature_r));

    return true;
}
/**
 * @functionname: secp256k1_ecdsa_verify
 * @description: 
 * @para: 
 * @return: 
 */
bool secp256k1_ecdsa_verify(
    uint8_t *hash,
    uint8_t *public_key,
    uint8_t *signature)
{
    uint32_t ecc_hash[SECP256K1_CURVE_LENGTH] = {0};
    uint32_t ecc_public_key_x[SECP256K1_CURVE_LENGTH] = {0};
    uint32_t ecc_public_key_y[SECP256K1_CURVE_LENGTH] = {0};
    uint32_t ecc_signature_r[SECP256K1_CURVE_LENGTH] = {0};
    uint32_t ecc_signature_s[SECP256K1_CURVE_LENGTH] = {0};

    ecc_utils_buffer_to_ecc_array(hash, ecc_hash, SECP256K1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(public_key, ecc_public_key_x, SECP256K1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(public_key + sizeof(uint32_t) * SECP256K1_CURVE_LENGTH, ecc_public_key_y, SECP256K1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(signature, ecc_signature_r, SECP256K1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(signature + sizeof(uint32_t) * SECP256K1_CURVE_LENGTH, ecc_signature_s, SECP256K1_CURVE_LENGTH);

    enable_module(BIT_PKI);
    return 0 == ECDSA_verify(
                    &secp256k1_ecc_g_str,
                    &secp256k1_math_g_str,
                    ecc_hash,
                    ecc_public_key_x,
                    ecc_public_key_y,
                    ecc_signature_r,
                    ecc_signature_s);
}
/**
 * @functionname: secp256r1_ecdsa_sign
 * @description: 
 * @para: 
 * @return: 
 */
bool secp256r1_ecdsa_sign(
    uint8_t *hash,
    uint16_t hash_len,
    uint8_t *key,
    uint8_t *signature)
{
    uint32_t ecc_hash[SECP256R1_CURVE_LENGTH] = {0};
    uint32_t ecc_key[SECP256R1_CURVE_LENGTH] = {0};
    uint32_t ecc_signature_r[SECP256R1_CURVE_LENGTH] = {0};
    uint32_t ecc_signature_s[SECP256R1_CURVE_LENGTH] = {0};

    NN_AssignZero(ecc_signature_r, SECP256R1_CURVE_LENGTH);
    NN_AssignZero(ecc_signature_s, SECP256R1_CURVE_LENGTH);

    ecc_utils_buffer_to_ecc_array(hash, ecc_hash, SECP256R1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(key, ecc_key, SECP256R1_CURVE_LENGTH);

    enable_module(BIT_PKI);
    if (ECDSA_sign(
            &secp256r1_ecc_g_str,
            &secp256r1_math_g_str,
            ecc_hash,
            ecc_key,
            ecc_signature_r,
            ecc_signature_s))
    {
        //printf("SIGNED FAILED\n");
        return false;
    }

    ecc_utils_ecc_array_to_buffer(ecc_signature_r, SECP256R1_CURVE_LENGTH, signature);
    ecc_utils_ecc_array_to_buffer(ecc_signature_s, SECP256R1_CURVE_LENGTH, signature + sizeof(ecc_signature_r));

    return true;
}
/**
 * @functionname: secp256r1_ecdsa_verify
 * @description: 
 * @para: 
 * @return: 
 */
bool secp256r1_ecdsa_verify(
    uint8_t *hash,
    uint8_t *public_key,
    uint8_t *signature)
{
    uint32_t ecc_hash[SECP256R1_CURVE_LENGTH] = {0};
    uint32_t ecc_public_key_x[SECP256R1_CURVE_LENGTH] = {0};
    uint32_t ecc_public_key_y[SECP256R1_CURVE_LENGTH] = {0};
    uint32_t ecc_signature_r[SECP256R1_CURVE_LENGTH] = {0};
    uint32_t ecc_signature_s[SECP256R1_CURVE_LENGTH] = {0};

    ecc_utils_buffer_to_ecc_array(hash, ecc_hash, SECP256R1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(public_key, ecc_public_key_x, SECP256R1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(public_key + sizeof(uint32_t) * SECP256R1_CURVE_LENGTH, ecc_public_key_y, SECP256R1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(signature, ecc_signature_r, SECP256R1_CURVE_LENGTH);
    ecc_utils_buffer_to_ecc_array(signature + sizeof(uint32_t) * SECP256R1_CURVE_LENGTH, ecc_signature_s, SECP256R1_CURVE_LENGTH);

    enable_module(BIT_PKI);
    return 0 == ECDSA_verify(
                    &secp256r1_ecc_g_str,
                    &secp256r1_math_g_str,
                    ecc_hash,
                    ecc_public_key_x,
                    ecc_public_key_y,
                    ecc_signature_r,
                    ecc_signature_s);
}
