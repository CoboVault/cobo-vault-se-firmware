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
#ifndef CRYPTO_API_H
#define CRYPTO_API_H

/** Avoid duplicate definitions */
#ifdef CRYPTO_API_GLOBAL
#define CRYPTO_API_EXT
#else
#define CRYPTO_API_EXT extern
#endif

/** Header file reference */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h> //memcpy...
#include <limits.h>
#include <ctype.h>
#include <secp256.h>

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/** Macro definitions*/
#ifndef SHA256_LEN
#define SHA256_LEN 32
#endif
#ifndef SHA512_LEN
#define SHA512_LEN 64
#endif
#ifndef RPMD160_LEN
#define RPMD160_LEN 20
#endif

    typedef enum crypto_curve_e
    {
        CRYPTO_CURVE_SECP256K1 = 0,
        CRYPTO_CURVE_SECP256R1,
        CRYPTO_CURVE_ED25519,
        CRYPTO_CURVE_SR25519,
    } crypto_curve_t;

    /** Function declarations */
    bool ecdsa_sign(
        crypto_curve_t curve,
        uint8_t *hash,
        uint16_t hash_len,
        uint8_t *private_key,
        uint8_t *signature,
        uint16_t *signature_len);

    bool ecdsa_verify(crypto_curve_t curve, uint8_t *hash, uint8_t *public_key, uint8_t *signature);
    void crypto_api_sm2_init(void);
    bool crypto_api_sm2_decrypt(
        uint8_t *private_key,
        uint8_t *encrypted_data,
        uint32_t encrypted_data_len,
        uint8_t *output,
        uint32_t *output_len);

    bool is_valid_private_key(crypto_curve_t curve, uint8_t *private_key);

    bool crypto_init(void);
    void ed25519_private_key_to_public_key(uint8_t *private_key, uint8_t *public_key);
    bool crypto_api_rsa_decrypt(uint8_t *private_key_n, uint16_t n_len, uint8_t *private_key_d,
                                uint16_t d_len, uint8_t *encrypted_data, uint16_t encrypted_data_len,
                                uint8_t *output, uint16_t *output_len);
    CRYPTO_API_EXT void ripeMD160_api(uint8_t *pData, uint32_t len, uint8_t *pDigest);
    CRYPTO_API_EXT void sha256_api(uint8_t *pData, uint32_t len, uint8_t *pDigest);
    CRYPTO_API_EXT void sha512_api(uint8_t *pData, uint32_t len, uint8_t *pDigest);
    CRYPTO_API_EXT void hmac_sha512_api(uint8_t *pData, uint32_t dataLen,
                                        uint8_t *pKey, uint32_t keyLen, uint8_t *pDigest);

/** Compatibility with the cplusplus*/
#ifdef __cplusplus
} /* Extern C */
#endif

#endif
