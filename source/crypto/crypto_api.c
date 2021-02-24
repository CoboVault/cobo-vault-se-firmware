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
#define CRYPTO_API_GLOBAL

/** Header file reference */
#include "crypto_api.h"
#include "sha2.h"
#include "RipeMD160.h"
#include "hmac.h"
#include "util.h"
#include "ed25519.h"
#include "rsa_keygen.h"
/** Function implementations */
/**
 * @functionname: crypto_init
 * @description: 
 * @para: 
 * @return: 
 */
bool crypto_init()
{
	secp256k1_init();
	secp256r1_init();
	return true;
}
/**
 * @functionname: ripeMD160_api
 * @description: 
 * @para: 
 * @return: 
 */
CRYPTO_API_EXT void ripeMD160_api(uint8_t *pData, uint32_t len, uint8_t *pDigest)
{
	RipeMD160(pData, len, pDigest);
}
/**
 * @functionname: sha256_api
 * @description: 
 * @para: 
 * @return: 
 */
CRYPTO_API_EXT void sha256_api(uint8_t *pData, uint32_t len, uint8_t *pDigest)
{
	sha256_Raw((UINT8 *)pData, (UINT32)len, (UINT8 *)pDigest);
}
/**
 * @functionname: sha512_api
 * @description: 
 * @para: 
 * @return: 
 */
CRYPTO_API_EXT void sha512_api(uint8_t *pData, uint32_t len, uint8_t *pDigest)
{
	sha512_Raw((UINT8 *)pData, (UINT32)len, (UINT8 *)pDigest);
}
/**
 * @functionname: hmac_sha512_api
 * @description: 
 * @para: 
 * @return: 
 */
CRYPTO_API_EXT void hmac_sha512_api(uint8_t *pData, uint32_t dataLen,
									uint8_t *pKey, uint32_t keyLen, uint8_t *pDigest)
{
	hmac_sha512(pKey, keyLen, pData, dataLen, pDigest);
}
/**
 * @functionname: is_valid_private_key
 * @description: 
 * @para: 
 * @return: 
 */
bool is_valid_private_key(crypto_curve_t curve, uint8_t *private_key)
{
	uint8_t zero_buf[32] = {0};
	uint8_t secp256_n[32] = {0};
	uint16_t key_length = 0;

	if (curve == CRYPTO_CURVE_ED25519)
	{
		return true;
	}

	if (memcmp(private_key, zero_buf, SECP256K1_CURVE_LENGTH * 4) == 0)
	{
		return false;
	}

	if (curve == CRYPTO_CURVE_SECP256K1)
	{
		ecc_utils_ecc_array_to_buffer(SECP256K1_N, SECP256K1_CURVE_LENGTH, secp256_n);
		key_length = SECP256K1_CURVE_LENGTH * 4;
	}
	else if (curve == CRYPTO_CURVE_SECP256R1)
	{
		ecc_utils_ecc_array_to_buffer(SECP256R1_N, SECP256R1_CURVE_LENGTH, secp256_n);
		key_length = SECP256R1_CURVE_LENGTH * 4;
	}
	else
	{
		return false;
	}

	if (memcmp(private_key, secp256_n, key_length) >= 0)
	{
		return false;
	}

	return true;
}
/**
 * @functionname: is_canonical
 * @description: 
 * @para: 
 * @return: 
 */
bool is_canonical(uint8_t signature[64])
{
	return !(signature[0] & 0x80) && !(signature[0] == 0 && !(signature[1] & 0x80)) && !(signature[32] & 0x80) && !(signature[32] == 0 && !(signature[33] & 0x80));
}
/**
 * @functionname: ecdsa_sign_once
 * @description: 
 * @para: 
 * @return: 
 */
bool ecdsa_sign_once(crypto_curve_t curve, uint8_t *hash, uint16_t hash_len, uint8_t *private_key, uint8_t *signature, uint16_t *signature_len)
{
	switch (curve)
	{
	case CRYPTO_CURVE_SECP256K1:
	{
		*signature_len = 64;
		return secp256k1_ecdsa_sign(
			hash,
			hash_len,
			private_key,
			signature);
	}
	case CRYPTO_CURVE_SECP256R1:
	{
		*signature_len = 64;
		return secp256r1_ecdsa_sign(
			hash,
			hash_len,
			private_key,
			signature);
	}
	case CRYPTO_CURVE_ED25519:
	{
		uint8_t public_key[32];
		*signature_len = 64;
		ed25519_publickey(private_key, public_key);
		ed25519_sign(hash, hash_len, private_key, public_key, signature);
		return true;
	}
	default:
	{
		return false;
	}
	}
}
/**
 * @functionname: ecdsa_sign
 * @description: 
 * @para: 
 * @return: 
 */
bool ecdsa_sign(crypto_curve_t curve, uint8_t *hash, uint16_t hash_len, uint8_t *private_key, uint8_t *signature, uint16_t *signature_len)
{
	bool is_succeed = false;
	do
	{
		is_succeed = ecdsa_sign_once(curve, hash, hash_len, private_key, signature, signature_len);
		if (!is_succeed)
		{
			return false;
		}
	} while (curve != CRYPTO_CURVE_ED25519 && !is_canonical(signature));

	return is_succeed;
}
/**
 * @functionname: ecdsa_verify
 * @description: 
 * @para: 
 * @return: 
 */
bool ecdsa_verify(crypto_curve_t curve, uint8_t *hash, uint8_t *public_key, uint8_t *signature)
{
	switch (curve)
	{
	case CRYPTO_CURVE_SECP256K1:
	{
		return secp256k1_ecdsa_verify(
			hash,
			public_key,
			signature);
	}
	case CRYPTO_CURVE_SECP256R1:
	{
		return secp256r1_ecdsa_verify(
			hash,
			public_key,
			signature);
	}
	case CRYPTO_CURVE_ED25519:
	{
		return false;
	}
	default:
	{
		return false;
	}
	}
}

/**
 * @functionname: ed25519_private_key_to_public_key
 * @description: 
 * @para: 
 * @return: 
 */
void ed25519_private_key_to_public_key(uint8_t *private_key, uint8_t *public_key)
{
	ed25519_publickey(private_key, public_key);
}

//RSA cryptosystem

/**
 * @functionname: crypto_para_u8_to_u32
 * @description: convert parameters from u8 data buffer to u32 structure
 * @para: in - u8_para; out - u32_para; ndigits - len of u32_para 
 * @return: 
 */
static void crypto_para_u8_to_u32(uint8_t *u8_para, uint32_t *u32_para, uint16_t ndigits)
{
	uint8_t *pt = (uint8_t *)u32_para;
	for (uint16_t i = 0; i < ndigits * 4; i++)
	{
		pt[ndigits * 4 - i - 1] = u8_para[i];
	}
}
/**
 * @functionname: crypto_para_u32_to_u8
 * @description: convert parameters from u8 data buffer to u32 structure
 * @para: in - u32_para; out - u8_para; ndigits - len of u32_para 
 * @return: 
 */
static void crypto_para_u32_to_u8(uint32_t *u32_para, uint8_t *u8_para, uint16_t ndigits)
{
	uint8_t *pt = (uint8_t *)u32_para;
	for (uint16_t i = 0; i < ndigits * 4; i++)
	{
		u8_para[i] = pt[ndigits * 4 - i - 1];
	}
}
/**
 * @functionname: crypto_api_rsa_decrypt
 * @description: 
 * @para: 
 * @return: 
 */
bool crypto_api_rsa_decrypt(uint8_t *private_key_n, uint16_t n_len, uint8_t *private_key_d, uint16_t d_len, uint8_t *encrypted_data, uint16_t encrypted_data_len, uint8_t *output, uint16_t *output_len)
{
	UINT8 ndigits_n;
	UINT8 ndigits_d;
	UINT8 res_length;
	UINT32 rsa_N[NDIGITS] = {0};
	UINT32 rsa_D[NDIGITS] = {0};
	UINT32 rsa_RESULT[NDIGITS] = {0};

	if ((n_len % 4) || (d_len % 4) || (encrypted_data_len % 4))
	{
		return false;
	}
	ndigits_n = n_len / 4;
	ndigits_d = d_len / 4;
	res_length = encrypted_data_len / 4;

	crypto_para_u8_to_u32(private_key_n, rsa_N, ndigits_n);
	crypto_para_u8_to_u32(private_key_d, rsa_D, ndigits_d);
	crypto_para_u8_to_u32(encrypted_data, rsa_RESULT, res_length);

	enable_module(BIT_PKI);

	if (rsa_mul_me(rsa_RESULT, res_length, rsa_D, ndigits_d, rsa_N, ndigits_n, rsa_RESULT, &res_length, CNST_RSA_EXP))
	{
		return false;
	}

	crypto_para_u32_to_u8(rsa_RESULT, output, res_length);
	*output_len = res_length * 4;

	return true;
}
