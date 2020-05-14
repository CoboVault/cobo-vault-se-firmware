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
#include "sha256.h"
#include "sha384.h"
#include "RipeMD160.h"
#include "hmac.h"
#include "sm2.h"
#include "ge.h"
#include "mason_util.h"

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
	ed25519_init();
	crypto_api_sm2_init();
	return true;
}
/**
 * @functionname: u32_to_buff
 * @description: 
 * @para: 
 * @return: 
 */
void u32_to_buff(uint32_t u32, uint8_t *buf)
{
	buf[0] = (uint8_t)(u32 >> 24);
	buf[1] = (uint8_t)(u32 >> 16);
	buf[2] = (uint8_t)(u32 >> 8);
	buf[3] = (uint8_t)(u32);
}
/**
 * @functionname: myatoui
 * @description: 
 * @para: 
 * @return: 
 */
unsigned int myatoui(const char *str)
{
	unsigned int n = 0;

	while (!isdigit(*str))
		++str;

	while (isdigit(*str))
	{
		int c;
		c = *str - '0';
		/* compare with n and MAX/10 , if n>MAX/10 (also consider of n=MAX/10) , data will overflow */
		if ((n > UINT_MAX / 10) || ((n == UINT_MAX / 10) && (c >= UINT_MAX % 10)))
		{
			return UINT_MAX;
		}
		n = n * 10 + c;
		++str;
	}
	return n;
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
	SHA256_hash((UINT8 *)pData, (UINT32)len, (UINT8 *)pDigest);
}
/**
 * @functionname: sha512_api
 * @description: 
 * @para: 
 * @return: 
 */
CRYPTO_API_EXT void sha512_api(uint8_t *pData, uint32_t len, uint8_t *pDigest)
{
	SHA512_hash((UINT8 *)pData, (UINT32)len, (UINT8 *)pDigest);
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
	hmac_sha512(pData, dataLen, pKey, keyLen, pDigest);
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
	return	!(signature[0] & 0x80)
		 && !(signature[0] == 0 &&  !(signature[1] & 0x80)) 
		 && !(signature[32] & 0x80) 
		 && !(signature[32] == 0 && !(signature[33] & 0x80));
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
		uint8_t fake_private_key[64];
		uint8_t public_key[32];
		*signature_len = 64;
		enable_module(BIT_PKI);
		ed25519_create_keypair(public_key, fake_private_key, private_key);
		enable_module(BIT_PKI);
		ed25519_sign(signature, hash, hash_len, public_key, fake_private_key);
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

const int SM2_CURVE_LEN_IN_BIT = 256;
const int SM2_CURVE_LEN_IN_BYTE = SM2_CURVE_LEN_IN_BIT / 8;
const int SM2_CURVE_LEN_IN_WORD = SM2_CURVE_LEN_IN_BYTE / 4;
static UINT32 SM2_N[8] = {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7203DF6B, 0x21C6052B, 0x53BBF409, 0x39D54123};
static UINT32 SM2_a[8] = {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFC};
static UINT32 SM2_b[8] = {0x28E9FA9E, 0x9D9F5E34, 0x4D5A9E4B, 0xCF6509A7, 0xF39789F5, 0x15AB8F92, 0xDDBCBD41, 0x4D940E93};
static UINT32 SM2_P[8] = {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF};
static UINT32 SM2_BaseX[8] = {0x32C4AE2C, 0x1F198119, 0x5F990446, 0x6A39C994, 0x8FE30BBF, 0xF2660BE1, 0x715A4589, 0x334C74C7};
static UINT32 SM2_BaseY[8] = {0xBC3736A2, 0xF4F6779C, 0x59BDCEE3, 0x6B692153, 0xD0A9877C, 0xC62A4740, 0x02DF32E5, 0x2139F0A0};

static ECC_G_STR ecc_sm2_glb_str;
// static MATH_G_STR math_sm2_glb_str;
static SM2_CRYPT_CTX sm2_context;
static SM3_CTX sm3_context;
/**
 * @functionname: crypto_api_sm2_init
 * @description: 
 * @para: 
 * @return: 
 */
void crypto_api_sm2_init()
{
	static bool has_inited = false;

	if (!has_inited)
	{
		sm2_swap_array(SM2_N, SM2_CURVE_LEN_IN_WORD);
		sm2_swap_array(SM2_a, SM2_CURVE_LEN_IN_WORD);
		sm2_swap_array(SM2_b, SM2_CURVE_LEN_IN_WORD);
		sm2_swap_array(SM2_P, SM2_CURVE_LEN_IN_WORD);
		sm2_swap_array(SM2_BaseX, SM2_CURVE_LEN_IN_WORD);
		sm2_swap_array(SM2_BaseY, SM2_CURVE_LEN_IN_WORD);

		has_inited = true;
	}

	ECC_para_initial(
		&ecc_sm2_glb_str,
		SM2_CURVE_LEN_IN_WORD,
		SM2_P,
		SM2_a,
		SM2_b,
		SM2_N,
		SM2_BaseX,
		SM2_BaseY);
}
/**
 * @functionname: crypto_api_sm2_encrypt
 * @description: 
 * @para: 
 * @return: 
 */
bool crypto_api_sm2_encrypt(uint8_t *public_key, uint8_t *data, uint16_t data_len)
{
	return true;
}
/**
 * @functionname: crypto_api_sm2_decrypt
 * @description: 
 * @para: 
 * @return: 
 */
bool crypto_api_sm2_decrypt(uint8_t *private_key, uint8_t *encrypted_data, uint32_t encrypted_data_len, uint8_t *output, uint32_t *output_len)
{
	uint8_t *c1;
	uint8_t *c2;
	uint8_t *c3;

	bool is_succeed = false;

	if (encrypted_data_len <= 96)
	{
		return false;
	}

	crypto_api_sm2_init();

	encrypted_data = encrypted_data + 1;
	encrypted_data_len--;

	c1 = encrypted_data;
	c3 = c1 + 64;
	c2 = c3 + 32;

	*output_len = encrypted_data_len - 96;

	is_succeed = (0 == sm2_decrypt(
						   &ecc_sm2_glb_str,
						   &sm2_context,
						   &sm3_context,
						   (uint8_t *)private_key,
						   c1,
						   c2,
						   c3,
						   *output_len,
						   output,
						   SM2_NORMAL));

	return is_succeed;
}
/**
 * @functionname: ed25519_public_key
 * @description: 
 * @para: 
 * @return: 
 */
bool ed25519_public_key(uint8_t *private_key, uint8_t *public_key)
{
	uint8_t hash[SHA512_LEN] = {0};
	ge_p3 A;

	sha512_api(private_key, 32, hash);

	hash[0] &= 248;
	hash[31] &= 63;
	hash[31] |= 64;

	ge_scalarmult_base(&A, hash);
	ge_p3_tobytes(public_key, &A);

	return true;
}
