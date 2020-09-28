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
/** Header file reference */
#include <mason_key.h>
#include <util.h>
#include <crypto_api.h>
#include <secp256.h>

/** Function implementations */
/**
 * @functionname: ckd_private_to_private
 * @description: 
 * @para: 
 * @return: 
 */
bool ckd_private_to_private(
    crypto_curve_t curve,
    private_key_t *parent_private_key,
    chaincode_t *parent_chaincode,
    uint32_t index,
    private_key_t *child_private_key,
    chaincode_t *child_chaincode)
{
    bool is_succeed = true;
    uint8_t data[COMPRESSED_PUBLIC_KEY_LEN + sizeof(uint32_t)] = {0};
    uint16_t data_len = COMPRESSED_PUBLIC_KEY_LEN + sizeof(uint32_t);
    compressed_public_key_t parent_compressed_public_key;
    uint8_t hmac_sha512_buf[SHA512_LEN];
    uint8_t *i_left = NULL;
    uint8_t *i_right = NULL;
    uint8_t derived_private_key[PRIVATE_KEY_LEN];

    if (index >= 0x80000000)
    {
        // hardened child
        data[0] = 0x00;
        memcpy(data + 1, parent_private_key->data, PRIVATE_KEY_LEN);
    }
    else
    {
        // normal child
        if (curve == CRYPTO_CURVE_ED25519)
        {
            return false;
        }
        private_key_to_compressed_public_key(curve, parent_private_key, &parent_compressed_public_key);
        memcpy(data, parent_compressed_public_key.data, COMPRESSED_PUBLIC_KEY_LEN);
    }

    // debug_key("DATA", data, data_len);

    while (true)
    {
        u32_to_buf(data + COMPRESSED_PUBLIC_KEY_LEN, index);
        hmac_sha512_api(
            data,
            data_len,
            parent_chaincode->data,
            CHAINCODE_LEN,
            hmac_sha512_buf);

        i_left = hmac_sha512_buf;
        i_right = hmac_sha512_buf + PRIVATE_KEY_LEN;

        // generate child private key
        switch (curve)
        {
        case CRYPTO_CURVE_ED25519:
        {
            memcpy(derived_private_key, i_left, PRIVATE_KEY_LEN);
            break;
        }
        case CRYPTO_CURVE_SECP256K1:
        {
            if (!secp256k1_generate_valid_key(i_left, parent_private_key->data, derived_private_key))
            {
                index++;
                continue;
            }
            break;
        }
        case CRYPTO_CURVE_SECP256R1:
        {
            if (!secp256r1_generate_valid_key(i_left, parent_private_key->data, derived_private_key))
            {
                data[0] = 0x01;
                memcpy(data + 1, i_right, PRIVATE_KEY_LEN);
                continue;
            }
            break;
        }
        default:
        {
            return false;
        }
        }

        memcpy(child_private_key->data, derived_private_key, PRIVATE_KEY_LEN);
        memcpy(child_chaincode->data, i_right, CHAINCODE_LEN);
        break;
    }
    return is_succeed;
}
/**
 * @functionname: ckd_private_to_public
 * @description: 
 * @para: 
 * @return: 
 */
bool ckd_private_to_public(
    private_key_t *parent_private_key,
    chaincode_t *parent_chaincode,
    uint32_t index,
    public_key_t *child_public_key,
    chaincode_t *child_chaincode)
{
    return true;
}
/**
 * @functionname: private_key_to_public_key
 * @description: 
 * @para: 
 * @return: 
 */
void private_key_to_public_key(
    crypto_curve_t curve,
    private_key_t *private_key,
    public_key_t *public_key)
{
    public_key->len = PUBLIC_KEY_LEN;
    if (curve == CRYPTO_CURVE_SECP256K1)
    {
        secp256k1_private_key_to_public_key(private_key->data,
                                            public_key->data,
                                            public_key->data + PUBLIC_KEY_LEN / 2);
    }
    else if (curve == CRYPTO_CURVE_SECP256R1)
    {
        secp256r1_private_key_to_public_key(private_key->data,
                                            public_key->data,
                                            public_key->data + PUBLIC_KEY_LEN / 2);
    }
    else if (curve == CRYPTO_CURVE_ED25519)
    {
        ed25519_private_key_to_public_key(private_key->data, public_key->data);
        public_key->len = PUBLIC_KEY_LEN / 2;
    }
}
/**
 * @functionname: public_key_to_compressed_public_key
 * @description: 
 * @para: 
 * @return: 
 */
void public_key_to_compressed_public_key(
    public_key_t *public_key,
    compressed_public_key_t *compressed_public_key)
{
    if (public_key->len == PUBLIC_KEY_LEN)
    {
        if (public_key->data[PUBLIC_KEY_LEN - 1] & 0x01)
        {
            compressed_public_key->data[0] = 0x03;
        }
        else
        {
            compressed_public_key->data[0] = 0x02;
        }
    }
    else
    {
        compressed_public_key->data[0] = 0x00;
    }
    memcpy(compressed_public_key->data + 1, public_key->data, PUBLIC_KEY_LEN / 2);
}
/**
 * @functionname: private_key_to_compressed_public_key
 * @description: 
 * @para: 
 * @return: 
 */
void private_key_to_compressed_public_key(
    crypto_curve_t curve,
    private_key_t *private_key,
    compressed_public_key_t *compressed_public_key)
{
    public_key_t public_key;
    private_key_to_public_key(curve, private_key, &public_key);
    public_key_to_compressed_public_key(&public_key, compressed_public_key);
}
/**
 * @functionname: private_key_to_fingerprint
 * @description: 
 * @para: 
 * @return: 
 */
void private_key_to_fingerprint(
    crypto_curve_t curve,
    private_key_t *private_key,
    uint8_t *fingerprint,
    uint16_t fingerprint_len)
{
    uint8_t hash256[SHA256_LEN] = {0};
    uint8_t ripemd160_buf[RPMD160_LEN] = {0};
    compressed_public_key_t compressed_public_key;
    // printf("COMPRESS PUB\n");
    private_key_to_compressed_public_key(curve, private_key, &compressed_public_key);

    // debug_key("Fingerprint compress", compressed_public_key.data, COMPRESSED_PUBLIC_KEY_LEN);

    // printf("SHA256\n");
    sha256_api(compressed_public_key.data, COMPRESSED_PUBLIC_KEY_LEN, hash256);
    // printf("RIPE160\n");
    ripeMD160_api(hash256, SHA256_LEN, ripemd160_buf);

    // printf("OUTPUT\n");
    memcpy(fingerprint, ripemd160_buf, fingerprint_len);
}
