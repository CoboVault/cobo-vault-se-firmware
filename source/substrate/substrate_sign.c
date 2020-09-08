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
#include "stdlib.h"
#include "stdio.h"
#include "substrate_sign.h"
#include "mason_wallet.h"
#include "mason_hdw.h"
#include "bip44.h"
//#include "blake2b.h"

bool mini_secret_from_entropy(sr25519_mini_secret_key seed)
{
    wallet_seed_t seedFromEntropy = {0};

    if ((E_HDWM_PASSPHRASE == gemHDWSwitch) && (SHA512_LEN == passphrase_seedFromEntropy.length))
    {
        memcpy(&seedFromEntropy, &passphrase_seedFromEntropy, sizeof(wallet_seed_t));
    }
    else if (!mason_seedFromEntropy_read(&seedFromEntropy))
    {
        return false;
    }
    memcpy(seed, seedFromEntropy.data, 32);
    return true;
}

bool from_bip39_phrase(sr25519_keypair keypair)
{
    sr25519_mini_secret_key seed = {0};
    if (!mini_secret_from_entropy(seed))
    {
        return false;
    }
    sr25519_keypair_from_seed(keypair, seed);
    return true;
}

bool encode_to(uint32_t input, uint8_t *dest, uint32_t *dest_len)
{
    if (input <= 0x63 /*0b00111111*/)
    {
        dest[0] = input << 2;
        *dest_len = 1;
    }
    else
    {
        return false;
    }
    return true;
}

bool using_encode(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len)
{
    uint8_t dest[4] = {0};
    uint32_t dest_len = 0;

    if (!encode_to(in_len, dest, &dest_len))
    {
        return false;
    }

    if (dest_len > 4)
    {
        return false;
    }
    memcpy(out, dest, dest_len);
    memcpy(out + dest_len, in, in_len);
    *out_len = in_len + dest_len;

    return true;
}

void cc_from_path_item_soft(const uint8_t *pItem, uint32_t itemlen, sr25519_chain_code cc_out)
{
    sr25519_chain_code cc = {0};
    uint8_t data[MAX_SURI_PATH_LEN + 4] = {0};
    uint32_t data_len = 0;

    using_encode(pItem, itemlen, data, &data_len);

    if (data_len > 32)
    {
        //uint8_t hash[32] = {0};
        //blake2b(data, data_len, hash, 32);
        //memcpy(cc, hash, 32);
        return;
    }
    else
    {
        memcpy(cc, data, data_len);
    }
    memcpy(cc_out, cc, 32);
}

void cc_from_path_item(const uint8_t *pItem, uint32_t itemlen, bool is_hard, sr25519_chain_code cc_out)
{
    if (0)
    {
        // number
        //cc_from_path_item_soft(number)
    }
    else
    {
        // something else
        cc_from_path_item_soft(pItem, itemlen, cc_out);
    }

    if (is_hard)
    {
        //
    }
}

bool parse_suri_path(uint8_t *path, uint32_t pathlen, suri_path_t *suriPath)
{
    char cSlash = '/';
    uint32_t cSlashCount = 0;
    uint32_t index = 0;

    if ((NULL == path) || (0 == pathlen) || (pathlen > MAX_SURI_PATH_LEN))
    {
        return false;
    }

    suriPath->depth = 0;

    while ((index < pathlen) && (cSlash == path[index++]))
    {
        uint32_t path_index = 0;
        if (suriPath->depth >= SURI_DEPTH)
        {
            break;
        }

        cSlashCount++;

        if (cSlash == path[index])
        {
            continue;
        }
        if ((cSlashCount > 2) || (index >= pathlen))
        {
            break; // password or invalid
        }
        path_index = index;
        while ((index < pathlen) && (cSlash != path[index]))
        {
            index++;
        }
        suriPath->item[suriPath->depth].is_hard = (2 == cSlashCount);
        cc_from_path_item((path + path_index), (index - path_index),
                          suriPath->item[suriPath->depth].is_hard, suriPath->item[suriPath->depth].cc);
        suriPath->depth++;
        cSlashCount = 0;
    }

    return true;
}

void public_key_to_fingerprint(public_key_t *public_key, uint8_t *fingerprint, uint16_t fingerprint_len)
{
    uint8_t hash256[SHA256_LEN] = {0};
    uint8_t ripemd160_buf[RPMD160_LEN] = {0};
    compressed_public_key_t compressed_public_key;

    public_key_to_compressed_public_key(public_key, &compressed_public_key);

    sha256_api(compressed_public_key.data, COMPRESSED_PUBLIC_KEY_LEN, hash256);

    ripeMD160_api(hash256, SHA256_LEN, ripemd160_buf);

    memcpy(fingerprint, ripemd160_buf, fingerprint_len);
}

bool derive_from_suri(uint8_t *path, uint32_t pathlen, sr25519_keypair keypair, extended_key_t *extended_key)
{
    uint8_t depth = 0;
    suri_path_t suriPath = {0};
    sr25519_keypair bip39_pair = {0};
    sr25519_keypair child_pair = {0};
    sr25519_keypair parent_pair = {0};

    if (!parse_suri_path(path, pathlen, &suriPath))
    {
        return false;
    }

    if (!from_bip39_phrase(bip39_pair))
    {
        return false;
    }

    memcpy(parent_pair, bip39_pair, 96);
    memcpy(child_pair, bip39_pair, 96);
    while (depth < suriPath.depth)
    {
        public_key_t public_key = {0};
        memcpy(public_key.data, parent_pair + 64, 32);
        public_key.len = 32;
        public_key_to_fingerprint(&public_key, extended_key->fingerprint, sizeof(extended_key->fingerprint));
        if (suriPath.item[depth].is_hard)
        {
            // hard derive
            sr25519_derive_keypair_hard(child_pair, parent_pair, suriPath.item[depth].cc);
        }
        else
        {
            // soft derive
            sr25519_derive_keypair_soft(child_pair, parent_pair, suriPath.item[depth].cc);
        }

        memcpy(parent_pair, child_pair, 96);
        memcpy(extended_key->chaincode, suriPath.item[depth].cc, CHAINCODE_LEN);
        depth++;
    }
    memcpy(keypair, child_pair, 96);

    public_key_t public_key = {0};
    compressed_public_key_t compressed_public_key = {0};
    uint8_t checksum[SHA256_LEN] = {0};

    u32_to_buf(extended_key->version, SF_VB_INT_MNET_PUB);

    extended_key->depth = suriPath.depth;

    u32_to_buf(extended_key->child_number, 0x00);

    memcpy(public_key.data, keypair + 64, 32);
    public_key.len = 32;
    public_key_to_compressed_public_key(&public_key, &compressed_public_key);
    memcpy(extended_key->key, compressed_public_key.data, COMPRESSED_PUBLIC_KEY_LEN);

    mason_HDW_gen_sha256sha256((uint8_t *)extended_key, sizeof(extended_key_t) - sizeof(extended_key->checksum), checksum, SHA256_LEN);
    memcpy(extended_key->checksum, checksum, 4);

    return true;
}

bool substrate_sign(uint8_t *suri, uint32_t suri_len, uint8_t *message, uint32_t message_len,
                    sr25519_signature signature, uint16_t *sign_len, public_key_t *pubkey)
{
    sr25519_keypair keypair = {0};
    sr25519_public_key public = {0};
    sr25519_secret_key secret = {0};
    extended_key_t extkey = {0};

    if (!derive_from_suri(suri, suri_len, keypair, &extkey))
    {
        return false;
    }

    memcpy(secret, keypair, 64);
    memcpy(public, keypair + 64, 32);

    sr25519_sign(signature, public, secret, message, message_len);

    memcpy(pubkey->data, public, 32);
    pubkey->len = 32;
    *sign_len = 64;
    return true;
}

bool substrate_derive_extpubkey(uint8_t *suri, uint32_t suri_len, extended_key_t *extpublic)
{
    bool ret = false;
    sr25519_keypair keypair = {0};

    ret = derive_from_suri(suri, suri_len, keypair, extpublic);
    memset(keypair, 0, 32);

    return ret;
}
