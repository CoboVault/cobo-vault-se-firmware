//
// This file is Scalar tooling base on schnorrkel
// https://github.com/w3f/schnorrkel.git
//
//

#include "keys.h"
#include "merlin.h"
#include "ed25519-donna.h"
#include "sr25519_util.h"
#include "scalars.h"
#include "ristretto-donna.h"

// Expand this `MiniSecretKey` into a `SecretKey`
void expand_uniform(sr25519_secret_key_key key, sr25519_secret_key_nonce nonce, sr25519_mini_secret_key mini_secret_key)
{
    merlin_transcript t = {0};

    merlin_transcript_init(&t, (uint8_t *)"ExpandSecretKeys", 16);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"mini", 4, mini_secret_key, 32);

    bignum256modm scalar = {0};
    uint8_t scalar_bytes[64] = {0};
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"sk", 2, scalar_bytes, 64);
    expand256_modm(scalar, scalar_bytes, 64);
    contract256_modm(key, scalar);
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"no", 2, nonce, 32);
}

// Expand this `MiniSecretKey` into a `SecretKey` using
// ed25519-style bit clamping.
void expand_ed25519(sr25519_secret_key_key key, sr25519_secret_key_nonce nonce, sr25519_mini_secret_key mini_secret_key)
{
    uint8_t hash[64] = {0};
    sr25519_hash(hash, mini_secret_key, 32);
    memcpy(key, hash, 32);
    key[0] &= 248;
    key[31] &= 63;
    key[31] |= 64;
    divide_scalar_bytes_by_cofactor(key, 32);
    key[31] &= 0x7F; //0b1111111;
    memcpy(nonce, hash + 32, 32);
}

void private_key_to_publuc_key(sr25519_public_key public_key, sr25519_secret_key private_key)
{
    ge25519 P = {0};
    bignum256modm s = {0};
    expand_raw256_modm(s, private_key);

    ge25519_scalarmult_base_niels(&P, ge25519_niels_base_multiples, s);
    ristretto_encode(public_key, P);
}

/**
* Generate a key pair.
*  keypair: keypair [32b key | 32b nonce | 32b public], output buffer of sr25519_keypair
*  mini_secret_key: generation seed - input buffer of sr25519_mini_secret_key
*/
void sr25519_keypair_from_seed(sr25519_keypair keypair, sr25519_mini_secret_key mini_secret_key)
{
    sr25519_secret_key_key secret_key_key = {0};
    sr25519_secret_key_nonce secret_key_nonce = {0};
    expand_ed25519(secret_key_key, secret_key_nonce, mini_secret_key);
    sr25519_public_key public_key = {0};
    private_key_to_publuc_key(public_key, secret_key_key);
    multiply_scalar_bytes_by_cofactor(secret_key_key, 32);

    memcpy(keypair, secret_key_key, 32);
    memcpy(keypair + 32, secret_key_nonce, 32);
    memcpy(keypair + 64, public_key, 32);
}
