#include <string.h>
#include "sr25519.h"
#include "ristretto-donna.h"
#include "merlin.h"
#include "sr25519_util.h"

void divide_scalar_bytes_by_cofactor(uint8_t *scalar, size_t scalar_len)
{
    uint8_t low = 0;

    for (int i = scalar_len - 1; i >= 0; i--)
    {
        uint8_t r = scalar[i] & (0x07); // 0b00000111
        scalar[i] >>= 3;
        scalar[i] += low;
        low = r << 5;
    }
}

void multiply_scalar_bytes_by_cofactor(uint8_t *scalar, size_t scalar_len)
{
    uint8_t high = 0;

    for (int i = 0; i < scalar_len; i++)
    {
        uint8_t r = scalar[i] & (0xE0); // 0b11100000
        scalar[i] <<= 3;
        scalar[i] += high;
        high = r >> 5;
    }
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

// Vaguely BIP32-like "hard" derivation of a `MiniSecretKey` from a `SecretKey`
void hard_derive_mini_secret_key(sr25519_mini_secret_key key_out, sr25519_chain_code chain_code_out, const sr25519_mini_secret_key key_in, const sr25519_chain_code chain_code_in)
{
    merlin_transcript t = {0};

    merlin_transcript_init(&t, (uint8_t *)"SchnorrRistrettoHDKD", 20);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, (uint8_t *)"", 0);
    if (chain_code_in != NULL)
    {
        merlin_transcript_commit_bytes(&t, (uint8_t *)"chain-code", 10, chain_code_in, 32);
    }
    merlin_transcript_commit_bytes(&t, (uint8_t *)"secret-key", 10, key_in, 32);
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"HDKD-hard", 9, key_out, 32);
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"HDKD-chaincode", 14, chain_code_out, 32);
}

// Derive a mutating scalar and new chain code from a public key and chain code.
void derive_scalar_and_chaincode(merlin_transcript *t, bignum256modm *scalar, sr25519_chain_code chain_code_out, const sr25519_public_key public, const sr25519_chain_code chain_code_in)
{
    if (chain_code_in != NULL)
    {
        merlin_transcript_commit_bytes(t, (uint8_t *)"chain-code", 10, chain_code_in, 32);
    }
    merlin_transcript_commit_bytes(t, (uint8_t *)"public-key", 10, public, 32);

    uint8_t buf[64] = {0};
    merlin_transcript_challenge_bytes(t, (uint8_t *)"HDKD-scalar", 11, buf, 64);
    expand256_modm(*scalar, buf, 64);

    merlin_transcript_challenge_bytes(t, (uint8_t *)"HDKD-chaincode", 14, chain_code_out, 32);
}

void derived_secret_key_simple(sr25519_secret_key_key key_out, sr25519_secret_key_nonce nonce_out, sr25519_chain_code chain_code_out, const sr25519_public_key public, const sr25519_secret_key_key key_in, const sr25519_secret_key_nonce nonce_in, const sr25519_chain_code chain_code_in)
{
    merlin_transcript t = {0};

    merlin_transcript_init(&t, (uint8_t *)"SchnorrRistrettoHDKD", 20);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, (uint8_t *)"", 0);

    bignum256modm scalar = {0};

    derive_scalar_and_chaincode(&t, &scalar, chain_code_out, public, chain_code_in);

    bignum256modm original_scalar = {0};
    bignum256modm final_scalar = {0};
    expand_raw256_modm(original_scalar, key_in);
    add256_modm(final_scalar, original_scalar, scalar);
    contract256_modm(key_out, final_scalar);

    uint8_t witness_data[64] = {0};
    memcpy(witness_data, key_in, 32);
    memcpy(witness_data + 32, nonce_in, 32);

    merlin_rng mrng = {0};
    merlin_rng_init(&mrng, &t);
    merlin_rng_commit_witness_bytes(&mrng, (uint8_t *)"HDKD-nonce", 10, nonce_in, 32);
    merlin_rng_commit_witness_bytes(&mrng, (uint8_t *)"HDKD-nonce", 10, witness_data, 64);

    uint8_t entropy[32] = {0};
    sr25519_randombytes(entropy, 32);
    merlin_rng_finalize(&mrng, entropy);
    merlin_rng_random_bytes(&mrng, nonce_out, 32);
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
    //multiply_scalar_bytes_by_cofactor(secret_key_key, 32);

    memcpy(keypair, secret_key_key, 32);
    memcpy(keypair + 32, secret_key_nonce, 32);
    memcpy(keypair + 64, public_key, 32);
}

void sr25519_uniform_keypair_from_seed(sr25519_keypair keypair, sr25519_mini_secret_key mini_secret_key)
{
    sr25519_secret_key_key secret_key_key = {0};
    sr25519_secret_key_nonce secret_key_nonce = {0};
    expand_ed25519(secret_key_key, secret_key_nonce, mini_secret_key);
    sr25519_public_key public_key = {0};
    private_key_to_publuc_key(public_key, secret_key_key);

    memcpy(keypair, secret_key_key, 32);
    memcpy(keypair + 32, secret_key_nonce, 32);
    memcpy(keypair + 64, public_key, 32);
}

void sr25519_keypair_ed25519_to_uniform(sr25519_keypair uniform_keypair, const sr25519_keypair ed25519_keypair)
{
    sr25519_secret_key_key secret_key_key = {0};
    memcpy(secret_key_key, ed25519_keypair, 32);
    divide_scalar_bytes_by_cofactor(secret_key_key, 32);

    memcpy(uniform_keypair, secret_key_key, 32);
    memcpy(uniform_keypair + 32, ed25519_keypair + 32, 64);
}


/**
* Perform a derivation on a secret
*  keypair_out: pre-allocated output buffer of sr25519_keypair
*  keypair_in: existing keypair - input buffer of sr25519_keypair
*  chain_code_in: chaincode - input buffer of sr25519_chain_code
*/
void sr25519_derive_keypair_hard(sr25519_keypair keypair_out, const sr25519_keypair keypair_in, const sr25519_chain_code chain_code_in)
{
    sr25519_mini_secret_key key_in = {0};
    memcpy(key_in, keypair_in, 32);
    //divide_scalar_bytes_by_cofactor(key_in, 32);

    sr25519_mini_secret_key key_out = {0};
    sr25519_chain_code chain_code_out = {0};

    hard_derive_mini_secret_key(key_out, chain_code_out, key_in, chain_code_in);

    sr25519_keypair_from_seed(keypair_out, key_out);
}

/**
* Perform a derivation on a secret
*  keypair_out: pre-allocated output buffer of sr25519_keypair
*  keypair_in: existing keypair - input buffer of sr25519_keypair
*  chain_code_in: chaincode - input buffer of sr25519_chain_code
*/
void sr25519_derive_keypair_soft(sr25519_keypair keypair_out, const sr25519_keypair keypair_in, const sr25519_chain_code chain_code_in)
{
    sr25519_secret_key_key key_in = {0};
    memcpy(key_in, keypair_in, 32);
    divide_scalar_bytes_by_cofactor(key_in, 32);
    sr25519_secret_key_nonce nonce_in = {0};
    memcpy(nonce_in, keypair_in + 32, 32);
    sr25519_public_key public = {0};
    memcpy(public, keypair_in + 64, 32);

    sr25519_secret_key_key key_out = {0};
    sr25519_secret_key_nonce nonce_out = {0};
    sr25519_public_key public_out = {0};
    sr25519_chain_code chain_code_out = {0};

    derived_secret_key_simple(key_out, nonce_out, chain_code_out, public, key_in, nonce_in, chain_code_in);

    private_key_to_publuc_key(public_out, key_out);
    multiply_scalar_bytes_by_cofactor(key_out, 32);

    memcpy(keypair_out, key_out, 32);
    memcpy(keypair_out + 32, nonce_out, 32);
    memcpy(keypair_out + 64, public_out, 32);
}

/**
* Perform a derivation on a publicKey
*  public_out: pre-allocated output buffer of sr25519_public_key
*  public_in: public key - input buffer of sr25519_public_key
*  chain_code_in: chaincode - input buffer of sr25519_chain_code
*/
void sr25519_derive_public_soft(sr25519_public_key public_out, const sr25519_public_key public_in, const sr25519_chain_code chain_code_in)
{
    merlin_transcript t = {0};

    merlin_transcript_init(&t, (uint8_t *)"SchnorrRistrettoHDKD", 20);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, (uint8_t *)"", 0);

    bignum256modm scalar = {0};
    uint8_t chain_code_out[32] = {0};
    derive_scalar_and_chaincode(&t, &scalar, chain_code_out, public_in, chain_code_in);

    ge25519 P1 = {0}, P2 = {0}, P = {0};
    ge25519_scalarmult_base_niels(&P1, ge25519_niels_base_multiples, scalar);
    ristretto_decode(&P2, public_in);
    ge25519_add(&P, &P1, &P2);
    ristretto_encode(public_out, P);
}

/**
* Sign a message
* The combination of both public and private key must be provided.
* This is effectively equivalent to a keypair.
*  signature_out: output buffer of sr25519_signature
*  public: public key - input buffer of sr25519_public_key
*  secret: private key (secret) - input buffer of sr25519_secret_key
*  message: Arbitrary message; input buffer of message
*  message_length: Length of a message
*/
void sr25519_sign(sr25519_signature signature_out, const sr25519_public_key public, const sr25519_secret_key secret, const uint8_t *message, unsigned long message_length)
{
    sr25519_secret_key_key secret_key = {0};
    sr25519_secret_key_nonce secret_nonce = {0};
    memcpy(secret_key, secret, 32);
    memcpy(secret_nonce, secret + 32, 32);
    //divide_scalar_bytes_by_cofactor(secret_key, 32);

    merlin_transcript t = {0};
    merlin_transcript_init(&t, (uint8_t *)"SigningContext", 14);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"", 0, (uint8_t *)"substrate", 9);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, message, message_length);

    merlin_transcript_commit_bytes(&t, (uint8_t *)"proto-name", 10, (uint8_t *)"Schnorr-sig", 11);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign:pk", 7, public, 32);

    bignum256modm r = {0};
    uint8_t scalar_bytes[64] = {0};
    merlin_rng mrng = {0};
    merlin_rng_init(&mrng, &t);
    merlin_rng_commit_witness_bytes(&mrng, (uint8_t *)"signing", 7, secret_nonce, 32);
    uint8_t entropy[32] = {0};
    sr25519_randombytes(entropy, 32);
    merlin_rng_finalize(&mrng, entropy);
    merlin_rng_random_bytes(&mrng, scalar_bytes, 32);
    expand256_modm(r, scalar_bytes, 64);

    ge25519 R = {0};
    ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
    uint8_t R_compressed[32] = {0};
    ristretto_encode(R_compressed, R);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign:R", 6, R_compressed, 32);

    bignum256modm k = {0};
    uint8_t buf[64] = {0};
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"sign:c", 6, buf, 64);
    expand256_modm(k, buf, 64);

    bignum256modm secret_key_scalar = {0};
    expand_raw256_modm(secret_key_scalar, secret_key);

    bignum256modm k_secret_key_scalar = {0};
    mul256_modm(k_secret_key_scalar, k, secret_key_scalar);

    bignum256modm s = {0};
    add256_modm(s, k_secret_key_scalar, r);

    uint8_t s_bytes[32] = {0};
    contract256_modm(s_bytes, s);

    memcpy(signature_out, R_compressed, 32);
    memcpy(signature_out + 32, s_bytes, 32);
    signature_out[63] |= 128;
}

/**
* Verify a message and its corresponding against a public key;
*  signature: verify this signature
*  message: Arbitrary message; input buffer of message
*  message_length: Message size
*  public: verify with this public key; input buffer of sr25519_public_key
*  returned true if signature is valid, false otherwise
*/
bool sr25519_verify(const sr25519_signature signature, const uint8_t *message, unsigned long message_length, const sr25519_public_key public)
{
    uint8_t signature_s[32] = {0};
    memcpy(signature_s, signature + 32, 32);

    if ((signature_s[31] & 128) == 0)
    {
        return false;
    }

    signature_s[31] &= 127;
    if ((signature_s[31] & 240) == 0)
    {
        signature_s[31] &= 0x7F; //0b01111111;
    }

    if ((signature_s[31] >> 7) != 0)
    {
        return false;
    }

    signature_s[31] &= 0x7F; //0b01111111;

    uint8_t signature_R[32] = {0};
    memcpy(signature_R, signature, 32);

    merlin_transcript t = {0};
    merlin_transcript_init(&t, (uint8_t *)"SigningContext", 14);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"", 0, (uint8_t *)"substrate", 9);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign-bytes", 10, message, message_length);

    merlin_transcript_commit_bytes(&t, (uint8_t *)"proto-name", 10, (uint8_t *)"Schnorr-sig", 11);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign:pk", 7, public, 32);
    merlin_transcript_commit_bytes(&t, (uint8_t *)"sign:R", 6, signature_R, 32);

    bignum256modm k = {0}, s = {0};
    uint8_t buf[64] = {0};
    merlin_transcript_challenge_bytes(&t, (uint8_t *)"sign:c", 6, buf, 64);
    expand256_modm(k, buf, 64);
    expand_raw256_modm(s, signature_s);

    int is_canonical = is_reduced256_modm(s);

    if (!is_canonical)
    {
        return false;
    }

    ge25519 A = {0}, R = {0};
    ristretto_decode(&A, public);
    curve25519_neg(A.x, A.x);
    curve25519_neg(A.t, A.t);
    ge25519_double_scalarmult_vartime(&R, &A, k, s);

    uint8_t R_compressed[32] = {0};
    ristretto_encode(R_compressed, R);
    uint8_t valid = uint8_32_ct_eq(R_compressed, signature_R);

    return valid;
}

