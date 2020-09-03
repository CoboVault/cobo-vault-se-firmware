//
// This file is Scalar tooling base on schnorrkel
// https://github.com/w3f/schnorrkel.git
//
//

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "merlin.h"
#include "scalars.h"
#include "keys.h"
#include "ristretto-donna.h"
#include "sr25519.h"
#include "sr25519_util.h"

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
    divide_scalar_bytes_by_cofactor(secret_key, 32);

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
