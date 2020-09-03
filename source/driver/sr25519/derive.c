//
// This file is Scalar tooling base on schnorrkel
// https://github.com/w3f/schnorrkel.git
//
//

#include "merlin.h"
#include "ed25519-donna.h"
#include "sr25519_util.h"
#include "scalars.h"
#include "sr25519.h"
#include "ristretto-donna.h"
#include "keys.h"

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
    divide_scalar_bytes_by_cofactor(key_in, 32);

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
