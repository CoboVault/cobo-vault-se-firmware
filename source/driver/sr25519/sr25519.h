#ifndef __SR25519_H__
#define __SR25519_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef uint8_t sr25519_mini_secret_key[32];
typedef uint8_t sr25519_secret_key[64];
typedef uint8_t sr25519_secret_key_key[32];
typedef uint8_t sr25519_secret_key_nonce[32];
typedef uint8_t sr25519_chain_code[32];
typedef uint8_t sr25519_public_key[32];
typedef uint8_t sr25519_keypair[96];
typedef uint8_t sr25519_signature[64];

void sr25519_derive_keypair_hard(sr25519_keypair derived, const sr25519_keypair keypair, const sr25519_chain_code chain_code);
void sr25519_derive_keypair_soft(sr25519_keypair derived, const sr25519_keypair keypair, const sr25519_chain_code chain_code);
void sr25519_derive_public_soft(sr25519_public_key derived_public, const sr25519_public_key public, const sr25519_chain_code chain_code);
void sr25519_keypair_from_seed(sr25519_keypair keypair, sr25519_mini_secret_key seed);
void sr25519_sign(sr25519_signature signature, const sr25519_public_key public, const sr25519_secret_key secret, const uint8_t *message, unsigned long message_length);
bool sr25519_verify(const sr25519_signature signature, const uint8_t *message, unsigned long message_length, const sr25519_public_key public);

#endif
