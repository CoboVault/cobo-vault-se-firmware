#ifndef ED25519_H
#define ED25519_H

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];

typedef unsigned char curve25519_key[32];

void ed25519_publickey(ed25519_secret_key sk, ed25519_public_key pk);
int ed25519_sign_open(unsigned char *m, size_t mlen, ed25519_public_key pk, ed25519_signature RS);
void ed25519_sign(unsigned char *m, size_t mlen, ed25519_secret_key sk, ed25519_public_key pk, ed25519_signature RS);

#if defined(__cplusplus)
}
#endif

#endif // ED25519_H
