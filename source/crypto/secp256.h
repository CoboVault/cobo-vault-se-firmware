#ifndef SECP256K1_H_
#define SECP256K1_H_

#include <ecc.h>
extern const UINT32 SECP256K1_CURVE_LENGTH;
extern UINT32 SECP256K1_P[8];
extern UINT32 SECP256K1_a[8];
extern UINT32 SECP256K1_b[8];
extern UINT32 SECP256K1_N[8];
extern UINT32 SECP256K1_G_BaseX[8];
extern UINT32 SECP256K1_G_BaseY[8];

extern const UINT32 SECP256R1_CURVE_LENGTH;
extern UINT32 SECP256R1_P[8];
extern UINT32 SECP256R1_a[8];
extern UINT32 SECP256R1_b[8];
extern UINT32 SECP256R1_N[8];
extern UINT32 SECP256R1_G_BaseX[8];
extern UINT32 SECP256R1_G_BaseY[8];

extern const UINT32 ED25519_CURVE_LENGTH;
extern UINT32 ED25519_P[8];
extern UINT32 ED25519_a[8];
extern UINT32 ED25519_b[8];
extern UINT32 ED25519_N[8];
extern UINT32 ED25519_G_BaseX[8];
extern UINT32 ED25519_G_BaseY[8];

void ecc_utils_buffer_to_ecc_array(uint8_t *buffer, uint32_t *ecc_array, uint32_t ecc_array_len);
void ecc_utils_ecc_array_to_buffer(uint32_t *ecc_array, uint32_t ecc_array_len, uint8_t *buffer);

void secp256k1_init(void);
bool secp256k1_private_key_to_public_key(uint8_t *private_key, uint8_t *public_key_x, uint8_t *public_key_y);
void secp256k1_add_mod(uint8_t *a, uint8_t *b, uint8_t *output);
bool secp256k1_generate_valid_key(
    uint8_t *i_left,
    uint8_t *parent_private_key,
    uint8_t *result_key);

bool secp256k1_ecdsa_sign(
    uint8_t *hash,
    uint16_t hash_len,
    uint8_t *private_key,
    uint8_t *signature);
bool secp256k1_ecdsa_verify(
    uint8_t *hash,
    uint8_t *public_key,
    uint8_t *signature);

void secp256r1_init(void);
bool secp256r1_private_key_to_public_key(uint8_t *private_key, uint8_t *public_key_x, uint8_t *public_key_y);
void secp256r1_add_mod(uint8_t *a, uint8_t *b, uint8_t *output);
bool secp256r1_generate_valid_key(
    uint8_t *i_left,
    uint8_t *parent_private_key,
    uint8_t *result_key);

bool secp256r1_ecdsa_sign(
    uint8_t *hash,
    uint16_t hash_len,
    uint8_t *private_key,
    uint8_t *signature);
bool secp256r1_ecdsa_verify(
    uint8_t *hash,
    uint8_t *public_key,
    uint8_t *signature);

void ed25519_init(void);
bool ed25519_private_key_to_public_key(uint8_t *private_key, uint8_t *public_key_x, uint8_t *public_key_y);
#endif
