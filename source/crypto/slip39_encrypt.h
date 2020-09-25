//
//  encrypt.h
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdint.h>

#define BASE_ITERATION_COUNT 2500
#define ROUND_COUNT 4

/**
 * this is the round function described in the slip39 spec for the Fiestel network
 * it uses to encrypt/decrypt secrets with a passphrase
 *
 * inputs: i: round number
 *         passphrase: ascii encoded passphrase
 *         exp: exponent for the number of iterations of pbkd to run
 *         salt: array of bytes to use a salt for the encryption
 *         salt_lentgh: length of the salt array
 *         r: array of bytes to encrypt
 *         r_length: lenght of the r array
 *         dest: location to store encrypted value
 *         dest_length: maximum number of bytes to write to dest
 */
void round_function(
    uint8_t i,
    const char *passphrase,
    uint8_t exp,
    const uint8_t *salt,
    uint32_t salt_length,
    const uint8_t *r,
    uint32_t r_length,
    uint8_t *dest,
    uint32_t dest_length
);

/**
 * encrypts input using passphrase with the Fiestel network described in the slip39 spec
 *
 * inputs:  input: array of bytes to encrypt
 *          input_length: length of input array
 *          passphrase: null terminated ascii string
 *          iteration_exponent: exponent for the number of pbkd rounds to use
 *          identifier: identifier for the shard set (used as part of the salt)
 *          output: memory location to write output to (same length as the input)
 */
void slip39_encrypt(
    const uint8_t *input,
    uint32_t input_length,
    const char *passphrase,
    uint8_t iteration_exponent,
    uint16_t identifier,
    uint8_t *output
);

/**
 * decrypts input using passphrase with the Fiestel network described in the slip39 spec
 *
 * inputs:  input: array of bytes to decrypt
 *          input_length: length of input array
 *          passphrase: null terminated ascii string
 *          iteration_exponent: exponent for the number of pbkd rounds to use
 *          identifier: identifier for the shard set (used as part of the salt)
 *          output: memory location to write output to (same length as the input)
 */
void slip39_decrypt(
    const uint8_t *input,
    uint32_t input_length,
    const char *passphrase,
    uint8_t iteration_exponent,
    uint16_t identifier,
    uint8_t *output
);

#endif /* ENCRYPT_H */
