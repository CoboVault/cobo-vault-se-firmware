//
//  encrypt.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//
#include <string.h>
#include <stdio.h>
#include <slip39_encrypt.h>
#include <pbkdf2.h>
//////////////////////////////////////////////////
// encrypt/decrypt
//

// #include <openssl/evp.h>
// #include <openssl/sha.h>
// crypto.h used for the version
// #include <openssl/crypto.h>

static const uint8_t customization[] = {
    's', 'h', 'a', 'm', 'i', 'r',
};

int32_t _get_salt(    uint16_t identifier, uint8_t *result, uint32_t result_length);
void feistel(uint8_t forward, const uint8_t *input, uint32_t input_length, const char *passphrase,
    uint8_t iteration_exponent, uint16_t identifier, uint8_t *output);

int32_t _get_salt(
    uint16_t identifier,
    uint8_t *result,
    uint32_t result_length
) {
    if(result_length < 8) {
        return -1;
    }

    for(unsigned int i=0; i<6; ++i) {
        result[i] = customization[i];
    }

    result[6] = identifier >> 8;
    result[7] = identifier & 0xff;
    return 8;
}

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
) {
    uint32_t pass_length = (uint32_t)strlen(passphrase) + 1;
    uint8_t pass[pass_length+2];
    sprintf( (char *) (pass+1), "%s", passphrase);
    pass[0] = i;
    uint32_t iterations = BASE_ITERATION_COUNT << exp;
    uint8_t saltr[salt_length + r_length];

    memcpy(saltr, salt, salt_length);
    memcpy(saltr+salt_length, r, r_length);

    pbkdf2_hmac_sha256(pass, pass_length,
                       saltr, salt_length+r_length,
                       iterations,
                       dest, dest_length);
}

void feistel(
    uint8_t forward,
    const uint8_t *input,
    uint32_t input_length,
    const char *passphrase,
    uint8_t iteration_exponent,
    uint16_t identifier,
    uint8_t *output
) {
    uint32_t half_length = input_length / 2;
    uint8_t *l, *r, *t, f[half_length];
    uint8_t salt[8];

    memcpy(output, input+half_length, half_length);
    memcpy(output + half_length, input, half_length);

    r = output;
    l = output+half_length;

    _get_salt(identifier, salt, 8);

    for(uint8_t i=0; i<ROUND_COUNT; ++i) {
        uint8_t index;
        if(forward) {
            index = i;
        } else {
            index = ROUND_COUNT-1-i;
        }
        round_function(index, passphrase, iteration_exponent, salt, 8, r, half_length, f, half_length);
        t = l;
        l = r;
        r = t;
        for(uint32_t j=0; j<half_length; ++j) {
            r[j] = r[j] ^ f[j];
        }
    }
}

void slip39_encrypt(
    const uint8_t *input,
    uint32_t input_length,
    const char *passphrase,
    uint8_t iteration_exponent,
    uint16_t identifier,
    uint8_t *output
) {
    feistel(1, input, input_length, passphrase, iteration_exponent, identifier, output);
}

void slip39_decrypt(
    const uint8_t *input,
    uint32_t input_length,
    const char *passphrase,
    uint8_t iteration_exponent,
    uint16_t identifier,
    uint8_t *output
) {
    feistel(0, input, input_length, passphrase, iteration_exponent, identifier, output);
}
