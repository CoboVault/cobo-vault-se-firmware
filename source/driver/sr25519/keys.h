//
// This file is Scalar tooling base on schnorrkel
// https://github.com/w3f/schnorrkel.git
//
//

#ifndef __SR25519_KEYS_H__
#define __SR25519_KEYS_H__

#include <stdint.h>
#include <stdlib.h>
#include "sr25519.h"

void private_key_to_publuc_key(sr25519_public_key public_key, sr25519_secret_key private_key);

#endif
