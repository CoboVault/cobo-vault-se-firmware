#ifndef __SR25519_UTIL_H__
#define __SR25519_UTIL_H__

#include <sha2.h>
#include <hrng.h>

//sr25519_hash
typedef SHA512_CTX sr25519_hash_context;

static void
sr25519_hash_init(sr25519_hash_context *ctx)
{
    sha512_Init(ctx);
}

static void
sr25519_hash_update(sr25519_hash_context *ctx, uint8_t *in, size_t inlen)
{
    sha512_Update(ctx, in, inlen);
}

static void
sr25519_hash_final(sr25519_hash_context *ctx, uint8_t *hash)
{
    sha512_Final(ctx, hash);
}

static void
sr25519_hash(uint8_t *hash, uint8_t *in, size_t inlen)
{
    sha512_Raw(in, inlen, hash);
}

//sr25519_randombytes
static void sr25519_randombytes(void *p, size_t len)
{
    size_t i = 0;
    uint8_t *out = (uint8_t *)p;
    hrng_initial();
    for (i = 0; i < len; i++)
    {
        out[i] = get_hrng8();
    }
    return;
}
#endif
