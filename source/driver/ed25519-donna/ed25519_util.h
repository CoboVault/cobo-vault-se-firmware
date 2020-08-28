#ifndef __ED25519_UTIL_H__
#define __ED25519_UTIL_H__

#include <sha2.h>
#include <hrng.h>

typedef SHA512_CTX ed25519_hash_context;

static void
ed25519_hash_init(ed25519_hash_context *ctx)
{
    sha512_Init(ctx);
}

static void
ed25519_hash_update(ed25519_hash_context *ctx, uint8_t *in, size_t inlen)
{
    sha512_Update(ctx, in, inlen);
}

static void
ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash)
{
    sha512_Final(ctx, hash);
}

static void
ed25519_hash(uint8_t *hash, uint8_t *in, size_t inlen)
{
    sha512_Raw(in, inlen, hash);
}

static void ed25519_randombytes_unsafe(void *p, size_t len)
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
