/** libmerlin
 *
 * A single-file implementation of Merlin transcripts.
 *
 * Author: Henry de Valence <hdevalence@hdevalence.ca>
 *
 * Derived from keccak-tiny, with attribution note preserved below:
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */
#include "merlin.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sr25519_util.h"

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
static const uint8_t rho[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                                27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
static const uint64_t RC[24] = {1ULL,
                                0x8082ULL,
                                0x800000000000808aULL,
                                0x8000000080008000ULL,
                                0x808bULL,
                                0x80000001ULL,
                                0x8000000080008081ULL,
                                0x8000000000008009ULL,
                                0x8aULL,
                                0x88ULL,
                                0x80008009ULL,
                                0x8000000aULL,
                                0x8000808bULL,
                                0x800000000000008bULL,
                                0x8000000000008089ULL,
                                0x8000000000008003ULL,
                                0x8000000000008002ULL,
                                0x8000000000000080ULL,
                                0x800aULL,
                                0x800000008000000aULL,
                                0x8000000080008081ULL,
                                0x8000000000008080ULL,
                                0x80000001ULL,
                                0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
    v = 0;            \
    REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static /*inline*/ void keccakf(void *state)
{
    uint64_t *a = (uint64_t *)state;
    uint64_t b[5] = {0};
    uint64_t t = 0;
    uint8_t x, y;
    int i;

    for (i = 0; i < 24; i++)
    {
        /* Theta */
        FOR5(x, 1, b[x] = 0; FOR5(y, 5, b[x] ^= a[x + y];))
        FOR5(x, 1, FOR5(y, 5, a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);))
        /* Rho and pi */
        t = a[1];
        x = 0;
        REPEAT24(b[0] = a[pi[x]]; a[pi[x]] = rol(t, rho[x]); t = b[0]; x++;)
        /* Chi */
        FOR5(y, 5,
             FOR5(x, 1, b[x] = a[y + x];)
                 FOR5(x, 1, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);))
        /* Iota */
        a[0] ^= RC[i];
    }
}

/******** A Strobe-128 context; internal functions. ********/

#define STROBE_R 166

#define FLAG_I (1)
#define FLAG_A (1 << 1)
#define FLAG_C (1 << 2)
#define FLAG_T (1 << 3)
#define FLAG_M (1 << 4)
#define FLAG_K (1 << 5)

static /*inline*/ void strobe128_run_f(merlin_strobe128 *ctx)
{
    ctx->u.state_bytes[ctx->pos] ^= ctx->pos_begin;
    ctx->u.state_bytes[ctx->pos + 1] ^= 0x04;
    ctx->u.state_bytes[STROBE_R + 1] ^= 0x80;
    keccakf(ctx->u.state);
    ctx->pos = 0;
    ctx->pos_begin = 0;
}

static void strobe128_absorb(merlin_strobe128 *ctx,
                             const uint8_t *data,
                             size_t data_len)
{
    size_t i;
    for (i = 0; i < data_len; ++i)
    {
        ctx->u.state_bytes[ctx->pos] ^= data[i];
        ctx->pos += 1;
        if (ctx->pos == STROBE_R)
        {
            strobe128_run_f(ctx);
        }
    }
}

static void strobe128_overwrite(merlin_strobe128 *ctx,
                                const uint8_t *data,
                                size_t data_len)
{
    size_t i;
    for (i = 0; i < data_len; ++i)
    {
        ctx->u.state_bytes[ctx->pos] = data[i];
        ctx->pos += 1;
        if (ctx->pos == STROBE_R)
        {
            strobe128_run_f(ctx);
        }
    }
}

static void strobe128_squeeze(merlin_strobe128 *ctx, uint8_t *data, size_t data_len)
{
    size_t i;
    for (i = 0; i < data_len; ++i)
    {
        data[i] = ctx->u.state_bytes[ctx->pos];
        ctx->u.state_bytes[ctx->pos] = 0;
        ctx->pos += 1;
        if (ctx->pos == STROBE_R)
        {
            strobe128_run_f(ctx);
        }
    }
}

static /*inline*/ void strobe128_begin_op(merlin_strobe128 *ctx,
                                          uint8_t flags,
                                          uint8_t more)
{
    if (more)
    {
        /* Changing flags while continuing is illegal */
        return;
    }

    /* T flag is not supported */

    uint8_t old_begin = ctx->pos_begin;
    ctx->pos_begin = ctx->pos + 1;
    ctx->cur_flags = flags;

    uint8_t data[2] = {old_begin, flags};
    strobe128_absorb(ctx, data, 2);

    /* Force running the permutation if C or K is set. */
    uint8_t force_f = 0 != (flags & (FLAG_C | FLAG_K));

    if (force_f && ctx->pos != 0)
    {
        strobe128_run_f(ctx);
    }
}

/******** A Strobe-128 context; external (to Strobe) functions. ********/

static void strobe128_meta_ad(merlin_strobe128 *ctx,
                              const uint8_t *data,
                              size_t data_len,
                              uint8_t more)
{
    strobe128_begin_op(ctx, FLAG_M | FLAG_A, more);
    strobe128_absorb(ctx, data, data_len);
}

static void strobe128_ad(merlin_strobe128 *ctx,
                         const uint8_t *data,
                         size_t data_len,
                         uint8_t more)
{
    strobe128_begin_op(ctx, FLAG_A, more);
    strobe128_absorb(ctx, data, data_len);
}

static void strobe128_prf(merlin_strobe128 *ctx,
                          uint8_t *data,
                          size_t data_len,
                          uint8_t more)
{
    strobe128_begin_op(ctx, FLAG_I | FLAG_A | FLAG_C, more);
    strobe128_squeeze(ctx, data, data_len);
}

static void strobe128_key(merlin_strobe128 *ctx,
                          const uint8_t *data,
                          size_t data_len,
                          uint8_t more)
{
    strobe128_begin_op(ctx, FLAG_C | FLAG_A, more);
    strobe128_overwrite(ctx, data, data_len);
}

static void strobe128_init(merlin_strobe128 *ctx,
                           const uint8_t *label,
                           size_t label_len)
{
    uint8_t init[18] = {1, 168, 1, 0, 1, 96, 83, 84, 82,
                        79, 66, 69, 118, 49, 46, 48, 46, 50};
    memset(ctx->u.state_bytes, 0, 200);
    memcpy(ctx->u.state_bytes, init, 18);
    keccakf(ctx->u.state);
    ctx->pos = 0;
    ctx->pos_begin = 0;
    ctx->cur_flags = 0;

    strobe128_meta_ad(ctx, label, label_len, 0);
}

/******** The Merlin transcript functions. ********/

void merlin_transcript_init(merlin_transcript *mctx, const uint8_t *label, size_t label_len)
{
    uint8_t merlin_label[] = "Merlin v1.0";
    strobe128_init(&mctx->sctx, merlin_label, 11);
    merlin_transcript_commit_bytes(mctx, (uint8_t *)"dom-sep", 7, label, label_len);
}

void merlin_transcript_commit_bytes(merlin_transcript *mctx, const uint8_t *label, size_t label_len, const uint8_t *message, size_t message_len)
{
    uint64_t message_len_bytes = message_len;
    strobe128_meta_ad(&mctx->sctx, label, label_len, 0);
    strobe128_meta_ad(&mctx->sctx, (uint8_t *)&message_len_bytes, 4, 1);
    strobe128_ad(&mctx->sctx, message, message_len, 0);
}

void merlin_transcript_challenge_bytes(merlin_transcript *mctx, const uint8_t *label, size_t label_len, uint8_t *buffer, size_t buffer_len)
{
    uint64_t buffer_len_bytes = buffer_len;
    strobe128_meta_ad(&mctx->sctx, label, label_len, 0);
    strobe128_meta_ad(&mctx->sctx, (uint8_t *)&buffer_len_bytes, 4, 1);
    strobe128_prf(&mctx->sctx, buffer, buffer_len, 0);
}

void merlin_rng_init(merlin_rng *mrng, const merlin_transcript *mctx)
{
    memcpy(&mrng->sctx, &mctx->sctx, sizeof(merlin_strobe128));
    mrng->finalized = 0;
}

void merlin_rng_commit_witness_bytes(merlin_rng *mrng,
                                     const uint8_t *label,
                                     size_t label_len,
                                     const uint8_t *witness,
                                     size_t witness_len)
{
    uint64_t witness_len_bytes = witness_len;
    strobe128_meta_ad(&mrng->sctx, label, label_len, 0);
    strobe128_meta_ad(&mrng->sctx, (uint8_t *)&witness_len_bytes, 4, 1);
    strobe128_key(&mrng->sctx, witness, witness_len, 0);
}

void merlin_rng_finalize(merlin_rng *mrng, const uint8_t entropy[32])
{
    strobe128_meta_ad(&mrng->sctx, (uint8_t *)"rng", 3, 0);
    strobe128_key(&mrng->sctx, entropy, 32, 0);
    mrng->finalized = 1;
}

void merlin_rng_random_bytes(merlin_rng *mrng, uint8_t *buffer, size_t buffer_len)
{
    uint64_t buffer_len_bytes = buffer_len;
    strobe128_meta_ad(&mrng->sctx, (uint8_t *)&buffer_len_bytes, 4, 1);
    strobe128_prf(&mrng->sctx, buffer, buffer_len, 0);
}

void merlin_rng_wipe(merlin_rng *mrng)
{
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(&mrng->sctx, sizeof(merlin_strobe128));
#else
    memset(&mrng->sctx, 0, sizeof(merlin_strobe128));
#endif
}
