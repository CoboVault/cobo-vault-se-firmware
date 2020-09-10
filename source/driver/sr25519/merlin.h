//
// This file is base on libmerlin
// https://github.com/hdevalence/libmerlin.git
//

#ifndef MERLIN_H
#define MERLIN_H
#define __STDC_WANT_LIB_EXT1__ 1
#include <stdint.h>
#include <stdlib.h>

/* XXX can these be made opaque without malloc? */

typedef struct merlin_strobe128_
{
  /* XXX endianness */
  union
  {
    uint64_t state[25];
    uint8_t state_bytes[200];
  } u;
  uint8_t pos;
  uint8_t pos_begin;
  uint8_t cur_flags;
} merlin_strobe128;

typedef struct merlin_transcript_
{
  merlin_strobe128 sctx;
} merlin_transcript;

typedef struct merlin_rng_
{
  merlin_strobe128 sctx;
  uint8_t finalized;
} merlin_rng;

void merlin_transcript_init(merlin_transcript *mctx,
                            const uint8_t *label,
                            size_t label_len);

void merlin_transcript_commit_bytes(merlin_transcript *mctx,
                                    const uint8_t *label,
                                    size_t label_len,
                                    const uint8_t *data,
                                    size_t data_len);

void merlin_transcript_challenge_bytes(merlin_transcript *mctx,
                                       const uint8_t *label,
                                       size_t label_len,
                                       uint8_t *buffer,
                                       size_t buffer_len);

void merlin_rng_init(merlin_rng *mrng, const merlin_transcript *mctx);

void merlin_rng_commit_witness_bytes(merlin_rng *mrng,
                                     const uint8_t *label,
                                     size_t label_len,
                                     const uint8_t *witness,
                                     size_t witness_len);

void merlin_rng_finalize(merlin_rng *mrng, const uint8_t entropy[32]);

void merlin_rng_random_bytes(merlin_rng *mrng, uint8_t *buffer, size_t buffer_len);

void merlin_rng_wipe(merlin_rng *mrng);

#endif
