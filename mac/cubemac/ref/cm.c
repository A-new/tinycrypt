/*
20081110
D. J. Bernstein
Public domain.
*/

#include "parameters.h"
#include "cubehash.h"

#define ROTATE(a,b) (((a) << (b)) | ((a) >> (32 - b)))

static void transform(hashState *state)
{
  int i;
  int r;
  crypto_uint32 y[16];

  for (r = 0;r < CUBEHASH_ROUNDS;++r) {
    for (i = 0;i < 16;++i) state->x[i + 16] += state->x[i];
    for (i = 0;i < 16;++i) y[i ^ 8] = state->x[i];
    for (i = 0;i < 16;++i) state->x[i] = ROTATE(y[i],7);
    for (i = 0;i < 16;++i) state->x[i] ^= state->x[i + 16];
    for (i = 0;i < 16;++i) y[i ^ 2] = state->x[i + 16];
    for (i = 0;i < 16;++i) state->x[i + 16] = y[i];
    for (i = 0;i < 16;++i) state->x[i + 16] += state->x[i];
    for (i = 0;i < 16;++i) y[i ^ 4] = state->x[i];
    for (i = 0;i < 16;++i) state->x[i] = ROTATE(y[i],11);
    for (i = 0;i < 16;++i) state->x[i] ^= state->x[i + 16];
    for (i = 0;i < 16;++i) y[i ^ 1] = state->x[i + 16];
    for (i = 0;i < 16;++i) state->x[i + 16] = y[i];
  }
}

HashReturn Init(hashState *state)
{
  int i;
  int j;

  state->hashbitlen = 128;
  for (i = 0;i < 32;++i) state->x[i] = 0;
  state->x[0] = 128 / 8;
  state->x[1] = 32;
  state->x[2] = 16;
  // apply initial 16 rounds
  transform(state);
  state->pos = 0;
  return SUCCESS;
}

HashReturn Update(hashState *state, const BitSequence *data,
                  DataLength databitlen)
{
  /* caller promises us that previous data had integral number of bytes */
  /* so state->pos is a multiple of 8 */

  while (databitlen >= 8) {
    crypto_uint32 u = *data;
    u <<= 8 * ((state->pos / 8) % 4);
    state->x[state->pos / 32] ^= u;
    data += 1;
    databitlen -= 8;
    state->pos += 8;
    if (state->pos == 8 * 32) {
      transform(state);
      state->pos = 0;
    }
  }
  if (databitlen > 0) {
    crypto_uint32 u = *data;
    u <<= 8 * ((state->pos / 8) % 4);
    state->x[state->pos / 32] ^= u;
    state->pos += databitlen;
  }
  return SUCCESS;
}

HashReturn Final(hashState *state, BitSequence *hashval)
{
  int i;
  crypto_uint32 u;

  u = (128 >> (state->pos % 8));
  u <<= 8 * ((state->pos / 8) % 4);
  state->x[state->pos / 32] ^= u;
  transform(state);
  state->x[31] ^= 1;
  // apply final 32 rounds
  transform(state);
  transform(state);  
  for (i = 0;i < state->hashbitlen / 8;++i) 
    hashval[i] = state->x[i / 4] >> (8 * (i % 4));

  return SUCCESS;
}
