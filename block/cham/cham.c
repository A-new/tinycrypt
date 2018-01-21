/**
  Copyright (C) 2018 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#include "cham.h"

// initialize sub keys
void cham128_setkey(void *in, void *out)
{
    int i;
    uint32_t *k=(uint32_t*)in;
    uint32_t *rk=(uint32_t*)out;

    for (i=0; i<KW; i++) {
      rk[i] = k[i] ^ ROTL32(k[i], 1) ^ ROTL32(k[i], 8);
      rk[(i + KW) ^ 1] = k[i] ^ ROTL32(k[i], 1) ^ ROTL32(k[i], 11);
    }
}

// encrypt 128-bits
void cham128_encrypt(void *keys, void *data)
{
    int i;
    uint32_t x0, x1, x2, x3;
    uint32_t t;
    uint32_t *rk=(uint32_t*)keys;
    uint32_t *x=(uint32_t*)data;
    
    x0 = x[0]; x1 = x[1];
    x2 = x[2]; x3 = x[3];

    for (i=0; i<R; i++)
    {
      if ((i & 1) == 0) {
        x0 = ROTL32((x0 ^ i) + (ROTL32(x1, 1) ^ rk[i & 7]), 8);
      } else {
        x0 = ROTL32((x0 ^ i) + (ROTL32(x1, 8) ^ rk[i & 7]), 1);
      }
      XCHG(x0, x1);
      XCHG(x1, x2);
      XCHG(x2, x3);
    }
    x[0] = x0; x[1] = x1;
    x[2] = x2; x[3] = x3;
}

// decrypt 128-bits
void cham128_decrypt(void *keys, void *data)
{
    int i;
    uint32_t x0, x1, x2, x3;
    uint32_t t;
    uint32_t *rk=(uint32_t*)keys;
    uint32_t *x=(uint32_t*)data;

    x0 = x[0]; x1 = x[1];
    x2 = x[2]; x3 = x[3];

    for (i = R-1; i >=0 ; i--)
    {
      XCHG(x2, x3);      
      XCHG(x1, x2);
      XCHG(x0, x1);
      
      if ((i & 1) == 0) {
        x0 = (ROTR32(x0, 8) - ((ROTL32(x1, 1) ^ rk[i & 7]))) ^ i;
      } else {
        x0 = (ROTR32(x0, 1) - ((ROTL32(x1, 8) ^ rk[i & 7]))) ^ i;
      }
    }
    x[0] = x0; x[1] = x1;
    x[2] = x2; x[3] = x3;
}
