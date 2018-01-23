/**
  Copyright © 2016 Odzhan. All Rights Reserved.

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
  
#include "s20.h"

// setup the key, must be 256-bits with 64-bit nonce
void s20_setkey(s20_ctx *c, void *key, void *nonce)
{
    w64_t  *iv=(w64_t*)nonce;
    w256_t *k=(w256_t*)key;
    
    c->w[ 0] = 0x61707865;
    // copy lower 128-bits of key
    memcpy(&c->b[4], k->b, 16);
    c->w[ 5] = 0x3320646E;
    // set 64-bit nonce
    c->w[ 6] = iv->w[0]; c->w[ 7] = iv->w[1];
    // set 64-bit counter
    c->w[ 8] = 0; c->w[ 9] = 0;
    c->w[10] = 0x79622D32;
    // copy upper 128-bits of key
    memcpy(&c->b[44], &k->b[16], 16);
    c->w[15] = 0x6B206574;
}

void F(uint32_t s[16])
{
    int      i;
    uint32_t a, b, c, d, r, t, idx;
    
   // 16-bit integers of each index
    uint16_t idx16[8]=
    { 0xC840, 0x1D95, 0x62EA, 0xB73F,     // column index
      0x3210, 0x4765, 0x98BA, 0xEDCF };   // diagonal index
    
    for (i=0; i<8; i++) {
      idx = idx16[i];
        
      a = (idx         & 0xF);
      b = ((idx >>  4) & 0xF);
      c = ((idx >>  8) & 0xF);
      d = ((idx >> 12) & 0xF);
  
      s[b] ^= ROTL32((s[a] + s[d]), 7);
      s[c] ^= ROTL32((s[b] + s[a]), 9);

      s[d] ^= ROTL32((s[c] + s[b]),13);
      s[a] ^= ROTL32((s[d] + s[c]),18);
    }    
}

// generate stream of bytes
void s20_stream (s20_ctx *c, w512_t *x)
{
    int i;

    // copy state to x
    memcpy(x->b, c->b, 64);
    // apply 20 rounds
    for (i=0; i<20; i+=2) {
      F(x->w);
    }
    // add state to x
    for (i=0; i<16; i++) {
      x->w[i] += c->w[i];
    }
    // update block counter
    c->q[4]++;
    // stopping at 2^70 bytes per nonce is user's responsibility
}

// encrypt or decrypt stream of bytes
void s20_encrypt (uint32_t len, void *buf, s20_ctx *c) 
{
    uint32_t r, i;
    w512_t   s;
    uint8_t  *p=(uint8_t*)buf;
    
    while (len) {      
      s20_stream(c, &s);
      
      r = MIN(len, S20_BLK_LEN);
      
      for (i=0; i<r; i++) {
        p[i] ^= s.b[i];
      }      
      len -= r;
      p   += r;
    }
}
