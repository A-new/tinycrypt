/**
  Copyright © 2017 Odzhan. All Rights Reserved.

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
  
#include "blabla.h"

// setup the key
void bb20_setkey(bb20_ctx *c, void *key, void *nonce)
{
    c->q[ 0] = 0x6170786593810fab;
    c->q[ 1] = 0x3320646ec7398aee;
    c->q[ 2] = 0x79622d3217318274;
    c->q[ 3] = 0x6b206574babadada;

    memcpy (&c->b[32], key, BB20_KEY_LEN);
    
    c->q[ 8] = 0x2ae36e593e46ad5f;
    c->q[ 9] = 0xb68f143029225fc9;
    c->q[10] = 0x8da1e08468303aa6;
    c->q[11] = 0xa48a209acd50a4a7;
    c->q[12] = 0x7fdc12f23f90778c;
    
    c->q[13] = 1; // set counter
    
    c->q[14] = ((uint64_t*)nonce)[0];
    c->q[15] = ((uint64_t*)nonce)[1];
}

// permutation function from blake2b
void F(uint64_t s[16])
{
    int         i;
    uint64_t    a, b, c, d, t, idx;
    uint32_t    r;
    
    uint16_t idx16[8]=
    { 0xC840, 0xD951, 0xEA62, 0xFB73,    // column index
      0xFA50, 0xCB61, 0xD872, 0xE943 };  // diagonal index
    
    for (i=0; i<8; i++) {
      idx = idx16[i];
        
      a = (idx         & 0xF);
      b = ((idx >>  4) & 0xF);
      c = ((idx >>  8) & 0xF);
      d = ((idx >> 12) & 0xF);
  
      r = 0x3F101820;
      
      // The quarter-round
      do {
        s[a]+= s[b]; 
        s[d] = ROTR64(s[d] ^ s[a], r & 0xFF);
        XCHG(c, a);
        XCHG(d, b);
        r >>= 8;
      } while (r != 0);
    }    
}

// generate stream of bytes
void bb20_stream (bb20_ctx *c, w1024_t *x)
{
    int i;

    // copy state to x
    memcpy(x->b, c->b, BB20_STATE_LEN);
    
    // apply 20 rounds of permutation function
    for (i=0; i<20; i+=2) {
      F(x->q);
    }
    // add state to x
    for (i=0; i<16; i++) {
      x->q[i] += c->q[i];
    }
    // update 64-bit counter
    c->q[13]++;
}


// encrypt or decrypt stream of len-bytes
void bb20_encrypt (uint64_t len, void *in, bb20_ctx *ctx) 
{
    uint64_t r, i;
    w1024_t  s;
    uint8_t  *p=(uint8_t*)in;
    
    while (len) {      
      bb20_stream(ctx, &s);
      
      r = MIN(len, BB20_BLK_LEN);
      
      // XOR input with stream
      for (i=0; i<r; i++) {
        p[i] ^= s.b[i];
      }
    
      len -= r;
      p   += r;
    }
}

// generate key stream of len-bytes
void bb20_keystream(uint64_t len, void *out, bb20_ctx *c) 
{
    memset(out, 0, len);       // zero initialize output
    bb20_encrypt(len, out, c); // encrypt it
}
