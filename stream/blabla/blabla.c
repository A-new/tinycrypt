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

// transforms block using ARX instructions
void blabla_permute(bb20_blk *blk, uint16_t idx) 
{
    uint64_t a, b, c, d;
    uint64_t *x=(uint64_t*)&blk->b;
    
    a = (idx         & 0xF);
    b = ((idx >>  4) & 0xF);
    c = ((idx >>  8) & 0xF);
    d = ((idx >> 12) & 0xF);
    
    x[a] += x[b]; 
    x[d] = ROTR64(x[d] ^ x[a], 32);
    
    x[c] += x[d]; 
    x[b] = ROTR64(x[b] ^ x[c], 24);
    
    x[a] += x[b]; 
    x[d] = ROTR64(x[d] ^ x[a], 16);
    
    x[c] += x[d]; 
    x[b] = ROTL64(x[b] ^ x[c],  1);
}

// generate stream of bytes
void bb20_stream (bb20_ctx *c, bb20_blk *x)
{
    int i, j;

    // 16-bit integers of each index
    uint16_t idx16[8]=
    { 0xC840, 0xD951, 0xEA62, 0xFB73, 
      0xFA50, 0xCB61, 0xD872, 0xE943 };
    
    // copy state to x
    memcpy(x->b, c->b, BB20_STATE_LEN);

    // apply 20 rounds
    for (i=0; i<20; i+=2) {
      for (j=0; j<8; j++) {
        blabla_permute(x, idx16[j]);
      }
    }
    // add state to x
    for (i=0; i<16; i++) {
      x->q[i] += c->q[i];
    }
    // update block counter
    c->q[13]++;
}

// encrypt or decrypt stream of len-bytes
void bb20_encrypt (uint64_t len, void *in, bb20_ctx *ctx) 
{
    uint64_t r, i;
    bb20_blk stream;
    uint8_t  *p=(uint8_t*)in;
    
    while (len) {      
      bb20_stream(ctx, &stream);
      
      r=(len>BB20_BLK_LEN) ? BB20_BLK_LEN : len;
      
      // xor input with stream
      for (i=0; i<r; i++) {
        p[i] ^= stream.b[i];
      }
    
      len -= r;
      p += r;
    }
}

// generate key stream of len-bytes
void bb20_keystream(uint64_t len, void *out, bb20_ctx *c) 
{
    memset(out, 0, len);       // zero initialize output
    bb20_encrypt(len, out, c); // encrypt it
}

#ifdef TEST

#include <stdio.h>

uint8_t bb_tv[]={
  173, 80, 254, 123, 103, 188, 241, 234, 16, 130, 154, 201, 95, 
  86, 3, 99, 72, 175, 218, 238, 238, 136, 184, 20, 133, 42, 
  223, 58, 55, 33, 216, 12, 166, 112, 185, 55, 193, 11, 119, 227, 
  146, 58, 124, 149, 74, 197, 80, 118, 0, 218, 217, 174, 61, 137, 
  91, 97, 40, 16, 211, 53, 189, 200, 89, 37, 141, 101, 46, 178, 2, 
  88, 27, 29, 13, 78, 105, 28, 101, 122, 99, 76, 252, 86, 87, 240, 
  169, 109, 187, 179, 192, 248, 16, 51, 90, 208, 222, 25, 0, 61, 
  209, 146, 176, 15, 28, 175, 43, 125, 235, 39, 67, 125, 251, 218, 
  135, 66, 3, 219, 156, 251, 221, 170, 137, 26, 84, 134, 231, 202, 
  116, 30, 126, 12, 146, 166, 195, 17, 233, 23, 50, 126, 236, 147, 
  63, 218, 165, 117, 37, 218, 219, 175, 191, 69, 142, 246, 98, 178, 
  17, 228, 142, 61, 231, 209, 67, 50, 195, 31, 217, 83, 25, 170, 233, 
  222, 82, 119, 102, 13, 94, 187, 62, 169, 14, 233, 217, 116, 190, 
  169, 178, 44, 38, 158, 186, 231, 118, 233, 236, 192, 108, 123, 
  105, 234, 169, 98, 208, 139, 87, 190, 110, 59, 114, 166, 114, 68, 
  174, 94, 192, 24, 47, 9, 149, 219, 84, 153, 231, 24, 148, 202, 204, 
  210, 238, 37, 156, 78, 239, 45, 42, 80, 144, 38, 182, 156, 240, 47, 
  170, 99, 8, 114, 35, 202, 242, 241, 198, 102, 21, 239, 48, 72, 43, 
  224, 29, 79, 215, 132, 82, 79, 224, 241, 161, 20, 190, 241, 81, 148, 
  70, 148, 88, 107, 47, 30, 5, 41, 226, 224, 81, 95, 96, 50, 159, 96, 
  221, 242, 17, 214, 22, 109, 12, 153, 96, 196, 6, 102, 109, 90 };

int main(void)
{
    uint8_t  key[BB20_KEY_LEN];
    uint8_t  nonce[BB20_NONCE_LEN]={0};
    int      i, equ;
    uint8_t  stream[300];
    bb20_ctx c;
    
    for (i=0; i<BB20_KEY_LEN; i++) {
      key[i] = (uint8_t)i;
    }
    
    bb20_setkey(&c, key, nonce);
    bb20_keystream(sizeof(stream), stream, &c);
    
    equ = memcmp(stream, bb_tv, sizeof(bb_tv))==0;

    printf ("\nBlaBla Test %s\n", equ?"PASSED":"FAILED");  
    return 0;
}

#endif
