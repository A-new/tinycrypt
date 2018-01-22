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
  
#include <stdio.h>
#include <stdint.h>

#include "macros.h"

#define S0 0
#define S1 1

typedef struct _seed_ctx {
  uint32_t kc[16];
  uint32_t ks[32];   
  union {
    uint32_t ss[1024];
    struct {    
      uint32_t ss0[256];
      uint32_t ss1[256];
      uint32_t ss2[256];
      uint32_t ss3[256];
    } x;
  };  
} seed_ctx;

typedef union _w32_t {
  uint8_t  b[4];
  uint32_t w;
} w32_t;

typedef union _w128_t {
  uint8_t  b[16];
  uint32_t w[4];
} w128_t;

// Matrix Multiplcation over GF(2)
uint8_t matmul(uint8_t idx, uint8_t x) 
{
    uint8_t i, r = 0;
    uint8_t *p;
    
    uint8_t a1[8]=
    { 0xE2, 0x58, 0x44, 0x41, 
      0xC2, 0x69, 0xD0, 0x2C };
    
    uint8_t a2[8]=
    { 0x6C, 0xA2, 0x30, 0x21, 
      0x2C, 0xE1, 0x2A, 0xD0 };
      
    p = (idx==S0) ? a1 : a2;
    
    for (i=0; i<8; i++) {      
      if (x & (1 << (7 - i))) {
        r ^= p[i];
      }
    }    
    return r;
}

// Multiplication over GF(2)
uint8_t gf_mul(uint8_t x, uint8_t y)
{
    uint8_t r = 0;

    while (y) {
      if (y & 1) {
        r ^= x;
      }
      x = (x + x) ^ (x & 0x80 ? 0x63 : 0x00);
      y >>= 1;
    }
    return r;
}

// Exponentiation over GF(2)
uint8_t gf_exp(uint8_t x, uint8_t n)
{
    uint8_t i, r = 1;
    
    for (i=0; i<n; i++) {
      r = gf_mul(r, x);
    }
    return r;
}

// Function G
uint32_t G(seed_ctx *c, uint32_t x) {  
  return (c->x.ss0[ (x) & 0xFF] ^ 
          c->x.ss1[((x) >> 8) & 0xFF] ^ 
          c->x.ss2[((x) >> 16) & 0xFF] ^ 
          c->x.ss3[((x) >> 24) & 0xFF]);
}

// Round function F
#define F(k0, k1, r0, r1, t0, t1) \
{ \
   t1 = (r0 ^ k0) ^ (r1 ^ k1); \
   t1 = G(t1); \
   t0 = t1 + (r0 ^ k0); \
   t0 = G(t0); \
   t1 += t0; \
   t1 = G(t1); \
   t0 += t1; \
}

void seed_init(seed_ctx *c, void *key)
{
    int i, x;
    uint32_t t;
    uint32_t k0, k1, k2, k3;
    w128_t *k=(w128_t*)key;
    uint8_t s1, s2;
    w32_t sa, sb;
    
    // The 128-bit input key is divided into four 32-bit blocks
    k0 = SWAP32(k->w[0]);
    k1 = SWAP32(k->w[1]);
    k2 = SWAP32(k->w[2]);
    k3 = SWAP32(k->w[3]);

    // generate KC values    
    for (i=0; i<16; i++) {
      c->kc[i] = ROTL32(0x9e3779b9, i);
    }
    
    // generate extended sbox arrays
    for (x=0; x<256; x++) {
      s1 = matmul(S0, gf_exp(x, 0xF7)) ^ 0xA9;
      s2 = matmul(S1, gf_exp(x, 0xFB)) ^ 0x38;
      
      for (i=0; i<4; i++) { 
        sa.b[i] = s1;
        sb.b[i] = s2;
      }
      
      c->x.ss0[x] = sa.w & SWAP32(0xFCF3CF3F);
      c->x.ss2[x] = sa.w & SWAP32(0xCF3FFCF3);      
      c->x.ss3[x] = sb.w & SWAP32(0x3FFCF3CF);           
      c->x.ss1[x] = sb.w & SWAP32(0xF3CF3FFC);           
    } 
    
    // Apply 16 rounds
    for (i=0; i<16; i++)
    {
      t = k0 + k2 - c->kc[i];
      c->ks[2 * i] = G(c, t);
      
      t = k1 - k3 + c->kc[i];
      c->ks[2 * i + 1] = G(c, t);

      // Odd round?
      if((i % 2) != 0) {
         t  = (k3 << 8) | (k2 >> 24);
         k2 = (k2 << 8) | (k3 >> 24);
         k3 = t;
      }
      // Even round?
      else {
         t = (k1 >> 8) | (k0 << 24);
         k0 = (k0 >> 8) | (k1 << 24);
         k1 = t;
      }
    }
}

void seed_encrypt(seed_ctx *c, void *in, void *out)
{
   int      i;
   uint32_t t0, t1, x0, x1, x2, x3;
   w32_t    *x=(w32_t*)in;
   
   // The 128-bit input is divided into two 64-bit blocks (L and R)
   x0 = SWAP32(x->w[0]); x1 = SWAP32(x->w[1]);
   x2 = SWAP32(x->w[2]); x3 = SWAP32(x->w[3]);

   // Perform 16 rounds
   for (i=0; i<16; i++)
   {
      // Apply function F
      F(ks[0], ks[1], x2, x3, t0, t1);

      t0 ^= x0;
      t1 ^= x1;
      XCHG();
      x0 = x2;
      x1 = x3;
      right0 = temp0;
      right1 = temp1;
   }

   // The resulting value is the ciphertext
   x->w[0] = SWAP32(right0);
   x->w[1] = SWAP32(right1);
   x->w[2] = SWAP32(left0);
   x->w[3] = SWAP32(left1);
}

int main(void)
{  
    int      x, y, z, i, j;
    uint8_t  m0=0xfc, m1=0xf3, m2=0xcf, m3=0x3f;
    seed_ctx c;
    uint8_t key[16];
    
    seed_init(&c, key);
    
    /**
    putchar('\n');

    for (i=0; i<256; i++) {
      if ((i & 7) == 0) putchar('\n');
      printf ("%02X, ", s1[i]);
    }
    
    putchar('\n');

    for (i=0; i<256; i++) {
      if ((i & 7) == 0) putchar('\n');
      printf ("%02X, ", s2[i]);
    }*/
    
   
    
    for (i=0; i<4; i++) {
      printf("\n//S-Box SS%i\nstatic const uint32_t ss%i[256] = \n{\n", i, i);
      for (j=0; j<256; j++) {
        if ((j & 7)==0) putchar('\n');
        printf ("0x%08X, ", c.ss[i*256+j]);      
      }
      printf("};");
    }
    
    return 0;
}

/*
// multiplcation by matrix over GF(2)
uint8_t matmul(uint8_t mat[8][8], uint8_t a) {
    uint8_t z, res = 0;
    int x, y;
    uint8_t t[8]=
    { 0xE2, 0x58, 0x44, 0x41, 
      0xC2, 0x69, 0xD0, 0x2C };
    
    for (x=0; x<8; x++) {
      if (a & (1 << (7 - x))) {
        res ^= t[x];
      }
    }    
    return res;
}

    putchar('\n');

    for (i=0; i<256; i++) {
      if ((i & 7) == 0) putchar('\n');
      printf ("%02X, ", s0[i]);
    }
    
    putchar('\n');

    for (i=0; i<256; i++) {
      if ((i & 7) == 0) putchar('\n');
      printf ("%02X, ", s1[i]);
    }
    
*/
