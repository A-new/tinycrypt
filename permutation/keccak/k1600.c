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

#include "keccak.h"

void k1600_permutex(void *state);

// round constant function
// Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1
uint64_t rc (uint8_t *LFSR)
{
    uint64_t c;
    uint32_t i, t;

    c = 0;
    t = *LFSR;
    
    for (i=1; i<128; i += i) 
    {
      if (t & 1) {
        c ^= (uint64_t)1ULL << (i - 1);
      }
      t = (t & 0x80) ? (t << 1) ^ 0x71 : t << 1;
    }
    *LFSR = (uint8_t)t;
    return c;
}

void k1600_permute (void *state)
{
    uint32_t i, j, rnd;
    uint64_t t, u, bc[5];
    uint8_t  r, lfsr=1;
    uint64_t *st=(uint64_t*)state;
  
    uint8_t p[24] = 
    { 10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 
      15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1  };
      
    uint8_t m[9] = 
    { 0, 1, 2, 3, 4, 0, 1, 2, 3};
  
    for (rnd=0; rnd<24; rnd++) {
      // Theta
      for (i=0; i<5; i++) {
        t  = st[i   ];
        t ^= st[i+ 5];      
        t ^= st[i+10];      
        t ^= st[i+15];      
        t ^= st[i+20];
        bc[i] = t;
      }
      for (i=0; i<5; i++) {
        t  = bc[m[(i + 4)]]; 
        t ^= ROTL64(bc[m[(i + 1)]], 1);
        for (j=i; j<25; j+=5) {
          st[j] ^= t;
        }
      }
      // Rho + Pi
      u = st[1];
      for (i=0, r=0; i<24; i++) {
        r += i + 1;
        u  = ROTL64(u, r & 63);
        XCHG(st[p[i]], u);
        bc[0] = u;
      }
      // Chi
      for (i=0; i<25; i+=5) {
        memcpy(&bc, &st[i], 5*8);
        for (j=0; j<5; j++) {
          t  = ~bc[m[(j + 1)]];
          t &=  bc[m[(j + 2)]];
          st[j + i] ^= t;
        }
      }
      // Iota
      st[0] ^= rc(&lfsr);
    }
}

#ifdef TEST

#include <stdio.h>

uint8_t tv1[]={
  0xe7,0xdd,0xe1,0x40,0x79,0x8f,0x25,0xf1,
  0x8a,0x47,0xc0,0x33,0xf9,0xcc,0xd5,0x84,
  0xee,0xa9,0x5a,0xa6,0x1e,0x26,0x98,0xd5,
  0x4d,0x49,0x80,0x6f,0x30,0x47,0x15,0xbd,
  0x57,0xd0,0x53,0x62,0x05,0x4e,0x28,0x8b,
  0xd4,0x6f,0x8e,0x7f,0x2d,0xa4,0x97,0xff,
  0xc4,0x47,0x46,0xa4,0xa0,0xe5,0xfe,0x90,
  0x76,0x2e,0x19,0xd6,0x0c,0xda,0x5b,0x8c,
  0x9c,0x05,0x19,0x1b,0xf7,0xa6,0x30,0xad,
  0x64,0xfc,0x8f,0xd0,0xb7,0x5a,0x93,0x30,
  0x35,0xd6,0x17,0x23,0x3f,0xa9,0x5a,0xeb,
  0x03,0x21,0x71,0x0d,0x26,0xe6,0xa6,0xa9,
  0x5f,0x55,0xcf,0xdb,0x16,0x7c,0xa5,0x81,
  0x26,0xc8,0x47,0x03,0xcd,0x31,0xb8,0x43,
  0x9f,0x56,0xa5,0x11,0x1a,0x2f,0xf2,0x01,
  0x61,0xae,0xd9,0x21,0x5a,0x63,0xe5,0x05,
  0xf2,0x70,0xc9,0x8c,0xf2,0xfe,0xbe,0x64,
  0x11,0x66,0xc4,0x7b,0x95,0x70,0x36,0x61,
  0xcb,0x0e,0xd0,0x4f,0x55,0x5a,0x7c,0xb8,
  0xc8,0x32,0xcf,0x1c,0x8a,0xe8,0x3e,0x8c,
  0x14,0x26,0x3a,0xae,0x22,0x79,0x0c,0x94,
  0xe4,0x09,0xc5,0xa2,0x24,0xf9,0x41,0x18,
  0xc2,0x65,0x04,0xe7,0x26,0x35,0xf5,0x16,
  0x3b,0xa1,0x30,0x7f,0xe9,0x44,0xf6,0x75,
  0x49,0xa2,0xec,0x5c,0x7b,0xff,0xf1,0xea };

uint8_t tv2[]={
  0x3c,0xcb,0x6e,0xf9,0x4d,0x95,0x5c,0x2d,
  0x6d,0xb5,0x57,0x70,0xd0,0x2c,0x33,0x6a,
  0x6c,0x6b,0xd7,0x70,0x12,0x8d,0x3d,0x09,
  0x94,0xd0,0x69,0x55,0xb2,0xd9,0x20,0x8a,
  0x56,0xf1,0xe7,0xe5,0x99,0x4f,0x9c,0x4f,
  0x38,0xfb,0x65,0xda,0xa2,0xb9,0x57,0xf9,
  0x0d,0xaf,0x75,0x12,0xae,0x3d,0x77,0x85,
  0xf7,0x10,0xd8,0xc3,0x47,0xf2,0xf4,0xfa,
  0x59,0x87,0x9a,0xf7,0xe6,0x9e,0x1b,0x1f,
  0x25,0xb4,0x98,0xee,0x0f,0xcc,0xfe,0xe4,
  0xa1,0x68,0xce,0xb9,0xb6,0x61,0xce,0x68,
  0x4f,0x97,0x8f,0xba,0xc4,0x66,0xea,0xde,
  0xf5,0xb1,0xaf,0x6e,0x83,0x3d,0xc4,0x33,
  0xd9,0xdb,0x19,0x27,0x04,0x54,0x06,0xe0,
  0x65,0x12,0x83,0x09,0xf0,0xa9,0xf8,0x7c,
  0x43,0x47,0x17,0xbf,0xa6,0x49,0x54,0xfd,
  0x40,0x4b,0x99,0xd8,0x33,0xad,0xdd,0x97,
  0x74,0xe7,0x0b,0x5d,0xfc,0xd5,0xea,0x48,
  0x3c,0xb0,0xb7,0x55,0xee,0xc8,0xb8,0xe3,
  0xe9,0x42,0x9e,0x64,0x6e,0x22,0xa0,0x91,
  0x7b,0xdd,0xba,0xe7,0x29,0x31,0x0e,0x90,
  0xe8,0xcc,0xa3,0xfa,0xc5,0x9e,0x2a,0x20,
  0xb6,0x3d,0x1c,0x4e,0x46,0x02,0x34,0x5b,
  0x59,0x10,0x4c,0xa4,0x62,0x4e,0x9f,0x60,
  0x5c,0xbf,0x8f,0x6a,0xd2,0x6c,0xd0,0x20 };
  
void bin2hex(uint8_t x[], int len) {
    int i;
    for (i=0; i<len; i++) {
      if ((i & 7)==0) putchar('\n');
      printf ("0x%02x,", x[i]);
    }
    putchar('\n');
}
  
int main(void)
{
    uint8_t  out[200];
    int      equ;
    
    memset(out, 0, sizeof(out));
    
    k1600_permutex(out);
    equ = memcmp(out, tv1, sizeof(tv1))==0;
    printf("Test 1 %s\n", equ ? "OK" : "Failed"); 
    //bin2hex(out, 200);

    k1600_permutex(out);
    equ = memcmp(out, tv2, sizeof(tv2))==0;
    printf("Test 2 %s\n", equ ? "OK" : "Failed");
    //bin2hex(out, 200);

    return 0;
}
#endif
