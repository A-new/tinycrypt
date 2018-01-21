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
  
#include "roadrunner.h"

// s-box layer
void sbox(uint8_t x[])
{
    uint8_t t = x[3];
    
    x[3] &= x[2];
    x[3] ^= x[1];
    x[1] |= x[2];
    x[1] ^= x[0];
    x[0] &= x[3];
    x[0] ^= t;
    t    &= x[1];
    x[2] ^= t;
}

void SLK(uint8_t x[], uint8_t *sk)
{
    uint8_t i, t;
    
    sbox(x);
    
    for(i=0; i<4; i++) {      
      t = ROTL8(x[i], 1); t ^= x[i];
      t = ROTL8(t, 1); x[i] ^= t;
      
      x[i] ^= sk[i];
    }
}

void rr_round(uint8_t *x, uint8_t *rk, uint8_t idx, uint8_t *ctr)
{
    uint8_t i;
    uint8_t t[4];
    
    for (i=0; i<4; i++) {
      t[i] = x[i];
    }
    for (i=0; i<3; i++) {
      if (i==2) x[3] ^= idx;
      SLK (x, rk + ctr[0]);
      ctr[0] = (ctr[0] + 4) & 15;
    }
    
    sbox(x);
    
    for (i=0; i<4; i++) x[i  ] ^= x[i+4];
    for (i=0; i<4; i++) x[i+4]  = t[i  ];
}
  
void road64_encrypt(void *data, void *keys)
{
    int      i;
    uint8_t t[4]={0};
    uint8_t *x=(uint8_t*)data;
    uint8_t *rk=(uint8_t*)keys;

    t[0] = 4;
    
    // key pre-whitening
    for (i=0; i<4; i++) x[i] ^= rk[i];
    
    // apply rounds
    for (i=RR_ROUNDS; i>0; i--) {
      rr_round(x, rk, i, t);
    }
    // 
    for (i=0; i<4; i++) t[i] = x[i];
    // key whitening
    for (i=0; i<4; i++) x[i  ] = x[i+4] ^ rk[i+4];
    for (i=0; i<4; i++) x[i+4] = t[i];
}
