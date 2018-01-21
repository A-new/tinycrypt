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


#include <stdint.h>
#include <string.h>

#include "threefish.h"

// for 256-bit keys
typedef struct _key_t {
  uint64_t k[5], t[3];
} key_t;

#define K(s) (((uint64_t*)key)[(s)])
#define T(s) (((uint64_t*)tweak)[(s)])

void add_key(key_t *c, void *data, uint8_t s)
{
    int i;
    uint64_t x0, x1, x2;
    uint64_t *x=(uint64_t*)data;
    
    for (i=0; i<4; i++) {
      x0 = x[i];
      x1 = c->k[(s + i) % 5];
      x2 = 0;
      
      if (i==1) x2 = c->t[s % 3];
      if (i==2) x2 = c->t[(s+1) % 3];
      if (i==3) x2 = s;

      x[i] = x0 + x1 + x2;
    }
}

void threefish(void *key, void *tweak, void *data)
{
    int      i, j, r, s=0;
    uint64_t t; 
    key_t    c;
    uint64_t *x=(uint64_t*)data;  
    
    uint8_t rc[16] = 
    { 14, 52, 23,  5, 25, 46, 58, 32, 
      16, 57, 40, 37, 33, 12, 22, 32};

    // copy key and tweak to local buffers  
    memcpy((void*)c.k, key,   32);
    memcpy((void*)c.t, tweak, 16);
    
    c.k[4] = 0x1BD11BDAA9FC1A22ULL;
    
    // initialize subkeys
    for(i=0; i<4; i++){
      c.k[4] ^= K(i);
    }
    c.t[2] = T(0) ^ T(1); 
    
    // apply 72 rounds
    for (i=0; i<72; i++)
    {
      // add key every 4 rounds
      if((i & 3) == 0) {
        add_key(&c, data, s);
        s++;
      }
        
      // apply mixing function
      for (j=0; j<4; j += 2) {
        r = rc[(i & 7) + (j << 2)];

        x[j]   += x[j+1];
        x[j+1]  = ROTL64(x[j+1], r);
        x[j+1] ^= x[j];    
      }
      
      // permute
      t    = x[1];
      x[1] = x[3];
      x[3] = t;
    }
    // add key
    add_key(&c, data, s);
}

