#include <stdint.h>

#include "macros.h"

void gimli(void *state)
{
  int      r, j;
  uint32_t t, x, y, z;
  uint32_t *s=(uint32_t*)state;
  
  for (r=0x9e377918; r!=0x9e377900; r--) {
    // apply SP-box
    for (j=0; j<4; j++) {
      x = ROTR32(s[    j], 8);
      y = ROTL32(s[4 + j], 9);
      z =        s[8 + j];

      s[8 + j] = x ^ (z << 1) ^ ((y & z) << 2);
      s[4 + j] = y ^ x        ^ ((x | z) << 1);
      s[j]     = z ^ y        ^ ((x & y) << 3);
    }

    // apply Linear layer
    t = r & 3;
    
    // small swap
    if (t == 0) {
      XCHG(s[0], s[1]);
      XCHG(s[2], s[3]);
      
      // add constant      
      s[0] ^= r;
    }   
    // big swap
    if (t == 2) {
      XCHG(s[0], s[2]);
      XCHG(s[1], s[3]);
    }
  }
}
