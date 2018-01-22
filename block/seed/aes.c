

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void bin2hex(uint8_t x[], int len) {
    int i;
    for (i=0; i<len; i++) {
      if ((i & 7)==0) putchar('\n');
      printf (" 0x%02x,", x[i]);
    }
    putchar('\n');
}

// Multiplication
uint8_t gf_mul(uint8_t x, uint8_t y, uint8_t p)
{
    uint8_t z = 0;

    while (y) {
      if (y & 1) {
        z ^= x;
      }
      x = (x << 1) ^ (x & 0x80 ? p : 0x00);
      y >>= 1;
    }
    return z;
}

int main (void)
{
    uint8_t gf_log[256], s[256], s_inv[256];
    int     i, x;

    for (i=0, x=1; i<256; i++) {
      gf_log[i] = x;
      x ^= gf_mul(2, x, 0x1b);
    }

    s[0] = 0x63;
    
    for (i=0; i<255; i++) {
      x = gf_log[255 - i];
      x |= x << 8;
      x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
      s[gf_log[i]] = (x ^ 0x63);
    }
    
    for (i=0; i<256; i++) {
      s_inv[s[i]] = i;
    }
  
    bin2hex(s, 256);
    bin2hex(s_inv, 256);
    
    return 0;
}

