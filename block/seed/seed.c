#include <stdio.h>
#include <stdint.h>

#define U8V(v)  ((uint8_t)(v)  & 0xFFU)
#define U16V(v) ((uint16_t)(v) & 0xFFFFU)
#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFUL)
#define U64V(v) ((uint64_t)(v) & 0xFFFFFFFFFFFFFFFFULL)

#define ROTL8(v, n) \
  (U8V((v) << (n)) | ((v) >> (8 - (n))))

#define ROTL16(v, n) \
  (U16V((v) << (n)) | ((v) >> (16 - (n))))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define ROTL64(v, n) \
  (U64V((v) << (n)) | ((v) >> (64 - (n))))

#define ROTR8(v, n) ROTL8(v, 8 - (n))
#define ROTR16(v, n) ROTL16(v, 16 - (n))
#define ROTR32(v, n) ROTL32(v, 32 - (n))
#define ROTR64(v, n) ROTL64(v, 64 - (n))

#define SBOX1 0
#define SBOX2 1

// 0x8A, 0xFE, 0x85, 0x42 
// 0x45, 0x21, 0x88, 0x14
//
// matrix used for s-box 1 generation
uint8_t m1[8][8] = {
    {1,0,0,0,1,0,1,0},
    {1,1,1,1,1,1,1,0},
    {1,0,0,0,0,1,0,1},
    {0,1,0,0,0,0,1,0},
    {0,1,0,0,0,1,0,1},
    {0,0,1,0,0,0,0,1},
    {1,0,0,0,1,0,0,0},
    {0,0,0,1,0,1,0,0},
};

// matrix used for s-box 2 generation
uint8_t m2[8][8] = {
    {0,1,0,0,0,1,0,1},
    {1,0,0,0,0,1,0,1},
    {1,1,1,1,1,1,1,0},
    {0,0,1,0,0,0,0,1},
    {1,0,0,0,1,0,1,0},
    {1,0,0,0,1,0,0,0},
    {0,1,0,0,0,0,1,0},
    {0,0,0,1,0,1,0,0},
};

uint32_t xpow(uint32_t x, uint32_t n)
{
    int i;
    uint32_t r = 1;
    
    for (i=0; i<n; i++) {
      r *= x;
    }
    return r;
}

// multiplcation by matrix over GF(2)
uint8_t matmul(uint8_t mat[8][8], uint8_t a) {
  uint8_t res = 0;
  int x, y;
  
  for (x = 0; x < 8; x++) {
    if (a & (1 << (7 - x))) {
      for (y = 0; y < 8; y++) {
        res ^= mat[y][x] << (7 - y);
      }
    }
  }
  return res;
}

uint8_t fieldmul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  
  while (b) {
    if (b & 1) 
      p ^= a;
    if (a & 0x80)
      a = (a << 1) ^ 0x63;  // x^8 + x^6 + x^5 + x + 1
    else
      a <<= 1;
    b >>= 1;
  }
  return p;
}

uint32_t gf_mul2 (uint32_t w) {
  uint32_t t = w & 0x80808080;
  
  return ( (w ^ t ) << 1) ^ ( ( t >> 7) * 0x63);
}

// ------------------------------------
// multiplicative inverse
// ------------------------------------
uint8_t gf_mulinv (uint8_t x)
{
  uint8_t y=x, i;

  if (x)
  {
    // calculate logarithm gen 3
    for (y=1, i=0; ;i++) {
      y ^= gf_mul2 (y);
      if (y==x) break;
    }
    i+=2;
    // calculate anti-logarithm gen 3
    for (y=1; i; i++) {
      y ^= gf_mul2(y);
    }
  }
  return y;
}
// ------------------------------------
// substitute byte
// ------------------------------------
uint8_t SubByte (uint8_t x)
{
  uint8_t i, y=0, sb;

  sb = y = gf_mulinv (x);

  for (i=0; i<4; i++) {
    y   = ROTL8(y, 1);
    sb ^= y;
  }
  return sb;
}

uint8_t sbox(uint8_t x, int b, int i) {
    uint8_t *m=(uint8_t*)m1;
    uint8_t p=169;
    
    if (i==SBOX2) {
      m=(uint8_t*)m2;
      p=251;
    }
    return matmul((uint8_t(*)[8])m, x) ^ p;
}

int main(void)
{
  int x=2;
  /*
  // x^8 + x^6 + x^5 + x^3 + x^0
  printf ("\ntwofish: %02X",
        xpow(x,8) ^ 
        xpow(x,6) ^ 
        xpow(x,5) ^ 
        xpow(x,3) ^ 
        xpow(x,0));

  // x^8 + x^4 + x^3 + x + 1        
  printf ("\naes: %02X",
        (xpow(x,8) ^ 
         xpow(x,4) ^ 
         xpow(x,3) ^ x ^ 1) & 255);

  // x^8 + x^6 + x^5 + x + 1         
  printf ("\nseed: %02X",
        (xpow(x,8) ^ 
         xpow(x,6) ^ 
         xpow(x,5) ^ x ^ 1));
        
  return 0;      */
  
  for (x=0; x<256; x++) {
    if ((x & 7)==0) putchar('\n');
    printf ("%i, ", sbox(x, 247, SBOX1));
  }
  return 0;
}
