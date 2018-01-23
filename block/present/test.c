
// test unit for PRESENT-128
// odzhan

#include <stdio.h>

#include "present.h"

// Plaintext: 0000000000000000 
// Given Key (128bit): 0000000000000000 0000000000000000
uint8_t k00_t00[]=
{ 0xaf, 0x00, 0x69, 0x2e, 0x2a, 0x70, 0xdb, 0x96 };

// Plaintext: ffffffffffffffff 
// Given Key (128bit): ffffffffffffffff ffffffffffffffff
uint8_t kff_tff[]=
{ 0xb4, 0xe5, 0x18, 0x42, 0xbd, 0x9f, 0x8d, 0x62 };

uint8_t *tv[2]={k00_t00, kff_tff};

int main(void)
{
  present_ctx ctx;
  uint8_t     buf[8];   // 64-bit plaintext
  uint8_t     key[16];  // 128-bit key
  int         i, equ;
  
  for (i=0; i<2; i++) {
    // if using alternative test vectors, remember to change these!
    memset(key, -i, sizeof(key));  
    memset(buf, -i, sizeof(buf));
  
    present128_setkey(&ctx, key);
    present128_encrypt(&ctx, buf);
    //present128_encryptx(key, buf);
    
    equ = memcmp (buf, tv[i], 8)==0;
    printf ("\nEncryption test #%i %s", (i+1), 
        equ ? "PASSED" : "FAILED");
  }
  return 0;
}
