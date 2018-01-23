

// RC5 test in C
// Odzhan

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "rc5.h"

typedef struct _rc5_tv {
  char *key;
  char *pt;
  char *ct;
} rc5_tv;

rc5_tv tv[2]=
{
  {"000102030405060708090A0B0C0D0E0F", "96950DDA654A3D62", "0011223344556677"},
  {"00000001000000000000000000000000", "0000000000000000", "AEDA56A5190042CE"}
};

void bin2hex(char *s, void *p, int len) {
  int i;
  printf("%s : ", s);
  for (i=0; i<len; i++) {
    printf ("%02x ", ((uint8_t*)p)[i]);
  }
  printf("\n\n");
}

size_t hex2bin (void *bin, char hex[]) {
  size_t  len, i;
  int     x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
} 

void xrc5_cryptx(void *key, void *data);

int main (int argc, char *argv[])
{
  int     i, j, e;
  RC5_CTX ctx;
  uint8_t pt1[8], pt2[8], ct1[8], ct2[8], key[16], t[16];
  
  for (i=0; i<2; i++)
  {
    hex2bin (key, tv[i].key);
    hex2bin (pt1, tv[i].pt);
    hex2bin (ct1, tv[i].ct);
    
    #ifdef SINGLE
      memcpy(t, key, 16); 
      memcpy(ct2, pt1, 8); 
      xrc5_cryptx(key, ct2);
    #else  
      rc5_setkey (&ctx, key);
      rc5_crypt (&ctx, pt1, ct2, RC5_ENCRYPT);
    #endif
    
    bin2hex("ciphertext", ct2, RC5_BLK_LEN);  
    
    e=memcmp (ct1, ct2, RC5_BLK_LEN);

    printf ("\n\nRC5 encryption test #%i %s", 
      (i+1), e==0?"passed":"failed");
      
    rc5_setkey (&ctx, key);  
    rc5_crypt (&ctx, ct2, pt2, RC5_DECRYPT);

    bin2hex("ciphertext", pt2, RC5_BLK_LEN);  
    
    e=memcmp (pt1, pt2, RC5_BLK_LEN);
    printf ("RC5 decryption test #%i %s\n", 
      (i+1), e==0?"passed":"failed");
  }
  return 0;
}
