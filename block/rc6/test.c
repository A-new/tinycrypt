
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "rc6.h"

// 256-bit keys

char *test_keys[] = 
{ "00000000000000000000000000000000"
  "00000000000000000000000000000000",
  "0123456789abcdef0112233445566778"
  "899aabbccddeeff01032547698badcfe" };

char *test_plaintexts[] =
{ "00000000000000000000000000000000",
  "02132435465768798a9bacbdcedfe0f1" };

char *test_ciphertexts[] =
{ "8f5fbd0510d15fa893fa3fda6e857ec2",
  "c8241816f0d7e48920ad16a1674e5d48"};

size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
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

void run_tests (void)
{
  int     i;
  uint8_t pt1[16], pt2[16], ct1[16], ct2[16], key[32];
  RC6_KEY ctx;
  
  for (i=0; i<sizeof (test_keys)/sizeof(char*); i++)
  {    
    hex2bin (key, test_keys[i]);
    hex2bin (ct1, test_ciphertexts[i]);
    hex2bin (pt1, test_plaintexts[i]);
    
    #ifdef SINGLE
      memcpy(ct2, pt1, sizeof(ct2)); 
      xrc6_cryptx(key, ct2);
    #else  
      rc6_setkey (&ctx, key);
      rc6_crypt (&ctx, pt1, ct2, RC6_ENCRYPT);
    #endif
    
    if (memcmp (ct1, ct2, sizeof(ct1))==0) {
      printf ("Encryption Passed test #%i\n", (i+1));
      
      rc6_setkey (&ctx, key);     
      rc6_crypt (&ctx, ct2, pt2, RC6_DECRYPT);
      
      if (memcmp (pt1, pt2, sizeof(pt1))==0) {
        printf ("Decryption passed test #%i\n", (i+1));
      } else {
        printf ("Decryption failed\n");
      }
    } else {
      printf ("Failed test #%i\n", (i+1));
    }
  }
}

int main (void)
{
  run_tests();
  return 0;
}
