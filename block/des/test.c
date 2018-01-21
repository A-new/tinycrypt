

// DES in C
// Odzhan

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

#include "des.h"

char *test_keys[] = 
{ "8000000000000000",
  "0001020304050607",
  "2BD6459F82C5B300",
  "A6A6A6A6A6A6A6A6",
  "9292929292929292" };

char *test_pt[] =
{ "0000000000000000",
  "41AD068548809D02",
  "B10F843097A0F932",
  "11DE2BCE0CB1765A",
  "9292929292929292" };
            
char *test_ct[] =
{ "95A8D72813DAA94D",
  "0011223344556677",
  "EA024714AD5C4D84",
  "A6A6A6A6A6A6A6A6",
  "5B365F2FB2CD7F32" };
  
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

int run_tests (void)
{
  int i, clen, fails=0;

  des_blk ct1, ct2, pt1, key;
  des_ctx ctx;
  
  for (i=0; i<sizeof (test_keys)/sizeof(char*); i++)
  { 
    hex2bin (key.v8, test_keys[i]);
    clen=hex2bin (ct1.v8, test_ct[i]);
    hex2bin (pt1.v8, test_pt[i]);
    
    //des_enc (ct2.v8, pt1.v8, key.v8);
    des_setkey(&ctx, key.v8);
    /*for (j=0; j<4; j++)
    {
      printf ("\n%08X %08X", ctx.keys[i].v32[0], ctx.keys[i].v32[1]);
    }*/
    
    des_enc (&ctx, pt1.v8, ct2.v8, DES_ENCRYPT);
    //des_enc (&ctx, ct2.v8, pt2.v8, DES_DECRYPT);
    
    if (memcmp (ct1.v8, ct2.v8, clen)==0) {
      printf ("\nPassed Encryption/Decryption test #%i %08X %08X", 
        (i+1), ct1.v32[0], ct2.v32[0]);
    } else {
      fails++;
      printf ("\nFailed test #%i : "
          "Got %08X %08X instead of %08X %08X for %08X %08X", (i+1), 
          ct2.v32[0], ct2.v32[1], ct1.v32[0], ct1.v32[1],
          pt1.v32[0], pt1.v32[1]);
          
    }
  }
  return fails;
}

int main (int argc, char *argv[])
{

  if (!run_tests()) {
    printf ("\n  [ self-test OK!\n");
  }

  return 0;
}
