

// SHA-256 in C test unit
// Odzhan

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>

#include "sha2.h"

char *text[] =
{ "",
  "a",
  "abc",
  "message digest",
  "abcdefghijklmnopqrstuvwxyz",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
};

char *SHA256_dgst[] =
{ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
  "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
  "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
  "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
};

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

int run_tests (void)
{
  uint8_t    dgst[SHA256_DIGEST_LENGTH], tv[SHA256_DIGEST_LENGTH];
  int        i, fails=0;
  SHA256_CTX ctx;
  
  for (i=0; i<sizeof(text)/sizeof(char*); i++)
  {    
    hex2bin (tv, SHA256_dgst[i]);
    
    SHA256_Init (&ctx);
    SHA256_Update (&ctx, text[i], strlen(text[i]));
    SHA256_Final (dgst, &ctx);
    
    if (memcmp (dgst, tv, SHA256_DIGEST_LENGTH) != 0) {
      printf ("Failed for string len %ld : %s\n", 
        strlen (text[i]), text[i]);
      ++fails;
    }
  }
  return fails;
}

/************************************************
*
* HMAC
*
************************************************/
void SHA256_HMAC (void *text, size_t text_len, 
void *key, size_t key_len, void* dgst)
{
  SHA256_CTX ctx;
  uint8_t    k_ipad[SHA256_CBLOCK], k_opad[SHA256_CBLOCK], tk[SHA256_DIGEST_LENGTH];
  size_t     i;
  uint8_t    *k=(uint8_t*)key;

  if (key_len > SHA256_CBLOCK) {
    SHA256_Init (&ctx);
    SHA256_Update (&ctx, key, key_len);
    SHA256_Final (tk, &ctx);
    key = tk;
    key_len = SHA256_DIGEST_LENGTH;
  }

  memset (k_ipad, 0x36, sizeof (k_ipad));
  memset (k_opad, 0x5c, sizeof (k_opad));

  /** XOR key with ipad and opad values */
  for (i=0; i<key_len; i++) {
    k_ipad[i] ^= k[i];
    k_opad[i] ^= k[i];
  }
  /**
  * perform inner 
  */
  SHA256_Init (&ctx);                   /* init context for 1st pass */
  SHA256_Update (&ctx, k_ipad, SHA256_CBLOCK);     /* start with inner pad */
  SHA256_Update (&ctx, text, text_len); /* then text of datagram */
  SHA256_Final (dgst, &ctx);            /* finish up 1st pass */
  /**
  * perform outer
  */
  SHA256_Init (&ctx);                   /* init context for 2nd pass */
  SHA256_Update (&ctx, k_opad, SHA256_CBLOCK);     /* start with outer pad */
  SHA256_Update (&ctx, dgst, SHA256_DIGEST_LENGTH); /* then results of 1st hash */
  SHA256_Final (dgst, &ctx);            /* finish up 2nd pass */
}

/**
* Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
* Code based on IEEE Std 802.11-2007, Annex H.4.2.
*/

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

int SHA256_PBKDF2 (void *pwd, size_t pwd_len, void *salt, size_t salt_len,
uint32_t rounds, void *key, size_t key_len)
{
  uint8_t *asalt, obuf[SHA256_DIGEST_LENGTH];
  uint8_t *k=(uint8_t*)key;
  uint8_t d1[SHA256_DIGEST_LENGTH], d2[SHA256_DIGEST_LENGTH];
  size_t i, j, count, r;

  if ((asalt = (uint8_t*)malloc(salt_len + 4)) == 0)
  return -1;

  memcpy(asalt, salt, salt_len);

  for (count = 1; key_len > 0; count++) {
    asalt[salt_len + 0] = (count >> 24) & 0xff;
    asalt[salt_len + 1] = (count >> 16) & 0xff;
    asalt[salt_len + 2] = (count >>  8) & 0xff;
    asalt[salt_len + 3] = count & 0xff;
    SHA256_HMAC(asalt, salt_len + 4, pwd, pwd_len, d1);
    memcpy(obuf, d1, sizeof(obuf));

    for (i = 1; i < rounds; i++) {
      SHA256_HMAC(d1, sizeof(d1), pwd, pwd_len, d2);
      memcpy(d1, d2, sizeof(d1));
      for (j = 0; j < sizeof(obuf); j++)
      obuf[j] ^= d1[j];
    }

    r = MIN(key_len, SHA256_DIGEST_LENGTH);
    memcpy(k, obuf, r);
    k += r;
    key_len -= r;
  };
  free (asalt);
  return 0;
}

int main (int argc, char *argv[])
{
  if (!run_tests()) {
    printf ("  [ self-test OK!\n");
  }

  return 0;
}
