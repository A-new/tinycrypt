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
  
#include "noekeon.h"

void noekeon(void *key, void *data)
{
  int      i, j;
  uint32_t t;

  uint32_t *s=(uint32_t*)data;
  uint32_t *k=(uint32_t*)key;

  uint8_t rc_tab[]=   
    { 0x80,
      0x1B, 0x36, 0x6C, 0xD8, 
      0xAB, 0x4D, 0x9A, 0x2F, 
      0x5E, 0xBC, 0x63, 0xC6, 
      0x97, 0x35, 0x6A, 0xD4 };
  
    for (i=0;;i++) {
      s[0] ^= rc_tab[i];
      // Theta
      t = s[0] ^ s[2]; 

      t ^= ROTR32(t, 8) ^ ROTL32(t, 8);

      s[1] ^= t; s[3] ^= t;

      for (j=0; j<4; j++) {
        s[j] ^= k[j];
      }

      t = s[1] ^ s[3]; 
      t ^= ROTR32(t, 8) ^ ROTL32(t, 8);

      s[0] ^= t; s[2] ^= t;

      if (i==Nr) break;

      // Pi1
      s[1] = ROTL32(s[1], 1);
      s[2] = ROTL32(s[2], 5);
      s[3] = ROTL32(s[3], 2);

      // Gamma
      s[1] ^= ~((s[3]) | (s[2]));
      s[0] ^=   s[2] & s[1];  

      XCHG(s[0], s[3]);

      s[2] ^= s[0] ^ s[1] ^ s[3];

      s[1] ^= ~((s[3]) | (s[2]));
      s[0] ^=   s[2] & s[1];  

      // Pi2
      s[1] = ROTR32(s[1], 1);
      s[2] = ROTR32(s[2], 5);
      s[3] = ROTR32(s[3], 2);
    }
}


#ifdef TEST

void print_bytes(char *s, void *p, int len) {
  int i;
  printf("%s : ", s);
  for (i=0; i<len; i++) {
    printf ("%02x ", ((uint8_t*)p)[i]);
  }
  putchar('\n');
}

int main(void) {
  
  uint8_t ct[]=
  { 0xd0, 0x36, 0x19, 0x4c, 0xc6, 0x70, 0x3b, 0x6e, 
    0x32, 0xcc, 0x2b, 0x6f, 0xa4, 0xd1, 0x21, 0x40 };
    
  uint8_t pt[]=
  { 0xed, 0x1f, 0x7c, 0x59, 0xec, 0x86, 0xa4, 0x9e, 
    0x2c, 0x6c, 0x22, 0xae, 0x20, 0xb4, 0xae, 0xde };

  uint8_t key[]=
  { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
  
  int equ;
  
  noekeon(key, pt);
  equ = memcmp (ct, pt, 16)==0;
  
  printf ("Encryption : %s : ",
      equ ? "OK" : "FAILED"); 
      
  print_bytes("CT", pt, sizeof(pt));
  
  return 0;
}

#endif
