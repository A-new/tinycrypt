


// test unit for blabla stream cipher

#include <stdio.h>
#include "blabla.h"

uint8_t bb_tv[]={
  173, 80, 254, 123, 103, 188, 241, 234, 16, 130, 154, 201, 95, 
  86, 3, 99, 72, 175, 218, 238, 238, 136, 184, 20, 133, 42, 
  223, 58, 55, 33, 216, 12, 166, 112, 185, 55, 193, 11, 119, 227, 
  146, 58, 124, 149, 74, 197, 80, 118, 0, 218, 217, 174, 61, 137, 
  91, 97, 40, 16, 211, 53, 189, 200, 89, 37, 141, 101, 46, 178, 2, 
  88, 27, 29, 13, 78, 105, 28, 101, 122, 99, 76, 252, 86, 87, 240, 
  169, 109, 187, 179, 192, 248, 16, 51, 90, 208, 222, 25, 0, 61, 
  209, 146, 176, 15, 28, 175, 43, 125, 235, 39, 67, 125, 251, 218, 
  135, 66, 3, 219, 156, 251, 221, 170, 137, 26, 84, 134, 231, 202, 
  116, 30, 126, 12, 146, 166, 195, 17, 233, 23, 50, 126, 236, 147, 
  63, 218, 165, 117, 37, 218, 219, 175, 191, 69, 142, 246, 98, 178, 
  17, 228, 142, 61, 231, 209, 67, 50, 195, 31, 217, 83, 25, 170, 233, 
  222, 82, 119, 102, 13, 94, 187, 62, 169, 14, 233, 217, 116, 190, 
  169, 178, 44, 38, 158, 186, 231, 118, 233, 236, 192, 108, 123, 
  105, 234, 169, 98, 208, 139, 87, 190, 110, 59, 114, 166, 114, 68, 
  174, 94, 192, 24, 47, 9, 149, 219, 84, 153, 231, 24, 148, 202, 204, 
  210, 238, 37, 156, 78, 239, 45, 42, 80, 144, 38, 182, 156, 240, 47, 
  170, 99, 8, 114, 35, 202, 242, 241, 198, 102, 21, 239, 48, 72, 43, 
  224, 29, 79, 215, 132, 82, 79, 224, 241, 161, 20, 190, 241, 81, 148, 
  70, 148, 88, 107, 47, 30, 5, 41, 226, 224, 81, 95, 96, 50, 159, 96, 
  221, 242, 17, 214, 22, 109, 12, 153, 96, 196, 6, 102, 109, 90 };

int main(void)
{
    uint8_t  key[BB20_KEY_LEN];
    uint8_t  nonce[BB20_NONCE_LEN]={0};
    int      i, equ;
    uint8_t  stream[300];
    bb20_ctx c;
    
    for (i=0; i<BB20_KEY_LEN; i++) {
      key[i] = (uint8_t)i;
    }
    
    bb20_setkey(&c, key, nonce);
    bb20_keystream(sizeof(stream), stream, &c);
    
    equ = memcmp(stream, bb_tv, sizeof(bb_tv))==0;

    printf ("\nBlaBla Test %s\n", equ?"PASSED":"FAILED");  
    return 0;
}