
#include <stdio.h>
#include <stdint.h>

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))

void ascon_permutex(void *state, int rnds);

void ascon_permute(void *state, int rnds) {
    int      i;
    uint64_t x0, x1, x2, x3, x4;
    uint64_t t0, t1, t2, t3, t4;
    
    uint64_t *x=(uint64_t*)state;
    
    // load 320-bit state
    x0 = x[0]; x1 = x[1];
    x2 = x[2]; x3 = x[3];
    x4 = x[4];

    for (i=0; i<rnds; i++) {
      // addition of round constant
      x2 ^= ((0xfull - i) << 4) | i;

      // substitution layer
      x0 ^= x4;    x4 ^= x3;    x2 ^= x1;
      t0  = x0;    t1  = x1;    t2  = x2;    t3  =  x3;    t4  = x4;
      t0  = ~t0;   t1  = ~t1;   t2  = ~t2;   t3  = ~t3;    t4  = ~t4;
      t0 &= x1;    t1 &= x2;    t2 &= x3;    t3 &=  x4;    t4 &= x0;
      x0 ^= t1;    x1 ^= t2;    x2 ^= t3;    x3 ^=  t4;    x4 ^= t0;
      x1 ^= x0;    x0 ^= x4;    x3 ^= x2;    x2  = ~x2;

      // linear diffusion layer
      x0 ^= ROTR(x0, 19) ^ ROTR(x0, 28);
      x1 ^= ROTR(x1, 61) ^ ROTR(x1, 39);
      x2 ^= ROTR(x2,  1) ^ ROTR(x2,  6);
      x3 ^= ROTR(x3, 10) ^ ROTR(x3, 17);
      x4 ^= ROTR(x4,  7) ^ ROTR(x4, 41);

    }
    // save 320-bit state
    x[0] = x0; x[1] = x1;
    x[2] = x2; x[3] = x3;
    x[4] = x4;
}

#ifdef TEST

#include <stdio.h>

int main(void) {
  uint64_t state1[5], state2[5];
  int      i, equ;
  
  memset(state1, 0, sizeof(state1));
  memset(state2, 0, sizeof(state2));
  
  for (i=0; i<5; i++) state1[i] = i;
  for (i=0; i<5; i++) state2[i] = i;
  
  ascon_permute(state1, 6);
  ascon_permutex(state2, 6);
  
  equ = (memcmp(state1, state2, sizeof(state1))==0);
  
  printf ("Test %s\n", equ ? "OK" : "FAILED");
  
  printf ("\n[*] state 1\n");
  for (i=0; i<40; i++) {
    if ((i & 7)==0) putchar('\n');
    printf ("%02x ", ((uint8_t*)&state1)[i]);
  }

  printf("\n\n[*] state 2\n");  
  for (i=0; i<40; i++) {
    if ((i & 7)==0) putchar('\n');
    printf ("%02x ", ((uint8_t*)&state2)[i]);
  }
  
  return 0;
}  
#endif
