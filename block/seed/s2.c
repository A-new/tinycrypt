// s2.c
// 2017-12=07  Markku-Juhani O. Saarinen <mjos@iki.fi>
// Print out ARIA S-Box S2, just had to try it out.

#include <stdio.h>
#include <stdint.h>

const uint8_t bm[8][8] = {
	{ 0, 1, 0, 1, 1, 1, 1, 0 },
	{ 0, 0, 1, 1, 1, 1, 0, 1 },
	{ 1, 1, 0, 1, 0, 1, 1, 1 },
	{ 1, 0, 0, 1, 1, 1, 0, 1 },
	{ 0, 0, 1, 0, 1, 1, 0, 0 },
	{ 1, 0, 0, 0, 0, 0, 0, 1 },
	{ 0, 1, 0, 1, 1, 1, 0, 1 },
	{ 1, 1, 0, 1, 0, 0, 1, 1 }
};

uint8_t matmul8(uint8_t x)
{
	int i, j;
	uint8_t y;
	
	y = 0;
	for (i = 0; i < 8; i++) {
	
		if (x & (1 << i)) {
			for (j = 0; j < 8; j++)
				y ^= bm[j][i] << j;
		}
	}
	
	return y;
}

int main()
{
	int i, x;
	int gf_log[256], gf_exp[256];

	x = 0x01;
	for (i = 0; i < 255; i++) {
		gf_exp[i] = x;
		gf_log[x] = i;
				
		x ^= x << 1;
		if (x & 0x100)
			x ^= 0x11B;
	}	
	
	for (i = 0; i < 256; i++) {
		
		x = i;
		if (x > 0) 
			x = gf_exp[ (247 * gf_log[x]) % 255 ];				
		
		x = matmul8(x) ^ 0xE2;
	
		printf(" %02X", x);
		if ((i & 0xF) == 0xF)
			printf("\n");
	}

	return 0;
}
