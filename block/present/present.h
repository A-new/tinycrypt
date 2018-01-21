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

#ifndef PRESENT_H
#define PRESENT_H
  
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PRESENT_RNDS 32

#define U8V(v)  ((uint8_t)(v)  & 0xFFU)
#define U16V(v) ((uint16_t)(v) & 0xFFFFU)
#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFUL)
#define U64V(v) ((uint64_t)(v) & 0xFFFFFFFFFFFFFFFFULL)

#ifndef INTRIN
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

#else
#define ROTL32(v, n) _rotl(v, n)
#define ROTR32(v, n) _rotr(v, n)
#endif
  
typedef struct _present_ctx_t {
    uint64_t key[PRESENT_RNDS];
} present_ctx;

typedef union _w32_t {
    uint8_t  b[4];
    uint32_t w;
} w32_t;
 
typedef union _w64_t {
    uint8_t  b[8];
    uint32_t w[2];
    uint64_t q;
} w64_t;

#ifdef __cplusplus
extern "C" {
#endif

void present128_setkey(present_ctx*, void*);
void present128_setkeyx(present_ctx*, void*);

void present128_encrypt(present_ctx*, void*);
void present128_encryptx(present_ctx*, void*);
    
#ifdef __cplusplus
}
#endif

#endif

