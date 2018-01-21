/**
  Copyright © 2015 Odzhan. All Rights Reserved.

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
  
#ifndef TEA_H
#define TEA_H
#include "../../macros.h"
   
#define TEA_ENCRYPT 0
#define TEA_DECRYPT 1

#define TEA_BLK_LEN 8
#define TEA_KEY_LEN 16

#define TEA_ROUNDS 32

typedef union tea_blk_t {
  uint8_t b[8];
  uint16_t w[4];
  uint32_t d[2];
  uint64_t q;
} tea_blk;

typedef union tea_key_t {
  uint8_t b[16];
  uint16_t w[8];
  uint32_t d[4];
  uint64_t q[2];  
} tea_key;

#ifdef __cplusplus
extern "C" {
#endif

  void TEA_Encryptx (void*, void*, int);
  void TEA_Encrypt (void*, void*, int);
  
#ifdef __cplusplus
}
#endif
#endif