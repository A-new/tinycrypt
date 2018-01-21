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
  
#ifndef BB20_H
#define BB20_H

#include "../../macros.h"

#define BB20_STATE_LEN 128
#define BB20_BLK_LEN   128
#define BB20_KEY_LEN    32
#define BB20_NONCE_LEN  16
#define BB20_ROUNDS     10

typedef union _bb20_blk_t {
  uint8_t  b[BB20_BLK_LEN];
  uint32_t w[BB20_BLK_LEN/4];
  uint64_t q[BB20_BLK_LEN/8];
} bb20_blk;

typedef union _bb20_ctx_t {
  uint8_t  b[BB20_STATE_LEN];
  uint32_t w[BB20_STATE_LEN/4];
  uint64_t q[BB20_STATE_LEN/8];
} bb20_ctx;

#ifdef __cplusplus
extern "C" {
#endif

  void bb20_setkey(bb20_ctx*, void*, void*);
  void bb20_encrypt(uint64_t, void*, bb20_ctx*);
  void bb20_keystream(uint64_t, void*, bb20_ctx*);
  
#ifdef __cplusplus
}
#endif

#endif
  