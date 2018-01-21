/**
  Copyright © 2016 Odzhan. All Rights Reserved.

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
  
#ifndef S20_H
#define S20_H

#include "../../macros.h"

#define S20_BLK_LEN 64

typedef union _s20_blk_t {
  uint8_t  b[S20_BLK_LEN];
  uint32_t w[S20_BLK_LEN/4];
  uint64_t q[S20_BLK_LEN/8];
} s20_blk;

typedef struct _s20_ctx_t {
  s20_blk s;
} s20_ctx;

#ifdef __cplusplus
extern "C" {
#endif

  // initialize 256-bit key
  void s20_setkey(s20_ctx*, void*, void*);
  void s20_setkeyx(s20_ctx*, void*, void*);
  
  // encrypt or decrypt stream of bytes
  void s20_encrypt(uint32_t, void*, s20_ctx*);
  void s20_encryptx(uint32_t, void*, s20_ctx*);
  
#ifdef __cplusplus
}
#endif

#endif
  