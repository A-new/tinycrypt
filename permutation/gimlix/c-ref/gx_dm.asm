;
;  Copyright © 2017 Odzhan. All Rights Reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions are
;  met:
;
;  1. Redistributions of source code must retain the above copyright
;  notice, this list of conditions and the following disclaimer.
;
;  2. Redistributions in binary form must reproduce the above copyright
;  notice, this list of conditions and the following disclaimer in the
;  documentation and/or other materials provided with the distribution.
;
;  3. The name of the author may not be used to endorse or promote products
;  derived from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
;  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
;  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;  POSSIBILITY OF SUCH DAMAGE.
;
; -----------------------------------------------
; Gimli permutation function (x86 dual mode)
;
; size: 144 bytes
;
; x86 uses cdecl convention
; x64 (windows) uses Microsoft Fast Calling Convention
; x64 (nix/bsd) uses 64-bit fast call (use -DNIX)
;
; -----------------------------------------------

    bits 32

    %ifndef BIN
      global gimlix
      global _gimlix
    %endif

%define j  eax
%define x  ebx
%define y  ecx
%define z  edx

%define s  esi

%define t0 ebp 
%define t1 edi

%define r  ecx

%define s0 edx
%define s1 ebx
%define s2 ebp
%define s3 esi

gimlix:
_gimlix:
    push   esi
    push   edi
    push   ebp
    push   ebx
    
    ; 64-bit Linux/BSD
    %ifdef NIX
    push   edi                  ; rdi = state
    %else
    ; 64-bit Windows
    push   ecx
    %endif
    pop    s                    ; rsi = state
    
    xor    eax, eax
    dec    eax
    jz     x64
    
    ; 32-bit
    mov    s, [esp+32+4]        ; esi = s 
x64:    
    mov    r, 0x9e377900 + 24
g_l0:    
    push   r
    xor    j, j
g_l1:
    ; x = ROTR32(s[    j], 8);
    mov    x, [s + j*4]  
    ror    x, 8  
    
    ; y = ROTL32(s[4 + j], 9);
    mov    y, [s + j*4 + (4*4)]   
    rol    y, 9
    
    ; z =        s[8 + j];
    mov    z, [s + j*4 + (4*8)]
    
    ; s[8 + j] = x ^ (z << 1) ^ ((y & z) << 2);
    mov    t0, y
    lea    t1, [z + z]
    and    t0, z
    shl    t0, 2
    xor    t1, t0
    mov    t0, x
    xor    t0, t1    
    mov    [s + j*4 + (8*4)], t0
    
    ; s[4 + j] = y ^ x        ^ ((x | z) << 1);
    mov    t0, x
    mov    t1, y
    or     t0, z
    shl    t0, 1
    xor    t1, x
    xor    t1, t0
    mov    [s + j*4 + (4*4)], t1
    
    ; s[j]     = z ^ y        ^ ((x & y) << 3);    
    xor    z, y
    and    x, y
    shl    x, 3
    xor    z, x
    mov    [s + j*4], z
    
    inc    al
    cmp    al, 4
    jnz    g_l1
    
    pop    r
    push   s
    pop    edi
    
    lodsd
    xchg   eax, s0
    lodsd
    xchg   eax, s1
    lodsd
    xchg   eax, s2
    lodsd
    xchg   eax, s3
    
    mov    al, cl
    and    al, 3
    jnz    g_l2
    
    ; XCHG (s[0], s[1]);
    xchg   s0, s1
    ; XCHG (s[2], s[3]);
    xchg   s2, s3
    ; s[0] ^= 0x9e377900 ^ r;
    xor    s0, r    
g_l2:
    cmp    al, 2
    jnz    g_l3
    
    ; XCHG (s[0], s[2]);
    xchg   s0, s2
    ; XCHG (s[1], s[3]);
    xchg   s1, s3
g_l3:
    push   edi
    xchg   eax, s0   
    stosd
    xchg   eax, s1
    stosd
    xchg   eax, s2
    stosd
    xchg   eax, s3
    stosd
    pop    s    
    dec    cl   
    jnz    g_l0
    
    pop    ebx
    pop    ebp
    pop    edi
    pop    esi
    ret
    
    
    