;
;  Copyright © 2015 Odzhan, Peter Ferrie. All Rights Reserved.
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

; -----------------------------------------------
; rc5 in x86 assembly
;
; https://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf
;
; size: 122 bytes
;
; global calls use cdecl convention
;
; -----------------------------------------------

  bits 32
  
%ifndef BIN
  global _rc5_setkeyx
  global _rc5_cryptx
%endif

%define RC5_BLK_LEN 8
%define RC5_ROUNDS  12
%define RC5_KEYLEN  16

%define RC5_KR      (2*(RC5_ROUNDS+1))
%define RC5_P       0xB7E15163
%define RC5_Q       0x9E3779B9

%define A ebx
%define B ebp
 
_rc5_cryptx:
rc5_crypt:
    pushad
    mov    esi, [esp+32+4]   ; key
    mov    ebx, [esp+32+8]   ; data
    xor    ecx, ecx
    mul    ecx
    mov    ch, 1
    sub    esp, ecx          ; allocate 128 bytes
    ; initialize L with 128-bit key    
    mov    edi, esp    
    rep    movsb
    ; initialize S   
    pushad
    mov    eax, 0xB7E15163   ; RC6_P
    mov    cl, RC5_KR    
r_l0:
    stosd
    add    eax, 0x9E3779B9   ; RC6_Q
    loop   r_l0
    popad
    ; create subkeys  
    push   ebx               ; save ptr to data
    xor    ebx, ebx          ; i=0    
r_lx:    
    xor    ebp, ebp          ; i%RC6_KR    
r_l1:
    cmp    ebp, RC5_KR
    je     r_lx    
    ; A = S[i%RC6_KR] = ROTL32(S[i%RC6_KR] + A+B, 3); 
    lea    eax, [eax+edx]    ; A  = A+B
    add    eax, [edi+ebp*4]  ; A += S[i%RC6_KR]
    rol    eax, 3            ; A  = ROTL32(A, 3)
    mov    [edi+ebp*4], eax  ; S[i%RC6_KR] = A
    
    ; B = L[i&7] = ROTL32(L[i&7] + A+B, A+B);
    add    edx, eax          ; B += A
    mov    ecx, edx          ; save A+B in ecx
    mov    esi, ebx          ; esi = i 
    and    esi, 7            ; esi %= 8
    add    edx, [esp+esi*4+4]; B += L[i%8] 
    rol    edx, cl           ; B = ROTL32(B, A+B)
    mov    [esp+esi*4+4], edx; L[i%8] = B    
    
    inc    ebp
    inc    ebx               ; i++
    cmp    bl, RC5_KR*3      ; i<RC6_KR*3
    jnz    r_l1
    
    pop    esi               ; esi = data
    push   esi               ; save ptr to data
    
    lodsd                    ; eax = A
    xchg   eax, A
    lodsd                    ; eax = B
    xchg   eax, B
    
    lodsd
    add    A, eax
    lodsd
    add    B, eax
r5_l2:
    push  ecx
    lodsd
    ; A = ROTL32(A ^ B, B) + key->x[i+2];
    xor   A, B
    mov   ecx, B
    rol   A, cl
    add   A, eax
    xchg  A, B
    pop   ecx
    loop  r5_l2
    
    xchg  eax, A
    stosd
    xchg  eax, B
    stosd
    popad
    ret
