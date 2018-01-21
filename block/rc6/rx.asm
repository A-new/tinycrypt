;
;  Copyright © 2015, 2017 Odzhan, Peter Ferrie. All Rights Reserved.
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
; RC6 block cipher in x86 assembly (encryption only)
;
; https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf
;
; size: 173 bytes
;
; global calls use cdecl convention
;
; -----------------------------------------------

        bits 32

%define RC6_ROUNDS 20
%define RC6_KR     (2*(RC6_ROUNDS+2))

%define A esi
%define B ebx
%define C edx
%define D ebp

%define S edi
%define L esp

        %ifndef BIN
          global xrc6_crypt
          global _xrc6_crypt
        %endif
        
xrc6_crypt:
_xrc6_crypt:
    pushad
    mov    esi, [esp+32+4]   ; key
    mov    ebx, [esp+32+8]   ; data
    xor    ecx, ecx
    mul    ecx
    mov    ch, 1
    sub    esp, ecx          ; allocate 256 bytes
    ; initialize L with 256-bit key    
    mov    edi, esp    
    shr    ecx, 3            ; 256/8 = 32
    rep    movsb
    ; initialize S   
    pushad
    mov    eax, 0xB7E15163   ; RC6_P
    mov    cl, RC6_KR    
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
    cmp    ebp, RC6_KR
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
    cmp    bl, RC6_KR*3      ; i<RC6_KR*3
    jnz    r_l1
    
    pop    esi               ; esi = data
    push   esi               ; save ptr to data
    
    ; load plaintext
    lodsd
    push   eax               ; save A
    lodsd
    xchg   eax, B            ; load B
    lodsd
    xchg   eax, C            ; load C
    lodsd
    xchg   eax, D            ; load D
    pop    A                 ; restore A
    
    push   20                ; ecx = RC6_ROUNDS
    pop    ecx    
    ; B += *k; k++;
    add    B, [edi]
    scasd
    ; D += *k; k++;
    add    D, [edi]
    scasd
r6c_l3:
    push   ecx    
    ; T0 = ROTL32(B * (2 * B + 1), 5);
    lea    eax, [B+B+1]
    imul   eax, B
    rol    eax, 5
    ; T1 = ROTL32(D * (2 * D + 1), 5);
    lea    ecx, [D+D+1]
    imul   ecx, D
    rol    ecx, 5
    ; A = ROTL32(A ^ T0, T1) + *k; k++;
    xor    A, eax
    rol    A, cl       ; T1 should be ecx
    add    A, [edi]    ; += *k; 
    scasd              ; k++;
    ; C = ROTL32(C ^ T1, T0) + *k; k++;
    xor    C, ecx      ; C ^= T1
    xchg   eax, ecx    ; 
    rol    C, cl       ; rotate by T0
    add    C, [edi]
    scasd
    ; swap
    xchg   D, eax
    xchg   C, eax
    xchg   B, eax
    xchg   A, eax
    xchg   D, eax
    ; decrease counter
    pop    ecx
    loop   r6c_l3
    
    ; A += *k; k++;
    add    A, [edi]
    ; C += *k; k++;
    add    C, [edi+4]
    ; save ciphertext
    pop    edi         ; edi=data
    xchg   eax, A
    stosd              ; save A
    xchg   eax, B      
    stosd              ; save B 
    xchg   eax, C
    stosd              ; save C 
    xchg   eax, D 
    stosd              ; save D
    mov    ch, 1       ; ecx = 256
    add    esp, ecx
    popad
    ret
    