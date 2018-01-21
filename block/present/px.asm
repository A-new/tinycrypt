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

; -----------------------------------------------
; PRESENT-128 block cipher in x86-64 assembly
;
; size: 188 for just encryption
;
; global calls use microsoft fastcall convention
;
; -----------------------------------------------
    bits 64
    
    %define PRESENT_RNDS 32
    
lsb:
    pop     rbx              ; rbx = sbox
    mov     cl, al           ; cl = x
    shr     al, 4            ; al = sbox[x >> 4] << 4
    xlatb                    ; 
    shl     al, 4    
    
    xchg    al, cl
    
    and     al, 15           ; al |= sbox[x & 0x0F]  
    xlatb
    or      al, cl    
    pop     rcx
    pop     rbx    
    ret
    
sub_byte:
    push    rbx 
    push    rcx 
    call    lsb
    ; sbox
    db      0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd
    db      0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2
    
%ifndef SINGLE
    
    %ifndef BIN
      global present128_setkeyx
      global present128_encryptx
    %endif
    
; rcx = present_ctx
; rdx = key    
present128_setkeyx:
    push    rsi
    push    rdi
    push    rbp
    push    rbx
    
    push    rcx              
    pop     rdi              ; rdi = ctx
    
    mov     rax, [rdx+8]     ; hi = key[1]
    mov     rdx, [rdx  ]     ; lo = key[0]
    
    xor     ecx, ecx         ; rnd = 0
psk:
    stosq                    ; ctx->key[rnd] = hi.q;  
    
    lea     ebx, [rcx*2+2]   ; lo.q  ^= (rnd + rnd) + 2;
    xor     rdx, rbx
    
    push    rax              ; t.q    = hi.q;
    pop     rbx
    push    rdx
    pop     rbp
    
    shl     rax, 61          ; hi.q   = (hi.q & 7) << 61;
    shr     rbp, 3           ; hi.q  |= (lo.q >> 3);
    or      rax, rbp
    
    shl     rdx, 61          ; lo.q    = (lo.q & 7) << 61;
    shr     rbx, 3           ; lo.q   |= ( t.q >> 3);
    or      rdx, rbx
    
    rol     rax, 8           ; hi.q    = ROTL64(hi.q, 8);
    call    sub_byte
    ror     rax, 8
    inc     cl
    cmp     cl, PRESENT_RNDS
    jne     psk
    jmp     pse_l4
    
; rcx = present_ctx
; rdx = buf    
present128_encryptx:
    push    rsi
    push    rdi
    push    rbp
    push    rbx
    
    push    rcx              ; rdi = present_ctx
    pop     rdi
    
    mov     rax, [rdx]       ; p.q = buf[0]
    
    push    PRESENT_RNDS-1
    pop     rcx
pse_l0:    
    xor     rax, [rdi]       ; p.q ^= ctx->key[i]
    scasq                    ; advance key position
    push    rcx              ; save i
    mov     cl, 8            ; j = 0
pse_l1:
    call    sub_byte         ; p.b[j] = sub_byte(p.b[j]); 
    ror     rax, 8           ; p.q    = ROTR64(s.q, 8);
    loop    pse_l1           ; j++ < 8
    ;
    mov     ebx, 0x30201000  ; r   = 0x30201000;
    xor     ebp, ebp
pse_l2:
    shr     rax, 1           ; CF = (p.q >> j) & 1
    jnc     pse_l3           ; no bit carried
    bts     rbp, rbx         ; set bit in rbp at position in bl
pse_l3:    
    inc     bl               ; r = ROTR32(r+1, 8);
    ror     ebx, 8

    add     cl, 4            ; j++
    jne     pse_l2

    xchg    rax, rbp         ; p.q = t.q 
    pop     rcx
    loop    pse_l0 
    
    ; post whitening
    xor     rax, [rdi]  ; p.q ^= ctx->key[PRESENT_RNDS-1];
    mov     [rdx], rax  ; buf[0] = p.q
pse_l4:    
    pop     rbx    
    pop     rbp    
    pop     rdi    
    pop     rsi    
    ret
    
%else

    %ifndef BIN
      global present128_encryptx
    %endif
    
present128_encryptx:
    push    rsi
    push    rdi
    push    rbp
    push    rbx
    
    mov     r9,  [rcx  ]     ; k0.q = key[0];
    mov     r10, [rcx+8]     ; k1.q = key[1];    
    mov     rax, [rdx  ]     ; p.q  = buf[0]
    
    push    rdx              ; save buf
    xor     edx, edx         ; i = 0
pse_l0:
    ; apply key whitening    
    xor     rax, r10         ; p.q ^= k1.q
    ; apply non-linear operation
    ; replace 16 nibbles with sbox values
    push    8
    pop     rcx
pse_l1:
    call    sub_byte         ; p.b[j] = sub_byte(p.b[j]); 
    ror     rax, 8           ; p.q    = ROTR64(p.q, 8);
    loop    pse_l1           ; j++ < 8

    ; apply linear operation
    ; bit permutations
    ;
    mov     ecx, 0x30201000  ; r   = 0x30201000;
    xor     ebp, ebp         ; t.q = 0;
    xor     ebx, ebx         ; j   = 0;
pse_l2:
    shr     rax, 1           ; CF = (p.q >> j) & 1
    jnc     pse_l3           ; no bit carried
    bts     rbp, rcx         ; set bit in rbp at position in cl
pse_l3:    
    inc     cl               ; r = ROTR32(r+1, 8);
    ror     ecx, 8
    
    add     bl, 4            ; j++, j < 64
    jne     pse_l2
    
    xchg    rax, rbp         ; p.q = t.q 
    
    ; create next subkey
    lea     ebx, [rdx*2+2]   ; k0.q ^= (i + i) + 2; 
    xchg    rdx, r9
    xchg    rax, r10
    xor     rdx, rbx
    
    push    rax              ; t.q   = k1.q;
    pop     rbx
    push    rdx
    pop     rbp
    
    ; k1.q = (k1.q << 61) | (k0.q >> 3);
    shl     rax, 61
    shr     rbp, 3 
    or      rax, rbp
    
    ; k0.q = (k0.q << 61) | ( t.q >> 3);
    shl     rdx, 61 
    shr     rbx, 3 
    or      rdx, rbx
    
    rol     rax, 8     ; k1.q    = ROTL64(k1.q, 8);         
    call    sub_byte   ; k1.b[0] = sub_byte(k1.b[0]);
    ror     rax, 8     ; k1.q    = ROTR64(k1.q, 8); 
    
    xchg    rdx, r9
    xchg    rax, r10
    
    inc     dl
    cmp     dl, PRESENT_RNDS
    jne     pse_l0
    
    pop     rdx
    
    ; post whitening and save
    ; ((uint64_t*)buf)[0] = (p.q ^ k1.q);
    xor     rax, r10     
    mov     [rdx], rax
    
    pop     rbx    
    pop     rbp    
    pop     rdi    
    pop     rsi    
    ret
    
%endif    
