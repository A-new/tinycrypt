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
; BlaBla stream cipher in x64 assembly
;
; size: 270 bytes for win64
;       258 bytes for linux (use -DNIX)
;
; -----------------------------------------------


    bits 64
    
    %ifndef BIN
      global bb20_setkeyx
      global bb20_encryptx
      global bb20_keystreamx
      global FX
    %endif
    
    
bb20_setkeyx:
    ; save
    push   rsi
    push   rdi
    
    push   rcx   ; rdi = c
    pop    rdi
    
    ; load values
    call   sk_l0
    dq     0x6170786593810fab
    dq     0x3320646ec7398aee
    dq     0x79622d3217318274
    dq     0x6b206574babadada    
    dq     0x2ae36e593e46ad5f
    dq     0xb68f143029225fc9
    dq     0x8da1e08468303aa6
    dq     0xa48a209acd50a4a7
    dq     0x7fdc12f23f90778c
sk_l0:
    pop    rsi
    push   (4*8)/4
    pop    rcx
    rep    movsd
    
    ; copy key
    xchg   rsi, rdx   ; rsi = key
    mov    cl, 32/4
    rep    movsd
    
    ; copy remaining values
    xchg   rsi, rdx
    mov    cl, (5*8)/4
    rep    movsd
    
    ; set counter
    ; c->q[13] = 1
    push   1
    pop    rax
    stosq
    
    ; set nonce
    push   r8        ; rsi = nonce   
    pop    rsi
    movsq
    movsq    
    
    ; restore
    pop    rdi
    pop    rsi
    ret    
    
; eax = index
FX:
    push    rbx
    push    rcx
    push    rdx
    push    rdi
    push    rsi
    push    rbp    
bb_f0:    
    ; load indexes
    call    bb_f1
    dw      0c840H, 0d951H
    dw      0ea62H, 0fb73H
    dw      0fa50H, 0cb61H
    dw      0d872H, 0e943H
bb_f1:
    pop     rsi  ; pointer to indexes
    push    rcx
    mov     cl, 8
bb_f2:
    xor     eax, eax 
    lodsw
    ; ========================
    mov     ebx, eax
    mov     edx, eax
    mov     esi, eax

    ; a = (idx         & 0xF);
    and     eax, 15
    ; b = ((idx >>  4) & 0xF);
    shr     ebx, 4
    and     ebx, 15
    ; c = ((idx >>  8) & 0xF);
    shr     edx, 8
    and     edx, 15
    ; d = ((idx >> 12) & 0xF);
    shr     esi, 12        
    
    ; load ecx with rotate values
    mov     ecx, 0x3F101820
q_l1:
    ; s[a]+= s[b];
    mov     rbp, [rdi+rbx*8]    
    add     [rdi+rax*8], rbp
    ; s[d] = ROTR64(s[d] ^ s[a], r & 0xFF);
    mov     rbp, [rdi+rsi*8]
    xor     rbp, [rdi+rax*8]
    ror     rbp, cl
    mov     [rdi+rsi*8], rbp
    ; ======================
    loop    bb_f2
    pop     rcx
    loop    bb_f1
        
    shr     ecx, 16
    jnz     q_l1
    
    pop     rbp
    pop     rsi
    pop     rdi
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; generate 128-byte stream 
; rdi has x
; rsi has state   
bb20_streamx:
    push    rcx       ; save rcx

    push    rsi       ; save state
    push    rdi       ; save x
    
    ; copy state to x
    xchg    eax, ecx  ; zero the upper 56-bits of rcx
    mov     cl, 128   ; 1024-bits
    rep     movsb
    
    mov     cl, 20/2
bb_sx0    
    ; apply 20 rounds of permutation function
    pop     rdi       ; restore x
    pop     rsi       ; restore state
    ; F(x->q);
    call    FX   
    loop    bb_sx0
    
    ; add state to x    
    mov     cl, 16
bb_sx1:
    ; x->q[i] += c->q[i];
    mov     rax, [rsi+rcx*8-8]
    add     [rdi+rcx*8-8], rax
    loop    bb_sx1

    ; update block counter
    ; c->q[13]++;
    stc
    adc     qword[rsi+13*8], rcx    
    pop     rcx
    ret
 
; void bb20_encrypt (uint64_t len, void *in, bb20_ctx *ctx)
bb20_encryptx:
    push    rsi
    push    rdi
    push    rbx
    push    rbp
  
    push    r8              ; rsi = ctx
    pop     rsi    
    
    push    rdx             ; rbx = in
    pop     rbx

    sub     rsp, 128
    push    rsp
    pop     rdi    
cc_l0:
    jecxz   cc_l2             ; exit if len==0
    call    bb20_streamx
    xor     eax, eax          ; idx = 0  
cc_l1:
    mov     dl, byte[rdi+rax]
    xor     byte[rbx+rax], dl ; p[idx] ^= stream[idx]
    inc     al
    cmp     al, 128
    loopne  cc_l1             ; --len
    jmp     cc_l0
cc_l2:
    add     rsp, 128
    pop     rbp
    pop     rbx
    pop     rdi
    pop     rsi
    ret

; generate key stream of len-bytes    
bb20_keystreamx:
    push    rdi
    ; memset(out, 0, len);
    push    rdx
    pop     rdi
    push    rcx
    xor     eax, eax
    rep     stosb    
    pop     rcx
    ; bb20_encrypt(len, out, c);
    call    bb20_encryptx    
    pop     rdi
    ret
    
    
    
    