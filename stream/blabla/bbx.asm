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
; ChaCha20 stream cipher in x64 assembly
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
    
    ; c->q[13] = 1
    push   1
    pop    rax
    stosq
    
    push   r8        ; rsi = nonce   
    pop    rsi
    movsq
    movsq    
    
    ; restore
    pop    rdi
    pop    rsi
    ret    
    

blabla_permute:
    push    rbx
    push    rcx
    push    rdx
    push    rdi
    push    rsi
    push    rbp
    
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
    
    lea     rax, [rdi+rax*4]
    lea     rbx, [rdi+rbx*4]
    lea     rdx, [rdi+rdx*4]
    lea     rsi, [rdi+rsi*4]
    ; load ecx with rotate values
    ; 16, 12, 8, 7
    mov     ecx, 07080C10h
    mov     ebp, [rbx]
q_l1:
    xor     edi, edi
q_l2:
    ; x[a] = PLUS(x[a],x[b]); 
    add     ebp, [rax]
    mov     [rax], ebp
    ; x[d] = ROTATE(XOR(x[d],x[a]),cl);
    ; also x[b] = ROTATE(XOR(x[b],x[c]),cl);
    xor     ebp, [rsi]
    rol     ebp, cl
    mov     [rsi], ebp
    xchg    cl, ch
    xchg    rdx, rax
    xchg    rsi, rbx
    dec     rdi
    jp      q_l2
    ; --------------------------------------------
    shr     ecx, 16
    jnz     q_l1
    
    pop     rbp
    pop     rsi
    pop     rdi
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; generate stream    
; expects ctx in rdi, stream buffer in rbx
bb20_stream:
    push    rcx
    
    push    rbx
    push    rsi
    push    rdi
    
    ; copy state to stream buffer in rbx
    push    rsi
    pop     rbx
    push    rdx
    pop     rcx
    rep     movsb

    ; apply 20 rounds of permutation function
    pop     rdi
    push    rdi
    push    20/2  ; 20 rounds
    pop     rbp
ccs_l1:
    ; load indexes
    call    ccs_l2
    dw      0c840H, 0d951H
    dw      0ea62H, 0fb73H
    dw      0fa50H, 0cb61H
    dw      0d872H, 0e943H
ccs_l2:
    pop     rsi  ; pointer to indexes
    mov     cl, 8
ccs_l3:
    xor     eax, eax 
    lodsw
    call    blabla_permute
    loop    ccs_l3
    dec     rbp
    jnz     ccs_l1

    ; restore registers
    pop     rsi
    pop     rdi
    pop     rbx
    
    ; add state to stream    
    mov     cl, 16
ccs_l4:
    mov     rax, [rdi+rcx*8-8]
    ; x->q[i] += c->q[i];
    add     [rbx+rcx*8-8], rax
    loop    ccs_l4

    ; update block counter
    ; c->q[13]++;
    stc
    adc     qword[rdi+13*8], rcx    
    pop     rcx
    ret
 
; void bb20_encrypt(bb20_ctx *ctx, void *in, uint32_t len) 
bb20_encryptx:
    push    rsi
    push    rdi
    push    rbx
    push    rbp
%ifndef NIX    
    push    rcx              ; rdi = ctx
    pop     rdi    
    push    rdx
    pop     rsi
    push    r8               ; rcx = len
    pop     rcx
%else
    push    rdx              ; rcx = len 
    pop     rcx
%endif
    sub     rsp, 128
    push    rsp
    pop     rbx    
cc_l0:
    jecxz   cc_l2             ; exit if len==0
    call    bb20_stream
    xor     eax, eax          ; idx = 0  
cc_l1:
    mov     dl, byte[rbx+rax]
    xor     byte[rsi+rax], dl ; p[idx] ^= stream[idx]
    sub     edx, 1
    loopnz  cc_l1             ; --len
    jmp     cc_l0
cc_l2:
    add     rsp, 128
    pop     rbp
    pop     rbx
    pop     rdi
    pop     rsi
    ret


    