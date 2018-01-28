                
                
                
; int nrv_unpack(void *unpacked, void *packed);
                
                bits 32
nrv_unpack:
                pushad
                mov     edi, [esp+32+4] ; dst
                mov     esi, [esp+32+8] ; src
                or      ebp, -1
                
                call    __pop_getbit
                
                add     ebx, ebx
                jnz     __x1
                
                mov     ebx, [esi]
                sub     esi, -4
                adc     ebx, ebx
__x1:
                retn
__pop_getbit:
                pop     edx
                xor     ebx, ebx
__decompr_literals_n2b:
                movsb
__decompr_loop_n2b:
                call    edx ; getbit
                jc      __decompr_literals_n2b
                xor     eax, eax
                inc     eax
__loop1_n2b:
; (P4&1)==1, s11
                call    edx ; getbit
                adc     eax, eax
                
                call    edx ; getbit
                jnc     __loop1_n2b
                
                xor     ecx, ecx
                sub     eax, 3
                jc      __decompr_ebpeax_n2b
; P2=4
                mov     cl, 4           ; P2
__q1:
                call    edx ; getbit
                adc     eax, eax
                loop    __q1
                
                neg     eax             ; !P5 
                
                jz      __decompr_end_n2b
                xchg    ebp, eax
__decompr_ebpeax_n2b:
; P1=0
                inc     ecx
__loop2_n2b:
                call    edx ; getbit
                adc     ecx, ecx
                
                call    edx ; getbit
                jnc     __loop2_n2b
; P3=0
; P1=0
                dec     ecx
__decompr_got_mlen_n2b:
                cmp     ebp, -0D00h
                adc     ecx, 1
                add     [esp+28], ecx      ; update unpacked length
                push    esi
                lea     esi, [edi+ebp]
                rep     movsb
                pop     esi
                jmp     __decompr_loop_n2b
__decompr_end_n2b:
                popad
                ret
                
