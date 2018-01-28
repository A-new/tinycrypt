                bits 32
upx_unpack:
                pushad
                mov     edi, [esp+32+4] ; dst
                mov     esi, [esp+32+8] ; src                
                or      ebp, -1         ; EBP = -1 
                
                call    __pop_getbit
                
                add     eax, eax
                jnz     __x1
                lodsd
                adc     eax, eax
__x1:
                retn
__pop_getbit:
                pop     ebx
                xor     eax, eax
__decompr_literals_n2b:
                movsb
__decompr_loop_n2b:
                call    ebx ; getbit
                jc      __decompr_literals_n2b
                cdq
                inc     edx
__loop1_n2b:
; (P4&1)==1, s11
                call    ebx ; getbit
                adc     edx, edx
                
                call    ebx ; getbit
                jnc     __loop1_n2b
                
                xor     ecx, ecx
                sub     edx, 3
                jc      __decompr_ebpeax_n2b
; P2=4
                mov     cl, 4           ; P2
__q1:
                call    ebx ; getbit
                adc     edx, edx
                
                loop    __q1
                neg     edx
                jz      __decompr_end_n2b
__decompr_ebpeax_n2b:
; P1=0
                inc     ecx
__loop2_n2b:
                call    ebx ; getbit
                adc     ecx, ecx
                
                call    ebx ; getbit
                jnc     __loop2_n2b
; P3=0
; P1=0
                dec     ecx
__decompr_got_mlen_n2b:
                cmp     edx, -0D00h
                adc     ecx, 1
                xchg    eax, esi
                lea     esi, [edi+edx]
                rep     movsb
                xchg    eax, esi
                jmp     __decompr_loop_n2b
__decompr_end_n2b:
                popad
                ret
                
