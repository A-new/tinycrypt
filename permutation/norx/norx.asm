; mark_description "Intel(R) C++ Compiler XE for applications running on IA-32, Version 15.0.0.108 Build 20140726";
; mark_description "-O2 -Os -GS- -FAs -c";
	.686P
 	.387
	OPTION DOTNAME
	ASSUME	CS:FLAT,DS:FLAT,SS:FLAT
;ident "-defaultlib:libcpmt"
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_aead_encrypt
TXTST0:
; -- Begin  _norx_aead_encrypt
;_norx_aead_encrypt	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_aead_encrypt
; mark_begin;
IF @Version GE 800
  .MMX
ELSEIF @Version GE 612
  .MMX
  MMWORD TEXTEQU <QWORD>
ENDIF
IF @Version GE 800
  .XMM
ELSEIF @Version GE 614
  .XMM
  XMMWORD TEXTEQU <OWORD>
ENDIF

	PUBLIC _norx_aead_encrypt
_norx_aead_encrypt	PROC NEAR 
; parameter 1: 8 + ebp
; parameter 2: 12 + ebp
; parameter 3: 16 + ebp
; parameter 4: 20 + ebp
; parameter 5: 24 + ebp
; parameter 6: 28 + ebp
; parameter 7: 32 + ebp
; parameter 8: 36 + ebp
; parameter 9: 40 + ebp
; parameter 10: 44 + ebp
.B1.1:                          ; Preds .B1.0

;;; {

        push      ebp                                           ;650.1
        mov       ebp, esp                                      ;650.1
        push      esi                                           ;650.1
        push      edi                                           ;650.1
        sub       esp, 96                                       ;650.1

;;;     unsigned char k[BYTES(NORX_K)];
;;;     norx_state_t state;
;;; 
;;;     memcpy(k, key, sizeof(k));

        lea       edi, DWORD PTR [-88+ebp]                      ;654.5
        mov       esi, DWORD PTR [44+ebp]                       ;654.5
        movsd                                                   ;654.5
                                ; LOE ebx esi edi
.B1.14:                         ; Preds .B1.1
        movsd                                                   ;654.5
                                ; LOE ebx esi edi
.B1.13:                         ; Preds .B1.14
        movsd                                                   ;654.5
                                ; LOE ebx esi edi
.B1.12:                         ; Preds .B1.13
        movsd                                                   ;654.5
                                ; LOE ebx
.B1.2:                          ; Preds .B1.12

;;;     norx_init(state, k, nonce);

        mov       ecx, DWORD PTR [40+ebp]                       ;655.5
        lea       eax, DWORD PTR [-72+ebp]                      ;655.5
        lea       edx, DWORD PTR [-16+eax]                      ;655.5
        call      _norx_init                                    ;655.5
                                ; LOE ebx
.B1.3:                          ; Preds .B1.2

;;;     norx_absorb_data(state, a, alen, HEADER_TAG);

        mov       edx, DWORD PTR [16+ebp]                       ;656.5
        lea       eax, DWORD PTR [-72+ebp]                      ;656.5
        mov       ecx, DWORD PTR [20+ebp]                       ;656.5
        mov       DWORD PTR [12+esp], 1                         ;656.5
        call      _norx_absorb_data.                            ;656.5
                                ; LOE ebx
.B1.4:                          ; Preds .B1.3
        mov       edi, DWORD PTR [8+ebp]                        ;642.6

;;;     norx_encrypt_data(state, c, m, mlen);

        lea       eax, DWORD PTR [-72+ebp]                      ;657.5
        mov       esi, DWORD PTR [28+ebp]                       ;642.6
        mov       edx, edi                                      ;657.5
        mov       ecx, DWORD PTR [24+ebp]                       ;657.5
        mov       DWORD PTR [12+esp], esi                       ;657.5
        call      _norx_encrypt_data.                           ;657.5
                                ; LOE ebx esi edi
.B1.5:                          ; Preds .B1.4

;;;     norx_absorb_data(state, z, zlen, TRAILER_TAG);

        mov       edx, DWORD PTR [32+ebp]                       ;658.5
        lea       eax, DWORD PTR [-72+ebp]                      ;658.5
        mov       ecx, DWORD PTR [36+ebp]                       ;658.5
        mov       DWORD PTR [12+esp], 4                         ;658.5
        call      _norx_absorb_data.                            ;658.5
                                ; LOE ebx esi edi
.B1.6:                          ; Preds .B1.5

;;;     norx_finalise(state, c + mlen, k);

        lea       edx, DWORD PTR [edi+esi]                      ;659.5
        lea       eax, DWORD PTR [-72+ebp]                      ;659.5
        lea       ecx, DWORD PTR [-16+eax]                      ;659.5
        call      _norx_finalise                                ;659.5
                                ; LOE ebx esi
.B1.7:                          ; Preds .B1.6
        mov       eax, DWORD PTR [12+ebp]                       ;642.6

;;;     *clen = mlen + BYTES(NORX_T);

        lea       esi, DWORD PTR [16+esi]                       ;660.20

;;;     burn(state, 0, sizeof(norx_state_t));

        push      16                                            ;661.5
        pop       ecx                                           ;661.5
        lea       edi, DWORD PTR [-72+ebp]                      ;661.5
        mov       DWORD PTR [eax], esi                          ;660.6
        xor       eax, eax                                      ;661.5
        rep   stosd                                             ;661.5
                                ; LOE ebx
.B1.8:                          ; Preds .B1.7

;;;     burn(k, 0, sizeof(k));

        xor       eax, eax                                      ;662.5
        lea       edi, DWORD PTR [-88+ebp]                      ;662.5
        stosd                                                   ;662.5
                                ; LOE eax ebx edi
.B1.17:                         ; Preds .B1.8
        stosd                                                   ;662.5
                                ; LOE eax ebx edi
.B1.16:                         ; Preds .B1.17
        stosd                                                   ;662.5
                                ; LOE eax ebx edi
.B1.15:                         ; Preds .B1.16
        stosd                                                   ;662.5
                                ; LOE ebx
.B1.9:                          ; Preds .B1.15

;;; }

        lea       esp, DWORD PTR [-8+ebp]                       ;663.1
        pop       edi                                           ;663.1
        pop       esi                                           ;663.1
        pop       ebp                                           ;663.1
        ret                                                     ;663.1
                                ; LOE
; mark_end;
_norx_aead_encrypt ENDP
;_norx_aead_encrypt	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_aead_encrypt
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_encrypt_data
TXTST1:
; -- Begin  _norx_encrypt_data
;_norx_encrypt_data	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_encrypt_data
; mark_begin;

	PUBLIC _norx_encrypt_data
_norx_encrypt_data	PROC NEAR 
; parameter 1: eax
; parameter 2: edx
; parameter 3: ecx
; parameter 4: 96 + esp
.B2.1:                          ; Preds .B2.0

;;; {

        mov       eax, DWORD PTR [4+esp]                        ;335.1
        mov       edx, DWORD PTR [8+esp]                        ;335.1
        mov       ecx, DWORD PTR [12+esp]                       ;335.1
	PUBLIC _norx_encrypt_data.
_norx_encrypt_data.::
        push      esi                                           ;335.1
        push      edi                                           ;335.1
        push      ebx                                           ;335.1
        push      ebp                                           ;335.1
        sub       esp, 64                                       ;335.1
        mov       esi, ecx                                      ;335.1
        mov       ebx, DWORD PTR [96+esp]                       ;334.6
        mov       ebp, edx                                      ;335.1
        mov       DWORD PTR [60+esp], eax                       ;335.1

;;;     if (inlen > 0)

        test      ebx, ebx                                      ;336.17
        jbe       .B2.11        ; Prob 50%                      ;336.17
                                ; LOE ebx ebp esi
.B2.2:                          ; Preds .B2.1

;;;     {
;;;         while (inlen >= BYTES(NORX_R))

        cmp       ebx, 48                                       ;338.25
        jb        .B2.7         ; Prob 10%                      ;338.25
                                ; LOE ebx ebp esi
.B2.4:                          ; Preds .B2.2 .B2.5

;;;         {
;;;             norx_encrypt_block(state, out, in);

        mov       edx, ebp                                      ;340.13
        mov       ecx, esi                                      ;340.13
        mov       eax, DWORD PTR [60+esp]                       ;340.13
        call      _norx_encrypt_block                           ;340.13
                                ; LOE ebx ebp esi
.B2.5:                          ; Preds .B2.4

;;;             #if defined(NORX_DEBUG)
;;;             printf("Encrypt block\n");
;;;             norx_debug(state, in, BYTES(NORX_R), out, BYTES(NORX_R));
;;;             #endif
;;;             inlen -= BYTES(NORX_R);

        add       ebx, -48                                      ;345.13

;;;             in    += BYTES(NORX_R);

        add       esi, 48                                       ;346.13

;;;             out   += BYTES(NORX_R);

        add       ebp, 48                                       ;347.13
        cmp       ebx, 48                                       ;338.25
        jae       .B2.4         ; Prob 82%                      ;338.25
                                ; LOE ebx ebp esi
.B2.7:                          ; Preds .B2.5 .B2.2

;;;         }
;;;         norx_encrypt_lastblock(state, out, in, inlen);

        xor       eax, eax                                      ;349.9
        lea       edi, DWORD PTR [12+esp]                       ;349.9
        push      12                                            ;349.9
        pop       ecx                                           ;349.9
        rep   stosd                                             ;349.9
                                ; LOE ebx ebp esi
.B2.8:                          ; Preds .B2.7
        mov       ecx, ebx                                      ;349.9
        lea       edi, DWORD PTR [12+esp]                       ;349.9
        rep   movsb                                             ;349.9
                                ; LOE ebx ebp
.B2.9:                          ; Preds .B2.8
        mov       BYTE PTR [12+esp+ebx], 1                      ;349.9
        lea       edx, DWORD PTR [12+esp]                       ;349.9
        mov       ecx, edx                                      ;349.9
        mov       eax, DWORD PTR [48+edx]                       ;349.9
        or        BYTE PTR [47+edx], -128                       ;349.9
        call      _norx_encrypt_block                           ;349.9
                                ; LOE ebx ebp
.B2.10:                         ; Preds .B2.9
        mov       edi, ebp                                      ;349.9
        lea       esi, DWORD PTR [12+esp]                       ;349.9
        mov       ecx, ebx                                      ;349.9
        rep   movsb                                             ;349.9
                                ; LOE
.B2.11:                         ; Preds .B2.10 .B2.1

;;;         #if defined(NORX_DEBUG)
;;;         printf("Encrypt lastblock\n");
;;;         norx_debug(state, in, inlen, out, inlen);
;;;         #endif
;;;     }
;;; }

        add       esp, 64                                       ;355.1
        pop       ebp                                           ;355.1
        pop       ebx                                           ;355.1
        pop       edi                                           ;355.1
        pop       esi                                           ;355.1
        ret                                                     ;355.1
                                ; LOE
; mark_end;
_norx_encrypt_data ENDP
;_norx_encrypt_data	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_encrypt_data
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_encrypt_block
TXTST2:
; -- Begin  _norx_encrypt_block
;_norx_encrypt_block	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_encrypt_block
; mark_begin;

_norx_encrypt_block	PROC NEAR PRIVATE
; parameter 1: eax
; parameter 2: edx
; parameter 3: ecx
.B3.1:                          ; Preds .B3.0

;;; {

        push      esi                                           ;176.1
        push      edi                                           ;176.1
        push      ebx                                           ;176.1
        push      ebp                                           ;176.1
        push      esi                                           ;176.1
        push      esi                                           ;176.1
        mov       esi, ecx                                      ;176.1
        mov       ebp, eax                                      ;176.1

;;;     size_t i;
;;;     norx_word_t * S = state->S;
;;; 
;;;     S[15] ^= PAYLOAD_TAG;
;;;     norx_permute(state);

        xor       bl, bl                                        ;181.5
        mov       DWORD PTR [4+esp], edx                        ;176.1
        xor       DWORD PTR [60+ebp], 2                         ;180.5
                                ; LOE ebp esi bl
.B3.2:                          ; Preds .B3.3 .B3.1
        mov       eax, ebp                                      ;181.5
        call      _F                                            ;181.5
                                ; LOE ebp esi bl
.B3.3:                          ; Preds .B3.2
        inc       bl                                            ;181.5
        cmp       bl, 6                                         ;181.5
        jb        .B3.2         ; Prob 83%                      ;181.5
                                ; LOE ebp esi bl
.B3.4:                          ; Preds .B3.3

;;; 
;;;     for (i = 0; i < WORDS(NORX_R); ++i) {

        xor       edi, edi                                      ;183.10
                                ; LOE ebp esi edi
.B3.5:                          ; Preds .B3.5 .B3.4

;;;         S[i] ^= LOAD(in + i * BYTES(NORX_W));

        movzx     ecx, BYTE PTR [1+esi+edi*4]                   ;184.17
        shl       ecx, 8                                        ;184.17
        movzx     edx, BYTE PTR [esi+edi*4]                     ;184.17
        or        edx, ecx                                      ;184.17
        movzx     ecx, BYTE PTR [2+esi+edi*4]                   ;184.17
        shl       ecx, 16                                       ;184.17
        or        edx, ecx                                      ;184.17
        movzx     ecx, BYTE PTR [3+esi+edi*4]                   ;184.17
        shl       ecx, 24                                       ;184.17
        or        edx, ecx                                      ;184.17

;;;         STORE(out + i * BYTES(NORX_W), S[i]);

        mov       eax, DWORD PTR [4+esp]                        ;185.9
        xor       edx, DWORD PTR [ebp+edi*4]                    ;184.9
        mov       ecx, edx                                      ;185.9
        mov       ebx, edx                                      ;185.9
        mov       DWORD PTR [ebp+edi*4], edx                    ;184.9
        mov       BYTE PTR [eax+edi*4], dl                      ;185.9
        shr       ecx, 8                                        ;185.9
        shr       ebx, 16                                       ;185.9
        shr       edx, 24                                       ;185.9
        mov       BYTE PTR [1+eax+edi*4], cl                    ;185.9
        mov       BYTE PTR [2+eax+edi*4], bl                    ;185.9
        mov       BYTE PTR [3+eax+edi*4], dl                    ;185.9
        inc       edi                                           ;183.38
        cmp       edi, 12                                       ;183.21
        jb        .B3.5         ; Prob 91%                      ;183.21
                                ; LOE ebp esi edi
.B3.6:                          ; Preds .B3.5

;;;     }
;;; }

        pop       ecx                                           ;187.1
        pop       ecx                                           ;187.1
        pop       ebp                                           ;187.1
        pop       ebx                                           ;187.1
        pop       edi                                           ;187.1
        pop       esi                                           ;187.1
        ret                                                     ;187.1
                                ; LOE
; mark_end;
_norx_encrypt_block ENDP
;_norx_encrypt_block	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_encrypt_block
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_absorb_data
TXTST3:
; -- Begin  _norx_absorb_data
;_norx_absorb_data	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_absorb_data
; mark_begin;

	PUBLIC _norx_absorb_data
_norx_absorb_data	PROC NEAR 
; parameter 1: eax
; parameter 2: edx
; parameter 3: ecx
; parameter 4: 92 + esp
.B4.1:                          ; Preds .B4.0

;;; {

        mov       eax, DWORD PTR [4+esp]                        ;281.1
        mov       edx, DWORD PTR [8+esp]                        ;281.1
        mov       ecx, DWORD PTR [12+esp]                       ;281.1
	PUBLIC _norx_absorb_data.
_norx_absorb_data.::
        push      esi                                           ;281.1
        push      edi                                           ;281.1
        push      ebx                                           ;281.1
        push      ebp                                           ;281.1
        sub       esp, 60                                       ;281.1
        mov       ebp, ecx                                      ;281.1
        mov       esi, edx                                      ;281.1
        mov       ebx, eax                                      ;281.1

;;;     if (inlen > 0)

        test      ebp, ebp                                      ;282.17
        jbe       .B4.10        ; Prob 50%                      ;282.17
                                ; LOE ebx ebp esi
.B4.2:                          ; Preds .B4.1

;;;     {
;;;         while (inlen >= BYTES(NORX_R))

        cmp       ebp, 48                                       ;284.25
        jb        .B4.7         ; Prob 10%                      ;284.25
                                ; LOE ebx ebp esi
.B4.4:                          ; Preds .B4.2 .B4.5

;;;         {
;;;             norx_absorb_block(state, in, tag);

        mov       eax, ebx                                      ;286.13
        mov       edx, esi                                      ;286.13
        mov       ecx, DWORD PTR [92+esp]                       ;286.13
        call      _norx_absorb_block                            ;286.13
                                ; LOE ebx ebp esi
.B4.5:                          ; Preds .B4.4

;;;             #if defined(NORX_DEBUG)
;;;             printf("Absorb block\n");
;;;             norx_debug(state, in, BYTES(NORX_R), NULL, 0);
;;;             #endif
;;;             inlen -= BYTES(NORX_R);

        add       ebp, -48                                      ;291.13

;;;             in += BYTES(NORX_R);

        add       esi, 48                                       ;292.13
        cmp       ebp, 48                                       ;284.25
        jae       .B4.4         ; Prob 82%                      ;284.25
                                ; LOE ebx ebp esi
.B4.7:                          ; Preds .B4.5 .B4.2

;;;         }
;;;         norx_absorb_lastblock(state, in, inlen, tag);

        xor       eax, eax                                      ;294.9
        lea       edi, DWORD PTR [12+esp]                       ;294.9
        push      12                                            ;294.9
        pop       ecx                                           ;294.9
        rep   stosd                                             ;294.9
                                ; LOE ebx ebp esi
.B4.8:                          ; Preds .B4.7
        mov       ecx, ebp                                      ;294.9
        lea       edi, DWORD PTR [12+esp]                       ;294.9
        rep   movsb                                             ;294.9
                                ; LOE ebx ebp
.B4.9:                          ; Preds .B4.8
        mov       BYTE PTR [12+esp+ebp], 1                      ;294.9
        mov       eax, ebx                                      ;294.9
        mov       ecx, DWORD PTR [92+esp]                       ;294.9
        lea       edx, DWORD PTR [12+esp]                       ;294.9
        or        BYTE PTR [47+edx], -128                       ;294.9
        call      _norx_absorb_block                            ;294.9
                                ; LOE
.B4.10:                         ; Preds .B4.9 .B4.1

;;;         #if defined(NORX_DEBUG)
;;;         printf("Absorb lastblock\n");
;;;         norx_debug(state, in, inlen, NULL, 0);
;;;         #endif
;;;     }
;;; }

        add       esp, 60                                       ;300.1
        pop       ebp                                           ;300.1
        pop       ebx                                           ;300.1
        pop       edi                                           ;300.1
        pop       esi                                           ;300.1
        ret                                                     ;300.1
                                ; LOE
; mark_end;
_norx_absorb_data ENDP
;_norx_absorb_data	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_absorb_data
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_absorb_block
TXTST4:
; -- Begin  _norx_absorb_block
;_norx_absorb_block	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_absorb_block
; mark_begin;

_norx_absorb_block	PROC NEAR PRIVATE
; parameter 1: eax
; parameter 2: edx
; parameter 3: ecx
.B5.1:                          ; Preds .B5.0

;;; {

        push      esi                                           ;156.1
        push      ebx                                           ;156.1
        push      ebp                                           ;156.1
        push      esi                                           ;156.1
        mov       esi, edx                                      ;156.1
        mov       ebp, eax                                      ;156.1

;;;     size_t i;
;;;     norx_word_t * S = state->S;
;;; 
;;;     S[15] ^= tag;
;;;     norx_permute(state);

        xor       bl, bl                                        ;161.5
        xor       DWORD PTR [60+ebp], ecx                       ;160.5
                                ; LOE ebp esi edi bl
.B5.2:                          ; Preds .B5.3 .B5.1
        mov       eax, ebp                                      ;161.5
        call      _F                                            ;161.5
                                ; LOE ebp esi edi bl
.B5.3:                          ; Preds .B5.2
        inc       bl                                            ;161.5
        cmp       bl, 6                                         ;161.5
        jb        .B5.2         ; Prob 83%                      ;161.5
                                ; LOE ebp esi edi bl
.B5.4:                          ; Preds .B5.3

;;; 
;;;     for (i = 0; i < WORDS(NORX_R); ++i) {

        xor       ecx, ecx                                      ;163.10
                                ; LOE ecx ebp esi edi
.B5.5:                          ; Preds .B5.5 .B5.4

;;;         S[i] ^= LOAD(in + i * BYTES(NORX_W));

        movzx     ebx, BYTE PTR [1+esi+ecx*4]                   ;164.17
        shl       ebx, 8                                        ;164.17
        movzx     edx, BYTE PTR [esi+ecx*4]                     ;164.17
        or        edx, ebx                                      ;164.17
        movzx     ebx, BYTE PTR [2+esi+ecx*4]                   ;164.17
        shl       ebx, 16                                       ;164.17
        or        edx, ebx                                      ;164.17
        movzx     ebx, BYTE PTR [3+esi+ecx*4]                   ;164.17
        shl       ebx, 24                                       ;164.17
        or        edx, ebx                                      ;164.17
        xor       DWORD PTR [ebp+ecx*4], edx                    ;164.9
        inc       ecx                                           ;163.38
        cmp       ecx, 12                                       ;163.21
        jb        .B5.5         ; Prob 91%                      ;163.21
                                ; LOE ecx ebp esi edi
.B5.6:                          ; Preds .B5.5

;;;     }
;;; }

        pop       ecx                                           ;166.1
        pop       ebp                                           ;166.1
        pop       ebx                                           ;166.1
        pop       esi                                           ;166.1
        ret                                                     ;166.1
                                ; LOE
; mark_end;
_norx_absorb_block ENDP
;_norx_absorb_block	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_absorb_block
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_finalise
TXTST5:
; -- Begin  _norx_finalise
;_norx_finalise	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_finalise
; mark_begin;

_norx_finalise	PROC NEAR PRIVATE
; parameter 1: eax
; parameter 2: edx
; parameter 3: ecx
.B6.1:                          ; Preds .B6.0

;;; {

        push      esi                                           ;592.1
        push      edi                                           ;592.1
        push      ebx                                           ;592.1
        push      ebp                                           ;592.1
        sub       esp, 32                                       ;592.1
        mov       ebp, ecx                                      ;592.1
        mov       DWORD PTR [28+esp], edx                       ;592.1

;;;     norx_word_t * S = state->S;
;;;     uint8_t lastblock[BYTES(NORX_C)];
;;; 
;;;     S[15] ^= FINAL_TAG;
;;; 
;;;     norx_permute(state);

        xor       bl, bl                                        ;598.5
        mov       DWORD PTR [20+esp], eax                       ;592.1
        xor       DWORD PTR [60+eax], 8                         ;596.5
                                ; LOE ebp bl
.B6.2:                          ; Preds .B6.3 .B6.1
        mov       eax, DWORD PTR [20+esp]                       ;598.5
        call      _F                                            ;598.5
                                ; LOE ebp bl
.B6.3:                          ; Preds .B6.2
        inc       bl                                            ;598.5
        cmp       bl, 6                                         ;598.5
        jb        .B6.2         ; Prob 83%                      ;598.5
                                ; LOE ebp bl
.B6.4:                          ; Preds .B6.3

;;; 
;;;     S[12] ^= LOAD(k + 0 * BYTES(NORX_W));

        movzx     edx, BYTE PTR [1+ebp]                         ;600.14
        shl       edx, 8                                        ;600.14
        movzx     esi, BYTE PTR [ebp]                           ;600.14
        movzx     ecx, BYTE PTR [2+ebp]                         ;600.14
        or        esi, edx                                      ;600.14
        shl       ecx, 16                                       ;600.14
        movzx     ebx, BYTE PTR [3+ebp]                         ;600.14
        or        esi, ecx                                      ;600.14

;;;     S[13] ^= LOAD(k + 1 * BYTES(NORX_W));

        movzx     edi, BYTE PTR [5+ebp]                         ;601.14
        shl       ebx, 24                                       ;600.14
        shl       edi, 8                                        ;601.14
        or        esi, ebx                                      ;600.14
        mov       eax, DWORD PTR [20+esp]                       ;600.5
        movzx     ebx, BYTE PTR [4+ebp]                         ;601.14
        movzx     edx, BYTE PTR [6+ebp]                         ;601.14
        or        ebx, edi                                      ;601.14
        shl       edx, 16                                       ;601.14
        movzx     ecx, BYTE PTR [7+ebp]                         ;601.14
        or        ebx, edx                                      ;601.14
        shl       ecx, 24                                       ;601.14
        xor       DWORD PTR [48+eax], esi                       ;600.5
        or        ebx, ecx                                      ;601.14

;;;     S[14] ^= LOAD(k + 2 * BYTES(NORX_W));

        movzx     esi, BYTE PTR [9+ebp]                         ;602.14
        shl       esi, 8                                        ;602.14
        xor       DWORD PTR [52+eax], ebx                       ;601.5
        movzx     ebx, BYTE PTR [8+ebp]                         ;602.14
        movzx     edx, BYTE PTR [10+ebp]                        ;602.14
        or        ebx, esi                                      ;602.14
        shl       edx, 16                                       ;602.14
        movzx     ecx, BYTE PTR [11+ebp]                        ;602.14
        or        ebx, edx                                      ;602.14
        shl       ecx, 24                                       ;602.14
        or        ebx, ecx                                      ;602.14

;;;     S[15] ^= LOAD(k + 3 * BYTES(NORX_W));

        movzx     edi, BYTE PTR [13+ebp]                        ;603.14
        shl       edi, 8                                        ;603.14
        xor       DWORD PTR [56+eax], ebx                       ;602.5
        movzx     ebx, BYTE PTR [12+ebp]                        ;603.14
        movzx     edx, BYTE PTR [14+ebp]                        ;603.14
        or        ebx, edi                                      ;603.14
        shl       edx, 16                                       ;603.14
        movzx     ecx, BYTE PTR [15+ebp]                        ;603.14
        or        ebx, edx                                      ;603.14
        shl       ecx, 24                                       ;603.14
        or        ebx, ecx                                      ;603.14
        xor       DWORD PTR [60+eax], ebx                       ;603.5

;;; 
;;;     norx_permute(state);

        xor       bl, bl                                        ;605.5
                                ; LOE ebp bl
.B6.5:                          ; Preds .B6.6 .B6.4
        mov       eax, DWORD PTR [20+esp]                       ;605.5
        call      _F                                            ;605.5
                                ; LOE ebp bl
.B6.6:                          ; Preds .B6.5
        inc       bl                                            ;605.5
        cmp       bl, 6                                         ;605.5
        jb        .B6.5         ; Prob 83%                      ;605.5
                                ; LOE ebp bl
.B6.7:                          ; Preds .B6.6

;;; 
;;;     S[12] ^= LOAD(k + 0 * BYTES(NORX_W));

        movzx     edi, BYTE PTR [1+ebp]                         ;607.14
        shl       edi, 8                                        ;607.14
        movzx     eax, BYTE PTR [ebp]                           ;607.14
        movzx     esi, BYTE PTR [2+ebp]                         ;607.14
        or        eax, edi                                      ;607.14
        shl       esi, 16                                       ;607.14
        movzx     ecx, BYTE PTR [3+ebp]                         ;607.14
        or        eax, esi                                      ;607.14

;;;     S[13] ^= LOAD(k + 1 * BYTES(NORX_W));

        movzx     edx, BYTE PTR [5+ebp]                         ;608.14
        shl       ecx, 24                                       ;607.14
        shl       edx, 8                                        ;608.14
        or        eax, ecx                                      ;607.14
        movzx     ebx, BYTE PTR [4+ebp]                         ;608.14
        movzx     ecx, BYTE PTR [6+ebp]                         ;608.14
        or        ebx, edx                                      ;608.14
        shl       ecx, 16                                       ;608.14
        mov       esi, DWORD PTR [20+esp]                       ;607.5
        or        ebx, ecx                                      ;608.14
        movzx     edi, BYTE PTR [7+ebp]                         ;608.14
        shl       edi, 24                                       ;608.14
        or        ebx, edi                                      ;608.14
        xor       ebx, DWORD PTR [52+esi]                       ;608.5
        mov       DWORD PTR [24+esp], ebx                       ;608.5
        mov       DWORD PTR [52+esi], ebx                       ;608.5

;;;     S[14] ^= LOAD(k + 2 * BYTES(NORX_W));

        movzx     ebx, BYTE PTR [9+ebp]                         ;609.14
        shl       ebx, 8                                        ;609.14
        movzx     edx, BYTE PTR [8+ebp]                         ;609.14
        movzx     ecx, BYTE PTR [10+ebp]                        ;609.14
        or        edx, ebx                                      ;609.14
        shl       ecx, 16                                       ;609.14

;;;     S[15] ^= LOAD(k + 3 * BYTES(NORX_W));

        movzx     ebx, BYTE PTR [13+ebp]                        ;610.14
        or        edx, ecx                                      ;609.14
        xor       eax, DWORD PTR [48+esi]                       ;607.5
        shl       ebx, 8                                        ;610.14
        movzx     edi, BYTE PTR [11+ebp]                        ;609.14
        shl       edi, 24                                       ;609.14
        movzx     ecx, BYTE PTR [12+ebp]                        ;610.14
        or        edx, edi                                      ;609.14
        or        ecx, ebx                                      ;610.14

;;; 
;;;     STORE(lastblock + 0 * BYTES(NORX_W), S[12]);

        mov       ebx, eax                                      ;612.5
        movzx     edi, BYTE PTR [14+ebp]                        ;610.14
        shl       edi, 16                                       ;610.14
        shr       ebx, 8                                        ;612.5
        or        ecx, edi                                      ;610.14
        mov       DWORD PTR [48+esi], eax                       ;607.5
        mov       BYTE PTR [4+esp], al                          ;612.11
        mov       BYTE PTR [5+esp], bl                          ;612.11
        mov       ebx, eax                                      ;612.5
        shr       eax, 24                                       ;612.5
        movzx     ebp, BYTE PTR [15+ebp]                        ;610.14
        mov       BYTE PTR [7+esp], al                          ;612.11
        shl       ebp, 24                                       ;610.14

;;;     STORE(lastblock + 1 * BYTES(NORX_W), S[13]);

        mov       eax, DWORD PTR [24+esp]                       ;613.5
        or        ecx, ebp                                      ;610.14
        xor       edx, DWORD PTR [56+esi]                       ;609.5
        mov       BYTE PTR [8+esp], al                          ;613.5
        shr       eax, 8                                        ;613.5
        mov       BYTE PTR [9+esp], al                          ;613.5
        mov       eax, DWORD PTR [24+esp]                       ;613.5
        shr       eax, 24                                       ;613.5
        mov       BYTE PTR [11+esp], al                         ;613.5

;;;     STORE(lastblock + 2 * BYTES(NORX_W), S[14]);

        mov       eax, edx                                      ;614.5
        xor       ecx, DWORD PTR [60+esi]                       ;610.5
        shr       ebx, 16                                       ;612.5
        mov       BYTE PTR [6+esp], bl                          ;612.11
        mov       ebx, DWORD PTR [24+esp]                       ;613.5
        shr       ebx, 16                                       ;613.5
        mov       DWORD PTR [56+esi], edx                       ;609.5
        mov       BYTE PTR [10+esp], bl                         ;613.5
        mov       ebx, edx                                      ;614.5
        mov       BYTE PTR [12+esp], dl                         ;614.5
        shr       eax, 16                                       ;614.5
        shr       edx, 24                                       ;614.5
        mov       BYTE PTR [14+esp], al                         ;614.5

;;;     STORE(lastblock + 3 * BYTES(NORX_W), S[15]);

        mov       eax, ecx                                      ;615.5
        mov       BYTE PTR [15+esp], dl                         ;614.5
        mov       edx, ecx                                      ;615.5
        mov       DWORD PTR [60+esi], ecx                       ;610.5

;;; 
;;;     memcpy(tag, lastblock, BYTES(NORX_T));

        lea       esi, DWORD PTR [4+esp]                        ;617.5
        shr       ebx, 8                                        ;614.5
        mov       BYTE PTR [12+esi], cl                         ;615.5
        shr       edx, 8                                        ;615.5
        shr       eax, 16                                       ;615.5
        shr       ecx, 24                                       ;615.5
        mov       edi, DWORD PTR [24+esi]                       ;617.5
        mov       BYTE PTR [9+esi], bl                          ;614.5
        mov       BYTE PTR [13+esi], dl                         ;615.5
        mov       BYTE PTR [14+esi], al                         ;615.5
        mov       BYTE PTR [15+esi], cl                         ;615.5
        movsd                                                   ;617.5
                                ; LOE esi edi
.B6.15:                         ; Preds .B6.7
        movsd                                                   ;617.5
                                ; LOE esi edi
.B6.14:                         ; Preds .B6.15
        movsd                                                   ;617.5
                                ; LOE esi edi
.B6.13:                         ; Preds .B6.14
        movsd                                                   ;617.5
                                ; LOE
.B6.8:                          ; Preds .B6.13

;;; 
;;;     #if defined(NORX_DEBUG)
;;;     printf("Finalise\n");
;;;     norx_debug(state, NULL, 0, NULL, 0);
;;;     #endif
;;; 
;;;     burn(lastblock, 0, BYTES(NORX_C)); /* burn buffer */

        xor       eax, eax                                      ;624.5
        lea       edi, DWORD PTR [4+esp]                        ;624.5
        stosd                                                   ;624.5
                                ; LOE eax edi
.B6.18:                         ; Preds .B6.8
        stosd                                                   ;624.5
                                ; LOE eax edi
.B6.17:                         ; Preds .B6.18
        stosd                                                   ;624.5
                                ; LOE eax edi
.B6.16:                         ; Preds .B6.17
        stosd                                                   ;624.5
                                ; LOE
.B6.9:                          ; Preds .B6.16

;;;     burn(state, 0, sizeof(norx_state_t)); /* at this point we can also burn the state */

        xor       eax, eax                                      ;625.5
        push      16                                            ;625.5
        pop       ecx                                           ;625.5
        mov       edi, DWORD PTR [20+esp]                       ;625.5
        rep   stosd                                             ;625.5
                                ; LOE
.B6.10:                         ; Preds .B6.9

;;; }

        add       esp, 32                                       ;626.1
        pop       ebp                                           ;626.1
        pop       ebx                                           ;626.1
        pop       edi                                           ;626.1
        pop       esi                                           ;626.1
        ret                                                     ;626.1
                                ; LOE
; mark_end;
_norx_finalise ENDP
;_norx_finalise	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_finalise
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_aead_decrypt
TXTST6:
; -- Begin  _norx_aead_decrypt
;_norx_aead_decrypt	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_aead_decrypt
; mark_begin;

	PUBLIC _norx_aead_decrypt
_norx_aead_decrypt	PROC NEAR 
; parameter 1: 8 + ebp
; parameter 2: 12 + ebp
; parameter 3: 16 + ebp
; parameter 4: 20 + ebp
; parameter 5: 24 + ebp
; parameter 6: 28 + ebp
; parameter 7: 32 + ebp
; parameter 8: 36 + ebp
; parameter 9: 40 + ebp
; parameter 10: 44 + ebp
.B7.1:                          ; Preds .B7.0

;;; {

        push      ebp                                           ;673.1
        mov       ebp, esp                                      ;673.1
        push      esi                                           ;673.1
        push      edi                                           ;673.1
        push      ebx                                           ;673.1
        sub       esp, 112                                      ;673.1
        mov       ebx, DWORD PTR [28+ebp]                       ;665.5

;;;     unsigned char k[BYTES(NORX_K)];
;;;     unsigned char tag[BYTES(NORX_T)];
;;;     norx_state_t state;
;;;     int result = -1;
;;; 
;;;     if (clen < BYTES(NORX_T)) {

        cmp       ebx, 16                                       ;679.16
        jae       .B7.3         ; Prob 11%                      ;679.16
                                ; LOE ebx
.B7.2:                          ; Preds .B7.1

;;;         return -1;

        push      -1                                            ;680.16
        pop       eax                                           ;680.16
                                ; LOE
.B7.23:                         ; Preds .B7.13 .B7.2
        lea       esp, DWORD PTR [-12+ebp]                      ;680.16
        pop       ebx                                           ;680.16
        pop       edi                                           ;680.16
        pop       esi                                           ;680.16
        pop       ebp                                           ;680.16
        ret                                                     ;680.16
                                ; LOE
.B7.3:                          ; Preds .B7.1

;;;     }
;;; 
;;;     memcpy(k, key, sizeof(k));

        mov       esi, DWORD PTR [44+ebp]                       ;683.5
        lea       edi, DWORD PTR [-92+ebp]                      ;683.5
        movsd                                                   ;683.5
                                ; LOE ebx esi edi
.B7.18:                         ; Preds .B7.3
        movsd                                                   ;683.5
                                ; LOE ebx esi edi
.B7.17:                         ; Preds .B7.18
        movsd                                                   ;683.5
                                ; LOE ebx esi edi
.B7.16:                         ; Preds .B7.17
        movsd                                                   ;683.5
                                ; LOE ebx
.B7.4:                          ; Preds .B7.16

;;;     norx_init(state, k, nonce);

        mov       ecx, DWORD PTR [40+ebp]                       ;684.5
        lea       eax, DWORD PTR [-76+ebp]                      ;684.5
        lea       edx, DWORD PTR [-16+eax]                      ;684.5
        call      _norx_init                                    ;684.5
                                ; LOE ebx
.B7.5:                          ; Preds .B7.4

;;;     norx_absorb_data(state, a, alen, HEADER_TAG);

        mov       edx, DWORD PTR [16+ebp]                       ;685.5
        lea       eax, DWORD PTR [-76+ebp]                      ;685.5
        mov       ecx, DWORD PTR [20+ebp]                       ;685.5
        mov       DWORD PTR [12+esp], 1                         ;685.5
        call      _norx_absorb_data.                            ;685.5
                                ; LOE ebx
.B7.6:                          ; Preds .B7.5
        mov       edi, DWORD PTR [24+ebp]                       ;665.5

;;;     norx_decrypt_data(state, m, c, clen - BYTES(NORX_T));

        lea       eax, DWORD PTR [-76+ebp]                      ;686.5
        mov       ecx, edi                                      ;686.5
        lea       esi, DWORD PTR [-16+ebx]                      ;686.43
        mov       edx, DWORD PTR [8+ebp]                        ;686.5
        mov       DWORD PTR [12+esp], esi                       ;686.5
        call      _norx_decrypt_data.                           ;686.5
                                ; LOE ebx esi edi
.B7.7:                          ; Preds .B7.6

;;;     norx_absorb_data(state, z, zlen, TRAILER_TAG);

        mov       edx, DWORD PTR [32+ebp]                       ;687.5
        lea       eax, DWORD PTR [-76+ebp]                      ;687.5
        mov       ecx, DWORD PTR [36+ebp]                       ;687.5
        mov       DWORD PTR [12+esp], 4                         ;687.5
        call      _norx_absorb_data.                            ;687.5
                                ; LOE ebx esi edi
.B7.8:                          ; Preds .B7.7

;;;     norx_finalise(state, tag, k);

        lea       eax, DWORD PTR [-76+ebp]                      ;688.5
        lea       edx, DWORD PTR [-32+eax]                      ;688.5
        lea       ecx, DWORD PTR [-16+eax]                      ;688.5
        call      _norx_finalise                                ;688.5
                                ; LOE ebx esi edi
.B7.9:                          ; Preds .B7.8
        mov       eax, DWORD PTR [12+ebp]                       ;665.5

;;;     *mlen = clen - BYTES(NORX_T);
;;; 
;;;     result = norx_verify_tag(c + clen - BYTES(NORX_T), tag);

        lea       edx, DWORD PTR [-108+ebp]                     ;691.14
        mov       DWORD PTR [eax], esi                          ;689.6
        lea       eax, DWORD PTR [-16+ebx+edi]                  ;691.14
        call      _norx_verify_tag.                             ;691.14
                                ; LOE eax esi
.B7.19:                         ; Preds .B7.9
        mov       edx, eax                                      ;691.14

;;;     if (result != 0) { /* burn decrypted plaintext on auth failure */

        test      edx, edx                                      ;692.19
        je        .B7.11        ; Prob 78%                      ;692.19
                                ; LOE edx esi
.B7.10:                         ; Preds .B7.19

;;;         burn(m, 0, clen - BYTES(NORX_T));

        mov       ecx, esi                                      ;693.9
        xor       al, al                                        ;693.9
        mov       edi, DWORD PTR [8+ebp]                        ;693.9
        rep   stosb                                             ;693.9
                                ; LOE edx
.B7.11:                         ; Preds .B7.10 .B7.19

;;;     }
;;;     burn(state, 0, sizeof(norx_state_t));

        xor       eax, eax                                      ;695.5
        lea       edi, DWORD PTR [-76+ebp]                      ;695.5
        push      16                                            ;695.5
        pop       ecx                                           ;695.5
        rep   stosd                                             ;695.5
                                ; LOE edx
.B7.12:                         ; Preds .B7.11

;;;     burn(k, 0, sizeof(k));

        xor       eax, eax                                      ;696.5
        lea       edi, DWORD PTR [-92+ebp]                      ;696.5
        stosd                                                   ;696.5
                                ; LOE eax edx edi
.B7.22:                         ; Preds .B7.12
        stosd                                                   ;696.5
                                ; LOE eax edx edi
.B7.21:                         ; Preds .B7.22
        stosd                                                   ;696.5
                                ; LOE eax edx edi
.B7.20:                         ; Preds .B7.21
        stosd                                                   ;696.5
                                ; LOE edx
.B7.13:                         ; Preds .B7.20

;;;     return result;

        mov       eax, edx                                      ;697.12
        jmp       .B7.23        ; Prob 100%                     ;697.12
                                ; LOE
; mark_end;
_norx_aead_decrypt ENDP
;_norx_aead_decrypt	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_aead_decrypt
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_decrypt_data
TXTST7:
; -- Begin  _norx_decrypt_data
;_norx_decrypt_data	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_decrypt_data
; mark_begin;

	PUBLIC _norx_decrypt_data
_norx_decrypt_data	PROC NEAR 
; parameter 1: eax
; parameter 2: edx
; parameter 3: ecx
; parameter 4: 92 + esp
.B8.1:                          ; Preds .B8.0

;;; {

        mov       eax, DWORD PTR [4+esp]                        ;358.1
        mov       edx, DWORD PTR [8+esp]                        ;358.1
        mov       ecx, DWORD PTR [12+esp]                       ;358.1
	PUBLIC _norx_decrypt_data.
_norx_decrypt_data.::
        push      esi                                           ;358.1
        push      edi                                           ;358.1
        push      ebx                                           ;358.1
        push      ebp                                           ;358.1
        sub       esp, 60                                       ;358.1
        mov       esi, ecx                                      ;358.1
        mov       DWORD PTR [56+esp], edx                       ;358.1
        mov       ebp, eax                                      ;358.1
        mov       edx, DWORD PTR [92+esp]                       ;357.6

;;;     if (inlen > 0)

        test      edx, edx                                      ;359.17
        mov       DWORD PTR [52+esp], edx                       ;357.6
        jbe       .B8.21        ; Prob 50%                      ;359.17
                                ; LOE ebp esi
.B8.2:                          ; Preds .B8.1

;;;     {
;;;         while (inlen >= BYTES(NORX_R))

        cmp       DWORD PTR [52+esp], 48                        ;361.25
        jb        .B8.11        ; Prob 10%                      ;361.25
                                ; LOE ebp esi
.B8.4:                          ; Preds .B8.2 .B8.9

;;;         {
;;;             norx_decrypt_block(state, out, in);

        xor       DWORD PTR [60+ebp], 2                         ;363.13
        xor       bl, bl                                        ;363.13
                                ; LOE ebp esi bl
.B8.5:                          ; Preds .B8.6 .B8.4
        mov       eax, ebp                                      ;363.13
        call      _F                                            ;363.13
                                ; LOE ebp esi bl
.B8.6:                          ; Preds .B8.5
        inc       bl                                            ;363.13
        cmp       bl, 6                                         ;363.13
        jb        .B8.5         ; Prob 83%                      ;363.13
                                ; LOE ebp esi bl
.B8.7:                          ; Preds .B8.6
        xor       edi, edi                                      ;363.13
                                ; LOE ebp esi edi
.B8.8:                          ; Preds .B8.8 .B8.7
        movzx     edx, BYTE PTR [1+esi+edi*4]                   ;363.13
        shl       edx, 8                                        ;363.13
        movzx     ebx, BYTE PTR [esi+edi*4]                     ;363.13
        or        ebx, edx                                      ;363.13
        movzx     edx, BYTE PTR [2+esi+edi*4]                   ;363.13
        shl       edx, 16                                       ;363.13
        or        ebx, edx                                      ;363.13
        movzx     edx, BYTE PTR [3+esi+edi*4]                   ;363.13
        shl       edx, 24                                       ;363.13
        or        ebx, edx                                      ;363.13
        mov       eax, DWORD PTR [56+esp]                       ;363.13
        mov       ecx, DWORD PTR [ebp+edi*4]                    ;363.13
        xor       ecx, ebx                                      ;363.13
        mov       edx, ecx                                      ;363.13
        shr       edx, 8                                        ;363.13
        mov       BYTE PTR [1+eax+edi*4], dl                    ;363.13
        mov       edx, ecx                                      ;363.13
        mov       BYTE PTR [eax+edi*4], cl                      ;363.13
        shr       edx, 16                                       ;363.13
        shr       ecx, 24                                       ;363.13
        mov       BYTE PTR [2+eax+edi*4], dl                    ;363.13
        mov       BYTE PTR [3+eax+edi*4], cl                    ;363.13
        mov       DWORD PTR [ebp+edi*4], ebx                    ;363.13
        inc       edi                                           ;363.13
        cmp       edi, 12                                       ;363.13
        jb        .B8.8         ; Prob 91%                      ;363.13
                                ; LOE ebp esi edi
.B8.9:                          ; Preds .B8.8

;;;             #if defined(NORX_DEBUG)
;;;             printf("Decrypt block\n");
;;;             norx_debug(state, in, BYTES(NORX_R), out, BYTES(NORX_R));
;;;             #endif
;;;             inlen -= BYTES(NORX_R);

        mov       edx, DWORD PTR [52+esp]                       ;368.13

;;;             in    += BYTES(NORX_R);

        add       esi, 48                                       ;369.13
        add       edx, -48                                      ;368.13

;;;             out   += BYTES(NORX_R);

        add       DWORD PTR [56+esp], 48                        ;370.13
        mov       DWORD PTR [52+esp], edx                       ;368.13
        cmp       edx, 48                                       ;361.25
        jae       .B8.4         ; Prob 82%                      ;361.25
                                ; LOE ebp esi
.B8.11:                         ; Preds .B8.2 .B8.9

;;;         }
;;;         norx_decrypt_lastblock(state, out, in, inlen);

        xor       DWORD PTR [60+ebp], 2                         ;372.9
        mov       BYTE PTR [4+esp], 0                           ;372.9
                                ; LOE ebp esi
.B8.12:                         ; Preds .B8.13 .B8.11
        mov       eax, ebp                                      ;372.9
        call      _F                                            ;372.9
                                ; LOE ebp esi
.B8.13:                         ; Preds .B8.12
        mov       dl, BYTE PTR [4+esp]                          ;372.9
        inc       dl                                            ;372.9
        mov       BYTE PTR [4+esp], dl                          ;372.9
        cmp       dl, 6                                         ;372.9
        jb        .B8.12        ; Prob 83%                      ;372.9
                                ; LOE ebp esi
.B8.14:                         ; Preds .B8.13
        xor       edi, edi                                      ;372.9
                                ; LOE ebp esi edi
.B8.15:                         ; Preds .B8.15 .B8.14
        mov       edx, DWORD PTR [ebp+edi*4]                    ;372.9
        mov       ecx, edx                                      ;372.9
        mov       ebx, edx                                      ;372.9
        mov       BYTE PTR [4+esp+edi*4], dl                    ;372.9
        shr       ecx, 8                                        ;372.9
        shr       ebx, 16                                       ;372.9
        shr       edx, 24                                       ;372.9
        mov       BYTE PTR [5+esp+edi*4], cl                    ;372.9
        mov       BYTE PTR [6+esp+edi*4], bl                    ;372.9
        mov       BYTE PTR [7+esp+edi*4], dl                    ;372.9
        inc       edi                                           ;372.9
        cmp       edi, 12                                       ;372.9
        jb        .B8.15        ; Prob 91%                      ;372.9
                                ; LOE ebp esi edi
.B8.16:                         ; Preds .B8.15
        mov       ecx, DWORD PTR [52+esp]                       ;372.9
        lea       edi, DWORD PTR [4+esp]                        ;372.9
        rep   movsb                                             ;372.9
                                ; LOE ebp
.B8.17:                         ; Preds .B8.16
        mov       edx, DWORD PTR [52+esp]                       ;372.9
        xor       edi, edi                                      ;372.9
        xor       BYTE PTR [4+esp+edx], 1                       ;372.9
        xor       BYTE PTR [51+esp], -128                       ;372.9
                                ; LOE ebp edi
.B8.18:                         ; Preds .B8.18 .B8.17
        movzx     edx, BYTE PTR [5+esp+edi*4]                   ;372.9
        shl       edx, 8                                        ;372.9
        movzx     esi, BYTE PTR [4+esp+edi*4]                   ;372.9
        or        esi, edx                                      ;372.9
        movzx     edx, BYTE PTR [6+esp+edi*4]                   ;372.9
        shl       edx, 16                                       ;372.9
        or        esi, edx                                      ;372.9
        movzx     edx, BYTE PTR [7+esp+edi*4]                   ;372.9
        shl       edx, 24                                       ;372.9
        or        esi, edx                                      ;372.9
        mov       ebx, DWORD PTR [ebp+edi*4]                    ;372.9
        xor       ebx, esi                                      ;372.9
        mov       edx, ebx                                      ;372.9
        mov       ecx, ebx                                      ;372.9
        mov       BYTE PTR [4+esp+edi*4], bl                    ;372.9
        shr       edx, 8                                        ;372.9
        shr       ecx, 16                                       ;372.9
        shr       ebx, 24                                       ;372.9
        mov       BYTE PTR [5+esp+edi*4], dl                    ;372.9
        mov       BYTE PTR [6+esp+edi*4], cl                    ;372.9
        mov       BYTE PTR [7+esp+edi*4], bl                    ;372.9
        mov       DWORD PTR [ebp+edi*4], esi                    ;372.9
        inc       edi                                           ;372.9
        cmp       edi, 12                                       ;372.9
        jb        .B8.18        ; Prob 91%                      ;372.9
                                ; LOE ebp edi
.B8.19:                         ; Preds .B8.18
        mov       edi, DWORD PTR [56+esp]                       ;372.9
        lea       esi, DWORD PTR [4+esp]                        ;372.9
        mov       ecx, DWORD PTR [48+esi]                       ;372.9
        rep   movsb                                             ;372.9
                                ; LOE
.B8.20:                         ; Preds .B8.19
        xor       eax, eax                                      ;372.9
        lea       edi, DWORD PTR [4+esp]                        ;372.9
        push      12                                            ;372.9
        pop       ecx                                           ;372.9
        rep   stosd                                             ;372.9
                                ; LOE
.B8.21:                         ; Preds .B8.20 .B8.1

;;;         #if defined(NORX_DEBUG)
;;;         printf("Decrypt lastblock\n");
;;;         norx_debug(state, in, inlen, out, inlen);
;;;         #endif
;;;     }
;;; }

        add       esp, 60                                       ;378.1
        pop       ebp                                           ;378.1
        pop       ebx                                           ;378.1
        pop       edi                                           ;378.1
        pop       esi                                           ;378.1
        ret                                                     ;378.1
                                ; LOE
; mark_end;
_norx_decrypt_data ENDP
;_norx_decrypt_data	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_decrypt_data
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _F
TXTST8:
; -- Begin  _F
;_F	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _F
; mark_begin;

_F	PROC NEAR PRIVATE
; parameter 1: eax
.B9.1:                          ; Preds .B9.0

;;; {

        push      ebp                                           ;123.1
        mov       ebp, esp                                      ;123.1
        push      esi                                           ;123.1
        push      edi                                           ;123.1
        push      ebx                                           ;123.1
        sub       esp, 56                                       ;123.1

;;;     /* Column step */
;;;     G(S[ 0], S[ 4], S[ 8], S[12]);

        mov       edx, DWORD PTR [eax]                          ;125.5
        mov       ecx, edx                                      ;125.5
        mov       esi, DWORD PTR [16+eax]                       ;125.5
        and       edx, esi                                      ;125.5
        xor       ecx, esi                                      ;125.5
        add       edx, edx                                      ;125.5
        xor       ecx, edx                                      ;125.5
        mov       edi, DWORD PTR [48+eax]                       ;125.5
        xor       edi, ecx                                      ;125.5
        rol       edi, 24                                       ;125.5
        mov       edx, DWORD PTR [32+eax]                       ;125.5
        mov       ebx, edx                                      ;125.5
        and       edx, edi                                      ;125.5
        xor       ebx, edi                                      ;125.5
        add       edx, edx                                      ;125.5
        xor       ebx, edx                                      ;125.5
        mov       edx, ecx                                      ;125.5
        xor       esi, ebx                                      ;125.5
        rol       esi, 21                                       ;125.5
        and       ecx, esi                                      ;125.5
        xor       edx, esi                                      ;125.5
        add       ecx, ecx                                      ;125.5
        xor       edx, ecx                                      ;125.5
        mov       ecx, ebx                                      ;125.5
        xor       edi, edx                                      ;125.5
        rol       edi, 16                                       ;125.5
        and       ebx, edi                                      ;125.5
        xor       ecx, edi                                      ;125.5
        add       ebx, ebx                                      ;125.5
        xor       ecx, ebx                                      ;125.5
        mov       DWORD PTR [-64+ebp], edx                      ;125.5
        xor       esi, ecx                                      ;125.5

;;;     G(S[ 1], S[ 5], S[ 9], S[13]);

        mov       ebx, DWORD PTR [4+eax]                        ;126.5
        mov       edx, DWORD PTR [20+eax]                       ;126.5
        mov       DWORD PTR [-56+ebp], ecx                      ;125.5
        mov       ecx, ebx                                      ;126.5
        and       ebx, edx                                      ;126.5
        xor       ecx, edx                                      ;126.5
        add       ebx, ebx                                      ;126.5
        xor       ecx, ebx                                      ;126.5
        mov       ebx, DWORD PTR [52+eax]                       ;126.5
        xor       ebx, ecx                                      ;126.5
        rol       ebx, 24                                       ;126.5
        mov       DWORD PTR [-60+ebp], edi                      ;125.5
        rol       esi, 1                                        ;125.5
        mov       edi, DWORD PTR [36+eax]                       ;126.5
        mov       DWORD PTR [-52+ebp], esi                      ;125.5
        mov       esi, edi                                      ;126.5
        and       edi, ebx                                      ;126.5
        xor       esi, ebx                                      ;126.5
        add       edi, edi                                      ;126.5
        xor       esi, edi                                      ;126.5
        mov       edi, ecx                                      ;126.5
        xor       edx, esi                                      ;126.5
        rol       edx, 21                                       ;126.5
        and       ecx, edx                                      ;126.5
        xor       edi, edx                                      ;126.5
        add       ecx, ecx                                      ;126.5
        xor       edi, ecx                                      ;126.5
        mov       ecx, esi                                      ;126.5
        xor       ebx, edi                                      ;126.5
        rol       ebx, 16                                       ;126.5
        and       esi, ebx                                      ;126.5
        xor       ecx, ebx                                      ;126.5
        add       esi, esi                                      ;126.5
        xor       ecx, esi                                      ;126.5
        mov       DWORD PTR [-40+ebp], ecx                      ;126.5
        xor       edx, ecx                                      ;126.5

;;;     G(S[ 2], S[ 6], S[10], S[14]);

        mov       esi, DWORD PTR [8+eax]                        ;127.5
        mov       ecx, DWORD PTR [24+eax]                       ;127.5
        mov       DWORD PTR [-48+ebp], edi                      ;126.5
        mov       edi, esi                                      ;127.5
        and       esi, ecx                                      ;127.5
        xor       edi, ecx                                      ;127.5
        add       esi, esi                                      ;127.5
        xor       edi, esi                                      ;127.5
        rol       edx, 1                                        ;126.5
        mov       DWORD PTR [-36+ebp], edx                      ;126.5
        mov       edx, DWORD PTR [56+eax]                       ;127.5
        xor       edx, edi                                      ;127.5
        rol       edx, 24                                       ;127.5
        mov       DWORD PTR [-44+ebp], ebx                      ;126.5
        mov       ebx, DWORD PTR [40+eax]                       ;127.5
        mov       esi, ebx                                      ;127.5
        and       ebx, edx                                      ;127.5
        xor       esi, edx                                      ;127.5
        add       ebx, ebx                                      ;127.5
        xor       esi, ebx                                      ;127.5
        mov       ebx, edi                                      ;127.5
        xor       ecx, esi                                      ;127.5
        rol       ecx, 21                                       ;127.5
        and       edi, ecx                                      ;127.5
        xor       ebx, ecx                                      ;127.5
        add       edi, edi                                      ;127.5
        xor       ebx, edi                                      ;127.5
        mov       edi, esi                                      ;127.5
        xor       edx, ebx                                      ;127.5
        rol       edx, 16                                       ;127.5
        and       esi, edx                                      ;127.5
        xor       edi, edx                                      ;127.5
        add       esi, esi                                      ;127.5
        xor       edi, esi                                      ;127.5
        xor       ecx, edi                                      ;127.5
        rol       ecx, 1                                        ;127.5
        mov       DWORD PTR [-28+ebp], edx                      ;127.5
        mov       DWORD PTR [-24+ebp], ecx                      ;127.5

;;;     G(S[ 3], S[ 7], S[11], S[15]);

        mov       ecx, DWORD PTR [12+eax]                       ;128.5
        mov       edx, DWORD PTR [28+eax]                       ;128.5
        mov       DWORD PTR [-32+ebp], ebx                      ;127.5
        mov       ebx, ecx                                      ;128.5
        and       ecx, edx                                      ;128.5
        xor       ebx, edx                                      ;128.5
        add       ecx, ecx                                      ;128.5
        xor       ebx, ecx                                      ;128.5
        mov       esi, DWORD PTR [60+eax]                       ;128.5
        xor       esi, ebx                                      ;128.5
        rol       esi, 24                                       ;128.5
        mov       DWORD PTR [-68+ebp], eax                      ;123.1
        mov       eax, DWORD PTR [44+eax]                       ;128.5
        mov       ecx, eax                                      ;128.5
        and       eax, esi                                      ;128.5
        xor       ecx, esi                                      ;128.5
        add       eax, eax                                      ;128.5
        xor       ecx, eax                                      ;128.5
        mov       eax, ebx                                      ;128.5
        xor       edx, ecx                                      ;128.5
        rol       edx, 21                                       ;128.5
        and       ebx, edx                                      ;128.5
        xor       eax, edx                                      ;128.5
        add       ebx, ebx                                      ;128.5
        xor       eax, ebx                                      ;128.5
        mov       ebx, ecx                                      ;128.5
        xor       esi, eax                                      ;128.5
        rol       esi, 16                                       ;128.5
        and       ecx, esi                                      ;128.5
        xor       ebx, esi                                      ;128.5
        add       ecx, ecx                                      ;128.5
        xor       ebx, ecx                                      ;128.5
        xor       edx, ebx                                      ;128.5
        rol       edx, 1                                        ;128.5
        mov       DWORD PTR [-20+ebp], eax                      ;128.5
        mov       DWORD PTR [-16+ebp], edx                      ;128.5

;;;     /* Diagonal step */
;;;     G(S[ 0], S[ 5], S[10], S[15]);

        mov       eax, DWORD PTR [-64+ebp]                      ;130.5
        mov       ecx, eax                                      ;130.5
        mov       edx, DWORD PTR [-36+ebp]                      ;130.5
        and       eax, edx                                      ;130.5
        xor       ecx, edx                                      ;130.5
        add       eax, eax                                      ;130.5
        xor       ecx, eax                                      ;130.5
        mov       eax, edi                                      ;130.5
        xor       esi, ecx                                      ;130.5
        rol       esi, 24                                       ;130.5
        and       edi, esi                                      ;130.5
        xor       eax, esi                                      ;130.5
        add       edi, edi                                      ;130.5
        xor       eax, edi                                      ;130.5
        mov       edi, ecx                                      ;130.5
        xor       edx, eax                                      ;130.5
        rol       edx, 21                                       ;130.5
        and       ecx, edx                                      ;130.5
        xor       edi, edx                                      ;130.5
        add       ecx, ecx                                      ;130.5
        xor       edi, ecx                                      ;130.5
        mov       ecx, DWORD PTR [-68+ebp]                      ;130.5
        mov       DWORD PTR [ecx], edi                          ;130.5
        xor       edi, esi                                      ;130.5
        rol       edi, 16                                       ;130.5
        mov       esi, eax                                      ;130.5
        and       eax, edi                                      ;130.5
        xor       esi, edi                                      ;130.5
        add       eax, eax                                      ;130.5
        xor       esi, eax                                      ;130.5
        xor       edx, esi                                      ;130.5
        rol       edx, 1                                        ;130.5
        mov       DWORD PTR [20+ecx], edx                       ;130.5

;;;     G(S[ 1], S[ 6], S[11], S[12]);

        mov       edx, DWORD PTR [-48+ebp]                      ;131.5
        mov       eax, DWORD PTR [-24+ebp]                      ;131.5
        mov       DWORD PTR [40+ecx], esi                       ;130.5
        mov       esi, edx                                      ;131.5
        and       edx, eax                                      ;131.5
        xor       esi, eax                                      ;131.5
        add       edx, edx                                      ;131.5
        xor       esi, edx                                      ;131.5
        mov       edx, DWORD PTR [-60+ebp]                      ;131.5
        xor       edx, esi                                      ;131.5
        rol       edx, 24                                       ;131.5
        mov       DWORD PTR [60+ecx], edi                       ;130.5
        mov       edi, ebx                                      ;131.5
        and       ebx, edx                                      ;131.5
        xor       edi, edx                                      ;131.5
        add       ebx, ebx                                      ;131.5
        xor       edi, ebx                                      ;131.5
        mov       ebx, esi                                      ;131.5
        xor       eax, edi                                      ;131.5
        rol       eax, 21                                       ;131.5
        and       esi, eax                                      ;131.5
        xor       ebx, eax                                      ;131.5
        add       esi, esi                                      ;131.5
        xor       ebx, esi                                      ;131.5
        mov       esi, edi                                      ;131.5
        xor       edx, ebx                                      ;131.5
        rol       edx, 16                                       ;131.5
        mov       DWORD PTR [48+ecx], edx                       ;131.5
        xor       esi, edx                                      ;131.5
        and       edx, edi                                      ;131.5
        add       edx, edx                                      ;131.5
        xor       esi, edx                                      ;131.5
        xor       eax, esi                                      ;131.5
        rol       eax, 1                                        ;131.5
        mov       DWORD PTR [24+ecx], eax                       ;131.5

;;;     G(S[ 2], S[ 7], S[ 8], S[13]);

        mov       eax, DWORD PTR [-32+ebp]                      ;132.5
        mov       edi, DWORD PTR [-16+ebp]                      ;132.5
        mov       DWORD PTR [44+ecx], esi                       ;131.5
        mov       esi, eax                                      ;132.5
        and       eax, edi                                      ;132.5
        xor       esi, edi                                      ;132.5
        add       eax, eax                                      ;132.5
        xor       esi, eax                                      ;132.5
        mov       DWORD PTR [4+ecx], ebx                        ;131.5
        mov       ebx, DWORD PTR [-44+ebp]                      ;132.5
        xor       ebx, esi                                      ;132.5
        rol       ebx, 24                                       ;132.5
        mov       edx, DWORD PTR [-56+ebp]                      ;132.5
        mov       eax, edx                                      ;132.5
        and       edx, ebx                                      ;132.5
        xor       eax, ebx                                      ;132.5
        add       edx, edx                                      ;132.5
        xor       eax, edx                                      ;132.5
        mov       edx, esi                                      ;132.5
        xor       edi, eax                                      ;132.5
        rol       edi, 21                                       ;132.5
        and       esi, edi                                      ;132.5
        xor       edx, edi                                      ;132.5
        add       esi, esi                                      ;132.5
        xor       edx, esi                                      ;132.5
        mov       esi, eax                                      ;132.5
        xor       ebx, edx                                      ;132.5
        rol       ebx, 16                                       ;132.5
        and       eax, ebx                                      ;132.5
        xor       esi, ebx                                      ;132.5
        add       eax, eax                                      ;132.5
        xor       esi, eax                                      ;132.5
        mov       DWORD PTR [52+ecx], ebx                       ;132.5
        mov       DWORD PTR [32+ecx], esi                       ;132.5
        xor       esi, edi                                      ;132.5

;;;     G(S[ 3], S[ 4], S[ 9], S[14]);

        mov       ebx, DWORD PTR [-20+ebp]                      ;133.5
        mov       edi, DWORD PTR [-52+ebp]                      ;133.5
        mov       DWORD PTR [8+ecx], edx                        ;132.5
        mov       edx, ebx                                      ;133.5
        and       ebx, edi                                      ;133.5
        xor       edx, edi                                      ;133.5
        add       ebx, ebx                                      ;133.5
        xor       edx, ebx                                      ;133.5
        mov       ebx, DWORD PTR [-28+ebp]                      ;133.5
        xor       ebx, edx                                      ;133.5
        rol       ebx, 24                                       ;133.5
        mov       eax, DWORD PTR [-40+ebp]                      ;133.5
        rol       esi, 1                                        ;132.5
        mov       DWORD PTR [28+ecx], esi                       ;132.5
        mov       esi, eax                                      ;133.5
        and       eax, ebx                                      ;133.5
        xor       esi, ebx                                      ;133.5
        add       eax, eax                                      ;133.5
        xor       esi, eax                                      ;133.5
        mov       eax, edx                                      ;133.5
        xor       edi, esi                                      ;133.5
        rol       edi, 21                                       ;133.5
        and       edx, edi                                      ;133.5
        xor       eax, edi                                      ;133.5
        add       edx, edx                                      ;133.5
        xor       eax, edx                                      ;133.5
        mov       edx, esi                                      ;133.5
        xor       ebx, eax                                      ;133.5
        rol       ebx, 16                                       ;133.5
        and       esi, ebx                                      ;133.5
        xor       edx, ebx                                      ;133.5
        add       esi, esi                                      ;133.5
        xor       edx, esi                                      ;133.5
        xor       edi, edx                                      ;133.5
        rol       edi, 1                                        ;133.5
        mov       DWORD PTR [12+ecx], eax                       ;133.5
        mov       DWORD PTR [56+ecx], ebx                       ;133.5
        mov       DWORD PTR [36+ecx], edx                       ;133.5
        mov       DWORD PTR [16+ecx], edi                       ;133.5
                                ; LOE
.B9.4:                          ; Preds .B9.1

;;; }

        lea       esp, DWORD PTR [-12+ebp]                      ;134.1
        pop       ebx                                           ;134.1
        pop       edi                                           ;134.1
        pop       esi                                           ;134.1
        pop       ebp                                           ;134.1
        ret                                                     ;134.1
                                ; LOE
; mark_end;
_F ENDP
;_F	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _F
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_verify_tag
TXTST9:
; -- Begin  _norx_verify_tag
;_norx_verify_tag	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_verify_tag
; mark_begin;

	PUBLIC _norx_verify_tag
_norx_verify_tag	PROC NEAR 
; parameter 1: eax
; parameter 2: edx
.B10.1:                         ; Preds .B10.0

;;; {

        mov       eax, DWORD PTR [4+esp]                        ;630.1
        mov       edx, DWORD PTR [8+esp]                        ;630.1
	PUBLIC _norx_verify_tag.
_norx_verify_tag.::
        push      esi                                           ;630.1
        push      ebx                                           ;630.1
        push      ebp                                           ;630.1

;;;     size_t i;
;;;     unsigned acc = 0;

        xor       esi, esi                                      ;632.18

;;; 
;;;     for (i = 0; i < BYTES(NORX_T); ++i) {

        xor       ebp, ebp                                      ;634.10
                                ; LOE eax edx ebp esi edi
.B10.2:                         ; Preds .B10.2 .B10.1

;;;         acc |= tag1[i] ^ tag2[i];

        movzx     ebx, BYTE PTR [ebp+eax]                       ;635.16
        movzx     ecx, BYTE PTR [ebp+edx]                       ;635.26
        xor       ebx, ecx                                      ;635.26
        inc       ebp                                           ;634.38
        or        esi, ebx                                      ;635.9
        cmp       ebp, 16                                       ;634.21
        jb        .B10.2        ; Prob 93%                      ;634.21
                                ; LOE eax edx ebp esi edi
.B10.3:                         ; Preds .B10.2

;;;     }
;;; 
;;;     return (((acc - 1) >> 8) & 1) - 1;

        dec       esi                                           ;638.21
        shr       esi, 8                                        ;638.27
        and       esi, 1                                        ;638.32
        dec       esi                                           ;638.37
        mov       eax, esi                                      ;638.37
                                ; LOE
.B10.6:                         ; Preds .B10.3
        pop       ebp                                           ;638.37
        pop       ebx                                           ;638.37
        pop       esi                                           ;638.37
        ret                                                     ;638.37
                                ; LOE
; mark_end;
_norx_verify_tag ENDP
;_norx_verify_tag	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_verify_tag
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_init
TXTST10:
; -- Begin  _norx_init
;_norx_init	ENDS
_TEXT	ENDS
_TEXT	SEGMENT  DWORD PUBLIC FLAT  'CODE'
;	COMDAT _norx_init
; mark_begin;

_norx_init	PROC NEAR PRIVATE
; parameter 1: eax
; parameter 2: edx
; parameter 3: ecx
.B11.1:                         ; Preds .B11.0

;;; {

        push      ebp                                           ;241.1
        mov       ebp, esp                                      ;241.1
        and       esp, -16                                      ;241.1
        push      esi                                           ;241.1
        push      edi                                           ;241.1
        push      ebx                                           ;241.1
        sub       esp, 36                                       ;241.1
        mov       esi, edx                                      ;241.1

;;;     norx_word_t * S = state->S;
;;;     size_t i;
;;; 
;;;     for(i = 0; i < 16; ++i) {
;;;         S[i] = i;

        push      4                                             ;246.9
        pop       edx                                           ;246.9
        mov       ebx, ecx                                      ;241.1
        mov       edi, eax                                      ;241.1
        movd      xmm0, edx                                     ;246.9
        xor       edx, edx                                      ;245.5
        pshufd    xmm1, xmm0, 0                                 ;246.9
        movdqa    xmm0, XMMWORD PTR [_2il0floatpacket.25]       ;246.9
                                ; LOE edx ebx esi edi xmm0 xmm1
.B11.2:                         ; Preds .B11.2 .B11.1
        movdqu    XMMWORD PTR [edi+edx*4], xmm0                 ;246.9
        add       edx, 4                                        ;245.5
        paddd     xmm0, xmm1                                    ;246.9
        cmp       edx, 16                                       ;245.5
        jb        .B11.2        ; Prob 93%                      ;245.5
                                ; LOE edx ebx esi edi xmm0 xmm1
.B11.3:                         ; Preds .B11.2

;;;     }
;;; 
;;;     F(S);

        mov       eax, edi                                      ;249.5
        call      _F                                            ;249.5
                                ; LOE ebx esi edi
.B11.4:                         ; Preds .B11.3

;;;     F(S);

        mov       eax, edi                                      ;250.5
        call      _F                                            ;250.5
                                ; LOE ebx esi edi
.B11.5:                         ; Preds .B11.4

;;; 
;;;     S[ 0] = LOAD(n + 0 * BYTES(NORX_W));

        movzx     ecx, BYTE PTR [1+ebx]                         ;252.13
        shl       ecx, 8                                        ;252.13
        movzx     edx, BYTE PTR [ebx]                           ;252.13
        or        edx, ecx                                      ;252.13
        movzx     ecx, BYTE PTR [2+ebx]                         ;252.13
        shl       ecx, 16                                       ;252.13
        or        edx, ecx                                      ;252.13
        movzx     ecx, BYTE PTR [3+ebx]                         ;252.13
        shl       ecx, 24                                       ;252.13
        or        edx, ecx                                      ;252.13
        mov       DWORD PTR [edi], edx                          ;252.5

;;;     S[ 1] = LOAD(n + 1 * BYTES(NORX_W));

        movzx     ecx, BYTE PTR [5+ebx]                         ;253.13
        shl       ecx, 8                                        ;253.13
        movzx     edx, BYTE PTR [4+ebx]                         ;253.13
        or        edx, ecx                                      ;253.13
        movzx     ecx, BYTE PTR [6+ebx]                         ;253.13
        shl       ecx, 16                                       ;253.13
        or        edx, ecx                                      ;253.13
        movzx     ecx, BYTE PTR [7+ebx]                         ;253.13
        shl       ecx, 24                                       ;253.13
        or        edx, ecx                                      ;253.13
        mov       DWORD PTR [4+edi], edx                        ;253.5

;;;     S[ 2] = LOAD(n + 2 * BYTES(NORX_W));

        movzx     edx, BYTE PTR [9+ebx]                         ;254.13
        shl       edx, 8                                        ;254.13
        movzx     ecx, BYTE PTR [8+ebx]                         ;254.13
        or        ecx, edx                                      ;254.13
        movzx     edx, BYTE PTR [10+ebx]                        ;254.13
        shl       edx, 16                                       ;254.13
        or        ecx, edx                                      ;254.13
        movzx     edx, BYTE PTR [11+ebx]                        ;254.13
        shl       edx, 24                                       ;254.13
        or        ecx, edx                                      ;254.13
        mov       DWORD PTR [8+edi], ecx                        ;254.5

;;;     S[ 3] = LOAD(n + 3 * BYTES(NORX_W));

        movzx     ecx, BYTE PTR [13+ebx]                        ;255.13
        shl       ecx, 8                                        ;255.13
        movzx     edx, BYTE PTR [12+ebx]                        ;255.13
        or        edx, ecx                                      ;255.13
        movzx     ecx, BYTE PTR [14+ebx]                        ;255.13
        shl       ecx, 16                                       ;255.13
        movzx     ebx, BYTE PTR [15+ebx]                        ;255.13
        or        edx, ecx                                      ;255.13
        shl       ebx, 24                                       ;255.13
        or        edx, ebx                                      ;255.13

;;; 
;;;     S[ 4] = LOAD(k + 0 * BYTES(NORX_W));
;;;     S[ 5] = LOAD(k + 1 * BYTES(NORX_W));
;;;     S[ 6] = LOAD(k + 2 * BYTES(NORX_W));
;;;     S[ 7] = LOAD(k + 3 * BYTES(NORX_W));
;;; 
;;;     S[12] ^= NORX_W;
;;;     S[13] ^= NORX_L;
;;;     S[14] ^= NORX_P;
;;;     S[15] ^= NORX_T;
;;; 
;;;     norx_permute(state);

        xor       bl, bl                                        ;267.5
        mov       DWORD PTR [12+edi], edx                       ;255.5
        movzx     edx, BYTE PTR [1+esi]                         ;257.13
        shl       edx, 8                                        ;257.13
        movzx     ecx, BYTE PTR [esi]                           ;257.13
        or        ecx, edx                                      ;257.13
        movzx     edx, BYTE PTR [2+esi]                         ;257.13
        shl       edx, 16                                       ;257.13
        or        ecx, edx                                      ;257.13
        movzx     edx, BYTE PTR [3+esi]                         ;257.13
        shl       edx, 24                                       ;257.13
        or        ecx, edx                                      ;257.13
        mov       DWORD PTR [16+edi], ecx                       ;257.5
        mov       DWORD PTR [16+esp], ecx                       ;257.13
        movzx     edx, BYTE PTR [4+esi]                         ;258.13
        movzx     ecx, BYTE PTR [5+esi]                         ;258.13
        shl       ecx, 8                                        ;258.13
        mov       DWORD PTR [20+esp], edx                       ;258.13
        or        ecx, edx                                      ;258.13
        movzx     edx, BYTE PTR [6+esi]                         ;258.13
        shl       edx, 16                                       ;258.13
        or        ecx, edx                                      ;258.13
        movzx     edx, BYTE PTR [7+esi]                         ;258.13
        shl       edx, 24                                       ;258.13
        or        ecx, edx                                      ;258.13
        mov       DWORD PTR [20+edi], ecx                       ;258.5
        movzx     edx, BYTE PTR [8+esi]                         ;259.13
        movzx     ecx, BYTE PTR [9+esi]                         ;259.13
        shl       ecx, 8                                        ;259.13
        mov       DWORD PTR [24+esp], edx                       ;259.13
        or        ecx, edx                                      ;259.13
        movzx     edx, BYTE PTR [10+esi]                        ;259.13
        shl       edx, 16                                       ;259.13
        or        ecx, edx                                      ;259.13
        movzx     edx, BYTE PTR [11+esi]                        ;259.13
        shl       edx, 24                                       ;259.13
        or        ecx, edx                                      ;259.13
        mov       DWORD PTR [24+edi], ecx                       ;259.5
        movzx     edx, BYTE PTR [12+esi]                        ;260.13
        movzx     ecx, BYTE PTR [13+esi]                        ;260.13
        shl       ecx, 8                                        ;260.13
        movdqu    xmm0, XMMWORD PTR [48+edi]                    ;262.5
        mov       DWORD PTR [28+esp], edx                       ;260.13
        or        ecx, edx                                      ;260.13
        movzx     edx, BYTE PTR [14+esi]                        ;260.13
        shl       edx, 16                                       ;260.13
        or        ecx, edx                                      ;260.13
        movzx     edx, BYTE PTR [15+esi]                        ;260.13
        shl       edx, 24                                       ;260.13
        pxor      xmm0, XMMWORD PTR [_2__cnst_pck.24]           ;262.5
        or        ecx, edx                                      ;260.13
        mov       DWORD PTR [28+edi], ecx                       ;260.5
        movdqu    XMMWORD PTR [48+edi], xmm0                    ;262.5
                                ; LOE esi edi bl
.B11.6:                         ; Preds .B11.7 .B11.5
        mov       eax, edi                                      ;267.5
        call      _F                                            ;267.5
                                ; LOE esi edi bl
.B11.7:                         ; Preds .B11.6
        inc       bl                                            ;267.5
        cmp       bl, 6                                         ;267.5
        jb        .B11.6        ; Prob 83%                      ;267.5
                                ; LOE esi edi bl
.B11.8:                         ; Preds .B11.7

;;; 
;;;     S[12] ^= LOAD(k + 0 * BYTES(NORX_W));

        mov       edx, DWORD PTR [16+esp]                       ;269.5
        xor       DWORD PTR [48+edi], edx                       ;269.5

;;;     S[13] ^= LOAD(k + 1 * BYTES(NORX_W));

        movzx     ecx, BYTE PTR [5+esi]                         ;270.14
        shl       ecx, 8                                        ;270.14
        movzx     ebx, BYTE PTR [6+esi]                         ;270.14
        mov       edx, DWORD PTR [20+esp]                       ;270.14
        shl       ebx, 16                                       ;270.14
        or        edx, ecx                                      ;270.14
        movzx     ecx, BYTE PTR [7+esi]                         ;270.14
        or        edx, ebx                                      ;270.14
        shl       ecx, 24                                       ;270.14
        or        edx, ecx                                      ;270.14
        xor       DWORD PTR [52+edi], edx                       ;270.5

;;;     S[14] ^= LOAD(k + 2 * BYTES(NORX_W));

        movzx     edx, BYTE PTR [9+esi]                         ;271.14
        shl       edx, 8                                        ;271.14
        mov       ecx, DWORD PTR [24+esp]                       ;271.14
        or        ecx, edx                                      ;271.14
        movzx     edx, BYTE PTR [10+esi]                        ;271.14
        shl       edx, 16                                       ;271.14
        or        ecx, edx                                      ;271.14
        movzx     edx, BYTE PTR [11+esi]                        ;271.14
        shl       edx, 24                                       ;271.14
        or        ecx, edx                                      ;271.14

;;;     S[15] ^= LOAD(k + 3 * BYTES(NORX_W));

        movzx     edx, BYTE PTR [13+esi]                        ;272.14
        shl       edx, 8                                        ;272.14
        xor       DWORD PTR [56+edi], ecx                       ;271.5
        mov       ecx, DWORD PTR [28+esp]                       ;272.14
        or        ecx, edx                                      ;272.14
        movzx     edx, BYTE PTR [14+esi]                        ;272.14
        shl       edx, 16                                       ;272.14
        movzx     esi, BYTE PTR [15+esi]                        ;272.14
        or        ecx, edx                                      ;272.14
        shl       esi, 24                                       ;272.14
        or        ecx, esi                                      ;272.14
        xor       DWORD PTR [60+edi], ecx                       ;272.5
                                ; LOE
.B11.11:                        ; Preds .B11.8

;;; 
;;; #if defined(NORX_DEBUG)
;;;     printf("Initialise\n");
;;;     norx_debug(state, NULL, 0, NULL, 0);
;;; #endif
;;; }

        add       esp, 36                                       ;278.1
        pop       ebx                                           ;278.1
        pop       edi                                           ;278.1
        pop       esi                                           ;278.1
        mov       esp, ebp                                      ;278.1
        pop       ebp                                           ;278.1
        ret                                                     ;278.1
                                ; LOE
; mark_end;
_norx_init ENDP
;_norx_init	ENDS
_TEXT	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
; -- End  _norx_init
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
	ALIGN 004H
	PUBLIC _norx_version
_norx_version	DD	OFFSET FLAT: ??_C@_03A@3?40?$AA@
_DATA	ENDS
_RDATA	SEGMENT  DWORD PUBLIC FLAT READ  'DATA'
_2il0floatpacket.25	DD	000000000H,000000001H,000000002H,000000003H
_2__cnst_pck.24	DD	32
	DD	6
	DD	1
	DD	128
_RDATA	ENDS
;	COMDAT ??_C@_03A@3?40?$AA@
_RDATA	SEGMENT  DWORD PUBLIC FLAT READ  'DATA'
;	COMDAT ??_C@_03A@3?40?$AA@
??_C@_03A@3?40?$AA@	DD	3157555
;??_C@_03A@3?40?$AA@	ENDS
_RDATA	ENDS
_DATA	SEGMENT  DWORD PUBLIC FLAT  'DATA'
_DATA	ENDS
	INCLUDELIB <libmmt>
	INCLUDELIB <LIBCMT>
	INCLUDELIB <libirc>
	INCLUDELIB <svml_dispmt>
	INCLUDELIB <OLDNAMES>
	INCLUDELIB <libdecimal>
	END
