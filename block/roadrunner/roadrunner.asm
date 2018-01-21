; Listing generated by Microsoft (R) Optimizing Compiler Version 16.00.40219.01 

	TITLE	c:\hub\tinycrypt\block\roadrunner\roadrunner.c
	.686P
	.XMM
	include listing.inc
	.model	flat

INCLUDELIB LIBCMT
INCLUDELIB OLDNAMES

PUBLIC	_sbox
; Function compile flags: /Ogspy
; File c:\hub\tinycrypt\block\roadrunner\roadrunner.c
;	COMDAT _sbox
_TEXT	SEGMENT
_x$ = 8							; size = 4
tv162 = 11						; size = 1
_sbox	PROC						; COMDAT

; 34   : {

	push	ebp
	mov	ebp, esp

; 35   :     uint8_t t = x[3];

	mov	eax, DWORD PTR _x$[ebp]
	mov	dl, BYTE PTR [eax+3]

; 36   :     
; 37   :     x[3] &= x[2];
; 38   :     x[3] ^= x[1];

	mov	cl, BYTE PTR [eax+1]
	push	ebx
	mov	bl, BYTE PTR [eax+2]
	and	bl, dl
	xor	bl, cl
	mov	BYTE PTR [eax+3], bl

; 39   :     x[1] |= x[2];

	mov	bl, BYTE PTR [eax+2]
	mov	BYTE PTR tv162[ebp], dl

; 40   :     x[1] ^= x[0];

	mov	dl, BYTE PTR [eax]
	or	cl, bl
	xor	cl, dl

; 41   :     x[0] &= x[3];

	and	dl, BYTE PTR [eax+3]
	mov	BYTE PTR [eax+1], cl

; 42   :     x[0] ^= t;
; 43   :     t    &= x[1];

	and	cl, BYTE PTR tv162[ebp]
	xor	dl, BYTE PTR tv162[ebp]

; 44   :     x[2] ^= t;

	xor	cl, bl
	mov	BYTE PTR [eax], dl
	mov	BYTE PTR [eax+2], cl
	pop	ebx

; 45   : }

	pop	ebp
	ret	0
_sbox	ENDP
_TEXT	ENDS
PUBLIC	_SLK
; Function compile flags: /Ogspy
;	COMDAT _SLK
_TEXT	SEGMENT
_x$ = 8							; size = 4
_key_part$ = 12						; size = 4
_SLK	PROC						; COMDAT

; 48   : {

	push	esi
	push	edi

; 49   :     uint8_t i, t;
; 50   :     
; 51   :     sbox(x);

	push	DWORD PTR _x$[esp+4]
	call	_sbox

; 52   :     
; 53   :     for(i=0; i<4; i++) {      

	mov	esi, DWORD PTR _key_part$[esp+8]
	pop	ecx
	mov	ecx, DWORD PTR _x$[esp+4]
	push	4
	sub	esi, ecx
	pop	edi
$LL3@SLK:

; 54   :       t = ROTL8(x[i], 1); t ^= x[i];

	mov	dl, BYTE PTR [ecx]
	mov	al, dl
	rol	al, 1
	xor	al, dl

; 55   :       t = ROTL8(t, 1); x[i] ^= t;

	rol	al, 1
	xor	al, dl
	mov	BYTE PTR [ecx], al

; 56   :       
; 57   :       x[i] ^= key_part[i];

	mov	dl, BYTE PTR [esi+ecx]
	xor	dl, al
	mov	BYTE PTR [ecx], dl
	inc	ecx
	dec	edi
	jne	SHORT $LL3@SLK

; 58   :     }
; 59   : }

	pop	edi
	pop	esi
	ret	0
_SLK	ENDP
_TEXT	ENDS
PUBLIC	_rr_round
; Function compile flags: /Ogspy
;	COMDAT _rr_round
_TEXT	SEGMENT
_t$ = 8							; size = 4
_x$ = 8							; size = 4
_rk$ = 12						; size = 4
_idx$ = 16						; size = 1
_ctr$ = 20						; size = 4
_rr_round PROC						; COMDAT

; 62   : {

	push	ebp
	mov	ebp, esp
	push	ebx
	push	esi

; 63   :     uint8_t i, t[4];
; 64   :     
; 65   :     memcpy(t, x, 4);
; 66   :     
; 67   :     for (i=0; i<3; i++) {

	mov	esi, DWORD PTR _ctr$[ebp]
	push	edi
	mov	edi, DWORD PTR _x$[ebp]
	mov	eax, DWORD PTR [edi]
	mov	DWORD PTR _t$[ebp], eax
	xor	bl, bl
$LL10@rr_round:

; 68   :       if (i==2) x[3] ^= idx;

	cmp	bl, 2
	jne	SHORT $LN7@rr_round
	mov	al, BYTE PTR _idx$[ebp]
	xor	BYTE PTR [edi+3], al
$LN7@rr_round:

; 69   :       SLK (x, rk + ctr[0]);

	movzx	eax, BYTE PTR [esi]
	add	eax, DWORD PTR _rk$[ebp]
	push	eax
	push	edi
	call	_SLK

; 70   :       ctr[0] = (ctr[0] + 4) & 15;

	mov	al, BYTE PTR [esi]
	add	al, 4
	and	al, 15					; 0000000fH
	inc	bl
	pop	ecx
	pop	ecx
	mov	BYTE PTR [esi], al
	cmp	bl, 3
	jb	SHORT $LL10@rr_round

; 71   :     }
; 72   :     
; 73   :     sbox(x);

	push	edi
	call	_sbox
	pop	ecx
	push	4
	mov	eax, edi
	pop	ecx
$LL6@rr_round:

; 74   :     
; 75   :     for (i=0; i<4; i++) x[i  ] ^= x[i+4];

	mov	dl, BYTE PTR [eax+4]
	xor	BYTE PTR [eax], dl
	inc	eax
	dec	ecx
	jne	SHORT $LL6@rr_round

; 76   :     for (i=0; i<4; i++) x[i+4]  = t[i  ];

	add	edi, 4
	lea	esi, DWORD PTR _t$[ebp]
	movsd
	pop	edi
	pop	esi
	pop	ebx

; 77   : }

	pop	ebp
	ret	0
_rr_round ENDP
_TEXT	ENDS
PUBLIC	_road64_encrypt
; Function compile flags: /Ogspy
;	COMDAT _road64_encrypt
_TEXT	SEGMENT
_i$ = -8						; size = 1
_t$ = -4						; size = 4
_x$ = 8							; size = 4
_rk$ = 12						; size = 4
_road64_encrypt PROC					; COMDAT

; 80   : {

	push	ebp
	mov	ebp, esp
	push	ecx
	push	ecx
	push	ebx

; 81   :     uint8_t i, t[4] = {0};

	mov	ebx, DWORD PTR _x$[ebp]
	push	esi

; 82   :     
; 83   :     t[0] = 4;
; 84   :     
; 85   :     // key whitening
; 86   :     for (i=0; i<4; i++) x[i] ^= rk[i];

	mov	esi, DWORD PTR _rk$[ebp]
	push	edi
	xor	eax, eax
	lea	edi, DWORD PTR _t$[ebp+1]
	stosw
	stosb
	push	4
	mov	BYTE PTR _t$[ebp], 4
	mov	eax, ebx
	sub	esi, ebx
	pop	edi
$LL15@road64_enc:
	mov	cl, BYTE PTR [esi+eax]
	xor	BYTE PTR [eax], cl
	inc	eax
	dec	edi
	jne	SHORT $LL15@road64_enc

; 87   :     
; 88   :     // apply rounds
; 89   :     for (i=NUMBER_OF_ROUNDS; i>0; i--) {

	mov	BYTE PTR _i$[ebp], 12			; 0000000cH
$LL28@road64_enc:

; 90   :       rr_round(x, rk, i, t);

	lea	eax, DWORD PTR _t$[ebp]
	push	eax
	push	DWORD PTR _i$[ebp]
	push	DWORD PTR _rk$[ebp]
	push	ebx
	call	_rr_round
	add	esp, 16					; 00000010H
	dec	BYTE PTR _i$[ebp]
	jne	SHORT $LL28@road64_enc

; 91   :     }
; 92   :     // 
; 93   :     for (i=0; i<4; i++) t[i] = x[i];
; 94   :     // key whitening
; 95   :     for (i=0; i<4; i++) x[i  ] = x[i+4] ^ rk[i+4];

	mov	ecx, DWORD PTR _rk$[ebp]
	mov	esi, ebx
	lea	edi, DWORD PTR _t$[ebp]
	movsd
	mov	esi, ebx
	push	4
	lea	eax, DWORD PTR [ecx+4]
	sub	esi, ecx
	mov	edi, ebx
	pop	ecx
$LL6@road64_enc:
	mov	dl, BYTE PTR [esi+eax]
	xor	dl, BYTE PTR [eax]
	inc	eax
	mov	BYTE PTR [edi], dl
	inc	edi
	dec	ecx
	jne	SHORT $LL6@road64_enc

; 96   :     for (i=0; i<4; i++) x[i+4] = t[i];

	lea	edi, DWORD PTR [ebx+4]
	lea	esi, DWORD PTR _t$[ebp]
	movsd
	pop	edi
	pop	esi
	pop	ebx

; 97   : }

	leave
	ret	0
_road64_encrypt ENDP
_TEXT	ENDS
END
