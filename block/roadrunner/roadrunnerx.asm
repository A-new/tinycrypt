; Listing generated by Microsoft (R) Optimizing Compiler Version 19.10.25019.0 

	TITLE	c:\hub\tinycrypt\block\roadrunner\roadrunnerx.c
	.686P
	.XMM
	include listing.inc
	.model	flat

INCLUDELIB LIBCMT
INCLUDELIB OLDNAMES

PUBLIC	_road64_encrypt
PUBLIC	_sbox
PUBLIC	_SLK
PUBLIC	_F
; Function compile flags: /Ogspy
; File c:\hub\tinycrypt\block\roadrunner\roadrunnerx.c
;	COMDAT _F
_TEXT	SEGMENT
_blk$ = 8						; size = 4
_key$ = 12						; size = 4
_key_idx$ = 16						; size = 4
_ci$ = 20						; size = 1
_F	PROC						; COMDAT

; 88   : {

	push	ebx

; 89   :     int      i;
; 90   :     uint32_t t;
; 91   :     uint8_t  *rk=(uint8_t*)key;
; 92   :     w32_t    *x=(w32_t*)blk;
; 93   :     
; 94   :     // save 32-bits
; 95   :     t = x->w;
; 96   :     
; 97   :     for (i=3; i>0; i--) {

	mov	ebx, DWORD PTR _key_idx$[esp]
	push	ebp
	push	esi
	mov	esi, DWORD PTR _blk$[esp+8]
	push	edi
	push	3
	pop	edi
	mov	ebp, DWORD PTR [esi]
$LL4@F:

; 98   :       // add round constant
; 99   :       if (i==1) x->b[3] ^= ci;

	cmp	edi, 1
	jne	SHORT $LN5@F
	mov	al, BYTE PTR _ci$[esp+12]
	xor	BYTE PTR [esi+3], al
$LN5@F:

; 100  :       // apply diffusion layer
; 101  :       SLK (x, rk + *key_idx);      

	movzx	eax, BYTE PTR [ebx]
	add	eax, DWORD PTR _key$[esp+12]
	push	eax
	push	esi
	call	_SLK

; 102  :       // advance master key index
; 103  :       *key_idx = (*key_idx + 4) & 15;

	mov	al, BYTE PTR [ebx]
	add	al, 4
	and	al, 15					; 0000000fH
	dec	edi
	mov	BYTE PTR [ebx], al
	pop	ecx
	pop	ecx
	test	edi, edi
	jg	SHORT $LL4@F

; 104  :     }
; 105  :     
; 106  :     // non-linear layer
; 107  :     sbox(x->b);

	push	esi
	call	_sbox

; 108  :     
; 109  :     // add upper 32-bits
; 110  :     blk->w[0]^= blk->w[1];

	mov	eax, DWORD PTR [esi+4]
	xor	DWORD PTR [esi], eax
	pop	ecx
	pop	edi

; 111  :     blk->w[1] = t;

	mov	DWORD PTR [esi+4], ebp
	pop	esi
	pop	ebp
	pop	ebx

; 112  : }

	ret	0
_F	ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
; File c:\hub\tinycrypt\block\roadrunner\roadrunnerx.c
;	COMDAT _SLK
_TEXT	SEGMENT
_x$ = 8							; size = 4
_sk$ = 12						; size = 4
_SLK	PROC						; COMDAT

; 67   : {

	push	esi

; 68   :     int     i;
; 69   :     uint8_t t;
; 70   :     uint8_t *p=x->b;

	mov	esi, DWORD PTR _x$[esp]
	push	edi

; 71   :     
; 72   :     // apply non-linear layer
; 73   :     sbox(p);

	push	esi
	call	_sbox

; 74   :     
; 75   :     for (i=3; i>=0; i--) {      

	mov	edx, DWORD PTR _sk$[esp+8]
	pop	ecx
	push	3
	pop	edi
	sub	edx, esi
$LL4@SLK:

; 76   :       // apply linear layer
; 77   :       t   = ROTL8(*p, 1) ^ *p;       

	mov	al, BYTE PTR [esi]
	rol	al, 1
	xor	al, BYTE PTR [esi]

; 78   :       *p ^= ROTL8(t,  1); 

	rol	al, 1
	xor	BYTE PTR [esi], al

; 79   :       
; 80   :       // add key
; 81   :       *p++ ^= *sk++;

	mov	cl, BYTE PTR [edx+esi]
	xor	BYTE PTR [esi], cl
	inc	esi
	sub	edi, 1
	jns	SHORT $LL4@SLK

; 82   :     }
; 83   : }

	pop	edi
	pop	esi
	ret	0
_SLK	ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
; File c:\hub\tinycrypt\block\roadrunner\roadrunnerx.c
;	COMDAT _sbox
_TEXT	SEGMENT
_x$ = 8							; size = 4
_sbox	PROC						; COMDAT

; 50   : {

	push	ebx
	push	esi

; 51   :     uint8_t t;
; 52   :     
; 53   :     t = x[3];

	mov	esi, DWORD PTR _x$[esp+4]

; 54   : 
; 55   :     x[3] &= x[2];

	mov	dl, BYTE PTR [esi+2]
	mov	bl, BYTE PTR [esi+3]
	mov	al, dl

; 56   :     x[3] ^= x[1];

	mov	cl, BYTE PTR [esi+1]
	and	al, bl
	xor	al, cl

; 57   :     x[1] |= x[2];

	or	cl, dl

; 58   :     x[1] ^= x[0];

	xor	cl, BYTE PTR [esi]
	mov	BYTE PTR [esi+3], al

; 59   :     x[0] &= x[3];

	mov	al, BYTE PTR [esi]
	and	al, BYTE PTR [esi+3]

; 60   :     x[0] ^=  t; 

	xor	al, bl
	mov	BYTE PTR [esi+1], cl
	mov	BYTE PTR [esi], al

; 61   :        t &= x[1];

	mov	al, cl
	and	al, bl

; 62   :     x[2] ^=  t;

	xor	al, dl
	mov	BYTE PTR [esi+2], al
	pop	esi
	pop	ebx

; 63   : }

	ret	0
_sbox	ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
; File c:\hub\tinycrypt\block\roadrunner\roadrunnerx.c
;	COMDAT _road64_encrypt
_TEXT	SEGMENT
_key_idx$ = -1						; size = 1
_data$ = 8						; size = 4
_key$ = 12						; size = 4
_road64_encrypt PROC					; COMDAT

; 116  : {

	push	ebp
	mov	ebp, esp
	push	ecx
	push	ebx

; 117  :     int      rnd;
; 118  :     uint8_t  key_idx;
; 119  :     uint32_t t;
; 120  :     w64_t    *x=(w64_t*)data;
; 121  :     uint32_t *rk=(uint32_t*)key;
; 122  : 
; 123  :     // initialize master key index
; 124  :     key_idx = 4;
; 125  :     
; 126  :     // add key
; 127  :     x->w[0] ^= rk[0];

	mov	ebx, DWORD PTR _key$[ebp]
	push	esi
	mov	esi, DWORD PTR _data$[ebp]
	push	edi
	mov	eax, DWORD PTR [ebx]

; 128  :     
; 129  :     // apply rounds
; 130  :     for (rnd=RR_ROUNDS; rnd>0; rnd--) {

	push	12					; 0000000cH
	xor	DWORD PTR [esi], eax
	mov	BYTE PTR _key_idx$[ebp], 4
	pop	edi
$LL4@road64_enc:

; 131  :       F(x, rk, &key_idx, rnd);

	push	edi
	lea	eax, DWORD PTR _key_idx$[ebp]
	push	eax
	push	ebx
	push	esi
	call	_F
	add	esp, 16					; 00000010H
	dec	edi
	test	edi, edi
	jg	SHORT $LL4@road64_enc

; 132  :     }
; 133  :     // swap
; 134  :     XCHG(x->w[0], x->w[1]);

	mov	ecx, DWORD PTR [esi]
	mov	eax, DWORD PTR [esi+4]
	mov	DWORD PTR [esi], eax
	mov	DWORD PTR [esi+4], ecx

; 135  :     // add key
; 136  :     x->w[0] ^= rk[1];

	mov	eax, DWORD PTR [ebx+4]
	xor	DWORD PTR [esi], eax
	pop	edi
	pop	esi
	pop	ebx

; 137  : }

	mov	esp, ebp
	pop	ebp
	ret	0
_road64_encrypt ENDP
_TEXT	ENDS
END
