; Listing generated by Microsoft (R) Optimizing Compiler Version 19.00.23026.0 

	TTL	C:\hub\tinycrypt\block\xtea\xtea.c
	THUMB
	.drectve
	DCB	"-defaultlib:LIBCMT "
	DCB	"-defaultlib:OLDNAMES "

	EXPORT	|xtea_encrypt|
;	COMDAT .pdata
.pdata	SEGMENT
|$pdata1$xtea_encrypt| DCD imagerel |xtea_encrypt|
	DCD	0x146099
; Function compile flags: /Ogspy
; File c:\hub\tinycrypt\block\xtea\xtea.c
;	COMDAT xtea_encrypt
.text$mn	SEGMENT

|xtea_encrypt| PROC

; 32   : void xtea_encrypt(uint32_t rnds, void *key, void *buf) {

	push        {r4-r8,lr}
|$M15|

; 33   :     int      i, j;
; 34   :     uint32_t v0, v1, t, sum=0;
; 35   :     uint32_t *k=(uint32_t*)key;
; 36   :     uint32_t *v=(uint32_t*)buf;
; 37   :     
; 38   :     v0 = v[0]; v1 = v[1];
; 39   :     
; 40   :     for (i=rnds<<1; i>0; i--) {

	lsls        r5,r0,#1
	ldrd        lr,r6,[r2]
	movs        r4,#0
	cmp         r5,#0
	ble         |$LN3@xtea_encry|
	ldr         r8,|$LN14@xtea_encry|		; =0x61c88647
|$LL4@xtea_encry|

; 41   :       t = sum;

	mov         r7,r4

; 42   :       if (i & 1) {

	tst         r5,#1
	beq         |$LN5@xtea_encry|

; 43   :         sum += 0x9E3779B9;

	sub         r4,r4,r8

; 44   :         t = sum >> 11;          

	lsrs        r7,r4,#0xB
|$LN5@xtea_encry|

; 45   :       }
; 46   :       v0  += ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[t & 3]));        

	lsls        r3,r6,#4
	eor         r3,r3,r6,lsr #5
	adds        r0,r3,r6
	and         r3,r7,#3
	ldr         r3,[r1,r3,lsl #2]
	subs        r5,r5,#1
	add         r3,r3,r4
	eors        r3,r3,r0
	add         r3,r3,lr

; 47   :       XCHG(v0, v1);

	mov         lr,r6
	mov         r6,r3
	cmp         r5,#0
	bgt         |$LL4@xtea_encry|
|$LN3@xtea_encry|

; 48   :     }
; 49   :     v[0] = v0; v[1] = v1;

	str         lr,[r2]
	str         r6,[r2,#4]
|$M12|

; 50   : }

	pop         {r4-r8,pc}
|$LN13@xtea_encry|
|$LN14@xtea_encry|
	DCD         0x61c88647
|$M16|

	ENDP  ; |xtea_encrypt|

	END
