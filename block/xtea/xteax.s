
// xtea in armv6 assembly
// 96 bytes
  .text
  .align  2
  .global xtea_encrypt

xtea_encrypt:
  push  {r4, r5, r6, r7, r8, lr}  
  mov   r0, r0, asl #1
  ldm   r2, {r4, r8}
  mov   r3, #0
  ldr   r6, xtea_const
.L2:
  tst   r0, #1
  addne r3, r3, r6
  moveq r7, r3
  movne r7, r3, lsr #11
  and   r7, r7, #3
  ldr   r7, [r1, r7, asl #2]
  add   r5, r3, r7
  mov   r7, r8, asl #4
  eor   r7, r7, r8, lsr #5
  add   r7, r7, r8
  eor   r7, r7, r5
  add   r7, r7, r4
  mov   r4, r8
  mov   r8, r7
  subs  r0, r0, #1
  bne   .L2
.L8:
  stm   r2, {r4, lr}
  pop   {r4, r5, r6, r7, r8, pc}
xtea_const: 
  .word 0x9E3779B9
