@echo off
yasm -DBIN -fbin xteax.asm -oxteax.bin
yasm -DBIN -fbin xteax2.asm -oxteax2.bin
yasm -fwin32 xteax.asm -oxteax.obj
yasm -fwin32 xteax2.asm -oxteax2.obj
cl /DASM test.c xteax.obj xtea.c