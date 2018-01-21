@echo off
yasm -fbin -DBIN xteax.asm -oxteax.bin
yasm -fwin32 xteax.asm -oxteax.obj
cl /c /Fa /O2 /Os /GS- xtea.c
jwasm -bin xtea.asm
cl test.c xtea.c xteax.obj
del *.obj