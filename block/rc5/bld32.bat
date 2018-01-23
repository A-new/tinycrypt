@echo off
yasm -fbin -DBIN r5x.asm -or5x.bin
yasm -fwin32 r5x.asm -or5x.obj
cl /DSINGLE test.c r5x.obj rc5.c