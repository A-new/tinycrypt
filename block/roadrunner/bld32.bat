@echo off
yasm -fwin32 rrx.asm -orrx.obj
yasm -fbin -DBIN rrx.asm -orrx.bin
cl test.c rrx.obj roadrunnerx.c