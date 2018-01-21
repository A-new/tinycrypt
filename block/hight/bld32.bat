@echo off
yasm -fbin -DBIN hx.asm -ohx.bin
yasm -fwin32 hx.asm -ohx.obj
cl test.c hx.obj hight.c