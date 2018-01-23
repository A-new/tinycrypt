@echo off
yasm -fbin -DBIN bbx.asm -obbx.bin
yasm -fwin64 bbx.asm -obbx.obj
cl test.c bbx.obj blabla.c