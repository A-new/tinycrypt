@echo off
yasm -fbin -DBIN rx.asm -orx.bin
yasm -fwin32 rx.asm -orx.obj
cl /DSINGLE test.c rx.obj rc6.c