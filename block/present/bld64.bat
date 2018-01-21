@echo off
yasm -fwin64 px.asm -opx.obj
yasm -DBIN px.asm -opx.bin
cl test.c p128.c px.obj
del *.obj *.err