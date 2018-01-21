@echo off
yasm -fwin32 spk64.asm -ospk64.obj
cl /nologo /DTEST /O2 /Os test.c speck32.c spk64.obj speck128.c
test
yasm -fwin32 -DSINGLE spk64.asm -ospk64.obj
cl /nologo /DTEST /DSINGLE /O2 /Os test.c speck32.c spk64.obj speck128.c
test