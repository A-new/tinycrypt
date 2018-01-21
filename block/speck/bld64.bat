@echo off
yasm -fwin64 spk128.asm -ospk128.obj
cl /nologo /DTEST /O2 /Os test.c speck32.c speck64.c spk128.obj
test
yasm -fwin64 -DSINGLE spk128.asm -ospk128.obj
cl /nologo /DTEST /DSINGLE /O2 /Os test.c speck32.c speck64.c spk128.obj
test