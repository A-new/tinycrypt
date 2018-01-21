@echo off
yasm -fwin32 chx.asm -ochx.obj
cl test.c chx.obj cham.c