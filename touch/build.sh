#!/bin/bash
rm touch.x64.o
rm touch.x86.o
x86_64-w64-mingw32-gcc -c touch.c -o touch.x64.o -lntdll
i686-w64-mingw32-gcc -c touch.c -o touch.x86.o -lntdll
