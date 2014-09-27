ppu-lv2-gcc --std=c99 -O2 -Wall -c cobra.c
ppu-lv2-ar rcs libcobra.a cobra.o
ppu-lv2-strip -x libcobra.a


