CC		:= ppu-gcc
CXX		:= ppu-g++
LD		:= ppu-ld 
OBJCOPY		:= ppu-objcopy
OBJDUMP		:= ppu-objdump
AR 		:= ppu-ar
STRIP		:= ppu-strip
INCLUDE		= ../common ../../ps2emu/include ../../lv1/include ../../debug/include
LIBSDIR         =
LIBS            =
BUILD_TYPE      = release
CIPHER=../stage2_cipher/st2cipher
KEYS=stage2_keys
IV=stage2_IV
HEADER=../../ps2emu_stage1.5/loader/stage2hw.h

CFLAGS = -ffunction-sections -fdata-sections -Os -m64 -fno-builtin -fno-exceptions \
			   -Os -Wall -Wno-strict-aliasing $(foreach dir,$(INCLUDE),-I$(dir)) \
			   -DPS2EMU -DPS2HWEMU -DFIRMWARE_3_55 -ffreestanding 
CFLAGS += --std=gnu99

ifeq ($(BUILD_TYPE), debug)
CFLAGS += -DDEBUG
endif

ifeq ($(BUILD_TYPE), debug2)
CFLAGS += -DDEBUG -DSTAGE1_5
endif

ifeq ($(BUILD_TYPE), release)
CFLAGS += -DSTAGE1_5
endif

LDFLAGS= -T ldscript.ld -nostartfiles -nostdlib -nodefaultlibs -Wl,-static -Wl,-s -L. $(foreach dir,$(LIBSDIR),-L$(dir)) $(LIBS) \
	-Wl,--gc-sections -Wl,-Map=ps2hwemu_stage2.map

OBJS = start.o crt0.o main.o ../../ps2emu/src/libc.o ../../ps2emu/src/libc_c.o ../../ps2emu/src/memory.o ../../ps2emu/src/io.o ../../ps2emu/src/patch.o 

ifeq ($(BUILD_TYPE), debug)
OBJS += ../../lv1/src/hvcall.o ../../lv1/src/device.o ../../debug/src/debug.o ../../debug/src/printf.o 
endif

all: ps2hwemu_stage2.bin

objdump: ps2hwemu_stage2.bin
	$(OBJDUMP) -D -EB -b binary -m powerpc:common64 ps2hwemu_stage2.bin

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	$(CIPHER) $@ $(KEYS) $(IV) $(HEADER)
	cp $@ /media/KINGSTON/s2.bin
	
ps2hwemu_stage2.elf: $(OBJS) ldscript.ld
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.elf *.bin *.map ../../ps2emu/src/*.o ../../lv1/src/*.o ../../debug/src/*.o
