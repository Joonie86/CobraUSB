CC		:= ppu-gcc
CXX		:= ppu-g++
LD		:= ppu-ld 
OBJCOPY		:= ppu-objcopy
OBJDUMP		:= ppu-objdump
AR 		:= ppu-ar
STRIP		:= ppu-strip
INCLUDE		= ../lv2/include ../lv1/include ../debug/include
LIBSDIR         =
LIBS            =
BUILD_TYPE      = debug
CIPHER		= ../stage2_cipher/st2cipher
KEYS		= stage1_5_keys
IV		= stage1_5_IV
TEA_CODE_KEY	= 0xFD,0x90,0x5A,0xBF,0x25,0xCD,0xC2,0x36,0x1F,0x9F,0xDE,0x08,0x8A,0x94,0x25,0x3B

CFLAGS = -ffunction-sections -fdata-sections -Os -m64 -fno-builtin -fsigned-char  -fno-exceptions \
			   -Os -Wall -Wno-strict-aliasing $(foreach dir,$(INCLUDE),-I$(dir)) \
			   -DLV2 -DFIRMWARE_3_55 -DCFW -DTEA_CODE_KEY=$(TEA_CODE_KEY) -ffreestanding 
CFLAGS += --std=gnu99

ifeq ($(BUILD_TYPE), debug)
CFLAGS += -DDEBUG
endif

LDFLAGS= -T stage2.ld -nostartfiles -nostdlib -nodefaultlibs -Wl,-static -Wl,-s -L. $(foreach dir,$(LIBSDIR),-L$(dir)) $(LIBS) \
	-Wl,--gc-sections -Wl,-Map=stage1_5.map

OBJS = start.o main.o gelic.o ../lv2/src/io.o ../lv2/src/thread.o ../lv2/src/libc.o ../lv2/src/memory.o ../lv2/src/synchronization.o ../lv2/src/usb.o ../lv2/src/patch.o ../lv1/src/mm.o ../lv1/src/hvcall.o ../lv1/src/device.o  
	

ifeq ($(BUILD_TYPE), debug)
OBJS += ../lv2/src/interrupt.o ../debug/src/debug.o ../debug/src/printf.o 
endif

all: stage1_5.bin

objdump: stage1_5.bin
	$(OBJDUMP) -D -EB -b binary -m powerpc:common64 stage1_5.bin

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	lzmautil e $@ stage1_5.lzma 
	truncate "--size=%16" stage1_5.lzma
	$(CIPHER) stage1_5.lzma $(KEYS) $(IV) stage1_5.rc6

stage1_5.elf: $(OBJS) stage2.ld
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.elf *.bin *.map ../lv2/src/*.o ../lv1/src/*.o ../debug/src/*.o
