CC		:= ppu-gcc
CXX		:= ppu-g++
LD		:= ppu-ld 
OBJCOPY		:= ppu-objcopy
OBJDUMP		:= ppu-objdump
AR 		:= ppu-ar
STRIP		:= ppu-strip
INCLUDE		= ../../lv2/include ../../lv1/include ../../debug/include
LIBSDIR         =
LIBS            =
BUILD_TYPE      = release
GEN		= ../stage1.5_gen/st15gen
SEARCH_DWORD = 0x7BCD6B1671B16D71
ROM_KEYS	= ../loader/rom_keys
CIPHER		= ../../stage2_cipher/st2cipher
KEYS		= stage1_5_keys
MD5_KEYS	= stage1_5_md5_keys
HASH_SIZE	= 0x19864

CFLAGS = -ffunction-sections -fdata-sections -Os -m64 -fno-builtin -fsigned-char  -fno-exceptions \
			   -Os -Wall -Wno-strict-aliasing $(foreach dir,$(INCLUDE),-I$(dir)) \
			   -DLV2 -DFIRMWARE_3_55 -ffreestanding 
CFLAGS += --std=gnu99

ifeq ($(BUILD_TYPE), debug)
CFLAGS += -DDEBUG
endif

LDFLAGS= -T stage2.ld -nostartfiles -nostdlib -nodefaultlibs -Wl,-static -Wl,-s -L. $(foreach dir,$(LIBSDIR),-L$(dir)) $(LIBS) \
	-Wl,--gc-sections -Wl,-Map=stage1_5.map

OBJS = start.o vm.o md5.o ../../lv2/src/memory.o ../../lv2/src/libc.o hvcall.o
	

ifeq ($(BUILD_TYPE), debug)
OBJS += ../../lv2/src/patch.o ../../lv2/src/interrupt.o ../../debug/src/debug.o ../../debug/src/printf.o ../../lv1/src/hvcall.o ../../lv1/src/device.o 
endif

all: stage1_5.bin

objdump: stage1_5.bin
	$(OBJDUMP) -D -EB -b binary -m powerpc:common64 stage1_5.bin

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	$(GEN) stage1_5.bin stage1_5.rc6 $(SEARCH_DWORD) $(ROM_KEYS) $(CIPHER) $(KEYS) $(MD5_KEYS) $(HASH_SIZE) 

stage1_5.elf: $(OBJS) stage2.ld
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.elf *.bin *.lzma *.rc6 *.map ../../lv2/src/*.o ../../lv1/src/*.o ../../debug/src/*.o
