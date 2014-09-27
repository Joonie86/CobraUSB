CC		:= ppu-gcc
CXX		:= ppu-g++
LD		:= ppu-ld 
OBJCOPY		:= ppu-objcopy
AR 		:= ppu-ar
STRIP		:= ppu-strip
INCLUDE		= ../lv2/include ../lv1/include ../debug/include
LIBSDIR         =
LIBS            =
TARGET		= stage1
BUILD_TYPE      = release
LV2GEN 		= ../lv2gen/lv2gen
LV2_KERNEL	= ../lv2gen/lv2_kernel.self
KERNEL_TARGET	= lv2_kernel.self
PAYLOAD_ADDR	= 0x7f0000
STAGE0 		= ../stage0_file/stage0.bin
STAGE0_ADDR	= 0x28FE30


CFLAGS = -ffunction-sections -fdata-sections -Os -m64 -fno-builtin -fno-exceptions \
			   -Os -Wall -Wno-strict-aliasing $(foreach dir,$(INCLUDE),-I$(dir)) \
			   -DLV2 -DFIRMWARE_3_55 -DCFW -ffreestanding 
CFLAGS += --std=gnu99

ifeq ($(BUILD_TYPE), debug)
CFLAGS += -DDEBUG
endif

LDFLAGS=-nostartfiles -nostdlib -mbig-endian
LDFLAGS= -T $(TARGET).ld -nostartfiles -nostdlib -nodefaultlibs -Wl,-static -Wl,-s -L. $(foreach dir,$(LIBSDIR),-L$(dir)) $(LIBS) -Wl,--gc-sections -Wl

OBJS = start.o main.o icache.o LZMA/LzmaDec.o ../lv2/src/libc.o ../lv2/src/memory.o ../lv2/src/synchronization.o ../lv2/src/usb.o ../lv1/src/hvcall.o 

ifeq ($(BUILD_TYPE), debug)
OBJS += ../lv1/src/device.o ../debug/src/debug.o ../debug/src/printf.o 
endif


all: $(TARGET).bin

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	$(LV2GEN) $(STAGE0) $(TARGET).bin $(LV2_KERNEL) $(KERNEL_TARGET) $(PAYLOAD_ADDR) $(STAGE0_ADDR)
	

$(TARGET).elf: $(OBJS) $(TARGET).ld
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.elf *.bin ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
