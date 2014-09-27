CELL_MK_DIR = $(CELL_SDK)/samples/mk
include $(CELL_MK_DIR)/sdk.makedef.mk

BUILD_TYPE     	= release

LIBSTUB_DIR		= ../lib
PRX_DIR		= .
INSTALL			= cp
PEXPORTPICKUP		= ppu-lv2-prx-exportpickup
PRX_LDFLAGS_EXTRA	= -L ../lib -Wl,--strip-unused-data
CIPHER 		= ../sprx_cipher2/sprx_cipher2.exe

CRT_HEAD                += $(shell ppu-lv2-gcc -print-file-name'='ecrti.o)
CRT_HEAD                += $(shell ppu-lv2-gcc -print-file-name'='crtbegin.o)
CRT_TAIL                += $(shell ppu-lv2-gcc -print-file-name'='crtend.o)
CRT_HEAD                += $(shell ppu-lv2-gcc -print-file-name'='ecrtn.o)

PPU_SRCS = main.c printf.c libc.c asmcode.s
PPU_PRX_TARGET = avchd.prx
PPU_PRX_LDFLAGS += $(PRX_LDFLAGS_EXTRA)
PPU_PRX_STRIP_FLAGS = -s
PPU_PRX_LDLIBS 	+= -lfs_stub -lnet_stub
PPU_CFLAGS += -Os -ffunction-sections -fdata-sections -fno-builtin-printf -nodefaultlibs -std=gnu99 -Wno-shadow -Wno-unused-parameter

ifeq ($(BUILD_TYPE), debug)
PPU_CFLAGS += -DDEBUG -DDEBUG_FILE
endif

CLEANFILES = $(PRX_DIR)/$(PPU_SPRX_TARGET)

all:
	$(MAKE) $(PPU_OBJS_DEPENDS)
	$(PPU_PRX_STRIP) --strip-debug --strip-section-header $(PPU_PRX_TARGET)
	$(MAKE_FSELF) $(PPU_PRX_TARGET) $(PPU_SPRX_TARGET)
	$(CIPHER) vsh $(PPU_SPRX_TARGET) $(PPU_SPRX_TARGET)

include $(CELL_MK_DIR)/sdk.target.mk




