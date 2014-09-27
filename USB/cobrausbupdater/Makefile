.PHONY: gen_pkg npdrm_package

BUILD_TYPE      = release

CELL_MK_DIR = $(CELL_SDK)/samples/mk
include $(CELL_MK_DIR)/sdk.makedef.mk

PPU_SRCS = main.cpp graphics.cpp dialog.cpp cobra.c sha1.c scandir.c $(VPSHADER_PPU_OBJS) $(FPSHADER_PPU_OBJS)
PPU_TARGET = updater.elf

PPU_INCDIRS	+= -I$(CELL_SDK)/target/ppu/include/sysutil

PPU_CPPFLAGS += -Wno-shadow -DNOT_SCANDIR
PPU_CFLAGS += -DNOT_SCANDIR

ifeq ($(BUILD_TYPE), debug)
PPU_CFLAGS += -DDEBUG
PPU_CPPFLAGS += -DDEBUG
endif

PPU_LDFLAGS += -L ../lib

EXPORT_OBJS = 


PPU_LDLIBS 	+= -lrtc_stub -lm -ldbgfont_gcm -lgcm_cmd -lgcm_sys_stub\
		    -lio_stub -lsysmodule_stub -lsysutil_stub -lfs_stub -ll10n_stub -lusbd_stub \
		    -lfontGcm -lfontFT_stub -lfreetype_stub -lfont_stub -lsysutil_screenshot_stub -lcobra-export_stub


VPSHADER_SRCS = vpshader.cg vpshader2.cg
FPSHADER_SRCS = fpshader.cg fpshader2.cg

VPSHADER_PPU_OBJS = $(patsubst %.cg, $(OBJS_DIR)/%.ppu.o, $(VPSHADER_SRCS))
FPSHADER_PPU_OBJS = $(patsubst %.cg, $(OBJS_DIR)/%.ppu.o, $(FPSHADER_SRCS))

include $(CELL_MK_DIR)/sdk.target.mk

PPU_OBJS += $(VPSHADER_PPU_OBJS) $(FPSHADER_PPU_OBJS) $(EXPORT_OBJS) 

MAKESELF = @makeself
PKG = /c/PS3Py/pkg.py
CIPHER 		= ../sprx_cipher2/sprx_cipher2.exe
TARGET_PKG = "Cobra_USB_Updater_1_0.pkg"
CONTENT_ID = UP0001-CBUP43210_00-0000000000000000

$(VPSHADER_PPU_OBJS): $(OBJS_DIR)/%.ppu.o : %.vpo
	@mkdir -p $(dir $(@))
	$(PPU_OBJCOPY)  -I binary -O elf64-powerpc-celloslv2 -B powerpc $< $@

$(FPSHADER_PPU_OBJS): $(OBJS_DIR)/%.ppu.o : %.fpo
	@mkdir -p $(dir $(@))
	$(PPU_OBJCOPY)  -I binary -O elf64-powerpc-celloslv2 -B powerpc $< $@


gen_pkg:: $(PPU_TARGET)
	$(PPU_STRIP) -s $< -o $(OBJS_DIR)/$(PPU_TARGET)
	$(MAKE_FSELF) $(OBJS_DIR)/$(PPU_TARGET) EBOOT.BIN				# to use in /app_home/PS3_GAME
	$(MAKE_FSELF_NPDRM)  $(OBJS_DIR)/$(PPU_TARGET) PS3_GAME/USRDIR/EBOOT.BIN
#	$(CIPHER) PS3_GAME/USRDIR/EBOOT.BIN PS3_GAME/USRDIR/EBOOT.BIN
	$(MAKE_PACKAGE_NPDRM) package.conf PS3_GAME/				# to install pkg
#	$(MAKESELF) app 341 1.0.0 01000002 10100000_01000003 retail $(OBJS_DIR)/$(PPU_TARGET) PS3_GAME/USRDIR/EBOOT.BIN
	@python $(PKG) --contentid $(CONTENT_ID) PS3_GAME/  $(TARGET_PKG)