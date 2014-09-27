#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/interrupt.h>
#include <lv2/modules.h>
#include <lv2/process.h>
#include <lv2/memory.h>
#include <lv2/io.h>
#include <lv2/symbols.h>
#include <lv2/patch.h>
#include <lv2/error.h>
#include <lv2/security.h>
#include <lv2/thread.h>
#include <lv2/syscall.h>
#include <cryptcode/cryptcode.h>
#include "common.h"
#include "modulespatch.h"
#include "permissions.h"
#include "crypto.h"
#include "config.h"
#include "storage_ext.h"
#include "psp.h"
#include "cobra.h"
#include "syscall8.h"
#include "self.h"
#include "authorized_sprx_md5.h"

// NOTE: self offsets are substracted 0x10000 bytes, sprx offsets are normal. 

#if defined(FIRMWARE_3_41)

#define VSH_HASH			0xa0556f3d002cb8fd
#define NAS_PLUGIN_HASH			0x6b70280200020017
#define EXPLORE_PLUGIN_HASH		0x8c0a948c000d99b1
#define EXPLORE_CATEGORY_GAME_HASH	0xa2bc1a5600052adc
#define BDP_DISC_CHECK_PLUGIN_HASH	0x86517b4c0000320d
#define PS1_EMU_HASH			0x7a611dec000a0505
#define GAME_EXT_PLUGIN_HASH		0x34c23b7d0001c920
#define X3_MDIMP1_HASH			0x32150f1b0000898f

/* vsh */
#define elf1_func1 			0x5f3fc0
#define elf1_func1_offset 		0x00
#define elf1_func2 			0x305354
#define elf1_func2_offset 		0x14
#define game_update_offset		0x3310f8

/* nas_plugin */
#define elf2_func1 			0x2eb7c
#define elf2_func1_offset		0x374

/* explore_plugin */
#define elf3_data_offset 		0x0022b888
#define app_home_offset			0x2367E8
#define ps2_nonbw_offset		0xD7194

/* explore_category_game */
#define elf4_data_offset 		0x000d68b8
#define ps2_nonbw_offset2		0x7522c

/* bdp_disc_check_plugin */
#define dvd_video_region_check_offset	0x1B20

/* ps1_emu */
#define get_region_offset		0x3E74		

/* game_ext_plugin */
#define sfo_check_offset		0x2029C
#define ps2_nonbw_offset3		0x114A4

#elif defined(FIRMWARE_3_55)

#define VSH_HASH			0xa05428bd002d15fb
#define VSH_REACTPSN_HASH		0xa05428bd002d15f7
#define BASIC_PLUGINS_HASH		0xdf98d6550002538b
#define NAS_PLUGIN_HASH			0xe21928ff00025c6f
#define EXPLORE_PLUGIN_HASH		0x8c0a948c000db78d
#define EXPLORE_CATEGORY_GAME_HASH	0xa2bc18fa00052c74
#define BDP_DISC_CHECK_PLUGIN_HASH	0x86517b7c0000324d
#define PS1_EMU_HASH			0x7a611fec000a0448
#define PS1_NETEMU_HASH			0x7a3451e9000c3040
#define GAME_EXT_PLUGIN_HASH		0x3bebd0440001dd6b
#define X3_MDIMP1_HASH			0x32150f1b00008951
#define PSP_EMULATOR_HASH		0x7be7aced00022a4b
#define EMULATOR_API_HASH		0xa9f5bb7a000108e1
#define PEMUCORELIB_HASH		0xf349a56300087ba4
#define EMULATOR_DRM_HASH		0x7cfa1581000037f5
#define EMULATOR_DRM_DATA_HASH		0xe7b395210000f959
#define LIBSYSUTIL_SAVEDATA_PSP_HASH	0xc7f8df5e00002fa2
#define LIBFS_EXTERNAL_HASH		0x5bc7bad800005fa4

/* vsh */
#define elf1_func1 			0x5FFEE8
#define elf1_func1_offset 		0x00
#define elf1_func2 			0x30A7C0
#define elf1_func2_offset 		0x14
#define game_update_offset		0x3365F4
#define psp_drm_patch1			0x307E74
#define psp_drm_patch2			0x3086C0
#define psp_drm_patch3			0x3082F8
#define psp_drm_patch4			0x308ACC
#define psp_drm_patchA			0x307EA8
#define psp_drm_patchB			0x308714
#define psp_drm_patchC			0x307814
#define revision_offset			0x6668B0
#define spoof_version_patch		0x190F74
#define psn_spoof_version_patch		0x26D238

/* basic_plugins */
#define pspemu_path_offset		0x559D8
#define psptrans_path_offset		0x56510

/* nas_plugin */
#define elf2_func1 			0x36EEC
#define elf2_func1_offset		0x374
#define geohot_pkg_offset		0x316C

/* explore_plugin */
#define elf3_data_offset 		0x22f688
#define app_home_offset			0x23A6C0
#define ps2_nonbw_offset		0xD7708

/* explore_category_game */
#define elf4_data_offset 		0xD6AD8
#define ps2_nonbw_offset2		0x7544C

/* bdp_disc_check_plugin */
#define dvd_video_region_check_offset	0x1B20

/* ps1_emu */
#define ps1_emu_get_region_offset	0x3E74	

/* ps1_netemu */
#define ps1_netemu_get_region_offset	0xB0154

/* game_ext_plugin */
#define sfo_check_offset		0x2345C
#define ps2_nonbw_offset3		0x14314
#define ps_region_error_offset		0x1C64

/* psp_emulator */
#define psp_set_psp_mode_offset		0x1714	

/* emulator_api */
#define psp_read			0x8710
#define psp_read_header			0x9B88
#define psp_drm_patch5			0x993c
#define psp_drm_patch6			0x9994
#define psp_drm_patch7			0x99AC
#define psp_drm_patch8			0x99B0
#define psp_drm_patch9			0x9AE0
#define psp_drm_patch10			0x9B38
#define psp_drm_patch11			0x9B38
#define psp_drm_patch12			0x9B48
#define psp_product_id_patch1		0x9CE4
#define psp_product_id_patch2		0x9D14
#define psp_product_id_patch3		0xA0E8
#define psp_product_id_patch4		0xA118

/* pemucorelib */
#define psp_eboot_dec_patch		0x5FF8C
#define psp_prx_patch			0x5919C
#define psp_savedata_bind_patch1	0x7CEE0
#define psp_savedata_bind_patch2	0x7CF38
#define psp_savedata_bind_patch3	0x7CB04
#define psp_prometheus_patch		0x10df04
#define psp_debug_patch			0xAD880

/* emulator_drm */
#define psp_drm_tag_overwrite		0x4C24
#define psp_drm_key_overwrite		(0x17900-0x7F00)

/* libsysutil_savedata_psp */
#define psp_savedata_patch1		0x4548
#define psp_savedata_patch2		0x47A0
#define psp_savedata_patch3		0x47A8
#define psp_savedata_patch4		0x47C0
#define psp_savedata_patch5		0x47D4
#define psp_savedata_patch6		0x4800
#define psp_savedata_patch7		0x4818

/* libfs (external */
#define aio_copy_root_offset		0xD37C

#endif /* FIRMWARE */

/* 3.72 */
#define PSP_EMULATOR372_HASH		0x7be7b71500052f98
#define EMULATOR_API372_HASH		0xa9f5b27a00041dc8
#define PEMUCORELIB372_HASH		0xf349a5630019f080

/* psp_emulator */
#define psp372_set_psp_mode_offset   	0x1860

/* emulator_api */
#define psp372_read			0x13C2C
#define psp372_read_header		0x1509C
#define psp372_drm_patch5		0x14E8C
#define psp372_drm_patch6		0x14EC0
#define psp372_drm_patch7		0x14ED8
#define psp372_drm_patch8		0x14EDC
#define psp372_drm_patch9		0x1501C
#define psp372_drm_patch10		0x15050
#define psp372_drm_patch11		0x15050
#define psp372_drm_patch12		0x15060
#define psp372_product_id_patch1	0x151F8
#define psp372_product_id_patch2	0x15228
#define psp372_product_id_patch3	0x15614

/* pemucorelib */
#define psp372_eboot_dec_patch		0x5DAA4
#define psp372_prx_patch		0x56C84
#define psp372_extra_savedata_patch	0x8366C

/* 4.00 */
#define PSP_EMULATOR400_HASH		0x7be644e500053508
#define EMULATOR_API400_HASH		0xa9f5bb7a00043158
#define PEMUCORELIB400_HASH		0xf349a5630019ee00

/* psp_emulator */
#define psp400_set_psp_mode_offset	0x19EC

/* emulator_api */
#define psp400_read			0x13E18
#define psp400_read_header		0x15288
#define psp400_drm_patch5		0x15078
#define psp400_drm_patch6		0x150AC
#define psp400_drm_patch7		0x150C4
#define psp400_drm_patch8		0x150C8
#define psp400_drm_patch9		0x15208
#define psp400_drm_patch10		0x1523C
#define psp400_drm_patch11		0x1523C
#define psp400_drm_patch12		0x1524C
#define psp400_product_id_patch1	0x153E4
#define psp400_product_id_patch2	0x15414
#define psp400_product_id_patch3	0x15800 

/* pemucorelib */
#define psp400_eboot_dec_patch		0x5DFE8
#define psp400_prx_patch		0x571C8
#define psp400_savedata_bind_patch1	0x78334
#define psp400_savedata_bind_patch2	0x7838C
#define psp400_savedata_bind_patch3	0x77EE8
#define psp400_extra_savedata_patch	0x838BC
#define psp400_prometheus_patch		0x11E3DC

#define VSH_HASH_STEP_SIZE	65536

#define MAX_VSH_PLUGINS		1


LV2_EXPORT int decrypt_func(uint64_t *, uint32_t *);

typedef struct
{
	uint32_t offset;
	uint32_t data;
	uint8_t *condition;
} SprxPatch;

typedef struct
{
	uint64_t hash;
	SprxPatch *patch_table;
	int destroy;
} PatchTableEntry;

typedef struct
{
	uint8_t keys[16];
	uint64_t nonce;
	int protection_type;
	uint32_t vsh_dif_keys_address;
} KeySet;

#define N_SPRX_KEYS_1 (sizeof(sprx_keys_set1)/sizeof(KeySet))

ENCRYPTED_DATA KeySet sprx_keys_set1[] =
{
	{ 
		{ 
			0xD6^0x56, 0xFD^0x40, 0xD2^0x26, 0xB9^0xEC, 0x2C^0x57, 0xCC^0xA3, 0x04^0x79, 0xDD^0x57,
			0x77^0x74, 0x3C^0x93, 0x7C^0x7E, 0x96^0x59, 0x09^0x0B, 0x5D^0xEF, 0x7A^0xAD, 0x3B^0xD4
		}, 
		
		0xBA2624B2B2AA7461ULL, PROTECTED_PROCESS_MANAGER, 0x10004
	},
	
};

// Keyset for pspemu, and for future vsh plugins or whatever is added later

#define N_SPRX_KEYS_2 (sizeof(sprx_keys_set2)/sizeof(KeySet))

ENCRYPTED_DATA KeySet sprx_keys_set2[] =
{
	{
		{
			0x7A^0xD4, 0x9E^0x3F, 0x0F^0x87, 0x7C^0xBC, 0xE3^0xCF, 0xFB^0x01, 0x0C^0x05, 0x09^0xF9, 
			0x4D^0x01, 0xE9^0x49, 0x6A^0x78, 0xEB^0x5F, 0xA2^0x65, 0xBD^0x85, 0xF7^0x71, 0x7B^0xE7
		},
		
		0x8F8FEBA931AF6A19ULL, PROTECTED_PROCESS_PSPEMU, 0x10014
	},
	
	{
		{
			0xDB^0xCC, 0x54^0x96, 0x44^0x6C, 0xB3^0x7F, 0xC6^0x3B, 0x27^0x24, 0x82^0x95, 0xB6^0xBB, 
			0x64^0xBC, 0x36^0x70, 0x3E^0x17, 0xFF^0xAD, 0x58^0x8D, 0x20^0x70, 0xD9^0xFB, 0x83^0x45
		},
		
		0xE13E0D15EF55C307ULL, PROTECTED_PROCESS_VSH, 0x10024
	},
};

#ifdef PSN_SUPPORT

#define PSN_PASSPHRASE_CHECK_LEN	8	
#define PSN_PASSPHRASE_LEN		56

uint8_t psn_passphrase_check355[PSN_PASSPHRASE_CHECK_LEN] = "d81819ff";
uint8_t psn_passphrase410[PSN_PASSPHRASE_LEN] = "0e444f4dbd92145de39ab5bff3a23071f9d44db7bcf13e8c455c81f1";

#endif

static uint8_t *saved_buf;
static void *saved_sce_hdr;

uint32_t protected_process = 0;
ProcessProtection protected_process_type = PROTECTED_PROCESS_NONE;
process_t vsh_process;

static uint32_t caller_process = 0;
static int ignore = 0;
static ProcessProtection self_loaded_protection_type = PROTECTED_PROCESS_NONE;
static int vsh_loaded = 0;

static uint8_t condition_true = 1;
uint8_t condition_ps2softemu = 0;
uint8_t condition_apphome = 0;
uint8_t condition_disable_gameupdate = 0; // Disabled
uint8_t condition_psp_iso = 0;
uint8_t condition_psp_dec = 0;
uint8_t condition_psp_keys = 0;
uint8_t condition_psp_change_emu = 0;
uint8_t condition_psp_prometheus = 0;

// Plugins
sys_prx_id_t vsh_plugins[MAX_VSH_PLUGINS];
static int loading_vsh_plugin;

ENCRYPTED_DATA SprxPatch vsh_patches[] =
{
	// Dif Keys for manager
	{ 4, 0x564026EC, &condition_true }, 
	{ 8, 0x57A37957, &condition_true }, 
	{ 0xC, 0x74937E59, &condition_true }, 
	{ 0x10, 0x0BEFADD4, &condition_true }, 
	// Dif keys for psp emu
	{ 0x14, 0xD43F87BC, &condition_true },
	{ 0x18, 0xCF0105F9, &condition_true },
	{ 0x1C, 0x0149785F, &condition_true },
	{ 0x20, 0x658571E7, &condition_true },
	// Dif keys for vsh plugins
	{ 0x24, 0xCC966C7F, &condition_true },
	{ 0x28, 0x3B2495BB, &condition_true },
	{ 0x2C, 0xBC7017AD, &condition_true },
	{ 0x30, 0x8D70FB45, &condition_true },
	//
	{ elf1_func1 + elf1_func1_offset, LI(R3, 1), &condition_true },
	{ elf1_func1 + elf1_func1_offset + 4, BLR, &condition_true },
	{ elf1_func2 + elf1_func2_offset, NOP, &condition_true },
	{ game_update_offset, LI(R3, -1), &condition_disable_gameupdate }, 	
	{ psp_drm_patch1, LI(R3, 0), &condition_true },
	{ psp_drm_patch2, LI(R3, 0), &condition_true },
	{ psp_drm_patch3, LI(R3, 0), &condition_true },
	{ psp_drm_patch4, LI(R0, 0), &condition_true },
	{ psp_drm_patchA, LI(R0, 0), &condition_true },
	{ psp_drm_patchB, LI(R31, 0), &condition_true },
	{ psp_drm_patchC, LI(R3, 0), &condition_true },		
#ifdef PSN_SUPPORT
	// PSN spoof  to XX.YY -> R6 = XX, R7 = YY; Note: decimal
	{ psn_spoof_version_patch, LI(R6, 4), &condition_true },
	{ psn_spoof_version_patch+4, LI(R7, 11), &condition_true },
#endif
	{ 0 }
};

ENCRYPTED_DATA SprxPatch nas_plugin_patches[] =
{
	{ elf2_func1 + elf2_func1_offset, NOP, &condition_true },
	{ geohot_pkg_offset, LI(0, 0), &condition_true },
	{ 0 }
};

ENCRYPTED_DATA SprxPatch explore_plugin_patches[] =
{
#ifndef CFW
	{ elf3_data_offset, 0x5f746f6f, &condition_true },
	{ elf3_data_offset + 4, 0x6c322e78, &condition_true },
	{ elf3_data_offset + 8, 0x6d6c2372, &condition_true },
	{ elf3_data_offset + 12, 0x6f6f7400, &condition_true },
#else
	// category_game.xml -> categorygam2.xml
	{ elf3_data_offset-4, 0x67616d32, &condition_true },
#endif
	{ app_home_offset, 0x2f646576, &condition_apphome },
	{ app_home_offset+4, 0x5f626476, &condition_apphome },
	{ app_home_offset+8, 0x642f5053, &condition_apphome }, 
	{ ps2_nonbw_offset, LI(0, 1), &condition_ps2softemu },
	{ 0 }
};

ENCRYPTED_DATA SprxPatch explore_category_game_patches[] =
{
#ifndef CFW
	{ elf4_data_offset, 0x5f746f6f, &condition_true },
	{ elf4_data_offset + 4, 0x6c322e78, &condition_true },
	{ elf4_data_offset + 8, 0x6d6c2372, &condition_true },
	{ elf4_data_offset + 12, 0x6f6f7400, &condition_true },
#else
	{ elf4_data_offset-4, 0x67616d32, &condition_true },
#endif
	{ ps2_nonbw_offset2, LI(0, 1), &condition_ps2softemu },
	{ 0 }
};

ENCRYPTED_DATA SprxPatch bdp_disc_check_plugin_patches[] =
{
	{ dvd_video_region_check_offset, LI(3, 1), &condition_true }, /* Kills standard dvd-video region protection (not RCE one) */
	{ 0 }
};

ENCRYPTED_DATA SprxPatch ps1_emu_patches[] =
{
	{ ps1_emu_get_region_offset, LI(29, 0x82), &condition_true }, /* regions 0x80-0x82 bypass region check. */
	{ 0 }
};

ENCRYPTED_DATA SprxPatch ps1_netemu_patches[] =
{
	// Some rare titles such as Langrisser Final Edition are launched through ps1_netemu!
	{ ps1_netemu_get_region_offset, LI(3, 0x82), &condition_true }, 
	{ 0 }
};

ENCRYPTED_DATA SprxPatch game_ext_plugin_patches[] =
{
	{ sfo_check_offset, NOP, &condition_true }, 
	{ ps2_nonbw_offset3, LI(0, 1), &condition_ps2softemu },
	{ ps_region_error_offset, NOP, &condition_true }, /* Needed sometimes... */
	{ 0 }
};

ENCRYPTED_DATA SprxPatch psp_emulator_patches[] =
{
	// Sets psp mode as opossed to minis mode. Increases compatibility, removes text protection and makes most savedata work
	{ psp_set_psp_mode_offset, LI(R4, 0), &condition_psp_iso },
	{ 0 }
};

ENCRYPTED_DATA SprxPatch emulator_api_patches[] =
{
	// Read umd patches
	{ psp_read, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_read+4, MFLR(R0), &condition_psp_iso },
	{ psp_read+8, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_read+0x0C, MR(R8, R7), &condition_psp_iso },
	{ psp_read+0x10, MR(R7, R6), &condition_psp_iso },
	{ psp_read+0x14, MR(R6, R5), &condition_psp_iso },
	{ psp_read+0x18, MR(R5, R4), &condition_psp_iso },
	{ psp_read+0x1C, MR(R4, R3), &condition_psp_iso },
	{ psp_read+0x20, LI(R3, SYSCALL8_OPCODE_READ_PSP_UMD), &condition_psp_iso },	
	{ psp_read+0x24, LI(R11, 8), &condition_psp_iso },
	{ psp_read+0x28, SC, &condition_psp_iso },
	{ psp_read+0x2C, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_read+0x30, MTLR(R0), &condition_psp_iso },
	{ psp_read+0x34, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_read+0x38, BLR, &condition_psp_iso },
	// Read header patches
	{ psp_read+0x3C, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_read+0x40, MFLR(R0), &condition_psp_iso },
	{ psp_read+0x44, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_read+0x48, MR(R7, R6), &condition_psp_iso },
	{ psp_read+0x4C, MR(R6, R5), &condition_psp_iso },
	{ psp_read+0x50, MR(R5, R4), &condition_psp_iso },
	{ psp_read+0x54, MR(R4, R3), &condition_psp_iso },
	{ psp_read+0x58, LI(R3, SYSCALL8_OPCODE_READ_PSP_HEADER), &condition_psp_iso },	
	{ psp_read+0x5C, LI(R11, 8), &condition_psp_iso },
	{ psp_read+0x60, SC, &condition_psp_iso },
	{ psp_read+0x64, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_read+0x68, MTLR(R0), &condition_psp_iso },
	{ psp_read+0x6C, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_read+0x70, BLR, &condition_psp_iso },
	{ psp_read_header, MAKE_CALL_VALUE(psp_read_header, psp_read+0x3C), &condition_psp_iso },
	// Drm patches
	{ psp_drm_patch5, MAKE_JUMP_VALUE(psp_drm_patch5, psp_drm_patch6), &condition_psp_iso },
	{ psp_drm_patch7, LI(R6, 0), &condition_psp_iso },
	{ psp_drm_patch8, LI(R7, 0), &condition_psp_iso },
	{ psp_drm_patch9, MAKE_JUMP_VALUE(psp_drm_patch9, psp_drm_patch10), &condition_psp_iso },
	{ psp_drm_patch11, LI(R6, 0), &condition_psp_iso },
	{ psp_drm_patch12, LI(R7, 0), &condition_psp_iso },
	// product id
	{ psp_product_id_patch1, MAKE_JUMP_VALUE(psp_product_id_patch1, psp_product_id_patch2), &condition_psp_iso },
	{ psp_product_id_patch3, MAKE_JUMP_VALUE(psp_product_id_patch3, psp_product_id_patch4), &condition_psp_iso },	
	{ 0 }
};

ENCRYPTED_DATA SprxPatch pemucorelib_patches[] =
{
	{ psp_eboot_dec_patch, LI(R6, 0x110), &condition_psp_dec }, // -> makes unsigned psp eboot.bin run, 0x10 works too
	{ psp_prx_patch, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_prx_patch+4, MFLR(R6), &condition_psp_iso },
	{ psp_prx_patch+8, STD(R6, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x0C, LI(R11, 8), &condition_psp_iso },
	{ psp_prx_patch+0x10, MR(R5, R4), &condition_psp_iso },
	{ psp_prx_patch+0x14, MR(R4, R3), &condition_psp_iso },
	{ psp_prx_patch+0x18, LI(R3, SYSCALL8_OPCODE_PSP_PRX_PATCH), &condition_psp_iso },
	{ psp_prx_patch+0x1C, SC, &condition_psp_iso },
	{ psp_prx_patch+0x20, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x24, MTLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x28, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_prx_patch+0x2C, BLR, &condition_psp_iso },	
	// Patch for savedata binding
	{ psp_savedata_bind_patch1, MR(R5, R19), &condition_psp_iso },
	{ psp_savedata_bind_patch2, MAKE_JUMP_VALUE(psp_savedata_bind_patch2, psp_prx_patch+0x30), &condition_psp_iso },
	{ psp_prx_patch+0x30, LD(R19, 0xFF98, SP), &condition_psp_iso },
	{ psp_prx_patch+0x34, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_prx_patch+0x38, MFLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x3C, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x40, LI(R11, 8), &condition_psp_iso },
	{ psp_prx_patch+0x44, MR(R4, R3), &condition_psp_iso },
	{ psp_prx_patch+0x48, LI(R3, SYSCALL8_OPCODE_PSP_POST_SAVEDATA_INITSTART), &condition_psp_iso },
	{ psp_prx_patch+0x4C, SC, &condition_psp_iso },
	{ psp_prx_patch+0x50, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x54, MTLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x58, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_prx_patch+0x5C, BLR, &condition_psp_iso },
	{ psp_savedata_bind_patch3, MAKE_JUMP_VALUE(psp_savedata_bind_patch3, psp_prx_patch+0x60), &condition_psp_iso },
	{ psp_prx_patch+0x60, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_prx_patch+0x64, MFLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x68, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x6C, LI(R11, 8), &condition_psp_iso },
	{ psp_prx_patch+0x70, LI(R3, SYSCALL8_OPCODE_PSP_POST_SAVEDATA_SHUTDOWNSTART), &condition_psp_iso },
	{ psp_prx_patch+0x74, SC, &condition_psp_iso },
	{ psp_prx_patch+0x78, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x7C, MTLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x80, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_prx_patch+0x84, BLR, &condition_psp_iso },
	// Prometheus
	{ psp_prometheus_patch, '.OLD', &condition_psp_prometheus },
#ifdef DEBUG
	{ psp_debug_patch, LI(R3, SYSCALL8_OPCODE_PSP_SONY_BUG), &condition_psp_iso },
	{ psp_debug_patch+4, LI(R11, 8), &condition_psp_iso },
	{ psp_debug_patch+8, SC, &condition_psp_iso },
#endif	
	{ 0 }
};

/*ENCRYPTED_DATA SprxPatch psp_emulator372_patches[] =
{
	// Sets psp mode as opossed to minis mode. Increases compatibility, removes text protection and makes most savedata work
	{ psp372_set_psp_mode_offset, LI(R4, 0), &condition_psp_iso },
	{ 0 }
};

ENCRYPTED_DATA SprxPatch emulator_api372_patches[] =
{
	// Read umd patches
	{ psp372_read, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp372_read+4, MFLR(R0), &condition_psp_iso },
	{ psp372_read+8, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp372_read+0x0C, MR(R8, R7), &condition_psp_iso },
	{ psp372_read+0x10, MR(R7, R6), &condition_psp_iso },
	{ psp372_read+0x14, MR(R6, R5), &condition_psp_iso },
	{ psp372_read+0x18, MR(R5, R4), &condition_psp_iso },
	{ psp372_read+0x1C, MR(R4, R3), &condition_psp_iso },
	{ psp372_read+0x20, LI(R3, SYSCALL8_OPCODE_READ_PSP_UMD), &condition_psp_iso },	
	{ psp372_read+0x24, LI(R11, 8), &condition_psp_iso },
	{ psp372_read+0x28, SC, &condition_psp_iso },
	{ psp372_read+0x2C, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp372_read+0x30, MTLR(R0), &condition_psp_iso },
	{ psp372_read+0x34, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp372_read+0x38, BLR, &condition_psp_iso },
	// Read header patches
	{ psp372_read+0x3C, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp372_read+0x40, MFLR(R0), &condition_psp_iso },
	{ psp372_read+0x44, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp372_read+0x48, MR(R7, R6), &condition_psp_iso },
	{ psp372_read+0x4C, MR(R6, R5), &condition_psp_iso },
	{ psp372_read+0x50, MR(R5, R4), &condition_psp_iso },
	{ psp372_read+0x54, MR(R4, R3), &condition_psp_iso },
	{ psp372_read+0x58, LI(R3, SYSCALL8_OPCODE_READ_PSP_HEADER), &condition_psp_iso },	
	{ psp372_read+0x5C, LI(R11, 8), &condition_psp_iso },
	{ psp372_read+0x60, SC, &condition_psp_iso },
	{ psp372_read+0x64, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp372_read+0x68, MTLR(R0), &condition_psp_iso },
	{ psp372_read+0x6C, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp372_read+0x70, BLR, &condition_psp_iso },
	{ psp372_read_header, MAKE_CALL_VALUE(psp372_read_header, psp372_read+0x3C), &condition_psp_iso },
	// Drm patches
	{ psp372_drm_patch5, MAKE_JUMP_VALUE(psp372_drm_patch5, psp372_drm_patch6), &condition_psp_iso },
	{ psp372_drm_patch7, LI(R6, 0), &condition_psp_iso },
	{ psp372_drm_patch8, LI(R7, 0), &condition_psp_iso },
	{ psp372_drm_patch9, MAKE_JUMP_VALUE(psp372_drm_patch9, psp372_drm_patch10), &condition_psp_iso },
	{ psp372_drm_patch11, LI(R6, 0), &condition_psp_iso },
	{ psp372_drm_patch12, LI(R7, 0), &condition_psp_iso },
	// product id
	{ psp372_product_id_patch1, MAKE_JUMP_VALUE(psp372_product_id_patch1, psp372_product_id_patch2), &condition_psp_iso },
	{ psp372_product_id_patch3, NOP, &condition_psp_iso },
	{ 0 }
};

ENCRYPTED_DATA SprxPatch pemucorelib372_patches[] =
{
	{ psp372_eboot_dec_patch, LI(6, 0x110), &condition_psp_dec }, // -> makes unsigned psp eboot.bin run, 0x10 works too
	{ psp372_prx_patch, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp372_prx_patch+4, MFLR(R6), &condition_psp_iso },
	{ psp372_prx_patch+8, STD(R6, 0x80, SP), &condition_psp_iso },
	{ psp372_prx_patch+0x0C, LI(R11, 8), &condition_psp_iso },
	{ psp372_prx_patch+0x10, MR(R5, R4), &condition_psp_iso },
	{ psp372_prx_patch+0x14, MR(R4, R3), &condition_psp_iso },
	{ psp372_prx_patch+0x18, LI(R3, SYSCALL8_OPCODE_PSP_PRX_PATCH), &condition_psp_iso },
	{ psp372_prx_patch+0x1C, SC, &condition_psp_iso },
	{ psp372_prx_patch+0x20, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp372_prx_patch+0x24, MTLR(R0), &condition_psp_iso },
	{ psp372_prx_patch+0x28, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp372_prx_patch+0x2C, BLR, &condition_psp_iso },	
	// Extra save data patch required since some 3.60+ firmware
	{ psp372_extra_savedata_patch, LI(R31, 1), &condition_psp_iso },	
	{ 0 }
};*/

ENCRYPTED_DATA SprxPatch psp_emulator400_patches[] =
{
	// Sets psp mode as opossed to minis mode. Increases compatibility, removes text protection and makes most savedata work
	{ psp400_set_psp_mode_offset, LI(R4, 0), &condition_psp_iso },
	{ 0 }
};

ENCRYPTED_DATA SprxPatch emulator_api400_patches[] =
{
	// Read umd patches
	{ psp400_read, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp400_read+4, MFLR(R0), &condition_psp_iso },
	{ psp400_read+8, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp400_read+0x0C, MR(R8, R7), &condition_psp_iso },
	{ psp400_read+0x10, MR(R7, R6), &condition_psp_iso },
	{ psp400_read+0x14, MR(R6, R5), &condition_psp_iso },
	{ psp400_read+0x18, MR(R5, R4), &condition_psp_iso },
	{ psp400_read+0x1C, MR(R4, R3), &condition_psp_iso },
	{ psp400_read+0x20, LI(R3, SYSCALL8_OPCODE_READ_PSP_UMD), &condition_psp_iso },	
	{ psp400_read+0x24, LI(R11, 8), &condition_psp_iso },
	{ psp400_read+0x28, SC, &condition_psp_iso },
	{ psp400_read+0x2C, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp400_read+0x30, MTLR(R0), &condition_psp_iso },
	{ psp400_read+0x34, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp400_read+0x38, BLR, &condition_psp_iso },
	// Read header patches
	{ psp400_read+0x3C, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp400_read+0x40, MFLR(R0), &condition_psp_iso },
	{ psp400_read+0x44, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp400_read+0x48, MR(R7, R6), &condition_psp_iso },
	{ psp400_read+0x4C, MR(R6, R5), &condition_psp_iso },
	{ psp400_read+0x50, MR(R5, R4), &condition_psp_iso },
	{ psp400_read+0x54, MR(R4, R3), &condition_psp_iso },
	{ psp400_read+0x58, LI(R3, SYSCALL8_OPCODE_READ_PSP_HEADER), &condition_psp_iso },	
	{ psp400_read+0x5C, LI(R11, 8), &condition_psp_iso },
	{ psp400_read+0x60, SC, &condition_psp_iso },
	{ psp400_read+0x64, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp400_read+0x68, MTLR(R0), &condition_psp_iso },
	{ psp400_read+0x6C, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp400_read+0x70, BLR, &condition_psp_iso },
	{ psp400_read_header, MAKE_CALL_VALUE(psp400_read_header, psp400_read+0x3C), &condition_psp_iso },
	// Drm patches
	{ psp400_drm_patch5, MAKE_JUMP_VALUE(psp400_drm_patch5, psp400_drm_patch6), &condition_psp_iso },
	{ psp400_drm_patch7, LI(R6, 0), &condition_psp_iso },
	{ psp400_drm_patch8, LI(R7, 0), &condition_psp_iso },
	{ psp400_drm_patch9, MAKE_JUMP_VALUE(psp400_drm_patch9, psp400_drm_patch10), &condition_psp_iso },
	{ psp400_drm_patch11, LI(R6, 0), &condition_psp_iso },
	{ psp400_drm_patch12, LI(R7, 0), &condition_psp_iso },
	// product id
	{ psp400_product_id_patch1, MAKE_JUMP_VALUE(psp400_product_id_patch1, psp400_product_id_patch2), &condition_psp_iso },
	{ psp400_product_id_patch3, NOP, &condition_psp_iso },	
	{ 0 }
};

ENCRYPTED_DATA SprxPatch pemucorelib400_patches[] =
{
	{ psp400_eboot_dec_patch, LI(R6, 0x110), &condition_psp_dec }, // -> makes unsigned psp eboot.bin run, 0x10 works too
	{ psp400_prx_patch, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp400_prx_patch+4, MFLR(R6), &condition_psp_iso },
	{ psp400_prx_patch+8, STD(R6, 0x80, SP), &condition_psp_iso },
	{ psp400_prx_patch+0x0C, LI(R11, 8), &condition_psp_iso },
	{ psp400_prx_patch+0x10, MR(R5, R4), &condition_psp_iso },
	{ psp400_prx_patch+0x14, MR(R4, R3), &condition_psp_iso },
	{ psp400_prx_patch+0x18, LI(R3, SYSCALL8_OPCODE_PSP_PRX_PATCH), &condition_psp_iso },
	{ psp400_prx_patch+0x1C, SC, &condition_psp_iso },
	{ psp400_prx_patch+0x20, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp400_prx_patch+0x24, MTLR(R0), &condition_psp_iso },
	{ psp400_prx_patch+0x28, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp400_prx_patch+0x2C, BLR, &condition_psp_iso },	
	// Patch for savedata binding
	{ psp400_savedata_bind_patch1, MR(R5, R19), &condition_psp_iso },
	{ psp400_savedata_bind_patch2, MAKE_JUMP_VALUE(psp400_savedata_bind_patch2, psp400_prx_patch+0x30), &condition_psp_iso },
	{ psp400_prx_patch+0x30, LD(R19, 0xFF98, SP), &condition_psp_iso },
	{ psp400_prx_patch+0x34, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp400_prx_patch+0x38, MFLR(R0), &condition_psp_iso },
	{ psp400_prx_patch+0x3C, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp400_prx_patch+0x40, LI(R11, 8), &condition_psp_iso },
	{ psp400_prx_patch+0x44, MR(R4, R3), &condition_psp_iso },
	{ psp400_prx_patch+0x48, LI(R3, SYSCALL8_OPCODE_PSP_POST_SAVEDATA_INITSTART), &condition_psp_iso },
	{ psp400_prx_patch+0x4C, SC, &condition_psp_iso },
	{ psp400_prx_patch+0x50, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp400_prx_patch+0x54, MTLR(R0), &condition_psp_iso },
	{ psp400_prx_patch+0x58, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp400_prx_patch+0x5C, BLR, &condition_psp_iso },
	{ psp400_savedata_bind_patch3, MAKE_JUMP_VALUE(psp400_savedata_bind_patch3, psp400_prx_patch+0x60), &condition_psp_iso },
	{ psp400_prx_patch+0x60, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp400_prx_patch+0x64, MFLR(R0), &condition_psp_iso },
	{ psp400_prx_patch+0x68, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp400_prx_patch+0x6C, LI(R11, 8), &condition_psp_iso },
	{ psp400_prx_patch+0x70, LI(R3, SYSCALL8_OPCODE_PSP_POST_SAVEDATA_SHUTDOWNSTART), &condition_psp_iso },
	{ psp400_prx_patch+0x74, SC, &condition_psp_iso },
	{ psp400_prx_patch+0x78, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp400_prx_patch+0x7C, MTLR(R0), &condition_psp_iso },
	{ psp400_prx_patch+0x80, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp400_prx_patch+0x84, BLR, &condition_psp_iso },
	// Extra save data patch required since some 3.60+ firmware
	{ psp400_extra_savedata_patch, LI(R31, 1), &condition_psp_iso },
	// Prometheus
	{ psp400_prometheus_patch, '.OLD', &condition_psp_prometheus },
	{ 0 }
};

ENCRYPTED_DATA SprxPatch libsysutil_savedata_psp_patches[] =
{	
	{ psp_savedata_patch1, MAKE_JUMP_VALUE(psp_savedata_patch1, psp_savedata_patch2), &condition_psp_iso },
	{ psp_savedata_patch3, NOP, &condition_psp_iso },
	{ psp_savedata_patch4, NOP, &condition_psp_iso },
	{ psp_savedata_patch5, NOP, &condition_psp_iso },
	{ psp_savedata_patch6, NOP, &condition_psp_iso },
	{ psp_savedata_patch7, NOP, &condition_psp_iso },	
	{ 0 }
};

ENCRYPTED_DATA SprxPatch libfs_external_patches[] =
{
	// Redirect internal libfs function to kernel. If condition_apphome is 1, it means there is a JB game mounted
	{ aio_copy_root_offset, STDU(SP, 0xFF90, SP), &condition_apphome },
	{ aio_copy_root_offset+4, MFLR(R0), &condition_apphome },
	{ aio_copy_root_offset+8, STD(R0, 0x80, SP), &condition_apphome },
	{ aio_copy_root_offset+0x0C, MR(R5, R4), &condition_apphome },
	{ aio_copy_root_offset+0x10, MR(R4, R3), &condition_apphome },
	{ aio_copy_root_offset+0x14, LI(R3, SYSCALL8_OPCODE_AIO_COPY_ROOT), &condition_apphome },
	{ aio_copy_root_offset+0x18, LI(R11, 8), &condition_apphome },
	{ aio_copy_root_offset+0x1C, SC, &condition_apphome },
	{ aio_copy_root_offset+0x20, LD(R0, 0x80, SP), &condition_apphome },
	{ aio_copy_root_offset+0x24, MTLR(R0), &condition_apphome },
	{ aio_copy_root_offset+0x28, ADDI(SP, SP, 0x70), &condition_apphome },
	{ aio_copy_root_offset+0x2C, BLR, &condition_apphome },
	{ 0 }
};

ENCRYPTED_DATA PatchTableEntry patch_table[] =
{
	{ VSH_HASH, vsh_patches, 1 },
	{ VSH_REACTPSN_HASH, vsh_patches, 1 },
	{ NAS_PLUGIN_HASH, nas_plugin_patches, 0 },
	{ EXPLORE_PLUGIN_HASH, explore_plugin_patches, 0 },
	{ EXPLORE_CATEGORY_GAME_HASH, explore_category_game_patches, 0 },	
	{ BDP_DISC_CHECK_PLUGIN_HASH, bdp_disc_check_plugin_patches, 0 },
	{ PS1_EMU_HASH, ps1_emu_patches, 0 },
	{ PS1_NETEMU_HASH, ps1_netemu_patches, 0 },
	{ GAME_EXT_PLUGIN_HASH, game_ext_plugin_patches, 0 },
	{ PSP_EMULATOR_HASH, psp_emulator_patches, 0 },
	{ EMULATOR_API_HASH, emulator_api_patches, 0 },
	{ PEMUCORELIB_HASH, pemucorelib_patches, 0 },
	{ PSP_EMULATOR400_HASH, psp_emulator400_patches, 0 },
	{ EMULATOR_API400_HASH, emulator_api400_patches, 0 },
	{ PEMUCORELIB400_HASH, pemucorelib400_patches, 0 },
	{ LIBSYSUTIL_SAVEDATA_PSP_HASH, libsysutil_savedata_psp_patches, 0 },
	{ LIBFS_EXTERNAL_HASH, libfs_external_patches }, 
};

#define N_PATCH_TABLE_ENTRIES	(sizeof(patch_table) / sizeof(PatchTableEntry))

LV2_HOOKED_FUNCTION_PRECALL_2(int, post_lv1_call_99_wrapper, (uint64_t *spu_obj, uint64_t *spu_args))
{
	// This replaces an original patch of psjailbreak, since we need to do more things
	process_t process = get_current_process();
	
	saved_buf = (void *)spu_args[0x20/8];
	saved_sce_hdr = (void *)spu_args[8/8];
	
	if (process)
	{
		caller_process = process->pid;
		//DPRINTF("caller_process = %08X\n", caller_process);
	}
	
	return 0;
}

ENCRYPTED_SUICIDAL_FUNCTION(void, do_dynamic_vsh_patches, (void *buf))
{
	uint8_t *buf8 = (uint8_t *)buf;
	uint32_t *buf32 = (uint32_t *)buf;
	
	//config.spoof_version = 0x0411;
	//config.spoof_revision = 55054;
	
	if (config.spoof_version && config.spoof_revision)
	{
		char rv[MAX_SPOOF_REVISION_CHARS+1];
			
		int n = snprintf(rv, sizeof(rv), "%05d", config.spoof_revision);
		if (n < sizeof(rv))
		{
			DPRINTF("Patching to revision %d\n", config.spoof_revision);
			memcpy(buf8+revision_offset, rv, n);
		}
		else
		{
			//DPRINTF("n = %d\n", n);
		}
			
		buf32[(spoof_version_patch+0)/4] = MR(R4, R27);
		buf32[(spoof_version_patch+4)/4] = LI(R11, 8);
		buf32[(spoof_version_patch+8)/4] = LI(R3, SYSCALL8_OPCODE_VSH_SPOOF_VERSION);
		buf32[(spoof_version_patch+12)/4] = SC;		
	}
}

ENCRYPTED_PATCHED_FUNCTION(int, modules_patching, (uint64_t *arg1, uint32_t *arg2))
{
	static unsigned int total = 0;
	static uint32_t *buf;
	static uint8_t keys[16];
	static uint64_t nonce = 0;
	
	SELF *self;
	uint64_t *ptr;
	uint32_t *ptr32;
	uint8_t *sce_hdr;
				
	ptr = (uint64_t *)(*(uint64_t *)MKA(TOC+decrypt_rtoc_entry_2));  
	ptr = (uint64_t *)ptr[0x68/8];
	ptr = (uint64_t *)ptr[0x18/8];
	ptr32 = (uint32_t *)ptr;
	sce_hdr = (uint8_t *)saved_sce_hdr; 
	self = (SELF *)sce_hdr;
	
	self_loaded_protection_type = PROTECTED_PROCESS_NONE;
		
	uint32_t *p = (uint32_t *)arg1[0x18/8];
	if ((p[0x30/4] >> 16) == 0x29)
	{
		int last_chunk = 0;
		KeySet *keySet = NULL;
		
		if (((ptr[0x10/8] << 24) >> 56) == 0xFF)
		{
			ptr[0x10/8] |= 2;
			*arg2 = 0x2C;
			last_chunk = 1;
		}
		else
		{
			ptr[0x10/8] |= 3;
			*arg2 = 6;
		}
		
		uint8_t *enc_buf = (uint8_t *)ptr[8/8];
		uint32_t chunk_size = ptr32[4/4];
		SPRX_EXT_HEADER *extHdr = (SPRX_EXT_HEADER *)(sce_hdr+self->metadata_offset+0x20);
		uint64_t magic = extHdr->magic&SPRX_EXT_MAGIC_MASK;
		uint8_t keyIndex = extHdr->magic&0xFF;
		ProcessProtection protection_type = PROTECTED_PROCESS_NONE;
		int dongle_decrypt = 0;
		
		if (magic == SPRX_EXT_MAGIC)
		{
			if (keyIndex >= N_SPRX_KEYS_1)
			{
				DPRINTF("This key is not implemented yet: %lx:%x\n", magic, keyIndex);
			}
			else
			{
				keySet = &sprx_keys_set1[keyIndex];
			}
			
		}
		else if (magic == SPRX_EXT_MAGIC2)
		{
			if (keyIndex >= N_SPRX_KEYS_2)
			{
				DPRINTF("This key is not implemented yet: %lx:%x\n", magic, keyIndex);
			}
			else
			{
				keySet = &sprx_keys_set2[keyIndex];
			}
		}
		
		if (keySet)
		{
			encrypted_data_toggle(keySet, sizeof(KeySet));
			
			if (total == 0)
			{
				uint8_t dif_keys[16];
				
				if (keySet->vsh_dif_keys_address)				
					copy_from_process(vsh_process, (void *)(uint64_t)keySet->vsh_dif_keys_address, dif_keys, 16);
				else
					memset(dif_keys, 0, 16);
				
				if (dongle_decrypt)	
				{
				}
				else
				{
					memcpy(keys, extHdr->keys_mod, 16);
				}
				
				for (int i = 0; i < 16; i++)
				{
					keys[i] ^= (keySet->keys[15-i] ^ dif_keys[15-i]);
				}
				
				nonce = keySet->nonce ^ extHdr->nonce_mod;		
			}
			
			protection_type = keySet->protection_type;
			encrypted_data_toggle(keySet, sizeof(KeySet));
			
			uint32_t num_blocks = chunk_size / 8;
			
			xtea_ctr(keys, nonce, enc_buf, num_blocks*8);		
			nonce += num_blocks;	
			
			if (last_chunk)
			{
				get_pseudo_random_number(keys, sizeof(keys));
				nonce = 0;
			}
		}
		
		memcpy(saved_buf, (void *)ptr[8/8], ptr32[4/4]);
		
		if (total == 0)
		{
			buf = (uint32_t *)saved_buf;			
		}
		
		if (last_chunk)
		{
			//DPRINTF("Total section size: %x\n", total+ptr32[4/4]);
			
			ELF *elf = (ELF *)(sce_hdr+self->elf_offset);
			// At the moment let's apply the process protection to ppc only, as we are only hooking ppc load module, and changing this is not trivial
			if (elf->magic == ELF_MAGIC && elf->machine == 0x15) 
			{
				if (keySet) /* if encrypted */
				{
					if (elf->type == 0xFFA4) /* is sprx */
					{
						if (caller_process != protected_process)
						{
							if (caller_process != vsh_process->pid)
							{
								if (protection_type != PROTECTED_PROCESS_VSH || !loading_vsh_plugin)
								{									
									DPRINTF("Cobra security panic: unprotected process %08X is trying to load an encrypted sprx\n", caller_process);
									while(1);
								}								
							}
						}
						else
						{
							if (protection_type != protected_process_type)
							{
								if (protection_type != PROTECTED_PROCESS_VSH || !loading_vsh_plugin)
								{
									DPRINTF("Cobra security panic: protected process %08X is trying yo load an encrypted sprx of other type (%x %x)\n", caller_process, protection_type, protected_process_type);
									while (1);
								}
							}
						}
					}
					else
					{
						// Then, it is a self, a new process
						// WARNING: if support for spu self is added, this part would need change!
						self_loaded_protection_type = protection_type;						
					}
				}
				else
				{
					if (!ignore && (caller_process == protected_process || caller_process == vsh_process->pid) && elf->type == 0xFFA4)
					{
						DPRINTF("Cobra security panic: protected process %08X is trying to load a decrypted sprx\n", caller_process);
						while (1);
					}
				}
			}
		}
		
		saved_buf += ptr32[4/4];		
	}
	else
	{
		decrypt_func(arg1, arg2);
		buf = (uint32_t *)saved_buf;
	}
	
	total += ptr32[4/4];
		
	if (((ptr[0x10/8] << 24) >> 56) == 0xFF)
	{
		uint64_t hash = 0;
					
		for (int i = 0; i < 0x100; i++)
		{
			hash ^= buf[i];			
		}
			
		hash = (hash << 32) | total;
		total = 0;
		//DPRINTF("hash = %lx\n", hash);
		
		if (condition_psp_keys)
		{		
			if (hash == EMULATOR_DRM_HASH)
			{
				buf[psp_drm_tag_overwrite/4] = LI(R5, psp_code);			
			}
			else if (hash == EMULATOR_DRM_DATA_HASH)
			{
				buf[psp_drm_key_overwrite/4] = psp_tag;
				memcpy(buf+((psp_drm_key_overwrite+8)/4), psp_keys, 16);
			}
		}
		
		if (condition_psp_change_emu)
		{
			if (hash == BASIC_PLUGINS_HASH)
			{
				memcpy(((char *)buf)+pspemu_path_offset, pspemu_path, sizeof(pspemu_path));
				memcpy(((char *)buf)+psptrans_path_offset, psptrans_path, sizeof(psptrans_path));				
			}
		}
		
		if (hash == VSH_HASH || hash == VSH_REACTPSN_HASH)
		{
			// MD5 will be checked after process creation, as we need a more secure algorithm
			/*if (hash == VSH_REACTPSN_HASH)
			{
				DPRINTF("React psn!\n");
			}*/
			do_dynamic_vsh_patches((buf));			
			vsh_loaded = 1;
		}
		
		encrypted_data_toggle(patch_table, sizeof(patch_table));
		encrypted_data_realloc_ptr(patch_table, sizeof(patch_table));
			
		for (int i = 0; i < N_PATCH_TABLE_ENTRIES; i++)
		{
			if (patch_table[i].hash == hash)
			{
				//DPRINTF("Now patching %lx\n", hash);
					
				int j = 0;
				SprxPatch *patch_c = &patch_table[i].patch_table[j];
				SprxPatch patch;
					
				encrypted_data_copy(patch_c, &patch, sizeof(SprxPatch));
				encrypted_data_realloc_ptr(&patch, sizeof(SprxPatch));
					
				while (patch.offset != 0)
				{
					if (*patch.condition)
					{
						buf[patch.offset/4] = patch.data;							
					}
					
					if (patch_table[i].destroy)
					{
						encrypted_data_destroy(patch_c, sizeof(SprxPatch));
					}
					
					j++;
					patch_c = &patch_table[i].patch_table[j];
					encrypted_data_copy(patch_c, &patch, sizeof(SprxPatch));
					encrypted_data_realloc_ptr(&patch, sizeof(SprxPatch));
				}
				
				if (patch_table[i].destroy)
					patch_table[i].destroy = 0;
					
				break;
			}
		}
			
		encrypted_data_toggle(patch_table, sizeof(patch_table));
	}
	
	return 0;
}

ENCRYPT_PATCHED_FUNCTION(modules_patching);

ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_2(int, pre_modules_verification, (uint32_t *ret, uint32_t error))
{
	/* Patch original from psjailbreak. Needs some tweaks to fix some games */	
	if (error == 0x13)
		return DO_POSTCALL; /* Fixes Mortal Kombat */
		
	*ret = 0;
	return 0;
}

ENCRYPT_PATCHED_FUNCTION(pre_modules_verification);

void pre_set_pte(void *unk, void *unk2, uint64_t ea, uint64_t lpar, uint32_t prot, uint64_t page_shift);

ENCRYPTED_SUICIDAL_FUNCTION(void, unhook_and_clear, (void))
{
	suspend_intr();
	unhook_function_with_postcall(set_pte_symbol, pre_set_pte, 6);	
	resume_intr();
	memset((void *)MKA(0x7f0000), 0, 0x10000);
}

LV2_HOOKED_FUNCTION_POSTCALL_6(void, pre_set_pte, (void *unk, void *unk2, uint64_t ea, uint64_t lpar, uint32_t prot, uint64_t page_shift))
{
	// We need to patch the text addr of vsh.self to make it writable
	process_t process = get_current_process();
	
	if (prot == 0x13 && process && strcmp(get_process_name(process)+8, "_main_sys_init_osd.") == 0) // vsh.self is loaded by sys_init_osd
	{
		prot &= ~3; // Remove PP
		prot |= 2; // Add new PP
		set_patched_func_param(5, prot);
		
		//dump_stack_trace2(16);
		
		if (ea == 0x6b0000)
		{
			unhook_and_clear();
		}
	}	
	//DPRINTF("%lx ea=%lx lpar=%lx shift=%lx\n", *(uint64_t *)unk2, ea, lpar, page_shift);
}

LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_8(int, load_process_hooked, (process_t process, int fd, char *path, int r6, uint64_t r7, uint64_t r8, uint64_t r9, uint64_t r10, uint64_t sp_70))
{
	DPRINTF("PROCESS %s (%08X) loaded\n", path, process->pid);
		
	if (self_loaded_protection_type != PROTECTED_PROCESS_NONE)
	{
		DPRINTF("Process %08X is now the cobra protected process (type: %x).\n", process->pid, self_loaded_protection_type);
		protected_process = process->pid;
		protected_process_type = self_loaded_protection_type;
	}
	else if (process->pid == protected_process)
	{
		
		DPRINTF("Unprotected new process has same pid as old protected process, removing protection\n");
		protected_process = 0;
	}
	else if (!vsh_process && vsh_loaded)
	{
		MD5Context ctx;
		void *buf;
		uint8_t md5[16];
		
		page_allocate_auto(NULL, 65536, 0x35, &buf);
		md5_reset(&ctx);
		
		for (uint64_t i = 0; i < spoof_version_patch; i += 65536)
		{
			uint64_t size = 65536;
			
			if ((i+size) > spoof_version_patch)
			{
				size = spoof_version_patch - i;
			}
			
			//DPRINTF("%lx %lx\n", i, size);
			
			copy_from_process(process, (void *)0x10000+i, buf, size);
			md5_update(&ctx, buf, size);			
		}
		
		for (uint64_t i = spoof_version_patch+0x10; i < revision_offset; i += 65536)
		{
			uint64_t size = 65536;
			
			if ((i+size) > revision_offset)
			{
				size = revision_offset - i;
			}
			
			//DPRINTF("%lx %lx\n", i, size);
			
			copy_from_process(process, (void *)0x10000+i, buf, size);
			md5_update(&ctx, buf, size);			
		}
		
		for (uint64_t i = revision_offset+8; i < VSH_HASH_SIZE; i += 65536)
		{
			uint64_t size = 65536;
			
			if ((i+size) > VSH_HASH_SIZE)
			{
				size = VSH_HASH_SIZE-i;
			}
			
			//DPRINTF("%lx %lx\n", i, size);
			
			copy_from_process(process, (void *)0x10000+i, buf, size);
			md5_update(&ctx, buf, size);			
		}
		
		md5_final(md5, &ctx);
		page_free(NULL, buf, 0x35);
		
#ifndef PSN_SUPPORT
		//TODO remove ifdef if psn supported is really added!
		
		// WARNING: md5 needs update each time vsh patches are added!
		if (memcmp(md5, vsh_md5, 16) != 0 && memcmp(md5, vsh_reactpsn_md5, 16) != 0)
		{
			DPRINTF("Cobra security panic: invalid vsh.self hash:\n");
			DPRINT_HEX(md5, 16);
			while (1);
		}
#endif
		
		vsh_process = process;
	}
	
	return 0;
}

// WARNING: even if this function seems to be protected by a internal lv2 mutex, modules_patching can be running at the same time that this function
// DO NOT USE any global vars, except protected_process and protected_process_type, that only change on ppu self load.
ENCRYPTED_FUNCTION(void, check_sprx, (int fd, process_t process))
{
	uint64_t orig_pos, pos, read;
	uint8_t *buf;
	SELF *self;
	
	ignore = 0;
	
	if (!process || (vsh_process != process && process->pid != protected_process))
	{
		return;
	}
	
	if (get_call_address(3) != (void *)MKA(load_module_by_fd_call1))
	{
		// At the moment, we are ignoring sprx loaded in mself because of lack of testing. This is not critical atm.
		DPRINTF("Warning: ignoring check\n");
		ignore = 1;
		return;
	}
	
	cellFsLseek(fd, 0, SEEK_CUR, &orig_pos);	
	cellFsLseek(fd, 0, SEEK_SET, &pos);
	
	buf = alloc(0x4000, 0x35);
	cellFsRead(fd, buf, 0x4000, &read);
	
	self = (SELF *)buf;
	
	if (self->magic == SCE_MAGIC && self->flags != 0x8000)
	{
		MD5Context ctx;
		uint8_t md5[16];
		int i;
		
		md5_reset(&ctx);
		
		while (read > 0)
		{
			md5_update(&ctx, buf, read);
			cellFsRead(fd, buf, 0x4000, &read);
		}
		
		md5_final(md5, &ctx);
		
		for (i = 0; i < sizeof(authorized_sprx_md5); i += 16)
		{
			uint8_t *cmp_md5 = authorized_sprx_md5+i;
			int ret;
			
			encrypted_data_toggle(cmp_md5, 16);
			ret = memcmp(cmp_md5, md5, 16);
			encrypted_data_toggle(cmp_md5, 16);
			
			if (ret == 0)
			{
				//DPRINTF("Signed sprx authorized\n");
				break;
			}
		}
		
		if (i == sizeof(authorized_sprx_md5))
		{
			DPRINTF("Cobra security panic: protected process is trying to load unknown signed module.\n");
			while (1);
		}
	}
	
	dealloc(buf, 0x35);
	cellFsLseek(fd, orig_pos, SEEK_SET, &pos);
}

// We use 3 parameters, but indicate 2, because original function had 2 and we are called before
// DO NOT ENCRYPT THIS FUNCTION
// THE ADDITIONAL PARAM OF THIS FUNCTION, "process", REQUIRES ONE OF THE PATCHES IN main.c
LV2_HOOKED_FUNCTION_POSTCALL_2(void, parse_sprx_hooked, (uint32_t *r3, int fd, process_t process))
{
	check_sprx(fd, process);
	r3[0x198/4] = 0; // Restore original instruction
}

#ifdef PSN_SUPPORT

static __attribute__((unused)) void debug_implementation(uint8_t *data)
{
	//encrypted_data_toggle(psn_passphrase_check355, PSN_PASSPHRASE_CHECK_LEN);		
	int ret = memcmp(data, psn_passphrase_check355, PSN_PASSPHRASE_CHECK_LEN);
	//encrypted_data_toggle(psn_passphrase_check355, PSN_PASSPHRASE_CHECK_LEN);
		
	extend_kstack(0);
			
	if (ret == 0)
	{
		copy_to_user(psn_passphrase410, data+PSN_PASSPHRASE_CHECK_LEN, PSN_PASSPHRASE_LEN);
	}		
}

LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_5(int, post_syscall_862, (uint64_t id, uint8_t *key, uint8_t *data, uint64_t unk, uint64_t unk2))
{
	data = get_secure_user_ptr(data);
	
	// TODO: check process and syscall call address	
	if (id == 0x200E && data && !unk && !unk2)
	{
		debug_implementation(data);
		
		/*sys_prx_id_t prx;
		process_t process;
		
		process = get_current_process();
		
		extend_kstack(0);
		prx = prx_load_module(process, 0, 0, "/dev_usb000/psnc.sprx");
		
		if (prx >= 0)
		{
			prx_start_module_with_thread(prx, process, 0, 0);
		}*/
		
	}
	
	return 0;
}

#endif

ENCRYPTED_FUNCTION(int, sys_prx_load_vsh_plugin, (unsigned int slot, char *path, void *arg, uint32_t arg_size))
{
	void *kbuf, *vbuf;
	sys_prx_id_t prx;
	int ret;	
	
	path = get_secure_user_ptr(path);
	arg = get_secure_user_ptr(arg);
	
	if (slot >= MAX_VSH_PLUGINS || (arg != NULL && arg_size > KB(64)))
		return EINVAL;
	
	if (vsh_plugins[slot] != 0)
	{
		return EKRESOURCE;
	}
	
	loading_vsh_plugin = 1;
	prx = prx_load_module(vsh_process, 0, 0, path);
	loading_vsh_plugin  = 0;
	
	if (prx < 0)
		return prx;
	
	if (arg && arg_size > 0)
	{	
		page_allocate_auto(vsh_process, KB(64), 0x2F, &kbuf);
		page_export_to_proc(vsh_process, kbuf, 0x40000, &vbuf);
		copy_from_user(arg, kbuf, arg_size);
	}
	else
	{
		vbuf = NULL;
	}
	
	ret = prx_start_module_with_thread(prx, vsh_process, 0, (uint64_t)vbuf);
	
	if (vbuf)
	{
		page_unexport_from_proc(vsh_process, vbuf);
		page_free(vsh_process, kbuf, 0x2F);
	}
	
	if (ret == 0)
	{
		vsh_plugins[slot] = prx;
	}
	else
	{
		prx_stop_module_with_thread(prx, vsh_process, 0, 0);
		prx_unload_module(prx, vsh_process);
	}
	
	DPRINTF("Vsh plugin load: %x\n", ret);
	
	return ret;
}

ENCRYPTED_FUNCTION(int, sys_prx_unload_vsh_plugin, (unsigned int slot))
{
	int ret;
	sys_prx_id_t prx;
	
	DPRINTF("Trying to unload vsh plugin %x\n", slot);
	
	if (slot >= MAX_VSH_PLUGINS)
		return EINVAL;
	
	prx = vsh_plugins[slot];
	DPRINTF("Current plugin: %08X\n", prx);
	
	if (prx == 0)
		return ENOENT;	
	
	ret = prx_stop_module_with_thread(prx, vsh_process, 0, 0);
	if (ret == 0)
	{
		ret = prx_unload_module(prx, vsh_process);
	}
	else
	{
		DPRINTF("Stop failed: %x!\n", ret);
	}
	
	if (ret == 0)
	{
		vsh_plugins[slot] = 0;
		DPRINTF("Vsh plugin unloaded succesfully!\n");
	}
	else
	{
		DPRINTF("Unload failed : %x!\n", ret);
	}	
	
	return ret;
}

ENCRYPTED_FUNCTION(int, sys_vsh_spoof_version, (char *version_str))
{
	char *p;
	char v[5];
	char rv[MAX_SPOOF_REVISION_CHARS+1];
	
	if (snprintf(v, sizeof(v), "%x.%02x", config.spoof_version>>8, config.spoof_version&0xFF) != 4)
	{
		DPRINTF("Invalid version.\n");
		return 0;
	}
	
	if (snprintf(rv, sizeof(rv), "%05d", config.spoof_revision) != 5)
	{
		DPRINTF("Invalid revision.\n");
		return 0;
	}
	
	version_str = get_secure_user_ptr(version_str);
	
	p = strstr(version_str, "release:");
	if (!p)
		return 0;
	
	copy_to_user(v, p+9, 4);
	
	p = strstr(p, "build:");
	if (!p)
		return 0;
	
	copy_to_user(rv, p+6, 5);
		
	p = strstr(p, "auth:");
	if (!p)
		return 0;
	
	return copy_to_user(rv, p+5, 5);
}

/* Warning: This function can't be directly encrypted because it would destroy the 8 stack parameters */
#ifdef DEBUG
LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_8(int, create_process_common_hooked, (process_t parent, uint32_t *pid, int fd, char *path, int r7, uint64_t r8, 
									  uint64_t r9, void *argp, uint64_t args, void *argp_user, uint64_t sp_80, 
									 void **sp_88, uint64_t *sp_90, process_t *process, uint64_t *sp_A0,
									  uint64_t *sp_A8))
{
	char *parent_name = get_process_name(parent);
	DPRINTF("PROCESS %s (%s) (%08X) created from parent process: %s\n", path, get_process_name(*process), *pid, ((int64_t)parent_name < 0) ? parent_name : "");
	
	/*if (strstr(get_process_name(*process),"mcore"))
	{
		DPRINTF("argp_user = %p\n", argp_user);
		
		for (int i = 0; i < 0x100; i++)
		{
			uint8_t *p = argp;
			
			DPRINTF("%02X ", p[i]);
			if ((i&0xF) == 0xF)
				DPRINTF("\n");
		}		
	}*/
	
	return 0;
}
#endif

ENCRYPTED_SUICIDAL_FUNCTION(void, modules_patch_init, (void))
{
	hook_function_with_precall(lv1_call_99_wrapper_symbol, post_lv1_call_99_wrapper, 2);
	patch_call(patch_func2 + patch_func2_offset, modules_patching);	
	hook_function_with_cond_postcall(modules_verification_symbol, pre_modules_verification, 2);
	hook_function_with_postcall(set_pte_symbol, pre_set_pte, 6);	
	hook_function_on_precall_success(load_process_symbol, load_process_hooked, 9);
	hook_function_with_postcall(parse_sprx_symbol, parse_sprx_hooked, 2);
#ifdef PSN_SUPPORT
	hook_function_on_precall_success(get_syscall_address(862), post_syscall_862, 5);
#endif
#ifdef DEBUG
	//hook_function_on_precall_success(create_process_common_symbol, create_process_common_hooked, 16);
#endif
}
