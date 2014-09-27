#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/memory.h>
#include <lv2/patch.h>
#include <lv2/syscall.h>
#include <lv2/usb.h>
#include <lv2/storage.h>
#include <lv2/thread.h>
#include <lv2/synchronization.h>
#include <lv2/modules.h>
#include <lv2/io.h>
#include <lv2/time.h>
#include <lv2/security.h>
#include <lv2/error.h>
#include <lv2/symbols.h>
#include <lv1/stor.h>
#include <lv1/patch.h>
#include <cryptcode/cryptcode.h>
#include "common.h"
#include "syscall8.h"
#include "cobra.h"
#include "modulespatch.h"
#include "mappath.h"
#include "storage_ext.h"
#include "region.h"
#include "permissions.h"
#include "psp.h"
#include "config.h"
#include "drm.h"

// Format of version: 
// byte 0, 7 MS bits -> reserved
// byte 0, 1 LS bit -> 1 = CFW version, 0 = OFW/exploit version
// byte 1 and 2 -> ps3 fw version in BCD e.g 3.55 = 03 55. For legacy reasons, 00 00 means 3.41
// byte 3 is cobra firmware version, 
// 1 = version 1.0-1.2, 
// 2 = 2.0, 
// 3 = 3.0
// 4 = 3.1 
// 5 = 3.2
// 6 = 3.3
// 7 = 4.0
// 8 = 4.1
// 9 = 4.2
// A = 4.3
// B = 4.4
// C = 5.0
// D = 5.1

#define COBRA_VERSION		0x0D
#define COBRA_VERSION_BCD	0x0509

#if defined(FIRMWARE_3_41)
#define FIRMWARE_VERSION	0x0000
#elif defined(FIRMWARE_3_55)
#define FIRMWARE_VERSION	0x0355
#endif

#if defined(CFW)
#define IS_CFW			1
#else
#define IS_CFW			0
#endif

#define MAKE_VERSION(cobra, fw, type) ((cobra&0xFF) | ((fw&0xffff)<<8) | ((type&0x1)<<24))

typedef struct
{
	uint32_t address;
	uint32_t data;
} Patch;

static Patch kernel_patches[] =
{
	{ patch_data1_offset, 0x01000000 },	
	{ patch_func8 + patch_func8_offset1, LI(3, 0) }, // force lv2open return 0
	// disable calls in lv2open to lv1_send_event_locally which makes the system crash
	{ patch_func8 + patch_func8_offset2, NOP },
	{ patch_func9 + patch_func9_offset, NOP },
	// psjailbreak, PL3, etc destroy this function to copy their code there.
	// We don't need that, but let's dummy the function just in case that patch is really necessary
	{ mem_base2, LI(3, 1) },
	{ mem_base2 + 4, BLR },		
	// sys_sm_shutdown, for ps2 let's pass to copy_from_user a fourth parameter
	{ shutdown_patch_offset, MR(6, 31) },
	{ module_sdk_version_patch_offset, NOP },
	// We need one parameter more in the function, so we do this patch, and then do in the patched function what the patched instruction did
	{ module_add_parameter_to_parse_sprxpatch_offset, LD(R5, 0, R24) }, // -> R5 is now process where the module is gonna be loaded
	// User thread prio hack	
	{ user_thread_prio_patch, NOP },
	{ user_thread_prio_patch2, NOP },	
};

#define N_KERNEL_PATCHES	(sizeof(kernel_patches) / sizeof(Patch))

// multiman compat layer (DISABLED)
/*uint64_t hermes_memcpy_dst;
uint64_t hermes_memcpy_src;*/

static INLINE int sys_get_version(uint32_t *version)
{
	uint32_t pv = MAKE_VERSION(COBRA_VERSION, FIRMWARE_VERSION, IS_CFW); 
	return copy_to_user(&pv, get_secure_user_ptr(version), sizeof(uint32_t));
}

static INLINE int sys_get_version2(uint16_t *version)
{
	uint16_t cb = COBRA_VERSION_BCD;
	return copy_to_user(&cb, get_secure_user_ptr(version), sizeof(uint16_t));
}

#ifdef TEST

#define MM_EA2VA(ea)			((ea) & ~0x8000000000000000ULL)
	
#define HPTE_V_BOLTED			0x0000000000000010ULL
#define HPTE_V_LARGE			0x0000000000000004ULL
#define HPTE_V_VALID			0x0000000000000001ULL
#define HPTE_R_PROT_MASK		0x0000000000000003ULL

static int mm_insert_htab_entry(u64 va_addr, u64 lpar_addr, u64 prot, u64 *index)
{
	u64 hpte_group, hpte_index, hpte_v, hpte_r, hpte_evicted_v, hpte_evicted_r;
	int result;

	hpte_group = (((va_addr >> 28) ^ ((va_addr & 0xFFFFFFFULL) >> 12)) & 0x7FF) << 3;
	hpte_v = ((va_addr >> 23) << 7) | HPTE_V_VALID;
	hpte_r = lpar_addr | 0x38 | (prot & HPTE_R_PROT_MASK);

	result = lv1_insert_htab_entry(0, hpte_group, hpte_v, hpte_r, HPTE_V_BOLTED, 0,
		&hpte_index, &hpte_evicted_v, &hpte_evicted_r);

	if ((result == 0) && (index != 0))
		*index = hpte_index;

	return result;
}

static int mm_map_lpar_memory_region(u64 lpar_start_addr, u64 ea_start_addr, u64 size,
	u64 page_shift, u64 prot)
{
	int i, result;

	for (i = 0; i < size >> page_shift; i++)
	{
		result = mm_insert_htab_entry(MM_EA2VA(ea_start_addr), lpar_start_addr, prot, 0);
 		if (result != 0)
 			return result;

		lpar_start_addr += (1 << page_shift);
		ea_start_addr += (1 << page_shift);
	}

	return 0;
}

static INLINE u64 map_hv(void)
{
	u64 mmap_lpar_addr;
	lv1_undocumented_function_114(0, 0xC, HV_SIZE, &mmap_lpar_addr);
	mm_map_lpar_memory_region(mmap_lpar_addr, HV_BASE, HV_SIZE, 0xC, 0);
	return mmap_lpar_addr;
}

#endif

ENCRYPTED_SYSCALL(int, syscall8, (uint64_t function, uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4, uint64_t param5, uint64_t param6, uint64_t param7))
{
	extend_kstack(0);
	
	//DPRINTF("Syscall 8 -> %lx\n", function);
	
	switch (function)
	{
		case SYSCALL8_OPCODE_GET_VERSION:
			return sys_get_version((uint32_t *)param1);
		break;
		
		case SYSCALL8_OPCODE_GET_VERSION2:
			return sys_get_version2((uint16_t *)param1);
		break;
		
		case SYSCALL8_OPCODE_GET_DISC_TYPE:
			return sys_storage_ext_get_disc_type((unsigned int *)param1, (unsigned int *)param2, (unsigned int *)param3);
		break;
		
		case SYSCALL8_OPCODE_READ_PS3_DISC:
			return sys_storage_ext_read_ps3_disc((void *)param1, param2, (uint32_t)param3);
		break;
		
		case SYSCALL8_OPCODE_FAKE_STORAGE_EVENT:
			return sys_storage_ext_fake_storage_event(param1, param2, param3);
		break;	
		
		case SYSCALL8_OPCODE_GET_EMU_STATE:
			return sys_storage_ext_get_emu_state((sys_emu_state_t *)param1);
		break;
		
		case SYSCALL8_OPCODE_MOUNT_PS3_DISCFILE:
			return sys_storage_ext_mount_ps3_discfile(param1, (char **)param2);
		break;
		
		case SYSCALL8_OPCODE_MOUNT_DVD_DISCFILE:
			return sys_storage_ext_mount_dvd_discfile(param1, (char **)param2);
		break;
		
		case SYSCALL8_OPCODE_MOUNT_BD_DISCFILE:
			return sys_storage_ext_mount_bd_discfile(param1, (char **)param2);
		break;
		
		case SYSCALL8_OPCODE_MOUNT_PSX_DISCFILE:
			return sys_storage_ext_mount_psx_discfile((char *)param1, param2, (ScsiTrackDescriptor *)param3);
		break;
		
		case SYSCALL8_OPCODE_MOUNT_PS2_DISCFILE:
			return sys_storage_ext_mount_ps2_discfile(param1, (char **)param2, param3, (ScsiTrackDescriptor *)param4);
		break;
		
		case SYSCALL8_OPCODE_MOUNT_DISCFILE_PROXY:
			return sys_storage_ext_mount_discfile_proxy(param1, param2, param3, param4, param5, param6, (ScsiTrackDescriptor *)param7);
		break;
		
		case SYSCALL8_OPCODE_UMOUNT_DISCFILE:
			return sys_storage_ext_umount_discfile();
		break;
		
		case SYSCALL8_OPCODE_MOUNT_ENCRYPTED_IMAGE:
			return sys_storage_ext_mount_encrypted_image((char *)param1, (char *)param2, (char *)param3, param4);
		
		case SYSCALL8_OPCODE_GET_ACCESS:
			return sys_permissions_get_access();
		break;
		
		case SYSCALL8_OPCODE_REMOVE_ACCESS:
			return sys_permissions_remove_access();
		break;
		
		case SYSCALL8_OPCODE_READ_COBRA_CONFIG:
			return sys_read_cobra_config((CobraConfig *)param1);
		break;
		
		case SYSCALL8_OPCODE_WRITE_COBRA_CONFIG:
			return sys_write_cobra_config((CobraConfig *)param1);
		break;	
		
		case SYSCALL8_OPCODE_COBRA_USB_COMMAND:
			return sys_cobra_usb_command(param1, param2, param3, (void *)param4, param5);
		break;
		
		case SYSCALL8_OPCODE_SET_PSP_UMDFILE:
			return sys_psp_set_umdfile((char *)param1, (char *)param2, param3);
		break;
		
		case SYSCALL8_OPCODE_SET_PSP_DECRYPT_OPTIONS:
			return sys_psp_set_decrypt_options(param1, param2, (uint8_t *)param3, param4, param5, (uint8_t *)param6, param7);
		break;
		
		case SYSCALL8_OPCODE_READ_PSP_HEADER:
			return sys_psp_read_header(param1, (char *)param2, param3, (uint64_t *)param4);
		break;
		
		case SYSCALL8_OPCODE_READ_PSP_UMD:
			return sys_psp_read_umd(param1, (void *)param2, param3, param4, param5);
		break;
		
		case SYSCALL8_OPCODE_PSP_PRX_PATCH:
			return sys_psp_prx_patch((uint32_t *)param1, (uint8_t *)param2, (void *)param3);
		break;
		
		case SYSCALL8_OPCODE_PSP_CHANGE_EMU:
			return sys_psp_set_emu_path((char *)param1);
		break;
		
		case SYSCALL8_OPCODE_PSP_POST_SAVEDATA_INITSTART:
			return sys_psp_post_savedata_initstart(param1, (void *)param2);
		break;
		
		case SYSCALL8_OPCODE_PSP_POST_SAVEDATA_SHUTDOWNSTART:
			return sys_psp_post_savedata_shutdownstart();
		break;
		
		case SYSCALL8_OPCODE_AIO_COPY_ROOT:
			return sys_aio_copy_root((char *)param1, (char *)param2);
		break;
		
		case SYSCALL8_OPCODE_MAP_PATHS:
			return sys_map_paths((char **)param1, (char **)param2, param3);
		break;
		
		case SYSCALL8_OPCODE_VSH_SPOOF_VERSION:
			return sys_vsh_spoof_version((char *)param1);
		break;		
		
		case SYSCALL8_OPCODE_LOAD_VSH_PLUGIN:
			return sys_prx_load_vsh_plugin(param1, (char *)param2, (void *)param3, param4);
		break;
		
		case SYSCALL8_OPCODE_UNLOAD_VSH_PLUGIN:
			return sys_prx_unload_vsh_plugin(param1);
		break;
		
		case SYSCALL8_OPCODE_DRM_GET_DATA:
			return sys_drm_get_data((void *)param1, param2);
		break;
		
#ifdef DEBUG
		case SYSCALL8_OPCODE_DUMP_STACK_TRACE:
			dump_stack_trace3((void *)param1, 16);
			return 0;
		break;
		
		case SYSCALL8_OPCODE_PSP_SONY_BUG:
			return sys_psp_sony_bug((uint32_t *)param1, (void *)param2, param3);
		break;
		
		/*case SYSCALL8_OPCODE_GENERIC_DEBUG:
			return sys_generic_debug(param1, (uint32_t *)param2, (void *)param3);
		break;*/
#endif

#ifdef TEST
		case SYSCALL8_OPCODE_CHANGE_LV2PATH:
		{
			u64 hv_lpar = map_hv();
			uint64_t addr = 0;
			
			if (lv1_peekd(0x1600C0ULL) == 0x2F666C682F6F732FULL) 
			{
           			addr = 0x1600C0ULL;
			} 
			else if (lv1_peekd(0x980C0ULL) == 0x2F666C682F6F732FULL) 
			{
				addr = 0x980C0ULL;
			} 
			else if (lv1_peekd(0xA7E60ULL) == 0x2F666C682F6F732FULL) 
			{
				addr = 0xA7E60ULL;
			}
			
			if (addr)
			{			
				lv1_poked(addr, 0x2F6C6F63616C5F73ULL);
				lv1_poked(addr+8, 0x7973302F6C76325FULL);
				lv1_poked(addr+0x10, 0x6B65726E656C2E73ULL);
				lv1_poked(addr+0x18, 0x656C660000000000ULL);
			}
			
			lv1_undocumented_function_115(hv_lpar);	
			return 0;
		}
		break;
#endif

#ifdef DEBUG
/*		// multiman compat layer (DISABLED)
		case SYSCALL8_OPCODE_HERMES_ENABLE: case SYSCALL8_OPCODE_HERMES_PERM_MODE:
			return 1;
		break;
		
		case SYSCALL8_OPCODE_HERMES_MEMCPY:
			return sys_hermes_memcpy(param1, param2, param3);
		break;
		
		case SYSCALL8_OPCODE_HERMES_PATHTABLE:
			return sys_hermes_pathtable(param1);
		break;
*/
#endif
	}
	
	DPRINTF("Unsupported syscall8 opcode: 0x%lx\n", function);
	
	return ENOSYS;
}

ENCRYPT_PATCHED_FUNCTION(syscall8);

#ifndef PEEK_POKE_TEST

static int dummy_syscall(void)
{
	return ENOSYS;
}

#else

#ifdef DEBUG /* Further protection against forgets */

static uint64_t peekq(uint64_t *address)
{
	return *address;
}

static void pokeq(uint64_t *address, uint64_t value)
{
	*address = value;
}

#endif

#endif

static INLINE void apply_kernel_patches(void)
{
	for (int i = 0; i < N_KERNEL_PATCHES; i++)
	{
		uint32_t *addr= (uint32_t *)MKA(kernel_patches[i].address);
		*addr = kernel_patches[i].data;
		clear_icache(addr, 4);
		get_pseudo_random_number(&kernel_patches[i], sizeof(Patch));
	}

#ifndef PEEK_POKE_TEST
	create_syscall(6, dummy_syscall); 
	create_syscall(7, dummy_syscall); 
#else
	create_syscall(6, peekq);
	create_syscall(7, pokeq);
#endif
	create_syscall(8, syscall8);
}

#define HTAB_BASE 	0x800000000f000000ULL
#define HTAB_LV2_START 	0x01000000ULL
#define HTAB_LV2_END 	0x01800000ULL

#ifdef FIRMWARE_3_55

#define MAP_SEARCH_START 	0x300000
#define MAP_SEARCH_END	 	0x600000
#define SEARCH_VALUE		0x358CF0

#define CORE_OS_SIZE		0x6FFFE0
#define CORE_OS_SUM		0xb230

#endif

static INLINE void __attribute__((noreturn)) security_panic(int critical)
{
	extern uint64_t _start;
	
	if (critical)
	{
#ifdef DEBUG
		cobra_led_control(COBRA_LED_RED|COBRA_LED_BLUE|COBRA_LED_GREEN);
#else
		cobra_suicide();
#endif
	}
	
	memset(&_start, 0, 128*1024);
	while(1);
}

static INLINE uint64_t pte_va(uint64_t pte0, uint32_t hash)
{
	return ((((pte0 >> 7) >> 5) ^ hash) << 12) | ((pte0 >> 7) << 23);
}

static INLINE void htab_check(void)
{
	uint64_t pte0, pte1;
	uint32_t i;
	
	// Check and correct lv2 kernel 
	for (i = 0; i < 128; i++)
	{
		pte0 = *(uint64_t *)(HTAB_BASE | ((i << 7)));
		pte1 = *(uint64_t *)(HTAB_BASE | ((i << 7) + 8));

		if (pte1&3)
		{
			DPRINTF("HTAB security panic (1)\n");
			security_panic(1);
		}
	}	
	
	// Process all entries in search of PP != 0
	for (i = 0; i < 16384; i++)
	{
		/* read the old value */
		pte0 = *(uint64_t *)(HTAB_BASE | ((i << 4)));
		pte1 = *(uint64_t *)(HTAB_BASE | ((i << 4) + 8));

		if (pte1&3)
		{
			int panic = 1;
			
			//DPRINTF("PAGE=%d PP=%lx va=%lx\n", i, pte1&3, pte_va(pte0, i/8));
			if ((pte1&3) == 3)
			{
				if (i == 67 || i == 74 || i == 98 || i == 107 || i == 115 || i == 122 || 
				    i == 1936 || i == 14336 || i == 14344 || i == 14352 || i == 14360)
				{
					uint64_t va = pte_va(pte0, i/8);
					
					if (va >= 0xd0000000 && va <= 0xd0005000)
					{
						if (pte1&4)
							panic = 0;
					}
					else if (va == 0xd00ff000)
					{
						if (pte1&4)
							panic = 0;
					}
					else if (va >= 0xf700000 && va <= 0xf703000)
					{
						if (!(pte1&4))
							panic = 0;
					}
				}
			}
			else
			{
				//DPRINTF("%lx %lx\n", pte1&3, pte_va(pte0, i/8));
			}
			
			if (panic)
			{
				DPRINTF("HTAB security panic(2)\n");
				security_panic(0);
			}
		}
	}
}

static INLINE void kernel_path_check(void)
{
	for (u64 search_addr = 0x10; search_addr < (HV_SIZE-0x1000); search_addr += 8)
	{
		if (lv1_peekd(search_addr) == 0x3700000000000000)
		{
			if (lv1_peekw(search_addr+0x10) == 0x5053335F && lv1_peekw(search_addr+0x14) == 0x4C504152)
			{
				if (lv1_peekw(search_addr+0x30) != 0x2F666C68 || lv1_peekw(search_addr+0x34) != 0x2F6F732F ||
				    lv1_peekw(search_addr+0x38) != 0x6C76325F || lv1_peekw(search_addr+0x3C) != 0x6B65726E ||
				    lv1_peekw(search_addr+0x40) != 0x656C2E73 || lv1_peekw(search_addr+0x44) != 0x656C6600)
				{
					DPRINTF("kernel path security panic\n");
					security_panic(0);
				}
			}
		}
	}
}

static INLINE void additional_security(uint64_t hv_lpar)
{
	int rare_maps_count = 0;
	
	htab_check();
	
	// Check addresses mapped with lv1 call 114
	for (u64 addr = MAP_SEARCH_START; addr < MAP_SEARCH_END; addr += 8)
	{
		if (lv1_peekd(addr) == SEARCH_VALUE && lv1_peekd(addr+0x60) == 0x8000000000000000ULL)
		{
			u64 lpar = lv1_peekd(addr+0x50);
			u64 phys_addr = lv1_peekd(addr+0xA8);
			u64 size = lv1_peekd(addr+0x58);
			
			if (lpar != hv_lpar && phys_addr >= 0 && phys_addr < (24*1024*1024))
			{
				DPRINTF("Rare map: lpar=%lx,phys_addr=%lx,size=%lx\n", lpar, phys_addr, size);
				rare_maps_count++;
				
				if (rare_maps_count > 1 || size != 0xC000) // Only one rare map allowed, and with that size 
				{
					DPRINTF("HV map security panic\n");
					security_panic(0);
				}
			}
			else
			{
				DPRINTF("Found expected map: lpar=%lx,phys_addr=%lx,size=%lx\n", lpar, phys_addr, size);
			}
		}
	}
	
	kernel_path_check();	
}

ENCRYPTED_SUICIDAL_FUNCTION(int, main, (uint64_t hv_lpar))
//int main(uint64_t hv_lpar)
{
#ifdef DEBUG
	debug_init();
	debug_install();
	extern uint64_t _start;
	DPRINTF("Stage 2 says hello (load base = %p) (version = %08X)\n", &_start, MAKE_VERSION(COBRA_VERSION, FIRMWARE_VERSION, IS_CFW));
#endif	
	cobra_device_init();
	storage_ext_init();	
	modules_patch_init();	
	drm_init();
	
	apply_kernel_patches();	
	map_path_patches();
	storage_ext_patches();
	region_patches();
	permissions_patches();
#ifdef DEBUG
	debug_patches();
#endif	

	map_path("/app_home", "/dev_usb000", 0);

	DPRINTF("hhv_lpar = %lx\n", hv_lpar);
	
	additional_security(hv_lpar);
	lv1_undocumented_function_115(hv_lpar);	
	
	return 0;
}
