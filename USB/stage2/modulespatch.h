#ifndef __MODULESPATCH_H__
#define __MODULESPATCH_H__

#include <lv2/process.h>
#include <lv2/thread.h>

// Lets keep the values greater more privileges
typedef enum
{	
	PROTECTED_PROCESS_NONE = -1,
	// 0-... for key set 1, each value = index in key
	PROTECTED_PROCESS_MANAGER,
	//...
	// 0x10000-... for key set 2
	PROTECTED_PROCESS_PSPEMU = 0x10000,
	//...
	// 0x20000, only VSH
	PROTECTED_PROCESS_VSH = 0x20000
} ProcessProtection;


extern uint8_t condition_ps2softemu;
extern uint8_t condition_apphome;
extern uint8_t condition_psp_iso;
extern uint8_t condition_psp_dec;
extern uint8_t condition_psp_keys;
extern uint8_t condition_psp_change_emu;
extern uint8_t condition_psp_prometheus;

extern process_t vsh_process;
extern uint32_t protected_process;
extern ProcessProtection protected_process_type;

void modules_patch_init(void);

/* Syscalls */
int sys_vsh_spoof_version(char *version_str);
int sys_prx_load_vsh_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size);
int sys_prx_unload_vsh_plugin(unsigned int slot);
int sys_thread_create_ex(sys_ppu_thread_t *thread, void *entry, uint64_t arg, int prio, uint64_t stacksize, uint64_t flags, const char *threadname);

#endif /* __MODULESPATCH_H__ */

