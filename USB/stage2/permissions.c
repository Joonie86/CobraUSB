#include <lv2/lv2.h>
#include <lv2/process.h>
#include <lv2/symbols.h>
#include <lv2/libc.h>
#include <lv2/error.h>
#include <lv2/patch.h>
#include <cryptcode/cryptcode.h>
#include "modulespatch.h"
#include "common.h"

uint32_t access_pid;
uint32_t vsh_pid;

// multiman compat layer (DISABLED)
/*static uint64_t *orig811_opd;
static uint64_t *orig813_opd;
static uint64_t orig811_addr;
static uint64_t orig813_addr;*/

static char *system_processes[] =
{
	"_main_sys_init_osd.",
	"_main_vsh.self",
	"_main_mcore.self",
	"_main_bdp_BDVD.self",
	"_main_bdp_BDMV.self",
	"_main_psp_emulator.",
	"_main_psp_translato",
	"_main_ps1_netemu.se",
	"_main_ps1_emu.self"
};

#define N_SYSTEM_PROCESSES (sizeof(system_processes) / sizeof(char *))

int is_system_process(process_t process)
{
	for (int i = 0; i < N_SYSTEM_PROCESSES; i++)
	{
		if (strcmp(get_process_name(process)+8, system_processes[i]) == 0)
			return 1;
	}
	
	return 0;
}

LV2_HOOKED_FUNCTION_COND_POSTCALL_4(int, permissions_func_hook, (void *r3, void *r4, void *r5, void *r6))
{
	process_t process = get_current_process_critical();
	
	if (process && is_system_process(process))
		return DO_POSTCALL;
	
	// Uncomment to do tests with original permissions except on cobra usb manager
	/*if (!process || process->pid != access_pid)
		return DO_POSTCALL;*/
		
	uint32_t call_addr = (uint32_t)((uint64_t)get_patched_func_call_address() & 0xFFFFFFFF);	
	
	/*if (process)
		DPRINTF("Function called from process %s, at %x\n", get_process_name(process)+8, call_addr);*/
	
	if (call_addr == permissions_exception2)
	{
		return DO_POSTCALL;
	}
	
	if (call_addr == permissions_exception1 || call_addr == permissions_exception3)
	{
		return (process == NULL);	
	}
		
	return 1;
}

ENCRYPTED_PATCHED_FUNCTION(uint32_t, get_pid_patched, (process_t process))
{
	if (process)
	{
		if (vsh_process && access_pid != 0 && process->pid == access_pid)
		{
			return vsh_process->pid;
		}
		
		return process->pid;	
	}
	
	return -1;
}

ENCRYPT_PATCHED_FUNCTION(get_pid_patched);

int sys_permissions_get_access(void)
{
	access_pid = get_current_process_critical()->pid;	
	return 0;
}

int sys_permissions_remove_access(void)
{
	if (access_pid == get_current_process_critical()->pid)
	{
		access_pid = 0;
		return 0;
	}
	
	return ENOENT;
}

// multiman compat layer (DISABLED)
/*ENCRYPTED_SYSCALL2(uint64_t, peekq, (uint64_t addr))
{
	DPRINTF("PEEK: %lx\n", addr);
	if (addr == MKA(0x2D7820))
	{
		if (get_current_process()->pid == access_pid)
		{
			return (0x40ULL << 56);
		}
		
		return (0x20ULL<<56);
	}
	else if (addr == MKA(0x140003b8))
	{
		return 0x7f83e37860000000ULL; 
	}
		
	return 0;
}

ENCRYPT_PATCHED_FUNCTION(peekq);

ENCRYPTED_SYSCALL2(void, pokeq, (uint64_t addr, uint64_t value))
{
	uint64_t **table = (uint64_t **)MKA(syscall_table_symbol);
	
	DPRINTF("POKE %lx %lx\n", addr, value);
	if (addr == MKA(0x2D7820))
	{
		uint64_t access = value>>56ULL;
		
		if (access == 0x20)
		{
			DPRINTF("Permission remove\n");
			sys_permissions_remove_access();
		}
		else if (access == 0x40)
		{
			DPRINTF("Permission access\n");
			sys_permissions_get_access();
		}
	}
	else if (addr == orig813_addr)
	{
		if (value ==  0xF88300007C001FACULL)
		{
			DPRINTF("New poke install\n");
			create_syscall2(813, pokeq);
		}
		else if (value == 0xF821FF017C0802A6ULL)
		{
			DPRINTF("New poke uninstall\n");
			table[813] = orig813_opd;
		}
	}
	else if (addr == orig811_addr)
	{
		if (value == 0x7C0802A6F8010010ULL)
		{
			DPRINTF("Install hvsc syscall\n");
			create_syscall2(811, peekq); // peekq returns 0 for almost everything, so it should be fine
		}
		else
		{
			DPRINTF("Remove hvsc syscall\n");
			table[811] = orig811_opd;
		}
	}	
}

ENCRYPT_PATCHED_FUNCTION(pokeq);*/

ENCRYPTED_SUICIDAL_FUNCTION(void, permissions_patches, (void))
{
	// multiman compat layer (DISABLED)
	/*uint64_t **table = (uint64_t **)MKA(syscall_table_symbol);	
	orig811_opd = table[811];
	orig813_opd = table[813];
	orig811_addr = orig811_opd[0];
	orig813_addr = orig813_opd[0];*/
	
	hook_function_with_cond_postcall(permissions_func_symbol, permissions_func_hook, 4);
	patch_call(ss_pid_call_1, get_pid_patched);
	
	// multiman compat layer (DISABLED)
	/*create_syscall2(6, peekq);
	create_syscall2(7, pokeq);*/
}

