#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "../vm/vm.h"

#if defined (PS2HWEMU)
#define SEED	0x773C
#elif defined(PS2GXEMU)
#define SEED	0x241B
#elif defined(PS2SOFTEMU)
#define SEED	0xFA96
#endif

xdata at PS3_ADDRESS volatile uint32_t ps3_address;
xdata at PS3_TOC uint32_t ps3_toc;

xdata at PS3_PARAM1 uint32_t ps3_param1_low;
xdata at PS3_PARAM2 uint32_t ps3_param2_low;
xdata at PS3_PARAM3 uint32_t ps3_param3_low;
xdata at PS3_PARAM4 uint32_t ps3_param4_low;
xdata at PS3_PARAM5 uint32_t ps3_param5_low;
xdata at PS3_PARAM1+4 uint32_t ps3_param1_high;
xdata at PS3_PARAM2+4 uint32_t ps3_param2_high;
xdata at PS3_PARAM3+4 uint32_t ps3_param3_high;
xdata at PS3_PARAM4+4 uint32_t ps3_param4_high;
xdata at PS3_PARAM5+4 uint32_t ps3_param5_high;
	
xdata at PS3_RESULT uint32_t ps3_result_low;
xdata at PS3_RESULT+4 uint32_t ps3_result_high;

xdata at PS3_RAM volatile uint8_t ps3_ram;
xdata at PS3_CALL uint8_t ps3_call;

xdata at XRAM_ADDR uint32_t xram_addr;
xdata at ROM_ADDR uint32_t rom_addr;
xdata at CYCLE_COUNT uint32_t cycle_count;
xdata at INST_COUNT uint32_t inst_count;

xdata at VM_TICK uint32_t vm_tick_low;
xdata at VM_REBOOT uint16_t vm_reboot;
xdata at VM_TERMINATE volatile uint8_t vm_terminate;

#define READ_PS3(addr, ddata) \
	ps3_address = addr; \
	*(ddata) = ps3_ram
	
#define WRITE_PS3(addr, ddata) \
	ps3_address = addr; \
	ps3_ram = ddata
	
#define ROM_KEYS_LEN		251
	
xdata at 0x6800 uint8_t loader_rom_keys[ROM_KEYS_LEN];

void main()
{
	uint8_t i;
	
	srand(SEED);
	
	for (i = 0; i < ROM_KEYS_LEN; i++)
	{
		loader_rom_keys[i] = rand();
		
#if defined(PS2HWEMU)
		switch (i&3)
		{
			case 0:
				loader_rom_keys[i] ^= 0x76;
			break;
			
			case 1:
				loader_rom_keys[i] ^= 0x57;
			break;
			
			case 2:
				loader_rom_keys[i] ^= 0x99;
			break;
			
			case 3:
				loader_rom_keys[i] ^= 0xF3;
			break;
		}
#endif
	}
	
	ps3_address = xram_addr+0x6800;
#ifdef PS2HWEMU
	vm_reboot = 0x200;
#else
	vm_reboot = 0x190;
#endif
}


