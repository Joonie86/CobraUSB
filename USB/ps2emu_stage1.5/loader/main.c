#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "../../ps2emu/include/ps2emu/symbols.h"
#include "../vm/vm.h"
#include "xtea.h"

#if defined(PS2HWEMU)
#include "stage2hw.h"
#elif defined(PS2GXEMU)
#include "stage2gx.h"
#elif defined(PS2SOFTEMU)
#include "stage2sw.h"
#endif

/* Stage1 symbols */
#ifdef PS2HWEMU
#define clear_icache_symbol	overwritten_symbol+0xf0
#else
#define clear_icache_symbol	overwritten_symbol+0xdc
#endif

/* Stage 1.5 VM symbols */
#if defined(PS2HWEMU)

#define stage1_5_addr		0x21f0000
#define stage1_5_section1_size	0x3a00
#define stage1_5_section2_addr	0x70a0
#define stage1_5_section2_size	0x138

#elif defined(PS2GXEMU)

#define stage1_5_addr		0x2BAFAE8
#define stage1_5_section1_size	0x3B00
#define stage1_5_section2_addr	0x72b8
#define stage1_5_section2_size	0x128

#elif defined(PS2SOFTEMU)

#define stage1_5_addr		0x2315560
#define stage1_5_section1_size	0x3B00
#define stage1_5_section2_addr	0x7140
#define stage1_5_section2_size	0x138

#endif

#if defined(PS2HWEMU)

#define STAGE2_ALIGNMENT	0
#define ARGS_ADDR_KEY		(arguments_symbol^0x6258366e)

#elif defined(PS2GXEMU)

#define STAGE2_ALIGNMENT	8
#define ARGS_ADDR_KEY		(arguments_symbol^0x90a2c570)

#elif defined(PS2SOFTEMU)

#define STAGE2_ALIGNMENT	0
#define ARGS_ADDR_KEY		(arguments_symbol^0x09c1b436)

#endif

#define XTEA_HASH		0x1000
#define XTEA_CBC_DECRYPT	0x1004
#define TEMP_BUF		0x1800
#define DEC_KEY			0x2000
#define DEC_IV			0x2010
#define HASH			0x2018
#define ARGS_ADDR		0x2020

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

xdata at VM_SAVED_PARAM1 uint32_t vm_saved_param1_low;
xdata at VM_SAVED_PARAM2 uint32_t vm_saved_param2_low;
xdata at VM_SAVED_PARAM3 uint32_t vm_saved_param3_low;
xdata at VM_SAVED_PARAM4 uint32_t vm_saved_param4_low;
xdata at VM_SAVED_PARAM1+4 uint32_t vm_saved_param1_high;
xdata at VM_SAVED_PARAM2+4 uint32_t vm_saved_param2_high;
xdata at VM_SAVED_PARAM3+4 uint32_t vm_saved_param3_high;
xdata at VM_SAVED_PARAM4+4 uint32_t vm_saved_param4_high;

xdata at ROM_RW uint8_t rom_rw[32768];

// Unencrypted, must be identified by stage 1.5 cipher
code uint8_t stage1_5_hash[8] =
{
	0x98, 0x98, 0x98, 0x98, 0x98, 0x98, 0x98, 0x98
};

#if defined(PS2HWEMU)

code uint8_t stage1_5_hash_key[8] =
{
	0x5C, 0x47, 0x20, 0x2C, 0xC6, 0x89, 0x3D, 0x07
};

#elif defined(PS2GXEMU)

code uint8_t stage1_5_hash_key[8] = 
{
	0x8E, 0x67, 0x2F, 0x7B, 0x50, 0x71, 0x6D, 0x83
};

#elif defined(PS2SOFTEMU)

code uint8_t stage1_5_hash_key[8] = 
{
	0xD4, 0xF5, 0x85, 0x8F, 0x0C, 0x96, 0xD2, 0x8F
};

#endif

code uint8_t xtea_keys[17] = 
{
	0x62, 0x3B, 0xD5, 0xF8, 0xE6, 0xCC, 0xA4, 0x84,
	0x44, 0xA1, 0x76, 0xD4, 0x80, 0x5A, 0x48, 0xC4, 
	0x24
};

xdata at XTEA_HASH uint32_t xtea_hash;
xdata at XTEA_CBC_DECRYPT uint32_t xtea_cbc_decrypt;
xdata at TEMP_BUF uint8_t temp_buf[256];
xdata at DEC_KEY uint8_t dec_key[16];
xdata at DEC_IV	uint8_t dec_IV[8];
xdata at HASH	uint8_t hash[8];
xdata at ARGS_ADDR uint32_t args_addr;

#define READ_PS3(addr, ddata) \
	ps3_address = addr; \
	*(ddata) = ps3_ram
	
#define WRITE_PS3(addr, ddata) \
	ps3_address = addr; \
	ps3_ram = ddata
	
void hash_memory(uint32_t address, uint32_t size)
{
	uint8_t i;
	
	for (i = 0; i < 8; i++)
		temp_buf[i] = hash[i];
	
	ps3_param1_low = xram_addr+TEMP_BUF;
	ps3_param2_low = address;
	ps3_param3_low = size;
	ps3_param4_low = xram_addr+HASH;
	ps3_address = xtea_hash;
	ps3_call = 1;
}

void main()
{
	uint32_t address;
	uint8_t alignment;
	int i;
	
	// Decrypt xtea core	
	uint16_t out = (uint16_t)xtea;
	address = rom_addr+out;
	
	address = (address+3)&~3;
	out = address-rom_addr;
	
	for (i = 0; i < sizeof(xtea)-3; i++)
	{
		rom_rw[out+i] = xtea[i+3] ^ xtea_keys[i%17];
	}
	
	xtea_hash = address+0x140;
	xtea_cbc_decrypt = address+0x94;
	
	ps3_param1_low = address;
	ps3_param2_low = sizeof(xtea);
	ps3_address = clear_icache_symbol;
	ps3_call = 1;	
	
	// Self-hash of stage 1.5
	for (i = 0; i < 8; i++)
	{
		uint16_t x = (uint16_t)stage1_5_hash+i;
		
		temp_buf[i+8] = rom_rw[x];
		rom_rw[x] = 0x98;
	}	
	
	hash_memory(stage1_5_addr, stage1_5_section1_size);
	hash_memory(stage1_5_addr+stage1_5_section2_addr, stage1_5_section2_size);
	
	for (i = 0; i < 8; i++)
	{
		if ((hash[i] ^ stage1_5_hash_key[i]) != temp_buf[i+8])
		{
			while (1) 
			{
				hash[i--] ^= hash[i+1];
			}
		}
	}
	
	// Hash ps2emu, including stage1
	for (i = 0; i < 8; i++)
		hash[i] = 0;
	
#if defined(PS2HWEMU)

	hash_memory(0x10000, 0x1809ec-0x10000);
	hash_memory(0x4c0a70+0x18, 0x20f88-0x18); // opd

#elif defined(PS2GXEMU)
	
	hash_memory(0, 0x22c0);
	hash_memory(0x6780, 0x140);
	hash_memory(0x10000, 0x2EDC8);
	hash_memory(0x3ee00, 0x215384);
	hash_memory(0x254200, 0x60b0); // Read only, non x
	hash_memory(0x25a300, 0xc7a08); // Read only, non x
	hash_memory(0x644430, 0x2a1c8); // opd	
	
#elif defined(PS2SOFTEMU)

	hash_memory(0, 0x22c0);
	hash_memory(0x7400, 0x140);
	hash_memory(0x10000, 0x22FC38);
	hash_memory(0x23fc80, 0x48a0);
	hash_memory(0x244580, 0x131048);
	hash_memory(0x597650, 0x295b0); // opd
	
#endif

	// Setup keys
#ifdef PS2HWEMU
	address = 0xbf97753f;
#else
	address =  vm_saved_param1_low;	
#endif
	args_addr = ((uint32_t)hash[2] << 24) | ((uint32_t)hash[5] << 16) | ((uint32_t)hash[1] << 8) | hash[4];
	args_addr ^= ARGS_ADDR_KEY;
	dec_IV[0] = hash[3];
	dec_IV[1] = (address>>8)&0xFF;
	dec_IV[2] = (address>>24)&0xFF;
	dec_IV[3] = hash[6];
	dec_IV[4] = address&0xFF;
	dec_IV[5] = hash[0];	
	dec_IV[6] = (address>>16)&0xFF;
	dec_IV[7] = hash[7];	
	
#ifdef PS2HWEMU

	for (i = 0; i < 7; i++)
	{
		READ_PS3(args_addr+0x959+i, &dec_key[i]);
	}
	
	srand(((dec_key[2] ^ hash[1]) << 8) | dec_key[7]);
	
	for (i = 8; i < 16; i++)
	{
		dec_key[i] = rand();
		dec_key[i] ^= hash[3];
	}

#else	
	for (i = 7; i >= 1; i--)
	{
		READ_PS3(args_addr+(0x4d9-1)+i, &dec_key[i]);	
		dec_key[i] ^= hash[0];
	}
	
	for (i = 15; i >= 9; i--)
	{
		READ_PS3(args_addr+(0x4e9-9)+i, &dec_key[i]);
		dec_key[i] ^= hash[3];
	}
	
	dec_key[0] = dec_key[4] ^ dec_key[12];	
#endif
	
	// Decrypt stage2	
	address = rom_addr+(uint32_t)stage2;
	alignment = address&0xF;
	
	if (alignment > STAGE2_ALIGNMENT)
	{
		address = (address+0x10)-(alignment-STAGE2_ALIGNMENT);
	}
	else
	{
		address = address+(STAGE2_ALIGNMENT-alignment);
	}	
	
	ps3_param1_low = xram_addr+DEC_KEY; // key
	ps3_param2_low = xram_addr+DEC_IV; // IV
	ps3_param3_low = rom_addr+(uint32_t)stage2+0x20; // input
	ps3_param4_low = address; //output
	ps3_param5_low = sizeof(stage2)-0x20; // size
	ps3_address = xtea_cbc_decrypt;
	ps3_call = 1;
	
	// Execute stage2
	ps3_param1_low = address;
	ps3_param2_low = sizeof(stage2)-0x20;
	ps3_address = clear_icache_symbol;
	ps3_call = 1;
	
	ps3_param1_low = vm_saved_param1_low;
	ps3_param1_high = vm_saved_param1_high;
	ps3_param2_low = vm_saved_param2_low;
	ps3_param2_high = vm_saved_param2_high;
	ps3_param3_low = vm_saved_param3_low;
	ps3_param3_high = vm_saved_param3_high;
	ps3_param4_low = vm_saved_param4_low;
	ps3_param4_high = vm_saved_param4_high;
	ps3_address = address;
	ps3_toc = TOC;
	ps3_call = 1;
	
	vm_terminate = 1;
}


