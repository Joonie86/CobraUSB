#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "../vm/vm.h"
#include "../../lv2/include/lv2/symbols.h"
#include "handshake.h"

enum
{
	CMD_SPI_FLASH_READ = 0x10,
	CMD_SPI_FLASH_READ_AND_DECRYPT,
	CMD_SPI_FLASH_PAGE_PROGRAM,
	CMD_SPI_FLASH_DECRYPT_AND_PAGE_PROGRAM,	
	CMD_SPI_FLASH_ERASE_SECTOR,
	CMD_SPI_FLASH_CHIP_ERASE,
	CMD_SCP_FLASHROM_READ,
	CMD_SCP_SET_BUFFER,
	CMD_SCP_CRYPT,
	CMD_SCP_HANDSHAKE,
	CMD_SCP_SET_USER_KEY,	
	CMD_SCP_SET_JTAG,
	CMD_SCP_READ_TDO,
	CMD_MCU_EEPROM_DECRYPT_AND_WRITE,
	CMD_MCU_REBOOT,
	CMD_MCU_START_BOOTLOADER,
	CMD_SPI_FLASH_READ_AND_DECRYPT2, 
	CMD_LED_CONTROL,
	CMD_PS3_SECURITY_IN,
	CMD_PS3_SECURITY_OUT,
	CMD_PS3_SET,
	CMD_PS3_VALIDATE,
};

#define TYPE_HOST2DEV 0x40
#define TYPE_DEV2HOST 0xc0

/* Stage 1 symbols */
#define stage1_ep_pipe_symbol			0x7FC1B0
#define stage1_usb_port_symbol			0x7FC1E4 /* +4 */
#define stage1_usb_queue_symbol			0x7FC1F4 /* +4 */
#define stage1_usb_driver_symbol		0x7FC190 /* direct pointer */
#define stage1_hv_lpar_symbol			0x7FC1C8


#define stage1_S_symbol				0x7FC18C /* +4 */
#define stage1_IV_symbol			0x7FC1D0
#define stage1_stage1_5_symbol			0x7FC214 /* +4 */
#define stage1_stage1_5_size_symbol		0x7FC208
#define stage1_rc6_key_setup_symbol		0x7F00F8 
#define stage1_rc6_cbc_decrypt_symbol		0x7F034C
#define stage1_clear_icache_symbol		0x7F00CC
#define stage1_cobra_usb_command_symbol		0x7F0710
#define stage1_alloc_and_decompress_symbol	0x7F04BC
#define stage1_toc_symbol			0x804220


#define DEC_KEY			0x3210
#define DEC_IV			0x3200
#define MD5_KEY			0x3250
#define HSK_KEY			0x3270

xdata at PS3_ADDRESS volatile uint32_t ps3_address;
xdata at PS3_TOC uint32_t ps3_toc;

xdata at PS3_PARAM1 uint32_t ps3_param1_low;
xdata at PS3_PARAM2 uint32_t ps3_param2_low;
xdata at PS3_PARAM3 uint32_t ps3_param3_low;
xdata at PS3_PARAM4 uint32_t ps3_param4_low;
xdata at PS3_PARAM5 uint32_t ps3_param5_low;
xdata at PS3_PARAM6 uint32_t ps3_param6_low;
xdata at PS3_PARAM7 uint32_t ps3_param7_low;
xdata at PS3_PARAM8 uint32_t ps3_param8_low;
xdata at PS3_PARAM1+4 uint32_t ps3_param1_high;
xdata at PS3_PARAM2+4 uint32_t ps3_param2_high;
xdata at PS3_PARAM3+4 uint32_t ps3_param3_high;
xdata at PS3_PARAM4+4 uint32_t ps3_param4_high;
xdata at PS3_PARAM5+4 uint32_t ps3_param5_high;
xdata at PS3_PARAM6+4 uint32_t ps3_param6_high;
xdata at PS3_PARAM7+4 uint32_t ps3_param7_high;
xdata at PS3_PARAM8+4 uint32_t ps3_param8_high;
	
xdata at PS3_RESULT uint32_t ps3_result_low;
xdata at PS3_RESULT+4 uint32_t ps3_result_high;

xdata at PS3_RAM volatile uint8_t ps3_ram;
xdata at PS3_CALL uint8_t ps3_call;

xdata at XRAM_ADDR uint32_t xram_addr;
xdata at ROM_ADDR uint32_t rom_addr;
xdata at VM_SELF_PTR uint32_t vm_self_ptr;
xdata at STAGE2_ADDR uint32_t stage2_addr;
xdata at STAGE2_SIZE uint32_t stage2_size;
xdata at CYCLE_COUNT uint32_t cycle_count;
xdata at INST_COUNT uint32_t inst_count;

xdata at VM_TICK uint32_t vm_tick_low;
xdata at VM_TERMINATE volatile uint8_t vm_terminate;

#define BUF_SIZE	256

#define READ_PS3(addr, ddata) \
	ps3_address = addr; \
	*(ddata) = ps3_ram
	
#define WRITE_PS3(addr, ddata) \
	ps3_address = addr; \
	ps3_ram = ddata
	
xdata at TEMP_BUF volatile uint8_t temp_buf[BUF_SIZE];
xdata at DEC_KEY uint8_t dec_key[16];
xdata at DEC_IV uint8_t dec_IV[16];
xdata at MD5_KEY uint8_t md5_key[16];
xdata at HSK_KEY uint8_t hsk_key[16];
xdata at STACK uint32_t stack_base_high;
xdata at STACK+4 uint32_t stack_base_low;
xdata at STACK+8 uint32_t stack_data[0x1000/4];

code uint8_t stage1_5_md5[24] =
{
	0x63, 0x63, 0x63, 0x63, // section1_size
	0x63, 0x63, 0x63, 0x63, // section2_size
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, // combined md5
};

code uint8_t psid_keys[16] = 
{
	0xBD, 0x06, 0xDE, 0xD1, 0x1E, 0x4B, 0x40, 0xA0,
	0x90, 0x16, 0x05, 0x88, 0x9E, 0x2F, 0x8F, 0xD5
};

uint32_t read_ps3_word(uint32_t address)
{
	uint32_t result;
	uint8_t *result_ptr = (uint8_t *)&result;
	
	READ_PS3(address, result_ptr+3);
	READ_PS3(address+1, result_ptr+2);
	READ_PS3(address+2, result_ptr+1);
	READ_PS3(address+3, result_ptr);
	
	return result;
}

void write_ps3_word(uint32_t address, uint32_t word)
{
	uint8_t *ptr = (uint8_t *)&word;
	
	WRITE_PS3(address, ptr[3]);
	WRITE_PS3(address+1, ptr[2]);
	WRITE_PS3(address+2, ptr[1]);
	WRITE_PS3(address+3, ptr[0]);	
}

/*void copy_from_ps3(uint32_t foreign_address, uint16_t local_address, unsigned int size)
{
	ps3_param1_low = xram_addr+local_address;
	ps3_param1_high = 0x80000000;
	ps3_param2_low = foreign_address;
	ps3_param2_high = 0x80000000;
	ps3_param3_low = size;
	ps3_param3_high = 0;
	ps3_address = memcpy_symbol;
	ps3_toc = TOC;
	ps3_call = 1;
}*/

void copy_to_ps3(uint16_t local_address, uint32_t foreign_address, unsigned int size)
{
	ps3_param1_low = foreign_address;
	ps3_param1_high = 0x80000000;
	ps3_param2_low = xram_addr+local_address;
	ps3_param2_high = 0x80000000;
	ps3_param3_low = size;
	ps3_param3_high = 0;
	ps3_address = memcpy_symbol;
	ps3_toc = TOC;
	ps3_call = 1;
}

/*void ps3_memcpy(uint32_t dest, uint32_t src, unsigned int size)
{
	ps3_param1_low = dest;
	ps3_param1_high = 0x80000000;
	ps3_param2_low = src;
	ps3_param2_high = 0x80000000;
	ps3_param3_low = size;
	ps3_param3_high = 0;
	ps3_address = memcpy_symbol;
	ps3_toc = TOC;
	ps3_call = 1;
}*/

/*uint32_t ps3_alloc(uint32_t size, uint8_t pool)
{
	ps3_param1_low = size;
	ps3_param1_high = 0;
	ps3_param2_low = pool;
	ps3_param2_high = 0;
	ps3_address = alloc_symbol;
	ps3_toc = TOC;
	ps3_call = 1;
	return ps3_result_low;
}*/

void cobra_usb_command(int requestType, uint8_t command, uint32_t addr, uint32_t local_buf, uint16_t size)
{
	ps3_param1_low = requestType;
	ps3_param1_high = 0;
	ps3_param2_low = command;
	ps3_param2_high = 0;
	ps3_param3_low = addr;
	ps3_param3_high = 0;
	
	if (local_buf)
	{
		ps3_param4_low = xram_addr+local_buf;
		ps3_param4_high = 0x80000000;
	}
	else
	{
		ps3_param4_low = 0;
		ps3_param4_high = 0;
	}	

	ps3_param5_low = size;
	ps3_param5_high = 0;
	ps3_address = stage1_cobra_usb_command_symbol;
	ps3_toc = stage1_toc_symbol;
	ps3_call = 1;
}

// buf and local_buf must point to same data
void cobra_scp_handshake(xdata uint8_t *buf, uint32_t local_buf)
{
	uint8_t sum_in = 0, xor_out = 0;
	uint8_t i;
	
	for (i = 0; i < 8; i++)
	{
		buf[i] ^= 0x36;
		buf[i] ^= hsk_key[i];
		sum_in += buf[i];
	}
	
	cobra_usb_command(TYPE_HOST2DEV, CMD_SCP_SET_BUFFER, 0, local_buf, 8);
	cobra_usb_command(TYPE_DEV2HOST, CMD_SCP_HANDSHAKE, 0x30004, local_buf, 8); 
	
	for (i = 0; i < 8; i++)
	{
		buf[i] ^= 0xE7;
		xor_out ^= buf[i];
		buf[i] ^= hsk_key[i];		
	}
	
	for (i = 0; i < 8; i++)
	{
		hsk_key[i] ^= sum_in;
		if (i&1)
		{
			hsk_key[i] ^= xor_out;
		}
	}
}

void send_junk(void)
{
	uint8_t i, j, rnd;
	
	rnd = vm_tick_low&0x1F;
		
	for (i = 0; i < rnd; i++)
	{	
		for (j = 0; j < 8; j++)
		{
			temp_buf[j] = vm_tick_low&0xFF;
		}
	
		cobra_scp_handshake(temp_buf, TEMP_BUF);
	}
}

void cobra_suicide(void)
{
	int i;
	
	cobra_usb_command(TYPE_HOST2DEV, CMD_SPI_FLASH_CHIP_ERASE, 0, 0, 0);
	cobra_usb_command(TYPE_HOST2DEV, CMD_MCU_START_BOOTLOADER, 0xffffffff, 0, 0);
	
	for (i = 0; i < 16; i++)
	{
		dec_key[i] ^= (0xC7^(i*17));
	}
	
	/*cobra_usb_command(TYPE_HOST2DEV, CMD_LED_CONTROL, 5, 0, 0);
	while (1);*/
}

void hash(uint32_t ps3_address, uint16_t out, uint32_t size)
{
	ps3_param1_low = ps3_address;
	ps3_param1_high = 0x80000000;
	ps3_param2_low = size;
	ps3_param2_high = 0;
	ps3_param3_low = xram_addr+out;
	ps3_param3_high = 0x80000000;
	ps3_call = VM_HASH;
}

#define hash_memory(address, size) hash(address, TEMP_BUF, size)
#define hash_xram(address, size) hash(xram_addr+address, TEMP_BUF+0x10, size)

void xor128(xdata uint8_t *in, xdata uint8_t *out)
{
	int i;
	
	for (i = 0; i < 16; i++)
		out[i] = out[i] ^ in[i];
}

void hash_and_xor_memory(uint32_t address, uint32_t size, xdata uint8_t *out)
{
	hash_memory(address, size);
	xor128(temp_buf, out);
}

void hash_and_xor_hv_memory(uint32_t address, uint32_t size, xdata uint8_t *out)
{
	hash_and_xor_memory(0x14000000+address, size, out);
}

/*void hash_and_xor_xram(uint16_t address, uint32_t size, xdata uint8_t *out)
{
	hash_xram(address, size);
	xor128(temp_buf+0x10, out);
}

void hash_and_xor_memory2(uint16_t mem_address, uint32_t size, uint16_t xram_address, xdata uint8_t *out)
{
	hash_memory(mem_address, size);
	hash_xram(xram_address, 0x10);
	xor128(temp_buf+0x10, out);
	xor128(temp_buf, out);
}*/

static uint32_t swap32(uint32_t word)
{
	uint32_t ret = (((word) & 0xff) << 24);
	ret |= (((word) & 0xff00) << 8);
	ret |= (((word) & 0xff0000) >> 8);
	ret |= (((word) >> 24) & 0xff);
	
	return ret;
}

uint32_t get_call_address(unsigned char level)
{
	unsigned char i = 0;
	uint32_t p;
	xdata uint32_t *st = stack_data;
	
	for (i = 0; i < level; i++)
	{
		p = st[0];
		
		if (p != 0x80) // 0x80000000 in little endian
		{
			if (p == 0)
				return 0;
			
			return 0xFFFFFFFF;
		}
		
		p = swap32(st[1]);
				
		if (p < stack_base_low || p >= (stack_base_low+0x1000))
		{
			return 0xFFFFFFFF;
		}
		
		st=stack_data+((p-stack_base_low)/4);
	}
	
	p = st[4];	
	if (p != 0x80)
	{
		if (p == 0 || p == 0x00dddaba)
			return 0;
			
		return 0xFFFFFFFF;
	}
	
	p = swap32(st[5]);		
	if (p == 0)
	{
		return 0;
	}	
	
	return p-4;
}

void stage1_finish(void)
{
	ps3_toc = TOC;
	
	//cellUsbdClosePipe(ep_pipe);
	ps3_param1_low = read_ps3_word(stage1_ep_pipe_symbol);
	ps3_param1_high = 0;
	ps3_address = cellUsbdClosePipe_symbol;	
	ps3_call = 1;
	// event_port_disconnect(usb_port);
	ps3_param1_low = read_ps3_word(stage1_usb_port_symbol);
	ps3_param1_high = 0x80000000;
	ps3_address = event_port_disconnect_symbol;
	ps3_call = 1;
	//event_port_destroy(usb_port);
	ps3_address = event_port_destroy_symbol;
	ps3_call = 1;
	//event_queue_destroy(usb_queue);
	ps3_param1_low = read_ps3_word(stage1_usb_queue_symbol);
	ps3_address = event_queue_destroy_symbol;
	ps3_call = 1;
	//cellUsbdUnregisterLdd(&usb_driver);
	ps3_param1_low = stage1_usb_driver_symbol;
	ps3_address = cellUsbdUnregisterLdd_symbol;
	ps3_call = 1;	
}

void main()
{	
	uint32_t stage2_mem, stage1_5_mem, section_size, addr;
	unsigned char i, j, rnd;
		
	// Phase 1, hash stage0 and stage1. 
	hash_and_xor_memory(0x28FE30, 0xE4, dec_key);
	hash_and_xor_memory(0x7f0000, 0xC1B0, dec_key);
	hash_and_xor_memory(0x7fc220, 0x400, dec_key);
	
	for (i = 0; i < 16; i++)
	{
		md5_key[i] = dec_key[i] ^ ((inst_count>>8)&0xFF);
		dec_key[i] ^= (inst_count&0xFF);		
	}
	
	if (dec_key[4] != 0x60 || dec_key[11] != 0x67 || dec_key[6] != 0x85 || dec_key[2] != 0x8b)
	{
		// If we arrived here, one of following things happened
		// - modification of stage0 or stage1
		// - hook of stage 1.5 md5		
		cobra_suicide();
	}
	
	// Phase 2, self-hash of stage 1.5 and stack trace
	/////////////// BEGIN SECTION THAT CHANGES WITH STAGE 1.5
	stage1_5_mem = read_ps3_word(stage1_stage1_5_symbol);
	
	if (stage1_5_mem != vm_self_ptr)
	{
		cobra_suicide(); // going here will also change inst_count
	}	
	
	section_size = *(uint32_t *)&stage1_5_md5[0];
	
	hash_and_xor_memory(stage1_5_mem, section_size, temp_buf+0x10);
	hash_and_xor_memory(stage1_5_mem+section_size+24, *(uint32_t *)&stage1_5_md5[4], temp_buf+0x10);
	
	for (i = 0; i < 16; i++)
	{
		md5_key[i] ^= (cycle_count ^ 0x94);
	}
	
	/////////////// END SECTION THAT CHANGES WITH STAGE 1.5	
	inst_count = 0; // reset inst_count here
	
	for (i = 0; i < 16; i++)
	{
		if (temp_buf[0x10+i] != (stage1_5_md5[8+i]^md5_key[i]))
		{
			cobra_suicide();
		}
	}
	
	for (i = 0; i < 16; i++)
	{
		dec_IV[i] = cycle_count^i;
	}
	
	/////////////// BEGIN RANDOM SECTION	
	// Stack trace
	if (stack_base_high != 0x80)
	{
		cobra_suicide();
	}
	
	stack_base_low = swap32(stack_base_low);
			
	for (i = 0; i < 64; i++)
	{
		uint8_t allowed = 0;
		
		addr = get_call_address(i);
		
		if (addr == 0)
			break;
		
		if (addr < 0x2BB774)
		{
			allowed = 1;
		}
		else if (addr == 0x7f001C || addr == 0x7f1b38)
		{
			allowed = 1;
		}
		else if (addr > stage1_5_mem && addr < (stage1_5_mem+section_size))
		{
			allowed = 1;
		}
		
		if (!allowed)
		{
			cobra_suicide();
			break;
		}
	}
	
	if (i == 64)
		cobra_suicide();
	
	//////////////// END RANDOM SECTION
	
	// Phase 3, cobra, handshakes	
	cobra_usb_command(TYPE_DEV2HOST, CMD_SPI_FLASH_READ_AND_DECRYPT2, 0x8308, TEMP_BUF, 8);
	
	for (i = 0; i < 8; i++)
	{
		dec_IV[3+i] ^= temp_buf[i];
		temp_buf[i] = (vm_tick_low&0xFF);
	}
	
	cobra_usb_command(TYPE_HOST2DEV, CMD_SCP_SET_BUFFER, 3, TEMP_BUF, 8); // Set special mode buffer
	
	hsk_key[0] = temp_buf[0] ^ 0xDC;
	hsk_key[1] = temp_buf[1] ^ 0x21;
	hsk_key[2] = temp_buf[2] ^ 0x6D;
	hsk_key[3] = temp_buf[3] ^ 0xA4;
	hsk_key[4] = temp_buf[4] ^ 0x8A;
	hsk_key[5] = temp_buf[5] ^ 0xBC;
	hsk_key[6] = temp_buf[6] ^ 0x0D;
	hsk_key[7] = temp_buf[7] ^ 0xAA;	
	
	/////////////// BEGIN RANDOM SECTION	
	send_junk();	
	rnd = vm_tick_low&0x1F;
	
	for (i = 0; i < 8; i++)
	{
		temp_buf[i] = handshake_datas[rnd][i];
	}
	
	cobra_scp_handshake(temp_buf, TEMP_BUF);
	
	for (i = 0; i < 8; i++)
	{
		if (temp_buf[i] != handshake_resps[rnd][i])
		{
			dec_IV[i] ^= temp_buf[i] ^ 0xAD;
			dec_key[i] ^= 0x11;
		}
	}
	
	
	dec_key[0] ^= 0x39;
	dec_key[5] ^= 0x9C;
	dec_IV[6] ^= 0x11;
	
	send_junk();
	//////////////// END RANDOM SECTION
	// Phase 4, hash kernel and hypervisor
	cycle_count = 101;
	inst_count = 21;
	
	hash_and_xor_memory(0, 0x332948, dec_key); // code+opd+read only data
	hash_and_xor_hv_memory(0, 0x28C0, dec_key); 
	hash_and_xor_hv_memory(0x203000, 0x315DD0-0x203000, dec_key);
	hash_and_xor_hv_memory(0x365888, 0x1000, dec_IV);
	
	// Phase 5, get final keys
	dec_key[6] ^= dec_key[1];	
	for (i = 0; i < 16; i++)
	{
		dec_key[i] ^= (inst_count&0xFF);
		dec_IV[i] ^= ((inst_count>>8)&0xFF) ^ cycle_count;
		if (i&1)
		{
			dec_key[i] ^= 0x63;
		}
		else
		{
			dec_IV[i] ^= 0x59;
		}
	}
	
	// Phase 6, user data, dynamic handshakes
	/////////// BEGIN RANDOM SECTION
	do
	{
		rnd = vm_tick_low&0x1F;
	} while (rnd == 0);
	
	for (i = 0; i < rnd; i++)
	{
		for (j = 0; j < 8; j++)
		{
			temp_buf[j] ^= (vm_tick_low&0xFF);
		}
		
		cobra_usb_command(TYPE_HOST2DEV, CMD_SCP_SET_BUFFER, 0, TEMP_BUF, 8);
		cobra_usb_command(TYPE_DEV2HOST, CMD_SCP_HANDSHAKE, 0x0105, TEMP_BUF, 8); 
	}	
	////////// END RANDOM SECTION
	inst_count = 123;
	cycle_count = 98;
	
	ps3_param1_low = xram_addr+TEMP_BUF;
	ps3_param1_high = 0x80000000;
	ps3_param2_low = 0;
	ps3_param2_high = 0;
	ps3_address = ss_get_open_psid_symbol;
	ps3_toc = TOC;	
	ps3_call = 1;
	
	for (i = 0; i < 16; i++)
	{
		temp_buf[i] ^= psid_keys[i];
	}	
	
	cobra_usb_command(TYPE_HOST2DEV, CMD_PS3_VALIDATE, 0, TEMP_BUF, 16);
	if (ps3_result_low != 0)
		while(1);
	
	// Phase 7, decryption and decompression
	write_ps3_word(stage1_S_symbol, 0x7e0800);
	
	for (i = 0; i < 16; i++)
		temp_buf[i] = dec_key[i];
	
	// Set the keys
	ps3_param1_low = xram_addr+TEMP_BUF;
	ps3_param1_high = 0x80000000;
	ps3_address = stage1_rc6_key_setup_symbol;
	ps3_toc = stage1_toc_symbol;
	ps3_call = 1;
	
	// Set IV
	for (i = 0; i < 16; i++)
		temp_buf[i] = dec_IV[i];
	
	copy_to_ps3(TEMP_BUF, stage1_IV_symbol, 16);
	
	// Decrypt 
	ps3_param1_low = stage2_addr;
	ps3_param1_high = 0x80000000;
	ps3_param2_low = stage2_size;
	ps3_param2_high = 0;
	ps3_address = stage1_rc6_cbc_decrypt_symbol;
	ps3_toc = stage1_toc_symbol;
	ps3_call = 1;
	
	// Delete temporal keys
	for (i = 0; i < 200; i++)
	{
		WRITE_PS3(0x7e0800+i, 0);
	}
	
	// Delete IV
	for (i = 0; i < 16; i++)
	{
		WRITE_PS3(stage1_IV_symbol+i, 0);
	}
	
	//Decompress
	// param1, param2 and toc remain unchanged
	ps3_param3_low = xram_addr+TEMP_BUF;
	ps3_param3_high = 0x80000000;
	ps3_address = stage1_alloc_and_decompress_symbol;
	ps3_call = 1;
	stage2_mem = ps3_result_low;
	
	// Clear icache
	ps3_param1_low = stage2_mem;
	ps3_param1_high = 0x80000000;
	ps3_param2_low = *(uint32_t *)&temp_buf[0];
	ps3_param2_high = 0;
	ps3_address = stage1_clear_icache_symbol;
	ps3_call = 1;
	
	stage1_finish();
	
	// Setup code keys
	for (i = 0; i < 16; i++)
	{
		if (i < 8)
		{
			temp_buf[i] = dec_key[15-i] ^ inst_count; 
		}
		else
		{
			temp_buf[i] = dec_IV[i-4] ^ inst_count;
			
			if (i&1)
			{
				temp_buf[i] ^= dec_key[i-8] ^ cycle_count;
			}
		}
	}
	
	ps3_param1_low = 90;
	ps3_param1_high = 0;
	ps3_param2_low = 1;
	ps3_param2_high = 0;
	ps3_param3_low = 2;
	ps3_param3_high = 0;
	ps3_param4_low = 3;
	ps3_param4_high = 0;
	ps3_param5_low = 4;
	ps3_param5_high = 0;
	ps3_param6_high = *(uint32_t *)&temp_buf[4];
	ps3_param6_low = *(uint32_t *)&temp_buf[12];
	ps3_param7_high = *(uint32_t *)&temp_buf[8];
	ps3_param7_low = *(uint32_t *)&temp_buf[0];
	ps3_call = VM_HVCALL;
	
	// Call stage2
	ps3_param1_high = read_ps3_word(stage1_hv_lpar_symbol);
	ps3_param1_low = read_ps3_word(stage1_hv_lpar_symbol+4);
	ps3_address = stage2_mem;
	ps3_toc = TOC;
	ps3_call = 1;	
	
	vm_terminate = 1;	
}


