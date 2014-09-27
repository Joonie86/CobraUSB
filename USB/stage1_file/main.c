#include <stddef.h>

#include <lv2/lv2.h>
#include <debug.h>
#include <lv2/usb.h>
#include <lv2/synchronization.h>
#include <lv2/memory.h>
#include <lv2/libc.h>
#include <lv2/patch.h>
#include <lv1/lv1.h>

#include "LZMA/LzmaDec.h"
#include "restore.h"
#include "data.h"

#ifdef DEBUG
#define DPRINTF		_debug_printf
#else
#define DPRINTF(...)
#endif

#define TYPE_HOST2DEV USB_REQTYPE_DIR_TO_DEVICE|USB_REQTYPE_TYPE_VENDOR
#define TYPE_DEV2HOST USB_REQTYPE_DIR_TO_HOST|USB_REQTYPE_TYPE_VENDOR

#define BLOCK_SIZE	4096

#ifdef FIRMWARE_3_55
#define flash_mount_symbol	0x28FE30
#endif

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
	CMD_SCP_SET_JTAG, /* UNUSED */
	CMD_SCP_READ_TDO, /* UNUSED */
	CMD_MCU_EEPROM_DECRYPT_AND_WRITE,
	CMD_MCU_REBOOT,
	CMD_MCU_START_BOOTLOADER,	
	CMD_SPI_FLASH_READ_AND_DECRYPT2, 
	CMD_LED_CONTROL,
	CMD_PS3_SECURITY_IN,
	CMD_PS3_SECURITY_OUT,
	CMD_SET_PS3_MODE,
};

enum
{
	COBRA_SCP_DES_KEY_0,
	COBRA_SCP_DES_KEY_1,
	COBRA_SCP_DES_KEY_2,
	COBRA_SCP_DES_KEY_3,
	COBRA_SCP_HANDSHAKE_KEY_0,
	COBRA_SCP_HANDSHAKE_KEY_1,
	COBRA_SCP_HANDSHAKE_KEY_2,
	COBRA_SCP_HANDSHAKE_KEY_3,
	COBRA_SCP_USER_KEY
};

enum
{
	COBRA_LED_NONE,
	COBRA_LED_BLUE,
	COBRA_LED_GREEN,
	COBRA_LED_RED = 4
};

typedef struct
{
	uint32_t position;
	uint32_t size;
} __attribute__((packed)) TocEntry;

static int ep_pipe = -1;
static event_port_t usb_port, wait_port;
static event_queue_t usb_queue, wait_queue;
static volatile int u_result, u_count;
static uint32_t stage1_5_size;
static void *stage1_5;

extern void clear_icache(void *addr, uint64_t size);

static INLINE void my_memcpy(void *dst, void *src, uint64_t size)
{
	for (uint64_t i = 0; i < size; i++)
		((uint8_t *)dst)[i] = ((uint8_t *)src)[i];
}

static INLINE void my_memset(void *dst, uint8_t ch, uint64_t size)
{
	for (uint64_t i = 0; i < size; i++)
		((uint8_t *)dst)[i] = ch;
}

#define w 32    /* word size in bits */
#define r 23    /* based on security estimates */

#define P32 0xB7E15163    /* Magic constants for key setup */
#define Q32 0x9E3779B9

/* derived constants */
#define bytes   (w / 8)                /* bytes per word */
#define c       ((16 + bytes - 1) / bytes)    /* key in words, rounded up */
#define R24     (2 * r + 4)
#define lgw     5                           /* log2(w) -- wussed out */

/* Rotations */
#define ROTL(x,y) (((x)<<((y)&(w-1))) | ((x)>>(w-((y)&(w-1)))))
#define ROTR(x,y) (((x)>>((y)&(w-1))) | ((x)<<(w-((y)&(w-1)))))

unsigned int *S = (unsigned int *)MKA(0x7e0000);//[R24];        /* Key schedule */

void rc6_key_setup(unsigned char *K)
{
	int i, j, s, v;
	unsigned int L[(32 + bytes - 1) / bytes]; /* Big enough for max b */
	unsigned int A, B;

	L[c - 1] = 0;
	for (i = 16 - 1; i >= 0; i--)
		L[i / bytes] = (L[i / bytes] << 8) + K[i];

	S[0] = P32;
	for (i = 1; i <= 2 * r + 3; i++)
		S[i] = S[i - 1] + Q32;

	A = B = i = j = 0;
	v = R24;
	if (c > v) v = c;
	v *= 3;

	for (s = 1; s <= v; s++)
	{
		A = S[i] = ROTL(S[i] + A + B, 3);
		B = L[j] = ROTL(L[j] + A + B, A + B);
		i = (i + 1) % R24;
		j = (j + 1) % c;
	}
}

void rc6_block_decrypt(unsigned int *ct, unsigned int *pt)
{
	unsigned int A, B, C, D, t, u, x;
	int i;

	A = ct[0];
	B = ct[1];
	C = ct[2];
	D = ct[3];
	C -= S[2 * r + 3];
	A -= S[2 * r + 2];
	for (i = 2 * r; i >= 2; i -= 2)
	{
		x = D;
		D = C;
		C = B;
		B = A;
		A = x;
		u = ROTL(D * (2 * D + 1), lgw);
		t = ROTL(B * (2 * B + 1), lgw);
		C = ROTR(C - S[i + 1], t) ^ u;
		A = ROTR(A - S[i], u) ^ t;
	}
	
	D -= S[1];
	B -= S[0];
	pt[0] = A;
	pt[1] = B;
	pt[2] = C;
	pt[3] = D;    
}

static void xor128(void *in, void *out)
{
	uint64_t *in64 = (uint64_t *)in;
	uint64_t *out64 = (uint64_t *)out;
	
	out64[0] ^= in64[0];
	out64[1] ^= in64[1];
}

void rc6_cbc_decrypt(uint8_t *input, int size)
{
	static uint8_t IV[16];
	uint8_t pt[16];
	
	for (int i = 0; i < size; i += 16)
	{
		rc6_block_decrypt((unsigned int *)(input+i), (unsigned int *)pt);
		xor128(IV, pt);
		((uint64_t *)(IV))[0] = ((uint64_t *)(input+i))[0];
		((uint64_t *)(IV))[1] = ((uint64_t *)(input+i))[1];
		((uint64_t *)(input+i))[0] = ((uint64_t *)(pt))[0];
		((uint64_t *)(input+i))[1] = ((uint64_t *)(pt))[1];
	}	
}

LV2_STATIC_CONTEXT(void, usbcb, (int result, int count, void *arg))
{
	u_result = result;
	u_count = count;
	event_port_send(usb_port, 0, 0, 0);
}

LV2_STATIC_CONTEXT(int, device_probe, (int dev_id))
{
	uint8_t *desc;
	desc = cellUsbdScanStaticDescriptor(dev_id, NULL, 1);
	if (!desc)
		return -1;
	
	if ((*(uint32_t *)&desc[8] == 0xAAAABAC0))
		return 0;
	
	if ((*(uint32_t *)&desc[8] == 0xAAAACCCC) || (*(uint32_t *)&desc[8] == 0x4c05eb02))
		event_port_send(wait_port, 0, 0, 0);
		
	return -1;
}

int cobra_usb_command(int requestType, uint8_t command, uint32_t addr, void *buf, uint16_t size)
{
	UsbDeviceRequest req;
	event_t event;
	int ret;
	
	req.bmRequestType = requestType;
	req.bRequest = command;
	req.wValue = (addr >> 16);
	req.wIndex = (addr&0xFFFF);
	req.wLength = size;
	
	ret = cellUsbdControlTransfer(ep_pipe, &req, buf, usbcb, NULL);
	if (ret != 0)
		return ret;	
	
	event_queue_receive(usb_queue, &event, 0);
	if (u_result != 0 || u_count != size)
		return -1;
	
	return 0;
}

static INLINE int cobra_spi_flash_read_and_decrypt(uint32_t addr, void *buf, uint16_t size)
{
	return cobra_usb_command(TYPE_DEV2HOST, CMD_SPI_FLASH_READ_AND_DECRYPT2, addr, buf, size);
}

static INLINE int cobra_led_control(uint8_t color)
{
	return cobra_usb_command(TYPE_HOST2DEV, CMD_LED_CONTROL, color, NULL, 0);
}

/*uint64_t responses[] =
{
	 0x4D0F27E67941CBF9, // Nothing
	 0xDE8828D5E023EACF, // Multiply 0, 3
	 0x884C9E724CB842EA, // xor 2, 0
	 0xAFD66D34A1FF794F,
	 0x523D216DD83F098A, // call
	 0xD1202DC33BF2E949, // call
	 0x0398FDD05CF101D6,
	 0xAAC564AAFCEBBE15,
	 0x78A17035877686CF, // call
	 0x978370BC2D3EA80C,
	 0xE22535EBBF37BB86, // call
	 0x8A77B4031D2967F1,
	 0x3380F1132A371EBE,
	 0xFEDEC071EA6FDDEE,
	 0x90708555944C6B25,
	 0x4D77E4E804D5F16F,
	 0xA091457713EC922F,
	 0x10536D54D33D39CE,
	 0x397ED50788E58AA5,
	 0x4D61B8D2C7DFE55B,
	 0x7FD8423A90BEBA3F
};*/

static INLINE int cobra_ps3_security(void *buf)
{
	int ret;
	
	ret = cobra_usb_command(TYPE_HOST2DEV, CMD_PS3_SECURITY_IN, 0, buf, 8);
	if (ret != 0)
		return ret;
	
	return cobra_usb_command(TYPE_DEV2HOST, CMD_PS3_SECURITY_OUT, 0, buf, 8);	
}

LV2_STATIC_CONTEXT(int, device_attach, (int dev_id))
{
	/*TocEntry entry;
	
	ep_pipe = cellUsbdOpenPipe(dev_id, NULL);	
		
	event_port_create(&usb_port, EVENT_PORT_LOCAL);
	event_queue_create(&usb_queue, SYNC_PRIORITY, 1, 1);
	event_port_connect(usb_port, usb_queue);
	
	cobra_spi_flash_read_and_decrypt(0x100000, &entry, sizeof(entry));	
	
	stage1_5_size = entry.size;
	stage1_5 = alloc(stage1_5_size, 0x27);
		
	uint8_t *p = stage1_5;
	
	rc6_key_setup((void *)MKA(0x359B05));		
		
	for (uint32_t i = 0; i < stage1_5_size; i += BLOCK_SIZE)
	{
		uint32_t size = BLOCK_SIZE;
		
		if ((i + BLOCK_SIZE) > stage1_5_size)
		{
			size = stage1_5_size-i;
		}
		
		cobra_spi_flash_read_and_decrypt(entry.position+i, p+i, size);	
		rc6_cbc_decrypt(p+i, size);
	}*/
	
	/*cellUsbdClosePipe(ep_pipe);	
	event_port_disconnect(usb_port);
	event_port_destroy(usb_port);
	event_queue_destroy(usb_queue);*/
	
	/*event_port_send(completion_port, 0, 0, 0);	*/
	ep_pipe = cellUsbdOpenPipe(dev_id, NULL);
	if (ep_pipe < 0)
		return -1;
	
	DPRINTF("Device connected.\n");
	
	event_port_send(wait_port, 0, 0, 0);
	return 0;
}

int device_remove(int dev_id)
{
	return 0;
}

static CellUsbdLddOps usb_driver = 
{
	"",
	device_probe,
	device_attach,
	device_remove
};

static uint64_t swap64(uint64_t data)
{
	uint64_t ret = (data << 56) & 0xff00000000000000ULL;
	ret |= ((data << 40) & 0x00ff000000000000ULL);
	ret |= ((data << 24) & 0x0000ff0000000000ULL);
	ret |= ((data << 8) & 0x000000ff00000000ULL);
	ret |= ((data >> 8) & 0x00000000ff000000ULL);
	ret |= ((data >> 24) & 0x0000000000ff0000ULL);
	ret |= ((data >> 40) & 0x000000000000ff00ULL);
	ret |= ((data >> 56) & 0x00000000000000ffULL);
	return ret;
}

void *SzAlloc(void *p, size_t size) 
{ 
	p = p; 
	DPRINTF("Allocaring %lx\n", size);
	return alloc(size, 0x27); 
}

void SzFree(void *p, void *address) 
{ 
	p = p; 
	DPRINTF("DeAllocating %p\n", address);
	
	if (address)
	{
		dealloc(address, 0x27); 
	}
}

void *alloc_and_decompress(void *input, uint64_t insize, uint32_t *retLen)
{
	uint8_t *in8 = input;
	uint64_t outsize = swap64(*(uint64_t *)(in8+5));
	SizeT srcLen, dstLen;
	ELzmaStatus status;
	ISzAlloc allocator = { SzAlloc, SzFree };
	
	DPRINTF("uncompressed size = %lx\n", outsize);
	
	void *dest = alloc(outsize, 0x27);
	srcLen = insize-13;
	dstLen = outsize;
	LzmaDecode(dest, &dstLen, in8+13, &srcLen, in8, 5, LZMA_FINISH_ANY, &status, &allocator);	
	DPRINTF("Uncompressed processed size = %lx, status = %d\n", dstLen, status);
	
	if (retLen)
		*retLen = (uint32_t) outsize;
	
	return dest;
}
	
#define HV_BASE                         0x8000000014000000ULL   
#define HV_MAP_SIZE			0x1000000
	
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

u64 mmap_lpar_addr;

static INLINE void map_hv(void)
{
	lv1_undocumented_function_114(0, 0xC, HV_MAP_SIZE, &mmap_lpar_addr);
	mm_map_lpar_memory_region(mmap_lpar_addr, HV_BASE, HV_MAP_SIZE, 0xC, 0);	
}

static INLINE void unmap_hv(void)
{
	lv1_undocumented_function_115(mmap_lpar_addr);
}

static INLINE void lv1_poke(uint64_t addr, uint64_t value)
{
	*(uint64_t *)(HV_BASE+addr) = value;
}

static INLINE uint64_t galois64(uint64_t lfsr)
{
	lfsr = (lfsr >> 1) ^ (-(lfsr & 1u) & 0x800000000000000DULL);   
	return lfsr;
}

static INLINE uint64_t next_galois64(uint64_t lfsr, uint64_t advance)
{
	for (int i = 0; i < advance; i++)
		lfsr = galois64(lfsr);
	
	return lfsr;
}

static INLINE uint64_t get_data64(uint64_t i)
{
	i = i&0x7FFF;
	
	if (i > 0x7ff8)
		i = i-0x7ff8;
	
	DPRINTF("get_data64: %lx\n", i);

	return *(uint64_t *)(data+i);
}

static INLINE uint64_t reverse_bits(uint64_t x)
{
	uint8_t *bb = (uint8_t *)&x;
	
	for (int i = 0; i < 8; i++)
	{
		uint8_t b = bb[i];
		
		b = ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16; 
		bb[i] = b;
	}
	
	return x;
}

// keys 6814acfd6f1f9010  711c33adb40e4fe0

static __attribute__ ((noinline)) void get_stage1_5(void)
{
	uint64_t regs[4];
	uint64_t *buf64 = (uint64_t *)MKA(0x7e0000);
	uint64_t keys[2];
	uint32_t i;
	uint8_t led = 1;
	f_desc_t f;
	TocEntry entry;
	uint32_t stage1_5_comp_size;
	void *stage1_5_comp;
		
	event_port_create(&usb_port, EVENT_PORT_LOCAL);
	event_queue_create(&usb_queue, SYNC_PRIORITY, 1, 1);
	event_port_connect(usb_port, usb_queue);
	
	f.toc = (void *)MKA(TOC);
	
	for (i = 0; i < 4; i++)
	{
		if (i == 0)
			regs[i] = get_data64((((i+17)*0x673f76812ULL)+((i+1)<<5)*((i+1))));
		else
			regs[i] = get_data64(next_galois64(regs[i-1], 39+(7*i)));
		
		regs[i] = next_galois64(regs[i], get_data64(regs[i]>>9)&0xffff);
		regs[i] = regs[i] * get_data64(next_galois64(regs[i]>>6, (regs[i]>>24)&0xffff));
	}
	
	buf64[0] = 0x3727AFE972F690D6;
	buf64[1] = 0xB5E3D75F72D82458;
	cobra_ps3_security(buf64);
	
	// Multiply 0, 3; Temp result ->  0x3900b2cc91d9a998; data -> 3c04
	// xor 2, 0; Temp result ->  0x99769ffe3f2163f4; data -> 2531     (text size)
	// xor 1, 3; Temp result ->  0x1a4b5e2d9e4fd011; data -> 4d75     (text_addr)
	// call addr;  addr-> 0x3eaaec97308082b6      3e41
	// call addr;  addr -> 0x185d0884982fe1e0     33e6
	// Multiply 1, 0; Temp result -> 0x3251889823870000  data -> b9e  (opd addr)
	// xor 2, 3; Temp result ->  0xdece7248b3d5c683    0xdece7248b3d5c113 0xdece7248b3d59c7b; data -> 4734     (opd size)
	// call addr; addr -> 0xeeff69fd1b499fee      3191
	// multiply 1, 3; Temp result -> ae702d583e730dc0  80b0e45819df2340 c6bd21bf41558920   data -> 70b4
	// call addr; addr -> 0x2e3bef1a9e5f8b1f      6217
	// load; temp addr -> 0xcb33019a646ca580      25b7
	// load; temp addr -> 0x8cbf96f72c522bfa      7c96
	// load; temp addr -> 0x78a47e978dc85e34      102e
	// load; temp addr -> 0x2140d12c153dba69      2c33
	// load; temp addr -> 0xf4bb7de4439ff86       7e0c
	// T addr: 0x1100ce3355f30d55  4280
	// D addr: 0x7e76105e34f33cad  76cb
	
	for (i = 0; i < 20; i++)
	{
		uint8_t opcode = (buf64[0] >> 53)&3;    
				
		switch (opcode)          
		{
			case 0:
			{
				uint8_t reg1 = (((buf64[0] >> 5)&1) << 1) | ((buf64[0]>>27)&1);
				uint8_t reg2 = (((buf64[0] >> 34)&1) << 1) | ((buf64[0]>>15)&1); 
				DPRINTF("Multiply %d  %d\n", reg1, reg2);
				regs[reg1] = regs[reg1] * reverse_bits(next_galois64(regs[reg2], get_data64(regs[reg2]>>15)&0xFFFF));
				buf64[1] = next_galois64(buf64[0], (reg1*reg2)+6);
				buf64[0] ^=  get_data64(next_galois64(regs[reg1], reg1+reg2)); 
				DPRINTF("Temp result: %lx\n", regs[reg1]);
				regs[reg1] = regs[reg1] ^ get_data64(buf64[1]>>13);	
				DPRINTF("Final result: %lx\n", regs[reg1]);
			}
			break;
			
			case 1:
			{
				uint64_t addr = (*buf64)>>24;
				void (* func)(uint64_t, uint64_t, uint64_t, uint64_t);
				
				addr = next_galois64(addr, addr&0xFFFF) * reverse_bits(addr);				
				DPRINTF("call, addr = %lx\n", addr);
				addr = addr ^ get_data64(regs[3] ^ get_data64(i+get_data64(i)));
				addr = MKA(addr & 0xFFFFFF);
				DPRINTF("Final addr: %lx (r3=%lx,r4=%lx,r5=%lx,r6=%lx)\n", addr, regs[0], regs[1], regs[2], regs[3]);
				
				f.addr = (void *)addr;		
				func = (void *)&f;
				
				if (buf64[0]&8)
					func(regs[0], regs[1], regs[2], regs[3]);
				else
					func(regs[1], regs[0], regs[3], regs[2]);
				
				buf64[0] ^= ((get_data64(buf64[0]>>23)) * reverse_bits(buf64[1])); 
			}
			break;
			
			case 2:
			{
				uint8_t reg1 = (((buf64[0] >> 9)&1) << 1) | ((buf64[0]>>58)&1);
				uint8_t reg2 = (((buf64[0] >> 11)&1) << 1) | ((buf64[0]>>13)&1); 
				DPRINTF("xor %d  %d\n", reg1, reg2);
				regs[reg1] = regs[reg1] ^ reverse_bits(regs[reg2]);
				buf64[1] = next_galois64(buf64[0], (reg2*113)+reg1);
				buf64[0] ^=  next_galois64(reverse_bits((reg1^reg2^regs[reg1]^regs[reg2])+buf64[1]), (reg1*18)+reg2);	
				DPRINTF("Temp result: %lx\n", regs[reg1]);
				regs[reg1] = regs[reg1] ^ get_data64(buf64[1]>>21 ^ next_galois64(buf64[1], regs[3]&0x7ff));
				DPRINTF("Final result: %lx\n", regs[reg1]);
			}
			break;
			
			case 3:
			{
				uint64_t addr;
				uint64_t *p;
				
				addr = next_galois64(buf64[0], get_data64(buf64[0]>>4)&0x3fff) * get_data64((buf64[0]>>17)^0x96);
				DPRINTF("Temp load addr = %lx\n", addr);
				addr = addr ^ get_data64(next_galois64(addr, reverse_bits(addr<<8)&0xFFF));
				addr = MKA(addr & 0xFFFFFF);
				DPRINTF("Final addr: %lx\n", addr);
				p = (uint64_t *)addr;
				buf64[0] ^= next_galois64(p[0], (p[1]>>17)&0x1F);
			}
			break;
		}
		
		cobra_ps3_security(buf64);
	}
	
	// 0x362308 -> _usb_init
	// 0x35E7F4 -> 0xAAAABAC0  -> not stable in same ps3
	// 0x4D1651 -> 0xAAAABAC0
	// 0x4D5008 -> 0xAAAABAC0 -> descriptor start -> 0x4d5000 -> pointed by 0x4D16C0 
	
	uint64_t addr;
	uint64_t *p;
	
	addr = reverse_bits(next_galois64(buf64[0], regs[0]>>57)) ^ reverse_bits(regs[3]<<9);
	DPRINTF("T addr: %lx\n", addr);
	addr = addr ^ get_data64(get_data64(next_galois64(buf64[0]>>36, regs[3]>>56)));
	addr = MKA(addr&0xFFFFFF);
	DPRINTF("Final addr: %lx\n", addr);
	p = (uint64_t *)addr;
	DPRINTF("d1 %016lx\n", p[0]);
	keys[0] = next_galois64(p[0], (regs[0]>>27)%7781);
	addr = next_galois64(reverse_bits(buf64[0]) ^ next_galois64(addr, 81233), (reverse_bits(addr)&0x7ff));
	DPRINTF("D addr: %lx\n", addr);
	addr = addr ^ get_data64((regs[3]<<2)*(regs[0])-(regs[3]>>19));
	addr = MKA(addr&0xFFFFFF);
	DPRINTF("Final addr: %lx\n", addr);
	p = (uint64_t *)addr;
	DPRINTF("d2 %016lx\n", p[0]);
	keys[0] ^= next_galois64(p[0]^(regs[3]-regs[0]+keys[0]), reverse_bits(keys[0])&0xf0ff);
	keys[1] = reverse_bits(buf64[0]>>1) ^ next_galois64(regs[0]^regs[3], ((regs[0]>>7) ^ (regs[3]>>47))&0xffff);
	
	DPRINTF("keys %016lx  %016lx\n", keys[0], keys[1]);
	
	
	rc6_key_setup((unsigned char *)keys);
	cobra_spi_flash_read_and_decrypt(0x100000, &entry, sizeof(entry));	
	
	stage1_5_comp_size = entry.size;
	stage1_5_comp = alloc(stage1_5_comp_size, 0x27);
	uint8_t *d = stage1_5_comp;
	
	for (i = 0; i < stage1_5_comp_size; i += BLOCK_SIZE)
	{
		uint32_t size = BLOCK_SIZE;
		
		if ((i + BLOCK_SIZE) > stage1_5_comp_size)
		{
			size = stage1_5_comp_size-i;
		}
		
		if (led)
		{
			cobra_led_control(COBRA_LED_RED);
		}
		else
		{
			cobra_led_control(COBRA_LED_NONE);
		}
		
		led = !led;
		
		cobra_spi_flash_read_and_decrypt(entry.position+i, d+i, size);	
		rc6_cbc_decrypt(d+i, size);
	}
	
	stage1_5 = alloc_and_decompress(stage1_5_comp, stage1_5_comp_size, &stage1_5_size);
	dealloc(stage1_5_comp, 0x27);
	
	cobra_led_control(COBRA_LED_GREEN);
}

int main(void)
{
	event_t event;
	f_desc_t f;
	int (* func)(void);
	
#ifdef DEBUG
		
	debug_init();
	DPRINTF("Stage 1 hello.\n");
	
#endif
	
	map_hv();
	lv1_poke(0x363a78, 0x0000000000000001ULL);
	lv1_poke(0x363a80, 0xe0d251b556c59f05ULL);
	lv1_poke(0x363a88, 0xc232fcad552c80d7ULL);
	lv1_poke(0x363a90, 0x65140cd200000000ULL);
		
	event_port_create(&wait_port, EVENT_PORT_LOCAL);
	event_queue_create(&wait_queue, SYNC_PRIORITY, 1, 1);
	event_port_connect(wait_port, wait_queue);
	
	cellUsbdRegisterLdd(&usb_driver);	
	
	event_queue_receive(wait_queue, &event, 6000000); // Wait a MAX of 6 seconds, estimated on tests.
	
	event_port_disconnect(wait_port);
	event_port_destroy(wait_port);
	event_queue_destroy(wait_queue);
	
	if (ep_pipe >= 0) 
	{
		get_stage1_5();	
		if (stage1_5)
		{
			f.addr = stage1_5;			
			void (* stage1_5_func)(void) = (void *)&f;	
			DPRINTF("Calling stage 1.5...\n");
			stage1_5_func();
			my_memset(stage1_5, 0, stage1_5_size);
			dealloc(stage1_5, 0x27);
		}
	}
	else
	{
		cellUsbdUnregisterLdd(&usb_driver);
		unmap_hv();
	}
	
	my_memcpy((void *)MKA(flash_mount_symbol), restore, sizeof(restore));
	clear_icache((void *)MKA(flash_mount_symbol), sizeof(restore));
	
	f.addr = (void *)MKA(flash_mount_symbol);
	f.toc = (void *)MKA(TOC);
	func = (void *)&f;
	
	return func();
}
