#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "self.h"

typedef struct
{
	uint8_t keys[16];
	uint64_t nonce;
	uint64_t magic;
} KeySet;

KeySet managerKey = { { 0xD6, 0xFD, 0xD2, 0xB9, 0x2C, 0xCC, 0x04, 0xDD, 0x77, 0x3C, 0x7C, 0x96, 0x09, 0x5D, 0x7A, 0x3B }, 0xBA2624B2B2AA7461ULL, SPRX_EXT_MAGIC };

KeySet pspeKey = { { 0x7A, 0x9E, 0x0F, 0x7C, 0xE3, 0xFB, 0x0C, 0x09, 0x4D, 0xE9, 0x6A, 0xEB, 0xA2, 0xBD, 0xF7, 0x7B }, 	0x8F8FEBA931AF6A19ULL, SPRX_EXT_MAGIC2 };

KeySet vshKey = { { 0xDB, 0x54, 0x44, 0xB3, 0xC6, 0x27, 0x82, 0xB6, 0x64, 0x36, 0x3E, 0xFF, 0x58, 0x20, 0xD9, 0x83 }, 0xE13E0D15EF55C307ULL, SPRX_EXT_MAGIC2+1 };

KeySet vshTBKey = { { 0x63, 0xF0, 0x28, 0x03, 0x71, 0x0F, 0x0E, 0xB6, 0xEA, 0x70, 0xEA, 0xD1, 0x18, 0xE9, 0xF9, 0x82 }, 0xAC434A1609C410D0ULL, SPRX_EXT_MAGIC+6};

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

static uint32_t swap32(uint32_t data)
{
	uint32_t ret = (((data) & 0xff) << 24);
	ret |= (((data) & 0xff00) << 8);
	ret |= (((data) & 0xff0000) >> 8);
	ret |= (((data) >> 24) & 0xff);
	
	return ret;
}

static uint16_t swap16(uint16_t data)
{
	uint32_t ret = (data<<8)&0xFF00;
	ret |= ((data>>8)&0xFF);
	
	return ret;
}

#ifdef WIN32
#include <windows.h>
#include <wincrypt.h>
static void get_rand(void *bfr, uint32_t size)
{
	HCRYPTPROV hProv;
	
	if (size == 0)
		return;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		fprintf(stderr, "Error aquiring crypt context.\n");
	
	if (!CryptGenRandom(hProv, size, bfr))
		fprintf(stderr, "Errorgetting random numbers.\n");

	CryptReleaseContext(hProv, 0);
}
#else
static void get_rand(void *bfr, uint32_t size)
{
	FILE *fp;
	
	if (size == 0)
		return;

	fp = fopen("/dev/urandom", "r");
	if (fp == NULL)
		fprintf(stderr, "Error aquiring crypt context.\n");

	if (fread(bfr, size, 1, fp) != 1)
		fprintf(stderr, "Error getting random numbers.\n");

	fclose(fp);
}
#endif


#define BUF_SIZE	(128*1024*1024)

uint8_t inbuf[BUF_SIZE];
static uint64_t g_nounce;

int ReadBinFile(char *file, void *buf, uint32_t size)
{
	FILE *f = fopen(file, "rb");
	if (!f)
		return -1;
	
	int read = fread(buf, 1, size, f);
	fclose(f);
	
	return read;
}

int WriteBinFile(char *file, void *buf, int size)
{
	FILE *f = fopen(file, "wb");
	if (!f)
		return -1;
	
	int read = fwrite(buf, 1, size, f);
	fclose(f);
	
	return read;
}

void xtea_encrypt_block(uint32_t *k, uint32_t *in, uint32_t *out) 
{
	uint32_t sum, y, z;
	uint32_t m[4];
	unsigned char i;

	sum = 0;
	y = swap32(in[0]);	
	z = swap32(in[1]);
	
	for (i = 0; i < 4; i++)
		m[i] = swap32(k[i]);
	

	for (i = 0; i < 32; i++) 
	{
		y += (((z<<4) ^ (z>>5)) + z) ^ (sum + m[sum&3]);
		sum += 0x9e3779b9;
		z += (((y<<4) ^ (y>>5)) + y) ^ (sum + m[sum>>11 &3]);
	}
	
	out[0] = swap32(y);
	out[1] = swap32(z);
}

static inline void xor64(void *in, void *out)
{
	uint64_t *in64 = (uint64_t *)in;
	uint64_t *out64 = (uint64_t *)out;
	
	out64[0] ^= in64[0];	
}

void xtea_ctr(uint8_t *key, uint8_t *buf, int size)
{
	uint8_t ct[8];
	
	g_nounce = swap64(g_nounce);
	
	for (int i = 0; i < size; i += 8)
	{
		if ((size-i) < 8)
		{
			//printf("Note: not encrypting last block.\n");
			break;
		}
		
		xtea_encrypt_block((uint32_t *)key, (uint32_t *)&g_nounce, (uint32_t *)ct);
		xor64(ct, buf+i);
		g_nounce = swap64(swap64(g_nounce)+1);		
	}

	g_nounce = swap64(g_nounce);	
}


void encrypt_section(void *buf, uint64_t size, uint8_t *keys, uint64_t nounce)
{
	g_nounce = nounce;
	xtea_ctr(keys, buf, size);
}

int main(int argc, char *argv[])
{	
	int input_size;
	SELF *self;
	ELF *elf;
	ELF_PHDR *phdr;
	SECTION_INFO *sections;
	SPRX_EXT_HEADER *cobra;
	int metadata_size;
	uint8_t keys[16];
	uint64_t nonce;
	KeySet *keySet = NULL;
	
	if (argc != 4)
	{
		printf("Usage: %s type input output\ntype: manager, pspemu", argv[0]);
		return -1;
	}
	
	if (strcmp(argv[1], "manager") == 0)
	{
		keySet = &managerKey;
	}
	else if (strcmp(argv[1], "pspemu") == 0)
	{
		keySet = &pspeKey;
	}
	else if (strcmp(argv[1], "vsh") == 0)
	{
		keySet = &vshKey;
	}
	else if (strcmp(argv[1], "vshtb") == 0)
	{
		keySet = &vshTBKey;
	}
	else
	{
		printf("Invalid type: %s\n", argv[1]);
		return -1;
	}
	
	input_size = ReadBinFile(argv[2], inbuf, sizeof(inbuf));
	if (input_size < 0)
	{
		printf("Error opening %s\n", argv[2]);
		return -1;
	}
	
	if (input_size == sizeof(inbuf))
	{
		printf("File has a size greater or equal to buf size.\nPlease recompile!\n");
		return -1;
	}
	
	self = (SELF *)inbuf;
	
	if (swap32(self->magic) != SCE_MAGIC)
	{
		printf("Not a valid self\n");
		return -1;
	}
	
	if (swap16(self->flags) != 0x8000)
	{
		printf("Not a decrypted file.\n");
		return -1;
	}
	
	elf = (ELF *)(inbuf+swap64(self->elf_offset));
	if (swap32(elf->magic) != ELF_MAGIC)
	{
		printf("Not elf header!\n");
		return -1;
	}
	
	metadata_size = swap64(self->header_len) - swap32(self->metadata_offset) - 0x20;
	
	if (metadata_size < sizeof(SPRX_EXT_HEADER))
	{
		printf("Metadata too small\n");
		return -1;
	}
	
	cobra = (SPRX_EXT_HEADER *)(inbuf+swap32(self->metadata_offset)+0x20);
	phdr = (ELF_PHDR *)(inbuf+swap64(self->elf_offset)+swap64(elf->phdr_offset));
	sections = (SECTION_INFO *)(inbuf+swap64(self->section_info_offset));
	
	cobra->magic = swap64(keySet->magic);
	get_rand(&cobra->nonce_mod, 8);
	get_rand(cobra->keys_mod, 16);
	
	for (int i = 0; i < 16; i++)
	{
		keys[i] = keySet->keys[15-i] ^ cobra->keys_mod[i];
	}
	
	get_rand(inbuf+swap32(self->metadata_offset)+0x20+sizeof(SPRX_EXT_HEADER), metadata_size-sizeof(SPRX_EXT_HEADER));
	
	nonce = swap64(cobra->nonce_mod) ^ keySet->nonce;
	
	for (uint16_t i = 0; i < swap16(elf->phnum); i++)
	{
		int type = swap32(phdr[i].type);
		uint64_t offset, size;
		
		
		if (((type != 1) && (type != 0x700000A4)) ||
			((phdr[i].segment_size == 0)))
			continue;
		
		offset = swap64(sections[i].offset);
		size = swap64(sections[i].size);
		
		printf("Encrypting section %lx %lx\n", offset, size);
		encrypt_section(inbuf+offset, size, keys, nonce);		
	}
	
	if (WriteBinFile(argv[3], inbuf, input_size) != input_size)
	{
		printf("Error writing output file.\n");
		return -1;
	}
	
	printf("Done.\n");
	
	return 0;
}
