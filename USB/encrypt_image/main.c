#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

uint8_t encrypted_image_keys[16] = 
{
	0x11, 0x0C, 0xE4, 0x15, 0xDD, 0x39, 0x76, 0x8C, 
	0x90, 0xB6, 0x40, 0xF5, 0xCB, 0x33, 0xC6, 0xB6
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
	uint64_t nonce;
		
	if (argc != 3)
	{
		printf("Usage: %s input output\n", argv[0]);
		return -1;
	}
	
	input_size = ReadBinFile(argv[1], inbuf, sizeof(inbuf));
	if (input_size < 0)
	{
		printf("Error opening %s\n", argv[1]);
		return -1;
	}
	
	if (input_size == sizeof(inbuf))
	{
		printf("File has a size greater or equal to buf size.\nPlease recompile!\n");
		return -1;
	}
	
	get_rand(&nonce, sizeof(nonce));
	printf("Nonce: %016llx\n", nonce);

	encrypt_section(inbuf, input_size, encrypted_image_keys, nonce);		
		
	if (WriteBinFile(argv[2], inbuf, input_size) != input_size)
	{
		printf("Error writing output file.\n");
		return -1;
	}
	
	printf("Done.\n");
	
	return 0;
}
