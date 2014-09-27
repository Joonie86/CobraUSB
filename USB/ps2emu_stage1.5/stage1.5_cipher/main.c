#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define SWAP32(x) ((((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | (((x) >> 24) & 0xff))

uint8_t key[16];
uint8_t IV[8];

uint8_t buf1[524288], buf2[524288];

void xtea_encrypt_block(uint32_t *k, uint32_t *in, uint32_t *out) 
{
	uint32_t sum, y, z;
	uint32_t m[4];
	unsigned char i;

	sum = 0;
	y = SWAP32(in[0]);	
	z = SWAP32(in[1]);
	
	for (i = 0; i < 4; i++)
		m[i] = SWAP32(k[i]);
	

	for (i = 0; i < 32; i++) 
	{
		y += (((z<<4) ^ (z>>5)) + z) ^ (sum + m[sum&3]);
		sum += 0x9e3779b9;
		z += (((y<<4) ^ (y>>5)) + y) ^ (sum + m[sum>>11 &3]);
	}
	
	out[0] = SWAP32(y);
	out[1] = SWAP32(z);
}

void xtea_decrypt_block(uint32_t *k, uint32_t *in, uint32_t *out) 
{
	uint32_t sum, y, z;
	unsigned char i;
	uint32_t m[4];

	sum = 0xC6EF3720; // DELTA*32
	y = SWAP32(in[0]), z = SWAP32(in[1]);
	
	for (i = 0; i < 4; i++)
		m[i] = SWAP32(k[i]);
	
	for (i=0; i<32; i++) 
	{
		z -= (((y<<4) ^ (y>>5)) + y) ^ (sum + m[sum>>11 &3]);
		sum -= 0x9e3779b9;
		y -= (((z<<4) ^ (z>>5)) + z) ^ (sum + m[sum&3]);
	}
	
	out[0] = SWAP32(y);
	out[1] = SWAP32(z);
}


static inline void xor64(void *in, void *out)
{
	uint64_t *in64 = (uint64_t *)in;
	uint64_t *out64 = (uint64_t *)out;
	
	out64[0] ^= in64[0];	
}

unsigned int xtea_cbc_encrypt(uint8_t *input, uint8_t *output, int size, uint8_t *key, uint8_t *IV)
{
	uint8_t pt[8];
	uint8_t ct[8];
	unsigned int outsize = 0;
	
	memcpy(ct, IV, 8);	
		
	while (size > 0)
	{
		memset(pt, 0, 8);		
		memcpy(pt, input, size >= 8 ? 8 : size);				
		xor64(ct, pt);
		xtea_encrypt_block((uint32_t *)key, (uint32_t *)pt, (uint32_t *)ct);
		memcpy(output, ct, sizeof(ct));
		
		size -= 8;
		input += 8;
		output += 8;
		outsize += 8;
	}
	
	return outsize;
}

void xtea_hash(uint8_t *hash_prev, uint8_t *in, uint32_t size, uint8_t *hash)
{
	for (uint32_t i = 0; i < size; i += 16)
	{
		if ((i+16) > size)
		{
			// Last block for size % 16 != 0
			uint32_t x = size&0xF;
			uint8_t temp[16];
			
			for (uint32_t j = 0; j < 16; j++)
			{
				if (j < x)
					temp[j] = in[i+j];
				else
					temp[j] = 0;
			}
			xtea_decrypt_block((uint32_t *)temp, (uint32_t *)hash_prev, (uint32_t *)hash);
			xor64(hash_prev, hash);
		}
		else
		{
			xtea_decrypt_block((uint32_t *)(in+i), (uint32_t *)hash_prev, (uint32_t *)hash);
			xor64(hash_prev, hash);
			*(uint64_t *)hash_prev = *(uint64_t *)hash;
		}
	}
}

void print64(uint8_t *buf)
{
	/*for (int i = 0; i < 8; i++)
		printf("%02X ", buf[i]);
	
	printf("\n");	*/
}

int main(int argc, char *argv[])
{
	FILE *i, *o, *k, *hk;
	uint32_t section1_size, section2_addr;
	uint8_t hash[8], hash_temp[8], hash_key[8];
	
	srand(time(NULL));
	
	if (argc != 7)
	{
		printf("Usage: %s input.bin keys.bin hash_keys.bin output.bin section1_size section2_addr\n", argv[0]);
		return -1;
	}
	
	i = fopen(argv[1], "rb");
	if (!i)
	{
		printf("Cannot open %s\n", argv[1]);
		return -1;
	}
	
	k = fopen(argv[2], "rb");
	if (!k)
	{
		printf("Cannot open %s\n", argv[2]);
		return -1;
	}
	
	hk = fopen(argv[3], "rb");
	if (!k)
	{
		printf("Cannot open %s\n", argv[3]);
		return -1;
	}
	
	o = fopen(argv[4], "wb");
	if (!o)
	{
		printf("Cannot open %s\n", argv[4]);
		return -1;
	}
	
	sscanf(argv[5], "0x%x", &section1_size);
	sscanf(argv[6], "0x%x", &section2_addr);
	
	fread(key, 1, sizeof(key), k);
	memset(IV, 0, sizeof(IV));
	
	int isize = fread(buf1, 1, sizeof(buf1), i);
	
	memset(hash_temp, 0, 8);
	xtea_hash(hash_temp, buf1, section1_size, hash);
	print64(hash);
	memcpy(hash_temp, hash, 8);
	xtea_hash(hash_temp, buf1+section2_addr, isize-section2_addr, hash);
	print64(hash);
	
	fread(hash_key, 1, sizeof(hash_key), hk);
	
	for (int i = 0; i < 8; i++)
	{
		hash[i] ^= hash_key[i];
	}
	
	print64(hash);
	
	for (int i = 0; i < (isize-8); i++)
	{
		int j;
		
		for (j = 0; j < 8; j++)
		{
			if (buf1[i+j] != 0x98)
				break;
		}
		
		if (j == 8)
		{
			memcpy(buf1+i, hash, 8);
		}
	}
	
	int osize = xtea_cbc_encrypt(buf1, buf2, isize, key, IV);	
	
	fwrite(buf2, 1, osize, o);
	
	fclose(i);
	fclose(o);
	fclose(k);
	fclose(hk);
	
	return 0;
}
