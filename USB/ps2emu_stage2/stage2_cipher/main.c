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

int main(int argc, char *argv[])
{
	FILE *i, *o, *k, *v;
	
	srand(time(NULL));
	
	if (argc != 5)
	{
		printf("Usage: %s input.bin keys.bin IV.bin output.h\n", argv[0]);
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
	
	v = fopen(argv[3], "rb");
	if (!v)
	{
		printf("Cannot open %s\n", argv[3]);
		return -1;
	}
	
	o = fopen(argv[4], "w");
	if (!o)
	{
		printf("Cannot open %s\n", argv[4]);
		return -1;
	}
	
	fread(key, 1, sizeof(key), k);
	fread(IV, 1, sizeof(IV), v);;
	
	int isize = fread(buf1, 1, sizeof(buf1), i);
	int osize = xtea_cbc_encrypt(buf1, buf2, isize, key, IV);
	
	
	fprintf(o, "code uint8_t stage2[%d] =\n{\t", (osize+32));
	
	for (int j = 0; j < (osize+32); j++)
	{
		fprintf(o, "0x%02X, ", (j >= 32) ? buf2[j-32] : rand()&0xff);
		if ((j&15) == 15)
		{
			if (j == (osize+31))
				fprintf(o, "\n");
			else			
				fprintf(o, "\n\t");
		}
	}
	
	if ((osize+32)%16 != 0)
	{
		fprintf(o, "\n");
	}
	
	fprintf(o, "};\n");
	
	
	fclose(i);
	fclose(o);
	fclose(k);
	fclose(v);
	
	return 0;
}
