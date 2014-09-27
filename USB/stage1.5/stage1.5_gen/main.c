#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "md5.h"

#define SWAP32(x) ((((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | (((x) >> 24) & 0xff))

uint8_t buf1[524288], buf2[524288];
uint8_t rom_keys[1024], md5_keys[16];

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

void command2(char *prog, char *arg1, char *arg2)
{
	char cmd[2048];
	
	snprintf(cmd, sizeof(cmd), "%s %s %s", prog, arg1, arg2);
	system(cmd);
}

void command3(char *prog, char *arg1, char *arg2, char *arg3)
{
	char cmd[2048];
	
	snprintf(cmd, sizeof(cmd), "%s %s %s %s", prog, arg1, arg2, arg3);
	system(cmd);
}

void command4(char *prog, char *arg1, char *arg2, char *arg3, char *arg4)
{
	char cmd[2048];
	
	snprintf(cmd, sizeof(cmd), "%s %s %s %s %s", prog, arg1, arg2, arg3, arg4);
	system(cmd);
}

void generate_iv(void)
{
	FILE *iv = fopen("tempIV.bin", "wb");
	uint8_t buf[16];
	
	memset(buf, 0, 16);
	fwrite(buf, 1, 16, iv);
	fclose(iv);
}

#define ROM_Read(x) (buf1[x] ^ rom_keys[(x-rom_addr) % rom_keys_len])

void insert_hash(char *input, uint64_t search_dword, char *rk, char *mk, uint32_t hashed_size)
{
	FILE *in, *k;
	int size, rom_keys_len;
	uint32_t i;
	
	in = fopen(input, "rb");
	if (!in)
	{
		printf("Cannot open %s\n", input);
		exit(-1);
	}
	
	size = fread(buf1, 1, sizeof(buf1), in);
	fclose(in);
	
	k = fopen(rk, "rb");
	if (!k)
	{
		printf("Cannot open %s\n", rk);
		exit(-1);
	}
	
	rom_keys_len = fread(rom_keys, 1, sizeof(rom_keys), k);
	fclose(k);
	
	k = fopen(mk, "rb");
	if (!k)
	{
		printf("Cannot open %s\n", mk);
		exit(-1);
	}
	
	if (fread(md5_keys, 1, sizeof(md5_keys), k) != 16)
	{
		fclose(k);
		printf("md5 keys are too small.\n");
		exit(-1);
	}
	fclose(k);
	
	for (i = 0; i < hashed_size; i += 8)
	{
		int flag = 0;
		
		if (search_dword < 0x10000)
		{
			i = search_dword-8;
			flag = 1;
		}
		
		if (flag || swap64(*(uint64_t *)&buf1[i]) == search_dword)
		{
			uint32_t rom_addr = i+8;
			uint32_t j;
			
			printf("ROM Found at address 0x%x\n", rom_addr);
			
			for (j = rom_addr; j < (hashed_size-24); j++)
			{
				uint32_t k;
								
				for (k = 0; k < 24; k++)
				{
					if (ROM_Read(j+k) != 0x63)
					{
						break;
					}
				}
				
				if (k == 24)
				{
					uint8_t md5[16], temp[16];
					uint32_t section1_size = j;
					uint32_t section2_size = hashed_size-section1_size-24;
					
					printf("md5 found at address 0x%x\nsection1_size= 0x%x, section2_size = 0x%x\n", j, section1_size, section2_size);
					
					MD5(buf1, section1_size, md5);
					MD5(buf1+section1_size+24, section2_size, temp);
					
					for (uint32_t l = 0; l < 16; l++)
					{
						md5[l] ^= temp[l];
						md5[l] ^= md5_keys[l];
					}
					
					memcpy(buf1+j, &section1_size, 4);
					memcpy(buf1+j+4, &section2_size, 4);
					memcpy(buf1+j+8, md5, 16);
					
					// reencode
					for (uint32_t l = 0; l < 24; l++)
					{
						buf1[j+l] ^= rom_keys[((j+l)-rom_addr) % rom_keys_len];
					}
					
					break;
				}
			}
			
			if (j == (hashed_size-24))
			{
				printf("md5 not found!\n");
				exit(-1);
			}
			
			break;			
		}
	}
	
	if (i == hashed_size)
	{
		printf("ROM not found!\n");
		exit(-1);
	}
	
	in = fopen(input, "wb");
	fwrite(buf1, 1, size, in);
	fclose(in);
}

int main(int argc, char *argv[])
{
	char *input, *output;
	char *cipher_program;
	char *rom_keys, *md5_keys;
	char *keys;
	uint64_t search_dword;
	uint32_t hashed_size;
	
	if (argc != 9)
	{
		printf("Usage: %s uncompressed_input encrypted_output search_dword rom_keys cipher_program keys md5_keys hashed_size\n", argv[0]);
		return -1;
	}
	
	input = argv[1];
	output = argv[2];
	sscanf(argv[3], "0x%lx", &search_dword);	
	rom_keys = argv[4];
	cipher_program = argv[5];	
	keys = argv[6];
	md5_keys = argv[7];
	sscanf(argv[8], "0x%x", &hashed_size);	
	
	insert_hash(input, search_dword, rom_keys, md5_keys, hashed_size);
	generate_iv();
	
	
	command3("lzmautil", "e", input, "temp.lzma");
	command2("truncate", "--size=%16", "temp.lzma");
	command4(cipher_program, "temp.lzma", keys, "tempIV.bin", output);
	unlink("tempIV.bin");
	unlink("temp.lzma");
	
	return 0;
}
