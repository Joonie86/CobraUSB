#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define SWAP32(x) ((((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | (((x) >> 24) & 0xff))

uint8_t buf[1048576];
uint8_t keys[1024];

int main(int argc, char *argv[])
{
	FILE *i, *o, *k;
	
	srand(time(NULL));
	
	uint64_t x1 = (0x08D308ULL)*0x1778878ULL;
	uint64_t x2 = 0x7FFFFFFFFFFFFE67LL;
	uint64_t p = x1*x2;
	
	printf("%16lx\n", p);
	
	if (argc != 4)
	{
		printf("Usage: %s input.bin keys.bin output.h\n", argv[0]);
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
	
	o = fopen(argv[3], "w");
	if (!o)
	{
		printf("Cannot open %s\n", argv[3]);
		return -1;
	}
	
	int isize = fread(buf, 1, sizeof(buf), i);
	int klen = fread(keys, 1, sizeof(keys), k);
	
	fprintf(o, "code uint8_t xtea[%d] =\n{\t", isize+4);
	
	for (int j = 0; j < (isize+3); j++)
	{
		fprintf(o, "0x%02X, ", (j >= 3) ? (buf[j-3] ^ keys[(j-3) % klen]) : (rand()&0xff));
		if ((j&15) == 15)
		{
			if (j == (isize+2))
				fprintf(o, "\n");
			else			
				fprintf(o, "\n\t");
		}
	}
	
	if ((isize+3) % 16 != 0)
	{
		fprintf(o, "\n");
	}
	
	fprintf(o, "};\n");
	
	
	fclose(i);
	fclose(k);
	fclose(o);
	
	return 0;
}
