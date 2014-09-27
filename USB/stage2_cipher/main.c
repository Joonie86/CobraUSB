#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define SWAP32(x) ((((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | (((x) >> 24) & 0xff))

/*uint8_t key[16] =
{
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78
};

uint8_t IV[16] =
{
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78
};*/
uint8_t key[16];

uint8_t IV[16];

uint8_t buf1[524288], buf2[524288];

#define w 32    /* word size in bits */
#define r 23    /* based on security estimates */

#define P32 0xB7E15163    /* Magic constants for key setup */
#define Q32 0x9E3779B9

/* derived constants */
#define bytes   (w / 8)                /* bytes per word */
#define c       ((b + bytes - 1) / bytes)    /* key in words, rounded up */
#define R24     (2 * r + 4)
#define lgw     5                           /* log2(w) -- wussed out */

/* Rotations */
#define ROTL(x,y) (((x)<<((y)&(w-1))) | ((x)>>(w-((y)&(w-1)))))
#define ROTR(x,y) (((x)>>((y)&(w-1))) | ((x)<<(w-((y)&(w-1)))))

unsigned int S[R24];        /* Key schedule */

void rc6_key_setup(unsigned char *K, int b)
{
    int i, j, s, v;
    unsigned int L[(32 + bytes - 1) / bytes]; /* Big enough for max b */
    unsigned int A, B;

    L[c - 1] = 0;
    for (i = b - 1; i >= 0; i--)
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

void rc6_block_encrypt(unsigned int *pt, unsigned int *ct)
{
    unsigned int A, B, C, D, t, u, x;
    int i;

    A = SWAP32(pt[0]);
    B = SWAP32(pt[1]);
    C = SWAP32(pt[2]);
    D = SWAP32(pt[3]);
    B += S[0];
    D += S[1];
    for (i = 2; i <= 2 * r; i += 2)
    {
        t = ROTL(B * (2 * B + 1), lgw);
        u = ROTL(D * (2 * D + 1), lgw);
        A = ROTL(A ^ t, u) + S[i];
        C = ROTL(C ^ u, t) + S[i + 1];
        x = A;
        A = B;
        B = C;
        C = D;
        D = x;
    }
    A += S[2 * r + 2];
    C += S[2 * r + 3];
    ct[0] = A;
    ct[1] = B;
    ct[2] = C;
    ct[3] = D;
    ct[0] = SWAP32(ct[0]);
    ct[1] = SWAP32(ct[1]);
    ct[2] = SWAP32(ct[2]);
    ct[3] = SWAP32(ct[3]);
}

static void xor128(uint8_t *buf1, uint8_t *buf2)
{
	int i;
	
	for (i = 0; i < 16; i++)
		buf1[i] ^= buf2[i];	
}

unsigned int RC6_CBC(uint8_t *input, uint8_t *output, int size, uint8_t *key, uint8_t *IV)
{
	uint8_t pt[16];
	uint8_t ct[16];
	unsigned int outsize = 0;
	
	memcpy(ct, IV, 16);	
	rc6_key_setup(key, 16);
	
	while (size > 0)
	{
		memset(pt, 0, 16);		
		memcpy(pt, input, size >= 16 ? 16 : size);				
		xor128(pt, ct);
		rc6_block_encrypt((unsigned int *)pt, (unsigned int *)ct);
		memcpy(output, ct, sizeof(ct));
		
		size -= 16;
		input += 16;
		output += 16;
		outsize += 16;
	}
	
	return outsize;
}

int main(int argc, char *argv[])
{
	FILE *i, *o, *k, *v;
	char *e;
	
	if (argc != 5)
	{
		printf("Usage: %s input.bin keys.bin IV.bin output.h/bin\n", argv[0]);
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
	
	fread(key, 1, sizeof(key), k);
	fread(IV, 1, sizeof(IV), v);
	
	int isize = fread(buf1, 1, sizeof(buf1), i);
	int osize = RC6_CBC(buf1, buf2, isize, key, IV);
	
	if ((e = strstr(argv[4], ".h")) && strlen(e) == 2)
	{	
		o = fopen(argv[4], "w");
		if (!o)
		{
			printf("Cannot open %s\n", argv[4]);
			return -1;
		}
	
	
		fprintf(o, "uint8_t stage2[%d] =\n{\t", osize);
	
		for (int j = 0; j < osize; j++)
		{
			fprintf(o, "0x%02X, ", buf2[j]);
			if ((j&15) == 15)
			{
				if (j == (osize-1))
					fprintf(o, "\n");
				else			
					fprintf(o, "\n\t");
			}
		}
	
		fprintf(o, "};\n");
	}
	else
	{
		o = fopen(argv[4], "wb");
		if (!o)
		{
			printf("Cannot open %s\n", argv[4]);
			return -1;
		}
		
		fwrite(buf2, 1, osize, o);
	}
	
	
	fclose(i);
	fclose(o);
	fclose(k);
	fclose(v);
	
	return 0;
}
