#include <stdint.h> 

void xtea_decrypt_block(uint32_t *k, uint32_t *in, uint32_t *out) 
{
	uint32_t sum, y, z;
	unsigned char i;

	sum = 0xC6EF3720; // DELTA*32
	y = in[0], z = in[1];
	
	for (i=0; i<32; i++) 
	{
		z -= (y<<4 ^ y>>5) + y ^ sum + k[sum>>11 &3];
		sum -= 0x9e3779b9;
		y -= (z<<4 ^ z>>5) + z ^ sum + k[sum&3];
	}
	
	out[0] = y;
	out[1] = z;
}

static inline void xor64(void *in, void *out)
{
	uint64_t *in64 = (uint64_t *)in;
	uint64_t *out64 = (uint64_t *)out;
	
	out64[0] ^= in64[0];	
}

void xtea_cbc_decrypt(uint8_t *key, uint8_t *IV, uint8_t *in, uint8_t *out, uint32_t size)
{
	for (uint32_t i = 0; i < size; i += 8)
	{	
		xtea_decrypt_block((uint32_t *)key, (uint32_t *)(in+i), (uint32_t *)(out+i));
		xor64(IV, out+i);
		*(uint64_t *)IV = *(uint64_t *)(in+i);		
	}
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
