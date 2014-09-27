#include <stdint.h> 

void xtea_decrypt_block(uint32_t *k, uint32_t *buf) 
{
	uint32_t sum, y, z;
	unsigned char i;

	sum = 0xC6EF3720; // DELTA*32
	y = buf[0], z = buf[1];
	
	for (i=0; i<32; i++) 
	{
		z -= (y<<4 ^ y>>5) + y ^ sum + k[sum>>11 &3];
		sum -= 0x9e3779b9;
		y -= (z<<4 ^ z>>5) + z ^ sum + k[sum&3];
	}
	
	buf[0] = y;
	buf[1] = z;
}

static inline void xor64(uint64_t in, void *out)
{
	uint64_t *out64 = (uint64_t *)out;
	
	out64[0] ^= in;	
}

void xtea_cbc_decrypt(uint8_t *key, uint64_t IV, uint8_t *buf, uint32_t size)
{
	for (uint32_t i = 0; i < size; i += 8)
	{	
		uint64_t temp = *(uint64_t *)(buf+i);
		
		xtea_decrypt_block((uint32_t *)key, (uint32_t *)(buf+i));
		xor64(IV, buf+i);
		IV = temp;		
	}
}

