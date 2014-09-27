#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <usb.h>
#include <openssl/des.h>

#include "cobra.h"

static uint8_t cobra_keys[][8] =
{
	{ 0x77, 0x9C, 0xCB, 0xFA, 0x5C, 0xB5, 0x5B, 0x07 },
	{ 0xF0, 0xBB, 0xD7, 0x89, 0x45, 0x7A, 0x1E, 0xD7 },
	{ 0x37, 0x5C, 0xF0, 0xEC, 0x9E, 0x0F, 0xF6, 0x60 },
	{ 0x37, 0x65, 0xFB, 0x63, 0x52, 0xB9, 0xC8, 0x6A },
};

static void swap64_p(void *p)
{
	uint64_t *p64 = (uint64_t *)p;
	uint64_t data = *p64;
	
	uint64_t ret = (data << 56) & 0xff00000000000000ULL;
	ret |= ((data << 40) & 0x00ff000000000000ULL);
	ret |= ((data << 24) & 0x0000ff0000000000ULL);
	ret |= ((data << 8) & 0x000000ff00000000ULL);
	ret |= ((data >> 8) & 0x00000000ff000000ULL);
	ret |= ((data >> 24) & 0x0000000000ff0000ULL);
	ret |= ((data >> 40) & 0x000000000000ff00ULL);
	ret |= ((data >> 56) & 0x00000000000000ffULL);
	*p64 = ret;
}

static uint8_t reverse_bits(uint8_t b)
{
	b = ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16; 
	return b;
}

static void translate_buffer(void *p)
{
	uint8_t *p8 = (uint8_t *)p;
	
	for (int i = 0; i < 8; i++)
	{
		p8[i] = reverse_bits(p8[i]);
	}
	
	swap64_p(p);	
}

int cobra_open_device(usb_dev_handle **handle, uint64_t *serial, uint32_t nretries)
{
	return 0;
}

int cobra_close_device(usb_dev_handle *handle)
{
	return 0;
}

int cobra_scp_encrypt(usb_dev_handle *handle, uint8_t key, void *buf, uint32_t size)
{
	des_key_schedule desKey;
	uint8_t *buf8 = buf;
	
	if (size & 7)
		return -1;
	
	for (uint32_t i = 0; i < size; i += 8, buf8 += 8)
	{
		translate_buffer(buf8);
		DES_set_key_unchecked((const_DES_cblock *)cobra_keys[key], &desKey);	
		DES_ecb_encrypt((const_DES_cblock *)buf8, (DES_cblock *)buf8, &desKey, 1);
		translate_buffer(buf8);
	}
	
	return 0;
}





