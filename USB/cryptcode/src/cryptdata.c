#include <cryptcode/cryptcode.h>
#include <lv1/lv1.h>

// increment counter (64-bit int) by 1
static INLINE void TEACtr64Inc(u8 *counter) 
{
	u32 n=8;
	u8  c;

	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

void TEAEncrypt(u32* v, u32* k)
{
	u32 v0=v[0], v1=v[1], sum=0, i;
	u32 delta=0x9e3779b9;
	u32 k0=k[0], k1=k[1], k2=k[2], k3=k[3];
	for (i=0; i < 32; i++) 
	{
		sum += delta;
		v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
		v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
	}
	v[0]=v0; v[1]=v1;
}

ENCRYPTED_FUNCTION(void, TEAEncryptCtr, (u8 *in, u8 *out, int streamOffset, int len, u8 ivec[8], u32 *key))
{
	unsigned int n;
	size_t l=0;
	u8 ecount[8];

	memset(ecount, 0, sizeof(ecount));
	n = streamOffset % 8;
	*(u16 *)&ivec[6] = (u16)(streamOffset / 8);

	// fill initial block if non-aligned
	if(n)
	{
		memcpy(ecount, ivec, 8);
		TEAEncrypt((u32 *)ecount, key);
	 	TEACtr64Inc(ivec);
	}
	while (l<len) {
		if (n==0) {
			memcpy(ecount, ivec, 8);
			TEAEncrypt((u32 *)ecount, key);
 			TEACtr64Inc(ivec);
		}
		out[l] = in[l] ^ ecount[n];
		++l;
		n = (n+1) % 8;
	}
}

#ifdef ENCRYPT_DATA
u8 cryptedDataMasterIV[8] = { 0xff };
ENCRYPTED_FUNCTION(void, encrypted_data_copy, (void *in, void *out, int len))
{
// TEA_DATA_KEY	= 0x62, 0xAD, 0x1A, 0x77, 0x84, 0x7C, 0x63, 0x75, 0x90, 0x6C, 0x20, 0xB6, 0x8D, 0x86, 0xE6, 0x49
	uint8_t teaIV[8];
	uint8_t teaKey[16];
	extern u32 __crypt_start;
	u32 streamOffset = (u32)((u64)in - (u64)&__crypt_start);

	// this function will be encrypted, so setup the TEA key without using an outside array, and the key will remain hidden
	teaKey[0] = TEA_DATA_KEY_0; 
	teaKey[1] = TEA_DATA_KEY_1; 
	teaKey[2] = TEA_DATA_KEY_2; 
	teaKey[3] = TEA_DATA_KEY_3; 
	teaKey[4] = TEA_DATA_KEY_4; 
	teaKey[5] = TEA_DATA_KEY_5; 
	teaKey[6] = TEA_DATA_KEY_6; 
	teaKey[7] = TEA_DATA_KEY_7; 
	teaKey[8] = TEA_DATA_KEY_8; 
	teaKey[9] = TEA_DATA_KEY_9; 
	teaKey[10] = TEA_DATA_KEY_10; 
	teaKey[11] = TEA_DATA_KEY_11; 
	teaKey[12] = TEA_DATA_KEY_12; 
	teaKey[13] = TEA_DATA_KEY_13; 
	teaKey[14] = TEA_DATA_KEY_14; 
	teaKey[15] = TEA_DATA_KEY_15;

	memcpy(teaIV, cryptedDataMasterIV, 8);
	TEAEncryptCtr(in, out, streamOffset, len, teaIV, (u32 *)teaKey);
}

ENCRYPTED_FUNCTION(void, encrypted_data_realloc_ptr, (void *buf, int len))
{
	extern uint64_t _start;
	uint64_t *buf64 = buf;
	
	for (int i = 0; i < len/8; i++)
	{
		uint16_t *buf16 = (uint16_t *)buf64;
		
		// Split comparison to avoid init reallocator
		if (buf16[0] == 0xBAAD && buf16[1] == 0xCAFE)
		{
			uint64_t baadcafe_base = ((uint64_t)buf16[0] << 48) | ((uint64_t)buf16[1] << 32);
			uint64_t base = (uint64_t)&_start;
			buf64[0] = (buf64[0] - baadcafe_base) + base;
		}
		
		buf64++;
	}
}

#else

void encrypted_data_copy(void *in, void *out, int len)
{
	memcpy(out, in, len);
}

void encrypted_data_realloc_ptr(void *buf, in len)
{
}

#endif // ENCRYPT_DATA


