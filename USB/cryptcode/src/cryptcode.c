#include <cryptcode/cryptcode.h>

#ifdef LV2
#include <lv2/synchronization.h>
#include <lv2/security.h>
#endif

#include <lv1/lv1.h>

static INLINE void funcrypt_updateInsnCache(void *addr, int len)
{
	u64 p = ((u64)addr) & ~0x1f;
	u64 end = ((u64)addr) + len;

	while (p < end) {
		asm volatile("dcbst 0,%0 ; sync ; icbi 0,%0" :: "r"(p));
		p += 32;		
	}

	asm volatile("sync ; isync");
}

static INLINE void funcrypt_TEADecrypt(u32* v, u64 key0, u64 key1) 
{
	u32 v0=v[0], v1=v[1], sum=0xC6EF3720, i;
	u32 delta=0x9e3779b9;
	u32 k0=(u32)(key0 >> 32), k1=(u32)key0, k2=(u32)(key1 >> 32), k3=(u32)key1;
	for (i=0; i<32; i++)
	{
		v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
		v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
		sum -= delta;
	}
	v[0]=v0; v[1]=v1;
}

static INLINE void funcrypt_TEADecryptCbc(u32 *in, u32 *out, int bytes, u32 *IV, u64 key0, u64 key1)
{
	while(bytes > 0)
	{
		u32 tmp[2], tmp2[2];
		tmp[0] = tmp2[0] = in[0];
		tmp[1] = tmp2[1] = in[1];
		funcrypt_TEADecrypt(tmp, key0, key1);
		out[0] = tmp[0] ^ IV[0];
		if(bytes >= 8)
			out[1] = tmp[1] ^ IV[1];
		IV[0] = tmp2[0];
		IV[1] = tmp2[1];
		in += 2;
		out += 2;
		bytes -= 8;
	}
}

static INLINE void funcrypt_TEAEncrypt(u32* v, u64 key0, u64 key1)
{
	u32 v0=v[0], v1=v[1], sum=0, i;
	u32 delta=0x9e3779b9;
	u32 k0=(u32)(key0 >> 32), k1=(u32)key0, k2=(u32)(key1 >> 32), k3=(u32)key1;
	for (i=0; i < 32; i++) 
	{
		sum += delta;
		v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
		v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
	}
	v[0]=v0; v[1]=v1;
}

static INLINE void funcrypt_TEAEncryptCbc(u32 *in, u32 *out, int bytes, u32 *IV, u64 key0, u64 key1)
{
	while(bytes > 0)
	{
		u32 tmp[2];
		tmp[0] = in[0] ^ IV[0];
		tmp[1] = in[1] ^ IV[1];
		funcrypt_TEAEncrypt(tmp, key0, key1);
		out[0] = tmp[0];
		if(bytes >= 8)
			out[1] = tmp[1];
		IV[0] = out[0];
		IV[1] = out[1];
		in += 2;
		out += 2;
		bytes -= 8;
	}
}

void code_cipher(u8 *codeBuf, u32 codeSize, u32 codeKey, int mode)
{
	uint8_t teaIV[8] = { TEA_CODE_IV };
	register u64 repoKey0, repoKey1;

	asm volatile (
	"mflr 0\n"
	"std 0, 16(1)\n"
	"li 3, 2\n"
	"li 4, 1\n"
	"li 5, 2\n"
	"li 6, 3\n"
	"li 7, 4\n"
	"li 11, 91\n"
	"sc 1\n"
	"ld 0, 16(1)\n"
	"mtlr 0\n"
	"mr %[repoKey0],4\n"
	"mr %[repoKey1],5\n"
	: [repoKey0]"=r" (repoKey0), [repoKey1]"=r" (repoKey1)
	:
	: "0", "3","4","5","6","7","8","9","10","11","12","cc"/*,"cr7","cr6","cr5","cr4","cr3","cr2","cr1","cr0"*/
	);
	
	repoKey0 ^= (((u64)codeKey << 32) | codeKey);
	repoKey1 ^= (((u64)codeKey << 32) | codeKey);
	if(mode == 0)
		funcrypt_TEADecryptCbc((u32 *)codeBuf, (u32 *)codeBuf, codeSize, (u32 *)teaIV, repoKey0, repoKey1);
	else
		funcrypt_TEAEncryptCbc((u32 *)codeBuf, (u32 *)codeBuf, codeSize, (u32 *)teaIV, repoKey0, repoKey1);
		
	funcrypt_updateInsnCache(codeBuf, codeSize);		
}

static mutex_t crypto_mutex;

void crypto_init(void)
{
	mutex_create(&crypto_mutex, SYNC_PRIORITY, SYNC_NOT_RECURSIVE);
}

#ifdef LV2

void lock_crypto_mutex(void)
{
	mutex_lock(crypto_mutex, 0);
}

void unlock_crypto_mutex(void)
{
	mutex_unlock(crypto_mutex);	
}

#endif

void crypto_destroy_function(u8 *codeBuf, u32 codeSize)
{
#ifdef LV2
	get_pseudo_random_number(codeBuf, codeSize);
#else
	memset(codeBuf, 0, codeSize);
#endif
}






