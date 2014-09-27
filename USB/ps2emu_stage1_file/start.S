#include <ps2emu/symbols.h>

.global _start


// Max size
// ps2hwemu: we are taking 1000 bytes but it can be increased
// ps2_gxemu: 1104 bytes
// ps2_softemu: 1332 bytes

#ifdef PS2HWEMU

#define stage1_addr	overwritten_symbol
#define stage2_addr	0x021f0000 
#define name_key	0xD08992ECBFC46040

#elif defined(PS2GXEMU)

#define stage1_addr	overwritten_symbol
#define stage2_addr	0x2BAFAE8
#define name_key	0xD09D3CBBD79E6240				  

#elif defined(PS2SOFTEMU)

#define stage1_addr	overwritten_symbol
#define stage2_addr	0x2315560
#define name_key	0xD09AF45234F96B60

#endif

_start:

	stdu 	%sp, -0xD0(%sp)
	mflr	%r0
	std	%r0, 0xE0(%sp)
	std	%r23, 0x70(%sp)
	std	%r24, 0x78(%sp)
	std	%r25, 0x80(%sp)
	std	%r26, 0x88(%sp)
	std	%r31, 0x90(%sp)
	std	%r30, 0x98(%sp)
			
	// Save registers
	mr	%r23, %r3
	mr	%r24, %r4
	mr	%r25, %r5
	mr	%r26, %r6
	
	lis	%r31, stage2_addr@ha
	addi	%r31, %r31, stage2_addr@l
	
	// r30 = ufs_open (0, decode(stage2_file)); 
	li	%r3, 0
	lis	%r4, (stage1_addr+stage2_file)@ha
	addi	%r4, %r4, (stage1_addr+stage2_file)@l
#ifdef PS2HWEMU

	li	%r5, 1
	sldi 	%r5, %r5, 63
	addi	%r5, %r5, -409
	ld	%r6, 0x70(%sp)
	mulld	%r6, %r0, %r6
	or	%r7, %r5, %r6
	orc	%r6, %r5, %r6
	nand	%r6, %r7, %r6
	li	%r5, -123
	mulld	%r7, %rtoc, %r5
	mulld	%r6, %r7, %r6	
#else
	ld	%r5, 0x160(%sp)
	mulld	%r5, %r5, %r23
	li	%r6, 1
	sldi	%r6, %r6, 63
	addi	%r6, %r6, -409
	mulld	%r6, %r5, %r6
#endif
	ld	%r5, 0(%r4)
	xor	%r5, %r5, %r6
	std	%r5, 0(%r4)
	bla	ufs_open_symbol
	mr	%r30, %r3	
	
	// ufs_fstat(r30, sp+A0)
	addi	%r4, %sp, 0xA0
	bla	ufs_fstat_symbol
	
	// ufs_read(r30, 0, stage2_addr, 0x10000);
	mr	%r3, %r30
	li	%r4, 0
	mr	%r5, %r31
	lis	%r6, 1
	bla	ufs_read_symbol
	
	// xtea_cbc_decrypt(key=sp+0xA0, IV=0, buf=stage2_addr, filesize)
	mr	%r6, %r3
	addi	%r3, %sp, 0xA0
	li	%r4, 0
	mr	%r5, %r31
	bl	xtea_cbc_decrypt
		
	// ufs_close(r30);
	mr	%r3, %r30
	bla	ufs_close_symbol
	
	// clear_icache(r31, 0x10000);
	mr	%r3, %r31
	lis	%r4, 1
	bl	clear_icache	
	
	// Stage 1.5 call
	mr	%r3, %r23
	mr	%r4, %r24
	mr	%r5, %r25
	mr	%r6, %r26
	mtctr	%r31
	bctrl	
	
// Exit must be at stage 1.5
	
	/*ld	%r23, 0x70(%sp)
	ld	%r24, 0x78(%sp)
	ld	%r25, 0x80(%sp)
	ld	%r26, 0x88(%sp)
	ld	%r31, 0x90(%sp)
	ld	%r30, 0x98(%sp)
	ld	%r0, 0xE0(%sp)
	mtlr	%r0
	addi	%sp, %sp, 0xD0
	blr*/
	
stage2_file:
.quad name_key
.long 0
	

	
