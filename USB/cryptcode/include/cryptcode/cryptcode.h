#ifndef __CRYPTCODE_H__
#define __CRYPTCODE_H__

#if defined(LV2)

#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/patch.h>
#include <lv2/syscall.h>
#include <lv2/security.h>

#endif

#ifdef ENCRYPT_DATA
#define ENCRYPTED_DATA	 __attribute__((section(".cryptData")))
#else
#define ENCRYPTED_DATA
#endif

#ifdef ENCRYPT_FUNCTIONS
#define ENCRYPTED_FUNCTION(ret, name, args) asm("" \
"	.section \".cryptStub\",\"aw\"\n" \
"	.align 3\n" \
"	.globl .cryptStub_"#name"\n" \
"	.cryptStub_"#name":\n" \
"	.quad _"#name"\n" \
"	.long 0xc0def00d\n" \
"	.long 0xdeadbeef\n" \
"	.section \".toc\",\"aw\"\n" \
"	.cryptToc_"#name":\n" \
"	.tc .cryptStub_"#name"[TC],.cryptStub_"#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.globl "#name"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad ."#name",.TOC.@tocbase\n" \
"	.section .text."#name",\"ax\",@progbits\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl ."#name"\n" \
"	.type   "#name", @function\n" \
"."#name":\n" \
"	ld 11, .cryptToc_"#name"@toc(2)\n" \
"	b .cryptCodeDispatch\n" \
"	.size "#name",.-."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_SUICIDAL_FUNCTION(ret, name, args) asm("" \
"	.section \".cryptStub\",\"aw\"\n" \
"	.align 3\n" \
"	.globl .cryptStub_"#name"\n" \
"	.cryptStub_"#name":\n" \
"	.quad _"#name"\n" \
"	.long 0xc0debeef\n" \
"	.long 0xdeadf00d\n" \
"	.section \".toc\",\"aw\"\n" \
"	.cryptToc_"#name":\n" \
"	.tc .cryptStub_"#name"[TC],.cryptStub_"#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.globl "#name"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad ."#name",.TOC.@tocbase\n" \
"	.section .text."#name",\"ax\",@progbits\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl ."#name"\n" \
"	.type   "#name", @function\n" \
"."#name":\n" \
"	ld 11, .cryptToc_"#name"@toc(2)\n" \
"	b .cryptCodeDispatch\n" \
"	.size "#name",.-."#name"\n"); \
ret name args; \
ret _##name args


#define ENCRYPT_PATCHED_FUNCTION(name) asm("" \
"	.section \".cryptStub\",\"aw\"\n" \
"	.align 3\n" \
"	.globl .cryptStub_"#name"\n" \
"	.cryptStub_"#name":\n" \
"	.quad _"#name"\n" \
"	.long 0xc0def00d\n" \
"	.long 0xdeadbeef\n" \
"	.section \".toc\",\"aw\"\n" \
"	.cryptToc_"#name":\n" \
"	.tc .cryptStub_"#name"[TC],.cryptStub_"#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.globl __"#name"\n" \
"	.align 3\n" \
"__"#name": \n" \
"	.quad .__"#name",.TOC.@tocbase\n" \
"	.section .text.__"#name",\"ax\",@progbits\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl .__"#name"\n" \
"	.type   __"#name", @function\n" \
".__"#name":\n" \
"	ld 11, .cryptToc_"#name"@toc(2)\n" \
"	b .cryptCodeDispatch\n" \
"	.size __"#name",.-.__"#name"\n"); 

#define ENCRYPT_PATCHED_SUICIDAL_FUNCTION(name) asm("" \
"	.section \".cryptStub\",\"aw\"\n" \
"	.align 3\n" \
"	.globl .cryptStub_"#name"\n" \
"	.cryptStub_"#name":\n" \
"	.quad _"#name"\n" \
"	.long 0xc0debeef\n" \
"	.long 0xdeadf00d\n" \
"	.section \".toc\",\"aw\"\n" \
"	.cryptToc_"#name":\n" \
"	.tc .cryptStub_"#name"[TC],.cryptStub_"#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.globl __"#name"\n" \
"	.align 3\n" \
"__"#name": \n" \
"	.quad .__"#name",.TOC.@tocbase\n" \
"	.section .text.__"#name",\"ax\",@progbits\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl .__"#name"\n" \
"	.type   __"#name", @function\n" \
".__"#name":\n" \
"	ld 11, .cryptToc_"#name"@toc(2)\n" \
"	b .cryptCodeDispatch\n" \
"	.size __"#name",.-.__"#name"\n"); 

#if defined(LV2)

#define ENCRYPTED_CONTEXT(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_CALLBACK 		ENCRYPTED_CONTEXT
#define ENCRYPTED_PATCHED_FUNCTION	ENCRYPTED_CONTEXT

#define ENCRYPTED_HOOKED_FUNCTION(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	nop\n" \
"	nop\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_0(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	nop\n" \
"	nop\n" \
"	std 2, 40(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_1(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	nop\n" \
"	nop\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -20\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_2(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	nop\n" \
"	nop\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -24\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_3(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	nop\n" \
"	nop\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -28\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_4(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	nop\n" \
"	nop\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -32\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_5(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	nop\n" \
"	nop\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -36\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_6(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	nop\n" \
"	nop\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -40\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_7(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	std 9, 96(1)\n" \
"	nop\n" \
"	nop\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	ld 9, 96(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -44\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_8(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	std 9, 96(1)\n" \
"	std 10, 104(1)\n" \
"	nop\n" \
"	nop\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	ld 9, 96(1)\n" \
"	ld 10, 104(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -48\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_0(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	nop\n" \
"	nop\n" \
"	cmpwi 3, 0\n" \
"	bne 1f\n" \
"	std 2, 40(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"1:\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_1(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	nop\n" \
"	nop\n" \
"	cmpwi 3, 0\n" \
"	bne 1f\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -20\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"1:\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_2(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	nop\n" \
"	nop\n" \
"	cmpwi 3, 0\n" \
"	bne 1f\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -24\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"1:\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_3(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	nop\n" \
"	nop\n" \
"	cmpwi 3, 0\n" \
"	bne 1f\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -28\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"1:\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_4(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	nop\n" \
"	nop\n" \
"	cmpwi 3, 0\n" \
"	bne 1f\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -32\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"1:\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_5(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	nop\n" \
"	nop\n" \
"	cmpwi 3, 0\n" \
"	bne 1f\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -36\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"1:\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_6(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	nop\n" \
"	nop\n" \
"	cmpwi 3, 0\n" \
"	bne 1f\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -40\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"1:\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_7(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	std 9, 96(1)\n" \
"	nop\n" \
"	nop\n" \
"	cmpwi 3, 0\n" \
"	bne 1f\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	ld 9, 96(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -44\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"1:\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_8(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	std 9, 96(1)\n" \
"	std 10, 104(1)\n" \
"	nop\n" \
"	nop\n" \
"	cmpwi 3, 0\n" \
"	bne 1f\n" \
"	std 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	ld 9, 96(1)\n" \
"	ld 10, 104(1)\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -48\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"1:\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_0(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_1(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_2(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_3(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_4(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_5(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_6(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_7(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	std 9, 96(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	ld 9, 96(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_8(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	std 9, 96(1)\n" \
"	std 10, 104(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	ld 9, 96(1)\n" \
"	ld 10, 104(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_0(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	extsw 4, 3\n" \
"	cmpwi 4, -15007\n" \
"	bne +12\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_1(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	extsw 4, 3\n" \
"	cmpwi 4, -15007\n" \
"	bne +16\n" \
"	ld 3, 48(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_2(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	extsw 4, 3\n" \
"	cmpwi 4, -15007\n" \
"	bne +20\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_3(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	extsw 4, 3\n" \
"	cmpwi 4, -15007\n" \
"	bne +24\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_4(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	extsw 4, 3\n" \
"	cmpwi 4, -15007\n" \
"	bne +28\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_5(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	extsw 4, 3\n" \
"	cmpwi 4, -15007\n" \
"	bne +32\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_6(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	extsw 4, 3\n" \
"	cmpwi 4, -15007\n" \
"	bne +36\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_7(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	std 9, 96(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	extsw 4, 3\n" \
"	cmpwi 4, -15007\n" \
"	bne +40\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	ld 9, 96(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_8(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -16\n" \
"	add  2, 2, 0\n" \
"	std 3, 48(1)\n" \
"	std 4, 56(1)\n" \
"	std 5, 64(1)\n" \
"	std 6, 72(1)\n" \
"	std 7, 80(1)\n" \
"	std 8, 88(1)\n" \
"	std 9, 96(1)\n" \
"	std 10, 104(1)\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	extsw 4, 3\n" \
"	cmpwi 4, -15007\n" \
"	bne +44\n" \
"	ld 3, 48(1)\n" \
"	ld 4, 56(1)\n" \
"	ld 5, 64(1)\n" \
"	ld 6, 72(1)\n" \
"	ld 7, 80(1)\n" \
"	ld 8, 88(1)\n" \
"	ld 9, 96(1)\n" \
"	ld 10, 104(1)\n" \
"	nop\n" \
"	nop\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#define ENCRYPTED_SYSCALL	ENCRYPTED_CONTEXT

#define ENCRYPTED_SYSCALL2(ret, name, args) asm("" \
"	.section \".text\"\n" \
"	.align 2\n" \
"	.p2align 3,,7\n" \
"	.globl "#name"\n" \
"	.section \".opd\",\"aw\"\n" \
"	.align 3\n" \
#name": \n" \
"	.quad .L."#name",.TOC.@tocbase\n" \
"	.previous\n" \
"	.type   "#name", @function\n" \
".L."#name":\n" \
"	nop\n" \
"	nop\n" \
"	nop\n" \
"	nop\n" \
"	mflr 0\n" \
"	std 0, 32(1)\n" \
"	std 2, 40(1)\n" \
"	bl +4\n" \
"	li 0, 0\n" \
"	li 2, 0\n" \
"	oris 2, 2, __toc@h\n" \
"	ori 2, 2, __toc@l\n" \
"	oris 0, 0, .L."#name"@h\n" \
"	ori 0, 0, .L."#name"@l\n" \
"	subf 0, 0, 2\n" \
"	mflr 2\n" \
"	addi 2, 2, -32\n" \
"	add  2, 2, 0\n" \
"	bl __"#name"\n" \
"	ld 2, 40(1)\n" \
"	ld 0, 32(1)\n" \
"	mtlr 0\n" \
"	blr\n" \
"	.size "#name",.-.L."#name"\n"); \
ret name args; \
ret _##name args

#endif // LV2

#else
#define ENCRYPTED_FUNCTION(ret, name, args) \
ret name args

#define ENCRYPT_PATCHED_FUNCTION(name)

#define ENCRYPTED_SUICIDAL_FUNCTION(ret, name, args) \
ret name args

#define ENCRYPT_PATCHED_SUICIDAL_FUNCTION(name)

#ifdef LV2

#define ENCRYPTED_CONTEXT 				LV2_CONTEXT
#define ENCRYPTED_CALLBACK				LV2_CALLBACK
#define ENCRYPTED_PATCHED_FUNCTION			LV2_PATCHED_FUNCTION
#define ENCRYPTED_HOOKED_FUNCTION			LV2_HOOKED_FUNCTION
#define	ENCRYPTED_HOOKED_FUNCTION_PRECALL_0		LV2_HOOKED_FUNCTION_PRECALL_0
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_1		LV2_HOOKED_FUNCTION_PRECALL_1
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_2		LV2_HOOKED_FUNCTION_PRECALL_2
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_3		LV2_HOOKED_FUNCTION_PRECALL_3
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_4		LV2_HOOKED_FUNCTION_PRECALL_4
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_5		LV2_HOOKED_FUNCTION_PRECALL_5
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_6		LV2_HOOKED_FUNCTION_PRECALL_6
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_7		LV2_HOOKED_FUNCTION_PRECALL_7
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_8		LV2_HOOKED_FUNCTION_PRECALL_8
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_0	LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_0
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_1	LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_1
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_2	LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_2
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_3	LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_3
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_4	LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_4
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_5	LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_5
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_6	LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_6
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_7	LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_7
#define ENCRYPTED_HOOKED_FUNCTION_PRECALL_SUCCESS_8	LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_8
#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_0		LV2_HOOKED_FUNCTION_POSTCALL_0
#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_1		LV2_HOOKED_FUNCTION_POSTCALL_1
#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_2		LV2_HOOKED_FUNCTION_POSTCALL_2
#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_3		LV2_HOOKED_FUNCTION_POSTCALL_3
#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_4		LV2_HOOKED_FUNCTION_POSTCALL_4
#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_5		LV2_HOOKED_FUNCTION_POSTCALL_5
#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_6		LV2_HOOKED_FUNCTION_POSTCALL_6
#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_7		LV2_HOOKED_FUNCTION_POSTCALL_7
#define ENCRYPTED_HOOKED_FUNCTION_POSTCALL_8		LV2_HOOKED_FUNCTION_POSTCALL_8
#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_0	LV2_HOOKED_FUNCTION_COND_POSTCALL_0
#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_1	LV2_HOOKED_FUNCTION_COND_POSTCALL_1
#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_2	LV2_HOOKED_FUNCTION_COND_POSTCALL_2
#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_3	LV2_HOOKED_FUNCTION_COND_POSTCALL_3
#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_4	LV2_HOOKED_FUNCTION_COND_POSTCALL_4
#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_5	LV2_HOOKED_FUNCTION_COND_POSTCALL_5
#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_6	LV2_HOOKED_FUNCTION_COND_POSTCALL_6
#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_7	LV2_HOOKED_FUNCTION_COND_POSTCALL_7
#define ENCRYPTED_HOOKED_FUNCTION_COND_POSTCALL_8	LV2_HOOKED_FUNCTION_COND_POSTCALL_8
#define ENCRYPTED_SYSCALL				LV2_SYSCALL
#define ENCRYPTED_SYSCALL2				LV2_SYSCALL2

#endif /* LV2 */

#endif // ENCRYPT_FUNCTIONS

void encrypted_data_copy(void *in, void *out, int len);

static INLINE void encrypted_data_toggle(void *buf, int len) 
{ 
	encrypted_data_copy(buf, buf, len);
}

void encrypted_data_realloc_ptr(void *buf, int len);

static INLINE void encrypted_data_destroy(void *buf, int len)
{
#ifdef LV2
	get_pseudo_random_number(buf, len);
#else
	memset(buf, 0, len);
#endif
}

uint64_t encrypted_function_destroy(void *function);

#endif /* __CRYPTCODE_H__ */
