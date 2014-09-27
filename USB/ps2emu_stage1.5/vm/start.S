.text
	.section .start,"ax",@progbits
	.align 3

	.global _start

_start:

	mflr	%r0
	std 	%r0, 0x10(%sp)
	stdu 	%sp, -0x80(%sp)
	std	%rtoc, 0x28(%sp)

	lis 	%rtoc, __toc@ha
	addi 	%rtoc, %rtoc, __toc@l
	bl	main	
	
	ld	%rtoc, 0x28(%sp)
	addi 	%sp, %sp, 0x80
	
	// Stage1 return
	ld	%r23, 0x70(%sp)
	ld	%r24, 0x78(%sp)
	ld	%r25, 0x80(%sp)
	ld	%r26, 0x88(%sp)
	ld	%r31, 0x90(%sp)
	ld	%r30, 0x98(%sp)
	ld	%r0, 0xE0(%sp)
	mtlr	%r0
	addi	%sp, %sp, 0xD0
	blr




