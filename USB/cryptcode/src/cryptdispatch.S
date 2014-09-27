.section	.text,"ax",@progbits

.type	.cryptCodeDispatch,@function
.globl	.cryptCodeDispatch
.cryptCodeDispatch:

	mflr	%r0
	std	%r0, 16(%sp)
	stdu    %r1, -0x90(%sp)

	// push caller arguments
	std	%r3, (6*8)(%sp)
	std	%r4, (7*8)(%sp)
	std	%r5, (8*8)(%sp)
	std	%r6, (9*8)(%sp)
	std	%r7, (10*8)(%sp)
	std	%r8, (11*8)(%sp)
	std	%r9, (12*8)(%sp)
	std	%r10, (13*8)(%sp)
	std 	%r11, (14*8)(%sp)

	// Enter global critical section
	bl	enter_critical_section
		
	// Get arguments and increase counter	
	ld	%r11, (14*8)(%sp)
	
	lwz	%r4, 8(%r11)
	clrlwi	%r6, %r4, 16 	// r6 = size
	clrrwi	%r9, %r4, 31	// r9 = (high bit << 31)
	srwi	%r7, %r4, 16 	// r7 = high 16 bits
	clrlwi	%r7, %r7, 17 	// r7 = counter value
	addi	%r7, %r7, 1 	// counter value update
	slwi	%r8, %r7, 16	
	or	%r4, %r8, %r6	// update r4 value
	or	%r4, %r4, %r9   // update r4 value
	stw	%r4, 8(%r11)
	
	ld	%r3, 0(%r11)
	ld	%r3, 0(%r3)
	std	%r3, (16*8)(%sp)
	
	cmpwi	%r7, 1
	bne	1f
	
	// decrypt code	
	mr	%r4, %r6
	lwz	%r5, 12(%r11)
	li	%r6, 0
	bl	code_cipher
	
1:
	// Leave critical section
	bl	leave_critical_section
	
	// run decrypted code
	ld	%r3, (6*8)(%sp)
	ld	%r4, (7*8)(%sp)
	ld	%r5, (8*8)(%sp)
	ld	%r6, (9*8)(%sp)
	ld	%r7, (10*8)(%sp)
	ld	%r8, (11*8)(%sp)
	ld	%r9, (12*8)(%sp)
	ld	%r10, (13*8)(%sp)

	ld	%r0, (16*8)(%sp)
	mtctr	%r0
	bctrl
	std	%r3, (6*8)(%sp)
	
	// Enter critical section
	bl	enter_critical_section
	
	// Get arguments and decrease counter
	ld	%r11, (14*8)(%sp)
	
	lwz	%r4, 8(%r11)
	clrlwi	%r6, %r4, 16 	// r6 = size
	clrrwi	%r9, %r4, 31	// r9 = (high bit << 31)
	srwi	%r7, %r4, 16 	// r7 = high 16 bits
	clrlwi	%r7, %r7, 17 	// r7 = counter value
	addi	%r7, %r7, -1 	// counter value update
	slwi	%r8, %r7, 16	
	or	%r4, %r8, %r6	// update r4 value
	stw	%r4, 8(%r11)
	
	cmpwi	%r7, 0
	bne	3f

	// re-encrypt code
	ld	%r3, 0(%r11)
	ld	%r3, 0(%r3)
	lwz	%r5, 12(%r11)
	mr	%r4, %r6
	li	%r6, 1
	cmpwi   %r9, 0
	beq	2f
	bl	crypto_destroy_function
	b	3f
	
2:
	bl	code_cipher
	
3:

	// Leave critical section
	bl	leave_critical_section
	
	// Return
	ld	%r3, (6*8)(%sp)
	addi	%sp, %sp, 0x90
	ld	%r0, 16(%sp)
	mtlr	%r0
	blr
	
enter_critical_section:

	mfmsr   %r0
	rlwinm  %r0, %r0, 0, 16, 16
	cmpdi   %r0, 0
	beqlr
	b	lock_crypto_mutex
	
leave_critical_section:

	mfmsr   %r0
	rlwinm  %r0, %r0, 0, 16, 16
	cmpdi   %r0, 0
	beqlr
	b	unlock_crypto_mutex

.global encrypted_function_destroy
encrypted_function_destroy:

	ld	%r3, 0(%r3)
	lha	%r3, 2(%r3)
	ldx	%r3, %r3, %r2
	lhz	%r4, 10(%r3)
	ld	%r3, 0(%r3)
	ld	%r3, 0(%r3)
	b	crypto_destroy_function


