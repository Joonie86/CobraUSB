.global hv_call
hv_call:

	mflr	%r0
	std	%r0, 0x10(%sp)
	mr	%r11, %r3
	mr	%r3, %r4
	mr	%r4, %r5
	mr	%r5, %r6
	mr	%r6, %r7
	mr	%r7, %r8
	mr	%r8, %r9
	mr	%r9, %r10
	sc	1
	ld	%r0, 0x10(%sp)
	mtlr	%r0
	blr

