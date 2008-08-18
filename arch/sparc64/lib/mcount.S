/*
 * Copyright (C) 2000 Anton Blanchard (anton@linuxcare.com)
 *
 * This file implements mcount(), which is used to collect profiling data.
 * This can also be tweaked for kernel stack overflow detection.
 */

#include <linux/linkage.h>

#include <asm/ptrace.h>
#include <asm/thread_info.h>

/*
 * This is the main variant and is called by C code.  GCC's -pg option
 * automatically instruments every C function with a call to this.
 */

#ifdef CONFIG_STACK_DEBUG

#define OVSTACKSIZE	4096		/* lets hope this is enough */

	.data
	.align		8
panicstring:
	.asciz		"Stack overflow\n"
	.align		8
ovstack:
	.skip		OVSTACKSIZE
#endif
	.text
	.align 32
	.globl mcount, _mcount
mcount:
_mcount:
#ifdef CONFIG_STACK_DEBUG
	/*
	 * Check whether %sp is dangerously low.
	 */
	ldub		[%g6 + TI_FPDEPTH], %g1
	srl		%g1, 1, %g3
	add		%g3, 1, %g3
	sllx		%g3, 8, %g3			! each fpregs frame is 256b
	add		%g3, 192, %g3
	add		%g6, %g3, %g3			! where does task_struct+frame end?
	sub		%g3, STACK_BIAS, %g3
	cmp		%sp, %g3
	bg,pt		%xcc, 1f
	 nop
	lduh		[%g6 + TI_CPU], %g1
	sethi		%hi(hardirq_stack), %g3
	or		%g3, %lo(hardirq_stack), %g3
	sllx		%g1, 3, %g1
	ldx		[%g3 + %g1], %g7
	sub		%g7, STACK_BIAS, %g7
	cmp		%sp, %g7
	bleu,pt		%xcc, 2f
	 sethi		%hi(THREAD_SIZE), %g3
	add		%g7, %g3, %g7
	cmp		%sp, %g7
	blu,pn		%xcc, 1f
2:	 sethi		%hi(softirq_stack), %g3
	or		%g3, %lo(softirq_stack), %g3
	ldx		[%g3 + %g1], %g7
	cmp		%sp, %g7
	bleu,pt		%xcc, 2f
	 sethi		%hi(THREAD_SIZE), %g3
	add		%g7, %g3, %g7
	cmp		%sp, %g7
	blu,pn		%xcc, 1f
	 nop
	/* If we are already on ovstack, don't hop onto it
	 * again, we are already trying to output the stack overflow
	 * message.
	 */
	sethi		%hi(ovstack), %g7		! cant move to panic stack fast enough
	 or		%g7, %lo(ovstack), %g7
	add		%g7, OVSTACKSIZE, %g3
	sub		%g3, STACK_BIAS + 192, %g3
	sub		%g7, STACK_BIAS, %g7
	cmp		%sp, %g7
	blu,pn		%xcc, 2f
	 cmp		%sp, %g3
	bleu,pn		%xcc, 1f
	 nop
2:	mov		%g3, %sp
	sethi		%hi(panicstring), %g3
	call		prom_printf
	 or		%g3, %lo(panicstring), %o0
	call		prom_halt
	 nop
#endif
1:	retl
	 nop
