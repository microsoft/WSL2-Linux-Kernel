/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kexec for arm64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 */

#include <linux/kexec.h>
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/kexec.h>
#include <asm/page.h>
#include <asm/sysreg.h>

GLOBAL(kexec_relocate_code_start)

/*
 * arm64_relocate_new_kernel - Put a 2nd stage image in place and boot it.
 *
 * The memory that the old kernel occupies may be overwritten when copying the
 * new image to its final location.  To assure that the
 * arm64_relocate_new_kernel routine which does that copy is not overwritten,
 * all code and data needed by arm64_relocate_new_kernel must be between the
 * symbols arm64_relocate_new_kernel and arm64_relocate_new_kernel_end.  The
 * machine_kexec() routine will copy arm64_relocate_new_kernel to the kexec
 * safe memory that has been set up to be preserved during the copy operation.
 */
ENTRY(arm64_relocate_new_kernel)
	/* Clear the sctlr_el2 flags. */
	mrs	x2, CurrentEL
	cmp	x2, #CurrentEL_EL2
	b.ne	1f
	mrs	x2, sctlr_el2
	ldr	x1, =SCTLR_ELx_FLAGS
	bic	x2, x2, x1
	pre_disable_mmu_workaround
	msr	sctlr_el2, x2
	isb
1:	/* Check if the new image needs relocation. */
	ldr	x16, [x0, #KEXEC_KRELOC_HEAD]	/* x16 = kimage_head */
	tbnz	x16, IND_DONE_BIT, .Ldone
	raw_dcache_line_size x15, x1		/* x15 = dcache line size */
.Lloop:
	and	x12, x16, PAGE_MASK		/* x12 = addr */
	/* Test the entry flags. */
.Ltest_source:
	tbz	x16, IND_SOURCE_BIT, .Ltest_indirection

	/* Invalidate dest page to PoC. */
	mov     x2, x13
	add     x20, x2, #PAGE_SIZE
	sub     x1, x15, #1
	bic     x2, x2, x1
2:	dc      ivac, x2
	add     x2, x2, x15
	cmp     x2, x20
	b.lo    2b
	dsb     sy

	copy_page x13, x12, x1, x2, x3, x4, x5, x6, x7, x8
	b	.Lnext
.Ltest_indirection:
	tbz	x16, IND_INDIRECTION_BIT, .Ltest_destination
	mov	x14, x12			/* ptr = addr */
	b	.Lnext
.Ltest_destination:
	tbz	x16, IND_DESTINATION_BIT, .Lnext
	mov	x13, x12			/* dest = addr */
.Lnext:
	ldr	x16, [x14], #8			/* entry = *ptr++ */
	tbz	x16, IND_DONE_BIT, .Lloop	/* while (!(entry & DONE)) */
.Ldone:
	/* wait for writes from copy_page to finish */
	dsb	nsh
	ic	iallu
	dsb	nsh
	isb

	/* Start new image. */
	ldr	x4, [x0, #KEXEC_KRELOC_ENTRY_ADDR]	/* x4 = kimage_start */
	ldr	x3, [x0, #KEXEC_KRELOC_KERN_ARG3]
	ldr	x2, [x0, #KEXEC_KRELOC_KERN_ARG2]
	ldr	x1, [x0, #KEXEC_KRELOC_KERN_ARG1]
	ldr	x0, [x0, #KEXEC_KRELOC_KERN_ARG0]	/* x0 = dtb address */
	br	x4
.ltorg
END(arm64_relocate_new_kernel)

.macro el1_sync_64
	br	x4			/* Jump to new world from el2 */
	.fill 31, 4, 0			/* Set other 31 instr to zeroes */
.endm

.macro invalid_vector label
\label:
	b \label
	.fill 31, 4, 0			/* Set other 31 instr to zeroes */
.endm

/* el2 vectors - switch el2 here while we restore the memory image. */
	.align 11
ENTRY(kexec_el2_vectors)
	invalid_vector el2_sync_invalid_sp0	/* Synchronous EL2t */
	invalid_vector el2_irq_invalid_sp0	/* IRQ EL2t */
	invalid_vector el2_fiq_invalid_sp0	/* FIQ EL2t */
	invalid_vector el2_error_invalid_sp0	/* Error EL2t */
	invalid_vector el2_sync_invalid_spx	/* Synchronous EL2h */
	invalid_vector el2_irq_invalid_spx	/* IRQ EL2h */
	invalid_vector el2_fiq_invalid_spx	/* FIQ EL2h */
	invalid_vector el2_error_invalid_spx	/* Error EL2h */
		el1_sync_64			/* Synchronous 64-bit EL1 */
	invalid_vector el1_irq_invalid_64	/* IRQ 64-bit EL1 */
	invalid_vector el1_fiq_invalid_64	/* FIQ 64-bit EL1 */
	invalid_vector el1_error_invalid_64	/* Error 64-bit EL1 */
	invalid_vector el1_sync_invalid_32	/* Synchronous 32-bit EL1 */
	invalid_vector el1_irq_invalid_32	/* IRQ 32-bit EL1 */
	invalid_vector el1_fiq_invalid_32	/* FIQ 32-bit EL1 */
	invalid_vector el1_error_invalid_32	/* Error 32-bit EL1 */
END(kexec_el2_vectors)

.Lkexec_relocate_code_end:
.org	KEXEC_CONTROL_PAGE_SIZE
.align 3	/* To keep the 64-bit values below naturally aligned. */
/*
 * kexec_relocate_code_size - Number of bytes to copy to the
 * control_code_page.
 */
GLOBAL(kexec_relocate_code_size)
	.quad	.Lkexec_relocate_code_end - kexec_relocate_code_start
GLOBAL(kexec_kern_reloc_offset)
	.quad	arm64_relocate_new_kernel - kexec_relocate_code_start
GLOBAL(kexec_el2_vectors_offset)
	.quad	kexec_el2_vectors - kexec_relocate_code_start
