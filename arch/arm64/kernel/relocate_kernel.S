/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kexec for arm64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 * Copyright (c) 2019, Microsoft Corporation.
 * Pavel Tatashin <patatash@linux.microsoft.com>
 */

#include <linux/kexec.h>
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/kexec.h>
#include <asm/page.h>
#include <asm/sysreg.h>

GLOBAL(kexec_relocate_code_start)
/* Invalidae TLB */
.macro tlb_invalidate
	dsb	sy
	dsb	ish
	tlbi	vmalle1
	dsb	ish
	isb
.endm

/* Turn-off mmu at level specified by sctlr */
.macro turn_off_mmu sctlr, tmp1, tmp2
	mrs	\tmp1, \sctlr
	ldr	\tmp2, =SCTLR_ELx_FLAGS
	bic	\tmp1, \tmp1, \tmp2
	pre_disable_mmu_workaround
	msr	\sctlr, \tmp1
	isb
.endm

/* Turn-on mmu at level specified by sctlr */
.macro turn_on_mmu sctlr, tmp1, tmp2
	mrs	\tmp1, \sctlr
	ldr	\tmp2, =SCTLR_ELx_FLAGS
	orr	\tmp1, \tmp1, \tmp2
	msr	\sctlr, \tmp1
	ic	iallu
	dsb	nsh
	isb
.endm

/*
 * Set ttbr0 and ttbr1, called while MMU is disabled, so no need to temporarily
 * set zero_page table. Invalidate TLB after new tables are set.
 */
.macro set_ttbr arg, tmp
	ldr	\tmp, [\arg, #KEXEC_KRELOC_TRANS_TTBR0]
	msr	ttbr0_el1, \tmp
	ldr	\tmp, [\arg, #KEXEC_KRELOC_TRANS_TTBR1]
	offset_ttbr1 \tmp
	msr	ttbr1_el1, \tmp
	isb
.endm

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
 *
 * This function temporarily enables MMU if kernel relocation is needed.
 * Also, if we enter this function at EL2 on non-VHE kernel, we temporarily go
 * to EL1 to enable MMU, and escalate back to EL2 at the end to do the jump to
 * the new kernel. This is determined by presence of el2_vector.
 */
ENTRY(arm64_relocate_new_kernel)
	mrs	x1, CurrentEL
	cmp	x1, #CurrentEL_EL2
	b.ne	1f
	turn_off_mmu sctlr_el2, x1, x2		/* Turn off MMU at EL2 */
1:	mov	x20, xzr			/* x20 will hold vector value */
	ldr	x11, [x0, #KEXEC_KRELOC_COPY_LEN]
	cbz	x11, 5f				/* Check if need to relocate */
	ldr	x20, [x0, #KEXEC_KRELOC_EL2_VECTOR]
	cbz	x20, 2f				/* need to reduce to EL1? */
	msr	vbar_el2, x20			/* el2_vector present, means */
	adr	x1, 2f				/* we will do copy in el1 but */
	msr	elr_el2, x1			/* do final jump from el2 */
	eret					/* Reduce to EL1 */
2:	set_ttbr x0, x1				/* Set our page tables */
	tlb_invalidate
	turn_on_mmu sctlr_el1, x1, x2		/* Turn MMU back on */
	ldr	x1, [x0, #KEXEC_KRELOC_DST_ADDR];
	ldr	x2, [x0, #KEXEC_KRELOC_SRC_ADDR];
	mov	x12, x1				/* x12 dst backup */
3:	copy_page x1, x2, x3, x4, x5, x6, x7, x8, x9, x10
	sub	x11, x11, #PAGE_SIZE
	cbnz	x11, 3b				/* page copy loop */
	raw_dcache_line_size x2, x3		/* x2 = dcache line size */
	sub	x3, x2, #1			/* x3 = dcache_size - 1 */
	bic	x12, x12, x3
4:	dc	cvau, x12			/* Flush D-cache */
	add	x12, x12, x2
	cmp	x12, x1				/* Compare to dst + len */
	b.ne	4b				/* D-cache flush loop */
	turn_off_mmu sctlr_el1, x1, x2		/* Turn off MMU */
	tlb_invalidate				/* Invalidate TLB */
5:	ldr	x4, [x0, #KEXEC_KRELOC_ENTRY_ADDR]	/* x4 = kimage_start */
	ldr	x3, [x0, #KEXEC_KRELOC_KERN_ARG3]
	ldr	x2, [x0, #KEXEC_KRELOC_KERN_ARG2]
	ldr	x1, [x0, #KEXEC_KRELOC_KERN_ARG1]
	ldr	x0, [x0, #KEXEC_KRELOC_KERN_ARG0]	/* x0 = dtb address */
	cbnz	x20, 6f				/* need to escalate to el2? */
	br	x4				/* Jump to new world */
6:	hvc	#0				/* enters kexec_el1_sync */
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
