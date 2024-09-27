/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * OpenRISC Linux
 *
 * Linux architectural port borrowing liberally from similar works of
 * others.  All original copyrights apply as per the original source
 * declaration.
 *
 * OpenRISC implementation:
 * Copyright (C) 2003 Matjaz Breskvar <phoenix@bsemi.com>
 * Copyright (C) 2010-2011 Jonas Bonn <jonas@southpole.se>
 * et al.
 */

#ifndef __ASM_OPENRISC_FIXMAP_H
#define __ASM_OPENRISC_FIXMAP_H

/* Why exactly do we need 2 empty pages between the top of the fixed
 * addresses and the top of virtual memory?  Something is using that
 * memory space but not sure what right now... If you find it, leave
 * a comment here.
 */
#define FIXADDR_TOP	((unsigned long) (-2*PAGE_SIZE))

#include <linux/kernel.h>
#include <linux/bug.h>
#include <asm/page.h>

enum fixed_addresses {
	FIX_EARLYCON_MEM_BASE,
	__end_of_fixed_addresses
};

#define FIXADDR_SIZE		(__end_of_fixed_addresses << PAGE_SHIFT)
/* FIXADDR_BOTTOM might be a better name here... */
#define FIXADDR_START		(FIXADDR_TOP - FIXADDR_SIZE)
#define FIXMAP_PAGE_IO		PAGE_KERNEL_NOCACHE

extern void __set_fixmap(enum fixed_addresses idx,
			 phys_addr_t phys, pgprot_t flags);

#define __fix_to_virt(x)	(FIXADDR_TOP - ((x) << PAGE_SHIFT))
#define __virt_to_fix(x)	((FIXADDR_TOP - ((x)&PAGE_MASK)) >> PAGE_SHIFT)

/*
 * 'index to address' translation. If anyone tries to use the idx
 * directly without tranlation, we catch the bug with a NULL-deference
 * kernel oops. Illegal ranges of incoming indices are caught too.
 */
static __always_inline unsigned long fix_to_virt(const unsigned int idx)
{
	/*
	 * this branch gets completely eliminated after inlining,
	 * except when someone tries to use fixaddr indices in an
	 * illegal way. (such as mixing up address types or using
	 * out-of-range indices).
	 *
	 * If it doesn't get removed, the linker will complain
	 * loudly with a reasonably clear error message..
	 */
	if (idx >= __end_of_fixed_addresses)
		BUG();

	return __fix_to_virt(idx);
}

static inline unsigned long virt_to_fix(const unsigned long vaddr)
{
	BUG_ON(vaddr >= FIXADDR_TOP || vaddr < FIXADDR_START);
	return __virt_to_fix(vaddr);
}

#endif
