/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2019, Microsoft Corporation.
 * Pavel Tatashin <patatash@linux.microsoft.com>
 */

#ifndef _ASM_TRANS_TABLE_H
#define _ASM_TRANS_TABLE_H

#include <linux/bits.h>
#include <asm/pgtable-types.h>

/*
 * trans_alloc_page
 *	- Allocator that should return exactly one zeroed page, if this
 *	 allocator fails, trans_pgd returns -ENOMEM error.
 *
 * trans_alloc_arg
 *	- Passed to trans_alloc_page as an argument
 */

struct trans_pgd_info {
	void * (*trans_alloc_page)(void *arg);
	void *trans_alloc_arg;
};

int trans_pgd_create_copy(pgd_t **dst_pgdp, unsigned long start,
			  unsigned long end);

int trans_pgd_map_page(struct trans_pgd_info *info, pgd_t *trans_pgd,
		       void *page, unsigned long dst_addr, pgprot_t pgprot);

#endif /* _ASM_TRANS_TABLE_H */
