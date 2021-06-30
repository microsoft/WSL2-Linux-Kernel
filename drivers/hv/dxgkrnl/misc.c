// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Helper functions
 *
 */

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>

#include "dxgkrnl.h"
#include "misc.h"

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk:err: " fmt

u16 *wcsncpy(u16 *dest, const u16 *src, size_t n)
{
	int i;

	for (i = 0; i < n; i++) {
		dest[i] = src[i];
		if (src[i] == 0) {
			i++;
			break;
		}
	}
	dest[i - 1] = 0;
	return dest;
}

int dxg_copy_from_user(void *to, const void __user *from, unsigned long len)
{
	int ret = copy_from_user(to, from, len);

	if (ret) {
		pr_err("copy_from_user failed: %p %p %lx\n", to, from, len);
		return -EINVAL;
	}
	return 0;
}

int dxg_copy_to_user(void __user *to, const void *from, unsigned long len)
{
	int ret = copy_to_user(to, from, len);

	if (ret) {
		pr_err("copy_to_user failed: %p %p %lx\n", to, from, len);
		return -EINVAL;
	}
	return 0;
}
