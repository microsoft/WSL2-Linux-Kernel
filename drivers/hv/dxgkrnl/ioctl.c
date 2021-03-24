// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Ioctl implementation
 *
 */

#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>

/*
 * Placeholder for IOCTL implementation
 */

long dxgk_compat_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	return -ENODEV;
}

long dxgk_unlocked_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	return -ENODEV;
}

void init_ioctls(void)
{
	/* Placeholder */
}
