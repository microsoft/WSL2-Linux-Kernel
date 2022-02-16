// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2022, Microsoft Corporation.
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

#include "dxgkrnl.h"
#include "dxgvmbus.h"

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk: " fmt

struct ioctl_desc {
	int (*ioctl_callback)(struct dxgprocess *p, void __user *arg);
	u32 ioctl;
	u32 arg_size;
};

static struct ioctl_desc ioctls[] = {

};

/*
 * IOCTL processing
 * The driver IOCTLs return
 * - 0 in case of success
 * - positive values, which are Windows NTSTATUS (for example, STATUS_PENDING).
 *   Positive values are success codes.
 * - Linux negative error codes
 */
static int dxgk_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	int code = _IOC_NR(p1);
	int status;
	struct dxgprocess *process;

	if (code < 1 ||  code >= ARRAY_SIZE(ioctls)) {
		DXG_ERR("bad ioctl %x %x %x %x",
			code, _IOC_TYPE(p1), _IOC_SIZE(p1), _IOC_DIR(p1));
		return -ENOTTY;
	}
	if (ioctls[code].ioctl_callback == NULL) {
		DXG_ERR("ioctl callback is NULL %x", code);
		return -ENOTTY;
	}
	if (ioctls[code].ioctl != p1) {
		DXG_ERR("ioctl mismatch. Code: %x User: %x Kernel: %x",
			code, p1, ioctls[code].ioctl);
		return -ENOTTY;
	}
	process = (struct dxgprocess *)f->private_data;
	if (process->tgid != current->tgid) {
		DXG_ERR("Call from a wrong process: %d %d",
			process->tgid, current->tgid);
		return -ENOTTY;
	}
	status = ioctls[code].ioctl_callback(process, (void *__user)p2);
	return status;
}

long dxgk_compat_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	DXG_TRACE("compat ioctl %x", p1);
	return dxgk_ioctl(f, p1, p2);
}

long dxgk_unlocked_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	DXG_TRACE("unlocked ioctl %x Code:%d", p1, _IOC_NR(p1));
	return dxgk_ioctl(f, p1, p2);
}
