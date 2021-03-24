// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * DXGPROCESS implementation
 *
 */

#include "dxgkrnl.h"

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk:err: " fmt

/*
 * Creates a new dxgprocess object
 * Must be called when dxgglobal->plistmutex is held
 */
struct dxgprocess *dxgprocess_create(void)
{
	/* Placeholder */
	return NULL;
}

void dxgprocess_destroy(struct dxgprocess *process)
{
	/* Placeholder */
}

void dxgprocess_release(struct kref *refcount)
{
	/* Placeholder */
}
