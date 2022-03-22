/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2022, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Headers for sync file objects
 *
 */

#ifndef _DXGSYNCFILE_H
#define _DXGSYNCFILE_H

#include <linux/sync_file.h>

int dxgkio_create_sync_file(struct dxgprocess *process, void *__user inargs);

struct dxgsyncpoint {
	struct dxghostevent	hdr;
	struct dma_fence	base;
	u64			fence_value;
	u64			context;
	spinlock_t		lock;
	u64			u64;
};

#endif	 /* _DXGSYNCFILE_H */
