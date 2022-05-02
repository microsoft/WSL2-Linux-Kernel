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
int dxgkio_wait_sync_file(struct dxgprocess *process, void *__user inargs);
int dxgkio_open_syncobj_from_syncfile(struct dxgprocess *p, void *__user args);

struct dxgsyncpoint {
	struct dxghostevent	hdr;
	struct dma_fence	base;
	struct dxgsharedsyncobject *shared_syncobj;
	u64			fence_value;
	u64			context;
	spinlock_t		lock;
	u64			u64;
};

#endif	 /* _DXGSYNCFILE_H */
