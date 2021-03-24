// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Handle manager implementation
 *
 */

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>

#include "misc.h"
#include "dxgkrnl.h"
#include "hmgr.h"

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk:err: " fmt

const struct d3dkmthandle zerohandle;

/*
 * Handle parameters
 */
#define HMGRHANDLE_INSTANCE_BITS	6
#define HMGRHANDLE_INDEX_BITS		24
#define HMGRHANDLE_UNIQUE_BITS		2

#define HMGRHANDLE_INSTANCE_SHIFT	0
#define HMGRHANDLE_INDEX_SHIFT	\
	(HMGRHANDLE_INSTANCE_BITS + HMGRHANDLE_INSTANCE_SHIFT)
#define HMGRHANDLE_UNIQUE_SHIFT	\
	(HMGRHANDLE_INDEX_BITS + HMGRHANDLE_INDEX_SHIFT)

#define HMGRHANDLE_INSTANCE_MASK \
	(((1 << HMGRHANDLE_INSTANCE_BITS) - 1) << HMGRHANDLE_INSTANCE_SHIFT)
#define HMGRHANDLE_INDEX_MASK      \
	(((1 << HMGRHANDLE_INDEX_BITS)    - 1) << HMGRHANDLE_INDEX_SHIFT)
#define HMGRHANDLE_UNIQUE_MASK     \
	(((1 << HMGRHANDLE_UNIQUE_BITS)   - 1) << HMGRHANDLE_UNIQUE_SHIFT)

#define HMGRHANDLE_INSTANCE_MAX	((1 << HMGRHANDLE_INSTANCE_BITS) - 1)
#define HMGRHANDLE_INDEX_MAX	((1 << HMGRHANDLE_INDEX_BITS) - 1)
#define HMGRHANDLE_UNIQUE_MAX	((1 << HMGRHANDLE_UNIQUE_BITS) - 1)

/*
 * Handle entry
 */
struct hmgrentry {
	union {
		void *object;
		struct {
			u32 prev_free_index;
			u32 next_free_index;
		};
	};
	u32 type:HMGRENTRY_TYPE_BITS + 1;
	u32 unique:HMGRHANDLE_UNIQUE_BITS;
	u32 instance:HMGRHANDLE_INSTANCE_BITS;
	u32 destroyed:1;
};

#define HMGRTABLE_INVALID_INDEX (~((1 << HMGRHANDLE_INDEX_BITS) - 1))

void hmgrtable_init(struct hmgrtable *table, struct dxgprocess *process)
{
	table->process = process;
	table->entry_table = NULL;
	table->table_size = 0;
	table->free_handle_list_head = HMGRTABLE_INVALID_INDEX;
	table->free_handle_list_tail = HMGRTABLE_INVALID_INDEX;
	table->free_count = 0;
	init_rwsem(&table->table_lock);
}

void hmgrtable_destroy(struct hmgrtable *table)
{
	if (table->entry_table) {
		vfree(table->entry_table);
		table->entry_table = NULL;
	}
}

