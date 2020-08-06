// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@microsoft.com>
 *
 * Dxgkrnl Graphics Port Driver
 * Handle manager definitions
 *
 */

#ifndef _HMGR_H_
#define _HMGR_H_

#include "misc.h"

struct hmgrentry;

/*
 * Handle manager table.
 *
 * Implementation notes:
 *   A list of free handles is built on top of the array of table entries.
 *   free_handle_list_head is the index of the first entry in the list.
 *   m_FreeHandleListTail is the index of an entry in the list, which is
 *   HMGRTABLE_MIN_FREE_ENTRIES from the head. It means that when a handle is
 *   freed, the next time the handle can be re-used is after allocating
 *   HMGRTABLE_MIN_FREE_ENTRIES number of handles.
 *   Handles are allocated from the start of the list and free handles are
 *   inserted after the tail of the list.
 *
 */
struct hmgrtable {
	struct dxgprocess	*process;
	struct hmgrentry	*entry_table;
	uint			free_handle_list_head;
	uint			free_handle_list_tail;
	uint			table_size;
	uint			free_count;
	struct rw_semaphore	table_lock;
};

/*
 * Handle entry data types.
 */
#define HMGRENTRY_TYPE_BITS 5

enum hmgrentry_type {
	HMGRENTRY_TYPE_FREE				= 0,
	HMGRENTRY_TYPE_DXGADAPTER			= 1,
	HMGRENTRY_TYPE_DXGSHAREDRESOURCE		= 2,
	HMGRENTRY_TYPE_DXGDEVICE			= 3,
	HMGRENTRY_TYPE_DXGRESOURCE			= 4,
	HMGRENTRY_TYPE_DXGALLOCATION			= 5,
	HMGRENTRY_TYPE_DXGOVERLAY			= 6,
	HMGRENTRY_TYPE_DXGCONTEXT			= 7,
	HMGRENTRY_TYPE_DXGSYNCOBJECT			= 8,
	HMGRENTRY_TYPE_DXGKEYEDMUTEX			= 9,
	HMGRENTRY_TYPE_DXGPAGINGQUEUE			= 10,
	HMGRENTRY_TYPE_DXGDEVICESYNCOBJECT		= 11,
	HMGRENTRY_TYPE_DXGPROCESS			= 12,
	HMGRENTRY_TYPE_DXGSHAREDVMOBJECT		= 13,
	HMGRENTRY_TYPE_DXGPROTECTEDSESSION		= 14,
	HMGRENTRY_TYPE_DXGHWQUEUE			= 15,
	HMGRENTRY_TYPE_DXGREMOTEBUNDLEOBJECT		= 16,
	HMGRENTRY_TYPE_DXGCOMPOSITIONSURFACEOBJECT	= 17,
	HMGRENTRY_TYPE_DXGCOMPOSITIONSURFACEPROXY	= 18,
	HMGRENTRY_TYPE_DXGTRACKEDWORKLOAD		= 19,
	HMGRENTRY_TYPE_LIMIT				= ((1 << HMGRENTRY_TYPE_BITS) - 1),
	HMGRENTRY_TYPE_MONITOREDFENCE			= HMGRENTRY_TYPE_LIMIT + 1,
};

void hmgrtable_init(struct hmgrtable *tbl, struct dxgprocess *process);
void hmgrtable_destroy(struct hmgrtable *tbl);
void hmgrtable_lock(struct hmgrtable *tbl, enum dxglockstate state);
void hmgrtable_unlock(struct hmgrtable *tbl, enum dxglockstate state);
struct d3dkmthandle hmgrtable_alloc_handle(struct hmgrtable *tbl, void *object,
				     enum hmgrentry_type t, bool make_valid);
struct d3dkmthandle hmgrtable_alloc_handle_safe(struct hmgrtable *tbl,
						void *obj,
						enum hmgrentry_type t,
						bool reserve);
int hmgrtable_assign_handle(struct hmgrtable *tbl, void *obj,
			    enum hmgrentry_type, struct d3dkmthandle h);
int hmgrtable_assign_handle_safe(struct hmgrtable *tbl, void *obj,
				 enum hmgrentry_type t, struct d3dkmthandle h);
void hmgrtable_free_handle(struct hmgrtable *tbl, enum hmgrentry_type t,
			   struct d3dkmthandle h);
void hmgrtable_free_handle_safe(struct hmgrtable *tbl, enum hmgrentry_type t,
				struct d3dkmthandle h);
struct d3dkmthandle hmgrtable_build_entry_handle(struct hmgrtable *tbl,
						 uint index);
enum hmgrentry_type hmgrtable_get_object_type(struct hmgrtable *tbl,
					      struct d3dkmthandle h);
void *hmgrtable_get_object(struct hmgrtable *tbl, struct d3dkmthandle h);
void *hmgrtable_get_object_by_type(struct hmgrtable *tbl, enum hmgrentry_type t,
				   struct d3dkmthandle h);
void *hmgrtable_get_object_ignore_destroyed(struct hmgrtable *tbl,
					    struct d3dkmthandle h,
					    enum hmgrentry_type t);
bool hmgrtable_mark_destroyed(struct hmgrtable *tbl, struct d3dkmthandle h);
bool hmgrtable_unmark_destroyed(struct hmgrtable *tbl, struct d3dkmthandle h);
void *hmgrtable_get_entry_object(struct hmgrtable *tbl, uint index);
bool hmgrtable_next_entry(struct hmgrtable *tbl,
			  uint *start_index,
			  enum hmgrentry_type *type,
			  struct d3dkmthandle *handle,
			  void **object);

#endif
