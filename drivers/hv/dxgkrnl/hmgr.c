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

#define HMGRTABLE_SIZE_INCREMENT	1024
#define HMGRTABLE_MIN_FREE_ENTRIES 128
#define HMGRTABLE_INVALID_INDEX (~((1 << HMGRHANDLE_INDEX_BITS) - 1))
#define HMGRTABLE_SIZE_MAX		0xFFFFFFF

static u32 table_size_increment = HMGRTABLE_SIZE_INCREMENT;

static inline u32 get_unique(struct d3dkmthandle h)
{
	return (h.v & HMGRHANDLE_UNIQUE_MASK) >> HMGRHANDLE_UNIQUE_SHIFT;
}

static u32 get_index(struct d3dkmthandle h)
{
	return (h.v & HMGRHANDLE_INDEX_MASK) >> HMGRHANDLE_INDEX_SHIFT;
}

u32 get_instance(struct d3dkmthandle h)
{
	return (h.v & HMGRHANDLE_INSTANCE_MASK) >> HMGRHANDLE_INSTANCE_SHIFT;
}

static bool is_handle_valid(struct hmgrtable *table, struct d3dkmthandle h,
			    bool ignore_destroyed, enum hmgrentry_type t)
{
	u32 index = get_index(h);
	u32 unique = get_unique(h);
	struct hmgrentry *entry;

	if (index >= table->table_size) {
		pr_err("%s Invalid index %x %d\n", __func__, h.v, index);
		return false;
	}

	entry = &table->entry_table[index];
	if (unique != entry->unique) {
		pr_err("%s Invalid unique %x %d %d %d %p",
			   __func__, h.v, unique, entry->unique,
			   index, entry->object);
		return false;
	}

	if (entry->destroyed && !ignore_destroyed) {
		pr_err("%s Invalid destroyed", __func__);
		return false;
	}

	if (entry->type == HMGRENTRY_TYPE_FREE) {
		pr_err("%s Entry is freed %x %d", __func__, h.v, index);
		return false;
	}

	if (t != HMGRENTRY_TYPE_FREE && t != entry->type) {
		pr_err("%s type mismatch %x %d %d", __func__, h.v,
			   t, entry->type);
		return false;
	}

	return true;
}

static struct d3dkmthandle build_handle(u32 index, u32 unique, u32 instance)
{
	struct d3dkmthandle handle;

	handle.v = (index << HMGRHANDLE_INDEX_SHIFT) & HMGRHANDLE_INDEX_MASK;
	handle.v |= (unique << HMGRHANDLE_UNIQUE_SHIFT) &
	    HMGRHANDLE_UNIQUE_MASK;
	handle.v |= (instance << HMGRHANDLE_INSTANCE_SHIFT) &
	    HMGRHANDLE_INSTANCE_MASK;

	return handle;
}

inline u32 hmgrtable_get_used_entry_count(struct hmgrtable *table)
{
	DXGKRNL_ASSERT(table->table_size >= table->free_count);
	return (table->table_size - table->free_count);
}

bool hmgrtable_mark_destroyed(struct hmgrtable *table, struct d3dkmthandle h)
{
	if (!is_handle_valid(table, h, false, HMGRENTRY_TYPE_FREE))
		return false;

	table->entry_table[get_index(h)].destroyed = true;
	return true;
}

bool hmgrtable_unmark_destroyed(struct hmgrtable *table, struct d3dkmthandle h)
{
	if (!is_handle_valid(table, h, true, HMGRENTRY_TYPE_FREE))
		return true;

	DXGKRNL_ASSERT(table->entry_table[get_index(h)].destroyed);
	table->entry_table[get_index(h)].destroyed = 0;
	return true;
}

static inline bool is_empty(struct hmgrtable *table)
{
	return (table->free_count == table->table_size);
}

void print_status(struct hmgrtable *table)
{
	int i;

	dev_dbg(dxgglobaldev, "hmgrtable head, tail %p %d %d\n",
		    table, table->free_handle_list_head,
		    table->free_handle_list_tail);
	if (table->entry_table == NULL)
		return;
	for (i = 0; i < 3; i++) {
		if (table->entry_table[i].type != HMGRENTRY_TYPE_FREE)
			dev_dbg(dxgglobaldev, "hmgrtable entry %p %d %p\n",
				    table, i, table->entry_table[i].object);
		else
			dev_dbg(dxgglobaldev, "hmgrtable entry %p %d %d %d\n",
				    table, i,
				    table->entry_table[i].next_free_index,
				    table->entry_table[i].prev_free_index);
	}
}

static bool expand_table(struct hmgrtable *table, u32 NumEntries)
{
	u32 new_table_size;
	struct hmgrentry *new_entry;
	u32 table_index;
	u32 new_free_count;
	u32 prev_free_index;
	u32 tail_index = table->free_handle_list_tail;

	/* The tail should point to the last free element in the list */
	if (!(table->free_count == 0 ||
	      table->entry_table[tail_index].next_free_index ==
	      HMGRTABLE_INVALID_INDEX)) {
		pr_err("%s:corruption\n", __func__);
		return false;
	}

	new_free_count = table_size_increment;
	new_table_size = table->table_size + table_size_increment;
	if (new_table_size < NumEntries) {
		new_free_count += NumEntries - new_table_size;
		new_table_size = NumEntries;
	}

	if (new_table_size > HMGRHANDLE_INDEX_MAX) {
		pr_err("%s:corruption\n", __func__);
		return false;
	}

	new_entry = (struct hmgrentry *)
	    vzalloc(new_table_size * sizeof(struct hmgrentry));
	if (new_entry == NULL) {
		pr_err("%s:allocation failed\n", __func__);
		return false;
	}

	if (table->entry_table) {
		memcpy(new_entry, table->entry_table,
		       table->table_size * sizeof(struct hmgrentry));
		vfree(table->entry_table);
	} else {
		table->free_handle_list_head = 0;
	}

	table->entry_table = new_entry;

	/* Initialize new table entries and add to the free list */
	table_index = table->table_size;

	prev_free_index = table->free_handle_list_tail;

	while (table_index < new_table_size) {
		struct hmgrentry *entry = &table->entry_table[table_index];

		entry->prev_free_index = prev_free_index;
		entry->next_free_index = table_index + 1;
		entry->type = HMGRENTRY_TYPE_FREE;
		entry->unique = 1;
		entry->instance = 0;
		prev_free_index = table_index;

		table_index++;
	}

	table->entry_table[table_index - 1].next_free_index =
	    (u32) HMGRTABLE_INVALID_INDEX;

	if (table->free_count != 0) {
		/* Link the current free list with the new entries */
		struct hmgrentry *entry;

		entry = &table->entry_table[table->free_handle_list_tail];
		entry->next_free_index = table->table_size;
	}
	table->free_handle_list_tail = new_table_size - 1;
	if (table->free_handle_list_head == HMGRTABLE_INVALID_INDEX)
		table->free_handle_list_head = table->table_size;

	table->table_size = new_table_size;
	table->free_count = new_free_count;

	return true;
}

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

void hmgrtable_lock(struct hmgrtable *table, enum dxglockstate state)
{
	if (state == DXGLOCK_EXCL)
		down_write(&table->table_lock);
	else
		down_read(&table->table_lock);
}

void hmgrtable_unlock(struct hmgrtable *table, enum dxglockstate state)
{
	if (state == DXGLOCK_EXCL)
		up_write(&table->table_lock);
	else
		up_read(&table->table_lock);
}

struct d3dkmthandle hmgrtable_alloc_handle(struct hmgrtable *table,
					   void *object,
					   enum hmgrentry_type type,
					   bool make_valid)
{
	u32 index;
	struct hmgrentry *entry;
	u32 unique;

	DXGKRNL_ASSERT(type <= HMGRENTRY_TYPE_LIMIT);
	DXGKRNL_ASSERT(type > HMGRENTRY_TYPE_FREE);

	if (table->free_count <= HMGRTABLE_MIN_FREE_ENTRIES) {
		if (!expand_table(table, 0)) {
			pr_err("hmgrtable expand_table failed\n");
			return zerohandle;
		}
	}

	if (table->free_handle_list_head >= table->table_size) {
		pr_err("hmgrtable corrupted handle table head\n");
		return zerohandle;
	}

	index = table->free_handle_list_head;
	entry = &table->entry_table[index];

	if (entry->type != HMGRENTRY_TYPE_FREE) {
		pr_err("hmgrtable expected free handle\n");
		return zerohandle;
	}

	table->free_handle_list_head = entry->next_free_index;

	if (entry->next_free_index != table->free_handle_list_tail) {
		if (entry->next_free_index >= table->table_size) {
			pr_err("hmgrtable invalid next free index\n");
			return zerohandle;
		}
		table->entry_table[entry->next_free_index].prev_free_index =
		    HMGRTABLE_INVALID_INDEX;
	}

	unique = table->entry_table[index].unique;

	table->entry_table[index].object = object;
	table->entry_table[index].type = type;
	table->entry_table[index].instance = 0;
	table->entry_table[index].destroyed = !make_valid;
	table->free_count--;

	return build_handle(index, unique, table->entry_table[index].instance);
}

int hmgrtable_assign_handle_safe(struct hmgrtable *table,
				 void *object,
				 enum hmgrentry_type type,
				 struct d3dkmthandle h)
{
	int ret;

	hmgrtable_lock(table, DXGLOCK_EXCL);
	ret = hmgrtable_assign_handle(table, object, type, h);
	hmgrtable_unlock(table, DXGLOCK_EXCL);
	return ret;
}

int hmgrtable_assign_handle(struct hmgrtable *table, void *object,
			    enum hmgrentry_type type, struct d3dkmthandle h)
{
	u32 index = get_index(h);
	u32 unique = get_unique(h);
	struct hmgrentry *entry = NULL;

	dev_dbg(dxgglobaldev, "%s %x, %d %p, %p\n",
		    __func__, h.v, index, object, table);

	if (index >= HMGRHANDLE_INDEX_MAX) {
		pr_err("handle index is too big: %x %d", h.v, index);
		return -EINVAL;
	}

	if (index >= table->table_size) {
		u32 new_size = index + table_size_increment;

		if (new_size > HMGRHANDLE_INDEX_MAX)
			new_size = HMGRHANDLE_INDEX_MAX;
		if (!expand_table(table, new_size)) {
			pr_err("failed to expand handle table %d", new_size);
			return -ENOMEM;
		}
	}

	entry = &table->entry_table[index];

	if (entry->type != HMGRENTRY_TYPE_FREE) {
		pr_err("the entry is already busy: %d %x",
			   entry->type,
			   hmgrtable_build_entry_handle(table, index).v);
		return -EINVAL;
	}

	if (index != table->free_handle_list_tail) {
		if (entry->next_free_index >= table->table_size) {
			pr_err("hmgr: invalid next free index %d\n",
				   entry->next_free_index);
			return -EINVAL;
		}
		table->entry_table[entry->next_free_index].prev_free_index =
		    entry->prev_free_index;
	} else {
		table->free_handle_list_tail = entry->prev_free_index;
	}

	if (index != table->free_handle_list_head) {
		if (entry->prev_free_index >= table->table_size) {
			pr_err("hmgr: invalid next prev index %d\n",
				   entry->prev_free_index);
			return -EINVAL;
		}
		table->entry_table[entry->prev_free_index].next_free_index =
		    entry->next_free_index;
	} else {
		table->free_handle_list_head = entry->next_free_index;
	}

	entry->prev_free_index = HMGRTABLE_INVALID_INDEX;
	entry->next_free_index = HMGRTABLE_INVALID_INDEX;
	entry->object = object;
	entry->type = type;
	entry->instance = 0;
	entry->unique = unique;
	entry->destroyed = false;

	table->free_count--;
	return 0;
}

struct d3dkmthandle hmgrtable_alloc_handle_safe(struct hmgrtable *table,
						void *obj,
						enum hmgrentry_type type,
						bool make_valid)
{
	struct d3dkmthandle h;

	hmgrtable_lock(table, DXGLOCK_EXCL);
	h = hmgrtable_alloc_handle(table, obj, type, make_valid);
	hmgrtable_unlock(table, DXGLOCK_EXCL);
	return h;
}

void hmgrtable_free_handle(struct hmgrtable *table, enum hmgrentry_type t,
			   struct d3dkmthandle h)
{
	struct hmgrentry *entry;
	u32 i = get_index(h);

	dev_dbg(dxgglobaldev, "%s: %p %x\n", __func__, table, h.v);

	/* Ignore the destroyed flag when checking the handle */
	if (is_handle_valid(table, h, true, t)) {
		DXGKRNL_ASSERT(table->free_count < table->table_size);
		entry = &table->entry_table[i];
		entry->unique = 1;
		entry->type = HMGRENTRY_TYPE_FREE;
		entry->destroyed = 0;
		if (entry->unique != HMGRHANDLE_UNIQUE_MAX)
			entry->unique += 1;
		else
			entry->unique = 1;

		table->free_count++;

		/*
		 * Insert the index to the free list at the tail.
		 */
		entry->next_free_index = HMGRTABLE_INVALID_INDEX;
		entry->prev_free_index = table->free_handle_list_tail;
		entry = &table->entry_table[table->free_handle_list_tail];
		entry->next_free_index = i;
		table->free_handle_list_tail = i;
	} else {
		pr_err("%s:error: %d %x\n", __func__, i, h.v);
	}
}

void hmgrtable_free_handle_safe(struct hmgrtable *table, enum hmgrentry_type t,
				struct d3dkmthandle h)
{
	hmgrtable_lock(table, DXGLOCK_EXCL);
	hmgrtable_free_handle(table, t, h);
	hmgrtable_unlock(table, DXGLOCK_EXCL);
}

struct d3dkmthandle hmgrtable_build_entry_handle(struct hmgrtable *table,
						 u32 index)
{
	DXGKRNL_ASSERT(index < table->table_size);

	return build_handle(index, table->entry_table[index].unique,
			    table->entry_table[index].instance);
}

void *hmgrtable_get_object(struct hmgrtable *table, struct d3dkmthandle h)
{
	if (!is_handle_valid(table, h, false, HMGRENTRY_TYPE_FREE))
		return NULL;

	return table->entry_table[get_index(h)].object;
}

void *hmgrtable_get_object_by_type(struct hmgrtable *table,
				   enum hmgrentry_type type,
				   struct d3dkmthandle h)
{
	if (!is_handle_valid(table, h, false, type)) {
		pr_err("%s invalid handle %x\n", __func__, h.v);
		return NULL;
	}
	return table->entry_table[get_index(h)].object;
}

void *hmgrtable_get_entry_object(struct hmgrtable *table, u32 index)
{
	DXGKRNL_ASSERT(index < table->table_size);
	DXGKRNL_ASSERT(table->entry_table[index].type != HMGRENTRY_TYPE_FREE);

	return table->entry_table[index].object;
}

enum hmgrentry_type hmgrtable_get_entry_type(struct hmgrtable *table,
					     u32 index)
{
	DXGKRNL_ASSERT(index < table->table_size);
	return (enum hmgrentry_type)table->entry_table[index].type;
}

enum hmgrentry_type hmgrtable_get_object_type(struct hmgrtable *table,
					      struct d3dkmthandle h)
{
	if (!is_handle_valid(table, h, false, HMGRENTRY_TYPE_FREE))
		return HMGRENTRY_TYPE_FREE;

	return hmgrtable_get_entry_type(table, get_index(h));
}

void *hmgrtable_get_object_ignore_destroyed(struct hmgrtable *table,
					    struct d3dkmthandle h,
					    enum hmgrentry_type type)
{
	if (!is_handle_valid(table, h, true, type))
		return NULL;
	return table->entry_table[get_index(h)].object;
}

bool hmgrtable_next_entry(struct hmgrtable *tbl,
			  u32 *index,
			  enum hmgrentry_type *type,
			  struct d3dkmthandle *handle,
			  void **object)
{
	u32 i;
	struct hmgrentry *entry;

	for (i = *index; i < tbl->table_size; i++) {
		entry = &tbl->entry_table[i];
		if (entry->type != HMGRENTRY_TYPE_FREE) {
			*index = i + 1;
			*object = entry->object;
			*handle = build_handle(i, entry->unique,
					       entry->instance);
			*type = entry->type;
			return true;
		}
	}
	return false;
}
