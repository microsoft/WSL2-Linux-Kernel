// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
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
	struct dxgprocess *process;
	int ret;

	process = vzalloc(sizeof(struct dxgprocess));
	if (process != NULL) {
		dev_dbg(dxgglobaldev, "new dxgprocess created\n");
		process->process = current;
		process->pid = current->pid;
		process->tgid = current->tgid;
		mutex_init(&process->process_mutex);
		ret = dxgvmb_send_create_process(process);
		if (ret < 0) {
			dev_dbg(dxgglobaldev, "send_create_process failed\n");
			vfree(process);
			process = NULL;
		} else {
			INIT_LIST_HEAD(&process->plistentry);
			kref_init(&process->process_kref);

			mutex_lock(&dxgglobal->plistmutex);
			list_add_tail(&process->plistentry,
				      &dxgglobal->plisthead);
			mutex_unlock(&dxgglobal->plistmutex);

			hmgrtable_init(&process->handle_table, process);
			hmgrtable_init(&process->local_handle_table, process);
			INIT_LIST_HEAD(&process->process_adapter_list_head);
		}
	}
	return process;
}

void dxgprocess_destroy(struct dxgprocess *process)
{
	int i;
	enum hmgrentry_type t;
	struct d3dkmthandle h;
	void *o;
	struct dxgsyncobject *syncobj;
	struct dxgprocess_adapter *entry;
	struct dxgprocess_adapter *tmp;

	/* Destroy all adapter state */
	dxgglobal_acquire_process_adapter_lock();
	list_for_each_entry_safe(entry, tmp,
				 &process->process_adapter_list_head,
				 process_adapter_list_entry) {
		dxgprocess_adapter_destroy(entry);
	}
	dxgglobal_release_process_adapter_lock();

	i = 0;
	while (hmgrtable_next_entry(&process->local_handle_table,
				    &i, &t, &h, &o)) {
		switch (t) {
		case HMGRENTRY_TYPE_DXGADAPTER:
			dxgprocess_close_adapter(process, h);
			break;
		default:
			pr_err("invalid entry in local handle table %d", t);
			break;
		}
	}

	i = 0;
	while (hmgrtable_next_entry(&process->handle_table, &i, &t, &h, &o)) {
		switch (t) {
		case HMGRENTRY_TYPE_DXGSYNCOBJECT:
			dev_dbg(dxgglobaldev, "Destroy syncobj: %p %d", o, i);
			syncobj = o;
			syncobj->handle.v = 0;
			dxgsyncobject_destroy(process, syncobj);
			break;
		default:
			pr_err("invalid entry in handle table %d", t);
			break;
		}
	}

	hmgrtable_destroy(&process->handle_table);
	hmgrtable_destroy(&process->local_handle_table);

	for (i = 0; i < 2; i++) {
		if (process->test_handle_table[i]) {
			hmgrtable_destroy(process->test_handle_table[i]);
			vfree(process->test_handle_table[i]);
			process->test_handle_table[i] = NULL;
		}
	}
}

void dxgprocess_release(struct kref *refcount)
{
	struct dxgprocess *process;

	process = container_of(refcount, struct dxgprocess, process_kref);

	mutex_lock(&dxgglobal->plistmutex);
	list_del(&process->plistentry);
	process->plistentry.next = NULL;
	mutex_unlock(&dxgglobal->plistmutex);

	dxgprocess_destroy(process);

	if (process->host_handle.v)
		dxgvmb_send_destroy_process(process->host_handle);
	vfree(process);
}

struct dxgprocess_adapter *dxgprocess_get_adapter_info(struct dxgprocess
						       *process,
						       struct dxgadapter
						       *adapter)
{
	struct dxgprocess_adapter *entry;

	list_for_each_entry(entry, &process->process_adapter_list_head,
			    process_adapter_list_entry) {
		if (adapter == entry->adapter) {
			dev_dbg(dxgglobaldev, "Found process info %p", entry);
			return entry;
		}
	}
	return NULL;
}

/*
 * Dxgprocess takes references on dxgadapter and dxgprocess_adapter.
 */
int dxgprocess_open_adapter(struct dxgprocess *process,
					struct dxgadapter *adapter,
					struct d3dkmthandle *h)
{
	int ret = 0;
	struct dxgprocess_adapter *adapter_info;
	struct d3dkmthandle handle;

	h->v = 0;
	adapter_info = dxgprocess_get_adapter_info(process, adapter);
	if (adapter_info == NULL) {
		dev_dbg(dxgglobaldev, "creating new process adapter info\n");
		adapter_info = dxgprocess_adapter_create(process, adapter);
		if (adapter_info == NULL) {
			ret = -ENOMEM;
			goto cleanup;
		}
	} else {
		adapter_info->refcount++;
	}

	handle = hmgrtable_alloc_handle_safe(&process->local_handle_table,
					     adapter, HMGRENTRY_TYPE_DXGADAPTER,
					     true);
	if (handle.v) {
		*h = handle;
	} else {
		pr_err("failed to create adapter handle\n");
		ret = -ENOMEM;
		goto cleanup;
	}

cleanup:

	if (ret < 0) {
		if (adapter_info) {
			dxgglobal_acquire_process_adapter_lock();
			dxgprocess_adapter_release(adapter_info);
			dxgglobal_release_process_adapter_lock();
		}
	}

	return ret;
}

int dxgprocess_close_adapter(struct dxgprocess *process,
			     struct d3dkmthandle handle)
{
	struct dxgadapter *adapter;
	struct dxgprocess_adapter *adapter_info;
	int ret = 0;

	if (handle.v == 0)
		return 0;

	hmgrtable_lock(&process->local_handle_table, DXGLOCK_EXCL);
	adapter = dxgprocess_get_adapter(process, handle);
	if (adapter)
		hmgrtable_free_handle(&process->local_handle_table,
				      HMGRENTRY_TYPE_DXGADAPTER, handle);
	hmgrtable_unlock(&process->local_handle_table, DXGLOCK_EXCL);

	if (adapter) {
		adapter_info = dxgprocess_get_adapter_info(process, adapter);
		if (adapter_info) {
			dxgglobal_acquire_process_adapter_lock();
			dxgprocess_adapter_release(adapter_info);
			dxgglobal_release_process_adapter_lock();
		} else {
			ret = -EINVAL;
		}
	} else {
		pr_err("%s failed %x", __func__, handle.v);
		ret = -EINVAL;
	}

	return ret;
}

struct dxgadapter *dxgprocess_get_adapter(struct dxgprocess *process,
					  struct d3dkmthandle handle)
{
	struct dxgadapter *adapter;

	adapter = hmgrtable_get_object_by_type(&process->local_handle_table,
					       HMGRENTRY_TYPE_DXGADAPTER,
					       handle);
	if (adapter == NULL)
		pr_err("%s failed %x\n", __func__, handle.v);
	return adapter;
}

/*
 * Gets the adapter object from the process handle table.
 * The adapter object is referenced.
 * The function acquired the handle table lock shared.
 */
struct dxgadapter *dxgprocess_adapter_by_handle(struct dxgprocess *process,
						struct d3dkmthandle handle)
{
	struct dxgadapter *adapter;

	hmgrtable_lock(&process->local_handle_table, DXGLOCK_SHARED);
	adapter = hmgrtable_get_object_by_type(&process->local_handle_table,
					       HMGRENTRY_TYPE_DXGADAPTER,
					       handle);
	if (adapter == NULL)
		pr_err("adapter_by_handle failed %x\n", handle.v);
	else if (kref_get_unless_zero(&adapter->adapter_kref) == 0) {
		pr_err("failed to acquire adapter reference\n");
		adapter = NULL;
	}
	hmgrtable_unlock(&process->local_handle_table, DXGLOCK_SHARED);
	return adapter;
}

struct dxgdevice *dxgprocess_device_by_object_handle(struct dxgprocess *process,
						     enum hmgrentry_type t,
						     struct d3dkmthandle handle)
{
	struct dxgdevice *device = NULL;
	void *obj;

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	obj = hmgrtable_get_object_by_type(&process->handle_table, t, handle);
	if (obj) {
		struct d3dkmthandle device_handle = {};

		switch (t) {
		case HMGRENTRY_TYPE_DXGDEVICE:
			device = obj;
			break;
		case HMGRENTRY_TYPE_DXGCONTEXT:
			device_handle =
			    ((struct dxgcontext *)obj)->device_handle;
			break;
		case HMGRENTRY_TYPE_DXGPAGINGQUEUE:
			device_handle =
			    ((struct dxgpagingqueue *)obj)->device_handle;
			break;
		case HMGRENTRY_TYPE_DXGHWQUEUE:
			device_handle =
			    ((struct dxghwqueue *)obj)->device_handle;
			break;
		default:
			pr_err("invalid handle type: %d\n", t);
			break;
		}
		if (device == NULL)
			device = hmgrtable_get_object_by_type(
					&process->handle_table,
					 HMGRENTRY_TYPE_DXGDEVICE,
					 device_handle);
		if (device)
			if (kref_get_unless_zero(&device->device_kref) == 0)
				device = NULL;
	}
	if (device == NULL)
		pr_err("device_by_handle failed: %d %x\n", t, handle.v);
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);
	return device;
}

struct dxgdevice *dxgprocess_device_by_handle(struct dxgprocess *process,
					      struct d3dkmthandle handle)
{
	return dxgprocess_device_by_object_handle(process,
						  HMGRENTRY_TYPE_DXGDEVICE,
						  handle);
}

void dxgprocess_ht_lock_shared_down(struct dxgprocess *process)
{
	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
}

void dxgprocess_ht_lock_shared_up(struct dxgprocess *process)
{
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);
}

void dxgprocess_ht_lock_exclusive_down(struct dxgprocess *process)
{
	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
}

void dxgprocess_ht_lock_exclusive_up(struct dxgprocess *process)
{
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
}
