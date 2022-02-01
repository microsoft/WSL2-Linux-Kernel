// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2022, Microsoft Corporation.
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
#define pr_fmt(fmt)	"dxgk: " fmt

/*
 * Creates a new dxgprocess object
 * Must be called when dxgglobal->plistmutex is held
 */
struct dxgprocess *dxgprocess_create(void)
{
	struct dxgprocess *process;
	int ret;
	struct dxgglobal *dxgglobal = dxggbl();

	process = kzalloc(sizeof(struct dxgprocess), GFP_KERNEL);
	if (process != NULL) {
		DXG_TRACE("new dxgprocess created");
		process->pid = current->pid;
		process->tgid = current->tgid;
		ret = dxgvmb_send_create_process(process);
		if (ret < 0) {
			DXG_TRACE("send_create_process failed");
			kfree(process);
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
			DXG_ERR("invalid entry in handle table %d", t);
			break;
		}
	}

	i = 0;
	while (hmgrtable_next_entry(&process->handle_table, &i, &t, &h, &o)) {
		switch (t) {
		case HMGRENTRY_TYPE_DXGSYNCOBJECT:
			DXG_TRACE("Destroy syncobj: %p %d", o, i);
			syncobj = o;
			syncobj->handle.v = 0;
			dxgsyncobject_destroy(process, syncobj);
			break;
		default:
			DXG_ERR("invalid entry in handle table %d", t);
			break;
		}
	}

	hmgrtable_destroy(&process->handle_table);
	hmgrtable_destroy(&process->local_handle_table);
}

void dxgprocess_release(struct kref *refcount)
{
	struct dxgprocess *process;
	struct dxgglobal *dxgglobal = dxggbl();

	process = container_of(refcount, struct dxgprocess, process_kref);

	mutex_lock(&dxgglobal->plistmutex);
	list_del(&process->plistentry);
	mutex_unlock(&dxgglobal->plistmutex);

	dxgprocess_destroy(process);

	if (process->host_handle.v)
		dxgvmb_send_destroy_process(process->host_handle);
	kfree(process);
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
			DXG_TRACE("Found process info %p", entry);
			return entry;
		}
	}
	return NULL;
}

/*
 * Dxgprocess takes references on dxgadapter and dxgprocess_adapter.
 *
 * The process_adapter lock is held.
 *
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
		DXG_TRACE("creating new process adapter info");
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
		DXG_ERR("failed to create adapter handle");
		ret = -ENOMEM;
	}

cleanup:

	if (ret < 0) {
		if (adapter_info)
			dxgprocess_adapter_release(adapter_info);
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
		DXG_ERR("Adapter not found %x", handle.v);
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
		DXG_ERR("Adapter not found %x", handle.v);
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
		DXG_ERR("adapter_by_handle failed %x", handle.v);
	else if (kref_get_unless_zero(&adapter->adapter_kref) == 0) {
		DXG_ERR("failed to acquire adapter reference");
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
		case HMGRENTRY_TYPE_DXGHWQUEUE:
			device_handle =
			    ((struct dxghwqueue *)obj)->device_handle;
			break;
		default:
			DXG_ERR("invalid handle type: %d", t);
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
		DXG_ERR("device_by_handle failed: %d %x", t, handle.v);
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
