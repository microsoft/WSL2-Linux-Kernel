// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@microsoft.com>
 *
 * Dxgkrnl Graphics Port Driver
 * DXGPROCSS implementation
 *
 */

#include "dxgkrnl.h"

/*
 * Creates a new dxgprocess object
 * Must be called when dxgglobal->plistmutex is held
 */
struct dxgprocess *dxgprocess_create(void)
{
	struct dxgprocess *process;
	int ret;

	TRACE_DEBUG(1, "%s", __func__);

	process = dxgmem_alloc(NULL, DXGMEM_PROCESS, sizeof(struct dxgprocess));
	if (process == NULL) {
		pr_err("failed to allocate dxgprocess\n");
	} else {
		TRACE_DEBUG(1, "new dxgprocess created\n");
		process->process = current;
		process->pid = current->pid;
		process->tgid = current->tgid;
		dxgmutex_init(&process->process_mutex, DXGLOCK_PROCESSMUTEX);
		ret = dxgvmb_send_create_process(process);
		if (ret) {
			TRACE_DEBUG(1, "dxgvmb_send_create_process failed\n");
			dxgmem_free(NULL, DXGMEM_PROCESS, process);
			process = NULL;
		} else {
			INIT_LIST_HEAD(&process->plistentry);
			process->refcount = 1;

			dxgmutex_lock(&dxgglobal->plistmutex);
			list_add_tail(&process->plistentry,
				      &dxgglobal->plisthead);
			dxgmutex_unlock(&dxgglobal->plistmutex);

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
	d3dkmt_handle h;
	void *o;
	struct dxgsyncobject *syncobj;
	struct dxgprocess_adapter *entry;
	struct dxgprocess_adapter *tmp;
	struct dxgadapter *adapter;

	TRACE_DEBUG(1, "%s", __func__);

	/* Destroy all adapter state */
	dxgglobal_acquire_process_adapter_lock();
	list_for_each_entry_safe(entry, tmp,
				 &process->process_adapter_list_head,
				 process_adapter_list_entry) {
		adapter = entry->adapter;
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
			TRACE_DEBUG(1, "Destroy syncobj: %p %d", o, i);
			syncobj = o;
			syncobj->handle = 0;
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
			dxgmem_free(process, DXGMEM_HANDLE_TABLE,
				    process->test_handle_table[i]);
			process->test_handle_table[i] = NULL;
		}
	}

	TRACE_DEBUG(1, "%s end", __func__);
}

/*
 * Release reference count on a process object
 */
void dxgprocess_release_reference(struct dxgprocess *process)
{
	TRACE_DEBUG(1, "%s %d", __func__, process->refcount);
	dxgmutex_lock(&dxgglobal->plistmutex);
	process->refcount--;
	if (process->refcount == 0) {
		list_del(&process->plistentry);
		process->plistentry.next = NULL;
		dxgmutex_unlock(&dxgglobal->plistmutex);

		dxgprocess_destroy(process);

		if (process->host_handle)
			dxgvmb_send_destroy_process(process->host_handle);
		dxgmem_check(process, DXGMEM_PROCESS);
		dxgmem_free(NULL, DXGMEM_PROCESS, process);
	} else {
		dxgmutex_unlock(&dxgglobal->plistmutex);
	}
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
			TRACE_DEBUG(1, "found process adapter info %p", entry);
			return entry;
		}
	}
	return NULL;
}

/*
 * Dxgprocess takes references on dxgadapter and  dxgprocess_adapter.
 */
int dxgprocess_open_adapter(struct dxgprocess *process,
			    struct dxgadapter *adapter, d3dkmt_handle *h)
{
	int ret = 0;
	struct dxgprocess_adapter *adapter_info;
	d3dkmt_handle handle;

	*h = 0;
	adapter_info = dxgprocess_get_adapter_info(process, adapter);
	if (adapter_info == NULL) {
		TRACE_DEBUG(1, "creating new process adapter info\n");
		adapter_info = dxgprocess_adapter_create(process, adapter);
		if (adapter_info == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
	} else {
		adapter_info->refcount++;
	}

	handle = hmgrtable_alloc_handle_safe(&process->local_handle_table,
					     adapter, HMGRENTRY_TYPE_DXGADAPTER,
					     true);
	if (handle) {
		*h = handle;
	} else {
		pr_err("failed to create adapter handle\n");
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

cleanup:

	if (ret) {
		if (adapter_info) {
			dxgglobal_acquire_process_adapter_lock();
			dxgprocess_adapter_release(adapter_info);
			dxgglobal_release_process_adapter_lock();
		}
	}

	return ret;
}

int dxgprocess_close_adapter(struct dxgprocess *process, d3dkmt_handle handle)
{
	struct dxgadapter *adapter;
	struct dxgprocess_adapter *adapter_info;
	int ret = 0;

	if (handle == 0)
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
			ret = STATUS_INVALID_PARAMETER;
		}
	} else {
		pr_err("%s failed %x", __func__, handle);
		ret = STATUS_INVALID_PARAMETER;
	}

	return ret;
}

struct dxgadapter *dxgprocess_get_adapter(struct dxgprocess *process,
					  d3dkmt_handle handle)
{
	struct dxgadapter *adapter;

	adapter = hmgrtable_get_object_by_type(&process->local_handle_table,
					       HMGRENTRY_TYPE_DXGADAPTER,
					       handle);
	if (adapter == NULL)
		pr_err("%s failed %x\n", __func__, handle);
	return adapter;
}

/*
 * Gets the adapter object from the process handle table.
 * The adapter object is referenced.
 * The function acquired the handle table lock shared.
 */
struct dxgadapter *dxgprocess_adapter_by_handle(struct dxgprocess *process,
						d3dkmt_handle handle)
{
	struct dxgadapter *adapter;

	hmgrtable_lock(&process->local_handle_table, DXGLOCK_SHARED);
	adapter = hmgrtable_get_object_by_type(&process->local_handle_table,
					       HMGRENTRY_TYPE_DXGADAPTER,
					       handle);
	if (adapter == NULL)
		pr_err("adapter_by_handle failed %x\n", handle);
	else if (!dxgadapter_acquire_reference(adapter)) {
		pr_err("failed to acquire adapter reference\n");
		adapter = NULL;
	}
	hmgrtable_unlock(&process->local_handle_table, DXGLOCK_SHARED);
	return adapter;
}

struct dxgdevice *dxgprocess_device_by_object_handle(struct dxgprocess *process,
						     enum hmgrentry_type t,
						     d3dkmt_handle handle)
{
	struct dxgdevice *device = NULL;
	void *obj;

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	obj = hmgrtable_get_object_by_type(&process->handle_table, t, handle);
	if (obj) {
		d3dkmt_handle device_handle = 0;

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
			if (!dxgdevice_acquire_reference(device))
				device = NULL;
	}
	if (device == NULL)
		pr_err("device_by_handle failed: %d %x\n", t, handle);
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);
	return device;
}

struct dxgdevice *dxgprocess_device_by_handle(struct dxgprocess *process,
					      d3dkmt_handle handle)
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
