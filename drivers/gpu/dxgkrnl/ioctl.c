// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@microsoft.com>
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

struct ioctl_desc {
	ntstatus(*ioctl_callback) (struct dxgprocess *p, void *__user arg);
	u32 ioctl;
	u32 arg_size;
};
static struct ioctl_desc ioctls[LX_IO_MAX + 1];

static int dxgsyncobj_release(struct inode *inode, struct file *file)
{
	struct dxgsharedsyncobject *syncobj = file->private_data;
	struct dxgthreadinfo *thread = dxglockorder_get_thread();

	TRACE_DEBUG(1, "%s: %p", __func__, syncobj);
	dxgmutex_lock(&syncobj->fd_mutex);
	dxgsharedsyncobj_acquire_reference(syncobj);
	syncobj->host_shared_handle_nt_reference--;
	if (syncobj->host_shared_handle_nt_reference == 0) {
		if (syncobj->host_shared_handle_nt) {
			dxgvmb_send_destroy_nt_shared_object(
					syncobj->host_shared_handle_nt);
			TRACE_DEBUG(1, "Syncobj host_handle_nt destroyed: %x",
				    syncobj->host_shared_handle_nt);
			syncobj->host_shared_handle_nt = 0;
		}
		dxgsharedsyncobj_release_reference(syncobj);
	}
	dxgmutex_unlock(&syncobj->fd_mutex);
	dxgsharedsyncobj_release_reference(syncobj);
	dxglockorder_put_thread(thread);
	return 0;
}

static const struct file_operations dxg_syncobj_fops = {
	.release = dxgsyncobj_release,
};

static int dxgsharedresource_release(struct inode *inode, struct file *file)
{
	struct dxgsharedresource *resource = file->private_data;
	struct dxgthreadinfo *thread = dxglockorder_get_thread();

	TRACE_DEBUG(1, "%s: %p", __func__, resource);
	dxgmutex_lock(&resource->fd_mutex);
	dxgsharedresource_acquire_reference(resource);
	resource->host_shared_handle_nt_reference--;
	if (resource->host_shared_handle_nt_reference == 0) {
		if (resource->host_shared_handle_nt) {
			dxgvmb_send_destroy_nt_shared_object(
					resource->host_shared_handle_nt);
			TRACE_DEBUG(1, "Resource host_handle_nt destroyed: %x",
				    resource->host_shared_handle_nt);
			resource->host_shared_handle_nt = 0;
		}
		dxgsharedresource_release_reference(resource);
	}
	dxgmutex_unlock(&resource->fd_mutex);
	dxgsharedresource_release_reference(resource);
	dxglockorder_put_thread(thread);
	return 0;
}

static const struct file_operations dxg_resource_fops = {
	.release = dxgsharedresource_release,
};

static int dxgk_open_adapter_from_luid(struct dxgprocess *process,
				       void *__user inargs)
{
	struct d3dkmt_openadapterfromluid args;
	int ret = 0;
	struct dxgadapter *entry;
	struct dxgadapter *adapter = NULL;
	struct d3dkmt_openadapterfromluid *__user result = inargs;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	dxgglobal_acquire_adapter_list_lock(DXGLOCK_SHARED);
	dxgglobal_acquire_process_adapter_lock();

	list_for_each_entry(entry, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (dxgadapter_acquire_lock_shared(entry) == 0) {
			TRACE_DEBUG(1, "Compare luids: %d:%d  %d:%d",
				    entry->luid.b, entry->luid.a,
				    args.adapter_luid.b, args.adapter_luid.a);
			if (*(u64 *) &entry->luid ==
			    *(u64 *) &args.adapter_luid) {
				ret =
				    dxgprocess_open_adapter(process, entry,
						    &args.adapter_handle);

				if (NT_SUCCESS(ret)) {
					ret = dxg_copy_to_user(
						&result->adapter_handle,
						&args.adapter_handle,
						sizeof(d3dkmt_handle));
				}
				adapter = entry;
			}
			dxgadapter_release_lock_shared(entry);
			if (adapter)
				break;
		}
	}

	dxgglobal_release_process_adapter_lock();
	dxgglobal_release_adapter_list_lock(DXGLOCK_SHARED);

	if (args.adapter_handle == 0)
		ret = STATUS_INVALID_PARAMETER;

cleanup:

	if (ret)
		dxgprocess_close_adapter(process, args.adapter_handle);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgkp_enum_adapters(struct dxgprocess *process,
			       union d3dkmt_enumadapters_filter filter,
			       uint adapter_count_max,
			       struct d3dkmt_adapterinfo *__user info_out,
			       uint * __user adapter_count_out)
{
	int ret = 0;
	struct dxgadapter *entry;
	struct d3dkmt_adapterinfo *info = NULL;
	struct dxgadapter **adapters = NULL;
	int adapter_count = 0;
	int i;

	TRACE_FUNC_ENTER(__func__);
	if (info_out == NULL || adapter_count_max == 0) {
		ret = 0;
		TRACE_DEBUG(1, "buffer is NULL");
		ret = dxg_copy_to_user(adapter_count_out,
				       &dxgglobal->num_adapters, sizeof(uint));
		goto cleanup;
	}

	if (adapter_count_max > 0xFFFF) {
		pr_err("too many adapters");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	info = dxgmem_alloc(process, DXGMEM_TMP,
			    sizeof(struct d3dkmt_adapterinfo) *
			    adapter_count_max);
	if (info == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	adapters = dxgmem_alloc(process, DXGMEM_TMP,
				sizeof(struct dxgadapter *) *
				adapter_count_max);
	if (adapters == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	dxgglobal_acquire_adapter_list_lock(DXGLOCK_SHARED);
	dxgglobal_acquire_process_adapter_lock();

	list_for_each_entry(entry, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (dxgadapter_acquire_lock_shared(entry) == 0) {
			struct d3dkmt_adapterinfo *inf = &info[adapter_count];

			ret = dxgprocess_open_adapter(process, entry,
						      &inf->adapter_handle);
			if (NT_SUCCESS(ret)) {
				inf->adapter_luid = entry->luid;
				adapters[adapter_count] = entry;
				TRACE_DEBUG(1, "adapter: %x %x:%x",
					    inf->adapter_handle,
					    inf->adapter_luid.b,
					    inf->adapter_luid.a);
				adapter_count++;
			}
			dxgadapter_release_lock_shared(entry);
		}
		if (ret)
			break;
	}

	dxgglobal_release_process_adapter_lock();
	dxgglobal_release_adapter_list_lock(DXGLOCK_SHARED);

	if (adapter_count > adapter_count_max) {
		ret = STATUS_BUFFER_TOO_SMALL;
		TRACE_DEBUG(1, "Too many adapters");
		ret = dxg_copy_to_user(adapter_count_out,
				       &dxgglobal->num_adapters, sizeof(uint));
		goto cleanup;
	}

	ret = dxg_copy_to_user(adapter_count_out, &adapter_count,
			       sizeof(adapter_count));
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(info_out, info, sizeof(info[0]) * adapter_count);

cleanup:

	if (NT_SUCCESS(ret)) {
		TRACE_DEBUG(1, "found %d adapters", adapter_count);
		goto success;
	}
	if (info) {
		for (i = 0; i < adapter_count; i++)
			dxgprocess_close_adapter(process,
						 info[i].adapter_handle);
	}
success:
	if (info)
		dxgmem_free(process, DXGMEM_TMP, info);
	if (adapters)
		dxgmem_free(process, DXGMEM_TMP, adapters);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgsharedresource_seal(struct dxgsharedresource *shared_resource)
{
	int ret = 0;
	int i = 0;
	uint8_t *private_data;
	uint data_size;
	struct dxgresource *resource;
	struct dxgallocation *alloc;

	TRACE_DEBUG(1, "Sealing resource: %p", shared_resource);

	down_write(&shared_resource->adapter->shared_resource_list_lock);
	if (shared_resource->sealed) {
		TRACE_DEBUG(1, "Resource already sealed");
		goto cleanup;
	}
	shared_resource->sealed = 1;
	if (!list_empty(&shared_resource->resource_list_head)) {
		resource =
		    list_first_entry(&shared_resource->resource_list_head,
				     struct dxgresource,
				     shared_resource_list_entry);
		TRACE_DEBUG(1, "First resource: %p", resource);
		dxgmutex_lock(&resource->resource_mutex);
		list_for_each_entry(alloc, &resource->alloc_list_head,
				    alloc_list_entry) {
			TRACE_DEBUG(1, "Resource alloc: %p %d", alloc,
				    alloc->priv_drv_data->data_size);
			shared_resource->allocation_count++;
			shared_resource->alloc_private_data_size +=
			    alloc->priv_drv_data->data_size;
			if (shared_resource->alloc_private_data_size <
			    alloc->priv_drv_data->data_size) {
				pr_err("alloc private data overflow");
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup1;
			}
		}
		if (shared_resource->alloc_private_data_size == 0)
			goto cleanup1;
		shared_resource->alloc_private_data =
			dxgmem_alloc(NULL, DXGMEM_ALLOCPRIVATE,
				shared_resource->alloc_private_data_size);
		if (shared_resource->alloc_private_data == NULL) {
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup1;
		}
		shared_resource->alloc_private_data_sizes =
			dxgmem_alloc(NULL, DXGMEM_ALLOCPRIVATE,
			sizeof(uint)*shared_resource->allocation_count);
		if (shared_resource->alloc_private_data_sizes == NULL) {
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup1;
		}
		private_data = shared_resource->alloc_private_data;
		data_size = shared_resource->alloc_private_data_size;
		i = 0;
		list_for_each_entry(alloc, &resource->alloc_list_head,
				    alloc_list_entry) {
			uint alloc_data_size = alloc->priv_drv_data->data_size;

			if (alloc_data_size) {
				if (data_size < alloc_data_size) {
					pr_err("Invalid private data size");
					ret = STATUS_INVALID_PARAMETER;
					goto cleanup1;
				}
				shared_resource->alloc_private_data_sizes[i] =
				    alloc_data_size;
				memcpy(private_data,
				       alloc->priv_drv_data->data,
				       alloc_data_size);
				dxgmem_free(alloc->process, DXGMEM_ALLOCPRIVATE,
					    alloc->priv_drv_data);
				alloc->priv_drv_data = NULL;
				private_data += alloc_data_size;
				data_size -= alloc_data_size;
			}
			i++;
		}
		if (data_size != 0) {
			pr_err("Data size mismatch");
			ret = STATUS_INVALID_PARAMETER;
		}
cleanup1:
		dxgmutex_unlock(&resource->resource_mutex);
	}
cleanup:
	up_write(&shared_resource->adapter->shared_resource_list_lock);
	return ret;
}

static int dxgk_enum_adapters(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_enumadapters2 args;
	int ret = 0;
	struct dxgadapter *entry;
	struct d3dkmt_adapterinfo *info = NULL;
	struct dxgadapter **adapters = NULL;
	int adapter_count = 0;
	int i;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.adapters == NULL) {
		ret = 0;
		TRACE_DEBUG(1, "buffer is NULL");
		args.num_adapters = dxgglobal->num_adapters;
		ret = dxg_copy_to_user(inargs, &args, sizeof(args));
		goto cleanup;
	}
	if (args.num_adapters < dxgglobal->num_adapters) {
		args.num_adapters = dxgglobal->num_adapters;
		TRACE_DEBUG(1, "buffer is too small");
		ret = STATUS_BUFFER_TOO_SMALL;
		goto cleanup;
	}

	if (args.num_adapters > D3DKMT_ADAPTERS_MAX) {
		TRACE_DEBUG(1, "too many adapters");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	info = dxgmem_alloc(process, DXGMEM_TMP,
			    sizeof(struct d3dkmt_adapterinfo) *
			    args.num_adapters);
	if (info == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	adapters = dxgmem_alloc(process, DXGMEM_TMP,
				sizeof(struct dxgadapter *) *
				args.num_adapters);
	if (adapters == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	dxgglobal_acquire_adapter_list_lock(DXGLOCK_SHARED);
	dxgglobal_acquire_process_adapter_lock();

	list_for_each_entry(entry, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (dxgadapter_acquire_lock_shared(entry) == 0) {
			struct d3dkmt_adapterinfo *inf = &info[adapter_count];

			ret = dxgprocess_open_adapter(process, entry,
						      &inf->adapter_handle);
			if (NT_SUCCESS(ret)) {
				inf->adapter_luid = entry->luid;
				adapters[adapter_count] = entry;
				TRACE_DEBUG(1, "adapter: %x %llx",
					    inf->adapter_handle,
					    *(u64 *) &inf->adapter_luid);
				adapter_count++;
			}
			dxgadapter_release_lock_shared(entry);
		}
		if (ret)
			break;
	}

	dxgglobal_release_process_adapter_lock();
	dxgglobal_release_adapter_list_lock(DXGLOCK_SHARED);

	args.num_adapters = adapter_count;

	ret = dxg_copy_to_user(inargs, &args, sizeof(args));
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(args.adapters, info,
			       sizeof(info[0]) * args.num_adapters);
	if (ret)
		goto cleanup;

cleanup:

	if (ret) {
		if (info) {
			for (i = 0; i < args.num_adapters; i++) {
				dxgprocess_close_adapter(process,
							 info[i].
							 adapter_handle);
			}
		}
	} else {
		TRACE_DEBUG(1, "found %d adapters", args.num_adapters);
	}

	if (info)
		dxgmem_free(process, DXGMEM_TMP, info);
	if (adapters)
		dxgmem_free(process, DXGMEM_TMP, adapters);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_enum_adapters3(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_enumadapters3 args;
	int ret = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	ret = dxgkp_enum_adapters(process, args.filter,
				  args.adapter_count,
				  args.adapters,
				  &((struct d3dkmt_enumadapters3 *)inargs)->
				  adapter_count);

cleanup:

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_close_adapter(struct dxgprocess *process, void *__user inargs)
{
	d3dkmt_handle args;
	int ret = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	ret = dxgprocess_close_adapter(process, args);
	if (ret)
		pr_err("%s failed", __func__);

cleanup:

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_query_adapter_info(struct dxgprocess *process,
				   void *__user inargs)
{
	struct d3dkmt_queryadapterinfo args;
	int ret = 0;
	struct dxgadapter *adapter = NULL;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.private_data_size > DXG_MAX_VM_BUS_PACKET_SIZE ||
	    args.private_data_size == 0) {
		pr_err("invalid private data size");
		goto cleanup;
	}

	TRACE_DEBUG(1, "Type: %d Size: %x", args.type, args.private_data_size);

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_query_adapter_info(process, &adapter->channel, &args);

	dxgadapter_release_lock_shared(adapter);

cleanup:

	if (adapter)
		dxgadapter_release_reference(adapter);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_create_device(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_createdevice args;
	int ret = 0;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	d3dkmt_handle host_device_handle = 0;
	bool adapter_locked = false;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	/* The call acquires reference on the adapter */
	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgdevice_create(adapter, process);
	if (device == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret)
		goto cleanup;

	adapter_locked = true;

	host_device_handle = dxgvmb_send_create_device(adapter, process, &args);
	if (host_device_handle) {
		ret =
		    dxg_copy_to_user(&((struct d3dkmt_createdevice *)inargs)->
				     device, &host_device_handle,
				     sizeof(d3dkmt_handle));
		if (ret)
			goto cleanup;

		hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
		ret = hmgrtable_assign_handle(&process->handle_table, device,
					      HMGRENTRY_TYPE_DXGDEVICE,
					      host_device_handle);
		if (!ret) {
			device->handle = host_device_handle;
			device->handle_valid = 1;
			device->object_state = DXGOBJECTSTATE_ACTIVE;
		}
		hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
	}

cleanup:

	if (ret) {
		if (host_device_handle)
			dxgvmb_send_destroy_device(adapter, process,
						   host_device_handle);
		if (device)
			dxgdevice_destroy(device);
	}

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);

	if (adapter)
		dxgadapter_release_reference(adapter);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_destroy_device(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_destroydevice args;
	int ret = 0;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	device = hmgrtable_get_object_by_type(&process->handle_table,
					      HMGRENTRY_TYPE_DXGDEVICE,
					      args.device);
	if (device) {
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGDEVICE, args.device);
		device->handle_valid = 0;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (device == NULL) {
		pr_err("invalid device handle: %x", args.device);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;

	dxgdevice_destroy(device);

	if (dxgadapter_acquire_lock_shared(adapter) == 0) {
		dxgvmb_send_destroy_device(adapter, process, args.device);
		dxgadapter_release_lock_shared(adapter);
	}

cleanup:

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_create_context_virtual(struct dxgprocess *process,
				       void *__user inargs)
{
	struct d3dkmt_createcontextvirtual args;
	int ret = 0;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct dxgcontext *context = NULL;
	d3dkmt_handle host_context_handle = 0;
	bool device_lock_acquired = false;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret)
		goto cleanup;

	device_lock_acquired = true;

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	context = dxgcontext_create(device);
	if (context == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	host_context_handle = dxgvmb_send_create_context(adapter,
							 process, &args);
	if (host_context_handle) {
		hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
		ret = hmgrtable_assign_handle(&process->handle_table, context,
					      HMGRENTRY_TYPE_DXGCONTEXT,
					      host_context_handle);
		if (!ret)
			context->handle = host_context_handle;
		hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
		if (ret)
			goto cleanup;
		ret =
		    dxg_copy_to_user(&
				     ((struct d3dkmt_createcontextvirtual *)
				      inargs)->context, &host_context_handle,
				     sizeof(d3dkmt_handle));
	} else {
		pr_err("invalid host handle");
		ret = STATUS_INVALID_PARAMETER;
	}

cleanup:

	if (ret) {
		if (host_context_handle) {
			dxgvmb_send_destroy_context(adapter, process,
						    host_context_handle);
		}
		if (context)
			dxgcontext_destroy_safe(process, context);
	}

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device) {
		if (device_lock_acquired)
			dxgdevice_release_lock_shared(device);
		dxgdevice_release_reference(device);
	}

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_destroy_context(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_destroycontext args;
	int ret = 0;
	struct dxgadapter *adapter = NULL;
	struct dxgcontext *context = NULL;
	struct dxgdevice *device = NULL;
	d3dkmt_handle device_handle = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	context = hmgrtable_get_object_by_type(&process->handle_table,
					       HMGRENTRY_TYPE_DXGCONTEXT,
					       args.context);
	if (context) {
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGCONTEXT, args.context);
		context->handle = 0;
		device_handle = context->device_handle;
		context->object_state = DXGOBJECTSTATE_DESTROYED;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (context == NULL) {
		pr_err("invalid context handle: %x", args.context);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, device_handle);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_destroy_context(adapter, process, args.context);

	dxgcontext_destroy_safe(process, context);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_create_hwcontext(struct dxgprocess *process,
				 void *__user inargs)
{
	/* This is obsolete entry point */
	return STATUS_NOT_SUPPORTED;
}

static int dxgk_destroy_hwcontext(struct dxgprocess *process,
				  void *__user inargs)
{
	/* This is obsolete entry point */
	return STATUS_NOT_SUPPORTED;
}

static int dxgk_create_hwqueue(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_createhwqueue args;
	struct dxgdevice *device = NULL;
	struct dxgcontext *context = NULL;
	struct dxgadapter *adapter = NULL;
	struct dxghwqueue *hwqueue = NULL;
	int ret = 0;
	bool device_lock_acquired = false;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.context);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret)
		goto cleanup;

	device_lock_acquired = true;

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	context = hmgrtable_get_object_by_type(&process->handle_table,
					       HMGRENTRY_TYPE_DXGCONTEXT,
					       args.context);
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);

	if (context == NULL) {
		pr_err("Invalid context handle %x", args.context);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	hwqueue = dxghwqueue_create(context);
	if (hwqueue == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_create_hwqueue(process, &adapter->channel, &args,
					 inargs, hwqueue);

cleanup:

	if (ret && hwqueue)
		dxghwqueue_destroy(process, hwqueue);

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device_lock_acquired)
		dxgdevice_release_lock_shared(device);

	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_destroy_hwqueue(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_destroyhwqueue args;
	int ret = 0;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct dxghwqueue *hwqueue = NULL;
	d3dkmt_handle device_handle = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	hwqueue = hmgrtable_get_object_by_type(&process->handle_table,
					       HMGRENTRY_TYPE_DXGHWQUEUE,
					       args.queue);
	if (hwqueue) {
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGHWQUEUE, args.queue);
		hwqueue->handle = 0;
		device_handle = hwqueue->device_handle;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (hwqueue == NULL) {
		pr_err("invalid hwqueue handle: %x", args.queue);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, device_handle);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_destroy_hwqueue(process, &adapter->channel,
					  args.queue);

	dxghwqueue_destroy(process, hwqueue);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_create_paging_queue(struct dxgprocess *process,
				    void *__user inargs)
{
	struct d3dkmt_createpagingqueue args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct dxgpagingqueue *pqueue = NULL;
	int ret = 0;
	d3dkmt_handle host_handle = 0;
	bool device_lock_acquired = false;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret)
		goto cleanup;

	device_lock_acquired = true;
	adapter = device->adapter;

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	pqueue = dxgpagingqueue_create(device);
	if (pqueue == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	ret = dxgvmb_send_create_paging_queue(process, &adapter->channel,
					      device, &args, pqueue);
	if (NT_SUCCESS(ret)) {
		host_handle = args.paging_queue;

		ret = dxg_copy_to_user(inargs, &args, sizeof(args));
		if (ret)
			goto cleanup;

		hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
		ret = hmgrtable_assign_handle(&process->handle_table, pqueue,
					      HMGRENTRY_TYPE_DXGPAGINGQUEUE,
					      host_handle);
		if (NT_SUCCESS(ret)) {
			pqueue->handle = host_handle;
			ret = hmgrtable_assign_handle(&process->handle_table,
						      NULL,
						      HMGRENTRY_TYPE_MONITOREDFENCE,
						      args.sync_object);
			if (NT_SUCCESS(ret))
				pqueue->syncobj_handle = args.sync_object;
		}
		hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
		/* should not fail after this */
	}

cleanup:

	if (ret) {
		if (pqueue)
			dxgpagingqueue_destroy(pqueue);
		if (host_handle)
			dxgvmb_send_destroy_paging_queue(process,
							 &adapter->channel,
							 host_handle);
	}

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device) {
		if (device_lock_acquired)
			dxgdevice_release_lock_shared(device);
		dxgdevice_release_reference(device);
	}

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_destroy_paging_queue(struct dxgprocess *process,
				     void *__user inargs)
{
	struct d3dddi_destroypagingqueue args;
	struct dxgpagingqueue *paging_queue = NULL;
	int ret = 0;
	d3dkmt_handle device_handle = 0;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	paging_queue = hmgrtable_get_object_by_type(&process->handle_table,
						    HMGRENTRY_TYPE_DXGPAGINGQUEUE,
						    args.paging_queue);
	if (paging_queue) {
		device_handle = paging_queue->device_handle;
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGPAGINGQUEUE,
				      args.paging_queue);
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_MONITOREDFENCE,
				      paging_queue->syncobj_handle);
		paging_queue->syncobj_handle = 0;
		paging_queue->handle = 0;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	if (device_handle)
		device = dxgprocess_device_by_handle(process, device_handle);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret) {
		dxgdevice_release_reference(device);
		device = NULL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_destroy_paging_queue(process, &adapter->channel,
					       args.paging_queue);

	dxgpagingqueue_destroy(paging_queue);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device) {
		dxgdevice_release_lock_shared(device);
		dxgdevice_release_reference(device);
	}

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int get_standard_alloc_priv_data(struct dxgdevice *device,
					struct d3dkmt_createstandardallocation
					*alloc_info,
					uint *standard_alloc_priv_data_size,
					void **standard_alloc_priv_data)
{
	int ret = 0;
	struct d3dkmdt_gdisurfacedata gdi_data = { };
	uint priv_data_size = 0;
	void *priv_data = NULL;

	TRACE_DEBUG(1, "%s", __func__);

	gdi_data.type = D3DKMDT_GDISURFACE_TEXTURE_CROSSADAPTER;
	gdi_data.width = alloc_info->existing_heap_data.size;
	gdi_data.height = 1;
	gdi_data.format = D3DDDIFMT_UNKNOWN;

	*standard_alloc_priv_data_size = 0;
	ret = dxgvmb_send_get_standard_alloc_priv_data(device,
						       D3DKMDT_STANDARDALLOCATION_GDISURFACE,
						       &gdi_data, 0,
						       &priv_data_size, NULL);
	if (ret)
		goto cleanup;
	TRACE_DEBUG(1, "Priv data size: %d", priv_data_size);
	if (priv_data_size == 0)
		goto cleanup;
	priv_data = dxgmem_alloc(device->process, DXGMEM_TMP, priv_data_size);
	if (priv_data == NULL) {
		ret = STATUS_NO_MEMORY;
		pr_err("failed to allocate memory for priv data: %d",
			   priv_data_size);
		goto cleanup;
	}
	ret = dxgvmb_send_get_standard_alloc_priv_data(device,
						       D3DKMDT_STANDARDALLOCATION_GDISURFACE,
						       &gdi_data, 0,
						       &priv_data_size,
						       priv_data);
	if (ret)
		goto cleanup;
	*standard_alloc_priv_data_size = priv_data_size;
	*standard_alloc_priv_data = priv_data;
	priv_data = NULL;

cleanup:
	if (priv_data)
		dxgmem_free(device->process, DXGMEM_TMP, priv_data);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

static int dxgk_create_allocation(struct dxgprocess *process,
				  void *__user inargs)
{
	struct d3dkmt_createallocation args;
	int ret = 0;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct d3dddi_allocationinfo2 *alloc_info = NULL;
	struct d3dkmt_createstandardallocation standard_alloc;
	uint alloc_info_size = 0;
	struct dxgresource *resource = NULL;
	struct dxgallocation **dxgalloc = NULL;
	struct dxgsharedresource *shared_resource = NULL;
	bool resource_mutex_acquired = false;
	uint standard_alloc_priv_data_size = 0;
	void *standard_alloc_priv_data = NULL;
	int i;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.alloc_count > D3DKMT_CREATEALLOCATION_MAX ||
	    args.alloc_count == 0) {
		pr_err("invalid number of allocations to create");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	alloc_info_size = sizeof(struct d3dddi_allocationinfo2) *
	    args.alloc_count;
	alloc_info = dxgmem_alloc(process, DXGMEM_TMP, alloc_info_size);
	if (alloc_info == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	ret = dxg_copy_from_user(alloc_info, args.allocation_info,
				 alloc_info_size);
	if (ret)
		goto cleanup;

	for (i = 0; i < args.alloc_count; i++) {
		if (args.flags.standard_allocation) {
			if (alloc_info[i].priv_drv_data_size != 0) {
				pr_err("private data size is not zero");
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup;
			}
		}
		if (alloc_info[i].priv_drv_data_size >=
		    DXG_MAX_VM_BUS_PACKET_SIZE) {
			pr_err("private data size is too big: %d %d %ld",
				   i, alloc_info[i].priv_drv_data_size,
				   sizeof(alloc_info[0]));
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
	}

	if (args.flags.existing_section || args.flags.create_protected) {
		pr_err("invalid allocation flags");
		goto cleanup;
	}

	if (args.flags.standard_allocation) {
		if (args.standard_allocation == NULL) {
			pr_err("invalid standard allocation");
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		ret = dxg_copy_from_user(&standard_alloc,
					 args.standard_allocation,
					 sizeof(standard_alloc));
		if (ret)
			goto cleanup;
		if (alloc_info[0].sysmem == NULL ||
		    args.priv_drv_data_size != 0 ||
		    args.alloc_count != 1 ||
		    standard_alloc.type !=
		    D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP ||
		    standard_alloc.existing_heap_data.size == 0 ||
		    standard_alloc.existing_heap_data.size & (PAGE_SIZE - 1) ||
		    (unsigned long)alloc_info[0].sysmem & (PAGE_SIZE - 1)) {
			pr_err("invalid standard allocation");
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		args.priv_drv_data_size =
		    sizeof(struct d3dkmt_createstandardallocation);
	}

	if (args.flags.create_shared && !args.flags.create_resource) {
		pr_err("create_resource must be set for create_shared");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret) {
		dxgdevice_release_reference(device);
		device = NULL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	if (args.flags.standard_allocation) {
		ret = get_standard_alloc_priv_data(device,
						   &standard_alloc,
						   &standard_alloc_priv_data_size,
						   &standard_alloc_priv_data);
		if (ret)
			goto cleanup;
		TRACE_DEBUG(1, "Alloc private data: %d",
			    standard_alloc_priv_data_size);
	}

	if (args.flags.create_resource) {
		resource = dxgresource_create(device);
		if (resource == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		resource->private_runtime_handle =
		    args.private_runtime_resource_handle;
		if (args.flags.create_shared) {
			shared_resource = dxgsharedresource_create(adapter);
			if (shared_resource == NULL) {
				ret = STATUS_NO_MEMORY;
				goto cleanup;
			}
			shared_resource->runtime_private_data_size =
			    args.priv_drv_data_size;
			shared_resource->resource_private_data_size =
			    args.priv_drv_data_size;
			if (args.flags.nt_security_sharing)
				shared_resource->nt_security = 1;

			shared_resource->runtime_private_data_size =
			    args.private_runtime_data_size;
			shared_resource->resource_private_data_size =
			    args.priv_drv_data_size;
			dxgsharedresource_add_resource(shared_resource,
						       resource);
			if (args.private_runtime_data_size) {
				shared_resource->runtime_private_data =
				    dxgmem_alloc(NULL,
						 DXGMEM_RUNTIMEPRIVATE,
						 args.
						 private_runtime_data_size);
				if (shared_resource->runtime_private_data ==
				    NULL) {
					ret = STATUS_NO_MEMORY;
					goto cleanup;
				}
				ret =
				    dxg_copy_from_user(shared_resource->
						       runtime_private_data,
						       args.
						       private_runtime_data,
						       args.
						       private_runtime_data_size);
				if (ret)
					goto cleanup;
			}
			if (args.priv_drv_data_size) {
				shared_resource->resource_private_data =
				    dxgmem_alloc(NULL,
						 DXGMEM_RESOURCEPRIVATE,
						 args.priv_drv_data_size);
				if (shared_resource->resource_private_data ==
				    NULL) {
					ret = STATUS_NO_MEMORY;
					goto cleanup;
				}
				ret =
				    dxg_copy_from_user(shared_resource->
						       resource_private_data,
						       args.priv_drv_data,
						       args.priv_drv_data_size);
				if (ret)
					goto cleanup;
			}
		}
	} else {
		if (args.resource) {
			/* Adding new allocations to the given resource */

			dxgprocess_ht_lock_shared_down(process);
			resource =
			    hmgrtable_get_object_by_type(&process->handle_table,
							 HMGRENTRY_TYPE_DXGRESOURCE,
							 args.resource);
			dxgresource_acquire_reference(resource);
			dxgprocess_ht_lock_shared_up(process);

			if (resource == NULL || resource->device != device) {
				pr_err("invalid resource handle %x",
					   args.resource);
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup;
			}
			if (resource->shared_owner &&
			    resource->shared_owner->sealed) {
				pr_err("Resource is sealed");
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup;
			}
			/* Synchronize with resource destruction */
			dxgmutex_lock(&resource->resource_mutex);
			if (!dxgresource_is_active(resource)) {
				dxgmutex_unlock(&resource->resource_mutex);
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup;
			}
			resource_mutex_acquired = true;
		}
	}

	dxgalloc = dxgmem_alloc(process, DXGMEM_TMP,
				sizeof(struct dxgallocation *) *
				args.alloc_count);
	if (dxgalloc == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	for (i = 0; i < args.alloc_count; i++) {
		struct dxgallocation *alloc;
		uint priv_data_size = alloc_info[i].priv_drv_data_size;

		if (alloc_info[i].sysmem && !args.flags.standard_allocation) {
			if ((unsigned long)
			    alloc_info[i].sysmem & (PAGE_SIZE - 1)) {
				pr_err("invalid sysmem alloc %d, %p",
					   i, alloc_info[i].sysmem);
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup;
			}
		}
		if ((alloc_info[0].sysmem == NULL) !=
		    (alloc_info[i].sysmem == NULL)) {
			pr_err("All allocations must have sysmem pointer");
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}

		dxgalloc[i] = dxgallocation_create(process);
		if (dxgalloc[i] == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		alloc = dxgalloc[i];

		if (resource)
			dxgresource_add_alloc(resource, alloc);
		else
			dxgdevice_add_alloc(device, alloc);
		if (args.flags.create_shared) {
			/* Remember alloc private data to use it during open */
			alloc->priv_drv_data = dxgmem_alloc(process,
							    DXGMEM_ALLOCPRIVATE,
							    priv_data_size +
							    offsetof(struct
								     privdata,
								     data) - 1);
			if (alloc->priv_drv_data == NULL) {
				ret = STATUS_NO_MEMORY;
				goto cleanup;
			}
			if (args.flags.standard_allocation) {
				memcpy(alloc->priv_drv_data->data,
				       standard_alloc_priv_data,
				       standard_alloc_priv_data_size);
				alloc->priv_drv_data->data_size =
				    standard_alloc_priv_data_size;
			} else {
				ret =
				    dxg_copy_from_user(alloc->priv_drv_data->
						       data,
						       alloc_info[i].
						       priv_drv_data,
						       priv_data_size);
				if (ret)
					goto cleanup;
				alloc->priv_drv_data->data_size =
				    priv_data_size;
			}
		}
	}

	ret = dxgvmb_send_create_allocation(process, device, &args, inargs,
					    resource, dxgalloc, alloc_info,
					    &standard_alloc);
	if (ret)
		goto cleanup;

cleanup:

	if (resource_mutex_acquired) {
		dxgmutex_unlock(&resource->resource_mutex);
		dxgresource_release_reference(resource);
	}
	if (ret) {
		if (dxgalloc) {
			for (i = 0; i < args.alloc_count; i++) {
				if (dxgalloc[i])
					dxgallocation_destroy(dxgalloc[i]);
			}
		}
		if (resource && args.flags.create_resource) {
			if (shared_resource) {
				dxgsharedresource_remove_resource
				    (shared_resource, resource);
			}
			dxgresource_destroy(resource);
		}
	}
	if (shared_resource)
		dxgsharedresource_release_reference(shared_resource);
	if (dxgalloc)
		dxgmem_free(process, DXGMEM_TMP, dxgalloc);
	if (standard_alloc_priv_data)
		dxgmem_free(process, DXGMEM_TMP, standard_alloc_priv_data);
	if (alloc_info)
		dxgmem_free(process, DXGMEM_TMP, alloc_info);

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device) {
		dxgdevice_release_lock_shared(device);
		dxgdevice_release_reference(device);
	}

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

int validate_alloc(struct dxgallocation *alloc0,
		   struct dxgallocation *alloc,
		   struct dxgdevice *device, d3dkmt_handle alloc_handle)
{
	uint fail_reason;

	if (alloc == NULL) {
		fail_reason = 1;
		goto cleanup;
	}
	if (alloc->resource_owner != alloc0->resource_owner) {
		fail_reason = 2;
		goto cleanup;
	}
	if (alloc->resource_owner) {
		if (alloc->owner.resource != alloc0->owner.resource) {
			fail_reason = 3;
			goto cleanup;
		}
		if (alloc->owner.resource->device != device) {
			fail_reason = 4;
			goto cleanup;
		}
		if (alloc->owner.resource->shared_owner) {
			fail_reason = 5;
			goto cleanup;
		}
	} else {
		if (alloc->owner.device != device) {
			fail_reason = 6;
			goto cleanup;
		}
	}
	return 0;
cleanup:
	pr_err("Alloc validation failed: reason: %d %x",
		   fail_reason, alloc_handle);
	return STATUS_INVALID_PARAMETER;
}

static int dxgk_destroy_allocation(struct dxgprocess *process,
				   void *__user inargs)
{
	struct d3dkmt_destroyallocation2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret = 0;
	d3dkmt_handle *alloc_handles = NULL;
	struct dxgallocation **allocs = NULL;
	struct dxgresource *resource = NULL;
	int i;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.alloc_count > D3DKMT_CREATEALLOCATION_MAX ||
	    ((args.alloc_count == 0) == (args.resource == 0))) {
		pr_err("invalid number of allocations");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.alloc_count) {
		uint handle_size = sizeof(d3dkmt_handle) * args.alloc_count;

		alloc_handles = dxgmem_alloc(process, DXGMEM_TMP, handle_size);
		if (alloc_handles == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		allocs = dxgmem_alloc(process, DXGMEM_TMP,
				      sizeof(struct dxgallocation *) *
				      args.alloc_count);
		if (allocs == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		ret = dxg_copy_from_user(alloc_handles, args.allocations,
					 handle_size);
		if (ret)
			goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	/* Acquire the device lock to synchronize with the device destriction */
	ret = dxgdevice_acquire_lock_shared(device);
	if (ret) {
		dxgdevice_release_reference(device);
		device = NULL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	/*
	 * Destroy the local allocation handles first. If the host handle
	 * is destroyed first, another object could be assigned to the process
	 * table at he same place as the allocation handle and it will fail.
	 */
	if (args.alloc_count) {
		dxgprocess_ht_lock_exclusive_down(process);
		for (i = 0; i < args.alloc_count; i++) {
			allocs[i] =
			    hmgrtable_get_object_by_type(&process->handle_table,
							 HMGRENTRY_TYPE_DXGALLOCATION,
							 alloc_handles[i]);
			ret =
			    validate_alloc(allocs[0], allocs[i], device,
					   alloc_handles[i]);
			if (ret) {
				dxgprocess_ht_lock_exclusive_up(process);
				goto cleanup;
			}
		}
		dxgprocess_ht_lock_exclusive_up(process);
		for (i = 0; i < args.alloc_count; i++)
			dxgallocation_free_handle(allocs[i]);
	} else {
		struct dxgallocation *alloc;

		dxgprocess_ht_lock_exclusive_down(process);
		resource = hmgrtable_get_object_by_type(&process->handle_table,
							HMGRENTRY_TYPE_DXGRESOURCE,
							args.resource);
		if (resource == NULL) {
			pr_err("Invalid resource handle: %x",
				   args.resource);
			ret = STATUS_INVALID_PARAMETER;
		} else if (resource->device != device) {
			pr_err("Resource belongs to wrong device: %x",
				   args.resource);
			ret = STATUS_INVALID_PARAMETER;
		} else {
			hmgrtable_free_handle(&process->handle_table,
					      HMGRENTRY_TYPE_DXGRESOURCE,
					      args.resource);
			resource->object_state = DXGOBJECTSTATE_DESTROYED;
			resource->handle = 0;
			resource->handle_valid = 0;
		}
		dxgprocess_ht_lock_exclusive_up(process);

		if (ret)
			goto cleanup;

		dxgdevice_acquire_alloc_list_lock_shared(device);
		list_for_each_entry(alloc, &resource->alloc_list_head,
				    alloc_list_entry) {
			dxgallocation_free_handle(alloc);
		}
		dxgdevice_release_alloc_list_lock_shared(device);
	}

	if (args.alloc_count && allocs[0]->resource_owner)
		resource = allocs[0]->owner.resource;

	if (resource) {
		dxgresource_acquire_reference(resource);
		dxgmutex_lock(&resource->resource_mutex);
	}

	ret = dxgvmb_send_destroy_allocation(process, device, &adapter->channel,
					     &args, alloc_handles);

	/*
	 * Destroy the allocations after the host destroyed it.
	 * The allocation gpadl teardown will wait until the host unmaps its
	 * gpadl.
	 */
	dxgdevice_acquire_alloc_list_lock(device);
	if (args.alloc_count) {
		for (i = 0; i < args.alloc_count; i++) {
			if (allocs[i]) {
				allocs[i]->alloc_handle = 0;
				dxgallocation_destroy(allocs[i]);
			}
		}
	} else {
		dxgresource_destroy(resource);
	}
	dxgdevice_release_alloc_list_lock(device);

	if (resource) {
		dxgmutex_unlock(&resource->resource_mutex);
		dxgresource_release_reference(resource);
	}

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device) {
		dxgdevice_release_lock_shared(device);
		dxgdevice_release_reference(device);
	}

	if (alloc_handles)
		dxgmem_free(process, DXGMEM_TMP, alloc_handles);

	if (allocs)
		dxgmem_free(process, DXGMEM_TMP, allocs);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_make_resident(struct dxgprocess *process, void *__user inargs)
{
	int ret = 0, ret2;
	struct d3dddi_makeresident args;
	struct d3dddi_makeresident *input = inargs;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.alloc_count > D3DKMT_CREATEALLOCATION_MAX ||
	    args.alloc_count == 0) {
		pr_err("invalid number of allocations");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	if (args.paging_queue == 0) {
		pr_err("paging queue is missing");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGPAGINGQUEUE,
						    args.paging_queue);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_make_resident(process, NULL, &adapter->channel,
					&args);
	if (ret && ret != STATUS_PENDING)
		goto cleanup;

	ret2 = dxg_copy_to_user(&input->paging_fence_value,
				&args.paging_fence_value, sizeof(uint64_t));
	if (ret2) {
		ret = ret2;
		goto cleanup;
	}

	ret2 = dxg_copy_to_user(&input->num_bytes_to_trim,
				&args.num_bytes_to_trim, sizeof(uint64_t));
	if (ret2) {
		ret = ret2;
		goto cleanup;
	}

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);

	return ret;
}

static int dxgk_evict(struct dxgprocess *process, void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_evict args;
	struct d3dkmt_evict *input = inargs;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.alloc_count > D3DKMT_CREATEALLOCATION_MAX ||
	    args.alloc_count == 0) {
		pr_err("invalid number of allocations");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_evict(process, &adapter->channel, &args);
	if (ret)
		goto cleanup;

	ret = dxg_copy_to_user(&input->num_bytes_to_trim,
			       &args.num_bytes_to_trim, sizeof(uint64_t));
	if (ret)
		goto cleanup;

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_offer_allocations(struct dxgprocess *process,
				  void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_offerallocations args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.allocation_count > D3DKMT_CREATEALLOCATION_MAX ||
	    args.allocation_count == 0) {
		pr_err("invalid number of allocations");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if ((args.resources == NULL) == (args.allocations == NULL)) {
		pr_err("invalid pointer to resources/allocations");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_offer_allocations(process, &adapter->channel, &args);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_reclaim_allocations(struct dxgprocess *process,
				    void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_reclaimallocations2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.allocation_count > D3DKMT_CREATEALLOCATION_MAX ||
	    args.allocation_count == 0) {
		pr_err("invalid number of allocations");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if ((args.resources == NULL) == (args.allocations == NULL)) {
		pr_err("invalid pointer to resources/allocations");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGPAGINGQUEUE,
						    args.paging_queue);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_reclaim_allocations(process, &adapter->channel,
					      device->handle, &args,
					      &((struct
						 d3dkmt_reclaimallocations2 *)
						inargs)->paging_fence_value);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_submit_command(struct dxgprocess *process, void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_submitcommand args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.broadcast_context_count > D3DDDI_MAX_BROADCAST_CONTEXT ||
	    args.broadcast_context_count == 0) {
		pr_err("invalid number of contexts");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.priv_drv_data_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		pr_err("invalid private data size");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.num_history_buffers > 1024) {
		pr_err("invalid number of history buffers");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.num_primaries > DXG_MAX_VM_BUS_PACKET_SIZE) {
		pr_err("invalid number of primaries");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.broadcast_context[0]);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_submit_command(process, &adapter->channel, &args);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_submit_command_to_hwqueue(struct dxgprocess *process,
					  void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_submitcommandtohwqueue args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.priv_drv_data_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		pr_err("invalid private data size");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.num_primaries > DXG_MAX_VM_BUS_PACKET_SIZE) {
		pr_err("invalid number of primaries");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGHWQUEUE,
						    args.hwqueue);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_submit_command_to_hwqueue(process, &adapter->channel,
						    &args);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_submit_signal_to_hwqueue(struct dxgprocess *process,
					 void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_submitsignalsyncobjectstohwqueue args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	d3dkmt_handle hwqueue;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.hwqueue_count > D3DDDI_MAX_BROADCAST_CONTEXT ||
	    args.hwqueue_count == 0) {
		pr_err("invalid hwqueue count");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.object_count > D3DDDI_MAX_OBJECT_SIGNALED ||
	    args.object_count == 0) {
		pr_err("invalid number of syn cobject");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxg_copy_from_user(&hwqueue, args.hwqueues,
				 sizeof(d3dkmt_handle));
	if (ret)
		goto cleanup;

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGHWQUEUE,
						    hwqueue);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, &adapter->channel,
					     args.flags, 0, 0,
					     args.object_count, args.objects,
					     args.hwqueue_count, args.hwqueues,
					     args.object_count,
					     args.fence_values, NULL, 0);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_submit_wait_to_hwqueue(struct dxgprocess *process,
				       void *__user inargs)
{
	struct d3dkmt_submitwaitforsyncobjectstohwqueue args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret = 0;
	d3dkmt_handle *objects = NULL;
	uint object_size;
	uint64_t *fences = NULL;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.object_count > D3DDDI_MAX_OBJECT_WAITED_ON ||
	    args.object_count == 0) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	object_size = sizeof(d3dkmt_handle) * args.object_count;
	objects = dxgmem_alloc(process, DXGMEM_TMP, object_size);
	if (objects == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	ret = dxg_copy_from_user(objects, args.objects, object_size);
	if (ret)
		goto cleanup;

	object_size = sizeof(uint64_t) * args.object_count;
	fences = dxgmem_alloc(process, DXGMEM_TMP, object_size);
	if (fences == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	ret = dxg_copy_from_user(fences, args.fence_values, object_size);
	if (ret)
		goto cleanup;

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGHWQUEUE,
						    args.hwqueue);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_wait_sync_object_gpu(process, &adapter->channel,
					       args.hwqueue, args.object_count,
					       objects, fences, false);

cleanup:

	if (objects)
		dxgmem_free(process, DXGMEM_TMP, objects);
	if (fences)
		dxgmem_free(process, DXGMEM_TMP, fences);
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_map_gpu_va(struct dxgprocess *process, void *__user inargs)
{
	int ret = 0, ret2;
	struct d3dddi_mapgpuvirtualaddress args;
	struct d3dddi_mapgpuvirtualaddress *input = inargs;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGPAGINGQUEUE,
						    args.paging_queue);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_map_gpu_va(process, 0, &adapter->channel, &args);
	if (ret && ret != (int)STATUS_PENDING)
		goto cleanup;

	ret2 = dxg_copy_to_user(&input->paging_fence_value,
				&args.paging_fence_value, sizeof(uint64_t));
	if (ret2) {
		ret = ret2;
		goto cleanup;
	}

	ret2 = dxg_copy_to_user(&input->virtual_address, &args.virtual_address,
				sizeof(args.virtual_address));
	if (ret2) {
		ret = ret2;
		goto cleanup;
	}

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_reserve_gpu_va(struct dxgprocess *process, void *__user inargs)
{
	int ret = 0;
	struct d3dddi_reservegpuvirtualaddress args;
	struct d3dddi_reservegpuvirtualaddress *input = inargs;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		device = dxgprocess_device_by_object_handle(process,
							    HMGRENTRY_TYPE_DXGPAGINGQUEUE,
							    args.adapter);
		if (device == NULL) {
			pr_err("invalid adapter or paging queue: 0x%x",
				   args.adapter);
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		adapter = device->adapter;
		dxgadapter_acquire_reference(adapter);
		dxgdevice_release_reference(device);
	} else {
		args.adapter = adapter->host_handle;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		dxgadapter_release_reference(adapter);
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_reserve_gpu_va(process, &adapter->channel, &args);
	if (ret)
		goto cleanup;

	ret = dxg_copy_to_user(&input->virtual_address, &args.virtual_address,
			       sizeof(args.virtual_address));
	if (ret)
		goto cleanup;

cleanup:

	if (adapter) {
		dxgadapter_release_lock_shared(adapter);
		dxgadapter_release_reference(adapter);
	}

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_free_gpu_va(struct dxgprocess *process, void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_freegpuvirtualaddress args;
	struct dxgadapter *adapter = NULL;

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		dxgadapter_release_reference(adapter);
		adapter = NULL;
		goto cleanup;
	}

	args.adapter = adapter->host_handle;
	ret = dxgvmb_send_free_gpu_va(process, &adapter->channel, &args);

cleanup:

	if (adapter) {
		dxgadapter_release_lock_shared(adapter);
		dxgadapter_release_reference(adapter);
	}

	return ret;
}

static int dxgk_update_gpu_va(struct dxgprocess *process, void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_updategpuvirtualaddress args;
	struct d3dkmt_updategpuvirtualaddress *input = inargs;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_update_gpu_va(process, &adapter->channel, &args);
	if (ret)
		goto cleanup;

	ret = dxg_copy_to_user(&input->fence_value, &args.fence_value,
			       sizeof(args.fence_value));
	if (ret)
		goto cleanup;

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	return ret;
}

static int dxgk_create_sync_object(struct dxgprocess *process,
				   void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_createsynchronizationobject2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct eventfd_ctx *event = NULL;
	struct dxgsyncobject *syncobj = NULL;
	bool host_event_added = false;
	bool device_lock_acquired = false;
	struct dxgsharedsyncobject *syncobjgbl = NULL;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret)
		goto cleanup;

	device_lock_acquired = true;

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	syncobj = dxgsyncobject_create(process, device, adapter, args.info.type,
				       args.info.flags);
	if (syncobj == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.info.flags.shared && syncobj->monitored_fence &&
	    !args.info.flags.nt_security_sharing) {
		pr_err("monitored fence requires nt_security_sharing");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.info.type == D3DDDI_CPU_NOTIFICATION) {
		event = eventfd_ctx_fdget((int)
					  args.info.cpu_notification.event);
		if (IS_ERR(event)) {
			pr_err("failed to reference the event");
			event = NULL;
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		syncobj->host_event->event_id = dxgglobal_new_host_event_id();
		syncobj->host_event->cpu_event = event;
		syncobj->host_event->remove_from_list = false;
		syncobj->host_event->destroy_after_signal = false;
		dxgglobal_add_host_event(syncobj->host_event);
		host_event_added = true;
		args.info.cpu_notification.event =
		    syncobj->host_event->event_id;
		TRACE_DEBUG(1, "creating CPU notification event: %lld",
			    args.info.cpu_notification.event);
	}

	ret = dxgvmb_send_create_sync_object(process, &adapter->channel, &args,
					     syncobj);
	if (ret)
		goto cleanup;

	if (args.info.flags.shared) {
		if (args.info.shared_handle == 0) {
			pr_err("shared handle should not be 0");
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		syncobjgbl = dxgsharedsyncobj_create(device->adapter, syncobj);
		if (syncobjgbl == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		dxgsharedsyncobj_add_syncobj(syncobjgbl, syncobj);

		syncobjgbl->host_shared_handle = args.info.shared_handle;
		if (!args.info.flags.nt_security_sharing) {
			hmgrtable_lock(&dxgglobal->handle_table, DXGLOCK_EXCL);
			syncobjgbl->global_shared_handle =
			    hmgrtable_alloc_handle(&dxgglobal->handle_table,
						   syncobjgbl,
						   HMGRENTRY_TYPE_DXGSYNCOBJECT,
						   true);
			if (syncobjgbl->global_shared_handle) {
				args.info.shared_handle =
				    syncobjgbl->global_shared_handle;
			} else {
				ret = STATUS_NO_MEMORY;
			}
			hmgrtable_unlock(&dxgglobal->handle_table,
					 DXGLOCK_EXCL);
			if (ret)
				goto cleanup;
		}
	}

	ret = dxg_copy_to_user(inargs, &args, sizeof(args));
	if (ret)
		goto cleanup;

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	ret = hmgrtable_assign_handle(&process->handle_table, syncobj,
				      HMGRENTRY_TYPE_DXGSYNCOBJECT,
				      args.sync_object);
	if (!ret)
		syncobj->handle = args.sync_object;
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

cleanup:

	if (ret) {
		if (syncobj) {
			dxgsyncobject_destroy(process, syncobj);
			if (args.sync_object)
				dxgvmb_send_destroy_sync_object(process,
								args.
								sync_object);
			event = NULL;
		}
		if (event)
			eventfd_ctx_put(event);
	}
	if (syncobjgbl)
		dxgsharedsyncobj_release_reference(syncobjgbl);
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device_lock_acquired)
		dxgdevice_release_lock_shared(device);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_destroy_sync_object(struct dxgprocess *process,
				    void *__user inargs)
{
	struct d3dkmt_destroysynchronizationobject args;
	struct dxgsyncobject *syncobj = NULL;
	int ret = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	TRACE_DEBUG(1, "handle 0x%x", args.sync_object);
	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	syncobj = hmgrtable_get_object_by_type(&process->handle_table,
					       HMGRENTRY_TYPE_DXGSYNCOBJECT,
					       args.sync_object);
	if (syncobj) {
		TRACE_DEBUG(1, "syncobj 0x%p", syncobj);
		syncobj->handle = 0;
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGSYNCOBJECT,
				      args.sync_object);
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (syncobj == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	dxgsyncobject_destroy(process, syncobj);

	ret = dxgvmb_send_destroy_sync_object(process, args.sync_object);

cleanup:

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_open_sync_object_nt(struct dxgprocess *process,
				    void *__user inargs)
{
	struct d3dkmt_opensyncobjectfromnthandle2 args;
	struct dxgsyncobject *syncobj = NULL;
	struct dxgsharedsyncobject *syncobj_fd = NULL;
	struct file *file = NULL;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct d3dddi_synchronizationobject_flags flags = { };
	int ret;
	bool device_lock_acquired = false;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	args.sync_object = 0;

	if (args.device) {
		device = dxgprocess_device_by_handle(process, args.device);
		if (device == NULL)
			goto cleanup;
	} else {
		pr_err("device handle is missing");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret)
		goto cleanup;

	device_lock_acquired = true;

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	file = fget(args.nt_handle);
	if (!file) {
		pr_err("failed to get file from handle: %llx",
			   args.nt_handle);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (file->f_op != &dxg_syncobj_fops) {
		pr_err("invalid fd: %llx", args.nt_handle);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	syncobj_fd = file->private_data;
	if (syncobj_fd == NULL) {
		pr_err("invalid private data: %llx", args.nt_handle);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	flags.shared = 1;
	flags.nt_security_sharing = 1;
	syncobj = dxgsyncobject_create(process, device, adapter,
				       syncobj_fd->type, flags);
	if (syncobj == NULL) {
		pr_err("failed to create sync object");
		goto cleanup;
	}

	dxgsharedsyncobj_add_syncobj(syncobj_fd, syncobj);

	ret = dxgvmb_send_open_sync_object_nt(process, &dxgglobal->channel,
					      &args, syncobj);
	if (ret) {
		pr_err("failed to open sync object on host: %x",
			   syncobj_fd->host_shared_handle);
		goto cleanup;
	}

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	ret = hmgrtable_assign_handle(&process->handle_table, syncobj,
				      HMGRENTRY_TYPE_DXGSYNCOBJECT,
				      args.sync_object);
	if (!ret) {
		syncobj->handle = args.sync_object;
		dxgsyncobject_acquire_reference(syncobj);
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (ret)
		goto cleanup;

	ret = dxg_copy_to_user(inargs, &args, sizeof(args));
	if (!ret)
		goto success;

cleanup:

	if (syncobj) {
		dxgsyncobject_destroy(process, syncobj);
		syncobj = NULL;
	}

	if (args.sync_object)
		dxgvmb_send_destroy_sync_object(process, args.sync_object);

success:

	if (file)
		fput(file);
	if (syncobj)
		dxgsyncobject_release_reference(syncobj);
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device_lock_acquired)
		dxgdevice_release_lock_shared(device);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_open_sync_object(struct dxgprocess *process,
				 void *__user inargs)
{
	d3dkmt_handle shared_handle = 0;
	d3dkmt_handle new_handle = 0;
	struct d3dkmt_opensynchronizationobject *__user inp = inargs;
	struct dxgsyncobject *syncobj = NULL;
	struct dxgsharedsyncobject *syncobjgbl = NULL;
	struct d3dddi_synchronizationobject_flags flags = { };
	int ret;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&shared_handle, &inp->shared_handle,
				 sizeof(shared_handle));
	if (ret)
		goto cleanup;

	hmgrtable_lock(&dxgglobal->handle_table, DXGLOCK_SHARED);
	syncobjgbl = hmgrtable_get_object_by_type(&dxgglobal->handle_table,
						  HMGRENTRY_TYPE_DXGSYNCOBJECT,
						  shared_handle);
	if (syncobjgbl)
		dxgsharedsyncobj_acquire_reference(syncobjgbl);
	hmgrtable_unlock(&dxgglobal->handle_table, DXGLOCK_SHARED);

	if (syncobjgbl == NULL) {
		pr_err("invalid sync object shared handle: %x",
			   shared_handle);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (syncobjgbl->monitored_fence) {
		pr_err("Open monitored fence using global handle");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	flags.shared = 1;
	syncobj = dxgsyncobject_create(process, NULL, syncobjgbl->adapter,
				       syncobjgbl->type, flags);
	if (syncobj == NULL) {
		pr_err("failed to create sync object");
		goto cleanup;
	}

	dxgsharedsyncobj_add_syncobj(syncobjgbl, syncobj);

	ret = dxgvmb_send_open_sync_object(process, &dxgglobal->channel,
					   syncobjgbl->host_shared_handle,
					   &new_handle);
	if (ret) {
		pr_err("failed to open sync object on host: %x",
			   syncobjgbl->host_shared_handle);
		goto cleanup;
	}

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	ret = hmgrtable_assign_handle(&process->handle_table, syncobj,
				      HMGRENTRY_TYPE_DXGSYNCOBJECT, new_handle);
	if (!ret) {
		syncobj->handle = new_handle;
		dxgsyncobject_acquire_reference(syncobj);
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (ret)
		goto cleanup;

	ret = dxg_copy_to_user(&inp->sync_object, &new_handle,
			       sizeof(new_handle));
	if (!ret)
		goto success;

cleanup:

	if (syncobj) {
		dxgsyncobject_destroy(process, syncobj);
		syncobj = NULL;
	}

	if (new_handle)
		dxgvmb_send_destroy_sync_object(process, new_handle);

success:

	if (syncobj)
		dxgsyncobject_release_reference(syncobj);
	if (syncobjgbl)
		dxgsharedsyncobj_release_reference(syncobjgbl);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_signal_sync_object(struct dxgprocess *process,
				   void *__user inargs)
{
	struct d3dkmt_signalsynchronizationobject2 args;
	struct d3dkmt_signalsynchronizationobject2 *__user in_args = inargs;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret = 0;
	uint fence_count = 1;
	struct eventfd_ctx *event = NULL;
	struct dxghostevent *host_event = NULL;
	bool host_event_added = false;
	u64 host_event_id = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.context_count >= D3DDDI_MAX_BROADCAST_CONTEXT ||
	    args.object_count > D3DDDI_MAX_OBJECT_SIGNALED) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.flags.enqueue_cpu_event) {
		host_event = dxgmem_alloc(process, DXGMEM_EVENT,
					  sizeof(*host_event));
		if (host_event == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		host_event->process = process;
		event = eventfd_ctx_fdget((int)args.cpu_event_handle);
		if (IS_ERR(event)) {
			pr_err("failed to reference the event");
			event = NULL;
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		fence_count = 0;
		host_event->cpu_event = event;
		host_event_id = dxgglobal_new_host_event_id();
		host_event->event_id = host_event_id;
		host_event->remove_from_list = true;
		host_event->destroy_after_signal = true;
		dxgglobal_add_host_event(host_event);
		host_event_added = true;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.context);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, &adapter->channel,
					     args.flags, args.fence.fence_value,
					     args.context, args.object_count,
					     in_args->object_array,
					     args.context_count,
					     in_args->contexts, fence_count,
					     NULL, (void *)host_event_id, 0);

	/*
	 * When the send operation succeeds, the host event will be destroyed
	 * after signal from the host
	 */

cleanup:

	if (ret) {
		if (host_event_added) {
			/* The event might be signaled and destroyed by host */
			host_event = dxgglobal_get_host_event(host_event_id);
			if (host_event) {
				eventfd_ctx_put(event);
				event = NULL;
				dxgmem_free(process, DXGMEM_EVENT, host_event);
				host_event = NULL;
			}
		}
		if (event)
			eventfd_ctx_put(event);
		if (host_event)
			dxgmem_free(process, DXGMEM_EVENT, host_event);
	}
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_signal_sync_object_cpu(struct dxgprocess *process,
				       void *__user inargs)
{
	struct d3dkmt_signalsynchronizationobjectfromcpu args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, &adapter->channel,
					     args.flags, 0, 0,
					     args.object_count, args.objects, 0,
					     NULL, args.object_count,
					     args.fence_values, NULL,
					     args.device);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_signal_sync_object_gpu(struct dxgprocess *process,
				       void *__user inargs)
{
	struct d3dkmt_signalsynchronizationobjectfromgpu args;
	struct d3dkmt_signalsynchronizationobjectfromgpu *__user user_args =
	    inargs;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct d3dddicb_signalflags flags = { };
	int ret = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.object_count == 0 ||
	    args.object_count > DXG_MAX_VM_BUS_PACKET_SIZE) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.context);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, &adapter->channel,
					     flags, 0, 0, args.object_count,
					     args.objects, 1,
					     &user_args->context,
					     args.object_count,
					     args.monitored_fence_values, NULL,
					     0);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_signal_sync_object_gpu2(struct dxgprocess *process,
					void *__user inargs)
{
	struct d3dkmt_signalsynchronizationobjectfromgpu2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	d3dkmt_handle context_handle;
	struct eventfd_ctx *event = NULL;
	uint64_t *fences = NULL;
	uint fence_count = 0;
	int ret = 0;
	struct dxghostevent *host_event = NULL;
	bool host_event_added = false;
	u64 host_event_id = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.flags.enqueue_cpu_event) {
		if (args.object_count != 0 || args.cpu_event_handle == 0) {
			pr_err("Bad input for EnqueueCpuEvent: %d %lld",
				   args.object_count, args.cpu_event_handle);

		}
	} else if (args.object_count == 0 ||
		   args.object_count > DXG_MAX_VM_BUS_PACKET_SIZE ||
		   args.context_count == 0 ||
		   args.context_count > DXG_MAX_VM_BUS_PACKET_SIZE) {
		pr_err("Invalid input: %d %d",
			   args.object_count, args.context_count);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxg_copy_from_user(&context_handle, args.contexts,
				 sizeof(d3dkmt_handle));
	if (ret)
		goto cleanup;

	if (args.flags.enqueue_cpu_event) {
		host_event = dxgmem_alloc(process, DXGMEM_EVENT,
					  sizeof(*host_event));
		if (host_event == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		host_event->process = process;
		event = eventfd_ctx_fdget((int)args.cpu_event_handle);
		if (IS_ERR(event)) {
			pr_err("failed to reference the event");
			event = NULL;
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		fence_count = 0;
		host_event->cpu_event = event;
		host_event_id = dxgglobal_new_host_event_id();
		host_event->event_id = host_event_id;
		host_event->remove_from_list = true;
		host_event->destroy_after_signal = true;
		dxgglobal_add_host_event(host_event);
		host_event_added = true;
	} else {
		fences = args.monitored_fence_values;
		fence_count = args.object_count;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    context_handle);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, &adapter->channel,
					     args.flags, 0, 0,
					     args.object_count, args.objects,
					     args.context_count, args.contexts,
					     fence_count, fences,
					     (void *)host_event_id, 0);

cleanup:

	if (ret) {
		if (host_event_added) {
			/* The event might be signaled and destroyed by host */
			host_event = dxgglobal_get_host_event(host_event_id);
			if (host_event) {
				eventfd_ctx_put(event);
				event = NULL;
				dxgmem_free(process, DXGMEM_EVENT, host_event);
				host_event = NULL;
			}
		}
		if (event)
			eventfd_ctx_put(event);
		if (host_event)
			dxgmem_free(process, DXGMEM_EVENT, host_event);
	}
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_wait_sync_object(struct dxgprocess *process,
				 void *__user inargs)
{
	struct d3dkmt_waitforsynchronizationobject2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret = 0;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.object_count > D3DDDI_MAX_OBJECT_WAITED_ON ||
	    args.object_count == 0) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.context);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	TRACE_DEBUG(1, "Fence value: %lld", args.fence.fence_value);
	ret = dxgvmb_send_wait_sync_object_gpu(process, &adapter->channel,
					       args.context, args.object_count,
					       args.object_array,
					       &args.fence.fence_value, true);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_wait_sync_object_cpu(struct dxgprocess *process,
				     void *__user inargs)
{
	struct d3dkmt_waitforsynchronizationobjectfromcpu args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct eventfd_ctx *event = NULL;
	struct dxghostevent host_event = { };
	struct dxghostevent *async_host_event = NULL;
	struct completion local_event = { };
	u64 event_id = 0;
	int ret = 0;
	unsigned long t;
	bool host_event_added = false;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.object_count > DXG_MAX_VM_BUS_PACKET_SIZE ||
	    args.object_count == 0) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args.async_event) {
		async_host_event = dxgmem_alloc(process, DXGMEM_EVENT,
						sizeof(*async_host_event));
		if (async_host_event == NULL) {
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		async_host_event->process = process;
		event = eventfd_ctx_fdget((int)args.async_event);
		if (IS_ERR(event)) {
			pr_err("failed to reference the event");
			event = NULL;
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		async_host_event->cpu_event = event;
		async_host_event->event_id = dxgglobal_new_host_event_id();
		async_host_event->destroy_after_signal = true;
		dxgglobal_add_host_event(async_host_event);
		event_id = async_host_event->event_id;
		host_event_added = true;
	} else {
		init_completion(&local_event);
		host_event.completion_event = &local_event;
		host_event.event_id = dxgglobal_new_host_event_id();
		dxgglobal_add_host_event(&host_event);
		event_id = host_event.event_id;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_wait_sync_object_cpu(process, &adapter->channel,
					       &args, event_id);
	if (ret)
		goto cleanup;

	if (args.async_event == 0) {
		t = wait_for_completion_timeout(&local_event, (10 * HZ));
		if (!t) {
			TRACE_DEBUG(1, "timeout waiting for completion");
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
	}

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);
	if (host_event.event_id)
		dxgglobal_remove_host_event(&host_event);
	if (ret) {
		if (host_event_added) {
			async_host_event = dxgglobal_get_host_event(event_id);
			if (async_host_event) {
				eventfd_ctx_put(event);
				event = NULL;
				dxgmem_free(process, DXGMEM_EVENT,
					    async_host_event);
				async_host_event = NULL;
			}
		}
		if (event)
			eventfd_ctx_put(event);
		if (async_host_event)
			dxgmem_free(process, DXGMEM_EVENT, async_host_event);
	}

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_wait_sync_object_gpu(struct dxgprocess *process,
				     void *__user inargs)
{
	struct d3dkmt_waitforsynchronizationobjectfromgpu args;
	struct dxgcontext *context = NULL;
	d3dkmt_handle device_handle = 0;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct dxgsyncobject *syncobj = NULL;
	d3dkmt_handle *objects = NULL;
	uint object_size;
	uint64_t *fences = NULL;
	int ret = 0;
	enum hmgrentry_type syncobj_type = HMGRENTRY_TYPE_FREE;
	bool monitored_fence = false;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.object_count > DXG_MAX_VM_BUS_PACKET_SIZE ||
	    args.object_count == 0) {
		pr_err("Invalid object count: %d", args.object_count);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	object_size = sizeof(d3dkmt_handle) * args.object_count;
	objects = dxgmem_alloc(process, DXGMEM_TMP, object_size);
	if (objects == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	ret = dxg_copy_from_user(objects, args.objects, object_size);
	if (ret)
		goto cleanup;

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	context = hmgrtable_get_object_by_type(&process->handle_table,
					       HMGRENTRY_TYPE_DXGCONTEXT,
					       args.context);
	if (context) {
		device_handle = context->device_handle;
		syncobj_type =
		    hmgrtable_get_object_type(&process->handle_table,
					      objects[0]);
	}
	if (device_handle == 0) {
		pr_err("Invalid context handle: %x", args.context);
		ret = STATUS_INVALID_PARAMETER;
	} else {
		if (syncobj_type == HMGRENTRY_TYPE_MONITOREDFENCE) {
			monitored_fence = true;
		} else if (syncobj_type == HMGRENTRY_TYPE_DXGSYNCOBJECT) {
			syncobj =
			    hmgrtable_get_object_by_type(&process->handle_table,
							 HMGRENTRY_TYPE_DXGSYNCOBJECT,
							 objects[0]);
			if (syncobj == NULL) {
				pr_err("Invalid syncobj: %x", objects[0]);
				ret = STATUS_INVALID_PARAMETER;
			} else {
				monitored_fence = syncobj->monitored_fence;
			}
		} else {
			pr_err("Invalid syncobj type: %x", objects[0]);
			ret = STATUS_INVALID_PARAMETER;
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);

	if (ret)
		goto cleanup;

	if (monitored_fence) {
		object_size = sizeof(uint64_t) * args.object_count;
		fences = dxgmem_alloc(process, DXGMEM_TMP, object_size);
		if (fences == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		ret = dxg_copy_from_user(fences, args.monitored_fence_values,
					 object_size);
		if (ret)
			goto cleanup;
	} else {
		fences = &args.fence_value;
	}

	device = dxgprocess_device_by_handle(process, device_handle);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_wait_sync_object_gpu(process, &adapter->channel,
					       args.context, args.object_count,
					       objects, fences,
					       !monitored_fence);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);
	if (objects)
		dxgmem_free(process, DXGMEM_TMP, objects);
	if (fences && fences != &args.fence_value)
		dxgmem_free(process, DXGMEM_TMP, fences);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_lock2(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_lock2 args;
	struct d3dkmt_lock2 *__user result = inargs;
	int ret = 0;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct dxgallocation *alloc = NULL;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	args.data = NULL;
	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	alloc = hmgrtable_get_object_by_type(&process->handle_table,
					     HMGRENTRY_TYPE_DXGALLOCATION,
					     args.allocation);
	if (alloc == NULL) {
		ret = STATUS_INVALID_PARAMETER;
	} else {
		if (alloc->cpu_address) {
			ret = dxg_copy_to_user(&result->data,
					       &alloc->cpu_address,
					       sizeof(args.data));
			if (NT_SUCCESS(ret)) {
				args.data = alloc->cpu_address;
				if (alloc->cpu_address_mapped)
					alloc->cpu_address_refcount++;
			}
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);
	if (ret)
		goto cleanup;
	if (args.data)
		goto success;

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_lock2(process, &adapter->channel, &args, result);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		dxgdevice_release_reference(device);

success:
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_unlock2(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_unlock2 args;
	int ret = 0;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct dxgallocation *alloc = NULL;
	bool done = false;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	alloc = hmgrtable_get_object_by_type(&process->handle_table,
					     HMGRENTRY_TYPE_DXGALLOCATION,
					     args.allocation);
	if (alloc == NULL) {
		ret = STATUS_INVALID_PARAMETER;
	} else {
		if (alloc->cpu_address == NULL) {
			pr_err("Allocation is not locked: %p", alloc);
			ret = STATUS_INVALID_PARAMETER;
		} else if (alloc->cpu_address_mapped) {
			if (alloc->cpu_address_refcount > 0) {
				alloc->cpu_address_refcount--;
				if (alloc->cpu_address_refcount != 0) {
					done = true;
				} else {
					dxg_unmap_iospace(alloc->cpu_address,
							  alloc->
							  num_pages <<
							  PAGE_SHIFT);
					alloc->cpu_address_mapped = false;
					alloc->cpu_address = NULL;
				}
			} else {
				pr_err("Bad cpu access refcount");
				done = true;
			}
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);
	if (done)
		goto success;
	if (ret)
		goto cleanup;

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_unlock2(process, &adapter->channel, &args);
	if (ret)
		goto cleanup;

cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		dxgdevice_release_reference(device);

success:
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_update_alloc_property(struct dxgprocess *process,
				      void *__user inargs)
{
	struct d3dddi_updateallocproperty args;
	int ret = 0;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGPAGINGQUEUE,
						    args.paging_queue);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_update_alloc_property(process, &adapter->channel,
						&args, inargs);

cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_mark_device_as_error(struct dxgprocess *process,
				     void *__user inargs)
{
	struct d3dkmt_markdeviceaserror args;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	int ret;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	ret = dxgvmb_send_mark_device_as_error(process, &adapter->channel,
					       &args);
cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_query_alloc_residency(struct dxgprocess *process,
				      void *__user inargs)
{
	struct d3dkmt_queryallocationresidency args;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	int ret;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if ((args.allocation_count == 0) == (args.resource == 0)) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	ret = dxgvmb_send_query_alloc_residency(process, &adapter->channel,
						&args);
cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_set_allocation_priority(struct dxgprocess *process,
					void *__user inargs)
{
	struct d3dkmt_setallocationpriority args;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	int ret;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	ret = dxgvmb_send_set_allocation_priority(process, &adapter->channel,
						  &args);
cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_get_allocation_priority(struct dxgprocess *process,
					void *__user inargs)
{
	struct d3dkmt_getallocationpriority args;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	int ret;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	ret = dxgvmb_send_get_allocation_priority(process, &adapter->channel,
						  &args);
cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static long set_context_scheduling_priority(struct dxgprocess *process,
					    d3dkmt_handle hcontext,
					    int priority, bool in_process)
{
	int ret = 0;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    hcontext);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	ret = dxgvmb_send_set_context_scheduling_priority(process,
							  &adapter->channel,
							  hcontext, priority,
							  in_process);
	if (ret)
		pr_err("send_set_context_scheduling_priority failed");
cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	return ret;
}

static int dxgk_set_context_scheduling_priority(struct dxgprocess *process,
						void *__user inargs)
{
	struct d3dkmt_setcontextschedulingpriority args;
	int ret;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	ret = set_context_scheduling_priority(process, args.context,
					      args.priority, false);
cleanup:
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static long get_context_scheduling_priority(struct dxgprocess *process,
					    d3dkmt_handle hcontext,
					    __user int *priority,
					    bool in_process)
{
	int ret = 0;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int pri = 0;

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    hcontext);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	ret = dxgvmb_send_get_context_scheduling_priority(process,
							  &adapter->channel,
							  hcontext, &pri,
							  in_process);
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(priority, &pri, sizeof(pri));

cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);

	return ret;
}

static int dxgk_get_context_scheduling_priority(struct dxgprocess *process,
						void *__user inargs)
{
	struct d3dkmt_getcontextschedulingpriority args;
	int ret;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	ret = get_context_scheduling_priority(process, args.context,
					      &((struct
						 d3dkmt_getcontextschedulingpriority
						 *)
						inargs)->priority, false);
cleanup:
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_set_context_process_scheduling_priority(struct dxgprocess
							*process,
							void *__user inargs)
{
	struct d3dkmt_setcontextinprocessschedulingpriority args;
	int ret;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	ret = set_context_scheduling_priority(process, args.context,
					      args.priority, true);
cleanup:
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_get_context_process_scheduling_priority(struct dxgprocess
							*process,
							void *__user inargs)
{
	struct d3dkmt_getcontextinprocessschedulingpriority args;
	int ret;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	ret = get_context_scheduling_priority(process, args.context,
					      &((struct
						 d3dkmt_getcontextinprocessschedulingpriority
						 *)
						inargs)->priority, true);
cleanup:
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_change_vidmem_reservation(struct dxgprocess *process,
					  void *__user inargs)
{
	struct d3dkmt_changevideomemoryreservation args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	TRACE_FUNC_ENTER(__func__);
	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.process != 0) {
		pr_err("setting memory reservation for other process");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;
	args.adapter = 0;
	ret = dxgvmb_send_change_vidmem_reservation(process, &adapter->channel,
						    0, &args);

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		dxgadapter_release_reference(adapter);
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_query_clock_calibration(struct dxgprocess *process,
					void *__user inargs)
{
	struct d3dkmt_queryclockcalibration args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;

	args.adapter = adapter->host_handle;
	ret = dxgvmb_send_query_clock_calibration(process, &adapter->channel,
						  &args, inargs);
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(inargs, &args, sizeof(args));

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		dxgadapter_release_reference(adapter);
	return ret;
}

static int dxgk_flush_heap_transitions(struct dxgprocess *process,
				       void *__user inargs)
{
	struct d3dkmt_flushheaptransitions args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;

	args.adapter = adapter->host_handle;
	ret = dxgvmb_send_flush_heap_transitions(process, &adapter->channel,
						 &args);
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(inargs, &args, sizeof(args));

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		dxgadapter_release_reference(adapter);
	return ret;
}

static int handle_table_escape(struct dxgprocess *process,
			       struct d3dkmt_escape *args,
			       struct d3dkmt_ht_desc *cmdin)
{
	int ret = 0;
	struct d3dkmt_ht_desc cmd;
	struct hmgrtable *table;

	dxgmutex_lock(&process->process_mutex);
	cmd = *cmdin;
	if (cmd.index >= 2) {
		pr_err("invalid table index");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	table = process->test_handle_table[cmd.index];
	if (table == NULL) {
		table = dxgmem_alloc(process, DXGMEM_HANDLE_TABLE,
				     sizeof(*table));
		if (table == NULL) {
			pr_err("failed to allocate handle table");
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		hmgrtable_init(table, process);
		process->test_handle_table[cmd.index] = table;
	}
	switch (cmd.command) {
	case D3DKMT_HT_COMMAND_ALLOC:
		cmd.handle = hmgrtable_alloc_handle_safe(table, cmd.object,
							 (enum hmgrentry_type)
							 cmd.object_type, true);
		ret = dxg_copy_to_user(args->priv_drv_data, &cmd, sizeof(cmd));
		break;
	case D3DKMT_HT_COMMAND_FREE:
		hmgrtable_free_handle_safe(table,
					   (enum hmgrentry_type)cmd.object_type,
					   cmd.handle);
		break;
		break;
	case D3DKMT_HT_COMMAND_ASSIGN:
		ret = hmgrtable_assign_handle_safe(table, cmd.object,
						   (enum hmgrentry_type)cmd.
						   object_type, cmd.handle);
		break;
	case D3DKMT_HT_COMMAND_GET:
		hmgrtable_lock(table, DXGLOCK_SHARED);
		cmd.object = hmgrtable_get_object_by_type(table,
							  (enum hmgrentry_type)
							  cmd.object_type,
							  cmd.handle);
		hmgrtable_unlock(table, DXGLOCK_SHARED);
		ret = dxg_copy_to_user(args->priv_drv_data, &cmd, sizeof(cmd));
		break;
	case D3DKMT_HT_COMMAND_DESTROY:
		if (table) {
			hmgrtable_destroy(table);
			dxgmem_free(process, DXGMEM_HANDLE_TABLE, table);
		}
		process->test_handle_table[cmd.index] = NULL;
		break;
	default:
		ret = STATUS_INVALID_PARAMETER;
		pr_err("unknoen handle table command");
		break;
	}

cleanup:
	dxgmutex_unlock(&process->process_mutex);
	return ret;
}

static int dxgk_escape(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_escape args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;

	if (args.type == D3DKMT_ESCAPE_DRT_TEST) {
		struct d3dkmt_ht_desc drtcmd;

		if (args.priv_drv_data_size >= sizeof(drtcmd)) {
			ret = dxg_copy_from_user(&drtcmd,
						 args.priv_drv_data,
						 sizeof(drtcmd));
			if (ret)
				goto cleanup;
			if (drtcmd.head.command ==
			    D3DKMT_DRT_TEST_COMMAND_HANDLETABLE) {
				dxgadapter_release_lock_shared(adapter);
				adapter_locked = false;
				ret = handle_table_escape(process, &args,
							  &drtcmd);
				goto cleanup;
			}
		}
	}

	args.adapter = adapter->host_handle;
	ret = dxgvmb_send_escape(process, &adapter->channel, &args);
	if (ret)
		goto cleanup;

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		dxgadapter_release_reference(adapter);
	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_query_vidmem_info(struct dxgprocess *process,
				  void *__user inargs)
{
	struct d3dkmt_queryvideomemoryinfo args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.process != 0) {
		pr_err("query vidmem info from another process ");
		goto cleanup;
	}

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;

	args.adapter = adapter->host_handle;
	ret = dxgvmb_send_query_vidmem_info(process, &adapter->channel,
					    &args, inargs);

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		dxgadapter_release_reference(adapter);
	if (ret)
		pr_err("%s failed: %x", __func__, ret);
	return ret;
}

static int dxgk_get_device_state(struct dxgprocess *process,
				 void *__user inargs)
{
	int ret = 0;
	struct d3dkmt_getdevicestate args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_get_device_state(process, &adapter->channel,
					   &args, inargs);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_reference(device);
	if (ret)
		pr_err("%s failed %x", __func__, ret);

	return ret;
}

static int dxgsharedsyncobj_get_host_nt_handle(struct dxgsharedsyncobject
					       *syncobj,
					       struct dxgprocess *process,
					       d3dkmt_handle object_handle)
{
	int ret = 0;

	dxgmutex_lock(&syncobj->fd_mutex);
	if (syncobj->host_shared_handle_nt_reference == 0) {
		ret = dxgvmb_send_create_nt_shared_object(process,
							  object_handle,
							  &syncobj->
							  host_shared_handle_nt);
		if (ret)
			goto cleanup;
		TRACE_DEBUG(1, "Host_shared_handle_ht: %x",
			    syncobj->host_shared_handle_nt);
		dxgsharedsyncobj_acquire_reference(syncobj);
	}
	syncobj->host_shared_handle_nt_reference++;
cleanup:
	dxgmutex_unlock(&syncobj->fd_mutex);
	return ret;
}

static int dxgsharedresource_get_host_nt_handle(struct dxgsharedresource
						*resource,
						struct dxgprocess *process,
						d3dkmt_handle object_handle)
{
	int ret = 0;

	dxgmutex_lock(&resource->fd_mutex);
	if (resource->host_shared_handle_nt_reference == 0) {
		ret = dxgvmb_send_create_nt_shared_object(process,
							  object_handle,
							  &resource->
							  host_shared_handle_nt);
		if (ret)
			goto cleanup;
		TRACE_DEBUG(1, "Resource host_shared_handle_ht: %x",
			    resource->host_shared_handle_nt);
		dxgsharedresource_acquire_reference(resource);
	}
	resource->host_shared_handle_nt_reference++;
cleanup:
	dxgmutex_unlock(&resource->fd_mutex);
	return ret;
}

enum dxg_sharedobject_type {
	DXG_SHARED_SYNCOBJECT,
	DXG_SHARED_RESOURCE
};

static int get_object_fd(enum dxg_sharedobject_type type,
			 void *object, int *fdout)
{
	struct file *file;
	int fd;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("get_unused_fd_flags failed: %x", fd);
		return STATUS_INTERNAL_ERROR;
	}

	switch (type) {
	case DXG_SHARED_SYNCOBJECT:
		file = anon_inode_getfile("dxgsyncobj",
					  &dxg_syncobj_fops, object, 0);
		break;
	case DXG_SHARED_RESOURCE:
		file = anon_inode_getfile("dxgresource",
					  &dxg_resource_fops, object, 0);
		break;
	default:
		return STATUS_INVALID_PARAMETER;
	};
	if (IS_ERR(file)) {
		pr_err("anon_inode_getfile failed: %x", fd);
		put_unused_fd(fd);
		return STATUS_INTERNAL_ERROR;
	}

	fd_install(fd, file);
	*fdout = fd;
	return 0;
}

static int dxgk_share_objects(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_shareobjects args;
	enum hmgrentry_type object_type;
	struct dxgsyncobject *syncobj = NULL;
	struct dxgresource *resource = NULL;
	struct dxgsharedsyncobject *shared_syncobj = NULL;
	struct dxgsharedresource *shared_resource = NULL;
	d3dkmt_handle *handles = NULL;
	int object_fd = 0;
	void *obj = NULL;
	uint handle_size;
	int ret;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	if (args.object_count == 0 || args.object_count > 1) {
		pr_err("invalid object count %d", args.object_count);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	handle_size = args.object_count * sizeof(d3dkmt_handle);

	handles = dxgmem_alloc(process, DXGMEM_TMP, handle_size);
	if (handles == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	ret = dxg_copy_from_user(handles, args.objects, handle_size);
	if (ret)
		goto cleanup;

	TRACE_DEBUG(1, "Sharing handle: %x", handles[0]);

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	object_type = hmgrtable_get_object_type(&process->handle_table,
						handles[0]);
	obj = hmgrtable_get_object(&process->handle_table, handles[0]);
	if (obj == NULL) {
		pr_err("invalid object handle %x", handles[0]);
		ret = STATUS_INVALID_PARAMETER;
	} else {
		switch (object_type) {
		case HMGRENTRY_TYPE_DXGSYNCOBJECT:
			syncobj = obj;
			if (syncobj->shared) {
				dxgsyncobject_acquire_reference(syncobj);
				shared_syncobj = syncobj->shared_owner;
			} else {
				pr_err("sync object is not shared");
				syncobj = NULL;
				ret = STATUS_INVALID_PARAMETER;
			}
			break;
		case HMGRENTRY_TYPE_DXGRESOURCE:
			resource = obj;
			if (resource->shared_owner) {
				dxgresource_acquire_reference(resource);
				shared_resource = resource->shared_owner;
			} else {
				resource = NULL;
				pr_err("resource object is not shared");
				ret = STATUS_INVALID_PARAMETER;
			}
			break;
		default:
			pr_err("invalid object type %d", object_type);
			ret = STATUS_INVALID_PARAMETER;
			break;
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);

	if (ret)
		goto cleanup;

	switch (object_type) {
	case HMGRENTRY_TYPE_DXGSYNCOBJECT:
		ret = get_object_fd(DXG_SHARED_SYNCOBJECT, shared_syncobj,
				    &object_fd);
		if (!ret)
			ret =
			    dxgsharedsyncobj_get_host_nt_handle(shared_syncobj,
								process,
								handles[0]);
		break;
	case HMGRENTRY_TYPE_DXGRESOURCE:
		ret = get_object_fd(DXG_SHARED_RESOURCE, shared_resource,
				    &object_fd);
		if (!ret)
			ret =
			    dxgsharedresource_get_host_nt_handle
			    (shared_resource, process, handles[0]);
		break;
	default:
		ret = STATUS_INVALID_PARAMETER;
		break;
	}

	if (ret)
		goto cleanup;

	TRACE_DEBUG(1, "Object FD: %x", object_fd);

	{
		winhandle tmp = (winhandle) object_fd;

		ret = dxg_copy_to_user(args.shared_handle, &tmp,
				       sizeof(winhandle));
	}

cleanup:
	if (ret) {
		if (object_fd > 0)
			put_unused_fd(object_fd);
	}

	if (handles)
		dxgmem_free(process, DXGMEM_TMP, handles);

	if (syncobj)
		dxgsyncobject_release_reference(syncobj);

	if (resource)
		dxgresource_release_reference(resource);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_invalidate_cache(struct dxgprocess *process,
				 void *__user inargs)
{
	pr_err("%s is not implemented", __func__);
	return STATUS_NOT_IMPLEMENTED;
}

static int dxgk_query_resource_info(struct dxgprocess *process,
				    void *__user inargs)
{
	struct d3dkmt_queryresourceinfo args;
	struct dxgdevice *device = NULL;
	struct dxgsharedresource *shared_resource = NULL;
	int ret;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	hmgrtable_lock(&dxgglobal->handle_table, DXGLOCK_SHARED);
	shared_resource = hmgrtable_get_object_by_type(&dxgglobal->handle_table,
						       HMGRENTRY_TYPE_DXGSHAREDRESOURCE,
						       args.global_share);
	if (shared_resource) {
		if (!dxgsharedresource_acquire_reference(shared_resource))
			shared_resource = NULL;
	}
	hmgrtable_unlock(&dxgglobal->handle_table, DXGLOCK_SHARED);

	if (shared_resource == NULL) {
		pr_err("Invalid shared resource handle: %x",
			   args.global_share);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret) {
		dxgdevice_release_reference(device);
		device = NULL;
		goto cleanup;
	}

	ret = dxgsharedresource_seal(shared_resource);
	if (ret)
		goto cleanup;

	args.private_runtime_data_size =
	    shared_resource->runtime_private_data_size;
	args.resource_priv_drv_data_size =
	    shared_resource->resource_private_data_size;
	args.allocation_count = shared_resource->allocation_count;
	args.total_priv_drv_data_size =
	    shared_resource->alloc_private_data_size;

	ret = dxg_copy_to_user(inargs, &args, sizeof(args));

cleanup:

	if (shared_resource)
		dxgsharedresource_release_reference(shared_resource);
	if (device)
		dxgdevice_release_lock_shared(device);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_query_resource_info_nt(struct dxgprocess *process,
				       void *__user inargs)
{
	struct d3dkmt_queryresourceinfofromnthandle args;
	int ret;
	struct dxgdevice *device = NULL;
	struct dxgsharedresource *shared_resource = NULL;
	struct file *file = NULL;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	file = fget(args.nt_handle);
	if (!file) {
		pr_err("failed to get file from handle: %llx",
			   args.nt_handle);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (file->f_op != &dxg_resource_fops) {
		pr_err("invalid fd: %llx", args.nt_handle);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	shared_resource = file->private_data;
	if (shared_resource == NULL) {
		pr_err("invalid private data: %llx", args.nt_handle);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret) {
		dxgdevice_release_reference(device);
		device = NULL;
		goto cleanup;
	}

	ret = dxgsharedresource_seal(shared_resource);
	if (ret)
		goto cleanup;

	args.private_runtime_data_size =
	    shared_resource->runtime_private_data_size;
	args.resource_priv_drv_data_size =
	    shared_resource->resource_private_data_size;
	args.allocation_count = shared_resource->allocation_count;
	args.total_priv_drv_data_size =
	    shared_resource->alloc_private_data_size;

	ret = dxg_copy_to_user(inargs, &args, sizeof(args));

cleanup:

	if (file)
		fput(file);
	if (device)
		dxgdevice_release_lock_shared(device);
	if (device)
		dxgdevice_release_reference(device);

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

int assign_resource_handles(struct dxgprocess *process,
			    struct dxgsharedresource *shared_resource,
			    struct d3dkmt_openresourcefromnthandle *args,
			    d3dkmt_handle resource_handle,
			    struct dxgresource *resource,
			    struct dxgallocation **allocs,
			    d3dkmt_handle *handles)
{
	int ret = 0;
	int i;
	uint8_t *cur_priv_data;
	struct d3dddi_openallocationinfo2 open_alloc_info = { };

	TRACE_DEBUG(1, "%s", __func__);

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	ret = hmgrtable_assign_handle(&process->handle_table, resource,
				      HMGRENTRY_TYPE_DXGRESOURCE,
				      resource_handle);
	if (ret)
		goto cleanup;
	resource->handle = resource_handle;
	resource->handle_valid = 1;
	cur_priv_data = shared_resource->alloc_private_data;
	for (i = 0; i < args->allocation_count; i++) {
		ret = hmgrtable_assign_handle(&process->handle_table, allocs[i],
					      HMGRENTRY_TYPE_DXGALLOCATION,
					      handles[i]);
		if (ret)
			goto cleanup;
		allocs[i]->alloc_handle = handles[i];
		allocs[i]->handle_valid = 1;
		open_alloc_info.allocation = handles[i];
		if (shared_resource->alloc_private_data_sizes)
			open_alloc_info.priv_drv_data_size =
			    shared_resource->alloc_private_data_sizes[i];
		else
			open_alloc_info.priv_drv_data_size = 0;

		open_alloc_info.priv_drv_data = cur_priv_data;
		cur_priv_data += open_alloc_info.priv_drv_data_size;

		ret = dxg_copy_to_user(&args->open_alloc_info[i],
				       &open_alloc_info,
				       sizeof(open_alloc_info));
		if (ret)
			goto cleanup;
	}
cleanup:
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
	if (ret) {
		for (i = 0; i < args->allocation_count; i++)
			dxgallocation_free_handle(allocs[i]);
		dxgresource_free_handle(resource);
	}
	TRACE_DEBUG(1, "%s end %x", __func__, ret);
	return ret;
}

int open_resource(struct dxgprocess *process,
		  struct d3dkmt_openresourcefromnthandle *args,
		  bool nt_handle, __user d3dkmt_handle *res_out)
{
	int ret = 0;
	int i;
	d3dkmt_handle *alloc_handles = NULL;
	int alloc_handles_size = sizeof(d3dkmt_handle) * args->allocation_count;
	struct dxgsharedresource *shared_resource = NULL;
	struct dxgresource *resource = NULL;
	struct dxgallocation **allocs = NULL;
	d3dkmt_handle global_share;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	d3dkmt_handle resource_handle = 0;
	struct file *file = NULL;

	TRACE_DEBUG(1, "Opening resource handle: %llx", args->nt_handle);

	if (nt_handle) {
		file = fget(args->nt_handle);
		if (!file) {
			pr_err("failed to get file from handle: %llx",
				   args->nt_handle);
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		if (file->f_op != &dxg_resource_fops) {
			pr_err("invalid fd type: %llx", args->nt_handle);
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		shared_resource = file->private_data;
		if (shared_resource == NULL) {
			pr_err("invalid private data: %llx",
				   args->nt_handle);
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		if (!dxgsharedresource_acquire_reference(shared_resource))
			shared_resource = NULL;
		else
			global_share = shared_resource->host_shared_handle_nt;
	} else {
		hmgrtable_lock(&dxgglobal->handle_table, DXGLOCK_SHARED);
		shared_resource =
		    hmgrtable_get_object_by_type(&dxgglobal->handle_table,
						 HMGRENTRY_TYPE_DXGSHAREDRESOURCE,
						 (d3dkmt_handle) args->
						 nt_handle);
		if (shared_resource) {
			if (!dxgsharedresource_acquire_reference
			    (shared_resource))
				shared_resource = NULL;
			else
				global_share =
				    shared_resource->host_shared_handle;
		}
		hmgrtable_unlock(&dxgglobal->handle_table, DXGLOCK_SHARED);
	}

	if (shared_resource == NULL) {
		pr_err("Invalid shared resource handle: %x",
			   (d3dkmt_handle) args->nt_handle);
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	TRACE_DEBUG(1, "Shared resource: %p %x", shared_resource,
		    global_share);

	device = dxgprocess_device_by_handle(process, args->device);
	if (device == NULL) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret) {
		dxgdevice_release_reference(device);
		device = NULL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgsharedresource_seal(shared_resource);
	if (ret)
		goto cleanup;

	if (args->allocation_count != shared_resource->allocation_count ||
	    args->private_runtime_data_size <
	    shared_resource->runtime_private_data_size ||
	    args->resource_priv_drv_data_size <
	    shared_resource->resource_private_data_size ||
	    args->total_priv_drv_data_size <
	    shared_resource->alloc_private_data_size) {
		ret = STATUS_INVALID_PARAMETER;
		pr_err("Invalid data sizes");
		goto cleanup;
	}

	alloc_handles = dxgmem_alloc(process, DXGMEM_TMP, alloc_handles_size);
	if (alloc_handles == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	allocs = dxgmem_alloc(process, DXGMEM_TMP,
			      sizeof(void *) * args->allocation_count);
	if (allocs == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	resource = dxgresource_create(device);
	if (resource == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	dxgsharedresource_add_resource(shared_resource, resource);

	for (i = 0; i < args->allocation_count; i++) {
		allocs[i] = dxgallocation_create(process);
		if (allocs[i] == NULL)
			goto cleanup;
		dxgresource_add_alloc(resource, allocs[i]);
	}

	ret = dxgvmb_send_open_resource(process, &adapter->channel,
					device->handle, nt_handle, global_share,
					args->allocation_count,
					args->total_priv_drv_data_size,
					&resource_handle, alloc_handles);
	if (ret) {
		pr_err("dxgvmb_send_open_resource failed");
		goto cleanup;
	}

	if (shared_resource->runtime_private_data_size) {
		ret = dxg_copy_to_user(args->private_runtime_data,
				       shared_resource->runtime_private_data,
				       shared_resource->
				       runtime_private_data_size);
		if (ret)
			goto cleanup;
	}

	if (shared_resource->resource_private_data_size) {
		ret = dxg_copy_to_user(args->resource_priv_drv_data,
				       shared_resource->resource_private_data,
				       shared_resource->
				       resource_private_data_size);
		if (ret)
			goto cleanup;
	}

	if (shared_resource->alloc_private_data_size) {
		ret = dxg_copy_to_user(args->total_priv_drv_data,
				       shared_resource->alloc_private_data,
				       shared_resource->
				       alloc_private_data_size);
		if (ret)
			goto cleanup;
	}

	ret = assign_resource_handles(process, shared_resource, args,
				      resource_handle, resource, allocs,
				      alloc_handles);
	if (ret)
		goto cleanup;

	ret = dxg_copy_to_user(res_out, &resource_handle,
			       sizeof(d3dkmt_handle));

cleanup:

	if (ret) {
		if (resource_handle) {
			struct d3dkmt_destroyallocation2 tmp = { };

			tmp.flags.assume_not_in_use = 1;
			tmp.device = args->device;
			tmp.resource = resource_handle;
			ret = dxgvmb_send_destroy_allocation(process, device,
							     &adapter->channel,
							     &tmp, NULL);
		}
		if (resource)
			dxgresource_destroy(resource);
	}

	if (file)
		fput(file);
	if (allocs)
		dxgmem_free(process, DXGMEM_TMP, allocs);
	if (shared_resource)
		dxgsharedresource_release_reference(shared_resource);
	if (alloc_handles)
		dxgmem_free(process, DXGMEM_TMP, alloc_handles);
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_lock_shared(device);
	if (device)
		dxgdevice_release_reference(device);

	return ret;
}

static int dxgk_open_resource(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_openresource args;
	struct d3dkmt_openresourcefromnthandle args_nt = { };
	int ret;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	args_nt.device = args.device;
	args_nt.nt_handle = (winhandle) args.global_share;
	args_nt.allocation_count = args.allocation_count;
	args_nt.open_alloc_info = args.open_alloc_info;
	args_nt.private_runtime_data_size = args.private_runtime_data_size;
	args_nt.private_runtime_data = args.private_runtime_data;
	args_nt.resource_priv_drv_data_size = args.resource_priv_drv_data_size;
	args_nt.resource_priv_drv_data = args.resource_priv_drv_data;
	args_nt.total_priv_drv_data_size = args.total_priv_drv_data_size;
	args_nt.total_priv_drv_data = args.total_priv_drv_data;

	ret = open_resource(process, &args_nt, false,
			    &((struct d3dkmt_openresource *)inargs)->resource);

cleanup:

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static ntstatus dxgk_open_resource_nt(struct dxgprocess *process,
				      void *__user inargs)
{
	struct d3dkmt_openresourcefromnthandle args;
	int ret;

	TRACE_FUNC_ENTER(__func__);

	ret = dxg_copy_from_user(&args, inargs, sizeof(args));
	if (ret)
		goto cleanup;

	ret = open_resource(process, &args, true,
			    &((struct d3dkmt_openresourcefromnthandle *)
			      inargs)->resource);

cleanup:

	TRACE_FUNC_EXIT(__func__, ret);
	return ret;
}

static int dxgk_render(struct dxgprocess *process, void *__user inargs)
{
	pr_err("%s is not implemented", __func__);
	return STATUS_NOT_IMPLEMENTED;
}

static int dxgk_create_context(struct dxgprocess *process, void *__user inargs)
{
	pr_err("%s is not implemented", __func__);
	return STATUS_NOT_IMPLEMENTED;
}

static int dxgk_get_shared_resource_adapter_luid(struct dxgprocess *process,
						 void *__user inargs)
{
	pr_err("shared_resource_adapter_luid is not implemented");
	return STATUS_NOT_IMPLEMENTED;
}

/*
 * IOCTL processing
 */
static int dxgk_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	struct dxgthreadinfo *thread;
	int code = _IOC_NR(p1);
	ntstatus status;
	struct dxgprocess *process;

	if (code < 1 || code > LX_IO_MAX) {
		pr_err("bad ioctl %x %x %x %x",
			   code, _IOC_TYPE(p1), _IOC_SIZE(p1), _IOC_DIR(p1));
		return STATUS_INVALID_PARAMETER;
	}
	if (ioctls[code].ioctl_callback == NULL) {
		pr_err("ioctl callback is NULL %x", code);
		return STATUS_INTERNAL_ERROR;
	}
	if (ioctls[code].ioctl != p1) {
		pr_err("ioctl mismatch. Code: %x User: %x Kernel: %x",
			   code, p1, ioctls[code].ioctl);
		return STATUS_INTERNAL_ERROR;
	}
	process = (struct dxgprocess *)f->private_data;
	if (process->tgid != current->tgid) {
		pr_err("Call from a wrong process: %d %d",
			   process->tgid, current->tgid);
		return STATUS_INVALID_PARAMETER;
	}
	thread = dxglockorder_get_thread();
	status = ioctls[code].ioctl_callback(process, (void *__user)p2);
	dxglockorder_check_empty(thread);
	dxglockorder_put_thread(thread);
	return status;
}

long dxgk_compat_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	TRACE_DEBUG(2, "compat ioctl %x", p1);
	return dxgk_ioctl(f, p1, p2);
}

long dxgk_unlocked_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	TRACE_DEBUG(2, "unlocked ioctl %x Code:%d", p1, _IOC_NR(p1));
	return dxgk_ioctl(f, p1, p2);
}

#define SET_IOCTL(callback, v)				\
	ioctls[_IOC_NR(v)].ioctl_callback = callback;	\
	ioctls[_IOC_NR(v)].ioctl = v

void ioctl_desc_init(void)
{
	memset(ioctls, 0, sizeof(ioctls));
	SET_IOCTL(/*0x1 */ dxgk_open_adapter_from_luid,
		  LX_DXOPENADAPTERFROMLUID);
	SET_IOCTL(/*0x2 */ dxgk_create_device,
		  LX_DXCREATEDEVICE);
	SET_IOCTL(/*0x3 */ dxgk_create_context,
		  LX_DXCREATECONTEXT);
	SET_IOCTL(/*0x4 */ dxgk_create_context_virtual,
		  LX_DXCREATECONTEXTVIRTUAL);
	SET_IOCTL(/*0x5 */ dxgk_destroy_context,
		  LX_DXDESTROYCONTEXT);
	SET_IOCTL(/*0x6 */ dxgk_create_allocation,
		  LX_DXCREATEALLOCATION);
	SET_IOCTL(/*0x7 */ dxgk_create_paging_queue,
		  LX_DXCREATEPAGINGQUEUE);
	SET_IOCTL(/*0x8 */ dxgk_reserve_gpu_va,
		  LX_DXRESERVEGPUVIRTUALADDRESS);
	SET_IOCTL(/*0x9 */ dxgk_query_adapter_info,
		  LX_DXQUERYADAPTERINFO);
	SET_IOCTL(/*0xa */ dxgk_query_vidmem_info,
		  LX_DXQUERYVIDEOMEMORYINFO);
	SET_IOCTL(/*0xb */ dxgk_make_resident,
		  LX_DXMAKERESIDENT);
	SET_IOCTL(/*0xc */ dxgk_map_gpu_va,
		  LX_DXMAPGPUVIRTUALADDRESS);
	SET_IOCTL(/*0xd */ dxgk_escape,
		  LX_DXESCAPE);
	SET_IOCTL(/*0xe */ dxgk_get_device_state,
		  LX_DXGETDEVICESTATE);
	SET_IOCTL(/*0xf */ dxgk_submit_command,
		  LX_DXSUBMITCOMMAND);
	SET_IOCTL(/*0x10 */ dxgk_create_sync_object,
		  LX_DXCREATESYNCHRONIZATIONOBJECT);
	SET_IOCTL(/*0x11 */ dxgk_signal_sync_object,
		  LX_DXSIGNALSYNCHRONIZATIONOBJECT);
	SET_IOCTL(/*0x12 */ dxgk_wait_sync_object,
		  LX_DXWAITFORSYNCHRONIZATIONOBJECT);
	SET_IOCTL(/*0x13 */ dxgk_destroy_allocation,
		  LX_DXDESTROYALLOCATION2);
	SET_IOCTL(/*0x14 */ dxgk_enum_adapters,
		  LX_DXENUMADAPTERS2);
	SET_IOCTL(/*0x15 */ dxgk_close_adapter,
		  LX_DXCLOSEADAPTER);
	SET_IOCTL(/*0x16 */ dxgk_change_vidmem_reservation,
		  LX_DXCHANGEVIDEOMEMORYRESERVATION);
	SET_IOCTL(/*0x17 */ dxgk_create_hwcontext,
		  LX_DXCREATEHWCONTEXT);
	SET_IOCTL(/*0x18 */ dxgk_create_hwqueue,
		  LX_DXCREATEHWQUEUE);
	SET_IOCTL(/*0x19 */ dxgk_destroy_device,
		  LX_DXDESTROYDEVICE);
	SET_IOCTL(/*0x1a */ dxgk_destroy_hwcontext,
		  LX_DXDESTROYHWCONTEXT);
	SET_IOCTL(/*0x1b */ dxgk_destroy_hwqueue,
		  LX_DXDESTROYHWQUEUE);
	SET_IOCTL(/*0x1c */ dxgk_destroy_paging_queue,
		  LX_DXDESTROYPAGINGQUEUE);
	SET_IOCTL(/*0x1d */ dxgk_destroy_sync_object,
		  LX_DXDESTROYSYNCHRONIZATIONOBJECT);
	SET_IOCTL(/*0x1e */ dxgk_evict,
		  LX_DXEVICT);
	SET_IOCTL(/*0x1f */ dxgk_flush_heap_transitions,
		  LX_DXFLUSHHEAPTRANSITIONS);
	SET_IOCTL(/*0x20 */ dxgk_free_gpu_va,
		  LX_DXFREEGPUVIRTUALADDRESS);
	SET_IOCTL(/*0x21 */ dxgk_get_context_process_scheduling_priority,
		  LX_DXGETCONTEXTINPROCESSSCHEDULINGPRIORITY);
	SET_IOCTL(/*0x22 */ dxgk_get_context_scheduling_priority,
		  LX_DXGETCONTEXTSCHEDULINGPRIORITY);
	SET_IOCTL(/*0x23 */ dxgk_get_shared_resource_adapter_luid,
		  LX_DXGETSHAREDRESOURCEADAPTERLUID);
	SET_IOCTL(/*0x24 */ dxgk_invalidate_cache,
		  LX_DXINVALIDATECACHE);
	SET_IOCTL(/*0x25 */ dxgk_lock2,
		  LX_DXLOCK2);
	SET_IOCTL(/*0x26 */ dxgk_mark_device_as_error,
		  LX_DXMARKDEVICEASERROR);
	SET_IOCTL(/*0x27 */ dxgk_offer_allocations,
		  LX_DXOFFERALLOCATIONS);
	SET_IOCTL(/*0x28 */ dxgk_open_resource,
		  LX_DXOPENRESOURCE);
	SET_IOCTL(/*0x29 */ dxgk_open_sync_object,
		  LX_DXOPENSYNCHRONIZATIONOBJECT);
	SET_IOCTL(/*0x2a */ dxgk_query_alloc_residency,
		  LX_DXQUERYALLOCATIONRESIDENCY);
	SET_IOCTL(/*0x2b */ dxgk_query_resource_info,
		  LX_DXQUERYRESOURCEINFO);
	SET_IOCTL(/*0x2c */ dxgk_reclaim_allocations,
		  LX_DXRECLAIMALLOCATIONS2);
	SET_IOCTL(/*0x2d */ dxgk_render,
		  LX_DXRENDER);
	SET_IOCTL(/*0x2e */ dxgk_set_allocation_priority,
		  LX_DXSETALLOCATIONPRIORITY);
	SET_IOCTL(/*0x2f */ dxgk_set_context_process_scheduling_priority,
		  LX_DXSETCONTEXTINPROCESSSCHEDULINGPRIORITY);
	SET_IOCTL(/*0x30 */ dxgk_set_context_scheduling_priority,
		  LX_DXSETCONTEXTSCHEDULINGPRIORITY);
	SET_IOCTL(/*0x31 */ dxgk_signal_sync_object_cpu,
		  LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMCPU);
	SET_IOCTL(/*0x32 */ dxgk_signal_sync_object_gpu,
		  LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMGPU);
	SET_IOCTL(/*0x33 */ dxgk_signal_sync_object_gpu2,
		  LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMGPU2);
	SET_IOCTL(/*0x34 */ dxgk_submit_command_to_hwqueue,
		  LX_DXSUBMITCOMMANDTOHWQUEUE);
	SET_IOCTL(/*0x35 */ dxgk_submit_wait_to_hwqueue,
		  LX_DXSUBMITWAITFORSYNCOBJECTSTOHWQUEUE);
	SET_IOCTL(/*0x36 */ dxgk_submit_signal_to_hwqueue,
		  LX_DXSUBMITSIGNALSYNCOBJECTSTOHWQUEUE);
	SET_IOCTL(/*0x37 */ dxgk_unlock2,
		  LX_DXUNLOCK2);
	SET_IOCTL(/*0x38 */ dxgk_update_alloc_property,
		  LX_DXUPDATEALLOCPROPERTY);
	SET_IOCTL(/*0x39 */ dxgk_update_gpu_va,
		  LX_DXUPDATEGPUVIRTUALADDRESS);
	SET_IOCTL(/*0x3a */ dxgk_wait_sync_object_cpu,
		  LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMCPU);
	SET_IOCTL(/*0x3b */ dxgk_wait_sync_object_gpu,
		  LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMGPU);
	SET_IOCTL(/*0x3c */ dxgk_get_allocation_priority,
		  LX_DXGETALLOCATIONPRIORITY);
	SET_IOCTL(/*0x3d */ dxgk_query_clock_calibration,
		  LX_DXQUERYCLOCKCALIBRATION);
	SET_IOCTL(/*0x3e */ dxgk_enum_adapters3,
		  LX_DXENUMADAPTERS3);
	SET_IOCTL(/*0x3f */ dxgk_share_objects,
		  LX_DXSHAREOBJECTS);
	SET_IOCTL(/*0x40 */ dxgk_open_sync_object_nt,
		  LX_DXOPENSYNCOBJECTFROMNTHANDLE2);
	SET_IOCTL(/*0x41 */ dxgk_query_resource_info_nt,
		  LX_DXQUERYRESOURCEINFOFROMNTHANDLE);
	SET_IOCTL(/*0x42 */ dxgk_open_resource_nt,
		  LX_DXOPENRESOURCEFROMNTHANDLE);
}
