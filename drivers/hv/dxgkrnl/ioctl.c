// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2022, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
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

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk: " fmt

struct ioctl_desc {
	int (*ioctl_callback)(struct dxgprocess *p, void __user *arg);
	u32 ioctl;
	u32 arg_size;
};

#ifdef DEBUG
static char *errorstr(int ret)
{
	return ret < 0 ? "err" : "";
}
#endif

static int dxgsyncobj_release(struct inode *inode, struct file *file)
{
	struct dxgsharedsyncobject *syncobj = file->private_data;

	DXG_TRACE("Release syncobj: %p", syncobj);
	mutex_lock(&syncobj->fd_mutex);
	kref_get(&syncobj->ssyncobj_kref);
	syncobj->host_shared_handle_nt_reference--;
	if (syncobj->host_shared_handle_nt_reference == 0) {
		if (syncobj->host_shared_handle_nt.v) {
			dxgvmb_send_destroy_nt_shared_object(
					syncobj->host_shared_handle_nt);
			DXG_TRACE("Syncobj host_handle_nt destroyed: %x",
				syncobj->host_shared_handle_nt.v);
			syncobj->host_shared_handle_nt.v = 0;
		}
		kref_put(&syncobj->ssyncobj_kref, dxgsharedsyncobj_release);
	}
	mutex_unlock(&syncobj->fd_mutex);
	kref_put(&syncobj->ssyncobj_kref, dxgsharedsyncobj_release);
	return 0;
}

static const struct file_operations dxg_syncobj_fops = {
	.release = dxgsyncobj_release,
};

static int dxgsharedresource_release(struct inode *inode, struct file *file)
{
	struct dxgsharedresource *resource = file->private_data;

	DXG_TRACE("Release resource: %p", resource);
	mutex_lock(&resource->fd_mutex);
	kref_get(&resource->sresource_kref);
	resource->host_shared_handle_nt_reference--;
	if (resource->host_shared_handle_nt_reference == 0) {
		if (resource->host_shared_handle_nt.v) {
			dxgvmb_send_destroy_nt_shared_object(
					resource->host_shared_handle_nt);
			DXG_TRACE("Resource host_handle_nt destroyed: %x",
				resource->host_shared_handle_nt.v);
			resource->host_shared_handle_nt.v = 0;
		}
		kref_put(&resource->sresource_kref, dxgsharedresource_destroy);
	}
	mutex_unlock(&resource->fd_mutex);
	kref_put(&resource->sresource_kref, dxgsharedresource_destroy);
	return 0;
}

static const struct file_operations dxg_resource_fops = {
	.release = dxgsharedresource_release,
};

static int dxgkio_open_adapter_from_luid(struct dxgprocess *process,
						   void *__user inargs)
{
	struct d3dkmt_openadapterfromluid args;
	int ret;
	struct dxgadapter *entry;
	struct dxgadapter *adapter = NULL;
	struct d3dkmt_openadapterfromluid *__user result = inargs;
	struct dxgglobal *dxgglobal = dxggbl();

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("Faled to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	dxgglobal_acquire_adapter_list_lock(DXGLOCK_SHARED);
	dxgglobal_acquire_process_adapter_lock();

	list_for_each_entry(entry, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (dxgadapter_acquire_lock_shared(entry) == 0) {
			if (*(u64 *) &entry->luid ==
			    *(u64 *) &args.adapter_luid) {
				ret = dxgprocess_open_adapter(process, entry,
						&args.adapter_handle);

				if (ret >= 0) {
					ret = copy_to_user(
						&result->adapter_handle,
						&args.adapter_handle,
						sizeof(struct d3dkmthandle));
					if (ret)
						ret = -EINVAL;
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

	if (args.adapter_handle.v == 0)
		ret = -EINVAL;

cleanup:

	if (ret < 0)
		dxgprocess_close_adapter(process, args.adapter_handle);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int dxgkio_query_statistics(struct dxgprocess *process,
				void __user *inargs)
{
	struct d3dkmt_querystatistics *args;
	int ret;
	struct dxgadapter *entry;
	struct dxgadapter *adapter = NULL;
	struct winluid tmp;
	struct dxgglobal *dxgglobal = dxggbl();

	args = vzalloc(sizeof(struct d3dkmt_querystatistics));
	if (args == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = copy_from_user(args, inargs, sizeof(*args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	dxgglobal_acquire_adapter_list_lock(DXGLOCK_SHARED);
	list_for_each_entry(entry, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (dxgadapter_acquire_lock_shared(entry) == 0) {
			if (*(u64 *) &entry->luid ==
			    *(u64 *) &args->adapter_luid) {
				adapter = entry;
				break;
			}
			dxgadapter_release_lock_shared(entry);
		}
	}
	dxgglobal_release_adapter_list_lock(DXGLOCK_SHARED);
	if (adapter) {
		tmp = args->adapter_luid;
		args->adapter_luid = adapter->host_adapter_luid;
		ret = dxgvmb_send_query_statistics(process, adapter, args);
		if (ret >= 0) {
			args->adapter_luid = tmp;
			ret = copy_to_user(inargs, args, sizeof(*args));
			if (ret) {
				DXG_ERR("failed to copy args");
				ret = -EINVAL;
			}
		}
		dxgadapter_release_lock_shared(adapter);
	}

cleanup:
	if (args)
		vfree(args);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkp_enum_adapters(struct dxgprocess *process,
		    union d3dkmt_enumadapters_filter filter,
		    u32 adapter_count_max,
		    struct d3dkmt_adapterinfo *__user info_out,
		    u32 * __user adapter_count_out)
{
	int ret = 0;
	struct dxgadapter *entry;
	struct d3dkmt_adapterinfo *info = NULL;
	struct dxgadapter **adapters = NULL;
	int adapter_count = 0;
	int i;
	struct dxgglobal *dxgglobal = dxggbl();

	if (info_out == NULL || adapter_count_max == 0) {
		ret = copy_to_user(adapter_count_out,
				   &dxgglobal->num_adapters, sizeof(u32));
		if (ret) {
			DXG_ERR("copy_to_user faled");
			ret = -EINVAL;
		}
		goto cleanup;
	}

	if (adapter_count_max > 0xFFFF) {
		DXG_ERR("too many adapters");
		ret = -EINVAL;
		goto cleanup;
	}

	info = vzalloc(sizeof(struct d3dkmt_adapterinfo) * adapter_count_max);
	if (info == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	adapters = vzalloc(sizeof(struct dxgadapter *) * adapter_count_max);
	if (adapters == NULL) {
		ret = -ENOMEM;
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
			if (ret >= 0) {
				inf->adapter_luid = entry->luid;
				adapters[adapter_count] = entry;
				DXG_TRACE("adapter: %x %x:%x",
					inf->adapter_handle.v,
					inf->adapter_luid.b,
					inf->adapter_luid.a);
				adapter_count++;
			}
			dxgadapter_release_lock_shared(entry);
		}
		if (ret < 0)
			break;
	}

	dxgglobal_release_process_adapter_lock();
	dxgglobal_release_adapter_list_lock(DXGLOCK_SHARED);

	if (adapter_count > adapter_count_max) {
		ret = STATUS_BUFFER_TOO_SMALL;
		DXG_TRACE("Too many adapters");
		ret = copy_to_user(adapter_count_out,
				   &dxgglobal->num_adapters, sizeof(u32));
		if (ret) {
			DXG_ERR("copy_to_user failed");
			ret = -EINVAL;
		}
		goto cleanup;
	}

	ret = copy_to_user(adapter_count_out, &adapter_count,
			   sizeof(adapter_count));
	if (ret) {
		DXG_ERR("failed to copy adapter_count");
		ret = -EINVAL;
		goto cleanup;
	}
	ret = copy_to_user(info_out, info, sizeof(info[0]) * adapter_count);
	if (ret) {
		DXG_ERR("failed to copy adapter info");
		ret = -EINVAL;
	}

cleanup:

	if (ret >= 0) {
		DXG_TRACE("found %d adapters", adapter_count);
		goto success;
	}
	if (info) {
		for (i = 0; i < adapter_count; i++)
			dxgprocess_close_adapter(process,
						 info[i].adapter_handle);
	}
success:
	if (info)
		vfree(info);
	if (adapters)
		vfree(adapters);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int dxgsharedresource_seal(struct dxgsharedresource *shared_resource)
{
	int ret = 0;
	int i = 0;
	u8 *private_data;
	u32 data_size;
	struct dxgresource *resource;
	struct dxgallocation *alloc;

	DXG_TRACE("Sealing resource: %p", shared_resource);

	down_write(&shared_resource->adapter->shared_resource_list_lock);
	if (shared_resource->sealed) {
		DXG_TRACE("Resource already sealed");
		goto cleanup;
	}
	shared_resource->sealed = 1;
	if (!list_empty(&shared_resource->resource_list_head)) {
		resource =
		    list_first_entry(&shared_resource->resource_list_head,
				     struct dxgresource,
				     shared_resource_list_entry);
		DXG_TRACE("First resource: %p", resource);
		mutex_lock(&resource->resource_mutex);
		list_for_each_entry(alloc, &resource->alloc_list_head,
				    alloc_list_entry) {
			DXG_TRACE("Resource alloc: %p %d", alloc,
				alloc->priv_drv_data->data_size);
			shared_resource->allocation_count++;
			shared_resource->alloc_private_data_size +=
			    alloc->priv_drv_data->data_size;
			if (shared_resource->alloc_private_data_size <
			    alloc->priv_drv_data->data_size) {
				DXG_ERR("alloc private data overflow");
				ret = -EINVAL;
				goto cleanup1;
			}
		}
		if (shared_resource->alloc_private_data_size == 0) {
			ret = -EINVAL;
			goto cleanup1;
		}
		shared_resource->alloc_private_data =
			vzalloc(shared_resource->alloc_private_data_size);
		if (shared_resource->alloc_private_data == NULL) {
			ret = -EINVAL;
			goto cleanup1;
		}
		shared_resource->alloc_private_data_sizes =
			vzalloc(sizeof(u32)*shared_resource->allocation_count);
		if (shared_resource->alloc_private_data_sizes == NULL) {
			ret = -EINVAL;
			goto cleanup1;
		}
		private_data = shared_resource->alloc_private_data;
		data_size = shared_resource->alloc_private_data_size;
		i = 0;
		list_for_each_entry(alloc, &resource->alloc_list_head,
				    alloc_list_entry) {
			u32 alloc_data_size = alloc->priv_drv_data->data_size;

			if (alloc_data_size) {
				if (data_size < alloc_data_size) {
					DXG_ERR(
						"Invalid private data size");
					ret = -EINVAL;
					goto cleanup1;
				}
				shared_resource->alloc_private_data_sizes[i] =
				    alloc_data_size;
				memcpy(private_data,
				       alloc->priv_drv_data->data,
				       alloc_data_size);
				vfree(alloc->priv_drv_data);
				alloc->priv_drv_data = NULL;
				private_data += alloc_data_size;
				data_size -= alloc_data_size;
			}
			i++;
		}
		if (data_size != 0) {
			DXG_ERR("Data size mismatch");
			ret = -EINVAL;
		}
cleanup1:
		mutex_unlock(&resource->resource_mutex);
	}
cleanup:
	up_write(&shared_resource->adapter->shared_resource_list_lock);
	return ret;
}

static int
dxgkio_enum_adapters(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_enumadapters2 args;
	int ret;
	struct dxgadapter *entry;
	struct d3dkmt_adapterinfo *info = NULL;
	struct dxgadapter **adapters = NULL;
	int adapter_count = 0;
	int i;
	struct dxgglobal *dxgglobal = dxggbl();

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.adapters == NULL) {
		DXG_TRACE("buffer is NULL");
		args.num_adapters = dxgglobal->num_adapters;
		ret = copy_to_user(inargs, &args, sizeof(args));
		if (ret) {
			DXG_ERR("failed to copy args to user");
			ret = -EINVAL;
		}
		goto cleanup;
	}
	if (args.num_adapters < dxgglobal->num_adapters) {
		args.num_adapters = dxgglobal->num_adapters;
		DXG_TRACE("buffer is too small");
		ret = -EOVERFLOW;
		goto cleanup;
	}

	if (args.num_adapters > D3DKMT_ADAPTERS_MAX) {
		DXG_TRACE("too many adapters");
		ret = -EINVAL;
		goto cleanup;
	}

	info = vzalloc(sizeof(struct d3dkmt_adapterinfo) * args.num_adapters);
	if (info == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	adapters = vzalloc(sizeof(struct dxgadapter *) * args.num_adapters);
	if (adapters == NULL) {
		ret = -ENOMEM;
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
			if (ret >= 0) {
				inf->adapter_luid = entry->luid;
				adapters[adapter_count] = entry;
				DXG_TRACE("adapter: %x %llx",
					inf->adapter_handle.v,
					*(u64 *) &inf->adapter_luid);
				adapter_count++;
			}
			dxgadapter_release_lock_shared(entry);
		}
		if (ret < 0)
			break;
	}

	dxgglobal_release_process_adapter_lock();
	dxgglobal_release_adapter_list_lock(DXGLOCK_SHARED);

	args.num_adapters = adapter_count;

	ret = copy_to_user(inargs, &args, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy args to user");
		ret = -EINVAL;
		goto cleanup;
	}
	ret = copy_to_user(args.adapters, info,
			   sizeof(info[0]) * args.num_adapters);
	if (ret) {
		DXG_ERR("failed to copy adapter info to user");
		ret = -EINVAL;
	}

cleanup:

	if (ret < 0) {
		if (info) {
			for (i = 0; i < args.num_adapters; i++) {
				dxgprocess_close_adapter(process,
							info[i].adapter_handle);
			}
		}
	} else {
		DXG_TRACE("found %d adapters", args.num_adapters);
	}

	if (info)
		vfree(info);
	if (adapters)
		vfree(adapters);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_enum_adapters3(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_enumadapters3 args;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgkp_enum_adapters(process, args.filter,
				  args.adapter_count,
				  args.adapters,
				  &((struct d3dkmt_enumadapters3 *)inargs)->
				  adapter_count);

cleanup:

	DXG_TRACE("ioctl: %s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_close_adapter(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmthandle args;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgprocess_close_adapter(process, args);
	if (ret < 0)
		DXG_ERR("failed to close adapter: %d", ret);

cleanup:

	DXG_TRACE("ioctl: %s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_query_adapter_info(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_queryadapterinfo args;
	int ret;
	struct dxgadapter *adapter = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.private_data_size > DXG_MAX_VM_BUS_PACKET_SIZE ||
	    args.private_data_size == 0) {
		DXG_ERR("invalid private data size");
		ret = -EINVAL;
		goto cleanup;
	}

	DXG_TRACE("Type: %d Size: %x", args.type, args.private_data_size);

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0)
		goto cleanup;

	ret = dxgvmb_send_query_adapter_info(process, adapter, &args);

	dxgadapter_release_lock_shared(adapter);

cleanup:

	if (adapter)
		kref_put(&adapter->adapter_kref, dxgadapter_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_create_device(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_createdevice args;
	int ret;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct d3dkmthandle host_device_handle = {};
	bool adapter_locked = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	/* The call acquires reference on the adapter */
	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgdevice_create(adapter, process);
	if (device == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0)
		goto cleanup;

	adapter_locked = true;

	host_device_handle = dxgvmb_send_create_device(adapter, process, &args);
	if (host_device_handle.v) {
		ret = copy_to_user(&((struct d3dkmt_createdevice *)inargs)->
				   device, &host_device_handle,
				   sizeof(struct d3dkmthandle));
		if (ret) {
			DXG_ERR("failed to copy device handle");
			ret = -EINVAL;
			goto cleanup;
		}

		hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
		ret = hmgrtable_assign_handle(&process->handle_table, device,
					      HMGRENTRY_TYPE_DXGDEVICE,
					      host_device_handle);
		if (ret >= 0) {
			device->handle = host_device_handle;
			device->handle_valid = 1;
			device->object_state = DXGOBJECTSTATE_ACTIVE;
		}
		hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
	}

cleanup:

	if (ret < 0) {
		if (host_device_handle.v)
			dxgvmb_send_destroy_device(adapter, process,
						   host_device_handle);
		if (device)
			dxgdevice_destroy(device);
	}

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);

	if (adapter)
		kref_put(&adapter->adapter_kref, dxgadapter_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_destroy_device(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_destroydevice args;
	int ret;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

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
		DXG_ERR("invalid device handle: %x", args.device.v);
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;

	dxgdevice_destroy(device);

	if (dxgadapter_acquire_lock_shared(adapter) == 0) {
		dxgvmb_send_destroy_device(adapter, process, args.device);
		dxgadapter_release_lock_shared(adapter);
	}

cleanup:

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_create_context_virtual(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_createcontextvirtual args;
	int ret;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct dxgcontext *context = NULL;
	struct d3dkmthandle host_context_handle = {};
	bool device_lock_acquired = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0)
		goto cleanup;

	device_lock_acquired = true;

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	context = dxgcontext_create(device);
	if (context == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	host_context_handle = dxgvmb_send_create_context(adapter,
							 process, &args);
	if (host_context_handle.v) {
		hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
		ret = hmgrtable_assign_handle(&process->handle_table, context,
					      HMGRENTRY_TYPE_DXGCONTEXT,
					      host_context_handle);
		if (ret >= 0)
			context->handle = host_context_handle;
		hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
		if (ret < 0)
			goto cleanup;
		ret = copy_to_user(&((struct d3dkmt_createcontextvirtual *)
				   inargs)->context, &host_context_handle,
				   sizeof(struct d3dkmthandle));
		if (ret) {
			DXG_ERR("failed to copy context handle");
			ret = -EINVAL;
		}
	} else {
		DXG_ERR("invalid host handle");
		ret = -EINVAL;
	}

cleanup:

	if (ret < 0) {
		if (host_context_handle.v) {
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
		kref_put(&device->device_kref, dxgdevice_release);
	}

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_destroy_context(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_destroycontext args;
	int ret;
	struct dxgadapter *adapter = NULL;
	struct dxgcontext *context = NULL;
	struct dxgdevice *device = NULL;
	struct d3dkmthandle device_handle = {};

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	context = hmgrtable_get_object_by_type(&process->handle_table,
					       HMGRENTRY_TYPE_DXGCONTEXT,
					       args.context);
	if (context) {
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGCONTEXT, args.context);
		context->handle.v = 0;
		device_handle = context->device_handle;
		context->object_state = DXGOBJECTSTATE_DESTROYED;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (context == NULL) {
		DXG_ERR("invalid context handle: %x", args.context.v);
		ret = -EINVAL;
		goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, device_handle);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_destroy_context(adapter, process, args.context);

	dxgcontext_destroy_safe(process, context);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %s %d", errorstr(ret), __func__, ret);
	return ret;
}

static int
dxgkio_create_hwqueue(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_createhwqueue args;
	struct dxgdevice *device = NULL;
	struct dxgcontext *context = NULL;
	struct dxgadapter *adapter = NULL;
	struct dxghwqueue *hwqueue = NULL;
	int ret;
	bool device_lock_acquired = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.context);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0)
		goto cleanup;

	device_lock_acquired = true;

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	context = hmgrtable_get_object_by_type(&process->handle_table,
					       HMGRENTRY_TYPE_DXGCONTEXT,
					       args.context);
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);

	if (context == NULL) {
		DXG_ERR("Invalid context handle %x", args.context.v);
		ret = -EINVAL;
		goto cleanup;
	}

	hwqueue = dxghwqueue_create(context);
	if (hwqueue == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_create_hwqueue(process, adapter, &args,
					 inargs, hwqueue);

cleanup:

	if (ret < 0 && hwqueue)
		dxghwqueue_destroy(process, hwqueue);

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device_lock_acquired)
		dxgdevice_release_lock_shared(device);

	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int dxgkio_destroy_hwqueue(struct dxgprocess *process,
					    void *__user inargs)
{
	struct d3dkmt_destroyhwqueue args;
	int ret;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct dxghwqueue *hwqueue = NULL;
	struct d3dkmthandle device_handle = {};

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	hwqueue = hmgrtable_get_object_by_type(&process->handle_table,
					       HMGRENTRY_TYPE_DXGHWQUEUE,
					       args.queue);
	if (hwqueue) {
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGHWQUEUE, args.queue);
		hwqueue->handle.v = 0;
		device_handle = hwqueue->device_handle;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (hwqueue == NULL) {
		DXG_ERR("invalid hwqueue handle: %x", args.queue.v);
		ret = -EINVAL;
		goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, device_handle);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_destroy_hwqueue(process, adapter, args.queue);

	dxghwqueue_destroy(process, hwqueue);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_create_paging_queue(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_createpagingqueue args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct dxgpagingqueue *pqueue = NULL;
	int ret;
	struct d3dkmthandle host_handle = {};
	bool device_lock_acquired = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0)
		goto cleanup;

	device_lock_acquired = true;
	adapter = device->adapter;

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	pqueue = dxgpagingqueue_create(device);
	if (pqueue == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = dxgvmb_send_create_paging_queue(process, device, &args, pqueue);
	if (ret >= 0) {
		host_handle = args.paging_queue;

		ret = copy_to_user(inargs, &args, sizeof(args));
		if (ret) {
			DXG_ERR("failed to copy input args");
			ret = -EINVAL;
			goto cleanup;
		}

		hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
		ret = hmgrtable_assign_handle(&process->handle_table, pqueue,
					      HMGRENTRY_TYPE_DXGPAGINGQUEUE,
					      host_handle);
		if (ret >= 0) {
			pqueue->handle = host_handle;
			ret = hmgrtable_assign_handle(&process->handle_table,
						NULL,
						HMGRENTRY_TYPE_MONITOREDFENCE,
						args.sync_object);
			if (ret >= 0)
				pqueue->syncobj_handle = args.sync_object;
		}
		hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
		/* should not fail after this */
	}

cleanup:

	if (ret < 0) {
		if (pqueue)
			dxgpagingqueue_destroy(pqueue);
		if (host_handle.v)
			dxgvmb_send_destroy_paging_queue(process,
							 adapter,
							 host_handle);
	}

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device) {
		if (device_lock_acquired)
			dxgdevice_release_lock_shared(device);
		kref_put(&device->device_kref, dxgdevice_release);
	}

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_destroy_paging_queue(struct dxgprocess *process, void *__user inargs)
{
	struct d3dddi_destroypagingqueue args;
	struct dxgpagingqueue *paging_queue = NULL;
	int ret;
	struct d3dkmthandle device_handle = {};
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

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
		paging_queue->syncobj_handle.v = 0;
		paging_queue->handle.v = 0;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	if (device_handle.v)
		device = dxgprocess_device_by_handle(process, device_handle);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0) {
		kref_put(&device->device_kref, dxgdevice_release);
		device = NULL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_destroy_paging_queue(process, adapter,
					       args.paging_queue);

	dxgpagingqueue_destroy(paging_queue);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device) {
		dxgdevice_release_lock_shared(device);
		kref_put(&device->device_kref, dxgdevice_release);
	}

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
get_standard_alloc_priv_data(struct dxgdevice *device,
			     struct d3dkmt_createstandardallocation *alloc_info,
			     u32 *standard_alloc_priv_data_size,
			     void **standard_alloc_priv_data,
			     u32 *standard_res_priv_data_size,
			     void **standard_res_priv_data)
{
	int ret;
	struct d3dkmdt_gdisurfacedata gdi_data = { };
	u32 priv_data_size = 0;
	u32 res_priv_data_size = 0;
	void *priv_data = NULL;
	void *res_priv_data = NULL;

	gdi_data.type = _D3DKMDT_GDISURFACE_TEXTURE_CROSSADAPTER;
	gdi_data.width = alloc_info->existing_heap_data.size;
	gdi_data.height = 1;
	gdi_data.format = _D3DDDIFMT_UNKNOWN;

	*standard_alloc_priv_data_size = 0;
	ret = dxgvmb_send_get_stdalloc_data(device,
					_D3DKMDT_STANDARDALLOCATION_GDISURFACE,
					&gdi_data, 0,
					&priv_data_size, NULL,
					&res_priv_data_size,
					NULL);
	if (ret < 0)
		goto cleanup;
	DXG_TRACE("Priv data size: %d", priv_data_size);
	if (priv_data_size == 0) {
		ret = -EINVAL;
		goto cleanup;
	}
	priv_data = vzalloc(priv_data_size);
	if (priv_data == NULL) {
		ret = -ENOMEM;
		DXG_ERR("failed to allocate memory for priv data: %d",
			priv_data_size);
		goto cleanup;
	}
	if (res_priv_data_size) {
		res_priv_data = vzalloc(res_priv_data_size);
		if (res_priv_data == NULL) {
			ret = -ENOMEM;
			DXG_ERR(
				"failed to alloc memory for res priv data: %d",
				res_priv_data_size);
			goto cleanup;
		}
	}
	ret = dxgvmb_send_get_stdalloc_data(device,
					_D3DKMDT_STANDARDALLOCATION_GDISURFACE,
					&gdi_data, 0,
					&priv_data_size,
					priv_data,
					&res_priv_data_size,
					res_priv_data);
	if (ret < 0)
		goto cleanup;
	*standard_alloc_priv_data_size = priv_data_size;
	*standard_alloc_priv_data = priv_data;
	*standard_res_priv_data_size = res_priv_data_size;
	*standard_res_priv_data = res_priv_data;
	priv_data = NULL;
	res_priv_data = NULL;

cleanup:
	if (priv_data)
		vfree(priv_data);
	if (res_priv_data)
		vfree(res_priv_data);
	if (ret)
		DXG_TRACE("err: %d", ret);
	return ret;
}

static int
dxgkio_create_allocation(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_createallocation args;
	int ret;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct d3dddi_allocationinfo2 *alloc_info = NULL;
	struct d3dkmt_createstandardallocation standard_alloc;
	u32 alloc_info_size = 0;
	struct dxgresource *resource = NULL;
	struct dxgallocation **dxgalloc = NULL;
	struct dxgsharedresource *shared_resource = NULL;
	bool resource_mutex_acquired = false;
	u32 standard_alloc_priv_data_size = 0;
	void *standard_alloc_priv_data = NULL;
	u32 res_priv_data_size = 0;
	void *res_priv_data = NULL;
	int i;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.alloc_count > D3DKMT_CREATEALLOCATION_MAX ||
	    args.alloc_count == 0) {
		DXG_ERR("invalid number of allocations to create");
		ret = -EINVAL;
		goto cleanup;
	}

	alloc_info_size = sizeof(struct d3dddi_allocationinfo2) *
	    args.alloc_count;
	alloc_info = vzalloc(alloc_info_size);
	if (alloc_info == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}
	ret = copy_from_user(alloc_info, args.allocation_info,
				 alloc_info_size);
	if (ret) {
		DXG_ERR("failed to copy alloc info");
		ret = -EINVAL;
		goto cleanup;
	}

	for (i = 0; i < args.alloc_count; i++) {
		if (args.flags.standard_allocation) {
			if (alloc_info[i].priv_drv_data_size != 0) {
				DXG_ERR("private data size not zero");
				ret = -EINVAL;
				goto cleanup;
			}
		}
		if (alloc_info[i].priv_drv_data_size >=
		    DXG_MAX_VM_BUS_PACKET_SIZE) {
			DXG_ERR("private data size too big: %d %d %ld",
				i, alloc_info[i].priv_drv_data_size,
				sizeof(alloc_info[0]));
			ret = -EINVAL;
			goto cleanup;
		}
	}

	if (args.flags.existing_section || args.flags.create_protected) {
		DXG_ERR("invalid allocation flags");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.flags.standard_allocation) {
		if (args.standard_allocation == NULL) {
			DXG_ERR("invalid standard allocation");
			ret = -EINVAL;
			goto cleanup;
		}
		ret = copy_from_user(&standard_alloc,
				     args.standard_allocation,
				     sizeof(standard_alloc));
		if (ret) {
			DXG_ERR("failed to copy std alloc data");
			ret = -EINVAL;
			goto cleanup;
		}
		if (standard_alloc.type ==
		    _D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP) {
			if (alloc_info[0].sysmem == NULL ||
			   (unsigned long)alloc_info[0].sysmem &
			   (PAGE_SIZE - 1)) {
				DXG_ERR("invalid sysmem pointer");
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup;
			}
			if (!args.flags.existing_sysmem) {
				DXG_ERR("expect existing_sysmem flag");
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup;
			}
		} else if (standard_alloc.type ==
		    _D3DKMT_STANDARDALLOCATIONTYPE_CROSSADAPTER) {
			if (args.flags.existing_sysmem) {
				DXG_ERR("existing_sysmem flag invalid");
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup;

			}
			if (alloc_info[0].sysmem != NULL) {
				DXG_ERR("sysmem should be NULL");
				ret = STATUS_INVALID_PARAMETER;
				goto cleanup;
			}
		} else {
			DXG_ERR("invalid standard allocation type");
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}

		if (args.priv_drv_data_size != 0 ||
		    args.alloc_count != 1 ||
		    standard_alloc.existing_heap_data.size == 0 ||
		    standard_alloc.existing_heap_data.size & (PAGE_SIZE - 1)) {
			DXG_ERR("invalid standard allocation");
			ret = -EINVAL;
			goto cleanup;
		}
		args.priv_drv_data_size =
		    sizeof(struct d3dkmt_createstandardallocation);
	}

	if (args.flags.create_shared && !args.flags.create_resource) {
		DXG_ERR("create_resource must be set for create_shared");
		ret = -EINVAL;
		goto cleanup;
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0) {
		kref_put(&device->device_kref, dxgdevice_release);
		device = NULL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	if (args.flags.standard_allocation) {
		ret = get_standard_alloc_priv_data(device,
						&standard_alloc,
						&standard_alloc_priv_data_size,
						&standard_alloc_priv_data,
						&res_priv_data_size,
						&res_priv_data);
		if (ret < 0)
			goto cleanup;
		DXG_TRACE("Alloc private data: %d",
			standard_alloc_priv_data_size);
	}

	if (args.flags.create_resource) {
		resource = dxgresource_create(device);
		if (resource == NULL) {
			ret = -ENOMEM;
			goto cleanup;
		}
		resource->private_runtime_handle =
		    args.private_runtime_resource_handle;
		if (args.flags.create_shared) {
			if (!args.flags.nt_security_sharing) {
				DXG_ERR(
					"nt_security_sharing must be set");
				ret = -EINVAL;
				goto cleanup;
			}
			shared_resource = dxgsharedresource_create(adapter);
			if (shared_resource == NULL) {
				ret = -ENOMEM;
				goto cleanup;
			}
			shared_resource->runtime_private_data_size =
			    args.priv_drv_data_size;
			shared_resource->resource_private_data_size =
			    args.priv_drv_data_size;

			shared_resource->runtime_private_data_size =
			    args.private_runtime_data_size;
			shared_resource->resource_private_data_size =
			    args.priv_drv_data_size;
			dxgsharedresource_add_resource(shared_resource,
						       resource);
			if (args.flags.standard_allocation) {
				shared_resource->resource_private_data =
					res_priv_data;
				shared_resource->resource_private_data_size =
					res_priv_data_size;
				res_priv_data = NULL;
			}
			if (args.private_runtime_data_size) {
				shared_resource->runtime_private_data =
				    vzalloc(args.private_runtime_data_size);
				if (shared_resource->runtime_private_data ==
				    NULL) {
					ret = -ENOMEM;
					goto cleanup;
				}
				ret = copy_from_user(
					shared_resource->runtime_private_data,
					args.private_runtime_data,
					args.private_runtime_data_size);
				if (ret) {
					DXG_ERR(
						"failed to copy runtime data");
					ret = -EINVAL;
					goto cleanup;
				}
			}
			if (args.priv_drv_data_size &&
			    !args.flags.standard_allocation) {
				shared_resource->resource_private_data =
				    vzalloc(args.priv_drv_data_size);
				if (shared_resource->resource_private_data ==
				    NULL) {
					ret = -ENOMEM;
					goto cleanup;
				}
				ret = copy_from_user(
					shared_resource->resource_private_data,
					args.priv_drv_data,
					args.priv_drv_data_size);
				if (ret) {
					DXG_ERR(
						"failed to copy res data");
					ret = -EINVAL;
					goto cleanup;
				}
			}
		}
	} else {
		if (args.resource.v) {
			/* Adding new allocations to the given resource */

			dxgprocess_ht_lock_shared_down(process);
			resource = hmgrtable_get_object_by_type(
				&process->handle_table,
				HMGRENTRY_TYPE_DXGRESOURCE,
				args.resource);
			kref_get(&resource->resource_kref);
			dxgprocess_ht_lock_shared_up(process);

			if (resource == NULL || resource->device != device) {
				DXG_ERR("invalid resource handle %x",
					args.resource.v);
				ret = -EINVAL;
				goto cleanup;
			}
			if (resource->shared_owner &&
			    resource->shared_owner->sealed) {
				DXG_ERR("Resource is sealed");
				ret = -EINVAL;
				goto cleanup;
			}
			/* Synchronize with resource destruction */
			mutex_lock(&resource->resource_mutex);
			if (!dxgresource_is_active(resource)) {
				mutex_unlock(&resource->resource_mutex);
				ret = -EINVAL;
				goto cleanup;
			}
			resource_mutex_acquired = true;
		}
	}

	dxgalloc = vzalloc(sizeof(struct dxgallocation *) * args.alloc_count);
	if (dxgalloc == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	for (i = 0; i < args.alloc_count; i++) {
		struct dxgallocation *alloc;
		u32 priv_data_size;

		if (args.flags.standard_allocation)
			priv_data_size = standard_alloc_priv_data_size;
		else
			priv_data_size = alloc_info[i].priv_drv_data_size;

		if (alloc_info[i].sysmem && !args.flags.standard_allocation) {
			if ((unsigned long)
			    alloc_info[i].sysmem & (PAGE_SIZE - 1)) {
				DXG_ERR("invalid sysmem alloc %d, %p",
					i, alloc_info[i].sysmem);
				ret = -EINVAL;
				goto cleanup;
			}
		}
		if ((alloc_info[0].sysmem == NULL) !=
		    (alloc_info[i].sysmem == NULL)) {
			DXG_ERR("All allocs must have sysmem pointer");
			ret = -EINVAL;
			goto cleanup;
		}

		dxgalloc[i] = dxgallocation_create(process);
		if (dxgalloc[i] == NULL) {
			ret = -ENOMEM;
			goto cleanup;
		}
		alloc = dxgalloc[i];

		if (resource) {
			ret = dxgresource_add_alloc(resource, alloc);
			if (ret < 0)
				goto cleanup;
		} else {
			dxgdevice_add_alloc(device, alloc);
		}
		if (args.flags.create_shared) {
			/* Remember alloc private data to use it during open */
			alloc->priv_drv_data = vzalloc(priv_data_size +
					offsetof(struct privdata, data));
			if (alloc->priv_drv_data == NULL) {
				ret = -ENOMEM;
				goto cleanup;
			}
			if (args.flags.standard_allocation) {
				memcpy(alloc->priv_drv_data->data,
				       standard_alloc_priv_data,
				       priv_data_size);
			} else {
				ret = copy_from_user(
					alloc->priv_drv_data->data,
					alloc_info[i].priv_drv_data,
					priv_data_size);
				if (ret) {
					DXG_ERR(
						"failed to copy priv data");
					ret = -EFAULT;
					goto cleanup;
				}
			}
			alloc->priv_drv_data->data_size = priv_data_size;
		}
	}

	ret = dxgvmb_send_create_allocation(process, device, &args, inargs,
					    resource, dxgalloc, alloc_info,
					    &standard_alloc);
cleanup:

	if (resource_mutex_acquired) {
		mutex_unlock(&resource->resource_mutex);
		kref_put(&resource->resource_kref, dxgresource_release);
	}
	if (ret < 0) {
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
		kref_put(&shared_resource->sresource_kref,
			 dxgsharedresource_destroy);
	if (dxgalloc)
		vfree(dxgalloc);
	if (standard_alloc_priv_data)
		vfree(standard_alloc_priv_data);
	if (res_priv_data)
		vfree(res_priv_data);
	if (alloc_info)
		vfree(alloc_info);

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device) {
		dxgdevice_release_lock_shared(device);
		kref_put(&device->device_kref, dxgdevice_release);
	}

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int validate_alloc(struct dxgallocation *alloc0,
			  struct dxgallocation *alloc,
			  struct dxgdevice *device,
			  struct d3dkmthandle alloc_handle)
{
	u32 fail_reason;

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
	DXG_ERR("Alloc validation failed: reason: %d %x",
		fail_reason, alloc_handle.v);
	return -EINVAL;
}

static int
dxgkio_destroy_allocation(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_destroyallocation2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret;
	struct d3dkmthandle *alloc_handles = NULL;
	struct dxgallocation **allocs = NULL;
	struct dxgresource *resource = NULL;
	int i;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.alloc_count > D3DKMT_CREATEALLOCATION_MAX ||
	    ((args.alloc_count == 0) == (args.resource.v == 0))) {
		DXG_ERR("invalid number of allocations");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.alloc_count) {
		u32 handle_size = sizeof(struct d3dkmthandle) *
				   args.alloc_count;

		alloc_handles = vzalloc(handle_size);
		if (alloc_handles == NULL) {
			ret = -ENOMEM;
			goto cleanup;
		}
		allocs = vzalloc(sizeof(struct dxgallocation *) *
				 args.alloc_count);
		if (allocs == NULL) {
			ret = -ENOMEM;
			goto cleanup;
		}
		ret = copy_from_user(alloc_handles, args.allocations,
					 handle_size);
		if (ret) {
			DXG_ERR("failed to copy alloc handles");
			ret = -EINVAL;
			goto cleanup;
		}
	}

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	/* Acquire the device lock to synchronize with the device destriction */
	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0) {
		kref_put(&device->device_kref, dxgdevice_release);
		device = NULL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	/*
	 * Destroy the local allocation handles first. If the host handle
	 * is destroyed first, another object could be assigned to the process
	 * table at the same place as the allocation handle and it will fail.
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
			if (ret < 0) {
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
			DXG_ERR("Invalid resource handle: %x",
				args.resource.v);
			ret = -EINVAL;
		} else if (resource->device != device) {
			DXG_ERR("Resource belongs to wrong device: %x",
				args.resource.v);
			ret = -EINVAL;
		} else {
			hmgrtable_free_handle(&process->handle_table,
					      HMGRENTRY_TYPE_DXGRESOURCE,
					      args.resource);
			resource->object_state = DXGOBJECTSTATE_DESTROYED;
			resource->handle.v = 0;
			resource->handle_valid = 0;
		}
		dxgprocess_ht_lock_exclusive_up(process);

		if (ret < 0)
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
		kref_get(&resource->resource_kref);
		mutex_lock(&resource->resource_mutex);
	}

	ret = dxgvmb_send_destroy_allocation(process, device, &args,
					     alloc_handles);

	/*
	 * Destroy the allocations after the host destroyed it.
	 * The allocation gpadl teardown will wait until the host unmaps its
	 * gpadl.
	 */
	dxgdevice_acquire_alloc_list_lock(device);
	if (args.alloc_count) {
		for (i = 0; i < args.alloc_count; i++) {
			if (allocs[i]) {
				allocs[i]->alloc_handle.v = 0;
				dxgallocation_destroy(allocs[i]);
			}
		}
	} else {
		dxgresource_destroy(resource);
	}
	dxgdevice_release_alloc_list_lock(device);

	if (resource) {
		mutex_unlock(&resource->resource_mutex);
		kref_put(&resource->resource_kref, dxgresource_release);
	}

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device) {
		dxgdevice_release_lock_shared(device);
		kref_put(&device->device_kref, dxgdevice_release);
	}

	if (alloc_handles)
		vfree(alloc_handles);

	if (allocs)
		vfree(allocs);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_offer_allocations(struct dxgprocess *process, void *__user inargs)
{
	int ret;
	struct d3dkmt_offerallocations args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.allocation_count > D3DKMT_MAKERESIDENT_ALLOC_MAX ||
	    args.allocation_count == 0) {
		DXG_ERR("invalid number of allocations");
		ret = -EINVAL;
		goto cleanup;
	}

	if ((args.resources == NULL) == (args.allocations == NULL)) {
		DXG_ERR("invalid pointer to resources/allocations");
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_offer_allocations(process, adapter, &args);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_reclaim_allocations(struct dxgprocess *process, void *__user inargs)
{
	int ret;
	struct d3dkmt_reclaimallocations2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct d3dkmt_reclaimallocations2 * __user in_args = inargs;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.allocation_count > D3DKMT_MAKERESIDENT_ALLOC_MAX ||
	    args.allocation_count == 0) {
		DXG_ERR("invalid number of allocations");
		ret = -EINVAL;
		goto cleanup;
	}

	if ((args.resources == NULL) == (args.allocations == NULL)) {
		DXG_ERR("invalid pointer to resources/allocations");
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						HMGRENTRY_TYPE_DXGPAGINGQUEUE,
						args.paging_queue);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_reclaim_allocations(process, adapter,
					      device->handle, &args,
					      &in_args->paging_fence_value);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_submit_command(struct dxgprocess *process, void *__user inargs)
{
	int ret;
	struct d3dkmt_submitcommand args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.broadcast_context_count > D3DDDI_MAX_BROADCAST_CONTEXT ||
	    args.broadcast_context_count == 0) {
		DXG_ERR("invalid number of contexts");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.priv_drv_data_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		DXG_ERR("invalid private data size");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.num_history_buffers > 1024) {
		DXG_ERR("invalid number of history buffers");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.num_primaries > DXG_MAX_VM_BUS_PACKET_SIZE) {
		DXG_ERR("invalid number of primaries");
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.broadcast_context[0]);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_submit_command(process, adapter, &args);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_submit_command_to_hwqueue(struct dxgprocess *process, void *__user inargs)
{
	int ret;
	struct d3dkmt_submitcommandtohwqueue args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.priv_drv_data_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		DXG_ERR("invalid private data size");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.num_primaries > DXG_MAX_VM_BUS_PACKET_SIZE) {
		DXG_ERR("invalid number of primaries");
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGHWQUEUE,
						    args.hwqueue);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_submit_command_hwqueue(process, adapter, &args);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_submit_signal_to_hwqueue(struct dxgprocess *process, void *__user inargs)
{
	int ret;
	struct d3dkmt_submitsignalsyncobjectstohwqueue args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct d3dkmthandle hwqueue = {};

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.hwqueue_count > D3DDDI_MAX_BROADCAST_CONTEXT ||
	    args.hwqueue_count == 0) {
		DXG_ERR("invalid hwqueue count: %d",
			args.hwqueue_count);
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.object_count > D3DDDI_MAX_OBJECT_SIGNALED ||
	    args.object_count == 0) {
		DXG_ERR("invalid number of syncobjects: %d",
			args.object_count);
		ret = -EINVAL;
		goto cleanup;
	}

	ret = copy_from_user(&hwqueue, args.hwqueues,
			     sizeof(struct d3dkmthandle));
	if (ret) {
		DXG_ERR("failed to copy hwqueue handle");
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGHWQUEUE,
						    hwqueue);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, adapter,
					     args.flags, 0, zerohandle,
					     args.object_count, args.objects,
					     args.hwqueue_count, args.hwqueues,
					     args.object_count,
					     args.fence_values, NULL,
					     zerohandle);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_submit_wait_to_hwqueue(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_submitwaitforsyncobjectstohwqueue args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret;
	struct d3dkmthandle *objects = NULL;
	u32 object_size;
	u64 *fences = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.object_count > D3DDDI_MAX_OBJECT_WAITED_ON ||
	    args.object_count == 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	object_size = sizeof(struct d3dkmthandle) * args.object_count;
	objects = vzalloc(object_size);
	if (objects == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}
	ret = copy_from_user(objects, args.objects, object_size);
	if (ret) {
		DXG_ERR("failed to copy objects");
		ret = -EINVAL;
		goto cleanup;
	}

	object_size = sizeof(u64) * args.object_count;
	fences = vzalloc(object_size);
	if (fences == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}
	ret = copy_from_user(fences, args.fence_values, object_size);
	if (ret) {
		DXG_ERR("failed to copy fence values");
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGHWQUEUE,
						    args.hwqueue);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_wait_sync_object_gpu(process, adapter,
					       args.hwqueue, args.object_count,
					       objects, fences, false);

cleanup:

	if (objects)
		vfree(objects);
	if (fences)
		vfree(fences);
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_create_sync_object(struct dxgprocess *process, void *__user inargs)
{
	int ret;
	struct d3dkmt_createsynchronizationobject2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct eventfd_ctx *event = NULL;
	struct dxgsyncobject *syncobj = NULL;
	bool device_lock_acquired = false;
	struct dxgsharedsyncobject *syncobjgbl = NULL;
	struct dxghosteventcpu *host_event = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0)
		goto cleanup;

	device_lock_acquired = true;

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	syncobj = dxgsyncobject_create(process, device, adapter, args.info.type,
				       args.info.flags);
	if (syncobj == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.info.type == _D3DDDI_CPU_NOTIFICATION) {
		event = eventfd_ctx_fdget((int)
					  args.info.cpu_notification.event);
		if (IS_ERR(event)) {
			DXG_ERR("failed to reference the event");
			event = NULL;
			ret = -EINVAL;
			goto cleanup;
		}
		host_event = syncobj->host_event;
		host_event->hdr.event_id = dxgglobal_new_host_event_id();
		host_event->cpu_event = event;
		host_event->remove_from_list = false;
		host_event->destroy_after_signal = false;
		host_event->hdr.event_type = dxghostevent_cpu_event;
		dxgglobal_add_host_event(&host_event->hdr);
		args.info.cpu_notification.event = host_event->hdr.event_id;
		DXG_TRACE("creating CPU notification event: %lld",
			args.info.cpu_notification.event);
	}

	ret = dxgvmb_send_create_sync_object(process, adapter, &args, syncobj);
	if (ret < 0)
		goto cleanup;

	if (args.info.flags.shared) {
		if (args.info.shared_handle.v == 0) {
			DXG_ERR("shared handle should not be 0");
			ret = -EINVAL;
			goto cleanup;
		}
		syncobjgbl = dxgsharedsyncobj_create(device->adapter, syncobj);
		if (syncobjgbl == NULL) {
			ret = -ENOMEM;
			goto cleanup;
		}
		dxgsharedsyncobj_add_syncobj(syncobjgbl, syncobj);

		syncobjgbl->host_shared_handle = args.info.shared_handle;
	}

	ret = copy_to_user(inargs, &args, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy output args");
		ret = -EINVAL;
		goto cleanup;
	}

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	ret = hmgrtable_assign_handle(&process->handle_table, syncobj,
				      HMGRENTRY_TYPE_DXGSYNCOBJECT,
				      args.sync_object);
	if (ret >= 0)
		syncobj->handle = args.sync_object;
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

cleanup:

	if (ret < 0) {
		if (syncobj) {
			dxgsyncobject_destroy(process, syncobj);
			if (args.sync_object.v)
				dxgvmb_send_destroy_sync_object(process,
							args.sync_object);
			event = NULL;
		}
		if (event)
			eventfd_ctx_put(event);
	}
	if (syncobjgbl)
		kref_put(&syncobjgbl->ssyncobj_kref, dxgsharedsyncobj_release);
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device_lock_acquired)
		dxgdevice_release_lock_shared(device);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_destroy_sync_object(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_destroysynchronizationobject args;
	struct dxgsyncobject *syncobj = NULL;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	DXG_TRACE("handle 0x%x", args.sync_object.v);
	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	syncobj = hmgrtable_get_object_by_type(&process->handle_table,
					       HMGRENTRY_TYPE_DXGSYNCOBJECT,
					       args.sync_object);
	if (syncobj) {
		DXG_TRACE("syncobj 0x%p", syncobj);
		syncobj->handle.v = 0;
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGSYNCOBJECT,
				      args.sync_object);
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (syncobj == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	dxgsyncobject_destroy(process, syncobj);

	ret = dxgvmb_send_destroy_sync_object(process, args.sync_object);

cleanup:

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_open_sync_object_nt(struct dxgprocess *process, void *__user inargs)
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
	struct dxgglobal *dxgglobal = dxggbl();

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	args.sync_object.v = 0;

	if (args.device.v) {
		device = dxgprocess_device_by_handle(process, args.device);
		if (device == NULL) {
			return -EINVAL;
			goto cleanup;
		}
	} else {
		DXG_ERR("device handle is missing");
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0)
		goto cleanup;

	device_lock_acquired = true;

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	file = fget(args.nt_handle);
	if (!file) {
		DXG_ERR("failed to get file from handle: %llx",
			args.nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}

	if (file->f_op != &dxg_syncobj_fops) {
		DXG_ERR("invalid fd: %llx", args.nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}

	syncobj_fd = file->private_data;
	if (syncobj_fd == NULL) {
		DXG_ERR("invalid private data: %llx", args.nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}

	flags.shared = 1;
	flags.nt_security_sharing = 1;
	syncobj = dxgsyncobject_create(process, device, adapter,
				       syncobj_fd->type, flags);
	if (syncobj == NULL) {
		DXG_ERR("failed to create sync object");
		ret = -ENOMEM;
		goto cleanup;
	}

	dxgsharedsyncobj_add_syncobj(syncobj_fd, syncobj);

	ret = dxgvmb_send_open_sync_object_nt(process, &dxgglobal->channel,
					      &args, syncobj);
	if (ret < 0) {
		DXG_ERR("failed to open sync object on host: %x",
			syncobj_fd->host_shared_handle.v);
		goto cleanup;
	}

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	ret = hmgrtable_assign_handle(&process->handle_table, syncobj,
				      HMGRENTRY_TYPE_DXGSYNCOBJECT,
				      args.sync_object);
	if (ret >= 0) {
		syncobj->handle = args.sync_object;
		kref_get(&syncobj->syncobj_kref);
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (ret < 0)
		goto cleanup;

	ret = copy_to_user(inargs, &args, sizeof(args));
	if (ret == 0)
		goto success;
	DXG_ERR("failed to copy output args");
	ret = -EINVAL;

cleanup:

	if (syncobj) {
		dxgsyncobject_destroy(process, syncobj);
		syncobj = NULL;
	}

	if (args.sync_object.v)
		dxgvmb_send_destroy_sync_object(process, args.sync_object);

success:

	if (file)
		fput(file);
	if (syncobj)
		kref_put(&syncobj->syncobj_kref, dxgsyncobject_release);
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device_lock_acquired)
		dxgdevice_release_lock_shared(device);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_signal_sync_object(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_signalsynchronizationobject2 args;
	struct d3dkmt_signalsynchronizationobject2 *__user in_args = inargs;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret;
	u32 fence_count = 1;
	struct eventfd_ctx *event = NULL;
	struct dxghosteventcpu *host_event = NULL;
	bool host_event_added = false;
	u64 host_event_id = 0;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.context_count >= D3DDDI_MAX_BROADCAST_CONTEXT ||
	    args.object_count > D3DDDI_MAX_OBJECT_SIGNALED) {
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.flags.enqueue_cpu_event) {
		host_event = kzalloc(sizeof(*host_event), GFP_KERNEL);
		if (host_event == NULL) {
			ret = -ENOMEM;
			goto cleanup;
		}
		host_event->process = process;
		event = eventfd_ctx_fdget((int)args.cpu_event_handle);
		if (IS_ERR(event)) {
			DXG_ERR("failed to reference the event");
			event = NULL;
			ret = -EINVAL;
			goto cleanup;
		}
		fence_count = 0;
		host_event->cpu_event = event;
		host_event_id = dxgglobal_new_host_event_id();
		host_event->hdr.event_type = dxghostevent_cpu_event;
		host_event->hdr.event_id = host_event_id;
		host_event->remove_from_list = true;
		host_event->destroy_after_signal = true;
		dxgglobal_add_host_event(&host_event->hdr);
		host_event_added = true;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.context);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, adapter,
					     args.flags, args.fence.fence_value,
					     args.context, args.object_count,
					     in_args->object_array,
					     args.context_count,
					     in_args->contexts, fence_count,
					     NULL, (void *)host_event_id,
					     zerohandle);

	/*
	 * When the send operation succeeds, the host event will be destroyed
	 * after signal from the host
	 */

cleanup:

	if (ret < 0) {
		if (host_event_added) {
			/* The event might be signaled and destroyed by host */
			host_event = (struct dxghosteventcpu *)
				dxgglobal_get_host_event(host_event_id);
			if (host_event) {
				eventfd_ctx_put(event);
				event = NULL;
				kfree(host_event);
				host_event = NULL;
			}
		}
		if (event)
			eventfd_ctx_put(event);
		if (host_event)
			kfree(host_event);
	}
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_signal_sync_object_cpu(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_signalsynchronizationobjectfromcpu args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}
	if (args.object_count == 0 ||
	    args.object_count > D3DDDI_MAX_OBJECT_SIGNALED) {
		DXG_TRACE("Too many syncobjects : %d", args.object_count);
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, adapter,
					     args.flags, 0, zerohandle,
					     args.object_count, args.objects, 0,
					     NULL, args.object_count,
					     args.fence_values, NULL,
					     args.device);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_signal_sync_object_gpu(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_signalsynchronizationobjectfromgpu args;
	struct d3dkmt_signalsynchronizationobjectfromgpu *__user user_args =
	    inargs;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct d3dddicb_signalflags flags = { };
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.object_count == 0 ||
	    args.object_count > DXG_MAX_VM_BUS_PACKET_SIZE) {
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.context);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, adapter,
					     flags, 0, zerohandle,
					     args.object_count,
					     args.objects, 1,
					     &user_args->context,
					     args.object_count,
					     args.monitored_fence_values, NULL,
					     zerohandle);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_signal_sync_object_gpu2(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_signalsynchronizationobjectfromgpu2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct d3dkmthandle context_handle;
	struct eventfd_ctx *event = NULL;
	u64 *fences = NULL;
	u32 fence_count = 0;
	int ret;
	struct dxghosteventcpu *host_event = NULL;
	bool host_event_added = false;
	u64 host_event_id = 0;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.flags.enqueue_cpu_event) {
		if (args.object_count != 0 || args.cpu_event_handle == 0) {
			DXG_ERR("Bad input in EnqueueCpuEvent: %d %lld",
				args.object_count, args.cpu_event_handle);
			ret = -EINVAL;
			goto cleanup;
		}
	} else if (args.object_count == 0 ||
		   args.object_count > DXG_MAX_VM_BUS_PACKET_SIZE ||
		   args.context_count == 0 ||
		   args.context_count > DXG_MAX_VM_BUS_PACKET_SIZE) {
		DXG_ERR("Invalid input: %d %d",
			args.object_count, args.context_count);
		ret = -EINVAL;
		goto cleanup;
	}

	ret = copy_from_user(&context_handle, args.contexts,
			     sizeof(struct d3dkmthandle));
	if (ret) {
		DXG_ERR("failed to copy context handle");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.flags.enqueue_cpu_event) {
		host_event = kzalloc(sizeof(*host_event), GFP_KERNEL);
		if (host_event == NULL) {
			ret = -ENOMEM;
			goto cleanup;
		}
		host_event->process = process;
		event = eventfd_ctx_fdget((int)args.cpu_event_handle);
		if (IS_ERR(event)) {
			DXG_ERR("failed to reference the event");
			event = NULL;
			ret = -EINVAL;
			goto cleanup;
		}
		fence_count = 0;
		host_event->cpu_event = event;
		host_event_id = dxgglobal_new_host_event_id();
		host_event->hdr.event_id = host_event_id;
		host_event->hdr.event_type = dxghostevent_cpu_event;
		host_event->remove_from_list = true;
		host_event->destroy_after_signal = true;
		dxgglobal_add_host_event(&host_event->hdr);
		host_event_added = true;
	} else {
		fences = args.monitored_fence_values;
		fence_count = args.object_count;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    context_handle);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_signal_sync_object(process, adapter,
					     args.flags, 0, zerohandle,
					     args.object_count, args.objects,
					     args.context_count, args.contexts,
					     fence_count, fences,
					     (void *)host_event_id, zerohandle);

cleanup:

	if (ret < 0) {
		if (host_event_added) {
			/* The event might be signaled and destroyed by host */
			host_event = (struct dxghosteventcpu *)
				dxgglobal_get_host_event(host_event_id);
			if (host_event) {
				eventfd_ctx_put(event);
				event = NULL;
				kfree(host_event);
				host_event = NULL;
			}
		}
		if (event)
			eventfd_ctx_put(event);
		if (host_event)
			kfree(host_event);
	}
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_wait_sync_object(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_waitforsynchronizationobject2 args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.object_count > D3DDDI_MAX_OBJECT_WAITED_ON ||
	    args.object_count == 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.context);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	DXG_TRACE("Fence value: %lld", args.fence.fence_value);
	ret = dxgvmb_send_wait_sync_object_gpu(process, adapter,
					       args.context, args.object_count,
					       args.object_array,
					       &args.fence.fence_value, true);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_wait_sync_object_cpu(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_waitforsynchronizationobjectfromcpu args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct eventfd_ctx *event = NULL;
	struct dxghosteventcpu host_event = { };
	struct dxghosteventcpu *async_host_event = NULL;
	struct completion local_event = { };
	u64 event_id = 0;
	int ret;
	bool host_event_added = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.object_count > DXG_MAX_VM_BUS_PACKET_SIZE ||
	    args.object_count == 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.async_event) {
		async_host_event = kzalloc(sizeof(*async_host_event),
					GFP_KERNEL);
		if (async_host_event == NULL) {
			ret = -EINVAL;
			goto cleanup;
		}
		async_host_event->process = process;
		event = eventfd_ctx_fdget((int)args.async_event);
		if (IS_ERR(event)) {
			DXG_ERR("failed to reference the event");
			event = NULL;
			ret = -EINVAL;
			goto cleanup;
		}
		async_host_event->cpu_event = event;
		async_host_event->hdr.event_id = dxgglobal_new_host_event_id();
		async_host_event->destroy_after_signal = true;
		async_host_event->hdr.event_type = dxghostevent_cpu_event;
		dxgglobal_add_host_event(&async_host_event->hdr);
		event_id = async_host_event->hdr.event_id;
		host_event_added = true;
	} else {
		init_completion(&local_event);
		host_event.completion_event = &local_event;
		host_event.hdr.event_id = dxgglobal_new_host_event_id();
		host_event.hdr.event_type = dxghostevent_cpu_event;
		dxgglobal_add_host_event(&host_event.hdr);
		event_id = host_event.hdr.event_id;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_wait_sync_object_cpu(process, adapter,
					       &args, event_id);
	if (ret < 0)
		goto cleanup;

	if (args.async_event == 0) {
		dxgadapter_release_lock_shared(adapter);
		adapter = NULL;
		ret = wait_for_completion_interruptible(&local_event);
		if (ret) {
			DXG_ERR("wait_completion_interruptible: %d",
				ret);
			ret = -ERESTARTSYS;
		}
	}

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);
	if (host_event.hdr.event_id)
		dxgglobal_remove_host_event(&host_event.hdr);
	if (ret < 0) {
		if (host_event_added) {
			async_host_event = (struct dxghosteventcpu *)
				dxgglobal_get_host_event(event_id);
			if (async_host_event) {
				if (async_host_event->hdr.event_type ==
				    dxghostevent_cpu_event) {
					eventfd_ctx_put(event);
					event = NULL;
					kfree(async_host_event);
					async_host_event = NULL;
				} else {
					DXG_ERR("Invalid event type");
					DXGKRNL_ASSERT(0);
				}
			}
		}
		if (event)
			eventfd_ctx_put(event);
		if (async_host_event)
			kfree(async_host_event);
	}

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_wait_sync_object_gpu(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_waitforsynchronizationobjectfromgpu args;
	struct dxgcontext *context = NULL;
	struct d3dkmthandle device_handle = {};
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct dxgsyncobject *syncobj = NULL;
	struct d3dkmthandle *objects = NULL;
	u32 object_size;
	u64 *fences = NULL;
	int ret;
	enum hmgrentry_type syncobj_type = HMGRENTRY_TYPE_FREE;
	bool monitored_fence = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.object_count > DXG_MAX_VM_BUS_PACKET_SIZE ||
	    args.object_count == 0) {
		DXG_ERR("Invalid object count: %d", args.object_count);
		ret = -EINVAL;
		goto cleanup;
	}

	object_size = sizeof(struct d3dkmthandle) * args.object_count;
	objects = vzalloc(object_size);
	if (objects == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}
	ret = copy_from_user(objects, args.objects, object_size);
	if (ret) {
		DXG_ERR("failed to copy objects");
		ret = -EINVAL;
		goto cleanup;
	}

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
	if (device_handle.v == 0) {
		DXG_ERR("Invalid context handle: %x", args.context.v);
		ret = -EINVAL;
	} else {
		if (syncobj_type == HMGRENTRY_TYPE_MONITOREDFENCE) {
			monitored_fence = true;
		} else if (syncobj_type == HMGRENTRY_TYPE_DXGSYNCOBJECT) {
			syncobj =
			    hmgrtable_get_object_by_type(&process->handle_table,
						HMGRENTRY_TYPE_DXGSYNCOBJECT,
						objects[0]);
			if (syncobj == NULL) {
				DXG_ERR("Invalid syncobj: %x",
					objects[0].v);
				ret = -EINVAL;
			} else {
				monitored_fence = syncobj->monitored_fence;
			}
		} else {
			DXG_ERR("Invalid syncobj type: %x",
				objects[0].v);
			ret = -EINVAL;
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);

	if (ret < 0)
		goto cleanup;

	if (monitored_fence) {
		object_size = sizeof(u64) * args.object_count;
		fences = vzalloc(object_size);
		if (fences == NULL) {
			ret = -ENOMEM;
			goto cleanup;
		}
		ret = copy_from_user(fences, args.monitored_fence_values,
				     object_size);
		if (ret) {
			DXG_ERR("failed to copy fences");
			ret = -EINVAL;
			goto cleanup;
		}
	} else {
		fences = &args.fence_value;
	}

	device = dxgprocess_device_by_handle(process, device_handle);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_wait_sync_object_gpu(process, adapter,
					       args.context, args.object_count,
					       objects, fences,
					       !monitored_fence);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);
	if (objects)
		vfree(objects);
	if (fences && fences != &args.fence_value)
		vfree(fences);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_lock2(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_lock2 args;
	struct d3dkmt_lock2 *__user result = inargs;
	int ret;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct dxgallocation *alloc = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	args.data = NULL;
	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	alloc = hmgrtable_get_object_by_type(&process->handle_table,
					     HMGRENTRY_TYPE_DXGALLOCATION,
					     args.allocation);
	if (alloc == NULL) {
		ret = -EINVAL;
	} else {
		if (alloc->cpu_address) {
			ret = copy_to_user(&result->data,
					   &alloc->cpu_address,
					   sizeof(args.data));
			if (ret == 0) {
				args.data = alloc->cpu_address;
				if (alloc->cpu_address_mapped)
					alloc->cpu_address_refcount++;
			} else {
				DXG_ERR("Failed to copy cpu address");
				ret = -EINVAL;
			}
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
	if (ret < 0)
		goto cleanup;
	if (args.data)
		goto success;

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_lock2(process, adapter, &args, result);

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

success:
	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_unlock2(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_unlock2 args;
	int ret;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	struct dxgallocation *alloc = NULL;
	bool done = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	alloc = hmgrtable_get_object_by_type(&process->handle_table,
					     HMGRENTRY_TYPE_DXGALLOCATION,
					     args.allocation);
	if (alloc == NULL) {
		ret = -EINVAL;
	} else {
		if (alloc->cpu_address == NULL) {
			DXG_ERR("Allocation is not locked: %p", alloc);
			ret = -EINVAL;
		} else if (alloc->cpu_address_mapped) {
			if (alloc->cpu_address_refcount > 0) {
				alloc->cpu_address_refcount--;
				if (alloc->cpu_address_refcount != 0) {
					done = true;
				} else {
					dxg_unmap_iospace(alloc->cpu_address,
						alloc->num_pages << PAGE_SHIFT);
					alloc->cpu_address_mapped = false;
					alloc->cpu_address = NULL;
				}
			} else {
				DXG_ERR("Invalid cpu access refcount");
				done = true;
			}
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
	if (done)
		goto success;
	if (ret < 0)
		goto cleanup;

	/*
	 * The call acquires reference on the device. It is safe to access the
	 * adapter, because the device holds reference on it.
	 */
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_unlock2(process, adapter, &args);

cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

success:
	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_update_alloc_property(struct dxgprocess *process, void *__user inargs)
{
	struct d3dddi_updateallocproperty args;
	int ret;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_object_handle(process,
						HMGRENTRY_TYPE_DXGPAGINGQUEUE,
						args.paging_queue);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgvmb_send_update_alloc_property(process, adapter,
						&args, inargs);

cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);

	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_mark_device_as_error(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_markdeviceaserror args;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}
	device->execution_state = _D3DKMT_DEVICEEXECUTION_RESET;
	ret = dxgvmb_send_mark_device_as_error(process, adapter, &args);
cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);
	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_query_alloc_residency(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_queryallocationresidency args;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if ((args.allocation_count == 0) == (args.resource.v == 0)) {
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}
	ret = dxgvmb_send_query_alloc_residency(process, adapter, &args);
cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);
	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_set_allocation_priority(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_setallocationpriority args;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}
	ret = dxgvmb_send_set_allocation_priority(process, adapter, &args);
cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);
	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_get_allocation_priority(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_getallocationpriority args;
	struct dxgadapter *adapter = NULL;
	struct dxgdevice *device = NULL;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}
	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}
	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}
	ret = dxgvmb_send_get_allocation_priority(process, adapter, &args);
cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);
	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_change_vidmem_reservation(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_changevideomemoryreservation args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.process != 0) {
		DXG_ERR("setting memory reservation for other process");
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;
	args.adapter.v = 0;
	ret = dxgvmb_send_change_vidmem_reservation(process, adapter,
						    zerohandle, &args);

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		kref_put(&adapter->adapter_kref, dxgadapter_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_query_clock_calibration(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_queryclockcalibration args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;

	args.adapter = adapter->host_handle;
	ret = dxgvmb_send_query_clock_calibration(process, adapter,
						  &args, inargs);
	if (ret < 0)
		goto cleanup;
	ret = copy_to_user(inargs, &args, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy output args");
		ret = -EINVAL;
	}

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		kref_put(&adapter->adapter_kref, dxgadapter_release);
	return ret;
}

static int
dxgkio_flush_heap_transitions(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_flushheaptransitions args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;

	args.adapter = adapter->host_handle;
	ret = dxgvmb_send_flush_heap_transitions(process, adapter, &args);
	if (ret < 0)
		goto cleanup;
	ret = copy_to_user(inargs, &args, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy output args");
		ret = -EINVAL;
	}

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		kref_put(&adapter->adapter_kref, dxgadapter_release);
	return ret;
}

static int
dxgkio_escape(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_escape args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;

	args.adapter = adapter->host_handle;
	ret = dxgvmb_send_escape(process, adapter, &args);

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		kref_put(&adapter->adapter_kref, dxgadapter_release);
	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_query_vidmem_info(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_queryvideomemoryinfo args;
	int ret;
	struct dxgadapter *adapter = NULL;
	bool adapter_locked = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.process != 0) {
		DXG_ERR("query vidmem info from another process");
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = dxgprocess_adapter_by_handle(process, args.adapter);
	if (adapter == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}
	adapter_locked = true;

	args.adapter = adapter->host_handle;
	ret = dxgvmb_send_query_vidmem_info(process, adapter, &args, inargs);

cleanup:

	if (adapter_locked)
		dxgadapter_release_lock_shared(adapter);
	if (adapter)
		kref_put(&adapter->adapter_kref, dxgadapter_release);
	if (ret < 0)
		DXG_ERR("failed: %x", ret);
	return ret;
}

static int
dxgkio_get_device_state(struct dxgprocess *process, void *__user inargs)
{
	int ret;
	struct d3dkmt_getdevicestate args;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	int global_device_state_counter = 0;
	struct dxgglobal *dxgglobal = dxggbl();

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	if (args.state_type == _D3DKMT_DEVICESTATE_EXECUTION) {
		global_device_state_counter =
			atomic_read(&dxgglobal->device_state_counter);
		if (device->execution_state_counter ==
		    global_device_state_counter) {
			args.execution_state = device->execution_state;
			ret = copy_to_user(inargs, &args, sizeof(args));
			if (ret) {
				DXG_ERR("failed to copy args to user");
				ret = -EINVAL;
			}
			goto cleanup;
		}
	}

	ret = dxgvmb_send_get_device_state(process, adapter, &args, inargs);

	if (ret == 0 && args.state_type == _D3DKMT_DEVICESTATE_EXECUTION) {
		device->execution_state = args.execution_state;
		device->execution_state_counter = global_device_state_counter;
	}

cleanup:

	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);
	if (ret < 0)
		DXG_ERR("Failed to get device state %x", ret);

	return ret;
}

static int
dxgsharedsyncobj_get_host_nt_handle(struct dxgsharedsyncobject *syncobj,
				    struct dxgprocess *process,
				    struct d3dkmthandle objecthandle)
{
	int ret = 0;

	mutex_lock(&syncobj->fd_mutex);
	if (syncobj->host_shared_handle_nt_reference == 0) {
		ret = dxgvmb_send_create_nt_shared_object(process,
			objecthandle,
			&syncobj->host_shared_handle_nt);
		if (ret < 0)
			goto cleanup;
		DXG_TRACE("Host_shared_handle_ht: %x",
			syncobj->host_shared_handle_nt.v);
		kref_get(&syncobj->ssyncobj_kref);
	}
	syncobj->host_shared_handle_nt_reference++;
cleanup:
	mutex_unlock(&syncobj->fd_mutex);
	return ret;
}

static int
dxgsharedresource_get_host_nt_handle(struct dxgsharedresource *resource,
				     struct dxgprocess *process,
				     struct d3dkmthandle objecthandle)
{
	int ret = 0;

	mutex_lock(&resource->fd_mutex);
	if (resource->host_shared_handle_nt_reference == 0) {
		ret = dxgvmb_send_create_nt_shared_object(process,
					objecthandle,
					&resource->host_shared_handle_nt);
		if (ret < 0)
			goto cleanup;
		DXG_TRACE("Resource host_shared_handle_ht: %x",
			resource->host_shared_handle_nt.v);
		kref_get(&resource->sresource_kref);
	}
	resource->host_shared_handle_nt_reference++;
cleanup:
	mutex_unlock(&resource->fd_mutex);
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
		DXG_ERR("get_unused_fd_flags failed: %x", fd);
		return -ENOTRECOVERABLE;
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
		return -EINVAL;
	};
	if (IS_ERR(file)) {
		DXG_ERR("anon_inode_getfile failed: %x", fd);
		put_unused_fd(fd);
		return -ENOTRECOVERABLE;
	}

	fd_install(fd, file);
	*fdout = fd;
	return 0;
}

static int
dxgkio_share_objects(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_shareobjects args;
	enum hmgrentry_type object_type;
	struct dxgsyncobject *syncobj = NULL;
	struct dxgresource *resource = NULL;
	struct dxgsharedsyncobject *shared_syncobj = NULL;
	struct dxgsharedresource *shared_resource = NULL;
	struct d3dkmthandle *handles = NULL;
	int object_fd = -1;
	void *obj = NULL;
	u32 handle_size;
	int ret;
	u64 tmp = 0;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	if (args.object_count == 0 || args.object_count > 1) {
		DXG_ERR("invalid object count %d", args.object_count);
		ret = -EINVAL;
		goto cleanup;
	}

	handle_size = args.object_count * sizeof(struct d3dkmthandle);

	handles = vzalloc(handle_size);
	if (handles == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}
	ret = copy_from_user(handles, args.objects, handle_size);
	if (ret) {
		DXG_ERR("failed to copy object handles");
		ret = -EINVAL;
		goto cleanup;
	}

	DXG_TRACE("Sharing handle: %x", handles[0].v);

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	object_type = hmgrtable_get_object_type(&process->handle_table,
						handles[0]);
	obj = hmgrtable_get_object(&process->handle_table, handles[0]);
	if (obj == NULL) {
		DXG_ERR("invalid object handle %x", handles[0].v);
		ret = -EINVAL;
	} else {
		switch (object_type) {
		case HMGRENTRY_TYPE_DXGSYNCOBJECT:
			syncobj = obj;
			if (syncobj->shared) {
				kref_get(&syncobj->syncobj_kref);
				shared_syncobj = syncobj->shared_owner;
			} else {
				DXG_ERR("sync object is not shared");
				syncobj = NULL;
				ret = -EINVAL;
			}
			break;
		case HMGRENTRY_TYPE_DXGRESOURCE:
			resource = obj;
			if (resource->shared_owner) {
				kref_get(&resource->resource_kref);
				shared_resource = resource->shared_owner;
			} else {
				resource = NULL;
				DXG_ERR("resource object shared");
				ret = -EINVAL;
			}
			break;
		default:
			DXG_ERR("invalid object type %d", object_type);
			ret = -EINVAL;
			break;
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);

	if (ret < 0)
		goto cleanup;

	switch (object_type) {
	case HMGRENTRY_TYPE_DXGSYNCOBJECT:
		ret = get_object_fd(DXG_SHARED_SYNCOBJECT, shared_syncobj,
				    &object_fd);
		if (ret < 0) {
			DXG_ERR("get_object_fd failed for sync object");
			goto cleanup;
		}
		ret = dxgsharedsyncobj_get_host_nt_handle(shared_syncobj,
							  process,
							  handles[0]);
		if (ret < 0) {
			DXG_ERR("get_host_nt_handle failed");
			goto cleanup;
		}
		break;
	case HMGRENTRY_TYPE_DXGRESOURCE:
		ret = get_object_fd(DXG_SHARED_RESOURCE, shared_resource,
				    &object_fd);
		if (ret < 0) {
			DXG_ERR("get_object_fd failed for resource");
			goto cleanup;
		}
		ret = dxgsharedresource_get_host_nt_handle(shared_resource,
							   process, handles[0]);
		if (ret < 0) {
			DXG_ERR("get_host_res_nt_handle failed");
			goto cleanup;
		}
		ret = dxgsharedresource_seal(shared_resource);
		if (ret < 0) {
			DXG_ERR("dxgsharedresource_seal failed");
			goto cleanup;
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret < 0)
		goto cleanup;

	DXG_TRACE("Object FD: %x", object_fd);

	tmp = (u64) object_fd;

	ret = copy_to_user(args.shared_handle, &tmp, sizeof(u64));
	if (ret) {
		DXG_ERR("failed to copy shared handle");
		ret = -EINVAL;
	}

cleanup:
	if (ret < 0) {
		if (object_fd >= 0)
			put_unused_fd(object_fd);
	}

	if (handles)
		vfree(handles);

	if (syncobj)
		kref_put(&syncobj->syncobj_kref, dxgsyncobject_release);

	if (resource)
		kref_put(&resource->resource_kref, dxgresource_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_query_resource_info_nt(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_queryresourceinfofromnthandle args;
	int ret;
	struct dxgdevice *device = NULL;
	struct dxgsharedresource *shared_resource = NULL;
	struct file *file = NULL;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	file = fget(args.nt_handle);
	if (!file) {
		DXG_ERR("failed to get file from handle: %llx",
			args.nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}

	if (file->f_op != &dxg_resource_fops) {
		DXG_ERR("invalid fd: %llx", args.nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}

	shared_resource = file->private_data;
	if (shared_resource == NULL) {
		DXG_ERR("invalid private data: %llx", args.nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0) {
		kref_put(&device->device_kref, dxgdevice_release);
		device = NULL;
		goto cleanup;
	}

	ret = dxgsharedresource_seal(shared_resource);
	if (ret < 0)
		goto cleanup;

	args.private_runtime_data_size =
	    shared_resource->runtime_private_data_size;
	args.resource_priv_drv_data_size =
	    shared_resource->resource_private_data_size;
	args.allocation_count = shared_resource->allocation_count;
	args.total_priv_drv_data_size =
	    shared_resource->alloc_private_data_size;

	ret = copy_to_user(inargs, &args, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy output args");
		ret = -EINVAL;
	}

cleanup:

	if (file)
		fput(file);
	if (device)
		dxgdevice_release_lock_shared(device);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
assign_resource_handles(struct dxgprocess *process,
			struct dxgsharedresource *shared_resource,
			struct d3dkmt_openresourcefromnthandle *args,
			struct d3dkmthandle resource_handle,
			struct dxgresource *resource,
			struct dxgallocation **allocs,
			struct d3dkmthandle *handles)
{
	int ret;
	int i;
	u8 *cur_priv_data;
	u32 total_priv_data_size = 0;
	struct d3dddi_openallocationinfo2 open_alloc_info = { };

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	ret = hmgrtable_assign_handle(&process->handle_table, resource,
				      HMGRENTRY_TYPE_DXGRESOURCE,
				      resource_handle);
	if (ret < 0)
		goto cleanup;
	resource->handle = resource_handle;
	resource->handle_valid = 1;
	cur_priv_data = args->total_priv_drv_data;
	for (i = 0; i < args->allocation_count; i++) {
		ret = hmgrtable_assign_handle(&process->handle_table, allocs[i],
					      HMGRENTRY_TYPE_DXGALLOCATION,
					      handles[i]);
		if (ret < 0)
			goto cleanup;
		allocs[i]->alloc_handle = handles[i];
		allocs[i]->handle_valid = 1;
		open_alloc_info.allocation = handles[i];
		if (shared_resource->alloc_private_data_sizes)
			open_alloc_info.priv_drv_data_size =
			    shared_resource->alloc_private_data_sizes[i];
		else
			open_alloc_info.priv_drv_data_size = 0;

		total_priv_data_size += open_alloc_info.priv_drv_data_size;
		open_alloc_info.priv_drv_data = cur_priv_data;
		cur_priv_data += open_alloc_info.priv_drv_data_size;

		ret = copy_to_user(&args->open_alloc_info[i],
				   &open_alloc_info,
				   sizeof(open_alloc_info));
		if (ret) {
			DXG_ERR("failed to copy alloc info");
			ret = -EINVAL;
			goto cleanup;
		}
	}
	args->total_priv_drv_data_size = total_priv_data_size;
cleanup:
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
	if (ret < 0) {
		for (i = 0; i < args->allocation_count; i++)
			dxgallocation_free_handle(allocs[i]);
		dxgresource_free_handle(resource);
	}
	return ret;
}

static int
open_resource(struct dxgprocess *process,
	      struct d3dkmt_openresourcefromnthandle *args,
	      __user struct d3dkmthandle *res_out,
	      __user u32 *total_driver_data_size_out)
{
	int ret = 0;
	int i;
	struct d3dkmthandle *alloc_handles = NULL;
	int alloc_handles_size = sizeof(struct d3dkmthandle) *
				 args->allocation_count;
	struct dxgsharedresource *shared_resource = NULL;
	struct dxgresource *resource = NULL;
	struct dxgallocation **allocs = NULL;
	struct d3dkmthandle global_share = {};
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct d3dkmthandle resource_handle = {};
	struct file *file = NULL;

	DXG_TRACE("Opening resource handle: %llx", args->nt_handle);

	file = fget(args->nt_handle);
	if (!file) {
		DXG_ERR("failed to get file from handle: %llx",
			args->nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}
	if (file->f_op != &dxg_resource_fops) {
		DXG_ERR("invalid fd type: %llx", args->nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}
	shared_resource = file->private_data;
	if (shared_resource == NULL) {
		DXG_ERR("invalid private data: %llx", args->nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}
	if (kref_get_unless_zero(&shared_resource->sresource_kref) == 0)
		shared_resource = NULL;
	else
		global_share = shared_resource->host_shared_handle_nt;

	if (shared_resource == NULL) {
		DXG_ERR("Invalid shared resource handle: %x",
			(u32)args->nt_handle);
		ret = -EINVAL;
		goto cleanup;
	}

	DXG_TRACE("Shared resource: %p %x", shared_resource,
		global_share.v);

	device = dxgprocess_device_by_handle(process, args->device);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0) {
		kref_put(&device->device_kref, dxgdevice_release);
		device = NULL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		adapter = NULL;
		goto cleanup;
	}

	ret = dxgsharedresource_seal(shared_resource);
	if (ret < 0)
		goto cleanup;

	if (args->allocation_count != shared_resource->allocation_count ||
	    args->private_runtime_data_size <
	    shared_resource->runtime_private_data_size ||
	    args->resource_priv_drv_data_size <
	    shared_resource->resource_private_data_size ||
	    args->total_priv_drv_data_size <
	    shared_resource->alloc_private_data_size) {
		ret = -EINVAL;
		DXG_ERR("Invalid data sizes");
		goto cleanup;
	}

	alloc_handles = vzalloc(alloc_handles_size);
	if (alloc_handles == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	allocs = vzalloc(sizeof(void *) * args->allocation_count);
	if (allocs == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	resource = dxgresource_create(device);
	if (resource == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}
	dxgsharedresource_add_resource(shared_resource, resource);

	for (i = 0; i < args->allocation_count; i++) {
		allocs[i] = dxgallocation_create(process);
		if (allocs[i] == NULL)
			goto cleanup;
		ret = dxgresource_add_alloc(resource, allocs[i]);
		if (ret < 0)
			goto cleanup;
	}

	ret = dxgvmb_send_open_resource(process, adapter,
					device->handle, global_share,
					args->allocation_count,
					args->total_priv_drv_data_size,
					&resource_handle, alloc_handles);
	if (ret < 0) {
		DXG_ERR("dxgvmb_send_open_resource failed");
		goto cleanup;
	}

	if (shared_resource->runtime_private_data_size) {
		ret = copy_to_user(args->private_runtime_data,
				shared_resource->runtime_private_data,
				shared_resource->runtime_private_data_size);
		if (ret) {
			DXG_ERR("failed to copy runtime data");
			ret = -EINVAL;
			goto cleanup;
		}
	}

	if (shared_resource->resource_private_data_size) {
		ret = copy_to_user(args->resource_priv_drv_data,
				shared_resource->resource_private_data,
				shared_resource->resource_private_data_size);
		if (ret) {
			DXG_ERR("failed to copy resource data");
			ret = -EINVAL;
			goto cleanup;
		}
	}

	if (shared_resource->alloc_private_data_size) {
		ret = copy_to_user(args->total_priv_drv_data,
				shared_resource->alloc_private_data,
				shared_resource->alloc_private_data_size);
		if (ret) {
			DXG_ERR("failed to copy alloc data");
			ret = -EINVAL;
			goto cleanup;
		}
	}

	ret = assign_resource_handles(process, shared_resource, args,
				      resource_handle, resource, allocs,
				      alloc_handles);
	if (ret < 0)
		goto cleanup;

	ret = copy_to_user(res_out, &resource_handle,
			   sizeof(struct d3dkmthandle));
	if (ret) {
		DXG_ERR("failed to copy resource handle to user");
		ret = -EINVAL;
		goto cleanup;
	}

	ret = copy_to_user(total_driver_data_size_out,
			   &args->total_priv_drv_data_size, sizeof(u32));
	if (ret) {
		DXG_ERR("failed to copy total driver data size");
		ret = -EINVAL;
	}

cleanup:

	if (ret < 0) {
		if (resource_handle.v) {
			struct d3dkmt_destroyallocation2 tmp = { };

			tmp.flags.assume_not_in_use = 1;
			tmp.device = args->device;
			tmp.resource = resource_handle;
			ret = dxgvmb_send_destroy_allocation(process, device,
							     &tmp, NULL);
		}
		if (resource)
			dxgresource_destroy(resource);
	}

	if (file)
		fput(file);
	if (allocs)
		vfree(allocs);
	if (shared_resource)
		kref_put(&shared_resource->sresource_kref,
			 dxgsharedresource_destroy);
	if (alloc_handles)
		vfree(alloc_handles);
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_lock_shared(device);
	if (device)
		kref_put(&device->device_kref, dxgdevice_release);

	return ret;
}

static int
dxgkio_open_resource_nt(struct dxgprocess *process,
				      void *__user inargs)
{
	struct d3dkmt_openresourcefromnthandle args;
	struct d3dkmt_openresourcefromnthandle *__user args_user = inargs;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	ret = open_resource(process, &args,
			    &args_user->resource,
			    &args_user->total_priv_drv_data_size);

cleanup:

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static int
dxgkio_share_object_with_host(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_shareobjectwithhost args;
	int ret;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgvmb_send_share_object_with_host(process, &args);
	if (ret) {
		DXG_ERR("dxgvmb_send_share_object_with_host dailed");
		goto cleanup;
	}

	ret = copy_to_user(inargs, &args, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy data to user");
		ret = -EINVAL;
	}

cleanup:

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static struct ioctl_desc ioctls[] = {
/* 0x00 */	{},
/* 0x01 */	{dxgkio_open_adapter_from_luid, LX_DXOPENADAPTERFROMLUID},
/* 0x02 */	{dxgkio_create_device, LX_DXCREATEDEVICE},
/* 0x03 */	{},
/* 0x04 */	{dxgkio_create_context_virtual, LX_DXCREATECONTEXTVIRTUAL},
/* 0x05 */	{dxgkio_destroy_context, LX_DXDESTROYCONTEXT},
/* 0x06 */	{dxgkio_create_allocation, LX_DXCREATEALLOCATION},
/* 0x07 */	{dxgkio_create_paging_queue, LX_DXCREATEPAGINGQUEUE},
/* 0x08 */	{},
/* 0x09 */	{dxgkio_query_adapter_info, LX_DXQUERYADAPTERINFO},
/* 0x0a */	{dxgkio_query_vidmem_info, LX_DXQUERYVIDEOMEMORYINFO},
/* 0x0b */	{},
/* 0x0c */	{},
/* 0x0d */	{dxgkio_escape, LX_DXESCAPE},
/* 0x0e */	{dxgkio_get_device_state, LX_DXGETDEVICESTATE},
/* 0x0f */	{dxgkio_submit_command, LX_DXSUBMITCOMMAND},
/* 0x10 */	{dxgkio_create_sync_object, LX_DXCREATESYNCHRONIZATIONOBJECT},
/* 0x11 */	{dxgkio_signal_sync_object, LX_DXSIGNALSYNCHRONIZATIONOBJECT},
/* 0x12 */	{dxgkio_wait_sync_object, LX_DXWAITFORSYNCHRONIZATIONOBJECT},
/* 0x13 */	{dxgkio_destroy_allocation, LX_DXDESTROYALLOCATION2},
/* 0x14 */	{dxgkio_enum_adapters, LX_DXENUMADAPTERS2},
/* 0x15 */	{dxgkio_close_adapter, LX_DXCLOSEADAPTER},
/* 0x16 */	{dxgkio_change_vidmem_reservation,
		  LX_DXCHANGEVIDEOMEMORYRESERVATION},
/* 0x17 */	{},
/* 0x18 */	{dxgkio_create_hwqueue, LX_DXCREATEHWQUEUE},
/* 0x19 */	{dxgkio_destroy_device, LX_DXDESTROYDEVICE},
/* 0x1a */	{},
/* 0x1b */	{dxgkio_destroy_hwqueue, LX_DXDESTROYHWQUEUE},
/* 0x1c */	{dxgkio_destroy_paging_queue, LX_DXDESTROYPAGINGQUEUE},
/* 0x1d */	{dxgkio_destroy_sync_object, LX_DXDESTROYSYNCHRONIZATIONOBJECT},
/* 0x1e */	{},
/* 0x1f */	{dxgkio_flush_heap_transitions, LX_DXFLUSHHEAPTRANSITIONS},
/* 0x20 */	{},
/* 0x21 */	{},
/* 0x22 */	{},
/* 0x23 */	{},
/* 0x24 */	{},
/* 0x25 */	{dxgkio_lock2, LX_DXLOCK2},
/* 0x26 */	{dxgkio_mark_device_as_error, LX_DXMARKDEVICEASERROR},
/* 0x27 */	{dxgkio_offer_allocations, LX_DXOFFERALLOCATIONS},
/* 0x28 */	{},
/* 0x29 */	{},
/* 0x2a */	{dxgkio_query_alloc_residency, LX_DXQUERYALLOCATIONRESIDENCY},
/* 0x2b */	{},
/* 0x2c */	{dxgkio_reclaim_allocations, LX_DXRECLAIMALLOCATIONS2},
/* 0x2d */	{},
/* 0x2e */	{dxgkio_set_allocation_priority, LX_DXSETALLOCATIONPRIORITY},
/* 0x2f */	{},
/* 0x30 */	{},
/* 0x31 */	{dxgkio_signal_sync_object_cpu,
		 LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMCPU},
/* 0x32 */	{dxgkio_signal_sync_object_gpu,
		 LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMGPU},
/* 0x33 */	{dxgkio_signal_sync_object_gpu2,
		 LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMGPU2},
/* 0x34 */	{dxgkio_submit_command_to_hwqueue, LX_DXSUBMITCOMMANDTOHWQUEUE},
/* 0x35 */	{dxgkio_submit_signal_to_hwqueue,
		  LX_DXSUBMITSIGNALSYNCOBJECTSTOHWQUEUE},
/* 0x36 */	{dxgkio_submit_wait_to_hwqueue,
		 LX_DXSUBMITWAITFORSYNCOBJECTSTOHWQUEUE},
/* 0x37 */	{dxgkio_unlock2, LX_DXUNLOCK2},
/* 0x38 */	{dxgkio_update_alloc_property, LX_DXUPDATEALLOCPROPERTY},
/* 0x39 */	{},
/* 0x3a */	{dxgkio_wait_sync_object_cpu,
		 LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMCPU},
/* 0x3b */	{dxgkio_wait_sync_object_gpu,
		 LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMGPU},
/* 0x3c */	{dxgkio_get_allocation_priority, LX_DXGETALLOCATIONPRIORITY},
/* 0x3d */	{dxgkio_query_clock_calibration, LX_DXQUERYCLOCKCALIBRATION},
/* 0x3e */	{dxgkio_enum_adapters3, LX_DXENUMADAPTERS3},
/* 0x3f */	{dxgkio_share_objects, LX_DXSHAREOBJECTS},
/* 0x40 */	{dxgkio_open_sync_object_nt, LX_DXOPENSYNCOBJECTFROMNTHANDLE2},
/* 0x41 */	{dxgkio_query_resource_info_nt,
		 LX_DXQUERYRESOURCEINFOFROMNTHANDLE},
/* 0x42 */	{dxgkio_open_resource_nt, LX_DXOPENRESOURCEFROMNTHANDLE},
/* 0x43 */	{dxgkio_query_statistics, LX_DXQUERYSTATISTICS},
/* 0x44 */	{dxgkio_share_object_with_host, LX_DXSHAREOBJECTWITHHOST},
/* 0x45 */	{},
};

/*
 * IOCTL processing
 * The driver IOCTLs return
 * - 0 in case of success
 * - positive values, which are Windows NTSTATUS (for example, STATUS_PENDING).
 *   Positive values are success codes.
 * - Linux negative error codes
 */
static int dxgk_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	int code = _IOC_NR(p1);
	int status;
	struct dxgprocess *process;

	if (code < 1 ||  code >= ARRAY_SIZE(ioctls)) {
		DXG_ERR("bad ioctl %x %x %x %x",
			code, _IOC_TYPE(p1), _IOC_SIZE(p1), _IOC_DIR(p1));
		return -ENOTTY;
	}
	if (ioctls[code].ioctl_callback == NULL) {
		DXG_ERR("ioctl callback is NULL %x", code);
		return -ENOTTY;
	}
	if (ioctls[code].ioctl != p1) {
		DXG_ERR("ioctl mismatch. Code: %x User: %x Kernel: %x",
			code, p1, ioctls[code].ioctl);
		return -ENOTTY;
	}
	process = (struct dxgprocess *)f->private_data;
	if (process->tgid != current->tgid) {
		DXG_ERR("Call from a wrong process: %d %d",
			process->tgid, current->tgid);
		return -ENOTTY;
	}
	status = ioctls[code].ioctl_callback(process, (void *__user)p2);
	return status;
}

long dxgk_compat_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	DXG_TRACE("compat ioctl %x", p1);
	return dxgk_ioctl(f, p1, p2);
}

long dxgk_unlocked_ioctl(struct file *f, unsigned int p1, unsigned long p2)
{
	DXG_TRACE("unlocked ioctl %x Code:%d", p1, _IOC_NR(p1));
	return dxgk_ioctl(f, p1, p2);
}

#ifdef DEBUG
void dxgk_validate_ioctls(void)
{
	int i;

	for (i=0; i < ARRAY_SIZE(ioctls); i++)
	{
		if (ioctls[i].ioctl && _IOC_NR(ioctls[i].ioctl) != i)
		{
			DXG_ERR("Invalid ioctl");
			DXGKRNL_ASSERT(0);
		}
	}
}
#endif
