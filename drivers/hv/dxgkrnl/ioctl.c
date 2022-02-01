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
			dev_err(DXGDEV,
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
					dev_err(DXGDEV,
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
			dxgresource_destroy(resource);
		}
	}
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

static struct ioctl_desc ioctls[] = {
/* 0x00 */	{},
/* 0x01 */	{dxgkio_open_adapter_from_luid, LX_DXOPENADAPTERFROMLUID},
/* 0x02 */	{dxgkio_create_device, LX_DXCREATEDEVICE},
/* 0x03 */	{},
/* 0x04 */	{dxgkio_create_context_virtual, LX_DXCREATECONTEXTVIRTUAL},
/* 0x05 */	{dxgkio_destroy_context, LX_DXDESTROYCONTEXT},
/* 0x06 */	{dxgkio_create_allocation, LX_DXCREATEALLOCATION},
/* 0x07 */	{},
/* 0x08 */	{},
/* 0x09 */	{dxgkio_query_adapter_info, LX_DXQUERYADAPTERINFO},
/* 0x0a */	{},
/* 0x0b */	{},
/* 0x0c */	{},
/* 0x0d */	{},
/* 0x0e */	{},
/* 0x0f */	{},
/* 0x10 */	{},
/* 0x11 */	{},
/* 0x12 */	{},
/* 0x13 */	{dxgkio_destroy_allocation, LX_DXDESTROYALLOCATION2},
/* 0x14 */	{dxgkio_enum_adapters, LX_DXENUMADAPTERS2},
/* 0x15 */	{dxgkio_close_adapter, LX_DXCLOSEADAPTER},
/* 0x16 */	{},
/* 0x17 */	{},
/* 0x18 */	{},
/* 0x19 */	{dxgkio_destroy_device, LX_DXDESTROYDEVICE},
/* 0x1a */	{},
/* 0x1b */	{},
/* 0x1c */	{},
/* 0x1d */	{},
/* 0x1e */	{},
/* 0x1f */	{},
/* 0x20 */	{},
/* 0x21 */	{},
/* 0x22 */	{},
/* 0x23 */	{},
/* 0x24 */	{},
/* 0x25 */	{},
/* 0x26 */	{},
/* 0x27 */	{},
/* 0x28 */	{},
/* 0x29 */	{},
/* 0x2a */	{},
/* 0x2b */	{},
/* 0x2c */	{},
/* 0x2d */	{},
/* 0x2e */	{},
/* 0x2f */	{},
/* 0x30 */	{},
/* 0x31 */	{},
/* 0x32 */	{},
/* 0x33 */	{},
/* 0x34 */	{},
/* 0x35 */	{},
/* 0x36 */	{},
/* 0x37 */	{},
/* 0x38 */	{},
/* 0x39 */	{},
/* 0x3a */	{},
/* 0x3b */	{},
/* 0x3c */	{},
/* 0x3d */	{},
/* 0x3e */	{dxgkio_enum_adapters3, LX_DXENUMADAPTERS3},
/* 0x3f */	{},
/* 0x40 */	{},
/* 0x41 */	{},
/* 0x42 */	{},
/* 0x43 */	{},
/* 0x44 */	{},
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
