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
 * dxgsyncpoint:
 *    - pointer to dxgsharedsyncobject
 *    - host_shared_handle_nt_reference incremented
 *    - list of (process, local syncobj d3dkmthandle) pairs
 * wait for sync file
 *    - get dxgsyncpoint
 *    - if process doesn't have a local syncobj
 *        - create local dxgsyncobject
 *        - send open syncobj to the host
 *    - Send wait for syncobj to the context
 * dxgsyncpoint destruction
 *    -  walk the list of (process, local syncobj)
 *    - destroy syncobj
 *    - remove reference to dxgsharedsyncobject
 */

#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>

#include "dxgkrnl.h"
#include "dxgvmbus.h"
#include "dxgsyncfile.h"

#undef dev_fmt
#define dev_fmt(fmt)	"dxgk: " fmt

#ifdef DEBUG
static char *errorstr(int ret)
{
	return ret < 0 ? "err" : "";
}
#endif

static const struct dma_fence_ops dxgdmafence_ops;

static struct dxgsyncpoint *to_syncpoint(struct dma_fence *fence)
{
	if (fence->ops != &dxgdmafence_ops)
		return NULL;
	return container_of(fence, struct dxgsyncpoint, base);
}

int dxgkio_create_sync_file(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_createsyncfile args;
	struct dxgsyncpoint *pt = NULL;
	int ret = 0;
	int fd;
	struct sync_file *sync_file = NULL;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct dxgsyncobject *syncobj = NULL;
	struct d3dkmt_waitforsynchronizationobjectfromcpu waitargs = {};
	bool device_lock_acquired = false;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		DXG_ERR("get_unused_fd_flags failed: %d", fd);
		ret = fd;
		goto cleanup;
	}

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EFAULT;
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		DXG_ERR("dxgprocess_device_by_handle failed");
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0) {
		DXG_ERR("dxgdevice_acquire_lock_shared failed");
		goto cleanup;
	}
	device_lock_acquired = true;

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		DXG_ERR("dxgadapter_acquire_lock_shared failed");
		adapter = NULL;
		goto cleanup;
	}

	pt = kzalloc(sizeof(*pt), GFP_KERNEL);
	if (!pt) {
		ret = -ENOMEM;
		goto cleanup;
	}
	spin_lock_init(&pt->lock);
	pt->fence_value = args.fence_value;
	pt->context = dma_fence_context_alloc(1);
	pt->hdr.event_id = dxgglobal_new_host_event_id();
	pt->hdr.event_type = dxghostevent_dma_fence;
	dxgglobal_add_host_event(&pt->hdr);

	dma_fence_init(&pt->base, &dxgdmafence_ops, &pt->lock,
		       pt->context, args.fence_value);

	sync_file = sync_file_create(&pt->base);
	if (sync_file == NULL) {
		DXG_ERR("sync_file_create failed");
		ret = -ENOMEM;
		goto cleanup;
	}
	dma_fence_put(&pt->base);

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	syncobj = hmgrtable_get_object(&process->handle_table,
				       args.monitored_fence);
	if (syncobj == NULL) {
		DXG_ERR("invalid syncobj handle %x", args.monitored_fence.v);
		ret = -EINVAL;
	} else {
		if (syncobj->shared) {
			kref_get(&syncobj->syncobj_kref);
			pt->shared_syncobj = syncobj->shared_owner;
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);

	if (pt->shared_syncobj) {
		ret = dxgsharedsyncobj_get_host_nt_handle(pt->shared_syncobj,
						process,
						args.monitored_fence);
		if (ret)
			pt->shared_syncobj = NULL;
	}
	if (ret)
		goto cleanup;

	waitargs.device = args.device;
	waitargs.object_count = 1;
	waitargs.objects = &args.monitored_fence;
	waitargs.fence_values = &args.fence_value;
	ret = dxgvmb_send_wait_sync_object_cpu(process, adapter,
					       &waitargs, false,
					       pt->hdr.event_id);
	if (ret < 0) {
		DXG_ERR("dxgvmb_send_wait_sync_object_cpu failed");
		goto cleanup;
	}

	args.sync_file_handle = (u64)fd;
	ret = copy_to_user(inargs, &args, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy output args");
		ret = -EFAULT;
		goto cleanup;
	}

	fd_install(fd, sync_file->file);

cleanup:
	if (syncobj && syncobj->shared)
		kref_put(&syncobj->syncobj_kref, dxgsyncobject_release);
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device) {
		if (device_lock_acquired)
			dxgdevice_release_lock_shared(device);
		kref_put(&device->device_kref, dxgdevice_release);
	}
	if (ret) {
		if (sync_file) {
			fput(sync_file->file);
			/* sync_file_release will destroy dma_fence */
			pt = NULL;
		}
		if (pt)
			dma_fence_put(&pt->base);
		if (fd >= 0)
			put_unused_fd(fd);
	}
	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

int dxgkio_open_syncobj_from_syncfile(struct dxgprocess *process,
				      void *__user inargs)
{
	struct d3dkmt_opensyncobjectfromsyncfile args;
	int ret = 0;
	struct dxgsyncpoint *pt = NULL;
	struct dma_fence *dmafence = NULL;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct dxgsyncobject *syncobj = NULL;
	struct d3dddi_synchronizationobject_flags flags = { };
	struct d3dkmt_opensyncobjectfromnthandle2 openargs = { };
	struct dxgglobal *dxgglobal = dxggbl();

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EFAULT;
		goto cleanup;
	}

	dmafence = sync_file_get_fence(args.sync_file_handle);
	if (dmafence == NULL) {
		DXG_ERR("failed to get dmafence from handle: %llx",
			args.sync_file_handle);
		ret = -EINVAL;
		goto cleanup;
	}
	pt = to_syncpoint(dmafence);
	if (pt->shared_syncobj == NULL) {
		DXG_ERR("Sync object is not shared");
		goto cleanup;
	}

	device = dxgprocess_device_by_handle(process, args.device);
	if (device == NULL) {
		DXG_ERR("dxgprocess_device_by_handle failed");
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0) {
		DXG_ERR("dxgdevice_acquire_lock_shared failed");
		kref_put(&device->device_kref, dxgdevice_release);
		device = NULL;
		goto cleanup;
	}

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		DXG_ERR("dxgadapter_acquire_lock_shared failed");
		adapter = NULL;
		goto cleanup;
	}

	flags.shared = 1;
	flags.nt_security_sharing = 1;
	syncobj = dxgsyncobject_create(process, device, adapter,
				       _D3DDDI_MONITORED_FENCE, flags);
	if (syncobj == NULL) {
		DXG_ERR("failed to create sync object");
		ret = -ENOMEM;
		goto cleanup;
	}
	dxgsharedsyncobj_add_syncobj(pt->shared_syncobj, syncobj);

	/* Open the shared syncobj to get a local handle */

	openargs.device = device->handle;
	openargs.flags.shared = 1;
	openargs.flags.nt_security_sharing = 1;
	openargs.flags.no_signal = 1;

	ret = dxgvmb_send_open_sync_object_nt(process,
				&dxgglobal->channel, &openargs, syncobj);
	if (ret) {
		DXG_ERR("Failed to open shared syncobj on host");
		goto cleanup;
	}

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	ret = hmgrtable_assign_handle(&process->handle_table,
				      syncobj,
				      HMGRENTRY_TYPE_DXGSYNCOBJECT,
				      openargs.sync_object);
	if (ret == 0) {
		syncobj->handle = openargs.sync_object;
		kref_get(&syncobj->syncobj_kref);
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	args.syncobj = openargs.sync_object;
	args.fence_value = pt->fence_value;
	args.fence_value_cpu_va = openargs.monitored_fence.fence_value_cpu_va;
	args.fence_value_gpu_va = openargs.monitored_fence.fence_value_gpu_va;

	ret = copy_to_user(inargs, &args, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy output args");
		ret = -EFAULT;
	}

cleanup:
	if (dmafence)
		dma_fence_put(dmafence);
	if (ret) {
		if (syncobj) {
			dxgsyncobject_destroy(process, syncobj);
			kref_put(&syncobj->syncobj_kref, dxgsyncobject_release);
		}
	}
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device) {
		dxgdevice_release_lock_shared(device);
		kref_put(&device->device_kref, dxgdevice_release);
	}

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

int dxgkio_wait_sync_file(struct dxgprocess *process, void *__user inargs)
{
	struct d3dkmt_waitsyncfile args;
	struct dma_fence *dmafence = NULL;
	int ret = 0;
	struct dxgsyncpoint *pt = NULL;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct d3dkmthandle syncobj_handle = {};
	bool device_lock_acquired = false;

	ret = copy_from_user(&args, inargs, sizeof(args));
	if (ret) {
		DXG_ERR("failed to copy input args");
		ret = -EFAULT;
		goto cleanup;
	}

	dmafence = sync_file_get_fence(args.sync_file_handle);
	if (dmafence == NULL) {
		DXG_ERR("failed to get dmafence from handle: %llx",
			args.sync_file_handle);
		ret = -EINVAL;
		goto cleanup;
	}
	pt = to_syncpoint(dmafence);

	device = dxgprocess_device_by_object_handle(process,
						    HMGRENTRY_TYPE_DXGCONTEXT,
						    args.context);
	if (device == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}

	ret = dxgdevice_acquire_lock_shared(device);
	if (ret < 0) {
		DXG_ERR("dxgdevice_acquire_lock_shared failed");
		device = NULL;
		goto cleanup;
	}
	device_lock_acquired = true;

	adapter = device->adapter;
	ret = dxgadapter_acquire_lock_shared(adapter);
	if (ret < 0) {
		DXG_ERR("dxgadapter_acquire_lock_shared failed");
		adapter = NULL;
		goto cleanup;
	}

	/* Open the shared syncobj to get a local handle */
	if (pt->shared_syncobj == NULL) {
		DXG_ERR("Sync object is not shared");
		goto cleanup;
	}
	ret = dxgvmb_send_open_sync_object(process,
				device->handle,
				pt->shared_syncobj->host_shared_handle,
				&syncobj_handle);
	if (ret) {
		DXG_ERR("Failed to open shared syncobj on host");
		goto cleanup;
	}

	/* Ask the host to insert the syncobj to the context queue */
	ret = dxgvmb_send_wait_sync_object_gpu(process, adapter,
					       args.context, 1,
					       &syncobj_handle,
					       &pt->fence_value,
					       false);
	if (ret < 0) {
		DXG_ERR("dxgvmb_send_wait_sync_object_cpu failed");
		goto cleanup;
	}

	/*
	 * Destroy the local syncobject immediately. This will not unblock
	 * GPU waiters, but will unblock CPU waiter, which includes the sync
	 * file itself.
	 */
	ret = dxgvmb_send_destroy_sync_object(process, syncobj_handle);

cleanup:
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device) {
		if (device_lock_acquired)
			dxgdevice_release_lock_shared(device);
		kref_put(&device->device_kref, dxgdevice_release);
	}
	if (dmafence)
		dma_fence_put(dmafence);

	DXG_TRACE("ioctl:%s %d", errorstr(ret), ret);
	return ret;
}

static const char *dxgdmafence_get_driver_name(struct dma_fence *fence)
{
	return "dxgkrnl";
}

static const char *dxgdmafence_get_timeline_name(struct dma_fence *fence)
{
	return "no_timeline";
}

static void dxgdmafence_release(struct dma_fence *fence)
{
	struct dxgsyncpoint *syncpoint;

	syncpoint = to_syncpoint(fence);
	if (syncpoint == NULL)
		return;

	if (syncpoint->hdr.event_id)
		dxgglobal_get_host_event(syncpoint->hdr.event_id);

	if (syncpoint->shared_syncobj)
		dxgsharedsyncobj_put(syncpoint->shared_syncobj);

	kfree(syncpoint);
}

static bool dxgdmafence_signaled(struct dma_fence *fence)
{
	struct dxgsyncpoint *syncpoint;

	syncpoint = to_syncpoint(fence);
	if (syncpoint == 0)
		return true;
	return __dma_fence_is_later(syncpoint->fence_value, fence->seqno,
				    fence->ops);
}

static bool dxgdmafence_enable_signaling(struct dma_fence *fence)
{
	return true;
}

static void dxgdmafence_value_str(struct dma_fence *fence,
				  char *str, int size)
{
	snprintf(str, size, "%lld", fence->seqno);
}

static void dxgdmafence_timeline_value_str(struct dma_fence *fence,
					   char *str, int size)
{
	struct dxgsyncpoint *syncpoint;

	syncpoint = to_syncpoint(fence);
	snprintf(str, size, "%lld", syncpoint->fence_value);
}

static const struct dma_fence_ops dxgdmafence_ops = {
	.get_driver_name = dxgdmafence_get_driver_name,
	.get_timeline_name = dxgdmafence_get_timeline_name,
	.enable_signaling = dxgdmafence_enable_signaling,
	.signaled = dxgdmafence_signaled,
	.release = dxgdmafence_release,
	.fence_value_str = dxgdmafence_value_str,
	.timeline_value_str = dxgdmafence_timeline_value_str,
};
