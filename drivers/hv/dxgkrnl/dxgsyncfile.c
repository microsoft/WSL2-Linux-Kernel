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
	int fd = get_unused_fd_flags(O_CLOEXEC);
	struct sync_file *sync_file = NULL;
	struct dxgdevice *device = NULL;
	struct dxgadapter *adapter = NULL;
	struct d3dkmt_waitforsynchronizationobjectfromcpu waitargs = {};

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
	if (adapter)
		dxgadapter_release_lock_shared(adapter);
	if (device)
		dxgdevice_release_lock_shared(device);
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
	if (syncpoint) {
		if (syncpoint->hdr.event_id)
			dxgglobal_get_host_event(syncpoint->hdr.event_id);
		kfree(syncpoint);
	}
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
