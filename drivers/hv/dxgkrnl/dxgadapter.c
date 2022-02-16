// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2022, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Implementation of dxgadapter and its objects
 *
 */

#include <linux/module.h>
#include <linux/hyperv.h>
#include <linux/pagemap.h>
#include <linux/eventfd.h>

#include "dxgkrnl.h"

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk: " fmt

int dxgadapter_set_vmbus(struct dxgadapter *adapter, struct hv_device *hdev)
{
	int ret;

	guid_to_luid(&hdev->channel->offermsg.offer.if_instance,
		     &adapter->luid);
	DXG_TRACE("%x:%x %p %pUb",
		adapter->luid.b, adapter->luid.a, hdev->channel,
		&hdev->channel->offermsg.offer.if_instance);

	ret = dxgvmbuschannel_init(&adapter->channel, hdev);
	if (ret)
		goto cleanup;

	adapter->channel.adapter = adapter;
	adapter->hv_dev = hdev;

	ret = dxgvmb_send_open_adapter(adapter);
	if (ret < 0) {
		DXG_ERR("dxgvmb_send_open_adapter failed: %d", ret);
		goto cleanup;
	}

	ret = dxgvmb_send_get_internal_adapter_info(adapter);

cleanup:
	if (ret)
		DXG_ERR("Failed to set vmbus: %d", ret);
	return ret;
}

void dxgadapter_start(struct dxgadapter *adapter)
{
	struct dxgvgpuchannel *ch = NULL;
	struct dxgvgpuchannel *entry;
	int ret;
	struct dxgglobal *dxgglobal = dxggbl();

	DXG_TRACE("%x-%x", adapter->luid.a, adapter->luid.b);

	/* Find the corresponding vGPU vm bus channel */
	list_for_each_entry(entry, &dxgglobal->vgpu_ch_list_head,
			    vgpu_ch_list_entry) {
		if (memcmp(&adapter->luid,
			   &entry->adapter_luid,
			   sizeof(struct winluid)) == 0) {
			ch = entry;
			break;
		}
	}
	if (ch == NULL) {
		DXG_TRACE("vGPU chanel is not ready");
		return;
	}

	/* The global channel is initialized when the first adapter starts */
	if (!dxgglobal->global_channel_initialized) {
		ret = dxgglobal_init_global_channel();
		if (ret) {
			dxgglobal_destroy_global_channel();
			return;
		}
		dxgglobal->global_channel_initialized = true;
	}

	/* Initialize vGPU vm bus channel */
	ret = dxgadapter_set_vmbus(adapter, ch->hdev);
	if (ret) {
		DXG_ERR("Failed to start adapter %p", adapter);
		adapter->adapter_state = DXGADAPTER_STATE_STOPPED;
		return;
	}

	adapter->adapter_state = DXGADAPTER_STATE_ACTIVE;
	DXG_TRACE("Adapter started %p", adapter);
}

void dxgadapter_stop(struct dxgadapter *adapter)
{
	bool adapter_stopped = false;

	down_write(&adapter->core_lock);
	if (!adapter->stopping_adapter)
		adapter->stopping_adapter = true;
	else
		adapter_stopped = true;
	up_write(&adapter->core_lock);

	if (adapter_stopped)
		return;

	if (dxgadapter_acquire_lock_exclusive(adapter) == 0) {
		dxgvmb_send_close_adapter(adapter);
		dxgadapter_release_lock_exclusive(adapter);
	}
	dxgvmbuschannel_destroy(&adapter->channel);

	adapter->adapter_state = DXGADAPTER_STATE_STOPPED;
}

void dxgadapter_release(struct kref *refcount)
{
	struct dxgadapter *adapter;

	adapter = container_of(refcount, struct dxgadapter, adapter_kref);
	DXG_TRACE("%p", adapter);
	kfree(adapter);
}

bool dxgadapter_is_active(struct dxgadapter *adapter)
{
	return adapter->adapter_state == DXGADAPTER_STATE_ACTIVE;
}

int dxgadapter_acquire_lock_exclusive(struct dxgadapter *adapter)
{
	down_write(&adapter->core_lock);
	if (adapter->adapter_state != DXGADAPTER_STATE_ACTIVE) {
		dxgadapter_release_lock_exclusive(adapter);
		return -ENODEV;
	}
	return 0;
}

void dxgadapter_acquire_lock_forced(struct dxgadapter *adapter)
{
	down_write(&adapter->core_lock);
}

void dxgadapter_release_lock_exclusive(struct dxgadapter *adapter)
{
	up_write(&adapter->core_lock);
}

int dxgadapter_acquire_lock_shared(struct dxgadapter *adapter)
{
	down_read(&adapter->core_lock);
	if (adapter->adapter_state == DXGADAPTER_STATE_ACTIVE)
		return 0;
	dxgadapter_release_lock_shared(adapter);
	return -ENODEV;
}

void dxgadapter_release_lock_shared(struct dxgadapter *adapter)
{
	up_read(&adapter->core_lock);
}
