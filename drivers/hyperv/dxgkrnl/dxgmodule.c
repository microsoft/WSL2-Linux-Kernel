// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Interface with Linux kernel and the VM bus driver
 *
 */

#include <linux/module.h>
#include <linux/eventfd.h>
#include <linux/hyperv.h>

#include "dxgkrnl.h"

struct dxgglobal *dxgglobal;
struct device *dxgglobaldev;

#define DXGKRNL_VERSION			0x0002
#define PCI_VENDOR_ID_MICROSOFT		0x1414
#define PCI_DEVICE_ID_VIRTUAL_RENDER	0x008E

//
// Interface from dxgglobal
//

struct vmbus_channel *dxgglobal_get_vmbus(void)
{
	return dxgglobal->channel.channel;
}

struct dxgvmbuschannel *dxgglobal_get_dxgvmbuschannel(void)
{
	return &dxgglobal->channel;
}

int dxgglobal_acquire_channel_lock(void)
{
	dxglockorder_acquire(DXGLOCK_GLOBAL_CHANNEL);
	down_read(&dxgglobal->channel_lock);
	if (dxgglobal->channel.channel == NULL) {
		pr_err("Failed to acquire global channel lock");
		return -ENODEV;
	} else {
		return 0;
	}
}

void dxgglobal_release_channel_lock(void)
{
	up_read(&dxgglobal->channel_lock);
	dxglockorder_release(DXGLOCK_GLOBAL_CHANNEL);
}

void dxgglobal_acquire_adapter_list_lock(enum dxglockstate state)
{
	TRACE_DEBUG(1, "%s", __func__);
	dxglockorder_acquire(DXGLOCK_GLOBAL_ADAPTERLIST);
	if (state == DXGLOCK_EXCL)
		down_write(&dxgglobal->adapter_list_lock);
	else
		down_read(&dxgglobal->adapter_list_lock);
}

void dxgglobal_release_adapter_list_lock(enum dxglockstate state)
{
	TRACE_DEBUG(1, "%s", __func__);
	if (state == DXGLOCK_EXCL)
		up_write(&dxgglobal->adapter_list_lock);
	else
		up_read(&dxgglobal->adapter_list_lock);
	dxglockorder_release(DXGLOCK_GLOBAL_ADAPTERLIST);
}

void dxgglobal_add_host_event(struct dxghostevent *event)
{
	spin_lock_irq(&dxgglobal->host_event_list_mutex);
	list_add_tail(&event->host_event_list_entry,
		      &dxgglobal->host_event_list_head);
	spin_unlock_irq(&dxgglobal->host_event_list_mutex);
}

void dxgglobal_remove_host_event(struct dxghostevent *event)
{
	spin_lock_irq(&dxgglobal->host_event_list_mutex);
	if (event->host_event_list_entry.next != NULL) {
		list_del(&event->host_event_list_entry);
		event->host_event_list_entry.next = NULL;
	}
	spin_unlock_irq(&dxgglobal->host_event_list_mutex);
}

void dxgglobal_signal_host_event(u64 event_id)
{
	struct dxghostevent *event;
	unsigned long flags;

	TRACE_DEBUG(1, "%s %lld\n", __func__, event_id);

	spin_lock_irqsave(&dxgglobal->host_event_list_mutex, flags);
	list_for_each_entry(event, &dxgglobal->host_event_list_head,
			    host_event_list_entry) {
		if (event->event_id == event_id) {
			TRACE_DEBUG(1, "found event to signal %lld\n",
				    event_id);
			if (event->remove_from_list ||
			    event->destroy_after_signal) {
				list_del(&event->host_event_list_entry);
				event->host_event_list_entry.next = NULL;
				TRACE_DEBUG(1, "removing event from list\n");
			}
			if (event->cpu_event) {
				TRACE_DEBUG(1, "signal cpu event\n");
				eventfd_signal(event->cpu_event, 1);
				if (event->destroy_after_signal)
					eventfd_ctx_put(event->cpu_event);
			} else {
				TRACE_DEBUG(1, "signal completion\n");
				complete(event->completion_event);
			}
			if (event->destroy_after_signal) {
				TRACE_DEBUG(1, "destroying event %p\n", event);
				dxgmem_free(event->process,
					    DXGMEM_EVENT, event);
			}
			break;
		}
	}
	spin_unlock_irqrestore(&dxgglobal->host_event_list_mutex, flags);
	TRACE_DEBUG(1, "dxgglobal_signal_host_event_end %lld\n", event_id);
}

struct dxghostevent *dxgglobal_get_host_event(u64 event_id)
{
	struct dxghostevent *entry;
	struct dxghostevent *event = NULL;

	spin_lock_irq(&dxgglobal->host_event_list_mutex);
	list_for_each_entry(entry, &dxgglobal->host_event_list_head,
			    host_event_list_entry) {
		if (entry->event_id == event_id) {
			list_del(&entry->host_event_list_entry);
			entry->host_event_list_entry.next = NULL;
			event = entry;
			break;
		}
	}
	spin_unlock_irq(&dxgglobal->host_event_list_mutex);
	return event;
}

u64 dxgglobal_new_host_event_id(void)
{
	return atomic64_inc_return(&dxgglobal->host_event_id);
}

void dxgglobal_acquire_process_adapter_lock(void)
{
	dxgmutex_lock(&dxgglobal->process_adapter_mutex);
}

void dxgglobal_release_process_adapter_lock(void)
{
	dxgmutex_unlock(&dxgglobal->process_adapter_mutex);
}

/*
 * File operations
 */

static struct dxgprocess *dxgglobal_get_current_process(void)
{
	/*
	 * Find the DXG process for the current process.
	 * A new process is created if necessary.
	 */
	struct dxgprocess *process = NULL;
	struct dxgprocess *entry = NULL;

	dxgmutex_lock(&dxgglobal->plistmutex);
	list_for_each_entry(entry, &dxgglobal->plisthead, plistentry) {
		/* All threads of a process have the same thread group ID */
		if (entry->process->tgid == current->tgid) {
			entry->refcount++;
			process = entry;
			TRACE_DEBUG(1, "found dxgprocess entry\n");
			break;
		}
	}
	dxgmutex_unlock(&dxgglobal->plistmutex);

	if (process == NULL)
		process = dxgprocess_create();

	return process;
}

static int dxgk_open(struct inode *n, struct file *f)
{
	int ret = 0;
	struct dxgprocess *process;
	struct dxgthreadinfo *thread;

	TRACE_DEBUG2(1, 0, "%s %p %d %d",
		     __func__, f, current->pid, current->tgid);

	thread = dxglockorder_get_thread();

	/* Find/create a dxgprocess structure for this process */
	process = dxgglobal_get_current_process();

	if (process) {
		f->private_data = process;
	} else {
		TRACE_DEBUG(1, "cannot create dxgprocess for open\n");
		ret = -EBADF;
	}

	dxglockorder_put_thread(thread);
	TRACE_DEBUG2(1, 0, "%s end %x", __func__, ret);
	return ret;
}

static int dxgk_release(struct inode *n, struct file *f)
{
	struct dxgthreadinfo *thread;
	struct dxgprocess *process;

	process = (struct dxgprocess *)f->private_data;
	TRACE_DEBUG2(1, 0, "%s %p, %p", __func__, f, process);

	if (process == NULL)
		return -EINVAL;

	thread = dxglockorder_get_thread();

	dxgprocess_release_reference(process);

	dxglockorder_check_empty(thread);
	dxglockorder_put_thread(thread);

	f->private_data = NULL;
	TRACE_DEBUG2(1, 0, "%s end", __func__);
	return 0;
}

static ssize_t dxgk_read(struct file *f, char __user *s, size_t len,
			 loff_t *o)
{
	TRACE_DEBUG(1, "file read\n");
	return 0;
}

static ssize_t dxgk_write(struct file *f, const char __user *s, size_t len,
			  loff_t *o)
{
	TRACE_DEBUG(1, "file write\n");
	return len;
}

const struct file_operations dxgk_fops = {
	.owner = THIS_MODULE,
	.open = dxgk_open,
	.release = dxgk_release,
	.compat_ioctl = dxgk_compat_ioctl,
	.unlocked_ioctl = dxgk_unlocked_ioctl,
	.write = dxgk_write,
	.read = dxgk_read,
};

/*
 * Interface with the VM bus driver
 */

static int dxgglobal_getiospace(struct dxgglobal *dxgglobal)
{
	/* Get mmio space for the global channel */
	struct hv_device *hdev = dxgglobal->hdev;
	struct vmbus_channel *channel = hdev->channel;
	resource_size_t pot_start = 0;
	resource_size_t pot_end = -1;
	int ret;

	dxgglobal->mmiospace_size = channel->offermsg.offer.mmio_megabytes;
	if (dxgglobal->mmiospace_size == 0) {
		TRACE_DEBUG(1, "zero mmio space is offered\n");
		return -ENOMEM;
	}
	dxgglobal->mmiospace_size <<= 20;
	TRACE_DEBUG(1, "mmio offered: %llx\n", dxgglobal->mmiospace_size);

	ret = vmbus_allocate_mmio(&dxgglobal->mem, hdev, pot_start, pot_end,
				  dxgglobal->mmiospace_size, 0x10000, false);
	if (ret) {
		pr_err("Unable to allocate mmio memory: %d\n", ret);
		return ret;
	}
	dxgglobal->mmiospace_size = dxgglobal->mem->end -
	    dxgglobal->mem->start + 1;
	dxgglobal->mmiospace_base = dxgglobal->mem->start;
	TRACE_DEBUG(1, "mmio allocated %llx  %llx %llx %llx\n",
		    dxgglobal->mmiospace_base,
		    dxgglobal->mmiospace_size,
		    dxgglobal->mem->start, dxgglobal->mem->end);

	return 0;
}

static int dxgglobal_init_global_channel(struct hv_device *hdev)
{
	int ret = 0;

	TRACE_DEBUG(1, "%s %x  %x", __func__, hdev->vendor_id, hdev->device_id);
	{
		TRACE_DEBUG(1, "device type   : %pUb\n", &hdev->dev_type);
		TRACE_DEBUG(1, "device channel: %pUb %p primary: %p\n",
			    &hdev->channel->offermsg.offer.if_type,
			    hdev->channel, hdev->channel->primary_channel);
	}

	if (dxgglobal->hdev) {
		/* This device should appear only once */
		pr_err("dxgglobal already initialized\n");
		ret = -EBADE;
		goto error;
	}

	dxgglobal->hdev = hdev;

	ret = dxgvmbuschannel_init(&dxgglobal->channel, hdev);
	if (ret) {
		pr_err("dxgvmbuschannel_init failed: %d\n", ret);
		goto error;
	}

	ret = dxgglobal_getiospace(dxgglobal);
	if (ret) {
		pr_err("getiospace failed: %d\n", ret);
		goto error;
	}

	ret = dxgvmb_send_set_iospace_region(dxgglobal->mmiospace_base,
					     dxgglobal->mmiospace_size, 0);
	if (ISERROR(ret)) {
		pr_err("send_set_iospace_region failed");
		goto error;
	}

	hv_set_drvdata(hdev, dxgglobal);

	dxgglobal->dxgdevice.minor = MISC_DYNAMIC_MINOR;
	dxgglobal->dxgdevice.name = "dxg";
	dxgglobal->dxgdevice.fops = &dxgk_fops;
	dxgglobal->dxgdevice.mode = 0666;
	ret = misc_register(&dxgglobal->dxgdevice);
	if (ret) {
		pr_err("misc_register failed: %d", ret);
		goto error;
	}
	dxgglobaldev = dxgglobal->dxgdevice.this_device;
	dxgglobal->device_initialized = true;

error:
	return ret;
}

static void dxgglobal_destroy_global_channel(void)
{
	dxglockorder_acquire(DXGLOCK_GLOBAL_CHANNEL);
	down_write(&dxgglobal->channel_lock);

	TRACE_DEBUG(1, "%s", __func__);

	if (dxgglobal->device_initialized) {
		misc_deregister(&dxgglobal->dxgdevice);
		dxgglobal->device_initialized = false;
		dxgglobaldev = NULL;
	}

	if (dxgglobal->mem) {
		vmbus_free_mmio(dxgglobal->mmiospace_base,
				dxgglobal->mmiospace_size);
		dxgglobal->mem = NULL;
	}

	dxgvmbuschannel_destroy(&dxgglobal->channel);

	if (dxgglobal->hdev) {
		hv_set_drvdata(dxgglobal->hdev, NULL);
		dxgglobal->hdev = NULL;
	}

	TRACE_DEBUG(1, "%s end\n", __func__);

	up_write(&dxgglobal->channel_lock);
	dxglockorder_release(DXGLOCK_GLOBAL_CHANNEL);
}

static int dxgglobal_create_adapter(struct hv_device *hdev)
{
	struct dxgadapter *adapter;
	int ret;

	TRACE_DEBUG(1, "%s", __func__);

	adapter = dxgmem_alloc(NULL, DXGMEM_ADAPTER, sizeof(struct dxgadapter));
	if (adapter == NULL) {
		pr_err("failed to allocated dxgadapter\n");
		return -ENOMEM;
	}

	ret = dxgadapter_init(adapter, hdev);
	if (ret) {
		dxgadapter_stop(adapter);
		dxgadapter_release_reference(adapter);
	} else {
		dxgglobal_acquire_adapter_list_lock(DXGLOCK_EXCL);

		TRACE_DEBUG(1, "new adapter added %p\n", adapter);

		list_add_tail(&adapter->adapter_list_entry,
			      &dxgglobal->adapter_list_head);
		dxgglobal->num_adapters++;

		dxgglobal_release_adapter_list_lock(DXGLOCK_EXCL);
	}

	TRACE_DEBUG(1, "%s end: %d\n", __func__, ret);
	return ret;
}

static void dxgglobal_stop_adapter(struct hv_device *hdev)
{
	struct dxgadapter *adapter = NULL;
	struct dxgadapter *entry;
	struct winluid luid;

	guid_to_luid(&hdev->channel->offermsg.offer.if_instance, &luid);

	TRACE_DEBUG(1, "%s: %x:%x\n", __func__, luid.b, luid.a);

	dxgglobal_acquire_adapter_list_lock(DXGLOCK_EXCL);

	list_for_each_entry(entry, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (*(u64 *) &luid == *(u64 *) &entry->luid) {
			adapter = entry;
			break;
		}
	}

	if (adapter)
		list_del(&adapter->adapter_list_entry);

	dxgglobal_release_adapter_list_lock(DXGLOCK_EXCL);

	if (adapter) {
		dxgadapter_stop(adapter);
		dxgadapter_release_reference(adapter);
	} else {
		pr_err("Adapter is not found\n");
	}

	TRACE_DEBUG(1, "%s end", __func__);
}

static const struct hv_vmbus_device_id id_table[] = {
	/* Per GPU Device GUID */
	{ HV_GPUP_DXGK_VGPU_GUID },
	/* Global Dxgkgnl channel for the virtual machine */
	{ HV_GPUP_DXGK_GLOBAL_GUID },
	{ }
};

static int dxg_probe_device(struct hv_device *hdev,
			    const struct hv_vmbus_device_id *dev_id)
{
	int ret = 0;
	struct dxgthreadinfo *thread = dxglockorder_get_thread();

	dxgmutex_lock(&dxgglobal->device_mutex);

	TRACE_DEBUG(1, "probe_device\n");

	if (uuid_le_cmp(hdev->dev_type, id_table[0].guid) == 0) {
		/* This is a new virtual GPU channel */
		ret = dxgglobal_create_adapter(hdev);
	} else if (uuid_le_cmp(hdev->dev_type, id_table[1].guid) == 0) {
		/* This is the global Dxgkgnl channel */
		ret = dxgglobal_init_global_channel(hdev);
		if (ret) {
			dxgglobal_destroy_global_channel();
			goto error;
		}
	} else {
		/* Unknown device type */
		pr_err("probe: unknown device type\n");
		ret = -EBADE;
		goto error;
	}

error:

	TRACE_DEBUG(1, "probe_device end\n");

	dxgmutex_unlock(&dxgglobal->device_mutex);

	dxglockorder_put_thread(thread);

	return ret;
}

static int dxg_remove_device(struct hv_device *hdev)
{
	int ret = 0;
	struct dxgthreadinfo *thread;

	TRACE_DEBUG(1, "%s\n", __func__);

	thread = dxglockorder_get_thread();
	dxgmutex_lock(&dxgglobal->device_mutex);

	if (uuid_le_cmp(hdev->dev_type, id_table[0].guid) == 0) {
		TRACE_DEBUG(1, "Remove virtual GPU\n");
		dxgglobal_stop_adapter(hdev);
	} else if (uuid_le_cmp(hdev->dev_type, id_table[1].guid) == 0) {
		TRACE_DEBUG(1, "Remove global channel device\n");
		dxgglobal_destroy_global_channel();
	} else {
		/* Unknown device type */
		pr_err("remove: unknown device type\n");
		ret = -EBADE;
	}

	dxgmutex_unlock(&dxgglobal->device_mutex);
	dxglockorder_put_thread(thread);
	return ret;
}

MODULE_DEVICE_TABLE(vmbus, id_table);

static struct hv_driver dxg_drv = {
	.name = KBUILD_MODNAME,
	.id_table = id_table,
	.probe = dxg_probe_device,
	.remove = dxg_remove_device,
	.driver = {
		   .probe_type = PROBE_PREFER_ASYNCHRONOUS,
		    },
};

/*
 * Interface with Linux kernel
 */

static int dxgglobal_create(void)
{
	int ret = 0;

	TRACE_DEBUG(1, "%s", __func__);

	dxgglobal = dxgmem_alloc(NULL, DXGMEM_GLOBAL, sizeof(struct dxgglobal));
	if (!dxgglobal) {
		pr_err("no memory for dxgglobal\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&dxgglobal->plisthead);
	dxgmutex_init(&dxgglobal->plistmutex, DXGLOCK_PROCESSLIST);
	dxgmutex_init(&dxgglobal->device_mutex, DXGLOCK_GLOBAL_DEVICE);
	dxgmutex_init(&dxgglobal->process_adapter_mutex,
		      DXGLOCK_PROCESSADAPTER);

	INIT_LIST_HEAD(&dxgglobal->thread_info_list_head);
	mutex_init(&dxgglobal->thread_info_mutex);

	INIT_LIST_HEAD(&dxgglobal->adapter_list_head);
	init_rwsem(&dxgglobal->adapter_list_lock);

	init_rwsem(&dxgglobal->channel_lock);

	INIT_LIST_HEAD(&dxgglobal->host_event_list_head);
	spin_lock_init(&dxgglobal->host_event_list_mutex);
	atomic64_set(&dxgglobal->host_event_id, 1);

	hmgrtable_init(&dxgglobal->handle_table, NULL);

	TRACE_DEBUG(1, "dxgglobal_init end\n");
	return ret;
}

static void dxgglobal_destroy(void)
{
	if (dxgglobal) {
		TRACE_DEBUG(1, "%s\n", __func__);

		if (dxgglobal->vmbus_registered)
			vmbus_driver_unregister(&dxg_drv);

		dxgglobal_destroy_global_channel();
		hmgrtable_destroy(&dxgglobal->handle_table);

		dxgmem_free(NULL, DXGMEM_GLOBAL, dxgglobal);
		dxgglobal = NULL;
		TRACE_DEBUG(1, "%s end\n", __func__);
	}
}

static int __init dxg_drv_init(void)
{
	int ret;

	pr_err("%s  Version: %x", __func__, DXGKRNL_VERSION);

	ret = dxgglobal_create();
	if (ret) {
		pr_err("dxgglobal_init failed");
		return -ENOMEM;
	}

	ret = vmbus_driver_register(&dxg_drv);
	if (ret) {
		pr_err("vmbus_driver_register failed: %d", ret);
		return ret;
	}
	dxgglobal->vmbus_registered = true;

	init_ioctls();

	return 0;
}

static void __exit dxg_drv_exit(void)
{
	struct dxgthreadinfo *thread;

	TRACE_DEBUG(1, "%s\n", __func__);

	thread = dxglockorder_get_thread();
	dxgglobal_destroy();
	thread->lock_held = true;	/* No need to acquire internal locks */
	dxglockorder_put_thread(thread);
	dxgmem_check(NULL, DXGMEM_GLOBAL);

	TRACE_DEBUG(1, "%s end\n", __func__);
}

module_init(dxg_drv_init);
module_exit(dxg_drv_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Microsoft Dxgkrnl virtual GPU Driver");
