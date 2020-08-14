// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Interface with Linux kernel and the VM bus driver
 *
 */

#include <linux/module.h>
#include <linux/eventfd.h>
#include <linux/hyperv.h>
#include <linux/pci.h>

#include "dxgkrnl.h"

struct dxgglobal *dxgglobal;
struct device *dxgglobaldev;

#define DXGKRNL_VERSION			0x2108
#define PCI_VENDOR_ID_MICROSOFT		0x1414
#define PCI_DEVICE_ID_VIRTUAL_RENDER	0x008E

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk:err: " fmt
#undef dev_fmt
#define dev_fmt(fmt)	"dxgk: " fmt

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
}

void dxgglobal_acquire_adapter_list_lock(enum dxglockstate state)
{
	if (state == DXGLOCK_EXCL)
		down_write(&dxgglobal->adapter_list_lock);
	else
		down_read(&dxgglobal->adapter_list_lock);
}

void dxgglobal_release_adapter_list_lock(enum dxglockstate state)
{
	if (state == DXGLOCK_EXCL)
		up_write(&dxgglobal->adapter_list_lock);
	else
		up_read(&dxgglobal->adapter_list_lock);
}

struct dxgadapter *find_pci_adapter(struct pci_dev *dev)
{
	struct dxgadapter *entry;
	struct dxgadapter *adapter = NULL;

	dxgglobal_acquire_adapter_list_lock(DXGLOCK_EXCL);

	list_for_each_entry(entry, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (dev == entry->pci_dev) {
			adapter = entry;
			break;
		}
	}

	dxgglobal_release_adapter_list_lock(DXGLOCK_EXCL);
	return adapter;
}

static struct dxgadapter *find_adapter(struct winluid *luid)
{
	struct dxgadapter *entry;
	struct dxgadapter *adapter = NULL;

	dxgglobal_acquire_adapter_list_lock(DXGLOCK_EXCL);

	list_for_each_entry(entry, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (memcmp(luid, &entry->luid, sizeof(struct winluid)) == 0) {
			adapter = entry;
			break;
		}
	}

	dxgglobal_release_adapter_list_lock(DXGLOCK_EXCL);
	return adapter;
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

	dev_dbg(dxgglobaldev, "%s %lld\n", __func__, event_id);

	spin_lock_irqsave(&dxgglobal->host_event_list_mutex, flags);
	list_for_each_entry(event, &dxgglobal->host_event_list_head,
			    host_event_list_entry) {
		if (event->event_id == event_id) {
			dev_dbg(dxgglobaldev, "found event to signal %lld\n",
				    event_id);
			if (event->remove_from_list ||
			    event->destroy_after_signal) {
				list_del(&event->host_event_list_entry);
				event->host_event_list_entry.next = NULL;
			}
			if (event->cpu_event) {
				dev_dbg(dxgglobaldev, "signal cpu event\n");
				eventfd_signal(event->cpu_event, 1);
				if (event->destroy_after_signal)
					eventfd_ctx_put(event->cpu_event);
			} else {
				dev_dbg(dxgglobaldev, "signal completion\n");
				complete(event->completion_event);
			}
			if (event->destroy_after_signal) {
				dev_dbg(dxgglobaldev, "destroying event %p\n",
					event);
				vfree(event);
			}
			break;
		}
	}
	spin_unlock_irqrestore(&dxgglobal->host_event_list_mutex, flags);
	dev_dbg(dxgglobaldev, "dxgglobal_signal_host_event_end %lld\n",
		event_id);
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
	mutex_lock(&dxgglobal->process_adapter_mutex);
}

void dxgglobal_release_process_adapter_lock(void)
{
	mutex_unlock(&dxgglobal->process_adapter_mutex);
}

int dxgglobal_create_adapter(struct pci_dev *dev, guid_t *guid,
			     struct winluid host_vgpu_luid)
{
	struct dxgadapter *adapter;
	int ret = 0;

	adapter = vzalloc(sizeof(struct dxgadapter));
	if (adapter == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	adapter->adapter_state = DXGADAPTER_STATE_WAITING_VMBUS;
	adapter->host_vgpu_luid = host_vgpu_luid;
	kref_init(&adapter->adapter_kref);
	init_rwsem(&adapter->core_lock);

	INIT_LIST_HEAD(&adapter->adapter_process_list_head);
	INIT_LIST_HEAD(&adapter->shared_resource_list_head);
	INIT_LIST_HEAD(&adapter->adapter_shared_syncobj_list_head);
	INIT_LIST_HEAD(&adapter->syncobj_list_head);
	init_rwsem(&adapter->shared_resource_list_lock);
	adapter->pci_dev = dev;
	guid_to_luid(guid, &adapter->luid);

	dxgglobal_acquire_adapter_list_lock(DXGLOCK_EXCL);

	list_add_tail(&adapter->adapter_list_entry,
		      &dxgglobal->adapter_list_head);
	dxgglobal->num_adapters++;
	dxgglobal_release_adapter_list_lock(DXGLOCK_EXCL);

	dev_dbg(dxgglobaldev, "new adapter added %p %x-%x\n", adapter,
		    adapter->luid.a, adapter->luid.b);
cleanup:
	dev_dbg(dxgglobaldev, "%s end: %d", __func__, ret);
	return ret;
}

static void dxgglobal_start_adapters(void)
{
	struct dxgadapter *adapter;

	if (dxgglobal->hdev == NULL) {
		dev_dbg(dxgglobaldev, "Global channel is not ready");
		return;
	}
	dxgglobal_acquire_adapter_list_lock(DXGLOCK_EXCL);
	list_for_each_entry(adapter, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (adapter->adapter_state == DXGADAPTER_STATE_WAITING_VMBUS)
			dxgadapter_start(adapter);
	}
	dxgglobal_release_adapter_list_lock(DXGLOCK_EXCL);
}

static void dxgglobal_stop_adapters(void)
{
	struct dxgadapter *adapter;

	if (dxgglobal->hdev == NULL) {
		dev_dbg(dxgglobaldev, "Global channel is not ready");
		return;
	}
	dxgglobal_acquire_adapter_list_lock(DXGLOCK_EXCL);
	list_for_each_entry(adapter, &dxgglobal->adapter_list_head,
			    adapter_list_entry) {
		if (adapter->adapter_state == DXGADAPTER_STATE_ACTIVE)
			dxgadapter_stop(adapter);
	}
	dxgglobal_release_adapter_list_lock(DXGLOCK_EXCL);
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

	mutex_lock(&dxgglobal->plistmutex);
	list_for_each_entry(entry, &dxgglobal->plisthead, plistentry) {
		/* All threads of a process have the same thread group ID */
		if (entry->process->tgid == current->tgid) {
			if (kref_get_unless_zero(&entry->process_kref)) {
				process = entry;
				dev_dbg(dxgglobaldev, "found dxgprocess");
			} else {
				dev_dbg(dxgglobaldev, "process is destroyed");
			}
			break;
		}
	}
	mutex_unlock(&dxgglobal->plistmutex);

	if (process == NULL)
		process = dxgprocess_create();

	return process;
}

static int dxgk_open(struct inode *n, struct file *f)
{
	int ret = 0;
	struct dxgprocess *process;

	dev_dbg(dxgglobaldev, "%s %p %d %d",
		     __func__, f, current->pid, current->tgid);


	/* Find/create a dxgprocess structure for this process */
	process = dxgglobal_get_current_process();

	if (process) {
		f->private_data = process;
	} else {
		dev_dbg(dxgglobaldev, "cannot create dxgprocess for open\n");
		ret = -EBADF;
	}

	dev_dbg(dxgglobaldev, "%s end %x", __func__, ret);
	return ret;
}

static int dxgk_release(struct inode *n, struct file *f)
{
	struct dxgprocess *process;

	process = (struct dxgprocess *)f->private_data;
	dev_dbg(dxgglobaldev, "%s %p, %p", __func__, f, process);

	if (process == NULL)
		return -EINVAL;

	kref_put(&process->process_kref, dxgprocess_release);

	f->private_data = NULL;
	return 0;
}

static ssize_t dxgk_read(struct file *f, char __user *s, size_t len,
			 loff_t *o)
{
	dev_dbg(dxgglobaldev, "file read\n");
	return 0;
}

static ssize_t dxgk_write(struct file *f, const char __user *s, size_t len,
			  loff_t *o)
{
	dev_dbg(dxgglobaldev, "file write\n");
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
 * Interface with the PCI driver
 */

/*
 * Part of the CPU config space of the vGPU device is used for vGPU
 * configuration data. Reading/writing of the PCI config space is forwarded
 * to the host.
 */

/* vGPU VM bus channel instance ID */
const int DXGK_VMBUS_CHANNEL_ID_OFFSET	= 192;
/* DXGK_VMBUS_INTERFACE_VERSION (u32) */
const int DXGK_VMBUS_VERSION_OFFSET	= DXGK_VMBUS_CHANNEL_ID_OFFSET +
					  sizeof(guid_t);
/* Luid of the virtual GPU on the host (struct winluid) */
const int DXGK_VMBUS_VGPU_LUID_OFFSET	= DXGK_VMBUS_VERSION_OFFSET +
					  sizeof(u32);
/* The guest writes its capavilities to this adderss */
const int DXGK_VMBUS_GUESTCAPS_OFFSET	= DXGK_VMBUS_VERSION_OFFSET +
					  sizeof(u32);

struct dxgk_vmbus_guestcaps {
	union {
		struct {
			u32	wsl2		: 1;
			u32	reserved	: 31;
		};
		u32 guest_caps;
	};
};

static int dxg_pci_read_dwords(struct pci_dev *dev, int offset, int size,
			       void *val)
{
	int off = offset;
	int ret;
	int i;

	for (i = 0; i < size / sizeof(int); i++) {
		ret = pci_read_config_dword(dev, off, &((int *)val)[i]);
		if (ret) {
			pr_err("Failed to read PCI config: %d", off);
			return ret;
		}
		off += sizeof(int);
	}
	return 0;
}

static int dxg_pci_probe_device(struct pci_dev *dev,
				const struct pci_device_id *id)
{
	int ret;
	guid_t guid;
	u32 vmbus_interface_ver = DXGK_VMBUS_INTERFACE_VERSION;
	struct winluid vgpu_luid = {};
	struct dxgk_vmbus_guestcaps guest_caps = {.wsl2 = 1};

	mutex_lock(&dxgglobal->device_mutex);

	if (dxgglobal->vmbus_ver == 0)  {
		/* Report capabilities to the host */

		ret = pci_write_config_dword(dev, DXGK_VMBUS_GUESTCAPS_OFFSET,
					guest_caps.guest_caps);
		if (ret)
			goto cleanup;

		/* Negotiate the VM bus version */

		ret = pci_read_config_dword(dev, DXGK_VMBUS_VERSION_OFFSET,
					&vmbus_interface_ver);
		if (ret == 0 && vmbus_interface_ver != 0)
			dxgglobal->vmbus_ver = vmbus_interface_ver;
		else
			dxgglobal->vmbus_ver = DXGK_VMBUS_INTERFACE_VERSION_OLD;

		if (dxgglobal->vmbus_ver < DXGK_VMBUS_INTERFACE_VERSION)
			goto read_channel_id;

		ret = pci_write_config_dword(dev, DXGK_VMBUS_VERSION_OFFSET,
					DXGK_VMBUS_INTERFACE_VERSION);
		if (ret)
			goto cleanup;

		if (dxgglobal->vmbus_ver > DXGK_VMBUS_INTERFACE_VERSION)
			dxgglobal->vmbus_ver = DXGK_VMBUS_INTERFACE_VERSION;
	}

read_channel_id:

	/* Get the VM bus channel ID for the virtual GPU */
	ret = dxg_pci_read_dwords(dev, DXGK_VMBUS_CHANNEL_ID_OFFSET,
				sizeof(guid), (int *)&guid);
	if (ret)
		goto cleanup;

	if (dxgglobal->vmbus_ver >= DXGK_VMBUS_INTERFACE_VERSION) {
		ret = dxg_pci_read_dwords(dev, DXGK_VMBUS_VGPU_LUID_OFFSET,
					  sizeof(vgpu_luid), &vgpu_luid);
		if (ret)
			goto cleanup;
	}

	/* Create new virtual GPU adapter */

	dev_dbg(dxgglobaldev, "Adapter channel: %pUb\n", &guid);
	dev_dbg(dxgglobaldev, "Vmbus interface version: %d\n",
		dxgglobal->vmbus_ver);
	dev_dbg(dxgglobaldev, "Host vGPU luid: %x-%x\n",
		vgpu_luid.b, vgpu_luid.a);

	ret = dxgglobal_create_adapter(dev, &guid, vgpu_luid);
	if (ret)
		goto cleanup;

	dxgglobal_start_adapters();

cleanup:

	mutex_unlock(&dxgglobal->device_mutex);

	if (ret)
		dev_dbg(dxgglobaldev, "err: %s %d", __func__, ret);
	return ret;
}

static void dxg_pci_remove_device(struct pci_dev *dev)
{
	struct dxgadapter *adapter;

	mutex_lock(&dxgglobal->device_mutex);

	adapter = find_pci_adapter(dev);
	if (adapter) {
		dxgglobal_acquire_adapter_list_lock(DXGLOCK_EXCL);
		list_del(&adapter->adapter_list_entry);
		dxgglobal->num_adapters--;
		dxgglobal_release_adapter_list_lock(DXGLOCK_EXCL);

		dxgadapter_stop(adapter);
		kref_put(&adapter->adapter_kref, dxgadapter_release);
	} else {
		pr_err("Failed to find dxgadapter");
	}

	mutex_unlock(&dxgglobal->device_mutex);
}

static struct pci_device_id dxg_pci_id_table = {
	.vendor = PCI_VENDOR_ID_MICROSOFT,
	.device = PCI_DEVICE_ID_VIRTUAL_RENDER,
	.subvendor = PCI_ANY_ID,
	.subdevice = PCI_ANY_ID
};

static struct pci_driver dxg_pci_drv = {
	.name = KBUILD_MODNAME,
	.id_table = &dxg_pci_id_table,
	.probe = dxg_pci_probe_device,
	.remove = dxg_pci_remove_device
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
		dev_dbg(dxgglobaldev, "zero mmio space is offered\n");
		return -ENOMEM;
	}
	dxgglobal->mmiospace_size <<= 20;
	dev_dbg(dxgglobaldev, "mmio offered: %llx\n",
		dxgglobal->mmiospace_size);

	ret = vmbus_allocate_mmio(&dxgglobal->mem, hdev, pot_start, pot_end,
				  dxgglobal->mmiospace_size, 0x10000, false);
	if (ret) {
		pr_err("Unable to allocate mmio memory: %d\n", ret);
		return ret;
	}
	dxgglobal->mmiospace_size = dxgglobal->mem->end -
	    dxgglobal->mem->start + 1;
	dxgglobal->mmiospace_base = dxgglobal->mem->start;
	dev_info(dxgglobaldev, "mmio allocated %llx  %llx %llx %llx\n",
		 dxgglobal->mmiospace_base,
		 dxgglobal->mmiospace_size,
		 dxgglobal->mem->start, dxgglobal->mem->end);

	return 0;
}

int dxgglobal_init_global_channel(void)
{
	int ret = 0;

	ret = dxgvmbuschannel_init(&dxgglobal->channel, dxgglobal->hdev);
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
	if (ret < 0) {
		pr_err("send_set_iospace_region failed");
		goto error;
	}

	hv_set_drvdata(dxgglobal->hdev, dxgglobal);

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
	dxgglobal->dxg_dev_initialized = true;

error:
	return ret;
}

void dxgglobal_destroy_global_channel(void)
{
	down_write(&dxgglobal->channel_lock);

	dxgglobal->global_channel_initialized = false;

	if (dxgglobal->dxg_dev_initialized) {
		misc_deregister(&dxgglobal->dxgdevice);
		dxgglobal->dxg_dev_initialized = false;
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

	up_write(&dxgglobal->channel_lock);
}

static void dxgglobal_stop_adapter_vmbus(struct hv_device *hdev)
{
	struct dxgadapter *adapter = NULL;
	struct winluid luid;

	guid_to_luid(&hdev->channel->offermsg.offer.if_instance, &luid);

	dev_dbg(dxgglobaldev, "%s: %x:%x\n", __func__, luid.b, luid.a);

	adapter = find_adapter(&luid);

	if (adapter && adapter->adapter_state == DXGADAPTER_STATE_ACTIVE) {
		down_write(&adapter->core_lock);
		dxgvmbuschannel_destroy(&adapter->channel);
		adapter->adapter_state = DXGADAPTER_STATE_STOPPED;
		up_write(&adapter->core_lock);
	}
}

static const struct hv_vmbus_device_id id_table[] = {
	/* Per GPU Device GUID */
	{ HV_GPUP_DXGK_VGPU_GUID },
	/* Global Dxgkgnl channel for the virtual machine */
	{ HV_GPUP_DXGK_GLOBAL_GUID },
	{ }
};

static int dxg_probe_vmbus(struct hv_device *hdev,
			   const struct hv_vmbus_device_id *dev_id)
{
	int ret = 0;
	struct winluid luid;
	struct dxgvgpuchannel *vgpuch;

	mutex_lock(&dxgglobal->device_mutex);

	if (uuid_le_cmp(hdev->dev_type, id_table[0].guid) == 0) {
		/* This is a new virtual GPU channel */
		guid_to_luid(&hdev->channel->offermsg.offer.if_instance, &luid);
		dev_dbg(dxgglobaldev, "vGPU channel: %pUb",
			    &hdev->channel->offermsg.offer.if_instance);
		vgpuch = vzalloc(sizeof(struct dxgvgpuchannel));
		if (vgpuch == NULL) {
			ret = -ENOMEM;
			goto error;
		}
		vgpuch->adapter_luid = luid;
		vgpuch->hdev = hdev;
		list_add_tail(&vgpuch->vgpu_ch_list_entry,
			      &dxgglobal->vgpu_ch_list_head);
		dxgglobal_start_adapters();
	} else if (uuid_le_cmp(hdev->dev_type, id_table[1].guid) == 0) {
		/* This is the global Dxgkgnl channel */
		dev_dbg(dxgglobaldev, "Global channel: %pUb",
			    &hdev->channel->offermsg.offer.if_instance);
		if (dxgglobal->hdev) {
			/* This device should appear only once */
			pr_err("global channel already present\n");
			ret = -EBADE;
			goto error;
		}
		dxgglobal->hdev = hdev;
		dxgglobal_start_adapters();
	} else {
		/* Unknown device type */
		pr_err("probe: unknown device type\n");
		ret = -EBADE;
		goto error;
	}

error:

	mutex_unlock(&dxgglobal->device_mutex);

	if (ret)
		dev_dbg(dxgglobaldev, "err: %s %d", __func__, ret);
	return ret;
}

static int dxg_remove_vmbus(struct hv_device *hdev)
{
	int ret = 0;
	struct dxgvgpuchannel *vgpu_channel;

	mutex_lock(&dxgglobal->device_mutex);

	if (uuid_le_cmp(hdev->dev_type, id_table[0].guid) == 0) {
		dev_dbg(dxgglobaldev, "Remove virtual GPU channel\n");
		dxgglobal_stop_adapter_vmbus(hdev);
		list_for_each_entry(vgpu_channel,
				    &dxgglobal->vgpu_ch_list_head,
				    vgpu_ch_list_entry) {
			if (vgpu_channel->hdev == hdev) {
				list_del(&vgpu_channel->vgpu_ch_list_entry);
				vfree(vgpu_channel);
				break;
			}
		}
	} else if (uuid_le_cmp(hdev->dev_type, id_table[1].guid) == 0) {
		dev_dbg(dxgglobaldev, "Remove global channel device\n");
		dxgglobal_destroy_global_channel();
	} else {
		/* Unknown device type */
		pr_err("remove: unknown device type\n");
		ret = -EBADE;
	}

	mutex_unlock(&dxgglobal->device_mutex);
	if (ret)
		dev_dbg(dxgglobaldev, "err: %s %d", __func__, ret);
	return ret;
}

MODULE_DEVICE_TABLE(vmbus, id_table);

static struct hv_driver dxg_drv = {
	.name = KBUILD_MODNAME,
	.id_table = id_table,
	.probe = dxg_probe_vmbus,
	.remove = dxg_remove_vmbus,
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

	dxgglobal = vzalloc(sizeof(struct dxgglobal));
	if (!dxgglobal)
		return -ENOMEM;

	INIT_LIST_HEAD(&dxgglobal->plisthead);
	mutex_init(&dxgglobal->plistmutex);
	mutex_init(&dxgglobal->device_mutex);
	mutex_init(&dxgglobal->process_adapter_mutex);

	INIT_LIST_HEAD(&dxgglobal->thread_info_list_head);
	mutex_init(&dxgglobal->thread_info_mutex);

	INIT_LIST_HEAD(&dxgglobal->vgpu_ch_list_head);
	INIT_LIST_HEAD(&dxgglobal->adapter_list_head);
	init_rwsem(&dxgglobal->adapter_list_lock);

	init_rwsem(&dxgglobal->channel_lock);

	INIT_LIST_HEAD(&dxgglobal->host_event_list_head);
	spin_lock_init(&dxgglobal->host_event_list_mutex);
	atomic64_set(&dxgglobal->host_event_id, 1);

	hmgrtable_init(&dxgglobal->handle_table, NULL);

	dev_dbg(dxgglobaldev, "dxgglobal_init end\n");
	return ret;
}

static void dxgglobal_destroy(void)
{
	if (dxgglobal) {
		dxgglobal_stop_adapters();

		if (dxgglobal->vmbus_registered)
			vmbus_driver_unregister(&dxg_drv);

		dxgglobal_destroy_global_channel();
		hmgrtable_destroy(&dxgglobal->handle_table);

		if (dxgglobal->pci_registered)
			pci_unregister_driver(&dxg_pci_drv);

		vfree(dxgglobal);
		dxgglobal = NULL;
	}
}

static int __init dxg_drv_init(void)
{
	int ret;


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

	dev_info(dxgglobaldev, "%s  Version: %x", __func__, DXGKRNL_VERSION);

	ret = pci_register_driver(&dxg_pci_drv);
	if (ret) {
		pr_err("pci_driver_register failed: %d", ret);
		return ret;
	}
	dxgglobal->pci_registered = true;

	init_ioctls();

	return 0;
}

static void __exit dxg_drv_exit(void)
{
	dxgglobal_destroy();
}

module_init(dxg_drv_init);
module_exit(dxg_drv_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Microsoft Dxgkrnl virtual GPU Driver");
