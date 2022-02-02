/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2022, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Headers for internal objects
 *
 */

#ifndef _DXGKRNL_H
#define _DXGKRNL_H

#include <linux/uuid.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/refcount.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>
#include <linux/miscdevice.h>
#include <linux/pci.h>
#include <linux/hyperv.h>
#include <uapi/misc/d3dkmthk.h>
#include <linux/version.h>
#include "misc.h"
#include "hmgr.h"
#include <uapi/misc/d3dkmthk.h>

struct dxgprocess;
struct dxgadapter;
struct dxgdevice;
struct dxgcontext;

/*
 * Driver private data.
 * A single /dev/dxg device is created per virtual machine.
 */
struct dxgdriver{
	struct dxgglobal	*dxgglobal;
	struct device 		*dxgdev;
	struct pci_driver 	pci_drv;
	struct hv_driver	vmbus_drv;
};
extern struct dxgdriver dxgdrv;

#define DXGDEV dxgdrv.dxgdev

struct dxgk_device_types {
	u32 post_device:1;
	u32 post_device_certain:1;
	u32 software_device:1;
	u32 soft_gpu_device:1;
	u32 warp_device:1;
	u32 bdd_device:1;
	u32 support_miracast:1;
	u32 mismatched_lda:1;
	u32 indirect_display_device:1;
	u32 xbox_one_device:1;
	u32 child_id_support_dwm_clone:1;
	u32 child_id_support_dwm_clone2:1;
	u32 has_internal_panel:1;
	u32 rfx_vgpu_device:1;
	u32 virtual_render_device:1;
	u32 support_preserve_boot_display:1;
	u32 is_uefi_frame_buffer:1;
	u32 removable_device:1;
	u32 virtual_monitor_device:1;
};

enum dxgdevice_flushschedulerreason {
	DXGDEVICE_FLUSHSCHEDULER_DEVICE_TERMINATE = 4,
};

enum dxgobjectstate {
	DXGOBJECTSTATE_CREATED,
	DXGOBJECTSTATE_ACTIVE,
	DXGOBJECTSTATE_STOPPED,
	DXGOBJECTSTATE_DESTROYED,
};

struct dxgvmbuschannel {
	struct vmbus_channel	*channel;
	struct hv_device	*hdev;
	struct dxgadapter	*adapter;
	spinlock_t		packet_list_mutex;
	struct list_head	packet_list_head;
	struct kmem_cache	*packet_cache;
	atomic64_t		packet_request_id;
};

int dxgvmbuschannel_init(struct dxgvmbuschannel *ch, struct hv_device *hdev);
void dxgvmbuschannel_destroy(struct dxgvmbuschannel *ch);
void dxgvmbuschannel_receive(void *ctx);

/*
 * The structure defines an offered vGPU vm bus channel.
 */
struct dxgvgpuchannel {
	struct list_head	vgpu_ch_list_entry;
	struct winluid		adapter_luid;
	struct hv_device	*hdev;
};

struct dxgglobal {
	struct dxgdriver	*drvdata;
	struct dxgvmbuschannel	channel;
	struct hv_device	*hdev;
	u32			num_adapters;
	u32			vmbus_ver;	/* Interface version */
	struct resource		*mem;
	u64			mmiospace_base;
	u64			mmiospace_size;
	struct miscdevice	dxgdevice;
	struct mutex		device_mutex;

	/*  list of created  processes */
	struct list_head	plisthead;
	struct mutex		plistmutex;

	/* list of created adapters */
	struct list_head	adapter_list_head;
	struct rw_semaphore	adapter_list_lock;

	/*
	 * List of the vGPU VM bus channels (dxgvgpuchannel)
	 * Protected by device_mutex
	 */
	struct list_head	vgpu_ch_list_head;

	/* protects acces to the global VM bus channel */
	struct rw_semaphore	channel_lock;

	/* protects the dxgprocess_adapter lists */
	struct mutex		process_adapter_mutex;

	bool			global_channel_initialized;
	bool			async_msg_enabled;
	bool			misc_registered;
	bool			pci_registered;
	bool			vmbus_registered;
};

static inline struct dxgglobal *dxggbl(void)
{
	return dxgdrv.dxgglobal;
}

int dxgglobal_create_adapter(struct pci_dev *dev, guid_t *guid,
			     struct winluid host_vgpu_luid);
void dxgglobal_acquire_adapter_list_lock(enum dxglockstate state);
void dxgglobal_release_adapter_list_lock(enum dxglockstate state);
int dxgglobal_init_global_channel(void);
void dxgglobal_destroy_global_channel(void);
struct vmbus_channel *dxgglobal_get_vmbus(void);
struct dxgvmbuschannel *dxgglobal_get_dxgvmbuschannel(void);
void dxgglobal_acquire_process_adapter_lock(void);
void dxgglobal_release_process_adapter_lock(void);
int dxgglobal_acquire_channel_lock(void);
void dxgglobal_release_channel_lock(void);

/*
 * Describes adapter information for each process
 */
struct dxgprocess_adapter {
	/* Entry in dxgadapter::adapter_process_list_head */
	struct list_head	adapter_process_list_entry;
	/* Entry in dxgprocess::process_adapter_list_head */
	struct list_head	process_adapter_list_entry;
	/* List of all dxgdevice objects created for the process on adapter */
	struct list_head	device_list_head;
	struct mutex		device_list_mutex;
	struct dxgadapter	*adapter;
	struct dxgprocess	*process;
	int			refcount;
};

struct dxgprocess_adapter *dxgprocess_adapter_create(struct dxgprocess *process,
						     struct dxgadapter
						     *adapter);
void dxgprocess_adapter_release(struct dxgprocess_adapter *adapter);
int dxgprocess_adapter_add_device(struct dxgprocess *process,
					      struct dxgadapter *adapter,
					      struct dxgdevice *device);
void dxgprocess_adapter_remove_device(struct dxgdevice *device);
void dxgprocess_adapter_stop(struct dxgprocess_adapter *adapter_info);
void dxgprocess_adapter_destroy(struct dxgprocess_adapter *adapter_info);

/*
 * The structure represents a process, which opened the /dev/dxg device.
 * A corresponding object is created on the host.
 */
struct dxgprocess {
	/*
	 * Process list entry in dxgglobal.
	 * Protected by the dxgglobal->plistmutex.
	 */
	struct list_head	plistentry;
	pid_t			pid;
	pid_t			tgid;
	/* how many time the process was opened */
	struct kref		process_kref;
	/*
	 * This handle table is used for all objects except dxgadapter
	 * The handle table lock order is higher than the local_handle_table
	 * lock
	 */
	struct hmgrtable	handle_table;
	/*
	 * This handle table is used for dxgadapter objects.
	 * The handle table lock order is lowest.
	 */
	struct hmgrtable	local_handle_table;
	/* Handle of the corresponding objec on the host */
	struct d3dkmthandle	host_handle;

	/* List of opened adapters (dxgprocess_adapter) */
	struct list_head	process_adapter_list_head;
};

struct dxgprocess *dxgprocess_create(void);
void dxgprocess_destroy(struct dxgprocess *process);
void dxgprocess_release(struct kref *refcount);
int dxgprocess_open_adapter(struct dxgprocess *process,
					struct dxgadapter *adapter,
					struct d3dkmthandle *handle);
int dxgprocess_close_adapter(struct dxgprocess *process,
					 struct d3dkmthandle handle);
struct dxgadapter *dxgprocess_get_adapter(struct dxgprocess *process,
					  struct d3dkmthandle handle);
struct dxgadapter *dxgprocess_adapter_by_handle(struct dxgprocess *process,
						struct d3dkmthandle handle);
struct dxgdevice *dxgprocess_device_by_handle(struct dxgprocess *process,
					      struct d3dkmthandle handle);
struct dxgdevice *dxgprocess_device_by_object_handle(struct dxgprocess *process,
						     enum hmgrentry_type t,
						     struct d3dkmthandle h);
void dxgprocess_ht_lock_shared_down(struct dxgprocess *process);
void dxgprocess_ht_lock_shared_up(struct dxgprocess *process);
void dxgprocess_ht_lock_exclusive_down(struct dxgprocess *process);
void dxgprocess_ht_lock_exclusive_up(struct dxgprocess *process);
struct dxgprocess_adapter *dxgprocess_get_adapter_info(struct dxgprocess
						       *process,
						       struct dxgadapter
						       *adapter);

enum dxgadapter_state {
	DXGADAPTER_STATE_ACTIVE		= 0,
	DXGADAPTER_STATE_STOPPED	= 1,
	DXGADAPTER_STATE_WAITING_VMBUS	= 2,
};

/*
 * This object represents the grapchis adapter.
 * Objects, which take reference on the adapter:
 * - dxgglobal
 * - dxgdevice
 * - adapter handle (struct d3dkmthandle)
 */
struct dxgadapter {
	struct rw_semaphore	core_lock;
	struct kref		adapter_kref;
	/* Entry in the list of adapters in dxgglobal */
	struct list_head	adapter_list_entry;
	/* The list of dxgprocess_adapter entries */
	struct list_head	adapter_process_list_head;
	struct pci_dev		*pci_dev;
	struct hv_device	*hv_dev;
	struct dxgvmbuschannel	channel;
	struct d3dkmthandle	host_handle;
	enum dxgadapter_state	adapter_state;
	struct winluid		host_adapter_luid;
	struct winluid		host_vgpu_luid;
	struct winluid		luid;	/* VM bus channel luid */
	u16			device_description[80];
	u16			device_instance_id[WIN_MAX_PATH];
	bool			stopping_adapter;
};

int dxgadapter_set_vmbus(struct dxgadapter *adapter, struct hv_device *hdev);
bool dxgadapter_is_active(struct dxgadapter *adapter);
void dxgadapter_start(struct dxgadapter *adapter);
void dxgadapter_stop(struct dxgadapter *adapter);
void dxgadapter_release(struct kref *refcount);
int dxgadapter_acquire_lock_shared(struct dxgadapter *adapter);
void dxgadapter_release_lock_shared(struct dxgadapter *adapter);
int dxgadapter_acquire_lock_exclusive(struct dxgadapter *adapter);
void dxgadapter_acquire_lock_forced(struct dxgadapter *adapter);
void dxgadapter_release_lock_exclusive(struct dxgadapter *adapter);
void dxgadapter_add_process(struct dxgadapter *adapter,
			    struct dxgprocess_adapter *process_info);
void dxgadapter_remove_process(struct dxgprocess_adapter *process_info);

/*
 * The object represent the device object.
 * The following objects take reference on the device
 * - dxgcontext
 * - device handle (struct d3dkmthandle)
 */
struct dxgdevice {
	enum dxgobjectstate	object_state;
	/* Device takes reference on the adapter */
	struct dxgadapter	*adapter;
	struct dxgprocess_adapter *adapter_info;
	struct dxgprocess	*process;
	/* Entry in the DGXPROCESS_ADAPTER device list */
	struct list_head	device_list_entry;
	struct kref		device_kref;
	/* Protects destcruction of the device object */
	struct rw_semaphore	device_lock;
	struct rw_semaphore	context_list_lock;
	struct list_head	context_list_head;
	/* List of paging queues. Protected by process handle table lock. */
	struct list_head	pqueue_list_head;
	struct d3dkmthandle	handle;
	enum d3dkmt_deviceexecution_state execution_state;
	u32			handle_valid;
};

struct dxgdevice *dxgdevice_create(struct dxgadapter *a, struct dxgprocess *p);
void dxgdevice_destroy(struct dxgdevice *device);
void dxgdevice_stop(struct dxgdevice *device);
void dxgdevice_mark_destroyed(struct dxgdevice *device);
int dxgdevice_acquire_lock_shared(struct dxgdevice *dev);
void dxgdevice_release_lock_shared(struct dxgdevice *dev);
void dxgdevice_release(struct kref *refcount);
void dxgdevice_add_context(struct dxgdevice *dev, struct dxgcontext *ctx);
void dxgdevice_remove_context(struct dxgdevice *dev, struct dxgcontext *ctx);
bool dxgdevice_is_active(struct dxgdevice *dev);
void dxgdevice_acquire_context_list_lock(struct dxgdevice *dev);
void dxgdevice_release_context_list_lock(struct dxgdevice *dev);

/*
 * The object represent the execution context of a device.
 */
struct dxgcontext {
	enum dxgobjectstate	object_state;
	struct dxgdevice	*device;
	struct dxgprocess	*process;
	/* entry in the device context list */
	struct list_head	context_list_entry;
	struct list_head	hwqueue_list_head;
	struct rw_semaphore	hwqueue_list_lock;
	struct kref		context_kref;
	struct d3dkmthandle	handle;
	struct d3dkmthandle	device_handle;
};

struct dxgcontext *dxgcontext_create(struct dxgdevice *dev);
void dxgcontext_destroy(struct dxgprocess *pr, struct dxgcontext *ctx);
void dxgcontext_destroy_safe(struct dxgprocess *pr, struct dxgcontext *ctx);
void dxgcontext_release(struct kref *refcount);
bool dxgcontext_is_active(struct dxgcontext *ctx);

long dxgk_compat_ioctl(struct file *f, unsigned int p1, unsigned long p2);
long dxgk_unlocked_ioctl(struct file *f, unsigned int p1, unsigned long p2);

/*
 * The convention is that VNBus instance id is a GUID, but the host sets
 * the lower part of the value to the host adapter LUID. The function
 * provides the necessary conversion.
 */
static inline void guid_to_luid(guid_t *guid, struct winluid *luid)
{
	*luid = *(struct winluid *)&guid->b[0];
}

/*
 * VM bus interface
 *
 */

/*
 * The interface version is used to ensure that the host and the guest use the
 * same VM bus protocol. It needs to be incremented every time the VM bus
 * interface changes. DXGK_VMBUS_LAST_COMPATIBLE_INTERFACE_VERSION is
 * incremented each time the earlier versions of the interface are no longer
 * compatible with the current version.
 */
#define DXGK_VMBUS_INTERFACE_VERSION_OLD		27
#define DXGK_VMBUS_INTERFACE_VERSION			40
#define DXGK_VMBUS_LAST_COMPATIBLE_INTERFACE_VERSION	16

void dxgvmb_initialize(void);
int dxgvmb_send_set_iospace_region(u64 start, u64 len);
int dxgvmb_send_create_process(struct dxgprocess *process);
int dxgvmb_send_destroy_process(struct d3dkmthandle process);
int dxgvmb_send_open_adapter(struct dxgadapter *adapter);
int dxgvmb_send_close_adapter(struct dxgadapter *adapter);
int dxgvmb_send_get_internal_adapter_info(struct dxgadapter *adapter);
struct d3dkmthandle dxgvmb_send_create_device(struct dxgadapter *adapter,
					      struct dxgprocess *process,
					      struct d3dkmt_createdevice *args);
int dxgvmb_send_destroy_device(struct dxgadapter *adapter,
			       struct dxgprocess *process,
			       struct d3dkmthandle h);
int dxgvmb_send_flush_device(struct dxgdevice *device,
			     enum dxgdevice_flushschedulerreason reason);
struct d3dkmthandle
dxgvmb_send_create_context(struct dxgadapter *adapter,
			   struct dxgprocess *process,
			   struct d3dkmt_createcontextvirtual
			   *args);
int dxgvmb_send_destroy_context(struct dxgadapter *adapter,
				struct dxgprocess *process,
				struct d3dkmthandle h);
int dxgvmb_send_query_adapter_info(struct dxgprocess *process,
				   struct dxgadapter *adapter,
				   struct d3dkmt_queryadapterinfo *args);
int dxgvmb_send_async_msg(struct dxgvmbuschannel *channel,
			  void *command,
			  u32 cmd_size);

int ntstatus2int(struct ntstatus status);

#ifdef DEBUG

void dxgk_validate_ioctls(void);

#define DXG_TRACE(fmt, ...)  do {			\
	trace_printk(dev_fmt(fmt) "\n", ##__VA_ARGS__);	\
}  while (0)

#define DXG_ERR(fmt, ...) do {				\
	dev_err(DXGDEV, fmt, ##__VA_ARGS__);		\
	trace_printk("*** dxgkerror *** " dev_fmt(fmt) "\n", ##__VA_ARGS__);	\
} while (0)

#else

#define DXG_TRACE(...)
#define DXG_ERR(fmt, ...) do {			\
	dev_err(DXGDEV, fmt, ##__VA_ARGS__);	\
} while (0)

#endif /* DEBUG */

#endif
