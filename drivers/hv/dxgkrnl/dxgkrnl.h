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
struct dxgallocation;
struct dxgresource;
struct dxgsharedresource;
struct dxgsyncobject;
struct dxgsharedsyncobject;
struct dxghwqueue;

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

struct dxgpagingqueue {
	struct dxgdevice	*device;
	struct dxgprocess	*process;
	struct list_head	pqueue_list_entry;
	struct d3dkmthandle	device_handle;
	struct d3dkmthandle	handle;
	struct d3dkmthandle	syncobj_handle;
	void			*mapped_address;
};

/*
 * The structure describes an event, which will be signaled by
 * a message from host.
 */
enum dxghosteventtype {
	dxghostevent_cpu_event = 1,
};

struct dxghostevent {
	struct list_head	host_event_list_entry;
	u64			event_id;
	enum dxghosteventtype	event_type;
};

struct dxghosteventcpu {
	struct dxghostevent	hdr;
	struct dxgprocess	*process;
	struct eventfd_ctx	*cpu_event;
	struct completion	*completion_event;
	bool			destroy_after_signal;
	bool			remove_from_list;
};

struct dxgpagingqueue *dxgpagingqueue_create(struct dxgdevice *device);
void dxgpagingqueue_destroy(struct dxgpagingqueue *pqueue);
void dxgpagingqueue_stop(struct dxgpagingqueue *pqueue);

/*
 * This is GPU synchronization object, which is used to synchronize execution
 * between GPU contextx/hardware queues or for tracking GPU execution progress.
 * A dxgsyncobject is created when somebody creates a syncobject or opens a
 * shared syncobject.
 * A syncobject belongs to an adapter, unless it is a cross-adapter object.
 * Cross adapter syncobjects are currently not implemented.
 *
 * D3DDDI_MONITORED_FENCE and D3DDDI_PERIODIC_MONITORED_FENCE are called
 * "device" syncobject, because the belong to a device (dxgdevice).
 * Device syncobjects are inserted to a list in dxgdevice.
 *
 * A syncobject can be "shared", meaning that it could be opened by many
 * processes.
 *
 * Shared syncobjects are inserted to a list in its owner
 * (dxgsharedsyncobject).
 * A syncobject can be shared by using a global handle or by using
 * "NT security handle".
 * When global handle sharing is used, the handle is created durinig object
 * creation.
 * When "NT security" is used, the handle for sharing is create be calling
 * dxgk_share_objects. On Linux "NT handle" is represented by a file
 * descriptor. FD points to dxgsharedsyncobject.
 */
struct dxgsyncobject {
	struct kref			syncobj_kref;
	enum d3dddi_synchronizationobject_type	type;
	/*
	 * List entry in dxgdevice for device sync objects.
	 * List entry in dxgadapter for other objects
	 */
	struct list_head		syncobj_list_entry;
	/* List entry in the dxgsharedsyncobject object for shared synobjects */
	struct list_head		shared_syncobj_list_entry;
	/* Adapter, the syncobject belongs to. NULL for stopped sync obejcts. */
	struct dxgadapter		*adapter;
	/*
	 * Pointer to the device, which was used to create the object.
	 * This is NULL for non-device syncbjects
	 */
	struct dxgdevice		*device;
	struct dxgprocess		*process;
	/* Used by D3DDDI_CPU_NOTIFICATION objects */
	struct dxghosteventcpu		*host_event;
	/* Owner object for shared syncobjects */
	struct dxgsharedsyncobject	*shared_owner;
	/* CPU virtual address of the fence value for "device" syncobjects */
	void				*mapped_address;
	/* Handle in the process handle table */
	struct d3dkmthandle		handle;
	/* Cached handle of the device. Used to avoid device dereference. */
	struct d3dkmthandle		device_handle;
	union {
		struct {
			/* Must be the first bit */
			u32		destroyed:1;
			/* Must be the second bit */
			u32		stopped:1;
			/* device syncobject */
			u32		monitored_fence:1;
			u32		cpu_event:1;
			u32		shared:1;
			u32		reserved:27;
		};
		long			flags;
	};
};

/*
 * The structure defines an offered vGPU vm bus channel.
 */
struct dxgvgpuchannel {
	struct list_head	vgpu_ch_list_entry;
	struct winluid		adapter_luid;
	struct hv_device	*hdev;
};

/*
 * The object is used as parent of all sync objects, created for a shared
 * syncobject. When a shared syncobject is created without NT security, the
 * handle in the global handle table will point to this object.
 */
struct dxgsharedsyncobject {
	struct kref			ssyncobj_kref;
	/* Referenced by file descriptors */
	int				host_shared_handle_nt_reference;
	/* Corresponding handle in the host global handle table */
	struct d3dkmthandle		host_shared_handle;
	/*
	 * When the sync object is shared by NT handle, this is the
	 * corresponding handle in the host
	 */
	struct d3dkmthandle		host_shared_handle_nt;
	/* Protects access to host_shared_handle_nt */
	struct mutex			fd_mutex;
	struct rw_semaphore		syncobj_list_lock;
	struct list_head		shared_syncobj_list_head;
	struct list_head		adapter_shared_syncobj_list_entry;
	struct dxgadapter		*adapter;
	enum d3dddi_synchronizationobject_type type;
	u32				monitored_fence:1;
};

struct dxgsharedsyncobject *dxgsharedsyncobj_create(struct dxgadapter *adapter,
						    struct dxgsyncobject
						    *syncobj);
void dxgsharedsyncobj_release(struct kref *refcount);
void dxgsharedsyncobj_add_syncobj(struct dxgsharedsyncobject *sharedsyncobj,
				  struct dxgsyncobject *syncobj);
void dxgsharedsyncobj_remove_syncobj(struct dxgsharedsyncobject *sharedsyncobj,
				     struct dxgsyncobject *syncobj);

struct dxgsyncobject *dxgsyncobject_create(struct dxgprocess *process,
					   struct dxgdevice *device,
					   struct dxgadapter *adapter,
					   enum
					   d3dddi_synchronizationobject_type
					   type,
					   struct
					   d3dddi_synchronizationobject_flags
					   flags);
void dxgsyncobject_destroy(struct dxgprocess *process,
			   struct dxgsyncobject *syncobj);
void dxgsyncobject_stop(struct dxgsyncobject *syncobj);
void dxgsyncobject_release(struct kref *refcount);

/*
 * device_state_counter - incremented every time the execition state of
 *	a DXGDEVICE is changed in the host. Used to optimize access to the
 *	device execution state.
 */
struct dxgglobal {
	struct dxgdriver	*drvdata;
	struct dxgvmbuschannel	channel;
	struct hv_device	*hdev;
	u32			num_adapters;
	u32			vmbus_ver;	/* Interface version */
	atomic_t		device_state_counter;
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

	/*  list of events, waiting to be signaled by the host */
	struct list_head	host_event_list_head;
	spinlock_t		host_event_list_mutex;
	atomic64_t		host_event_id;

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
void dxgglobal_add_host_event(struct dxghostevent *hostevent);
void dxgglobal_remove_host_event(struct dxghostevent *hostevent);
u64 dxgglobal_new_host_event_id(void);
void dxgglobal_signal_host_event(u64 event_id);
struct dxghostevent *dxgglobal_get_host_event(u64 event_id);
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
	/* List of all dxgsharedresource objects */
	struct list_head	shared_resource_list_head;
	/* List of all dxgsharedsyncobject objects */
	struct list_head	adapter_shared_syncobj_list_head;
	/* List of all non-device dxgsyncobject objects */
	struct list_head	syncobj_list_head;
	/* This lock protects shared resource and syncobject lists */
	struct rw_semaphore	shared_resource_list_lock;
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
void dxgadapter_add_shared_syncobj(struct dxgadapter *adapter,
				   struct dxgsharedsyncobject *so);
void dxgadapter_remove_shared_syncobj(struct dxgadapter *adapter,
				      struct dxgsharedsyncobject *so);
void dxgadapter_add_syncobj(struct dxgadapter *adapter,
			    struct dxgsyncobject *so);
void dxgadapter_remove_syncobj(struct dxgsyncobject *so);
void dxgadapter_add_process(struct dxgadapter *adapter,
			    struct dxgprocess_adapter *process_info);
void dxgadapter_remove_process(struct dxgprocess_adapter *process_info);
void dxgadapter_remove_shared_resource(struct dxgadapter *adapter,
				       struct dxgsharedresource *object);

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
	/* List of device allocations */
	struct rw_semaphore	alloc_list_lock;
	struct list_head	alloc_list_head;
	struct list_head	resource_list_head;
	/* List of paging queues. Protected by process handle table lock. */
	struct list_head	pqueue_list_head;
	struct list_head	syncobj_list_head;
	struct d3dkmthandle	handle;
	enum d3dkmt_deviceexecution_state execution_state;
	int			execution_state_counter;
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
void dxgdevice_add_alloc(struct dxgdevice *dev, struct dxgallocation *a);
void dxgdevice_remove_alloc(struct dxgdevice *dev, struct dxgallocation *a);
void dxgdevice_remove_alloc_safe(struct dxgdevice *dev,
				 struct dxgallocation *a);
void dxgdevice_add_resource(struct dxgdevice *dev, struct dxgresource *res);
void dxgdevice_remove_resource(struct dxgdevice *dev, struct dxgresource *res);
void dxgdevice_add_paging_queue(struct dxgdevice *dev,
				struct dxgpagingqueue *pqueue);
void dxgdevice_remove_paging_queue(struct dxgpagingqueue *pqueue);
void dxgdevice_add_syncobj(struct dxgdevice *dev, struct dxgsyncobject *so);
void dxgdevice_remove_syncobj(struct dxgsyncobject *so);
bool dxgdevice_is_active(struct dxgdevice *dev);
void dxgdevice_acquire_context_list_lock(struct dxgdevice *dev);
void dxgdevice_release_context_list_lock(struct dxgdevice *dev);
void dxgdevice_acquire_alloc_list_lock(struct dxgdevice *dev);
void dxgdevice_release_alloc_list_lock(struct dxgdevice *dev);
void dxgdevice_acquire_alloc_list_lock_shared(struct dxgdevice *dev);
void dxgdevice_release_alloc_list_lock_shared(struct dxgdevice *dev);

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
int dxgcontext_add_hwqueue(struct dxgcontext *ctx,
				       struct dxghwqueue *hq);
void dxgcontext_remove_hwqueue(struct dxgcontext *ctx, struct dxghwqueue *hq);
void dxgcontext_remove_hwqueue_safe(struct dxgcontext *ctx,
				    struct dxghwqueue *hq);
bool dxgcontext_is_active(struct dxgcontext *ctx);

/*
 * The object represent the execution hardware queue of a device.
 */
struct dxghwqueue {
	/* entry in the context hw queue list */
	struct list_head	hwqueue_list_entry;
	struct kref		hwqueue_kref;
	struct dxgcontext	*context;
	struct dxgprocess	*process;
	struct d3dkmthandle	progress_fence_sync_object;
	struct d3dkmthandle	handle;
	struct d3dkmthandle	device_handle;
	void			*progress_fence_mapped_address;
};

struct dxghwqueue *dxghwqueue_create(struct dxgcontext *ctx);
void dxghwqueue_destroy(struct dxgprocess *pr, struct dxghwqueue *hq);
void dxghwqueue_release(struct kref *refcount);

/*
 * A shared resource object is created to track the list of dxgresource objects,
 * which are opened for the same underlying shared resource.
 * Objects are shared by using a file descriptor handle.
 * FD is created by calling dxgk_share_objects and providing shandle to
 * dxgsharedresource. The FD points to a dxgresource object, which is created
 * by calling dxgk_open_resource_nt.  dxgresource object is referenced by the
 * FD.
 *
 * The object is referenced by every dxgresource in its list.
 *
 */
struct dxgsharedresource {
	/* Every dxgresource object in the resource list takes a reference */
	struct kref		sresource_kref;
	struct dxgadapter	*adapter;
	/* List of dxgresource objects, opened for the shared resource. */
	/* Protected by dxgadapter::shared_resource_list_lock */
	struct list_head	resource_list_head;
	/* Entry in the list of dxgsharedresource in dxgadapter */
	/* Protected by dxgadapter::shared_resource_list_lock */
	struct list_head	shared_resource_list_entry;
	struct mutex		fd_mutex;
	/* Referenced by file descriptors */
	int			host_shared_handle_nt_reference;
	/* Corresponding global handle in the host */
	struct d3dkmthandle	host_shared_handle;
	/*
	 * When the sync object is shared by NT handle, this is the
	 * corresponding handle in the host
	 */
	struct d3dkmthandle	host_shared_handle_nt;
	/* Values below are computed when the resource is sealed */
	u32			runtime_private_data_size;
	u32			alloc_private_data_size;
	u32			resource_private_data_size;
	u32			allocation_count;
	union {
		struct {
			/* Cannot add new allocations */
			u32	sealed:1;
			u32	reserved:31;
		};
		long		flags;
	};
	u32			*alloc_private_data_sizes;
	u8			*alloc_private_data;
	u8			*runtime_private_data;
	u8			*resource_private_data;
};

struct dxgsharedresource *dxgsharedresource_create(struct dxgadapter *adapter);
void dxgsharedresource_destroy(struct kref *refcount);
void dxgsharedresource_add_resource(struct dxgsharedresource *sres,
				    struct dxgresource *res);
void dxgsharedresource_remove_resource(struct dxgsharedresource *sres,
				       struct dxgresource *res);

struct dxgresource {
	struct kref		resource_kref;
	enum dxgobjectstate	object_state;
	struct d3dkmthandle	handle;
	struct list_head	alloc_list_head;
	struct list_head	resource_list_entry;
	struct list_head	shared_resource_list_entry;
	struct dxgdevice	*device;
	struct dxgprocess	*process;
	/* Protects adding allocations to resource and resource destruction */
	struct mutex		resource_mutex;
	u64			private_runtime_handle;
	union {
		struct {
			u32	destroyed:1;	/* Must be the first */
			u32	handle_valid:1;
			u32	reserved:30;
		};
		long		flags;
	};
	/* Owner of the shared resource */
	struct dxgsharedresource *shared_owner;
};

struct dxgresource *dxgresource_create(struct dxgdevice *dev);
void dxgresource_destroy(struct dxgresource *res);
void dxgresource_free_handle(struct dxgresource *res);
void dxgresource_release(struct kref *refcount);
int dxgresource_add_alloc(struct dxgresource *res,
				      struct dxgallocation *a);
void dxgresource_remove_alloc(struct dxgresource *res, struct dxgallocation *a);
void dxgresource_remove_alloc_safe(struct dxgresource *res,
				   struct dxgallocation *a);
bool dxgresource_is_active(struct dxgresource *res);

struct privdata {
	u32 data_size;
	u8 data[1];
};

struct dxgallocation {
	/* Entry in the device list or resource list (when resource exists) */
	struct list_head		alloc_list_entry;
	/* Allocation owner */
	union {
		struct dxgdevice	*device;
		struct dxgresource	*resource;
	} owner;
	struct dxgprocess		*process;
	/* Pointer to private driver data desc. Used for shared resources */
	struct privdata			*priv_drv_data;
	struct d3dkmthandle		alloc_handle;
	/* Set to 1 when allocation belongs to resource. */
	u32				resource_owner:1;
	/* Set to 1 when 'cpu_address' is mapped to the IO space. */
	u32				cpu_address_mapped:1;
	/* Set to 1 when the allocatio is mapped as cached */
	u32				cached:1;
	u32				handle_valid:1;
	/* GPADL address list for existing sysmem allocations */
#ifdef _MAIN_KERNEL_
	struct vmbus_gpadl		gpadl;
#else
	u32				gpadl;
#endif
	/* Number of pages in the 'pages' array */
	u32				num_pages;
	/*
	 * How many times dxgk_lock2 is called to allocation, which is mapped
	 * to IO space.
	 */
	u32				cpu_address_refcount;
	/*
	 * CPU address from the existing sysmem allocation, or
	 * mapped to the CPU visible backing store in the IO space
	 */
	void				*cpu_address;
	/* Describes pages for the existing sysmem allocation */
	struct page			**pages;
};

struct dxgallocation *dxgallocation_create(struct dxgprocess *process);
void dxgallocation_stop(struct dxgallocation *a);
void dxgallocation_destroy(struct dxgallocation *a);
void dxgallocation_free_handle(struct dxgallocation *a);

long dxgk_compat_ioctl(struct file *f, unsigned int p1, unsigned long p2);
long dxgk_unlocked_ioctl(struct file *f, unsigned int p1, unsigned long p2);

int dxg_unmap_iospace(void *va, u32 size);
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
int dxgvmb_send_create_paging_queue(struct dxgprocess *pr,
				    struct dxgdevice *dev,
				    struct d3dkmt_createpagingqueue *args,
				    struct dxgpagingqueue *pq);
int dxgvmb_send_destroy_paging_queue(struct dxgprocess *process,
				     struct dxgadapter *adapter,
				     struct d3dkmthandle h);
int dxgvmb_send_create_allocation(struct dxgprocess *pr, struct dxgdevice *dev,
				  struct d3dkmt_createallocation *args,
				  struct d3dkmt_createallocation *__user inargs,
				  struct dxgresource *res,
				  struct dxgallocation **allocs,
				  struct d3dddi_allocationinfo2 *alloc_info,
				  struct d3dkmt_createstandardallocation *stda);
int dxgvmb_send_destroy_allocation(struct dxgprocess *pr, struct dxgdevice *dev,
				   struct d3dkmt_destroyallocation2 *args,
				   struct d3dkmthandle *alloc_handles);
int dxgvmb_send_submit_command(struct dxgprocess *pr,
			       struct dxgadapter *adapter,
			       struct d3dkmt_submitcommand *args);
int dxgvmb_send_create_sync_object(struct dxgprocess *pr,
				   struct dxgadapter *adapter,
				   struct d3dkmt_createsynchronizationobject2
				   *args, struct dxgsyncobject *so);
int dxgvmb_send_destroy_sync_object(struct dxgprocess *pr,
				    struct d3dkmthandle h);
int dxgvmb_send_signal_sync_object(struct dxgprocess *process,
				   struct dxgadapter *adapter,
				   struct d3dddicb_signalflags flags,
				   u64 legacy_fence_value,
				   struct d3dkmthandle context,
				   u32 object_count,
				   struct d3dkmthandle *object,
				   u32 context_count,
				   struct d3dkmthandle *contexts,
				   u32 fence_count, u64 *fences,
				   struct eventfd_ctx *cpu_event,
				   struct d3dkmthandle device);
int dxgvmb_send_wait_sync_object_gpu(struct dxgprocess *process,
				     struct dxgadapter *adapter,
				     struct d3dkmthandle context,
				     u32 object_count,
				     struct d3dkmthandle *objects,
				     u64 *fences,
				     bool legacy_fence);
int dxgvmb_send_wait_sync_object_cpu(struct dxgprocess *process,
				     struct dxgadapter *adapter,
				     struct
				     d3dkmt_waitforsynchronizationobjectfromcpu
				     *args,
				     u64 cpu_event);
int dxgvmb_send_lock2(struct dxgprocess *process,
		      struct dxgadapter *adapter,
		      struct d3dkmt_lock2 *args,
		      struct d3dkmt_lock2 *__user outargs);
int dxgvmb_send_unlock2(struct dxgprocess *process,
			struct dxgadapter *adapter,
			struct d3dkmt_unlock2 *args);
int dxgvmb_send_update_alloc_property(struct dxgprocess *process,
				      struct dxgadapter *adapter,
				      struct d3dddi_updateallocproperty *args,
				      struct d3dddi_updateallocproperty *__user
				      inargs);
int dxgvmb_send_mark_device_as_error(struct dxgprocess *process,
				     struct dxgadapter *adapter,
				     struct d3dkmt_markdeviceaserror *args);
int dxgvmb_send_set_allocation_priority(struct dxgprocess *process,
					struct dxgadapter *adapter,
					struct d3dkmt_setallocationpriority *a);
int dxgvmb_send_get_allocation_priority(struct dxgprocess *process,
					struct dxgadapter *adapter,
					struct d3dkmt_getallocationpriority *a);
int dxgvmb_send_offer_allocations(struct dxgprocess *process,
				  struct dxgadapter *adapter,
				  struct d3dkmt_offerallocations *args);
int dxgvmb_send_reclaim_allocations(struct dxgprocess *process,
				    struct dxgadapter *adapter,
				    struct d3dkmthandle device,
				    struct d3dkmt_reclaimallocations2 *args,
				    u64 __user *paging_fence_value);
int dxgvmb_send_change_vidmem_reservation(struct dxgprocess *process,
					  struct dxgadapter *adapter,
					  struct d3dkmthandle other_process,
					  struct
					  d3dkmt_changevideomemoryreservation
					  *args);
int dxgvmb_send_create_hwqueue(struct dxgprocess *process,
			       struct dxgadapter *adapter,
			       struct d3dkmt_createhwqueue *args,
			       struct d3dkmt_createhwqueue *__user inargs,
			       struct dxghwqueue *hq);
int dxgvmb_send_destroy_hwqueue(struct dxgprocess *process,
				struct dxgadapter *adapter,
				struct d3dkmthandle handle);
int dxgvmb_send_query_adapter_info(struct dxgprocess *process,
				   struct dxgadapter *adapter,
				   struct d3dkmt_queryadapterinfo *args);
int dxgvmb_send_submit_command_hwqueue(struct dxgprocess *process,
				       struct dxgadapter *adapter,
				       struct d3dkmt_submitcommandtohwqueue *a);
int dxgvmb_send_query_clock_calibration(struct dxgprocess *process,
					struct dxgadapter *adapter,
					struct d3dkmt_queryclockcalibration *a,
					struct d3dkmt_queryclockcalibration
					*__user inargs);
int dxgvmb_send_flush_heap_transitions(struct dxgprocess *process,
				       struct dxgadapter *adapter,
				       struct d3dkmt_flushheaptransitions *arg);
int dxgvmb_send_open_sync_object_nt(struct dxgprocess *process,
				    struct dxgvmbuschannel *channel,
				    struct d3dkmt_opensyncobjectfromnthandle2
				    *args,
				    struct dxgsyncobject *syncobj);
int dxgvmb_send_query_alloc_residency(struct dxgprocess *process,
				      struct dxgadapter *adapter,
				      struct d3dkmt_queryallocationresidency
				      *args);
int dxgvmb_send_escape(struct dxgprocess *process,
		       struct dxgadapter *adapter,
		       struct d3dkmt_escape *args);
int dxgvmb_send_query_vidmem_info(struct dxgprocess *process,
				  struct dxgadapter *adapter,
				  struct d3dkmt_queryvideomemoryinfo *args,
				  struct d3dkmt_queryvideomemoryinfo
				  *__user iargs);
int dxgvmb_send_get_device_state(struct dxgprocess *process,
				 struct dxgadapter *adapter,
				 struct d3dkmt_getdevicestate *args,
				 struct d3dkmt_getdevicestate *__user inargs);
int dxgvmb_send_create_nt_shared_object(struct dxgprocess *process,
					struct d3dkmthandle object,
					struct d3dkmthandle *shared_handle);
int dxgvmb_send_destroy_nt_shared_object(struct d3dkmthandle shared_handle);
int dxgvmb_send_open_resource(struct dxgprocess *process,
			      struct dxgadapter *adapter,
			      struct d3dkmthandle device,
			      struct d3dkmthandle global_share,
			      u32 allocation_count,
			      u32 total_priv_drv_data_size,
			      struct d3dkmthandle *resource_handle,
			      struct d3dkmthandle *alloc_handles);
int dxgvmb_send_get_stdalloc_data(struct dxgdevice *device,
				  enum d3dkmdt_standardallocationtype t,
				  struct d3dkmdt_gdisurfacedata *data,
				  u32 physical_adapter_index,
				  u32 *alloc_priv_driver_size,
				  void *prive_alloc_data,
				  u32 *res_priv_data_size,
				  void *priv_res_data);
int dxgvmb_send_query_statistics(struct dxgprocess *process,
				 struct dxgadapter *adapter,
				 struct d3dkmt_querystatistics *args);
int dxgvmb_send_async_msg(struct dxgvmbuschannel *channel,
			  void *command,
			  u32 cmd_size);
int dxgvmb_send_share_object_with_host(struct dxgprocess *process,
				struct d3dkmt_shareobjectwithhost *args);

void signal_host_cpu_event(struct dxghostevent *eventhdr);
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
