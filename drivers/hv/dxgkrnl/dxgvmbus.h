/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2022, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * VM bus interface with the host definitions
 *
 */

#ifndef _DXGVMBUS_H
#define _DXGVMBUS_H

struct dxgprocess;
struct dxgadapter;

#define DXG_MAX_VM_BUS_PACKET_SIZE	(1024 * 128)
#define DXG_VM_PROCESS_NAME_LENGTH	260

enum dxgkvmb_commandchanneltype {
	DXGKVMB_VGPU_TO_HOST,
	DXGKVMB_VM_TO_HOST,
	DXGKVMB_HOST_TO_VM
};

/*
 *
 * Commands, sent to the host via the guest global VM bus channel
 * DXG_GUEST_GLOBAL_VMBUS
 *
 */

enum dxgkvmb_commandtype_global {
	DXGK_VMBCOMMAND_VM_TO_HOST_FIRST	= 1000,
	DXGK_VMBCOMMAND_CREATEPROCESS	= DXGK_VMBCOMMAND_VM_TO_HOST_FIRST,
	DXGK_VMBCOMMAND_DESTROYPROCESS		= 1001,
	DXGK_VMBCOMMAND_OPENSYNCOBJECT		= 1002,
	DXGK_VMBCOMMAND_DESTROYSYNCOBJECT	= 1003,
	DXGK_VMBCOMMAND_CREATENTSHAREDOBJECT	= 1004,
	DXGK_VMBCOMMAND_DESTROYNTSHAREDOBJECT	= 1005,
	DXGK_VMBCOMMAND_SIGNALFENCE		= 1006,
	DXGK_VMBCOMMAND_NOTIFYPROCESSFREEZE	= 1007,
	DXGK_VMBCOMMAND_NOTIFYPROCESSTHAW	= 1008,
	DXGK_VMBCOMMAND_QUERYETWSESSION		= 1009,
	DXGK_VMBCOMMAND_SETIOSPACEREGION	= 1010,
	DXGK_VMBCOMMAND_COMPLETETRANSACTION	= 1011,
	DXGK_VMBCOMMAND_SHAREOBJECTWITHHOST	= 1021,
	DXGK_VMBCOMMAND_INVALID_VM_TO_HOST
};

/*
 *
 * Commands, sent to the host via the per adapter VM bus channel
 * DXG_GUEST_VGPU_VMBUS
 *
 */

enum dxgkvmb_commandtype {
	DXGK_VMBCOMMAND_CREATEDEVICE		= 0,
	DXGK_VMBCOMMAND_DESTROYDEVICE		= 1,
	DXGK_VMBCOMMAND_QUERYADAPTERINFO	= 2,
	DXGK_VMBCOMMAND_DDIQUERYADAPTERINFO	= 3,
	DXGK_VMBCOMMAND_CREATEALLOCATION	= 4,
	DXGK_VMBCOMMAND_DESTROYALLOCATION	= 5,
	DXGK_VMBCOMMAND_CREATECONTEXTVIRTUAL	= 6,
	DXGK_VMBCOMMAND_DESTROYCONTEXT		= 7,
	DXGK_VMBCOMMAND_CREATESYNCOBJECT	= 8,
	DXGK_VMBCOMMAND_CREATEPAGINGQUEUE	= 9,
	DXGK_VMBCOMMAND_DESTROYPAGINGQUEUE	= 10,
	DXGK_VMBCOMMAND_MAKERESIDENT		= 11,
	DXGK_VMBCOMMAND_EVICT			= 12,
	DXGK_VMBCOMMAND_ESCAPE			= 13,
	DXGK_VMBCOMMAND_OPENADAPTER		= 14,
	DXGK_VMBCOMMAND_CLOSEADAPTER		= 15,
	DXGK_VMBCOMMAND_FREEGPUVIRTUALADDRESS	= 16,
	DXGK_VMBCOMMAND_MAPGPUVIRTUALADDRESS	= 17,
	DXGK_VMBCOMMAND_RESERVEGPUVIRTUALADDRESS = 18,
	DXGK_VMBCOMMAND_UPDATEGPUVIRTUALADDRESS	= 19,
	DXGK_VMBCOMMAND_SUBMITCOMMAND		= 20,
	dxgk_vmbcommand_queryvideomemoryinfo	= 21,
	DXGK_VMBCOMMAND_WAITFORSYNCOBJECTFROMCPU = 22,
	DXGK_VMBCOMMAND_LOCK2			= 23,
	DXGK_VMBCOMMAND_UNLOCK2			= 24,
	DXGK_VMBCOMMAND_WAITFORSYNCOBJECTFROMGPU = 25,
	DXGK_VMBCOMMAND_SIGNALSYNCOBJECT	= 26,
	DXGK_VMBCOMMAND_SIGNALFENCENTSHAREDBYREF = 27,
	DXGK_VMBCOMMAND_GETDEVICESTATE		= 28,
	DXGK_VMBCOMMAND_MARKDEVICEASERROR	= 29,
	DXGK_VMBCOMMAND_ADAPTERSTOP		= 30,
	DXGK_VMBCOMMAND_SETQUEUEDLIMIT		= 31,
	DXGK_VMBCOMMAND_OPENRESOURCE		= 32,
	DXGK_VMBCOMMAND_SETCONTEXTSCHEDULINGPRIORITY = 33,
	DXGK_VMBCOMMAND_PRESENTHISTORYTOKEN	= 34,
	DXGK_VMBCOMMAND_SETREDIRECTEDFLIPFENCEVALUE = 35,
	DXGK_VMBCOMMAND_GETINTERNALADAPTERINFO	= 36,
	DXGK_VMBCOMMAND_FLUSHHEAPTRANSITIONS	= 37,
	DXGK_VMBCOMMAND_BLT			= 38,
	DXGK_VMBCOMMAND_DDIGETSTANDARDALLOCATIONDRIVERDATA = 39,
	DXGK_VMBCOMMAND_CDDGDICOMMAND		= 40,
	DXGK_VMBCOMMAND_QUERYALLOCATIONRESIDENCY = 41,
	DXGK_VMBCOMMAND_FLUSHDEVICE		= 42,
	DXGK_VMBCOMMAND_FLUSHADAPTER		= 43,
	DXGK_VMBCOMMAND_DDIGETNODEMETADATA	= 44,
	DXGK_VMBCOMMAND_SETEXISTINGSYSMEMSTORE	= 45,
	DXGK_VMBCOMMAND_ISSYNCOBJECTSIGNALED	= 46,
	DXGK_VMBCOMMAND_CDDSYNCGPUACCESS	= 47,
	DXGK_VMBCOMMAND_QUERYSTATISTICS		= 48,
	DXGK_VMBCOMMAND_CHANGEVIDEOMEMORYRESERVATION = 49,
	DXGK_VMBCOMMAND_CREATEHWQUEUE		= 50,
	DXGK_VMBCOMMAND_DESTROYHWQUEUE		= 51,
	DXGK_VMBCOMMAND_SUBMITCOMMANDTOHWQUEUE	= 52,
	DXGK_VMBCOMMAND_GETDRIVERSTOREFILE	= 53,
	DXGK_VMBCOMMAND_READDRIVERSTOREFILE	= 54,
	DXGK_VMBCOMMAND_GETNEXTHARDLINK		= 55,
	DXGK_VMBCOMMAND_UPDATEALLOCATIONPROPERTY = 56,
	DXGK_VMBCOMMAND_OFFERALLOCATIONS	= 57,
	DXGK_VMBCOMMAND_RECLAIMALLOCATIONS	= 58,
	DXGK_VMBCOMMAND_SETALLOCATIONPRIORITY	= 59,
	DXGK_VMBCOMMAND_GETALLOCATIONPRIORITY	= 60,
	DXGK_VMBCOMMAND_GETCONTEXTSCHEDULINGPRIORITY = 61,
	DXGK_VMBCOMMAND_QUERYCLOCKCALIBRATION	= 62,
	DXGK_VMBCOMMAND_QUERYRESOURCEINFO	= 64,
	DXGK_VMBCOMMAND_LOGEVENT		= 65,
	DXGK_VMBCOMMAND_SETEXISTINGSYSMEMPAGES	= 66,
	DXGK_VMBCOMMAND_INVALID
};

/*
 * Commands, sent by the host to the VM
 */
enum dxgkvmb_commandtype_host_to_vm {
	DXGK_VMBCOMMAND_SIGNALGUESTEVENT,
	DXGK_VMBCOMMAND_PROPAGATEPRESENTHISTORYTOKEN,
	DXGK_VMBCOMMAND_SETGUESTDATA,
	DXGK_VMBCOMMAND_SIGNALGUESTEVENTPASSIVE,
	DXGK_VMBCOMMAND_SENDWNFNOTIFICATION,
	DXGK_VMBCOMMAND_INVALID_HOST_TO_VM
};

struct dxgkvmb_command_vm_to_host {
	u64				command_id;
	struct d3dkmthandle		process;
	enum dxgkvmb_commandchanneltype	channel_type;
	enum dxgkvmb_commandtype_global	command_type;
};

struct dxgkvmb_command_vgpu_to_host {
	u64				command_id;
	struct d3dkmthandle		process;
	u32				channel_type	: 8;
	u32				async_msg	: 1;
	u32				reserved	: 23;
	enum dxgkvmb_commandtype	command_type;
};

struct dxgkvmb_command_host_to_vm {
	u64					command_id;
	struct d3dkmthandle			process;
	u32					channel_type	: 8;
	u32					async_msg	: 1;
	u32					reserved	: 23;
	enum dxgkvmb_commandtype_host_to_vm	command_type;
};

struct dxgkvmb_command_signalguestevent {
	struct dxgkvmb_command_host_to_vm hdr;
	u64				event;
	u64				process_id;
	bool				dereference_event;
};

enum set_guestdata_type {
	SETGUESTDATA_DATATYPE_DWORD	= 0,
	SETGUESTDATA_DATATYPE_UINT64	= 1
};

struct dxgkvmb_command_setguestdata {
	struct dxgkvmb_command_host_to_vm hdr;
	void *guest_pointer;
	union {
		u64	data64;
		u32	data32;
	};
	u32	dereference	: 1;
	u32	data_type	: 4;
};

struct dxgkvmb_command_opensyncobject {
	struct dxgkvmb_command_vm_to_host hdr;
	struct d3dkmthandle		device;
	struct d3dkmthandle		global_sync_object;
	u32				engine_affinity;
	struct d3dddi_synchronizationobject_flags flags;
};

struct dxgkvmb_command_opensyncobject_return {
	struct d3dkmthandle		sync_object;
	struct ntstatus			status;
	u64				gpu_virtual_address;
	u64				guest_cpu_physical_address;
};

/*
 * The command returns struct d3dkmthandle of a shared object for the
 * given pre-process object
 */
struct dxgkvmb_command_createntsharedobject {
	struct dxgkvmb_command_vm_to_host hdr;
	struct d3dkmthandle		object;
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroyntsharedobject {
	struct dxgkvmb_command_vm_to_host hdr;
	struct d3dkmthandle		shared_handle;
};

/* Returns ntstatus */
struct dxgkvmb_command_setiospaceregion {
	struct dxgkvmb_command_vm_to_host hdr;
	u64				start;
	u64				length;
	u32				shared_page_gpadl;
};

/* Returns ntstatus */
struct dxgkvmb_command_setexistingsysmemstore {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		device;
	struct d3dkmthandle		allocation;
	u32				gpadl;
};

struct dxgkvmb_command_createprocess {
	struct dxgkvmb_command_vm_to_host hdr;
	void			*process;
	u64			process_id;
	u16			process_name[DXG_VM_PROCESS_NAME_LENGTH + 1];
	u8			csrss_process:1;
	u8			dwm_process:1;
	u8			wow64_process:1;
	u8			linux_process:1;
};

struct dxgkvmb_command_createprocess_return {
	struct d3dkmthandle	hprocess;
};

// The command returns ntstatus
struct dxgkvmb_command_destroyprocess {
	struct dxgkvmb_command_vm_to_host hdr;
};

struct dxgkvmb_command_openadapter {
	struct dxgkvmb_command_vgpu_to_host hdr;
	u32				vmbus_interface_version;
	u32				vmbus_last_compatible_interface_version;
	struct winluid			guest_adapter_luid;
};

struct dxgkvmb_command_openadapter_return {
	struct d3dkmthandle		host_adapter_handle;
	struct ntstatus			status;
	u32				vmbus_interface_version;
	u32				vmbus_last_compatible_interface_version;
};

struct dxgkvmb_command_closeadapter {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		host_handle;
};

struct dxgkvmb_command_getinternaladapterinfo {
	struct dxgkvmb_command_vgpu_to_host hdr;
};

struct dxgkvmb_command_getinternaladapterinfo_return {
	struct dxgk_device_types	device_types;
	u32				driver_store_copy_mode;
	u32				driver_ddi_version;
	u32				secure_virtual_machine	: 1;
	u32				virtual_machine_reset	: 1;
	u32				is_vail_supported	: 1;
	u32				hw_sch_enabled		: 1;
	u32				hw_sch_capable		: 1;
	u32				va_backed_vm		: 1;
	u32				async_msg_enabled	: 1;
	u32				hw_support_state	: 2;
	u32				reserved		: 23;
	struct winluid			host_adapter_luid;
	u16				device_description[80];
	u16				device_instance_id[WIN_MAX_PATH];
	struct winluid			host_vgpu_luid;
};

struct dxgkvmb_command_queryadapterinfo {
	struct dxgkvmb_command_vgpu_to_host hdr;
	enum kmtqueryadapterinfotype	query_type;
	u32				private_data_size;
	u8				private_data[1];
};

struct dxgkvmb_command_queryadapterinfo_return {
	struct ntstatus			status;
	u8				private_data[1];
};

/* Returns ntstatus */
struct dxgkvmb_command_setallocationpriority {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
	u32				allocation_count;
	/* struct d3dkmthandle    allocations[allocation_count or 0]; */
	/* u32 priorities[allocation_count or 1]; */
};

struct dxgkvmb_command_getallocationpriority {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
	u32				allocation_count;
	/* struct d3dkmthandle allocations[allocation_count or 0]; */
};

struct dxgkvmb_command_getallocationpriority_return {
	struct ntstatus			status;
	/* u32 priorities[allocation_count or 1]; */
};

struct dxgkvmb_command_createdevice {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_createdeviceflags	flags;
	bool				cdd_device;
	void				*error_code;
};

struct dxgkvmb_command_createdevice_return {
	struct d3dkmthandle		device;
};

struct dxgkvmb_command_destroydevice {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		device;
};

struct dxgkvmb_command_flushdevice {
	struct dxgkvmb_command_vgpu_to_host	hdr;
	struct d3dkmthandle			device;
	enum dxgdevice_flushschedulerreason	reason;
};

struct dxgkvmb_command_submitcommand {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_submitcommand	args;
	/* HistoryBufferHandles */
	/* PrivateDriverData    */
};

struct dxgkvmb_command_submitcommandtohwqueue {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_submitcommandtohwqueue args;
	/* Written primaries */
	/* PrivateDriverData */
};

/* Returns  ntstatus */
struct dxgkvmb_command_flushheaptransitions {
	struct dxgkvmb_command_vgpu_to_host hdr;
};

struct dxgkvmb_command_queryclockcalibration {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_queryclockcalibration args;
};

struct dxgkvmb_command_queryclockcalibration_return {
	struct ntstatus			status;
	struct dxgk_gpuclockdata	clock_data;
};

struct dxgkvmb_command_createallocation_allocinfo {
	u32				flags;
	u32				priv_drv_data_size;
	u32				vidpn_source_id;
};

struct dxgkvmb_command_createallocation {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
	u32				private_runtime_data_size;
	u32				priv_drv_data_size;
	u32				alloc_count;
	struct d3dkmt_createallocationflags flags;
	u64				private_runtime_resource_handle;
	bool				make_resident;
/* dxgkvmb_command_createallocation_allocinfo alloc_info[alloc_count]; */
/* u8 private_rutime_data[private_runtime_data_size] */
/* u8 priv_drv_data[] for each alloc_info */
};

struct dxgkvmb_command_openresource {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		device;
	bool				nt_security_sharing;
	struct d3dkmthandle		global_share;
	u32				allocation_count;
	u32				total_priv_drv_data_size;
};

struct dxgkvmb_command_openresource_return {
	struct d3dkmthandle		resource;
	struct ntstatus			status;
/* struct d3dkmthandle   allocation[allocation_count]; */
};

struct dxgkvmb_command_querystatistics {
	struct dxgkvmb_command_vgpu_to_host	hdr;
	struct d3dkmt_querystatistics		args;
};

struct dxgkvmb_command_querystatistics_return {
	struct ntstatus				status;
	u32					reserved;
	struct d3dkmt_querystatistics_result	result;
};

struct dxgkvmb_command_getstandardallocprivdata {
	struct dxgkvmb_command_vgpu_to_host hdr;
	enum d3dkmdt_standardallocationtype alloc_type;
	u32				priv_driver_data_size;
	u32				priv_driver_resource_size;
	u32				physical_adapter_index;
	union {
		struct d3dkmdt_sharedprimarysurfacedata	primary;
		struct d3dkmdt_shadowsurfacedata	shadow;
		struct d3dkmdt_stagingsurfacedata	staging;
		struct d3dkmdt_gdisurfacedata		gdi_surface;
	};
};

struct dxgkvmb_command_getstandardallocprivdata_return {
	struct ntstatus			status;
	u32				priv_driver_data_size;
	u32				priv_driver_resource_size;
	union {
		struct d3dkmdt_sharedprimarysurfacedata	primary;
		struct d3dkmdt_shadowsurfacedata	shadow;
		struct d3dkmdt_stagingsurfacedata	staging;
		struct d3dkmdt_gdisurfacedata		gdi_surface;
	};
/* char alloc_priv_data[priv_driver_data_size]; */
/* char resource_priv_data[priv_driver_resource_size]; */
};

struct dxgkarg_describeallocation {
	u64				allocation;
	u32				width;
	u32				height;
	u32				format;
	u32				multisample_method;
	struct d3dddi_rational		refresh_rate;
	u32				private_driver_attribute;
	u32				flags;
	u32				rotation;
};

struct dxgkvmb_allocflags {
	union {
		u32			flags;
		struct {
			u32		primary:1;
			u32		cdd_primary:1;
			u32		dod_primary:1;
			u32		overlay:1;
			u32		reserved6:1;
			u32		capture:1;
			u32		reserved0:4;
			u32		reserved1:1;
			u32		existing_sysmem:1;
			u32		stereo:1;
			u32		direct_flip:1;
			u32		hardware_protected:1;
			u32		reserved2:1;
			u32		reserved3:1;
			u32		reserved4:1;
			u32		protected:1;
			u32		cached:1;
			u32		independent_primary:1;
			u32		reserved:11;
		};
	};
};

struct dxgkvmb_command_allocinfo_return {
	struct d3dkmthandle		allocation;
	u32				priv_drv_data_size;
	struct dxgkvmb_allocflags	allocation_flags;
	u64				allocation_size;
	struct dxgkarg_describeallocation driver_info;
};

struct dxgkvmb_command_createallocation_return {
	struct d3dkmt_createallocationflags flags;
	struct d3dkmthandle		resource;
	struct d3dkmthandle		global_share;
	u32				vgpu_flags;
	struct dxgkvmb_command_allocinfo_return allocation_info[1];
	/* Private driver data for allocations */
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroyallocation {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
	u32				alloc_count;
	struct d3dddicb_destroyallocation2flags flags;
	struct d3dkmthandle		allocations[1];
};

struct dxgkvmb_command_createcontextvirtual {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		context;
	struct d3dkmthandle		device;
	u32				node_ordinal;
	u32				engine_affinity;
	struct d3dddi_createcontextflags flags;
	enum d3dkmt_clienthint		client_hint;
	u32				priv_drv_data_size;
	u8				priv_drv_data[1];
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroycontext {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle	context;
};

struct dxgkvmb_command_createpagingqueue {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_createpagingqueue	args;
};

struct dxgkvmb_command_createpagingqueue_return {
	struct d3dkmthandle	paging_queue;
	struct d3dkmthandle	sync_object;
	u64			fence_storage_physical_address;
	u64			fence_storage_offset;
};

struct dxgkvmb_command_destroypagingqueue {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle	paging_queue;
};

struct dxgkvmb_command_createsyncobject {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_createsynchronizationobject2 args;
	u32				client_hint;
};

struct dxgkvmb_command_createsyncobject_return {
	struct d3dkmthandle	sync_object;
	struct d3dkmthandle	global_sync_object;
	u64			fence_gpu_va;
	u64			fence_storage_address;
	u32			fence_storage_offset;
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroysyncobject {
	struct dxgkvmb_command_vm_to_host hdr;
	struct d3dkmthandle	sync_object;
};

/* The command returns ntstatus */
struct dxgkvmb_command_signalsyncobject {
	struct dxgkvmb_command_vgpu_to_host hdr;
	u32				object_count;
	struct d3dddicb_signalflags	flags;
	u32				context_count;
	u64				fence_value;
	union {
		/* Pointer to the guest event object */
		u64			cpu_event_handle;
		/* Non zero when signal from CPU is done */
		struct d3dkmthandle		device;
	};
	/* struct d3dkmthandle ObjectHandleArray[object_count] */
	/* struct d3dkmthandle ContextArray[context_count]     */
	/* u64 MonitoredFenceValueArray[object_count] */
};

/* The command returns ntstatus */
struct dxgkvmb_command_waitforsyncobjectfromcpu {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		device;
	u32				object_count;
	struct d3dddi_waitforsynchronizationobjectfromcpu_flags flags;
	u64				guest_event_pointer;
	bool				dereference_event;
	/* struct d3dkmthandle ObjectHandleArray[object_count] */
	/* u64 FenceValueArray [object_count] */
};

/* The command returns ntstatus */
struct dxgkvmb_command_waitforsyncobjectfromgpu {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		context;
	/* Must be 1 when bLegacyFenceObject is TRUE */
	u32				object_count;
	bool				legacy_fence_object;
	u64				fence_values[1];
	/* struct d3dkmthandle ObjectHandles[object_count] */
};

struct dxgkvmb_command_lock2 {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_lock2		args;
	bool				use_legacy_lock;
	u32				flags;
	u32				priv_drv_data;
};

struct dxgkvmb_command_lock2_return {
	struct ntstatus			status;
	void				*cpu_visible_buffer_offset;
};

struct dxgkvmb_command_unlock2 {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_unlock2		args;
	bool				use_legacy_unlock;
};

struct dxgkvmb_command_updateallocationproperty {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dddi_updateallocproperty args;
};

struct dxgkvmb_command_updateallocationproperty_return {
	u64				paging_fence_value;
	struct ntstatus			status;
};

struct dxgkvmb_command_markdeviceaserror {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_markdeviceaserror args;
};

/* Returns ntstatus */
struct dxgkvmb_command_changevideomemoryreservation {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_changevideomemoryreservation args;
};

/* Returns the same structure */
struct dxgkvmb_command_createhwqueue {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct ntstatus			status;
	struct d3dkmthandle		hwqueue;
	struct d3dkmthandle		hwqueue_progress_fence;
	void				*hwqueue_progress_fence_cpuva;
	u64				hwqueue_progress_fence_gpuva;
	struct d3dkmthandle		context;
	struct d3dddi_createhwqueueflags flags;
	u32				priv_drv_data_size;
	char				priv_drv_data[1];
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroyhwqueue {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		hwqueue;
};

struct dxgkvmb_command_queryallocationresidency {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_queryallocationresidency args;
	/* struct d3dkmthandle allocations[0 or number of allocations] */
};

struct dxgkvmb_command_queryallocationresidency_return {
	struct ntstatus			status;
	/* d3dkmt_allocationresidencystatus[NumAllocations] */
};

/* Returns only private data */
struct dxgkvmb_command_escape {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		adapter;
	struct d3dkmthandle		device;
	enum d3dkmt_escapetype		type;
	struct d3dddi_escapeflags	flags;
	u32				priv_drv_data_size;
	struct d3dkmthandle		context;
	u8				priv_drv_data[1];
};

struct dxgkvmb_command_queryvideomemoryinfo {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmthandle		adapter;
	enum d3dkmt_memory_segment_group memory_segment_group;
	u32				physical_adapter_index;
};

struct dxgkvmb_command_queryvideomemoryinfo_return {
	u64			budget;
	u64			current_usage;
	u64			current_reservation;
	u64			available_for_reservation;
};

struct dxgkvmb_command_getdevicestate {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_getdevicestate	args;
};

struct dxgkvmb_command_getdevicestate_return {
	struct d3dkmt_getdevicestate	args;
	struct ntstatus			status;
};

struct dxgkvmb_command_shareobjectwithhost {
	struct dxgkvmb_command_vm_to_host hdr;
	struct d3dkmthandle	device_handle;
	struct d3dkmthandle	object_handle;
	u64			reserved;
};

struct dxgkvmb_command_shareobjectwithhost_return {
	struct ntstatus	status;
	u32		alignment;
	u64		vail_nt_handle;
};

int
dxgvmb_send_sync_msg(struct dxgvmbuschannel *channel,
		     void *command, u32 command_size, void *result,
		     u32 result_size);

#endif /* _DXGVMBUS_H */
