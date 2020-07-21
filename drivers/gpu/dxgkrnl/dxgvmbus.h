// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@microsoft.com>
 *
 * Dxgkrnl Graphics Port Driver
 * VM bus interface with the host definitions
 *
 */

#ifndef _DXGVMBUS_H
#define _DXGVMBUS_H

#include "d3dkmthk.h"

struct dxgprocess;
struct dxgadapter;

#define DXG_MAX_VM_BUS_PACKET_SIZE   (1024 * 128)

#define DXGK_DECL_VMBUS_OUTPUTSIZE(Type)\
	((sizeof(##Type) + 0x7) & ~(uint)0x7)
#define DXGK_DECL_VMBUS_ALIGN_FOR_OUTPUT(Size) (((Size) + 0x7) & ~(uint)0x7)
/*
 * Defines a structure, which has the size, multiple of 8 bytes.
 */
#define DXGK_DECL_ALIGNED8_STRUCT(Type, Name, OutputSize)	\
	const uint _Size	= DXGK_DECL_VMBUS_OUTPUTSIZE(Type);	\
	uint8_t _AlignedStruct[_Size];				\
	##Type & Name	= (##Type &)_AlignedStruct;		\
	uint OutputSize	= _Size

#define DXGK_BUFFER_VMBUS_ALIGNED(Buffer) (((Buffer) & 7)	== 0)

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

#define DXG_VM_PROCESS_NAME_LENGTH 260

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
	dxgk_vmbcommand_getdevicestate		= 28,
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
	DXGK_VMBCOMMAND_INVALID
};

enum dxgkvmb_commandtype_host_to_vm {
	DXGK_VMBCOMMAND_SIGNALGUESTEVENT,
	DXGK_VMBCOMMAND_PROPAGATEPRESENTHISTORYTOKEN,
	DXGK_VMBCOMMAND_SETGUESTDATA,
	DXGK_VMBCOMMAND_SIGNALGUESTEVENTPASSIVE,
	DXGK_VMBCOMMAND_SENDWNFNOTIFICATION,
	DXGK_VMBCOMMAND_INVALID_HOST_TO_VM
};

struct dxgkvmb_command_vm_to_host {
	uint64_t			command_id;
	d3dkmt_handle			process;
	enum dxgkvmb_commandchanneltype	channel_type;
	enum dxgkvmb_commandtype_global	command_type;
};

struct dxgkvmb_command_vgpu_to_host {
	uint64_t			command_id;
	d3dkmt_handle			process;
	u32				channel_type;
	enum dxgkvmb_commandtype	command_type;
};

struct dxgkvmb_command_host_to_vm {
	uint64_t			command_id;
	d3dkmt_handle			process;
	enum dxgkvmb_commandchanneltype	channel_type;
	enum dxgkvmb_commandtype_host_to_vm command_type;
};

struct dxgkvmb_command_signalguestevent {
	struct dxgkvmb_command_host_to_vm hdr;
	uint64_t			event;
	winhandle			process_id;
	bool				dereference_event;
};

struct dxgkvmb_command_opensyncobject {
	struct dxgkvmb_command_vm_to_host hdr;
	d3dkmt_handle			device;
	d3dkmt_handle			global_sync_object;
	uint				engine_affinity;
	struct d3dddi_synchronizationobject_flags flags;
};

struct dxgkvmb_command_opensyncobject_return {
	d3dkmt_handle			sync_object;
	ntstatus			status;
	d3dgpu_virtual_address		gpu_virtual_address;
	uint64_t			guest_cpu_physical_address;
};

/*
 * The command returns d3dkmt_handle of a shared object for the
 * given pre-process object
 */
struct dxgkvmb_command_createntsharedobject {
	struct dxgkvmb_command_vm_to_host hdr;
	d3dkmt_handle			object;
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroyntsharedobject {
	struct dxgkvmb_command_vm_to_host hdr;
	d3dkmt_handle			shared_handle;
};

/* Returns ntstatus */
struct dxgkvmb_command_setiospaceregion {
	struct dxgkvmb_command_vm_to_host hdr;
	uint64_t			start;
	uint64_t			length;
	uint				shared_page_gpadl;
};

/* Returns ntstatus */
struct dxgkvmb_command_setexistingsysmemstore {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	d3dkmt_handle			allocation;
	uint				gpadl;
};

struct dxgkvmb_command_createprocess {
	struct dxgkvmb_command_vm_to_host hdr;
	void				*process;
	winhandle			process_id;
	winwchar			process_name[DXG_VM_PROCESS_NAME_LENGTH + 1];
	bool				csrss_process:1;
	bool				dwm_process:1;
	bool				wow64_process:1;
	bool				linux_process:1;
};

struct dxgkvmb_command_createprocess_return {
	d3dkmt_handle			hprocess;
};

// The command returns ntstatus
struct dxgkvmb_command_destroyprocess {
	struct dxgkvmb_command_vm_to_host hdr;
};

struct dxgkvmb_command_openadapter {
	struct dxgkvmb_command_vgpu_to_host hdr;
	uint				vmbus_interface_version;
	uint				vmbus_last_compatible_interface_version;
	struct winluid			guest_adapter_luid;
};

struct dxgkvmb_command_openadapter_return {
	d3dkmt_handle			host_adapter_handle;
	ntstatus			status;
	uint				vmbus_interface_version;
	uint				vmbus_last_compatible_interface_version;
};

struct dxgkvmb_command_closeadapter {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			host_handle;
};

struct dxgkvmb_command_getinternaladapterinfo {
	struct dxgkvmb_command_vgpu_to_host hdr;
};

struct dxgkvmb_command_getinternaladapterinfo_return {
	struct dxgk_device_types	device_types;
	uint				driver_store_copy_mode;
	uint				driver_ddi_version;
	uint				secure_virtual_machine:1;
	uint				virtual_machine_reset:1;
	uint				is_vail_supported:1;
	struct winluid			host_adapter_luid;
	winwchar			device_description[80];
	winwchar			device_instance_id[W_MAX_PATH];
};

struct dxgkvmb_command_queryadapterinfo {
	struct dxgkvmb_command_vgpu_to_host hdr;
	enum kmtqueryadapterinfotype	query_type;
	uint				private_data_size;
	uint8_t				private_data[1];
};

/* Returns ntstatus */
struct dxgkvmb_command_setallocationpriority {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	d3dkmt_handle			resource;
	uint				allocation_count;
	/* d3dkmt_handle    allocations[allocation_count or 0]; */
	/* uint priorities[allocation_count or 1]; */
};

struct dxgkvmb_command_getallocationpriority {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	d3dkmt_handle			resource;
	uint				allocation_count;
	/* d3dkmt_handle allocations[allocation_count or 0]; */
};

struct dxgkvmb_command_getallocationpriority_return {
	ntstatus			status;
	/* uint priorities[allocation_count or 1]; */
};

/* Returns ntstatus */
struct dxgkvmb_command_setcontextschedulingpriority {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			context;
	int				priority;
};

/* Returns ntstatus */
struct dxgkvmb_command_setcontextschedulingpriority2 {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			context;
	int				priority;
	bool				in_process;
};

struct dxgkvmb_command_getcontextschedulingpriority {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			context;
	bool				in_process;
};

struct dxgkvmb_command_getcontextschedulingpriority_return {
	ntstatus			status;
	int				priority;
};

struct dxgkvmb_command_createdevice {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_createdeviceflags	flags;
	bool				cdd_device;
	void				*error_code;
};

struct dxgkvmb_command_createdevice_return {
	d3dkmt_handle			device;
};

struct dxgkvmb_command_destroydevice {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
};

struct dxgkvmb_command_makeresident {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	d3dkmt_handle			paging_queue;
	struct d3dddi_makeresident_flags flags;
	uint				alloc_count;
	d3dkmt_handle			allocations[1];
};

struct dxgkvmb_command_makeresident_return {
	uint64_t			paging_fence_value;
	uint64_t			num_bytes_to_trim;
	ntstatus			status;
};

struct dxgkvmb_command_evict {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	struct d3dddi_evict_flags	flags;
	uint				alloc_count;
	d3dkmt_handle			allocations[1];
};

struct dxgkvmb_command_evict_return {
	uint64_t			num_bytes_to_trim;
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

struct dxgkvmb_command_freegpuvirtualaddress {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_freegpuvirtualaddress args;
};

struct dxgkvmb_command_mapgpuvirtualaddress {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dddi_mapgpuvirtualaddress args;
	d3dkmt_handle			device;
};

struct dxgkvmb_command_mapgpuvirtualaddress_return {
	d3dgpu_virtual_address		virtual_address;
	uint64_t			paging_fence_value;
	ntstatus			status;
};

struct dxgkvmb_command_reservegpuvirtualaddress {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dddi_reservegpuvirtualaddress args;
};

struct dxgkvmb_command_reservegpuvirtualaddress_return {
	d3dgpu_virtual_address		virtual_address;
	uint64_t			paging_fence_value;
};

struct dxgkvmb_command_updategpuvirtualaddress {
	struct dxgkvmb_command_vgpu_to_host hdr;
	uint64_t			fence_value;
	d3dkmt_handle			device;
	d3dkmt_handle			context;
	d3dkmt_handle			fence_object;
	uint				num_operations;
	uint				flags;
	struct d3dddi_updategpuvirtualaddress_operation operations[1];
};

struct dxgkvmb_command_queryclockcalibration {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_queryclockcalibration args;
};

struct dxgkvmb_command_queryclockcalibration_return {
	ntstatus			status;
	struct dxgk_gpuclockdata	clock_data;
};

struct dxgkvmb_command_createallocation_allocinfo {
	uint				flags;
	uint				priv_drv_data_size;
	uint				vidpn_source_id;
};

struct dxgkvmb_command_createallocation {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	d3dkmt_handle			resource;
	uint				private_runtime_data_size;
	uint				priv_drv_data_size;
	uint				alloc_count;
	struct d3dkmt_createallocationflags flags;
	winhandle			private_runtime_resource_handle;
	bool				make_resident;
/* dxgkvmb_command_createallocation_allocinfo alloc_info[alloc_count]; */
/* uint8_t private_rutime_data[private_runtime_data_size] */
/* uint8_t priv_drv_data[] for each alloc_info */
};

struct dxgkvmb_command_openresource {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	bool				nt_security_sharing;
	d3dkmt_handle			global_share;
	uint				allocation_count;
	uint				total_priv_drv_data_size;
};

struct dxgkvmb_command_openresource_return {
	d3dkmt_handle			resource;
	ntstatus			status;
/* d3dkmt_handle   allocation[allocation_count]; */
};

struct dxgkvmb_command_getstandardallocprivdata {
	struct dxgkvmb_command_vgpu_to_host hdr;
	enum d3dkmdt_standardallocationtype alloc_type;
	uint				priv_driver_data_size;
	uint				priv_driver_resource_size;
	uint				physical_adapter_index;
	union {
		struct d3dkmdt_sharedprimarysurfacedata	primary;
		struct d3dkmdt_shadowsurfacedata	shadow;
		struct d3dkmtd_stagingsurfacedata	staging;
		struct d3dkmdt_gdisurfacedata		gdi_surface;
	};
};

struct dxgkvmb_command_getstandardallocprivdata_return {
	ntstatus			status;
	uint				priv_driver_data_size;
	uint				priv_driver_resource_size;
	union {
		struct d3dkmdt_sharedprimarysurfacedata	primary;
		struct d3dkmdt_shadowsurfacedata	shadow;
		struct d3dkmtd_stagingsurfacedata	staging;
		struct d3dkmdt_gdisurfacedata		gdi_surface;
	};
/* char alloc_priv_data[priv_driver_data_size]; */
/* char resource_priv_data[priv_driver_resource_size]; */
};

struct dxgkarg_describeallocation {
	winhandle			allocation;
	uint				width;
	uint				height;
	uint				format;
	uint				multisample_method;
	struct d3dddi_rational		refresh_rate;
	uint				private_driver_attribute;
	uint				flags;
	uint				rotation;
};

struct dxgkvmb_allocflags {
	union {
		uint			flags;
		struct {
			uint		primary:1;
			uint		cdd_primary:1;
			uint		dod_primary:1;
			uint		overlay:1;
			uint		reserved6:1;
			uint		capture:1;
			uint		reserved0:4;
			uint		reserved1:1;
			uint		existing_sysmem:1;
			uint		stereo:1;
			uint		direct_flip:1;
			uint		hardware_protected:1;
			uint		reserved2:1;
			uint		reserved3:1;
			uint		reserved4:1;
			uint		protected:1;
			uint		cached:1;
			uint		independent_primary:1;
			uint		reserved:11;
		};
	};
};

struct dxgkvmb_command_allocinfo_return {
	d3dkmt_handle			allocation;
	uint				priv_drv_data_size;
	struct dxgkvmb_allocflags	allocation_flags;
	uint64_t			allocation_size;
	struct dxgkarg_describeallocation driver_info;
};

struct dxgkvmb_command_createallocation_return {
	struct d3dkmt_createallocationflags flags;
	d3dkmt_handle			resource;
	d3dkmt_handle			global_share;
	uint				vgpu_flags;
	struct dxgkvmb_command_allocinfo_return allocation_info[1];
	/* Private driver data for allocations */
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroyallocation {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	d3dkmt_handle			resource;
	uint				alloc_count;
	struct d3dddicb_destroyallocation2flags flags;
	d3dkmt_handle			allocations[1];
};

struct dxgkvmb_command_createcontextvirtual {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			context;
	d3dkmt_handle			device;
	uint				node_ordinal;
	uint				engine_affinity;
	struct d3dddi_createcontextflags flags;
	enum d3dkmt_clienthint		client_hint;
	uint				priv_drv_data_size;
	uint8_t				priv_drv_data[1];
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroycontext {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			context;
};

struct dxgkvmb_command_createpagingqueue {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_createpagingqueue	args;
};

struct dxgkvmb_command_createpagingqueue_return {
	d3dkmt_handle			paging_queue;
	d3dkmt_handle			sync_object;
	uint64_t			fence_storage_physical_address;
	uint64_t			fence_storage_offset;
};

struct dxgkvmb_command_destroypagingqueue {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			paging_queue;
};

struct dxgkvmb_command_createsyncobject {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_createsynchronizationobject2 args;
	uint				client_hint;
};

struct dxgkvmb_command_createsyncobject_return {
	d3dkmt_handle			sync_object;
	d3dkmt_handle			global_sync_object;
	d3dgpu_virtual_address		fence_gpu_va;
	uint64_t			fence_storage_address;
	uint				fence_storage_offset;
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroysyncobject {
	struct dxgkvmb_command_vm_to_host hdr;
	d3dkmt_handle			sync_object;
};

/* The command returns ntstatus */
struct dxgkvmb_command_signalsyncobject {
	struct dxgkvmb_command_vgpu_to_host hdr;
	uint				object_count;
	struct d3dddicb_signalflags	flags;
	uint				context_count;
	uint64_t			fence_value;
	union {
		/* Pointer to the guest event object */
		winhandle		cpu_event_handle;
		/* Non zero when signal from CPU is done */
		d3dkmt_handle		device;
	};
	/* d3dkmt_handle ObjectHandleArray[object_count] */
	/* d3dkmt_handle ContextArray[context_count]     */
	/* uint64_t MonitoredFenceValueArray[object_count] */
};

/* The command returns ntstatus */
struct dxgkvmb_command_waitforsyncobjectfromcpu {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	uint				object_count;
	struct d3dddi_waitforsynchronizationobjectfromcpu_flags flags;
	uint64_t			guest_event_pointer;
	bool				dereference_event;
	/* d3dkmt_handle ObjectHandleArray[object_count] */
	/* uint64_t FenceValueArray [object_count] */
};

/* The command returns ntstatus */
struct dxgkvmb_command_waitforsyncobjectfromgpu {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			context;
	/* Must be 1 when bLegacyFenceObject is TRUE */
	uint				object_count;
	bool				legacy_fence_object;
	uint64_t			fence_values[1];
	/* d3dkmt_handle ObjectHandles[object_count] */
};

struct dxgkvmb_command_lock2 {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_lock2		args;
	bool				use_legacy_lock;
	uint				flags;
	uint				priv_drv_data;
};

struct dxgkvmb_command_lock2_return {
	ntstatus			status;
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
	uint64_t			paging_fence_value;
	ntstatus			status;
};

struct dxgkvmb_command_markdeviceaserror {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_markdeviceaserror args;
};

/* Returns ntstatus */
struct dxgkvmb_command_offerallocations {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	uint				allocation_count;
	enum d3dkmt_offer_priority	priority;
	struct d3dkmt_offer_flags	flags;
	bool				resources;
	d3dkmt_handle			allocations[1];
};

struct dxgkvmb_command_reclaimallocations {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			device;
	d3dkmt_handle			paging_queue;
	uint				allocation_count;
	bool				resources;
	bool				write_results;
	d3dkmt_handle			allocations[1];
};

struct dxgkvmb_command_reclaimallocations_return {
	uint64_t			paging_fence_value;
	ntstatus			status;
	enum d3dddi_reclaim_result	discarded[1];
};

/* Returns ntstatus */
struct dxgkvmb_command_changevideomemoryreservation {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_changevideomemoryreservation args;
};

/* Returns the same structure */
struct dxgkvmb_command_createhwqueue {
	struct dxgkvmb_command_vgpu_to_host hdr;
	ntstatus			status;
	d3dkmt_handle			hwqueue;
	d3dkmt_handle			hwqueue_progress_fence;
	void 				*hwqueue_progress_fence_cpuva;
	d3dgpu_virtual_address		hwqueue_progress_fence_gpuva;
	d3dkmt_handle			context;
	struct d3dddi_createhwqueueflags flags;
	uint				priv_drv_data_size;
	uint8_t				priv_drv_data[1];
};

/* The command returns ntstatus */
struct dxgkvmb_command_destroyhwqueue {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			hwqueue;
};

struct dxgkvmb_command_queryallocationresidency {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_queryallocationresidency args;
	/* d3dkmt_handle allocations[0 or number of allocations] */
};

struct dxgkvmb_command_queryallocationresidency_return {
	ntstatus			status;
	/* d3dkmt_allocationresidencystatus[NumAllocations] */
};

/* Returns only private data */
struct dxgkvmb_command_escape {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			adapter;
	d3dkmt_handle			device;
	enum d3dkmt_escapetype		type;
	struct d3dddi_escapeflags	flags;
	uint				priv_drv_data_size;
	d3dkmt_handle			context;
	uint8_t				priv_drv_data[1];
};

struct dxgkvmb_command_queryvideomemoryinfo {
	struct dxgkvmb_command_vgpu_to_host hdr;
	d3dkmt_handle			adapter;
	enum d3dkmt_memory_segment_group memory_segment_group;
	uint				physical_adapter_index;
};

struct dxgkvmb_command_queryvideomemoryinfo_return {
	uint64_t			budget;
	uint64_t			current_usage;
	uint64_t			current_reservation;
	uint64_t			available_for_reservation;
};

struct dxgkvmb_command_getdevicestate {
	struct dxgkvmb_command_vgpu_to_host hdr;
	struct d3dkmt_getdevicestate	args;
};

struct dxgkvmb_command_getdevicestate_return {
	struct d3dkmt_getdevicestate	args;
	ntstatus			status;
};

/*
 * Helper functions
 */
static inline void command_vm_to_host_init2(struct dxgkvmb_command_vm_to_host
					    *command,
					    enum dxgkvmb_commandtype_global
					    type, d3dkmt_handle process)
{
	command->command_type	= type;
	command->process	= process;
	command->command_id	= 0;
	command->channel_type	= DXGKVMB_VM_TO_HOST;
}

static inline void command_vgpu_to_host_init0(struct dxgkvmb_command_vm_to_host
					      *command)
{
	command->command_type	= DXGK_VMBCOMMAND_INVALID;
	command->process	= 0;
	command->command_id	= 0;
	command->channel_type	= DXGKVMB_VGPU_TO_HOST;
}

static inline void command_vgpu_to_host_init1(struct
					      dxgkvmb_command_vgpu_to_host
					      *command,
					      enum dxgkvmb_commandtype type)
{
	command->command_type	= type;
	command->process	= 0;
	command->command_id	= 0;
	command->channel_type	= DXGKVMB_VGPU_TO_HOST;
}

static inline void command_vgpu_to_host_init2(struct
					      dxgkvmb_command_vgpu_to_host
					      *command,
					      enum dxgkvmb_commandtype type,
					      d3dkmt_handle process_handle)
{
	command->command_type	= type;
	command->process	= process_handle;
	command->command_id	= 0;
	command->channel_type	= DXGKVMB_VGPU_TO_HOST;
}

int dxgvmb_send_sync_msg(struct dxgvmbuschannel *channel,
			 void *command,
			 u32 command_size, void *result, u32 result_size);

#endif /* _DXGVMBUS_H */
