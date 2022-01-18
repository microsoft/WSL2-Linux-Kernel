/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * User mode WDDM interface definitions
 *
 */

#ifndef _D3DKMTHK_H
#define _D3DKMTHK_H

/*
 * This structure matches the definition of D3DKMTHANDLE in Windows.
 * The handle is opaque in user mode. It is used by user mode applications to
 * represent kernel mode objects, created by dxgkrnl.
 */
struct d3dkmthandle {
	union {
		struct {
			__u32 instance	:  6;
			__u32 index	: 24;
			__u32 unique	: 2;
		};
		__u32 v;
	};
};

/*
 * VM bus messages return Windows' NTSTATUS, which is integer and only negative
 * value indicates a failure. A positive number is a success and needs to be
 * returned to user mode as the IOCTL return code. Negative status codes are
 * converted to Linux error codes.
 */
struct ntstatus {
	union {
		struct {
			int code	: 16;
			int facility	: 13;
			int customer	: 1;
			int severity	: 2;
		};
		int v;
	};
};

/*
 * Matches the Windows LUID definition.
 * LUID is a locally unique identifier (similar to GUID, but not global),
 * which is guaranteed to be unique intil the computer is rebooted.
 */
struct winluid {
	__u32 a;
	__u32 b;
};

#define D3DDDI_MAX_WRITTEN_PRIMARIES		16

#define D3DKMT_CREATEALLOCATION_MAX		1024
#define D3DKMT_ADAPTERS_MAX			64
#define D3DDDI_MAX_BROADCAST_CONTEXT		64
#define D3DDDI_MAX_OBJECT_WAITED_ON		32
#define D3DDDI_MAX_OBJECT_SIGNALED		32

struct d3dkmt_adapterinfo {
	struct d3dkmthandle		adapter_handle;
	struct winluid			adapter_luid;
	__u32				num_sources;
	__u32				present_move_regions_preferred;
};

struct d3dkmt_enumadapters2 {
	__u32				num_adapters;
	__u32				reserved;
#ifdef __KERNEL__
	struct d3dkmt_adapterinfo	*adapters;
#else
	__u64				*adapters;
#endif
};

struct d3dkmt_closeadapter {
	struct d3dkmthandle		adapter_handle;
};

struct d3dkmt_openadapterfromluid {
	struct winluid			adapter_luid;
	struct d3dkmthandle		adapter_handle;
};

struct d3dddi_allocationlist {
	struct d3dkmthandle		allocation;
	union {
		struct {
			__u32		write_operation		:1;
			__u32		do_not_retire_instance	:1;
			__u32		offer_priority		:3;
			__u32		reserved		:27;
		};
		__u32			value;
	};
};

struct d3dddi_patchlocationlist {
	__u32				allocation_index;
	union {
		struct {
			__u32		slot_id:24;
			__u32		reserved:8;
		};
		__u32			value;
	};
	__u32				driver_id;
	__u32				allocation_offset;
	__u32				patch_offset;
	__u32				split_offset;
};

struct d3dkmt_createdeviceflags {
	__u32				legacy_mode:1;
	__u32				request_vSync:1;
	__u32				disable_gpu_timeout:1;
	__u32				gdi_device:1;
	__u32				reserved:28;
};

struct d3dkmt_createdevice {
	struct d3dkmthandle		adapter;
	__u32				reserved3;
	struct d3dkmt_createdeviceflags	flags;
	struct d3dkmthandle		device;
#ifdef __KERNEL__
	void				*command_buffer;
#else
	__u64				command_buffer;
#endif
	__u32				command_buffer_size;
	__u32				reserved;
#ifdef __KERNEL__
	struct d3dddi_allocationlist	*allocation_list;
#else
	__u64				allocation_list;
#endif
	__u32				allocation_list_size;
	__u32				reserved1;
#ifdef __KERNEL__
	struct d3dddi_patchlocationlist	*patch_location_list;
#else
	__u64				patch_location_list;
#endif
	__u32				patch_location_list_size;
	__u32				reserved2;
};

struct d3dkmt_destroydevice {
	struct d3dkmthandle		device;
};

enum d3dkmt_clienthint {
	_D3DKMT_CLIENTHNT_UNKNOWN	= 0,
	_D3DKMT_CLIENTHINT_OPENGL	= 1,
	_D3DKMT_CLIENTHINT_CDD		= 2,
	_D3DKMT_CLIENTHINT_DX7		= 7,
	_D3DKMT_CLIENTHINT_DX8		= 8,
	_D3DKMT_CLIENTHINT_DX9		= 9,
	_D3DKMT_CLIENTHINT_DX10		= 10,
};

struct d3dddi_createcontextflags {
	union {
		struct {
			__u32		null_rendering:1;
			__u32		initial_data:1;
			__u32		disable_gpu_timeout:1;
			__u32		synchronization_only:1;
			__u32		hw_queue_supported:1;
			__u32		reserved:27;
		};
		__u32			value;
	};
};

struct d3dkmt_destroycontext {
	struct d3dkmthandle		context;
};

struct d3dkmt_createcontextvirtual {
	struct d3dkmthandle		device;
	__u32				node_ordinal;
	__u32				engine_affinity;
	struct d3dddi_createcontextflags flags;
#ifdef __KERNEL__
	void				*priv_drv_data;
#else
	__u64				priv_drv_data;
#endif
	__u32				priv_drv_data_size;
	enum d3dkmt_clienthint		client_hint;
	struct d3dkmthandle		context;
};

struct d3dddi_createhwqueueflags {
	union {
		struct {
			__u32		disable_gpu_timeout:1;
			__u32		reserved:31;
		};
		__u32			value;
	};
};

enum d3dddi_pagingqueue_priority {
	_D3DDDI_PAGINGQUEUE_PRIORITY_BELOW_NORMAL	= -1,
	_D3DDDI_PAGINGQUEUE_PRIORITY_NORMAL		= 0,
	_D3DDDI_PAGINGQUEUE_PRIORITY_ABOVE_NORMAL	= 1,
};

struct d3dkmt_createpagingqueue {
	struct d3dkmthandle		device;
	enum d3dddi_pagingqueue_priority priority;
	struct d3dkmthandle		paging_queue;
	struct d3dkmthandle		sync_object;
#ifdef __KERNEL__
	void				*fence_cpu_virtual_address;
#else
	__u64				fence_cpu_virtual_address;
#endif
	__u32				physical_adapter_index;
};

struct d3dddi_destroypagingqueue {
	struct d3dkmthandle		paging_queue;
};

enum d3dkmt_escapetype {
	_D3DKMT_ESCAPE_DRIVERPRIVATE	= 0,
	_D3DKMT_ESCAPE_VIDMM		= 1,
	_D3DKMT_ESCAPE_VIDSCH		= 3,
	_D3DKMT_ESCAPE_DEVICE		= 4,
	_D3DKMT_ESCAPE_DRT_TEST		= 8,
};

struct d3dddi_escapeflags {
	union {
		struct {
			__u32		hardware_access:1;
			__u32		device_status_query:1;
			__u32		change_frame_latency:1;
			__u32		no_adapter_synchronization:1;
			__u32		reserved:1;
			__u32		virtual_machine_data:1;
			__u32		driver_known_escape:1;
			__u32		driver_common_escape:1;
			__u32		reserved2:24;
		};
		__u32			value;
	};
};

struct d3dkmt_escape {
	struct d3dkmthandle		adapter;
	struct d3dkmthandle		device;
	enum d3dkmt_escapetype		type;
	struct d3dddi_escapeflags	flags;
#ifdef __KERNEL__
	void				*priv_drv_data;
#else
	__u64				priv_drv_data;
#endif
	__u32				priv_drv_data_size;
	struct d3dkmthandle		context;
};

enum dxgk_render_pipeline_stage {
	_DXGK_RENDER_PIPELINE_STAGE_UNKNOWN		= 0,
	_DXGK_RENDER_PIPELINE_STAGE_INPUT_ASSEMBLER	= 1,
	_DXGK_RENDER_PIPELINE_STAGE_VERTEX_SHADER	= 2,
	_DXGK_RENDER_PIPELINE_STAGE_GEOMETRY_SHADER	= 3,
	_DXGK_RENDER_PIPELINE_STAGE_STREAM_OUTPUT	= 4,
	_DXGK_RENDER_PIPELINE_STAGE_RASTERIZER		= 5,
	_DXGK_RENDER_PIPELINE_STAGE_PIXEL_SHADER	= 6,
	_DXGK_RENDER_PIPELINE_STAGE_OUTPUT_MERGER	= 7,
};

enum dxgk_page_fault_flags {
	_DXGK_PAGE_FAULT_WRITE			= 0x1,
	_DXGK_PAGE_FAULT_FENCE_INVALID		= 0x2,
	_DXGK_PAGE_FAULT_ADAPTER_RESET_REQUIRED	= 0x4,
	_DXGK_PAGE_FAULT_ENGINE_RESET_REQUIRED	= 0x8,
	_DXGK_PAGE_FAULT_FATAL_HARDWARE_ERROR	= 0x10,
	_DXGK_PAGE_FAULT_IOMMU			= 0x20,
	_DXGK_PAGE_FAULT_HW_CONTEXT_VALID	= 0x40,
	_DXGK_PAGE_FAULT_PROCESS_HANDLE_VALID	= 0x80,
};

enum dxgk_general_error_code {
	_DXGK_GENERAL_ERROR_PAGE_FAULT		= 0,
	_DXGK_GENERAL_ERROR_INVALID_INSTRUCTION	= 1,
};

struct dxgk_fault_error_code {
	union {
		struct {
			__u32	is_device_specific_code:1;
			enum dxgk_general_error_code general_error_code:31;
		};
		struct {
			__u32	is_device_specific_code_reserved_bit:1;
			__u32	device_specific_code:31;
		};
	};
};

struct d3dkmt_devicereset_state {
	union {
		struct {
			__u32	desktop_switched:1;
			__u32	reserved:31;
		};
		__u32		value;
	};
};

struct d3dkmt_devicepagefault_state {
	__u64				faulted_primitive_api_sequence_number;
	enum dxgk_render_pipeline_stage	faulted_pipeline_stage;
	__u32				faulted_bind_table_entry;
	enum dxgk_page_fault_flags	page_fault_flags;
	struct dxgk_fault_error_code	fault_error_code;
	__u64				faulted_virtual_address;
};

enum d3dkmt_deviceexecution_state {
	_D3DKMT_DEVICEEXECUTION_ACTIVE			= 1,
	_D3DKMT_DEVICEEXECUTION_RESET			= 2,
	_D3DKMT_DEVICEEXECUTION_HUNG			= 3,
	_D3DKMT_DEVICEEXECUTION_STOPPED			= 4,
	_D3DKMT_DEVICEEXECUTION_ERROR_OUTOFMEMORY	= 5,
	_D3DKMT_DEVICEEXECUTION_ERROR_DMAFAULT		= 6,
	_D3DKMT_DEVICEEXECUTION_ERROR_DMAPAGEFAULT	= 7,
};

enum d3dkmt_devicestate_type {
	_D3DKMT_DEVICESTATE_EXECUTION		= 1,
	_D3DKMT_DEVICESTATE_PRESENT		= 2,
	_D3DKMT_DEVICESTATE_RESET		= 3,
	_D3DKMT_DEVICESTATE_PRESENT_DWM		= 4,
	_D3DKMT_DEVICESTATE_PAGE_FAULT		= 5,
	_D3DKMT_DEVICESTATE_PRESENT_QUEUE	= 6,
};

struct d3dkmt_getdevicestate {
	struct d3dkmthandle				device;
	enum d3dkmt_devicestate_type			state_type;
	union {
		enum d3dkmt_deviceexecution_state	execution_state;
		struct d3dkmt_devicereset_state		reset_state;
		struct d3dkmt_devicepagefault_state	page_fault_state;
		char alignment[48];
	};
};

enum d3dkmdt_gdisurfacetype {
	_D3DKMDT_GDISURFACE_INVALID				= 0,
	_D3DKMDT_GDISURFACE_TEXTURE				= 1,
	_D3DKMDT_GDISURFACE_STAGING_CPUVISIBLE			= 2,
	_D3DKMDT_GDISURFACE_STAGING				= 3,
	_D3DKMDT_GDISURFACE_LOOKUPTABLE				= 4,
	_D3DKMDT_GDISURFACE_EXISTINGSYSMEM			= 5,
	_D3DKMDT_GDISURFACE_TEXTURE_CPUVISIBLE			= 6,
	_D3DKMDT_GDISURFACE_TEXTURE_CROSSADAPTER		= 7,
	_D3DKMDT_GDISURFACE_TEXTURE_CPUVISIBLE_CROSSADAPTER	= 8,
};

struct d3dddi_rational {
	__u32	numerator;
	__u32	denominator;
};

enum d3dddiformat {
	_D3DDDIFMT_UNKNOWN = 0,
};

struct d3dkmdt_gdisurfacedata {
	__u32				width;
	__u32				height;
	__u32				format;
	enum d3dkmdt_gdisurfacetype	type;
	__u32				flags;
	__u32				pitch;
};

struct d3dkmdt_stagingsurfacedata {
	__u32	width;
	__u32	height;
	__u32	pitch;
};

struct d3dkmdt_sharedprimarysurfacedata {
	__u32			width;
	__u32			height;
	enum d3dddiformat	format;
	struct d3dddi_rational	refresh_rate;
	__u32			vidpn_source_id;
};

struct d3dkmdt_shadowsurfacedata {
	__u32			width;
	__u32			height;
	enum d3dddiformat	format;
	__u32			pitch;
};

enum d3dkmdt_standardallocationtype {
	_D3DKMDT_STANDARDALLOCATION_SHAREDPRIMARYSURFACE	= 1,
	_D3DKMDT_STANDARDALLOCATION_SHADOWSURFACE		= 2,
	_D3DKMDT_STANDARDALLOCATION_STAGINGSURFACE		= 3,
	_D3DKMDT_STANDARDALLOCATION_GDISURFACE			= 4,
};

struct d3dddi_synchronizationobject_flags {
	union {
		struct {
			__u32	shared:1;
			__u32	nt_security_sharing:1;
			__u32	cross_adapter:1;
			__u32	top_of_pipeline:1;
			__u32	no_signal:1;
			__u32	no_wait:1;
			__u32	no_signal_max_value_on_tdr:1;
			__u32	no_gpu_access:1;
			__u32	reserved:23;
		};
		__u32		value;
	};
};

enum d3dddi_synchronizationobject_type {
	_D3DDDI_SYNCHRONIZATION_MUTEX		= 1,
	_D3DDDI_SEMAPHORE			= 2,
	_D3DDDI_FENCE				= 3,
	_D3DDDI_CPU_NOTIFICATION		= 4,
	_D3DDDI_MONITORED_FENCE			= 5,
	_D3DDDI_PERIODIC_MONITORED_FENCE	= 6,
	_D3DDDI_SYNCHRONIZATION_TYPE_LIMIT
};

struct d3dddi_synchronizationobjectinfo2 {
	enum d3dddi_synchronizationobject_type	type;
	struct d3dddi_synchronizationobject_flags flags;
	union {
		struct {
			__u32	initial_state;
		} synchronization_mutex;

		struct {
			__u32			max_count;
			__u32			initial_count;
		} semaphore;

		struct {
			__u64		fence_value;
		} fence;

		struct {
			__u64		event;
		} cpu_notification;

		struct {
			__u64	initial_fence_value;
#ifdef __KERNEL__
			void	*fence_cpu_virtual_address;
#else
			__u64	*fence_cpu_virtual_address;
#endif
			__u64	fence_gpu_virtual_address;
			__u32	engine_affinity;
		} monitored_fence;

		struct {
			struct d3dkmthandle	adapter;
			__u32			vidpn_target_id;
			__u64			time;
#ifdef __KERNEL__
			void			*fence_cpu_virtual_address;
#else
			__u64			fence_cpu_virtual_address;
#endif
			__u64			fence_gpu_virtual_address;
			__u32			engine_affinity;
		} periodic_monitored_fence;

		struct {
			__u64	reserved[8];
		} reserved;
	};
	struct d3dkmthandle			shared_handle;
};

struct d3dkmt_createsynchronizationobject2 {
	struct d3dkmthandle				device;
	__u32						reserved;
	struct d3dddi_synchronizationobjectinfo2	info;
	struct d3dkmthandle				sync_object;
	__u32						reserved1;
};

struct d3dkmt_waitforsynchronizationobject2 {
	struct d3dkmthandle	context;
	__u32			object_count;
	struct d3dkmthandle	object_array[D3DDDI_MAX_OBJECT_WAITED_ON];
	union {
		struct {
			__u64	fence_value;
		} fence;
		__u64		reserved[8];
	};
};

struct d3dddicb_signalflags {
	union {
		struct {
			__u32	signal_at_submission:1;
			__u32	enqueue_cpu_event:1;
			__u32	allow_fence_rewind:1;
			__u32	reserved:28;
			__u32	DXGK_SIGNAL_FLAG_INTERNAL0:1;
		};
		__u32		value;
	};
};

struct d3dkmt_signalsynchronizationobject2 {
	struct d3dkmthandle		context;
	__u32				object_count;
	struct d3dkmthandle	object_array[D3DDDI_MAX_OBJECT_SIGNALED];
	struct d3dddicb_signalflags	flags;
	__u32				context_count;
	struct d3dkmthandle		contexts[D3DDDI_MAX_BROADCAST_CONTEXT];
	union {
		struct {
			__u64		fence_value;
		} fence;
		__u64			cpu_event_handle;
		__u64			reserved[8];
	};
};

struct d3dddi_waitforsynchronizationobjectfromcpu_flags {
	union {
		struct {
			__u32	wait_any:1;
			__u32	reserved:31;
		};
		__u32		value;
	};
};

struct d3dkmt_waitforsynchronizationobjectfromcpu {
	struct d3dkmthandle	device;
	__u32			object_count;
#ifdef __KERNEL__
	struct d3dkmthandle	*objects;
	__u64			*fence_values;
#else
	__u64			objects;
	__u64			fence_values;
#endif
	__u64			async_event;
	struct d3dddi_waitforsynchronizationobjectfromcpu_flags flags;
};

struct d3dkmt_signalsynchronizationobjectfromcpu {
	struct d3dkmthandle	device;
	__u32			object_count;
#ifdef __KERNEL__
	struct d3dkmthandle	*objects;
	__u64			*fence_values;
#else
	__u64			objects;
	__u64			fence_values;
#endif
	struct d3dddicb_signalflags	flags;
};

struct d3dkmt_waitforsynchronizationobjectfromgpu {
	struct d3dkmthandle	context;
	__u32			object_count;
#ifdef __KERNEL__
	struct d3dkmthandle	*objects;
#else
	__u64			objects;
#endif
	union {
#ifdef __KERNEL__
		__u64		*monitored_fence_values;
#else
		__u64		monitored_fence_values;
#endif
		__u64		fence_value;
		__u64		reserved[8];
	};
};

struct d3dkmt_signalsynchronizationobjectfromgpu {
	struct d3dkmthandle	context;
	__u32			object_count;
#ifdef __KERNEL__
	struct d3dkmthandle	*objects;
#else
	__u64			objects;
#endif
	union {
#ifdef __KERNEL__
		__u64		*monitored_fence_values;
#else
		__u64		monitored_fence_values;
#endif
		__u64		reserved[8];
	};
};

struct d3dkmt_signalsynchronizationobjectfromgpu2 {
	__u32				object_count;
	__u32				reserved1;
#ifdef __KERNEL__
	struct d3dkmthandle		*objects;
#else
	__u64				objects;
#endif
	struct d3dddicb_signalflags	flags;
	__u32				context_count;
#ifdef __KERNEL__
	struct d3dkmthandle		*contexts;
#else
	__u64				contexts;
#endif
	union {
		__u64			fence_value;
		__u64			cpu_event_handle;
#ifdef __KERNEL__
		__u64			*monitored_fence_values;
#else
		__u64			monitored_fence_values;
#endif
		__u64			reserved[8];
	};
};

struct d3dkmt_destroysynchronizationobject {
	struct d3dkmthandle	sync_object;
};

struct d3dkmt_submitcommandflags {
	__u32					null_rendering:1;
	__u32					present_redirected:1;
	__u32					reserved:30;
};

struct d3dkmt_submitcommand {
	__u64					command_buffer;
	__u32					command_length;
	struct d3dkmt_submitcommandflags	flags;
	__u64					present_history_token;
	__u32					broadcast_context_count;
	struct d3dkmthandle	broadcast_context[D3DDDI_MAX_BROADCAST_CONTEXT];
	__u32					reserved;
#ifdef __KERNEL__
	void					*priv_drv_data;
#else
	__u64					priv_drv_data;
#endif
	__u32					priv_drv_data_size;
	__u32					num_primaries;
	struct d3dkmthandle	written_primaries[D3DDDI_MAX_WRITTEN_PRIMARIES];
	__u32					num_history_buffers;
	__u32					reserved1;
#ifdef __KERNEL__
	struct d3dkmthandle			*history_buffer_array;
#else
	__u64					history_buffer_array;
#endif
};

struct d3dkmt_submitcommandtohwqueue {
	struct d3dkmthandle	hwqueue;
	__u32			reserved;
	__u64			hwqueue_progress_fence_id;
	__u64			command_buffer;
	__u32			command_length;
	__u32			priv_drv_data_size;
#ifdef __KERNEL__
	void			*priv_drv_data;
#else
	__u64			priv_drv_data;
#endif
	__u32			num_primaries;
	__u32			reserved1;
#ifdef __KERNEL__
	struct d3dkmthandle	*written_primaries;
#else
	__u64			written_primaries;
#endif
};

struct d3dkmt_setallocationpriority {
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
#ifdef __KERNEL__
	const struct d3dkmthandle	*allocation_list;
#else
	__u64				allocation_list;
#endif
	__u32				allocation_count;
	__u32				reserved;
#ifdef __KERNEL__
	const __u32			*priorities;
#else
	__u64				priorities;
#endif
};

struct d3dkmt_getallocationpriority {
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
#ifdef __KERNEL__
	const struct d3dkmthandle	*allocation_list;
#else
	__u64				allocation_list;
#endif
	__u32				allocation_count;
	__u32				reserved;
#ifdef __KERNEL__
	__u32				*priorities;
#else
	__u64				priorities;
#endif
};

enum d3dkmt_allocationresidencystatus {
	_D3DKMT_ALLOCATIONRESIDENCYSTATUS_RESIDENTINGPUMEMORY		= 1,
	_D3DKMT_ALLOCATIONRESIDENCYSTATUS_RESIDENTINSHAREDMEMORY	= 2,
	_D3DKMT_ALLOCATIONRESIDENCYSTATUS_NOTRESIDENT			= 3,
};

struct d3dkmt_queryallocationresidency {
	struct d3dkmthandle			device;
	struct d3dkmthandle			resource;
#ifdef __KERNEL__
	struct d3dkmthandle			*allocations;
#else
	__u64					allocations;
#endif
	__u32					allocation_count;
	__u32					reserved;
#ifdef __KERNEL__
	enum d3dkmt_allocationresidencystatus	*residency_status;
#else
	__u64					residency_status;
#endif
};

struct d3dddicb_lock2flags {
	union {
		struct {
			__u32	reserved:32;
		};
		__u32		value;
	};
};

struct d3dkmt_lock2 {
	struct d3dkmthandle		device;
	struct d3dkmthandle		allocation;
	struct d3dddicb_lock2flags	flags;
	__u32				reserved;
#ifdef __KERNEL__
	void				*data;
#else
	__u64				data;
#endif
};

struct d3dkmt_unlock2 {
	struct d3dkmthandle			device;
	struct d3dkmthandle			allocation;
};

enum d3dkmt_standardallocationtype {
	_D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP	= 1,
	_D3DKMT_STANDARDALLOCATIONTYPE_CROSSADAPTER	= 2,
};

struct d3dkmt_standardallocation_existingheap {
	__u64	size;
};

struct d3dkmt_createstandardallocationflags {
	union {
		struct {
			__u32		reserved:32;
		};
		__u32			value;
	};
};

struct d3dkmt_createstandardallocation {
	enum d3dkmt_standardallocationtype		type;
	__u32						reserved;
	struct d3dkmt_standardallocation_existingheap	existing_heap_data;
	struct d3dkmt_createstandardallocationflags	flags;
	__u32						reserved1;
};

struct d3dddi_allocationinfo2 {
	struct d3dkmthandle	allocation;
#ifdef __KERNEL__
	const void		*sysmem;
#else
	__u64			sysmem;
#endif
#ifdef __KERNEL__
	void			*priv_drv_data;
#else
	__u64			priv_drv_data;
#endif
	__u32			priv_drv_data_size;
	__u32			vidpn_source_id;
	union {
		struct {
			__u32	primary:1;
			__u32	stereo:1;
			__u32	override_priority:1;
			__u32	reserved:29;
		};
		__u32		value;
	} flags;
	__u64			gpu_virtual_address;
	union {
		__u32		priority;
		__u64		unused;
	};
	__u64			reserved[5];
};

struct d3dkmt_createallocationflags {
	union {
		struct {
			__u32		create_resource:1;
			__u32		create_shared:1;
			__u32		non_secure:1;
			__u32		create_protected:1;
			__u32		restrict_shared_access:1;
			__u32		existing_sysmem:1;
			__u32		nt_security_sharing:1;
			__u32		read_only:1;
			__u32		create_write_combined:1;
			__u32		create_cached:1;
			__u32		swap_chain_back_buffer:1;
			__u32		cross_adapter:1;
			__u32		open_cross_adapter:1;
			__u32		partial_shared_creation:1;
			__u32		zeroed:1;
			__u32		write_watch:1;
			__u32		standard_allocation:1;
			__u32		existing_section:1;
			__u32		reserved:14;
		};
		__u32			value;
	};
};

struct d3dkmt_createallocation {
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
	struct d3dkmthandle		global_share;
	__u32				reserved;
#ifdef __KERNEL__
	const void			*private_runtime_data;
#else
	__u64				private_runtime_data;
#endif
	__u32				private_runtime_data_size;
	__u32				reserved1;
	union {
#ifdef __KERNEL__
		struct d3dkmt_createstandardallocation *standard_allocation;
		const void *priv_drv_data;
#else
		__u64	standard_allocation;
		__u64	priv_drv_data;
#endif
	};
	__u32				priv_drv_data_size;
	__u32				alloc_count;
#ifdef __KERNEL__
	struct d3dddi_allocationinfo2	*allocation_info;
#else
	__u64				allocation_info;
#endif
	struct d3dkmt_createallocationflags flags;
	__u32				reserved2;
	__u64				private_runtime_resource_handle;
};

struct d3dddicb_destroyallocation2flags {
	union {
		struct {
			__u32		assume_not_in_use:1;
			__u32		synchronous_destroy:1;
			__u32		reserved:29;
			__u32		system_use_only:1;
		};
		__u32			value;
	};
};

struct d3dkmt_destroyallocation2 {
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
#ifdef __KERNEL__
	const struct d3dkmthandle	*allocations;
#else
	__u64				allocations;
#endif
	__u32				alloc_count;
	struct d3dddicb_destroyallocation2flags flags;
};

enum d3dkmt_memory_segment_group {
	_D3DKMT_MEMORY_SEGMENT_GROUP_LOCAL	= 0,
	_D3DKMT_MEMORY_SEGMENT_GROUP_NON_LOCAL	= 1
};

struct d3dkmt_queryvideomemoryinfo {
	__u64					process;
	struct d3dkmthandle			adapter;
	enum d3dkmt_memory_segment_group	memory_segment_group;
	__u64					budget;
	__u64					current_usage;
	__u64					current_reservation;
	__u64					available_for_reservation;
	__u32					physical_adapter_index;
};

struct d3dkmt_adaptertype {
	union {
		struct {
			__u32		render_supported:1;
			__u32		display_supported:1;
			__u32		software_device:1;
			__u32		post_device:1;
			__u32		hybrid_discrete:1;
			__u32		hybrid_integrated:1;
			__u32		indirect_display_device:1;
			__u32		paravirtualized:1;
			__u32		acg_supported:1;
			__u32		support_set_timings_from_vidpn:1;
			__u32		detachable:1;
			__u32		compute_only:1;
			__u32		prototype:1;
			__u32		reserved:19;
		};
		__u32			value;
	};
};

enum kmtqueryadapterinfotype {
	_KMTQAITYPE_UMDRIVERPRIVATE	= 0,
	_KMTQAITYPE_ADAPTERTYPE		= 15,
	_KMTQAITYPE_ADAPTERTYPE_RENDER	= 57
};

struct d3dkmt_queryadapterinfo {
	struct d3dkmthandle		adapter;
	enum kmtqueryadapterinfotype	type;
#ifdef __KERNEL__
	void				*private_data;
#else
	__u64				private_data;
#endif
	__u32				private_data_size;
};

struct d3dkmt_flushheaptransitions {
	struct d3dkmthandle	adapter;
};

struct d3dddi_openallocationinfo2 {
	struct d3dkmthandle	allocation;
#ifdef __KERNEL__
	void			*priv_drv_data;
#else
	__u64			priv_drv_data;
#endif
	__u32			priv_drv_data_size;
	__u64			gpu_va;
	__u64			reserved[6];
};

struct d3dddi_updateallocproperty_flags {
	union {
		struct {
			__u32			accessed_physically:1;
			__u32			reserved:31;
		};
		__u32				value;
	};
};

struct d3dddi_segmentpreference {
	union {
		struct {
			__u32			segment_id0:5;
			__u32			direction0:1;
			__u32			segment_id1:5;
			__u32			direction1:1;
			__u32			segment_id2:5;
			__u32			direction2:1;
			__u32			segment_id3:5;
			__u32			direction3:1;
			__u32			segment_id4:5;
			__u32			direction4:1;
			__u32			reserved:2;
		};
		__u32				value;
	};
};

struct d3dddi_updateallocproperty {
	struct d3dkmthandle			paging_queue;
	struct d3dkmthandle			allocation;
	__u32					supported_segment_set;
	struct d3dddi_segmentpreference		preferred_segment;
	struct d3dddi_updateallocproperty_flags	flags;
	__u64					paging_fence_value;
	union {
		struct {
			__u32			set_accessed_physically:1;
			__u32			set_supported_segmentSet:1;
			__u32			set_preferred_segment:1;
			__u32			reserved:29;
		};
		__u32				property_mask_value;
	};
};

struct d3dkmt_changevideomemoryreservation {
	__u64			process;
	struct d3dkmthandle	adapter;
	enum d3dkmt_memory_segment_group memory_segment_group;
	__u64			reservation;
	__u32			physical_adapter_index;
};

struct d3dkmt_createhwqueue {
	struct d3dkmthandle	context;
	struct d3dddi_createhwqueueflags flags;
	__u32			priv_drv_data_size;
	__u32			reserved;
#ifdef __KERNEL__
	void			*priv_drv_data;
#else
	__u64			priv_drv_data;
#endif
	struct d3dkmthandle	queue;
	struct d3dkmthandle	queue_progress_fence;
#ifdef __KERNEL__
	void			*queue_progress_fence_cpu_va;
#else
	__u64			queue_progress_fence_cpu_va;
#endif
	__u64			queue_progress_fence_gpu_va;
};

struct d3dkmt_destroyhwqueue {
	struct d3dkmthandle	queue;
};

struct d3dkmt_submitwaitforsyncobjectstohwqueue {
	struct d3dkmthandle	hwqueue;
	__u32			object_count;
#ifdef __KERNEL__
	struct d3dkmthandle	*objects;
	__u64			*fence_values;
#else
	__u64			objects;
	__u64			fence_values;
#endif
};

struct d3dkmt_submitsignalsyncobjectstohwqueue {
	struct d3dddicb_signalflags	flags;
	__u32				hwqueue_count;
#ifdef __KERNEL__
	struct d3dkmthandle		*hwqueues;
#else
	__u64				hwqueues;
#endif
	__u32				object_count;
	__u32				reserved;
#ifdef __KERNEL__
	struct d3dkmthandle		*objects;
	__u64				*fence_values;
#else
	__u64				objects;
	__u64				fence_values;
#endif
};

struct d3dkmt_opensyncobjectfromnthandle2 {
	__u64			nt_handle;
	struct d3dkmthandle	device;
	struct d3dddi_synchronizationobject_flags flags;
	struct d3dkmthandle	sync_object;
	__u32			reserved1;
	union {
		struct {
#ifdef __KERNEL__
			void	*fence_value_cpu_va;
#else
			__u64	fence_value_cpu_va;
#endif
			__u64	fence_value_gpu_va;
			__u32	engine_affinity;
		} monitored_fence;
		__u64	reserved[8];
	};
};

struct d3dkmt_openresourcefromnthandle {
	struct d3dkmthandle	device;
	__u32			reserved;
	__u64			nt_handle;
	__u32			allocation_count;
	__u32			reserved1;
#ifdef __KERNEL__
	struct d3dddi_openallocationinfo2 *open_alloc_info;
#else
	__u64			open_alloc_info;
#endif
	int			private_runtime_data_size;
	__u32			reserved2;
#ifdef __KERNEL__
	void			*private_runtime_data;
#else
	__u64			private_runtime_data;
#endif
	__u32			resource_priv_drv_data_size;
	__u32			reserved3;
#ifdef __KERNEL__
	void			*resource_priv_drv_data;
#else
	__u64			resource_priv_drv_data;
#endif
	__u32			total_priv_drv_data_size;
#ifdef __KERNEL__
	void			*total_priv_drv_data;
#else
	__u64			total_priv_drv_data;
#endif
	struct d3dkmthandle	resource;
	struct d3dkmthandle	keyed_mutex;
#ifdef __KERNEL__
	void			*keyed_mutex_private_data;
#else
	__u64			keyed_mutex_private_data;
#endif
	__u32			keyed_mutex_private_data_size;
	struct d3dkmthandle	sync_object;
};

struct d3dkmt_queryresourceinfofromnthandle {
	struct d3dkmthandle	device;
	__u32			reserved;
	__u64			nt_handle;
#ifdef __KERNEL__
	void			*private_runtime_data;
#else
	__u64			private_runtime_data;
#endif
	__u32			private_runtime_data_size;
	__u32			total_priv_drv_data_size;
	__u32			resource_priv_drv_data_size;
	__u32			allocation_count;
};

struct d3dkmt_shareobjects {
	__u32			object_count;
	__u32			reserved;
#ifdef __KERNEL__
	const struct d3dkmthandle *objects;
	void			*object_attr;	/* security attributes */
#else
	__u64			objects;
	__u64			object_attr;
#endif
	__u32			desired_access;
	__u32			reserved1;
#ifdef __KERNEL__
	__u64			*shared_handle;	/* output file descriptors */
#else
	__u64			shared_handle;
#endif
};

union d3dkmt_enumadapters_filter {
	struct {
		__u64	include_compute_only:1;
		__u64	include_display_only:1;
		__u64	reserved:62;
	};
	__u64		value;
};

struct d3dkmt_enumadapters3 {
	union d3dkmt_enumadapters_filter	filter;
	__u32					adapter_count;
	__u32					reserved;
#ifdef __KERNEL__
	struct d3dkmt_adapterinfo		*adapters;
#else
	__u64					adapters;
#endif
};

struct d3dkmt_shareobjectwithhost {
	struct d3dkmthandle	device_handle;
	struct d3dkmthandle	object_handle;
	__u64			reserved;
	__u64			object_vail_nt_handle;
};

/*
 * Dxgkrnl Graphics Port Driver ioctl definitions
 *
 */

#define LX_DXOPENADAPTERFROMLUID	\
	_IOWR(0x47, 0x01, struct d3dkmt_openadapterfromluid)
#define LX_DXCREATEDEVICE		\
	_IOWR(0x47, 0x02, struct d3dkmt_createdevice)
#define LX_DXCREATECONTEXTVIRTUAL	\
	_IOWR(0x47, 0x04, struct d3dkmt_createcontextvirtual)
#define LX_DXDESTROYCONTEXT		\
	_IOWR(0x47, 0x05, struct d3dkmt_destroycontext)
#define LX_DXCREATEALLOCATION		\
	_IOWR(0x47, 0x06, struct d3dkmt_createallocation)
#define LX_DXCREATEPAGINGQUEUE		\
	_IOWR(0x47, 0x07, struct d3dkmt_createpagingqueue)
#define LX_DXQUERYADAPTERINFO		\
	_IOWR(0x47, 0x09, struct d3dkmt_queryadapterinfo)
#define LX_DXQUERYVIDEOMEMORYINFO	\
	_IOWR(0x47, 0x0a, struct d3dkmt_queryvideomemoryinfo)
#define LX_DXESCAPE			\
	_IOWR(0x47, 0x0d, struct d3dkmt_escape)
#define LX_DXGETDEVICESTATE		\
	_IOWR(0x47, 0x0e, struct d3dkmt_getdevicestate)
#define LX_DXSUBMITCOMMAND		\
	_IOWR(0x47, 0x0f, struct d3dkmt_submitcommand)
#define LX_DXCREATESYNCHRONIZATIONOBJECT \
	_IOWR(0x47, 0x10, struct d3dkmt_createsynchronizationobject2)
#define LX_DXSIGNALSYNCHRONIZATIONOBJECT \
	_IOWR(0x47, 0x11, struct d3dkmt_signalsynchronizationobject2)
#define LX_DXWAITFORSYNCHRONIZATIONOBJECT \
	_IOWR(0x47, 0x12, struct d3dkmt_waitforsynchronizationobject2)
#define LX_DXDESTROYALLOCATION2		\
	_IOWR(0x47, 0x13, struct d3dkmt_destroyallocation2)
#define LX_DXENUMADAPTERS2		\
	_IOWR(0x47, 0x14, struct d3dkmt_enumadapters2)
#define LX_DXCLOSEADAPTER		\
	_IOWR(0x47, 0x15, struct d3dkmt_closeadapter)
#define LX_DXCHANGEVIDEOMEMORYRESERVATION \
	_IOWR(0x47, 0x16, struct d3dkmt_changevideomemoryreservation)
#define LX_DXCREATEHWQUEUE		\
	_IOWR(0x47, 0x18, struct d3dkmt_createhwqueue)
#define LX_DXDESTROYHWQUEUE		\
	_IOWR(0x47, 0x1b, struct d3dkmt_destroyhwqueue)
#define LX_DXDESTROYPAGINGQUEUE		\
	_IOWR(0x47, 0x1c, struct d3dddi_destroypagingqueue)
#define LX_DXDESTROYDEVICE		\
	_IOWR(0x47, 0x19, struct d3dkmt_destroydevice)
#define LX_DXDESTROYSYNCHRONIZATIONOBJECT \
	_IOWR(0x47, 0x1d, struct d3dkmt_destroysynchronizationobject)
#define LX_DXFLUSHHEAPTRANSITIONS	\
	_IOWR(0x47, 0x1f, struct d3dkmt_flushheaptransitions)
#define LX_DXLOCK2			\
	_IOWR(0x47, 0x25, struct d3dkmt_lock2)
#define LX_DXQUERYALLOCATIONRESIDENCY	\
	_IOWR(0x47, 0x2a, struct d3dkmt_queryallocationresidency)
#define LX_DXSETALLOCATIONPRIORITY	\
	_IOWR(0x47, 0x2e, struct d3dkmt_setallocationpriority)
#define LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMCPU \
	_IOWR(0x47, 0x31, struct d3dkmt_signalsynchronizationobjectfromcpu)
#define LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMGPU \
	_IOWR(0x47, 0x32, struct d3dkmt_signalsynchronizationobjectfromgpu)
#define LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMGPU2 \
	_IOWR(0x47, 0x33, struct d3dkmt_signalsynchronizationobjectfromgpu2)
#define LX_DXSUBMITCOMMANDTOHWQUEUE	\
	_IOWR(0x47, 0x34, struct d3dkmt_submitcommandtohwqueue)
#define LX_DXSUBMITSIGNALSYNCOBJECTSTOHWQUEUE \
	_IOWR(0x47, 0x35, struct d3dkmt_submitsignalsyncobjectstohwqueue)
#define LX_DXSUBMITWAITFORSYNCOBJECTSTOHWQUEUE \
	_IOWR(0x47, 0x36, struct d3dkmt_submitwaitforsyncobjectstohwqueue)
#define LX_DXUNLOCK2			\
	_IOWR(0x47, 0x37, struct d3dkmt_unlock2)
#define LX_DXUPDATEALLOCPROPERTY	\
	_IOWR(0x47, 0x38, struct d3dddi_updateallocproperty)
#define LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMCPU \
	_IOWR(0x47, 0x3a, struct d3dkmt_waitforsynchronizationobjectfromcpu)
#define LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMGPU \
	_IOWR(0x47, 0x3b, struct d3dkmt_waitforsynchronizationobjectfromgpu)
#define LX_DXGETALLOCATIONPRIORITY	\
	_IOWR(0x47, 0x3c, struct d3dkmt_getallocationpriority)
#define LX_DXENUMADAPTERS3		\
	_IOWR(0x47, 0x3e, struct d3dkmt_enumadapters3)
#define LX_DXSHAREOBJECTS		\
	_IOWR(0x47, 0x3f, struct d3dkmt_shareobjects)
#define LX_DXOPENSYNCOBJECTFROMNTHANDLE2 \
	_IOWR(0x47, 0x40, struct d3dkmt_opensyncobjectfromnthandle2)
#define LX_DXQUERYRESOURCEINFOFROMNTHANDLE \
	_IOWR(0x47, 0x41, struct d3dkmt_queryresourceinfofromnthandle)
#define LX_DXOPENRESOURCEFROMNTHANDLE	\
	_IOWR(0x47, 0x42, struct d3dkmt_openresourcefromnthandle)
#define LX_DXSHAREOBJECTWITHHOST	\
	_IOWR(0x47, 0x44, struct d3dkmt_shareobjectwithhost)

#endif /* _D3DKMTHK_H */
