/* SPDX-License-Identifier: GPL-2.0 */

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
			u32 instance	:  6;
			u32 index	: 24;
			u32 unique	: 2;
		};
		u32 v;
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

/* Matches Windows LUID definition */
struct winluid {
	u32 a;
	u32 b;
};

#define D3DDDI_MAX_WRITTEN_PRIMARIES		16
#define D3DDDI_MAX_MPO_PRESENT_DIRTY_RECTS	0xFFF

#define D3DKMT_CREATEALLOCATION_MAX		1024
#define D3DKMT_MAKERESIDENT_ALLOC_MAX		(1024 * 10)
#define D3DKMT_ADAPTERS_MAX			64
#define D3DDDI_MAX_BROADCAST_CONTEXT		64
#define D3DDDI_MAX_OBJECT_WAITED_ON		32
#define D3DDDI_MAX_OBJECT_SIGNALED		32

struct d3dkmt_adapterinfo {
	struct d3dkmthandle		adapter_handle;
	struct winluid			adapter_luid;
	u32				num_sources;
	u32				present_move_regions_preferred;
};

struct d3dkmt_enumadapters2 {
	u32				num_adapters;
	struct d3dkmt_adapterinfo	*adapters;
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
			u32		write_operation		:1;
			u32		do_not_retire_instance	:1;
			u32		offer_priority		:3;
			u32		reserved		:27;
		};
		u32			value;
	};
};

struct d3dddi_patchlocationlist {
	u32				allocation_index;
	union {
		struct {
			u32		slot_id:24;
			u32		reserved:8;
		};
		u32			value;
	};
	u32				driver_id;
	u32				allocation_offset;
	u32				patch_offset;
	u32				split_offset;
};

struct d3dkmt_createdeviceflags {
	u32				legacy_mode:1;
	u32				request_vSync:1;
	u32				disable_gpu_timeout:1;
	u32				reserved:29;
};

struct d3dkmt_createdevice {
	union {
		struct d3dkmthandle	adapter;
		void			*adapter_pointer;
	};
	struct d3dkmt_createdeviceflags	flags;
	struct d3dkmthandle		device;
	void				*command_buffer;
	u32				command_buffer_size;
	struct d3dddi_allocationlist	*allocation_list;
	u32				allocation_list_size;
	struct d3dddi_patchlocationlist	*patch_location_list;
	u32				patch_location_list_size;
};

struct d3dkmt_destroydevice {
	struct d3dkmthandle		device;
};

enum d3dkmt_clienthint {
	D3DKMT_CLIENTHINT_UNKNOWN	= 0,
	D3DKMT_CLIENTHINT_OPENGL	= 1,
	D3DKMT_CLIENTHINT_CDD		= 2,
	D3DKMT_CLIENTHINT_DX7		= 7,
	D3DKMT_CLIENTHINT_DX8		= 8,
	D3DKMT_CLIENTHINT_DX9		= 9,
	D3DKMT_CLIENTHINT_DX10		= 10,
};

struct d3dddi_createcontextflags {
	union {
		struct {
			u32		null_rendering:1;
			u32		initial_data:1;
			u32		disable_gpu_timeout:1;
			u32		synchronization_only:1;
			u32		hw_queue_supported:1;
			u32		reserved:27;
		};
		u32			value;
	};
};

struct d3dkmt_createcontext {
	struct d3dkmthandle		device;
	u32				node_ordinal;
	u32				engine_affinity;
	struct d3dddi_createcontextflags flags;
	void				*priv_drv_data;
	u32				priv_drv_data_size;
	enum d3dkmt_clienthint		client_hint;
	struct d3dkmthandle		context;
	void				*command_buffer;
	u32				command_buffer_size;
	struct d3dddi_allocationlist	*allocation_list;
	u32				allocation_list_size;
	struct d3dddi_patchlocationlist	*patch_location_list;
	u32				patch_location_list_size;
	u64				obsolete;
};

struct d3dkmt_destroycontext {
	struct d3dkmthandle		context;
};

struct d3dkmt_createcontextvirtual {
	struct d3dkmthandle		device;
	u32				node_ordinal;
	u32				engine_affinity;
	struct d3dddi_createcontextflags flags;
	void				*priv_drv_data;
	u32				priv_drv_data_size;
	enum d3dkmt_clienthint		client_hint;
	struct d3dkmthandle		context;
};

struct d3dddi_createhwcontextflags {
	union {
		struct {
			u32		reserved:32;
		};
		u32			value;
	};
};

struct d3dddi_createhwqueueflags {
	union {
		struct {
			u32		disable_gpu_timeout:1;
			u32		reserved:31;
		};
		u32			value;
	};
};

enum d3dddi_pagingqueue_priority {
	D3DDDI_PAGINGQUEUE_PRIORITY_BELOW_NORMAL	= -1,
	D3DDDI_PAGINGQUEUE_PRIORITY_NORMAL		= 0,
	D3DDDI_PAGINGQUEUE_PRIORITY_ABOVE_NORMAL	= 1,
};

struct d3dkmt_createpagingqueue {
	struct d3dkmthandle		device;
	enum d3dddi_pagingqueue_priority priority;
	struct d3dkmthandle		paging_queue;
	struct d3dkmthandle		sync_object;
	void				*fence_cpu_virtual_address;
	u32				physical_adapter_index;
};

struct d3dddi_destroypagingqueue {
	struct d3dkmthandle		paging_queue;
};

struct d3dkmt_renderflags {
	u32				resize_command_buffer:1;
	u32				resize_allocation_list:1;
	u32				resize_patch_location_list:1;
	u32				null_rendering:1;
	u32				present_redirected:1;
	u32				render_km:1;
	u32				render_km_readback:1;
	u32				reserved:25;
};
struct d3dkmt_render {
	union {
		struct d3dkmthandle	device;
		struct d3dkmthandle	context;
	};
	u32				command_offset;
	u32				command_length;
	u32				allocation_count;
	u32				patch_location_count;
	void				*new_command_buffer;
	u32				new_command_buffer_size;
	struct d3dddi_allocationlist	*new_allocation_list;
	u32				new_allocation_list_size;
	struct d3dddi_patchlocationlist	*new_patch_pocation_list;
	u32				new_patch_pocation_list_size;
	struct d3dkmt_renderflags	flags;
	u64				present_history_token;
	u32				broadcast_context_count;
	struct d3dkmthandle	broadcast_context[D3DDDI_MAX_BROADCAST_CONTEXT];
	u32				queued_buffer_count;
	u64				obsolete;
	void				*priv_drv_data;
	u32				priv_drv_data_size;
};

enum d3dkmt_standardallocationtype {
	D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP	= 1,
	D3DKMT_STANDARDALLOCATIONTYPE_CROSSADAPTER	= 2,
};

struct d3dkmt_standardallocation_existingheap {
	u64	size;
};

struct d3dkmt_createstandardallocationflags {
	union {
		struct {
			u32		reserved:32;
		};
		u32			value;
	};
};

struct d3dkmt_createstandardallocation {
	enum d3dkmt_standardallocationtype		type;
	struct d3dkmt_standardallocation_existingheap	existing_heap_data;
	struct d3dkmt_createstandardallocationflags	flags;
};

struct d3dddi_allocationinfo2 {
	struct d3dkmthandle	allocation;
	union {
		u64		section;
		const void	*sysmem;
	};
	void			*priv_drv_data;
	u32			priv_drv_data_size;
	u32			vidpn_source_id;
	union {
		struct {
			u32	primary:1;
			u32	stereo:1;
			u32	override_priority:1;
			u32	reserved:29;
		};
		u32		value;
	} flags;
	u64			gpu_virtual_address;
	union {
		u32		priority;
		u64		unused;
	};
	u64			reserved[5];
};

struct d3dkmt_createallocationflags {
	union {
		struct {
			u32		create_resource:1;
			u32		create_shared:1;
			u32		non_secure:1;
			u32		create_protected:1;
			u32		restrict_shared_access:1;
			u32		existing_sysmem:1;
			u32		nt_security_sharing:1;
			u32		read_only:1;
			u32		create_write_combined:1;
			u32		create_cached:1;
			u32		swap_chain_back_buffer:1;
			u32		cross_adapter:1;
			u32		open_cross_adapter:1;
			u32		partial_shared_creation:1;
			u32		zeroed:1;
			u32		write_watch:1;
			u32		standard_allocation:1;
			u32		existing_section:1;
			u32		reserved:14;
		};
		u32			value;
	};
};

struct d3dkmt_createallocation {
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
	struct d3dkmthandle		global_share;
	const void			*private_runtime_data;
	u32				private_runtime_data_size;
	union {
		struct d3dkmt_createstandardallocation *standard_allocation;
		const void		*priv_drv_data;
	};
	u32				priv_drv_data_size;
	u32				alloc_count;
	struct d3dddi_allocationinfo2	*allocation_info;
	struct d3dkmt_createallocationflags flags;
	u64				private_runtime_resource_handle;
};

struct d3dddicb_destroyallocation2flags {
	union {
		struct {
			u32		assume_not_in_use:1;
			u32		synchronous_destroy:1;
			u32		reserved:29;
			u32		system_use_only:1;
		};
		u32			value;
	};
};

struct d3dkmt_destroyallocation2 {
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
	const struct d3dkmthandle	*allocations;
	u32				alloc_count;
	struct d3dddicb_destroyallocation2flags flags;
};

struct d3dddi_makeresident_flags {
	union {
		struct {
			u32		cant_trim_further:1;
			u32		must_succeed:1;
			u32		reserved:30;
		};
		u32			value;
	};
};

struct d3dddi_makeresident {
	struct d3dkmthandle		paging_queue;
	u32				alloc_count;
	const struct d3dkmthandle	*allocation_list;
	const u32			*priority_list;
	struct d3dddi_makeresident_flags flags;
	u64				paging_fence_value;
	u64				num_bytes_to_trim;
};

struct d3dddi_evict_flags {
	union {
		struct {
			u32		evict_only_if_necessary:1;
			u32		not_written_to:1;
			u32		reserved:30;
		};
		u32			value;
	};
};

struct d3dkmt_evict {
	struct d3dkmthandle		device;
	u32				alloc_count;
	const struct d3dkmthandle	*allocations;
	struct d3dddi_evict_flags	flags;
	u64				num_bytes_to_trim;
};

struct d3dddigpuva_protection_type {
	union {
		struct {
			u64	write:1;
			u64	execute:1;
			u64	zero:1;
			u64	no_access:1;
			u64	system_use_only:1;
			u64	reserved:59;
		};
		u64		value;
	};
};

enum d3dddi_updategpuvirtualaddress_operation_type {
	D3DDDI_UPDATEGPUVIRTUALADDRESS_MAP		= 0,
	D3DDDI_UPDATEGPUVIRTUALADDRESS_UNMAP		= 1,
	D3DDDI_UPDATEGPUVIRTUALADDRESS_COPY		= 2,
	D3DDDI_UPDATEGPUVIRTUALADDRESS_MAP_PROTECT	= 3,
};

struct d3dddi_updategpuvirtualaddress_operation {
	enum d3dddi_updategpuvirtualaddress_operation_type operation;
	union {
		struct {
			u64		base_address;
			u64		size;
			struct d3dkmthandle allocation;
			u64		allocation_offset;
			u64		allocation_size;
		} map;
		struct {
			u64		base_address;
			u64		size;
			struct d3dkmthandle allocation;
			u64		allocation_offset;
			u64		allocation_size;
			struct d3dddigpuva_protection_type protection;
			u64		driver_protection;
		} map_protect;
		struct {
			u64	base_address;
			u64	size;
			struct d3dddigpuva_protection_type protection;
		} unmap;
		struct {
			u64	source_address;
			u64	size;
			u64	dest_address;
		} copy;
	};
};

enum d3dddigpuva_reservation_type {
	D3DDDIGPUVA_RESERVE_NO_ACCESS		= 0,
	D3DDDIGPUVA_RESERVE_ZERO		= 1,
	D3DDDIGPUVA_RESERVE_NO_COMMIT		= 2
};

struct d3dkmt_updategpuvirtualaddress {
	struct d3dkmthandle			device;
	struct d3dkmthandle			context;
	struct d3dkmthandle			fence_object;
	u32					num_operations;
	struct d3dddi_updategpuvirtualaddress_operation *operations;
	u32					reserved0;
	u64					reserved1;
	u64					fence_value;
	union {
		struct {
			u32			do_not_wait:1;
			u32			reserved:31;
		};
		u32				value;
	} flags;
};

struct d3dddi_mapgpuvirtualaddress {
	struct d3dkmthandle			paging_queue;
	u64					base_address;
	u64					minimum_address;
	u64					maximum_address;
	struct d3dkmthandle			allocation;
	u64					offset_in_pages;
	u64					size_in_pages;
	struct d3dddigpuva_protection_type	protection;
	u64					driver_protection;
	u32					reserved0;
	u64					reserved1;
	u64					virtual_address;
	u64					paging_fence_value;
};

struct d3dddi_reservegpuvirtualaddress {
	struct d3dkmthandle			adapter;
	u64					base_address;
	u64					minimum_address;
	u64					maximum_address;
	u64					size;
	enum d3dddigpuva_reservation_type	reservation_type;
	u64					driver_protection;
	u64					virtual_address;
	u64					paging_fence_value;
};

struct d3dkmt_freegpuvirtualaddress {
	struct d3dkmthandle	adapter;
	u64			base_address;
	u64			size;
};

enum d3dkmt_memory_segment_group {
	D3DKMT_MEMORY_SEGMENT_GROUP_LOCAL	= 0,
	D3DKMT_MEMORY_SEGMENT_GROUP_NON_LOCAL	= 1
};

struct d3dkmt_queryvideomemoryinfo {
	u64					process;
	struct d3dkmthandle			adapter;
	enum d3dkmt_memory_segment_group	memory_segment_group;
	u64					budget;
	u64					current_usage;
	u64					current_reservation;
	u64					available_for_reservation;
	u32					physical_adapter_index;
};

enum qai_driverversion {
	KMT_DRIVERVERSION_WDDM_1_0		= 1000,
	KMT_DRIVERVERSION_WDDM_1_1_PRERELEASE	= 1102,
	KMT_DRIVERVERSION_WDDM_1_1		= 1105,
	KMT_DRIVERVERSION_WDDM_1_2		= 1200,
	KMT_DRIVERVERSION_WDDM_1_3		= 1300,
	KMT_DRIVERVERSION_WDDM_2_0		= 2000,
	KMT_DRIVERVERSION_WDDM_2_1		= 2100,
	KMT_DRIVERVERSION_WDDM_2_2		= 2200,
	KMT_DRIVERVERSION_WDDM_2_3		= 2300,
	KMT_DRIVERVERSION_WDDM_2_4		= 2400,
	KMT_DRIVERVERSION_WDDM_2_5		= 2500,
	KMT_DRIVERVERSION_WDDM_2_6		= 2600,
	KMT_DRIVERVERSION_WDDM_2_7		= 2700
};

struct d3dkmt_adaptertype {
	union {
		struct {
			u32		render_supported:1;
			u32		display_supported:1;
			u32		software_device:1;
			u32		post_device:1;
			u32		hybrid_discrete:1;
			u32		hybrid_integrated:1;
			u32		indirect_display_device:1;
			u32		paravirtualized:1;
			u32		acg_supported:1;
			u32		support_set_timings_from_vidpn:1;
			u32		detachable:1;
			u32		compute_only:1;
			u32		prototype:1;
			u32		reserved:19;
		};
		u32			value;
	};
};

enum kmtqueryadapterinfotype {
	KMTQAITYPE_UMDRIVERPRIVATE				= 0,
	KMTQAITYPE_UMDRIVERNAME					= 1,
	KMTQAITYPE_UMOPENGLINFO					= 2,
	KMTQAITYPE_GETSEGMENTSIZE				= 3,
	KMTQAITYPE_ADAPTERGUID					= 4,
	KMTQAITYPE_FLIPQUEUEINFO				= 5,
	KMTQAITYPE_ADAPTERADDRESS				= 6,
	KMTQAITYPE_SETWORKINGSETINFO				= 7,
	KMTQAITYPE_ADAPTERREGISTRYINFO				= 8,
	KMTQAITYPE_CURRENTDISPLAYMODE				= 9,
	KMTQAITYPE_MODELIST					= 10,
	KMTQAITYPE_CHECKDRIVERUPDATESTATUS			= 11,
	KMTQAITYPE_VIRTUALADDRESSINFO				= 12,
	KMTQAITYPE_DRIVERVERSION				= 13,
	KMTQAITYPE_ADAPTERTYPE					= 15,
	KMTQAITYPE_OUTPUTDUPLCONTEXTSCOUNT			= 16,
	KMTQAITYPE_WDDM_1_2_CAPS				= 17,
	KMTQAITYPE_UMD_DRIVER_VERSION				= 18,
	KMTQAITYPE_DIRECTFLIP_SUPPORT				= 19,
	KMTQAITYPE_MULTIPLANEOVERLAY_SUPPORT			= 20,
	KMTQAITYPE_DLIST_DRIVER_NAME				= 21,
	KMTQAITYPE_WDDM_1_3_CAPS				= 22,
	KMTQAITYPE_MULTIPLANEOVERLAY_HUD_SUPPORT		= 23,
	KMTQAITYPE_WDDM_2_0_CAPS				= 24,
	KMTQAITYPE_NODEMETADATA					= 25,
	KMTQAITYPE_CPDRIVERNAME					= 26,
	KMTQAITYPE_XBOX						= 27,
	KMTQAITYPE_INDEPENDENTFLIP_SUPPORT			= 28,
	KMTQAITYPE_MIRACASTCOMPANIONDRIVERNAME			= 29,
	KMTQAITYPE_PHYSICALADAPTERCOUNT				= 30,
	KMTQAITYPE_PHYSICALADAPTERDEVICEIDS			= 31,
	KMTQAITYPE_DRIVERCAPS_EXT				= 32,
	KMTQAITYPE_QUERY_MIRACAST_DRIVER_TYPE			= 33,
	KMTQAITYPE_QUERY_GPUMMU_CAPS				= 34,
	KMTQAITYPE_QUERY_MULTIPLANEOVERLAY_DECODE_SUPPORT	= 35,
	KMTQAITYPE_QUERY_HW_PROTECTION_TEARDOWN_COUNT		= 36,
	KMTQAITYPE_QUERY_ISBADDRIVERFORHWPROTECTIONDISABLED	= 37,
	KMTQAITYPE_MULTIPLANEOVERLAY_SECONDARY_SUPPORT		= 38,
	KMTQAITYPE_INDEPENDENTFLIP_SECONDARY_SUPPORT		= 39,
	KMTQAITYPE_PANELFITTER_SUPPORT				= 40,
	KMTQAITYPE_PHYSICALADAPTERPNPKEY			= 41,
	KMTQAITYPE_GETSEGMENTGROUPSIZE				= 42,
	KMTQAITYPE_MPO3DDI_SUPPORT				= 43,
	KMTQAITYPE_HWDRM_SUPPORT				= 44,
	KMTQAITYPE_MPOKERNELCAPS_SUPPORT			= 45,
	KMTQAITYPE_MULTIPLANEOVERLAY_STRETCH_SUPPORT		= 46,
	KMTQAITYPE_GET_DEVICE_VIDPN_OWNERSHIP_INFO		= 47,
	KMTQAITYPE_QUERYREGISTRY				= 48,
	KMTQAITYPE_KMD_DRIVER_VERSION				= 49,
	KMTQAITYPE_BLOCKLIST_KERNEL				= 50,
	KMTQAITYPE_BLOCKLIST_RUNTIME				= 51,
	KMTQAITYPE_ADAPTERGUID_RENDER				= 52,
	KMTQAITYPE_ADAPTERADDRESS_RENDER			= 53,
	KMTQAITYPE_ADAPTERREGISTRYINFO_RENDER			= 54,
	KMTQAITYPE_CHECKDRIVERUPDATESTATUS_RENDER		= 55,
	KMTQAITYPE_DRIVERVERSION_RENDER				= 56,
	KMTQAITYPE_ADAPTERTYPE_RENDER				= 57,
	KMTQAITYPE_WDDM_1_2_CAPS_RENDER				= 58,
	KMTQAITYPE_WDDM_1_3_CAPS_RENDER				= 59,
	KMTQAITYPE_QUERY_ADAPTER_UNIQUE_GUID			= 60,
	KMTQAITYPE_NODEPERFDATA					= 61,
	KMTQAITYPE_ADAPTERPERFDATA				= 62,
	KMTQAITYPE_ADAPTERPERFDATA_CAPS				= 63,
	KMTQUITYPE_GPUVERSION					= 64,
	KMTQAITYPE_DRIVER_DESCRIPTION				= 65,
	KMTQAITYPE_DRIVER_DESCRIPTION_RENDER			= 66,
	KMTQAITYPE_SCANOUT_CAPS					= 67,
	KMTQAITYPE_PARAVIRTUALIZATION_RENDER			= 68,
};

struct d3dkmt_queryadapterinfo {
	struct d3dkmthandle		adapter;
	enum kmtqueryadapterinfotype	type;
	void				*private_data;
	u32				private_data_size;
};

enum d3dkmt_escapetype {
	D3DKMT_ESCAPE_DRIVERPRIVATE	= 0,
	D3DKMT_ESCAPE_VIDMM		= 1,
	D3DKMT_ESCAPE_VIDSCH		= 3,
	D3DKMT_ESCAPE_DEVICE		= 4,
	D3DKMT_ESCAPE_DRT_TEST		= 8,
};

enum d3dkmt_drt_test_command {
	D3DKMT_DRT_TEST_COMMAND_HANDLETABLE = 39,
};

struct d3dkmt_drt_escape_head {
	u32				signature;
	u32				buffer_size;
	enum d3dkmt_drt_test_command	command;
};

enum d3dkmt_ht_command {
	D3DKMT_HT_COMMAND_ALLOC,
	D3DKMT_HT_COMMAND_FREE,
	D3DKMT_HT_COMMAND_ASSIGN,
	D3DKMT_HT_COMMAND_GET,
	D3DKMT_HT_COMMAND_DESTROY,
};

struct d3dkmt_ht_desc {
	struct d3dkmt_drt_escape_head	head;
	enum d3dkmt_ht_command		command;
	u32				index;
	struct d3dkmthandle		handle;
	u32				object_type;
	void				*object;
};

struct d3dddi_escapeflags {
	union {
		struct {
			u32		hardware_access:1;
			u32		device_status_query:1;
			u32		change_frame_latency:1;
			u32		no_adapter_synchronization:1;
			u32		reserved:1;
			u32		virtual_machine_data:1;
			u32		driver_known_escape:1;
			u32		driver_common_escape:1;
			u32		reserved2:24;
		};
		u32			value;
	};
};

struct d3dkmt_escape {
	struct d3dkmthandle		adapter;
	struct d3dkmthandle		device;
	enum d3dkmt_escapetype		type;
	struct d3dddi_escapeflags	flags;
	void				*priv_drv_data;
	u32				priv_drv_data_size;
	struct d3dkmthandle		context;
};

enum dxgk_render_pipeline_stage {
	DXGK_RENDER_PIPELINE_STAGE_UNKNOWN		= 0,
	DXGK_RENDER_PIPELINE_STAGE_INPUT_ASSEMBLER	= 1,
	DXGK_RENDER_PIPELINE_STAGE_VERTEX_SHADER	= 2,
	DXGK_RENDER_PIPELINE_STAGE_GEOMETRY_SHADER	= 3,
	DXGK_RENDER_PIPELINE_STAGE_STREAM_OUTPUT	= 4,
	DXGK_RENDER_PIPELINE_STAGE_RASTERIZER		= 5,
	DXGK_RENDER_PIPELINE_STAGE_PIXEL_SHADER		= 6,
	DXGK_RENDER_PIPELINE_STAGE_OUTPUT_MERGER	= 7,
};

enum dxgk_page_fault_flags {
	DXGK_PAGE_FAULT_WRITE			= 0x1,
	DXGK_PAGE_FAULT_FENCE_INVALID		= 0x2,
	DXGK_PAGE_FAULT_ADAPTER_RESET_REQUIRED	= 0x4,
	DXGK_PAGE_FAULT_ENGINE_RESET_REQUIRED	= 0x8,
	DXGK_PAGE_FAULT_FATAL_HARDWARE_ERROR	= 0x10,
	DXGK_PAGE_FAULT_IOMMU			= 0x20,
	DXGK_PAGE_FAULT_HW_CONTEXT_VALID	= 0x40,
	DXGK_PAGE_FAULT_PROCESS_HANDLE_VALID	= 0x80,
};

enum dxgk_general_error_code {
	DXGK_GENERAL_ERROR_PAGE_FAULT		= 0,
	DXGK_GENERAL_ERROR_INVALID_INSTRUCTION	= 1,
};

struct dxgk_fault_error_code {
	union {
		struct {
			u32	is_device_specific_code:1;
			enum dxgk_general_error_code general_error_code:31;
		};
		struct {
			u32	is_device_specific_code_reserved_bit:1;
			u32	device_specific_code:31;
		};
	};
};

enum d3dkmt_deviceexecution_state {
	D3DKMT_DEVICEEXECUTION_ACTIVE			= 1,
	D3DKMT_DEVICEEXECUTION_RESET			= 2,
	D3DKMT_DEVICEEXECUTION_HUNG			= 3,
	D3DKMT_DEVICEEXECUTION_STOPPED			= 4,
	D3DKMT_DEVICEEXECUTION_ERROR_OUTOFMEMORY	= 5,
	D3DKMT_DEVICEEXECUTION_ERROR_DMAFAULT		= 6,
	D3DKMT_DEVICEEXECUTION_ERROR_DMAPAGEFAULT	= 7,
};

struct d3dkmt_devicereset_state {
	union {
		struct {
			u32	desktop_switched:1;
			u32	reserved:31;
		};
		u32		value;
	};
};

struct d3dkmt_present_stats {
	u32		present_count;
	u32		present_refresh_count;
	u32		sync_refresh_count;
	u64		sync_qpc_time;
	u64		sync_gpu_time;
};

struct d3dkmt_devicepresent_state {
	u32				vidpn_source_id;
	struct d3dkmt_present_stats	present_stats;
};

struct d3dkmt_present_stats_dwm {
	u32	present_count;
	u32	present_refresh_count;
	u64	present_qpc_time;
	u32	sync_refresh_count;
	u64	sync_qpc_time;
	u32	custom_present_duration;
};

struct d3dkmt_devicepagefault_state {
	u64				faulted_primitive_api_sequence_number;
	enum dxgk_render_pipeline_stage	faulted_pipeline_stage;
	u32				faulted_bind_table_entry;
	enum dxgk_page_fault_flags	page_fault_flags;
	struct dxgk_fault_error_code	fault_error_code;
	u64				faulted_virtual_address;
};

struct d3dkmt_devicepresent_state_dwm {
	u32				vidpn_source_id;
	struct d3dkmt_present_stats_dwm	present_stats;
};

struct d3dkmt_devicepresent_queue_state {
	u32	vidpn_source_id;
	bool	bQueuedPresentLimitReached;
};

enum d3dkmt_devicestate_type {
	D3DKMT_DEVICESTATE_EXECUTION		= 1,
	D3DKMT_DEVICESTATE_PRESENT		= 2,
	D3DKMT_DEVICESTATE_RESET		= 3,
	D3DKMT_DEVICESTATE_PRESENT_DWM		= 4,
	D3DKMT_DEVICESTATE_PAGE_FAULT		= 5,
	D3DKMT_DEVICESTATE_PRESENT_QUEUE	= 6,
};

struct d3dkmt_getdevicestate {
	struct d3dkmthandle				device;
	enum d3dkmt_devicestate_type			state_type;
	union {
		enum d3dkmt_deviceexecution_state	execution_state;
		struct d3dkmt_devicepresent_state	present_state;
		struct d3dkmt_devicereset_state		reset_state;
		struct d3dkmt_devicepresent_state_dwm	present_state_dwm;
		struct d3dkmt_devicepagefault_state	page_fault_state;
		struct d3dkmt_devicepresent_queue_state	present_queue_state;
	};
};

enum d3dkmdt_gdisurfacetype {
	D3DKMDT_GDISURFACE_INVALID				= 0,
	D3DKMDT_GDISURFACE_TEXTURE				= 1,
	D3DKMDT_GDISURFACE_STAGING_CPUVISIBLE			= 2,
	D3DKMDT_GDISURFACE_STAGING				= 3,
	D3DKMDT_GDISURFACE_LOOKUPTABLE				= 4,
	D3DKMDT_GDISURFACE_EXISTINGSYSMEM			= 5,
	D3DKMDT_GDISURFACE_TEXTURE_CPUVISIBLE			= 6,
	D3DKMDT_GDISURFACE_TEXTURE_CROSSADAPTER			= 7,
	D3DKMDT_GDISURFACE_TEXTURE_CPUVISIBLE_CROSSADAPTER	= 8,
};

struct d3dddi_rational {
	u32	numerator;
	u32	denominator;
};

enum d3dddiformat {
	D3DDDIFMT_UNKNOWN = 0,
};

struct d3dkmdt_gdisurfacedata {
	u32				width;
	u32				height;
	u32				format;
	enum d3dkmdt_gdisurfacetype	type;
	u32				flags;
	u32				pitch;
};

struct d3dkmtd_stagingsurfacedata {
	u32	width;
	u32	height;
	u32	pitch;
};

struct d3dkmdt_sharedprimarysurfacedata {
	u32			width;
	u32			height;
	enum d3dddiformat	format;
	struct d3dddi_rational	refresh_rate;
	u32			vidpn_source_id;
};

struct d3dkmdt_shadowsurfacedata {
	u32			width;
	u32			height;
	enum d3dddiformat	format;
	u32			pitch;
};

enum d3dkmdt_standardallocationtype {
	D3DKMDT_STANDARDALLOCATION_SHAREDPRIMARYSURFACE	= 1,
	D3DKMDT_STANDARDALLOCATION_SHADOWSURFACE	= 2,
	D3DKMDT_STANDARDALLOCATION_STAGINGSURFACE	= 3,
	D3DKMDT_STANDARDALLOCATION_GDISURFACE		= 4,
};

struct d3dddi_synchronizationobject_flags {
	union {
		struct {
			u32	shared:1;
			u32	nt_security_sharing:1;
			u32	cross_adapter:1;
			u32	top_of_pipeline:1;
			u32	no_signal:1;
			u32	no_wait:1;
			u32	no_signal_max_value_on_tdr:1;
			u32	no_gpu_access:1;
			u32	reserved:23;
		};
		u32		value;
	};
};

enum d3dddi_synchronizationobject_type {
	D3DDDI_SYNCHRONIZATION_MUTEX		= 1,
	D3DDDI_SEMAPHORE			= 2,
	D3DDDI_FENCE				= 3,
	D3DDDI_CPU_NOTIFICATION			= 4,
	D3DDDI_MONITORED_FENCE			= 5,
	D3DDDI_PERIODIC_MONITORED_FENCE		= 6,
	D3DDDI_SYNCHRONIZATION_TYPE_LIMIT
};

struct d3dddi_synchronizationobjectinfo2 {
	enum d3dddi_synchronizationobject_type	type;
	struct d3dddi_synchronizationobject_flags flags;
	union {
		struct {
			u32	initial_state;
		} synchronization_mutex;

		struct {
			u32			max_count;
			u32			initial_count;
		} semaphore;

		struct {
			u64		fence_value;
		} fence;

		struct {
			u64		event;
		} cpu_notification;

		struct {
			u64	initial_fence_value;
			void	*fence_cpu_virtual_address;
			u64	fence_gpu_virtual_address;
			u32	engine_affinity;
		} monitored_fence;

		struct periodic_monitored_fence_t {
			struct d3dkmthandle	adapter;
			u32			vidpn_target_id;
			u64			time;
			void			*fence_cpu_virtual_address;
			u64			fence_gpu_virtual_address;
			u32			engine_affinity;
		} periodic_monitored_fence;

		struct {
			u64	reserved[8];
		} reserved;
	};
	struct d3dkmthandle			shared_handle;
};

struct d3dkmt_createsynchronizationobject2 {
	struct d3dkmthandle			device;
	struct d3dddi_synchronizationobjectinfo2 info;
	struct d3dkmthandle			sync_object;
};

struct d3dkmt_waitforsynchronizationobject2 {
	struct d3dkmthandle	context;
	u32			object_count;
	struct d3dkmthandle	object_array[D3DDDI_MAX_OBJECT_WAITED_ON];
	union {
		struct {
			u64	fence_value;
		} fence;
		u64		reserved[8];
	};
};

struct d3dddicb_signalflags {
	union {
		struct {
			u32			signal_at_submission:1;
			u32			enqueue_cpu_event:1;
			u32			allow_fence_rewind:1;
			u32			reserved:28;
			u32			DXGK_SIGNAL_FLAG_INTERNAL0:1;
		};
		u32				value;
	};
};

struct d3dkmt_signalsynchronizationobject2 {
	struct d3dkmthandle		context;
	u32				object_count;
	struct d3dkmthandle	object_array[D3DDDI_MAX_OBJECT_SIGNALED];
	struct d3dddicb_signalflags	flags;
	u32				context_count;
	struct d3dkmthandle		contexts[D3DDDI_MAX_BROADCAST_CONTEXT];
	union {
		struct {
			u64		fence_value;
		} fence;
		u64			cpu_event_handle;
		u64			reserved[8];
	};
};

struct d3dddi_waitforsynchronizationobjectfromcpu_flags {
	union {
		struct {
			u32			wait_any:1;
			u32			reserved:31;
		};
		u32				value;
	};
};

struct d3dkmt_waitforsynchronizationobjectfromcpu {
	struct d3dkmthandle			device;
	u32					object_count;
	struct d3dkmthandle			*objects;
	u64					*fence_values;
	u64					async_event;
	struct d3dddi_waitforsynchronizationobjectfromcpu_flags flags;
};

struct d3dkmt_signalsynchronizationobjectfromcpu {
	struct d3dkmthandle			device;
	u32					object_count;
	struct d3dkmthandle			*objects;
	u64					*fence_values;
	struct d3dddicb_signalflags		flags;
};

struct d3dkmt_waitforsynchronizationobjectfromgpu {
	struct d3dkmthandle			context;
	u32					object_count;
	struct d3dkmthandle			*objects;
	union {
		u64			*monitored_fence_values;
		u64			fence_value;
		u64			reserved[8];
	};
};

struct d3dkmt_signalsynchronizationobjectfromgpu {
	struct d3dkmthandle		context;
	u32				object_count;
	struct d3dkmthandle		*objects;
	union {
		u64			*monitored_fence_values;
		u64			reserved[8];
	};
};

struct d3dkmt_signalsynchronizationobjectfromgpu2 {
	u32				object_count;
	struct d3dkmthandle		*objects;
	struct d3dddicb_signalflags	flags;
	u32				context_count;
	struct d3dkmthandle		*contexts;
	union {
		u64			fence_value;
		u64			cpu_event_handle;
		u64			*monitored_fence_values;
		u64			reserved[8];
	};
};

struct d3dkmt_destroysynchronizationobject {
	struct d3dkmthandle	sync_object;
};

struct d3dkmt_opensynchronizationobject {
	struct d3dkmthandle	shared_handle;
	struct d3dkmthandle	sync_object;
	u64			reserved[8];
};

struct d3dkmt_submitcommandflags {
	u32					null_rendering:1;
	u32					present_redirected:1;
	u32					reserved:30;
};

struct d3dkmt_submitcommand {
	u64					command_buffer;
	u32					command_length;
	struct d3dkmt_submitcommandflags	flags;
	u64					present_history_token;
	u32					broadcast_context_count;
	struct d3dkmthandle	broadcast_context[D3DDDI_MAX_BROADCAST_CONTEXT];
	void					*priv_drv_data;
	u32					priv_drv_data_size;
	u32					num_primaries;
	struct d3dkmthandle	written_primaries[D3DDDI_MAX_WRITTEN_PRIMARIES];
	u32					num_history_buffers;
	struct d3dkmthandle			*history_buffer_array;
};

struct d3dkmt_submitcommandtohwqueue {
	struct d3dkmthandle			hwqueue;
	u64					hwqueue_progress_fence_id;
	u64					command_buffer;
	u32					command_length;
	u32					priv_drv_data_size;
	void					*priv_drv_data;
	u32					num_primaries;
	struct d3dkmthandle			*written_primaries;
};

struct d3dkmt_setcontextschedulingpriority {
	struct d3dkmthandle			context;
	int					priority;
};

struct d3dkmt_setcontextinprocessschedulingpriority {
	struct d3dkmthandle			context;
	int					priority;
};

struct d3dkmt_getcontextschedulingpriority {
	struct d3dkmthandle			context;
	int					priority;
};

struct d3dkmt_getcontextinprocessschedulingpriority {
	struct d3dkmthandle			context;
	int					priority;
};

struct d3dkmt_setallocationpriority {
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
	const struct d3dkmthandle	*allocation_list;
	u32				allocation_count;
	const u32			*priorities;
};

struct d3dkmt_getallocationpriority {
	struct d3dkmthandle		device;
	struct d3dkmthandle		resource;
	const struct d3dkmthandle	*allocation_list;
	u32				allocation_count;
	u32				*priorities;
};

enum d3dkmt_allocationresidencystatus {
	D3DKMT_ALLOCATIONRESIDENCYSTATUS_RESIDENTINGPUMEMORY	= 1,
	D3DKMT_ALLOCATIONRESIDENCYSTATUS_RESIDENTINSHAREDMEMORY	= 2,
	D3DKMT_ALLOCATIONRESIDENCYSTATUS_NOTRESIDENT		= 3,
};

struct d3dkmt_queryallocationresidency {
	struct d3dkmthandle			device;
	struct d3dkmthandle			resource;
	struct d3dkmthandle			*allocations;
	u32					allocation_count;
	enum d3dkmt_allocationresidencystatus	*residency_status;
};

struct D3DDDICB_LOCK2FLAGS {
	union {
		struct {
			u32			reserved:32;
		};
		u32				value;
	};
};

struct d3dkmt_lock2 {
	struct d3dkmthandle			device;
	struct d3dkmthandle			allocation;
	struct D3DDDICB_LOCK2FLAGS		flags;
	void					*data;
};

struct d3dkmt_unlock2 {
	struct d3dkmthandle			device;
	struct d3dkmthandle			allocation;
};

enum D3DKMT_DEVICE_ERROR_REASON {
	D3DKMT_DEVICE_ERROR_REASON_GENERIC	= 0x80000000,
	D3DKMT_DEVICE_ERROR_REASON_DRIVER_ERROR	= 0x80000006,
};

struct d3dkmt_markdeviceaserror {
	struct d3dkmthandle			device;
	enum D3DKMT_DEVICE_ERROR_REASON		reason;
};

struct D3DDDI_UPDATEALLOCPROPERTY_FLAGS {
	union {
		struct {
			u32			accessed_physically:1;
			u32			reserved:31;
		};
		u32				value;
	};
};

struct D3DDDI_SEGMENTPREFERENCE {
	union {
		struct {
			u32			segment_id0:5;
			u32			direction0:1;
			u32			segment_id1:5;
			u32			direction1:1;
			u32			segment_id2:5;
			u32			direction2:1;
			u32			segment_id3:5;
			u32			direction3:1;
			u32			segment_id4:5;
			u32			direction4:1;
			u32			reserved:2;
		};
		u32				value;
	};
};

struct d3dddi_updateallocproperty {
	struct d3dkmthandle			paging_queue;
	struct d3dkmthandle			allocation;
	u32					supported_segment_set;
	struct D3DDDI_SEGMENTPREFERENCE		preferred_segment;
	struct D3DDDI_UPDATEALLOCPROPERTY_FLAGS	flags;
	u64					paging_fence_value;
	union {
		struct {
			u32			set_accessed_physically:1;
			u32			set_supported_segmentSet:1;
			u32			set_preferred_segment:1;
			u32			reserved:29;
		};
		u32				property_mask_value;
	};
};

enum d3dkmt_offer_priority {
	D3DKMT_OFFER_PRIORITY_LOW	= 1,
	D3DKMT_OFFER_PRIORITY_NORMAL	= 2,
	D3DKMT_OFFER_PRIORITY_HIGH	= 3,
	D3DKMT_OFFER_PRIORITY_AUTO	= 4,
};

struct d3dkmt_offer_flags {
	union {
		struct {
			u32	offer_immediately:1;
			u32	allow_decommit:1;
			u32	reserved:30;
		};
		u32		value;
	};
};

struct d3dkmt_offerallocations {
	struct d3dkmthandle		device;
	struct d3dkmthandle		*resources;
	const struct d3dkmthandle	*allocations;
	u32				allocation_count;
	enum d3dkmt_offer_priority	priority;
	struct d3dkmt_offer_flags	flags;
};

enum d3dddi_reclaim_result {
	D3DDDI_RECLAIM_RESULT_OK		= 0,
	D3DDDI_RECLAIM_RESULT_DISCARDED		= 1,
	D3DDDI_RECLAIM_RESULT_NOT_COMMITTED	= 2,
};

struct d3dkmt_reclaimallocations2 {
	struct d3dkmthandle	paging_queue;
	u32			allocation_count;
	struct d3dkmthandle	*resources;
	struct d3dkmthandle	*allocations;
	union {
		u32	*discarded;
		enum d3dddi_reclaim_result *results;
	};
	u64			paging_fence_value;
};

struct d3dkmt_changevideomemoryreservation {
	u64			process;
	struct d3dkmthandle	adapter;
	enum d3dkmt_memory_segment_group memory_segment_group;
	u64			reservation;
	u32			physical_adapter_index;
};

struct d3dkmt_createhwcontext {
	struct d3dkmthandle	device;
	u32			node_ordinal;
	u32			engine_affinity;
	struct d3dddi_createhwcontextflags flags;
	u32			priv_drv_data_size;
	void			*priv_drv_data;
	struct d3dkmthandle	context;
};

struct d3dkmt_destroyhwcontext {
	struct d3dkmthandle	context;
};

struct d3dkmt_createhwqueue {
	struct d3dkmthandle	context;
	struct d3dddi_createhwqueueflags flags;
	u32			priv_drv_data_size;
	void			*priv_drv_data;
	struct d3dkmthandle	queue;
	struct d3dkmthandle	queue_progress_fence;
	void			*queue_progress_fence_cpu_va;
	u64			queue_progress_fence_gpu_va;
};

struct d3dkmt_destroyhwqueue {
	struct d3dkmthandle	queue;
};

struct d3dkmt_submitwaitforsyncobjectstohwqueue {
	struct d3dkmthandle	hwqueue;
	u32			object_count;
	struct d3dkmthandle	*objects;
	u64			*fence_values;
};

struct d3dkmt_submitsignalsyncobjectstohwqueue {
	struct d3dddicb_signalflags flags;
	u32			hwqueue_count;
	struct d3dkmthandle	*hwqueues;
	u32			object_count;
	struct d3dkmthandle	*objects;
	u64			*fence_values;
};

struct dxgk_gpuclockdata_flags {
	union {
		struct {
			u32	context_management_processor:1;
			u32	reserved:31;
		};
		u32		value;
	};
};

struct dxgk_gpuclockdata {
	u64				gpu_frequency;
	u64				gpu_clock_counter;
	u64				cpu_clock_counter;
	struct dxgk_gpuclockdata_flags	flags;
} __packed;

struct d3dkmt_queryclockcalibration {
	struct d3dkmthandle	adapter;
	u32			node_ordinal;
	u32			physical_adapter_index;
	struct dxgk_gpuclockdata clock_data;
};

struct d3dkmt_flushheaptransitions {
	struct d3dkmthandle	adapter;
};

struct d3dkmt_getsharedresourceadapterluid {
	struct d3dkmthandle	global_share;
	u64			handle;
	struct winluid		adapter_luid;
};

struct d3dkmt_invalidatecache {
	struct d3dkmthandle	device;
	struct d3dkmthandle	allocation;
	u64			offset;
	u64			length;
};

struct d3dddi_openallocationinfo2 {
	struct d3dkmthandle	allocation;
	void			*priv_drv_data;
	u32			priv_drv_data_size;
	u64			gpu_va;
	u64			reserved[6];
};

struct d3dkmt_opensyncobjectfromnthandle {
	u64			nt_handle;
	struct d3dkmthandle	sync_object;
};

struct d3dkmt_opensyncobjectfromnthandle2 {
	u64			nt_handle;
	struct d3dkmthandle	device;
	struct d3dddi_synchronizationobject_flags flags;
	struct d3dkmthandle	sync_object;
	union {
		struct {
			void	*fence_value_cpu_va;
			u64	fence_value_gpu_va;
			u32	engine_affinity;
		} monitored_fence;
		u64	reserved[8];
	};
};

struct d3dkmt_openresource {
	struct d3dkmthandle	device;
	struct d3dkmthandle	global_share;
	u32			allocation_count;
	struct d3dddi_openallocationinfo2 *open_alloc_info;
	void			*private_runtime_data;
	int			private_runtime_data_size;
	void			*resource_priv_drv_data;
	u32			resource_priv_drv_data_size;
	void			*total_priv_drv_data;
	u32			total_priv_drv_data_size;
	struct d3dkmthandle	resource;
};

struct d3dkmt_openresourcefromnthandle {
	struct d3dkmthandle	device;
	u64			nt_handle;
	u32			allocation_count;
	struct d3dddi_openallocationinfo2 *open_alloc_info;
	int			private_runtime_data_size;
	void			*private_runtime_data;
	u32			resource_priv_drv_data_size;
	void			*resource_priv_drv_data;
	u32			total_priv_drv_data_size;
	void			*total_priv_drv_data;
	struct d3dkmthandle	resource;
	struct d3dkmthandle	keyed_mutex;
	void			*keyed_mutex_private_data;
	u32			keyed_mutex_private_data_size;
	struct d3dkmthandle	sync_object;
};

struct d3dkmt_queryresourceinfofromnthandle {
	struct d3dkmthandle	device;
	u64			nt_handle;
	void			*private_runtime_data;
	u32			private_runtime_data_size;
	u32			total_priv_drv_data_size;
	u32			resource_priv_drv_data_size;
	u32			allocation_count;
};

struct d3dkmt_queryresourceinfo {
	struct d3dkmthandle	device;
	struct d3dkmthandle	global_share;
	void			*private_runtime_data;
	u32			private_runtime_data_size;
	u32			total_priv_drv_data_size;
	u32			resource_priv_drv_data_size;
	u32			allocation_count;
};

struct d3dkmt_shareobjects {
	u32			object_count;
	const struct d3dkmthandle *objects;	/* per-process DXG handle */
	void			*object_attr;	/* security attributes */
	u32			desired_access;
	u64			*shared_handle;	/* output file descriptor */
};

union d3dkmt_enumadapters_filter {
	struct {
		u64	include_compute_only:1;
		u64	include_display_only:1;
		u64	reserved:62;
	};
	u64		value;
};

struct d3dkmt_enumadapters3 {
	union d3dkmt_enumadapters_filter	filter;
	u32					adapter_count;
	struct d3dkmt_adapterinfo		*adapters;
};

enum d3dkmt_querystatistics_type {
	D3DKMT_QUERYSTATISTICS_ADAPTER                = 0,
	D3DKMT_QUERYSTATISTICS_PROCESS                = 1,
	D3DKMT_QUERYSTATISTICS_PROCESS_ADAPTER        = 2,
	D3DKMT_QUERYSTATISTICS_SEGMENT                = 3,
	D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT        = 4,
	D3DKMT_QUERYSTATISTICS_NODE                   = 5,
	D3DKMT_QUERYSTATISTICS_PROCESS_NODE           = 6,
	D3DKMT_QUERYSTATISTICS_VIDPNSOURCE            = 7,
	D3DKMT_QUERYSTATISTICS_PROCESS_VIDPNSOURCE    = 8,
	D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP  = 9,
	D3DKMT_QUERYSTATISTICS_PHYSICAL_ADAPTER       = 10,
};

struct d3dkmt_querystatistics_result {
	char size[0x308];
};

struct d3dkmt_querystatistics {
	union {
		struct {
			enum d3dkmt_querystatistics_type	type;
			struct winluid				adapter_luid;
			u64					process;
			struct d3dkmt_querystatistics_result	result;
		};
		char size[0x328];
	};
};

/*
 * Dxgkrnl Graphics Port Driver ioctl definitions
 *
 */

#define LX_DXOPENADAPTERFROMLUID	\
	_IOWR(0x47, 0x01, struct d3dkmt_openadapterfromluid)
#define LX_DXCREATEDEVICE		\
	_IOWR(0x47, 0x02, struct d3dkmt_createdevice)
#define LX_DXCREATECONTEXT		\
	_IOWR(0x47, 0x03, struct d3dkmt_createcontext)
#define LX_DXCREATECONTEXTVIRTUAL	\
	_IOWR(0x47, 0x04, struct d3dkmt_createcontextvirtual)
#define LX_DXDESTROYCONTEXT		\
	_IOWR(0x47, 0x05, struct d3dkmt_destroycontext)
#define LX_DXCREATEALLOCATION		\
	_IOWR(0x47, 0x06, struct d3dkmt_createallocation)
#define LX_DXCREATEPAGINGQUEUE		\
	_IOWR(0x47, 0x07, struct d3dkmt_createpagingqueue)
#define LX_DXRESERVEGPUVIRTUALADDRESS	\
	_IOWR(0x47, 0x08, struct d3dddi_reservegpuvirtualaddress)
#define LX_DXQUERYADAPTERINFO		\
	_IOWR(0x47, 0x09, struct d3dkmt_queryadapterinfo)
#define LX_DXQUERYVIDEOMEMORYINFO	\
	_IOWR(0x47, 0x0a, struct d3dkmt_queryvideomemoryinfo)
#define LX_DXMAKERESIDENT		\
	_IOWR(0x47, 0x0b, struct d3dddi_makeresident)
#define LX_DXMAPGPUVIRTUALADDRESS	\
	_IOWR(0x47, 0x0c, struct d3dddi_mapgpuvirtualaddress)
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
#define LX_DXCREATEHWCONTEXT		\
	_IOWR(0x47, 0x17, struct d3dkmt_createhwcontext)
#define LX_DXCREATEHWQUEUE		\
	_IOWR(0x47, 0x18, struct d3dkmt_createhwqueue)
#define LX_DXDESTROYDEVICE		\
	_IOWR(0x47, 0x19, struct d3dkmt_destroydevice)
#define LX_DXDESTROYHWCONTEXT		\
	_IOWR(0x47, 0x1a, struct d3dkmt_destroyhwcontext)
#define LX_DXDESTROYHWQUEUE		\
	_IOWR(0x47, 0x1b, struct d3dkmt_destroyhwqueue)
#define LX_DXDESTROYPAGINGQUEUE		\
	_IOWR(0x47, 0x1c, struct d3dddi_destroypagingqueue)
#define LX_DXDESTROYSYNCHRONIZATIONOBJECT \
	_IOWR(0x47, 0x1d, struct d3dkmt_destroysynchronizationobject)
#define LX_DXEVICT			\
	_IOWR(0x47, 0x1e, struct d3dkmt_evict)
#define LX_DXFLUSHHEAPTRANSITIONS	\
	_IOWR(0x47, 0x1f, struct d3dkmt_flushheaptransitions)
#define LX_DXFREEGPUVIRTUALADDRESS	\
	_IOWR(0x47, 0x20, struct d3dkmt_freegpuvirtualaddress)
#define LX_DXGETCONTEXTINPROCESSSCHEDULINGPRIORITY \
	_IOWR(0x47, 0x21, struct d3dkmt_getcontextinprocessschedulingpriority)
#define LX_DXGETCONTEXTSCHEDULINGPRIORITY \
	_IOWR(0x47, 0x22, struct d3dkmt_getcontextschedulingpriority)
#define LX_DXGETSHAREDRESOURCEADAPTERLUID \
	_IOWR(0x47, 0x23, struct d3dkmt_getsharedresourceadapterluid)
#define LX_DXINVALIDATECACHE		\
	_IOWR(0x47, 0x24, struct d3dkmt_invalidatecache)
#define LX_DXLOCK2			\
	_IOWR(0x47, 0x25, struct d3dkmt_lock2)
#define LX_DXMARKDEVICEASERROR		\
	_IOWR(0x47, 0x26, struct d3dkmt_markdeviceaserror)
#define LX_DXOFFERALLOCATIONS		\
	_IOWR(0x47, 0x27, struct d3dkmt_offerallocations)
#define LX_DXOPENRESOURCE		\
	_IOWR(0x47, 0x28, struct d3dkmt_openresource)
#define LX_DXOPENSYNCHRONIZATIONOBJECT	\
	_IOWR(0x47, 0x29, struct d3dkmt_opensynchronizationobject)
#define LX_DXQUERYALLOCATIONRESIDENCY	\
	_IOWR(0x47, 0x2a, struct d3dkmt_queryallocationresidency)
#define LX_DXQUERYRESOURCEINFO		\
	_IOWR(0x47, 0x2b, struct d3dkmt_queryresourceinfo)
#define LX_DXRECLAIMALLOCATIONS2	\
	_IOWR(0x47, 0x2c, struct d3dkmt_reclaimallocations2)
#define LX_DXRENDER			\
	_IOWR(0x47, 0x2d, struct d3dkmt_render)
#define LX_DXSETALLOCATIONPRIORITY	\
	_IOWR(0x47, 0x2e, struct d3dkmt_setallocationpriority)
#define LX_DXSETCONTEXTINPROCESSSCHEDULINGPRIORITY \
	_IOWR(0x47, 0x2f, struct d3dkmt_setcontextinprocessschedulingpriority)
#define LX_DXSETCONTEXTSCHEDULINGPRIORITY \
	_IOWR(0x47, 0x30, struct d3dkmt_setcontextschedulingpriority)
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
#define LX_DXUPDATEGPUVIRTUALADDRESS	\
	_IOWR(0x47, 0x39, struct d3dkmt_updategpuvirtualaddress)
#define LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMCPU \
	_IOWR(0x47, 0x3a, struct d3dkmt_waitforsynchronizationobjectfromcpu)
#define LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMGPU \
	_IOWR(0x47, 0x3b, struct d3dkmt_waitforsynchronizationobjectfromgpu)
#define LX_DXGETALLOCATIONPRIORITY	\
	_IOWR(0x47, 0x3c, struct d3dkmt_getallocationpriority)
#define LX_DXQUERYCLOCKCALIBRATION	\
	_IOWR(0x47, 0x3d, struct d3dkmt_queryclockcalibration)
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
#define LX_DXQUERYSTATISTICS	\
	_IOWR(0x47, 0x43, struct d3dkmt_querystatistics)

#define LX_IO_MAX 0x43

#endif /* _D3DKMTHK_H */
