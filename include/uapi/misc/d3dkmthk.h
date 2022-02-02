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

#define D3DKMT_ADAPTERS_MAX			64

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

enum d3dkmt_deviceexecution_state {
	_D3DKMT_DEVICEEXECUTION_ACTIVE			= 1,
	_D3DKMT_DEVICEEXECUTION_RESET			= 2,
	_D3DKMT_DEVICEEXECUTION_HUNG			= 3,
	_D3DKMT_DEVICEEXECUTION_STOPPED			= 4,
	_D3DKMT_DEVICEEXECUTION_ERROR_OUTOFMEMORY	= 5,
	_D3DKMT_DEVICEEXECUTION_ERROR_DMAFAULT		= 6,
	_D3DKMT_DEVICEEXECUTION_ERROR_DMAPAGEFAULT	= 7,
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
#define LX_DXQUERYADAPTERINFO		\
	_IOWR(0x47, 0x09, struct d3dkmt_queryadapterinfo)
#define LX_DXENUMADAPTERS2		\
	_IOWR(0x47, 0x14, struct d3dkmt_enumadapters2)
#define LX_DXCLOSEADAPTER		\
	_IOWR(0x47, 0x15, struct d3dkmt_closeadapter)
#define LX_DXDESTROYDEVICE		\
	_IOWR(0x47, 0x19, struct d3dkmt_destroydevice)
#define LX_DXENUMADAPTERS3		\
	_IOWR(0x47, 0x3e, struct d3dkmt_enumadapters3)

#endif /* _D3DKMTHK_H */
