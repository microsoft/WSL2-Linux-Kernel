/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Misc definitions
 *
 */

#ifndef _MISC_H_
#define _MISC_H_

struct dxgprocess;

enum dxgk_memory_tag {
	DXGMEM_GLOBAL		= 0,
	DXGMEM_ADAPTER		= 1,
	DXGMEM_THREADINFO	= 2,
	DXGMEM_PROCESS		= 3,
	DXGMEM_VMBUS		= 4,
	DXGMEM_DEVICE		= 5,
	DXGMEM_RESOURCE		= 6,
	DXGMEM_CONTEXT		= 7,
	DXGMEM_PQUEUE		= 8,
	DXGMEM_SYNCOBJ		= 9,
	DXGMEM_PROCESS_ADAPTER	= 10,
	DXGMEM_HWQUEUE		= 11,
	DXGMEM_HANDLE_TABLE	= 12,
	DXGMEM_TMP		= 13,
	DXGMEM_ALLOCATION	= 14,
	DXGMEM_EVENT		= 15,
	DXGMEM_HOSTEVENT	= 16,
	DXGMEM_SHAREDSYNCOBJ	= 17,
	DXGMEM_SHAREDRESOURCE	= 18,
	DXGMEM_ALLOCPRIVATE	= 19,
	DXGMEM_RUNTIMEPRIVATE	= 20,
	DXGMEM_RESOURCEPRIVATE	= 21,
	DXGMEM_LAST
};

/* Max number of nested synchronization locks */
#define DXGK_MAX_LOCK_DEPTH	64
/* Max characters in Windows path */
#define WIN_MAX_PATH		260

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

extern const struct d3dkmthandle zerohandle;

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

/*
 * Synchronization lock hierarchy.
 *
 * The higher enum value, the higher is the lock order.
 * When a lower lock ois held, the higher lock should not be acquired.
 */
enum dxgk_lockorder {
	DXGLOCK_INVALID = 0,
	DXGLOCK_PROCESSADAPTERDEVICELIST,	/* device_list_mutex */
	DXGLOCK_GLOBAL_HOSTEVENTLIST,		/* host_event_list_mutex */
	DXGLOCK_GLOBAL_CHANNEL,			/* channel_lock */
	DXGLOCK_FDMUTEX,			/* fd_mutex */
	DXGLOCK_PROCESSLIST,			/* plistmutex */
	DXGLOCK_HANDLETABLE,			/* table_lock */
	DXGLOCK_DEVICE_CONTEXTLIST,		/* context_list_lock */
	DXGLOCK_DEVICE_ALLOCLIST,		/* alloc_list_lock */
	DXGLOCK_RESOURCE,			/* resource_mutex */
	DXGLOCK_SHAREDRESOURCELIST,		/* shared_resource_list_lock */
	DXGLOCK_ADAPTER,			/* core_lock */
	DXGLOCK_DEVICE,				/* device_lock */
	DXGLOCK_PROCESSMUTEX,			/* process->process_mutex */
	DXGLOCK_PROCESSADAPTER,			/* process_adapter_mutex */
	DXGLOCK_GLOBAL_ADAPTERLIST,		/* adapter_list_lock */
	DXGLOCK_GLOBAL_DEVICE,			/* device_mutex */
};

struct dxgk_lockinfo {
	enum dxgk_lockorder lock_order;
};

struct dxgthreadinfo {
	struct list_head	thread_info_list_entry;
	struct task_struct	*thread;
	int			refcount;
	int			current_lock_index;
	struct dxgk_lockinfo	lock_info[DXGK_MAX_LOCK_DEPTH];
	bool			lock_held;
};

u16 *wcsncpy(u16 *dest, const u16 *src, size_t n);

enum dxglockstate {
	DXGLOCK_SHARED,
	DXGLOCK_EXCL
};

/*
 * Some of the Windows return codes, which needs to be translated to Linux
 * IOCTL return codes. Positive values are success codes and need to be
 * returned from the driver IOCTLs. libdxcore.so depends on returning
 * specific return codes.
 */
#define STATUS_SUCCESS					((int)(0))
#define	STATUS_OBJECT_NAME_INVALID			((int)(0xC0000033L))
#define	STATUS_DEVICE_REMOVED				((int)(0xC00002B6L))
#define	STATUS_INVALID_HANDLE				((int)(0xC0000008L))
#define	STATUS_ILLEGAL_INSTRUCTION			((int)(0xC000001DL))
#define	STATUS_NOT_IMPLEMENTED				((int)(0xC0000002L))
#define	STATUS_PENDING					((int)(0x00000103L))
#define	STATUS_ACCESS_DENIED				((int)(0xC0000022L))
#define	STATUS_BUFFER_TOO_SMALL				((int)(0xC0000023L))
#define	STATUS_OBJECT_TYPE_MISMATCH			((int)(0xC0000024L))
#define	STATUS_GRAPHICS_ALLOCATION_BUSY			((int)(0xC01E0102L))
#define	STATUS_NOT_SUPPORTED				((int)(0xC00000BBL))
#define	STATUS_TIMEOUT					((int)(0x00000102L))
#define	STATUS_INVALID_PARAMETER			((int)(0xC000000DL))
#define	STATUS_NO_MEMORY				((int)(0xC0000017L))
#define	STATUS_OBJECT_NAME_COLLISION			((int)(0xC0000035L))

#define NT_SUCCESS(status)				(status.v >= 0)

#ifndef CONFIG_DXGKRNL_DEBUG

#define DXGKRNL_ASSERT(exp)
#define dxgmem_check(process, ignore_tag)
#define dxgmem_addalloc(process, tag)
#define dxgmem_remalloc(process, tag)

#define dxglockorder_acquire(order)
#define dxglockorder_release(order)
#define dxglockorder_check_empty(info)
#define dxglockorder_get_thread() NULL
#define dxglockorder_put_thread(info)

#else

#define DXGKRNL_ASSERT(exp)	\
do {				\
	if (!(exp)) {		\
		dump_stack();	\
		BUG_ON(true);	\
	}			\
} while (0)

void dxgmem_check(struct dxgprocess *process, enum dxgk_memory_tag ignore_tag);
void dxgmem_addalloc(struct dxgprocess *process, enum dxgk_memory_tag tag);
void dxgmem_remalloc(struct dxgprocess *process, enum dxgk_memory_tag tag);

void dxglockorder_acquire(enum dxgk_lockorder order);
void dxglockorder_release(enum dxgk_lockorder order);
void dxglockorder_check_empty(struct dxgthreadinfo *info);
struct dxgthreadinfo *dxglockorder_get_thread(void);
void dxglockorder_put_thread(struct dxgthreadinfo *info);

#endif /* CONFIG_DXGKRNL_DEBUG */

#endif /* _MISC_H_ */
