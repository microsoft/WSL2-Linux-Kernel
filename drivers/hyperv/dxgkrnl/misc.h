// SPDX-License-Identifier: GPL-2.0

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

void dxgmem_check(struct dxgprocess *process, enum dxgk_memory_tag ignore_tag);
void *dxgmem_alloc(struct dxgprocess *process, enum dxgk_memory_tag tag,
		   size_t size);
void dxgmem_free(struct dxgprocess *process, enum dxgk_memory_tag tag,
		 void *address);
void *dxgmem_kalloc(enum dxgk_memory_tag tag, size_t size, gfp_t flags);
void dxgmem_kfree(enum dxgk_memory_tag tag, void *address);

#define DXGK_MAX_LOCK_DEPTH	64
#define W_MAX_PATH		260

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

struct winluid {
	uint a;
	uint b;
};

/*
 * Synchronization lock hierarchy.
 * dxgadapter->adapter_process_list_lock
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

void dxglockorder_acquire(enum dxgk_lockorder order);
void dxglockorder_release(enum dxgk_lockorder order);
void dxglockorder_check_empty(struct dxgthreadinfo *info);
struct dxgthreadinfo *dxglockorder_get_thread(void);
void dxglockorder_put_thread(struct dxgthreadinfo *info);
void dxg_panic(void);

struct dxgmutex {
	struct mutex		mutex;
	enum dxgk_lockorder	lock_order;
};
void dxgmutex_init(struct dxgmutex *m, enum dxgk_lockorder order);
void dxgmutex_lock(struct dxgmutex *m);
void dxgmutex_unlock(struct dxgmutex *m);

u16 *wcsncpy(u16 *dest, const u16 *src, size_t n);

enum dxglockstate {
	DXGLOCK_SHARED,
	DXGLOCK_EXCL
};

#define STATUS_SUCCESS					(int)(0)
#define	STATUS_GRAPHICS_DRIVER_MISMATCH			(int)(0xC01E0009L)
#define	STATUS_OBJECT_NAME_INVALID			(int)(0xC0000033L)
#define	STATUS_OBJECT_PATH_INVALID			(int)(0xC0000039L)
#define	STATUS_DEVICE_REMOVED				(int)(0xC00002B6L)
#define	STATUS_DISK_FULL				(int)(0xC000007FL)
#define	STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE		(int)(0xC01E0200L)
#define	STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST		(int)(0xC01E0116L)
#define	STATUS_GRAPHICS_ALLOCATION_CLOSED		(int)(0xC01E0112L)
#define	STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE	(int)(0xC01E0113L)
#define	STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE	(int)(0xC01E0114L)
#define	STATUS_ILLEGAL_CHARACTER			(int)(0xC0000161L)
#define	STATUS_INVALID_HANDLE				(int)(0xC0000008L)
#define	STATUS_ILLEGAL_INSTRUCTION			(int)(0xC000001DL)
#define	STATUS_INVALID_PARAMETER_1			(int)(0xC00000EFL)
#define	STATUS_INVALID_PARAMETER_2			(int)(0xC00000F0L)
#define	STATUS_INVALID_PARAMETER_3			(int)(0xC00000F1L)
#define	STATUS_INVALID_PARAMETER_4			(int)(0xC00000F2L)
#define	STATUS_INVALID_PARAMETER_5			(int)(0xC00000F3L)
#define	STATUS_INVALID_PARAMETER_6			(int)(0xC00000F4L)
#define	STATUS_INVALID_PARAMETER_7			(int)(0xC00000F5L)
#define	STATUS_INVALID_PARAMETER_8			(int)(0xC00000F6L)
#define	STATUS_INVALID_PARAMETER_9			(int)(0xC00000F7L)
#define	STATUS_INVALID_PARAMETER_10			(int)(0xC00000F8L)
#define	STATUS_INVALID_PARAMETER_11			(int)(0xC00000F9L)
#define	STATUS_INVALID_PARAMETER_12			(int)(0xC00000FAL)
#define	STATUS_IN_PAGE_ERROR				(int)(0xC0000006L)
#define	STATUS_NOT_IMPLEMENTED				(int)(0xC0000002L)
#define	STATUS_PENDING					(int)(0x00000103L)
#define	STATUS_ACCESS_DENIED				(int)(0xC0000022L)
#define	STATUS_BUFFER_TOO_SMALL				(int)(0xC0000023L)
#define	STATUS_OBJECT_PATH_SYNTAX_BAD			(int)(0xC000003BL)
#define	STATUS_OBJECT_TYPE_MISMATCH			(int)(0xC0000024L)
#define	STATUS_GRAPHICS_ALLOCATION_BUSY			(int)(0xC01E0102L)
#define	STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE		(int)(0xC01E0115L)
#define	STATUS_PRIVILEGED_INSTRUCTION			(int)(0xC0000096L)
#define	STATUS_SHARING_VIOLATION			(int)(0xC0000043L)
#define	STATUS_BUFFER_OVERFLOW				(int)(0x80000005L)
#define	STATUS_MEDIA_WRITE_PROTECTED			(int)(0xC00000A2L)
#define	STATUS_INTEGER_OVERFLOW				(int)(0xC0000095L)
#define	STATUS_PRIVILEGE_NOT_HELD			(int)(0xC0000061L)
#define	STATUS_NOT_SUPPORTED				(int)(0xC00000BBL)
#define	STATUS_HOST_UNREACHABLE				(int)(0xC000023DL)
#define	STATUS_NETWORK_UNREACHABLE			(int)(0xC000023CL)
#define	STATUS_CONNECTION_REFUSED			(int)(0xC0000236L)
#define	STATUS_CONNECTION_REFUSED			(int)(0xC0000236L)
#define	STATUS_TIMEOUT					(int)(0x00000102L)
#define	STATUS_WRONG_VOLUME				(int)(0xC0000012L)
#define	STATUS_IO_TIMEOUT				(int)(0xC00000B5L)
#define	STATUS_RETRY					(int)(0xC000022DL)
#define	STATUS_CANCELLED				(int)(0xC0000120L)
#define	STATUS_CONNECTION_DISCONNECTED			(int)(0xC000020CL)
#define	STATUS_CONNECTION_RESET				(int)(0xC000020DL)
#define	STATUS_CONNECTION_ABORTED			(int)(0xC0000241L)
#define	STATUS_INVALID_PARAMETER			(int)(0xC000000DL)
#define	STATUS_INVALID_DEVICE_REQUEST			(int)(0xC0000010L)
#define	STATUS_OBJECT_NAME_NOT_FOUND			(int)(0xC0000034L)
#define	STATUS_OBJECT_PATH_NOT_FOUND			(int)(0xC000003AL)
#define	STATUS_NOT_FOUND				(int)(0xC0000225L)
#define	STATUS_DELETE_PENDING				(int)(0xC0000056L)
#define	STATUS_BAD_NETWORK_NAME				(int)(0xC00000CCL)
#define	STATUS_CANNOT_DELETE				(int)(0xC0000121L)
#define	STATUS_INTERNAL_ERROR				(int)(0xC00000E5L)
#define	STATUS_OBJECTID_EXISTS				(int)(0xC000022BL)
#define	STATUS_DUPLICATE_OBJECTID			(int)(0xC000022AL)
#define	STATUS_ADDRESS_ALREADY_EXISTS			(int)(0xC000020AL)
#define	STATUS_ACCESS_VIOLATION				(int)(0xC0000005L)
#define	STATUS_INSUFFICIENT_RESOURCES			(int)(0xC000009AL)
#define	STATUS_NO_MEMORY				(int)(0xC0000017L)
#define	STATUS_COMMITMENT_LIMIT				(int)(0xC000012DL)
#define	STATUS_GRAPHICS_NO_VIDEO_MEMORY			(int)(0xC01E0100L)
#define	STATUS_OBJECTID_NOT_FOUND			(int)(0xC00002F0L)
#define	STATUS_DIRECTORY_NOT_EMPTY			(int)(0xC0000101L)
#define	STATUS_OBJECT_NAME_EXISTS			(int)(0x40000000L)
#define	STATUS_OBJECT_NAME_COLLISION			(int)(0xC0000035L)
#define	STATUS_UNSUCCESSFUL				(int)(0xC0000001L)
#define	STATUS_NOT_IMPLEMENTED				(int)(0xC0000002L)
#define NT_SUCCESS(status)				(status.v >= 0)

#define ISERROR(ret)					(ret < 0)
#define EINTERNALERROR					EINVAL

#define DXGKRNL_ASSERT(exp)
#define UNUSED(x) (void)(x)

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk:err: " fmt
#define pr_fmt1(fmt)	"dxgk: " fmt
#define pr_fmt2(fmt)	"dxgk:    " fmt

#define DXGKDEBUG 1
/* #define USEPRINTK 1 */

#ifndef DXGKDEBUG
#define TRACE_DEBUG(...)
#define TRACE_DEFINE(...)
#define TRACE_FUNC_ENTER(...)
#define TRACE_FUNC_EXIT(...)
#else
#ifdef USEPRINTK
#define TRACE_DEBUG(level, fmt, ...)\
	printk(KERN_DEBUG pr_fmt2(fmt), ##__VA_ARGS__);

#define TRACE_DEBUG2(level, offset, fmt, ...)				\
do {									\
	if (offset == 0)						\
		printk(KERN_DEBUG pr_fmt1(fmt), ##__VA_ARGS__);	\
	else								\
		printk(KERN_DEBUG pr_fmt2(fmt), ##__VA_ARGS__);	\
} while (false)

#define TRACE_FUNC_ENTER(msg) \
	printk(KERN_DEBUG "dxgk: %s", msg)
#define TRACE_FUNC_EXIT(msg, ret)				\
do {								\
	if (ISERROR(ret))					\
		dxg_pr_err("%s %x %d", msg, ret, ret);		\
	else							\
		printk(KERN_DEBUG "dxgk: %s end", msg);		\
} while (false)
#define TRACE_FUNC_EXIT_ERR(msg, ret)				\
do {								\
	if (ISERROR(ret))					\
		dxg_pr_err("%s %x", msg, ret);			\
} while (false)
#else
#define TRACE_DEBUG(level, fmt, ...)\
	dev_dbg(dxgglobaldev, pr_fmt2(fmt), ##__VA_ARGS__)

#define TRACE_DEBUG2(level, offset, fmt, ...)			\
do {								\
	if (offset == 0)					\
		dev_dbg(dxgglobaldev, pr_fmt1(fmt), ##__VA_ARGS__); \
	else							\
		dev_dbg(dxgglobaldev, pr_fmt2(fmt), ##__VA_ARGS__);\
} while (false)

#define TRACE_FUNC_ENTER(msg)				\
	dev_dbg(dxgglobaldev, "dxgk: %s", msg)
#define TRACE_FUNC_EXIT(msg, ret)			\
do {							\
	if (ISERROR(ret))				\
		dev_dbg(dxgglobaldev, "dxgk:err: %s %x", msg, ret); \
	else						\
		dev_dbg(dxgglobaldev, "dxgk: %s end", msg);	\
} while (false)
#define TRACE_FUNC_EXIT_ERR(msg, ret)			\
do {							\
	if (ISERROR(ret))				\
		dev_dbg(dxgglobaldev, "dxgk:err: %s %x", msg, ret); \
} while (false)
#endif /* USEPRINTK */
#define TRACE_DEFINE(arg) arg
#endif

#ifdef DXGKDEBUGLOCKORDER
#define TRACE_LOCK_ORDER(...)  TRACE_DEBUG(...)
#else
#define TRACE_LOCK_ORDER(...)
#endif

#endif
