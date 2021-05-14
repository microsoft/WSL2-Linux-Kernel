/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Misc definitions
 *
 */

#ifndef _MISC_H_
#define _MISC_H_

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
 *
 * device_list_mutex
 * host_event_list_mutex
 * channel_lock
 * fd_mutex
 * plistmutex
 * table_lock
 * context_list_lock
 * alloc_list_lock
 * resource_mutex
 * shared_resource_list_lock
 * core_lock
 * device_lock
 * process->process_mutex
 * process_adapter_mutex
 * adapter_list_lock
 * device_mutex
 */

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
#define STATUS_OBJECT_NAME_NOT_FOUND			((int)(0xC0000034L))


#define NT_SUCCESS(status)				(status.v >= 0)

#ifndef DEBUG

#define DXGKRNL_ASSERT(exp)

#else

#define DXGKRNL_ASSERT(exp)	\
do {				\
	if (!(exp)) {		\
		dump_stack();	\
		BUG_ON(true);	\
	}			\
} while (0)

#endif /* DEBUG */

#endif /* _MISC_H_ */
