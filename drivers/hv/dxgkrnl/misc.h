/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2022, Microsoft Corporation.
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

extern const struct d3dkmthandle zerohandle;

/*
 * Synchronization lock hierarchy.
 *
 * The locks here are in the order from lowest to highest.
 * When a lower lock is held, the higher lock should not be acquired.
 *
 * channel_lock (VMBus channel lock)
 * fd_mutex
 * plistmutex (process list mutex)
 * table_lock (handle table lock)
 * core_lock (dxgadapter lock)
 * device_lock (dxgdevice lock)
 * process_adapter_mutex
 * adapter_list_lock
 * device_mutex (dxgglobal mutex)
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
