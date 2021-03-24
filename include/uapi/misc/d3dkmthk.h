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
 * Matches the Windows LUID definition.
 * LUID is a locally unique identifier (similar to GUID, but not global),
 * which is guaranteed to be unique intil the computer is rebooted.
 */
struct winluid {
	__u32 a;
	__u32 b;
};

#endif /* _D3DKMTHK_H */
