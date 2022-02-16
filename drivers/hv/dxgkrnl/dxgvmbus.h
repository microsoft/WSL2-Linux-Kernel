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

#define DXG_MAX_VM_BUS_PACKET_SIZE	(1024 * 128)

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

struct dxgkvmb_command_host_to_vm {
	u64					command_id;
	struct d3dkmthandle			process;
	u32					channel_type	: 8;
	u32					async_msg	: 1;
	u32					reserved	: 23;
	enum dxgkvmb_commandtype_host_to_vm	command_type;
};

/* Returns ntstatus */
struct dxgkvmb_command_setiospaceregion {
	struct dxgkvmb_command_vm_to_host hdr;
	u64				start;
	u64				length;
	u32				shared_page_gpadl;
};

#endif /* _DXGVMBUS_H */
