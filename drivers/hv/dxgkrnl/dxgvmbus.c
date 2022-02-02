// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2022, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * VM bus interface implementation
 *
 */

#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/eventfd.h>
#include <linux/hyperv.h>
#include <linux/mman.h>
#include <linux/delay.h>
#include <linux/pagemap.h>
#include "dxgkrnl.h"
#include "dxgvmbus.h"

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk: " fmt

#define RING_BUFSIZE (256 * 1024)

/*
 * The structure is used to track VM bus packets, waiting for completion.
 */
struct dxgvmbuspacket {
	struct list_head packet_list_entry;
	u64 request_id;
	struct completion wait;
	void *buffer;
	u32 buffer_length;
	int status;
	bool completed;
};

struct dxgvmb_ext_header {
	/* Offset from the start of the message to DXGKVMB_COMMAND_BASE */
	u32		command_offset;
	u32		reserved;
	struct winluid	vgpu_luid;
};

#define VMBUSMESSAGEONSTACK	64

struct dxgvmbusmsg {
/* Points to the allocated buffer */
	struct dxgvmb_ext_header	*hdr;
/* Points to dxgkvmb_command_vm_to_host or dxgkvmb_command_vgpu_to_host */
	void				*msg;
/* The vm bus channel, used to pass the message to the host */
	struct dxgvmbuschannel		*channel;
/* Message size in bytes including the header and the payload */
	u32				size;
/* Buffer used for small messages */
	char				msg_on_stack[VMBUSMESSAGEONSTACK];
};

struct dxgvmbusmsgres {
/* Points to the allocated buffer */
	struct dxgvmb_ext_header	*hdr;
/* Points to dxgkvmb_command_vm_to_host or dxgkvmb_command_vgpu_to_host */
	void				*msg;
/* The vm bus channel, used to pass the message to the host */
	struct dxgvmbuschannel		*channel;
/* Message size in bytes including the header, the payload and the result */
	u32				size;
/* Result buffer size in bytes */
	u32				res_size;
/* Points to the result within the allocated buffer */
	void				*res;
};

static int init_message(struct dxgvmbusmsg *msg, struct dxgadapter *adapter,
			struct dxgprocess *process, u32 size)
{
	struct dxgglobal *dxgglobal = dxggbl();

	bool use_ext_header = dxgglobal->vmbus_ver >=
			      DXGK_VMBUS_INTERFACE_VERSION;

	if (use_ext_header)
		size += sizeof(struct dxgvmb_ext_header);
	msg->size = size;
	if (size <= VMBUSMESSAGEONSTACK) {
		msg->hdr = (void *)msg->msg_on_stack;
		memset(msg->hdr, 0, size);
	} else {
		msg->hdr = vzalloc(size);
		if (msg->hdr == NULL)
			return -ENOMEM;
	}
	if (use_ext_header) {
		msg->msg = (char *)&msg->hdr[1];
		msg->hdr->command_offset = sizeof(msg->hdr[0]);
		if (adapter)
			msg->hdr->vgpu_luid = adapter->host_vgpu_luid;
	} else {
		msg->msg = (char *)msg->hdr;
	}
	if (adapter && !dxgglobal->async_msg_enabled)
		msg->channel = &adapter->channel;
	else
		msg->channel = &dxgglobal->channel;
	return 0;
}

static void free_message(struct dxgvmbusmsg *msg, struct dxgprocess *process)
{
	if (msg->hdr && (char *)msg->hdr != msg->msg_on_stack)
		vfree(msg->hdr);
}

/*
 * Helper functions
 */

static void command_vm_to_host_init2(struct dxgkvmb_command_vm_to_host *command,
				     enum dxgkvmb_commandtype_global t,
				     struct d3dkmthandle process)
{
	command->command_type	= t;
	command->process	= process;
	command->command_id	= 0;
	command->channel_type	= DXGKVMB_VM_TO_HOST;
}

static void command_vgpu_to_host_init1(struct dxgkvmb_command_vgpu_to_host
					*command,
					enum dxgkvmb_commandtype type)
{
	command->command_type	= type;
	command->process.v	= 0;
	command->command_id	= 0;
	command->channel_type	= DXGKVMB_VGPU_TO_HOST;
}

static void command_vgpu_to_host_init2(struct dxgkvmb_command_vgpu_to_host
					*command,
					enum dxgkvmb_commandtype type,
					struct d3dkmthandle process)
{
	command->command_type	= type;
	command->process	= process;
	command->command_id	= 0;
	command->channel_type	= DXGKVMB_VGPU_TO_HOST;
}

int ntstatus2int(struct ntstatus status)
{
	if (NT_SUCCESS(status))
		return (int)status.v;
	switch (status.v) {
	case STATUS_OBJECT_NAME_COLLISION:
		return -EEXIST;
	case STATUS_NO_MEMORY:
		return -ENOMEM;
	case STATUS_INVALID_PARAMETER:
		return -EINVAL;
	case STATUS_OBJECT_NAME_INVALID:
	case STATUS_OBJECT_NAME_NOT_FOUND:
		return -ENOENT;
	case STATUS_TIMEOUT:
		return -EAGAIN;
	case STATUS_BUFFER_TOO_SMALL:
		return -EOVERFLOW;
	case STATUS_DEVICE_REMOVED:
		return -ENODEV;
	case STATUS_ACCESS_DENIED:
		return -EACCES;
	case STATUS_NOT_SUPPORTED:
		return -EPERM;
	case STATUS_ILLEGAL_INSTRUCTION:
		return -EOPNOTSUPP;
	case STATUS_INVALID_HANDLE:
		return -EBADF;
	case STATUS_GRAPHICS_ALLOCATION_BUSY:
		return -EINPROGRESS;
	case STATUS_OBJECT_TYPE_MISMATCH:
		return -EPROTOTYPE;
	case STATUS_NOT_IMPLEMENTED:
		return -EPERM;
	default:
		return -EINVAL;
	}
}

int dxgvmbuschannel_init(struct dxgvmbuschannel *ch, struct hv_device *hdev)
{
	int ret;

	ch->hdev = hdev;
	spin_lock_init(&ch->packet_list_mutex);
	INIT_LIST_HEAD(&ch->packet_list_head);
	atomic64_set(&ch->packet_request_id, 0);

	ch->packet_cache = kmem_cache_create("DXGK packet cache",
					     sizeof(struct dxgvmbuspacket), 0,
					     0, NULL);
	if (ch->packet_cache == NULL) {
		DXG_ERR("packet_cache alloc failed");
		ret = -ENOMEM;
		goto cleanup;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
	hdev->channel->max_pkt_size = DXG_MAX_VM_BUS_PACKET_SIZE;
#endif
	ret = vmbus_open(hdev->channel, RING_BUFSIZE, RING_BUFSIZE,
			 NULL, 0, dxgvmbuschannel_receive, ch);
	if (ret) {
		DXG_ERR("vmbus_open failed: %d", ret);
		goto cleanup;
	}

	ch->channel = hdev->channel;

cleanup:

	return ret;
}

void dxgvmbuschannel_destroy(struct dxgvmbuschannel *ch)
{
	kmem_cache_destroy(ch->packet_cache);
	ch->packet_cache = NULL;

	if (ch->channel) {
		vmbus_close(ch->channel);
		ch->channel = NULL;
	}
}

static void command_vm_to_host_init1(struct dxgkvmb_command_vm_to_host *command,
				     enum dxgkvmb_commandtype_global type)
{
	command->command_type = type;
	command->process.v = 0;
	command->command_id = 0;
	command->channel_type = DXGKVMB_VM_TO_HOST;
}

static void process_inband_packet(struct dxgvmbuschannel *channel,
				  struct vmpacket_descriptor *desc)
{
	u32 packet_length = hv_pkt_datalen(desc);
	struct dxgkvmb_command_host_to_vm *packet;

	if (channel->adapter == NULL) {
		if (packet_length < sizeof(struct dxgkvmb_command_host_to_vm)) {
			DXG_ERR("Invalid global packet");
		} else {
			packet = hv_pkt_data(desc);
			DXG_TRACE("global packet %d",
				packet->command_type);
			switch (packet->command_type) {
			case DXGK_VMBCOMMAND_SIGNALGUESTEVENT:
			case DXGK_VMBCOMMAND_SIGNALGUESTEVENTPASSIVE:
				break;
			case DXGK_VMBCOMMAND_SENDWNFNOTIFICATION:
				break;
			default:
				DXG_ERR("unexpected host message %d",
					packet->command_type);
			}
		}
	} else {
		DXG_ERR("Unexpected packet for adapter channel");
	}
}

static void process_completion_packet(struct dxgvmbuschannel *channel,
				      struct vmpacket_descriptor *desc)
{
	struct dxgvmbuspacket *packet = NULL;
	struct dxgvmbuspacket *entry;
	u32 packet_length = hv_pkt_datalen(desc);
	unsigned long flags;

	spin_lock_irqsave(&channel->packet_list_mutex, flags);
	list_for_each_entry(entry, &channel->packet_list_head,
			    packet_list_entry) {
		if (desc->trans_id == entry->request_id) {
			packet = entry;
			list_del(&packet->packet_list_entry);
			packet->completed = true;
			break;
		}
	}
	spin_unlock_irqrestore(&channel->packet_list_mutex, flags);
	if (packet) {
		if (packet->buffer_length) {
			if (packet_length < packet->buffer_length) {
				DXG_TRACE("invalid size %d Expected:%d",
					packet_length,
					packet->buffer_length);
				packet->status = -EOVERFLOW;
			} else {
				memcpy(packet->buffer, hv_pkt_data(desc),
				       packet->buffer_length);
			}
		}
		complete(&packet->wait);
	} else {
		DXG_ERR("did not find packet to complete");
	}
}

/* Receive callback for messages from the host */
void dxgvmbuschannel_receive(void *ctx)
{
	struct dxgvmbuschannel *channel = ctx;
	struct vmpacket_descriptor *desc;
	u32 packet_length = 0;

	DXG_TRACE("New adapter message: %p", channel->adapter);
	foreach_vmbus_pkt(desc, channel->channel) {
		packet_length = hv_pkt_datalen(desc);
		DXG_TRACE("next packet (id, size, type): %llu %d %d",
			desc->trans_id, packet_length, desc->type);
		if (desc->type == VM_PKT_COMP) {
			process_completion_packet(channel, desc);
		} else {
			if (desc->type != VM_PKT_DATA_INBAND)
				DXG_ERR("unexpected packet type");
			else
				process_inband_packet(channel, desc);
		}
	}
}

int dxgvmb_send_sync_msg(struct dxgvmbuschannel *channel,
			 void *command,
			 u32 cmd_size,
			 void *result,
			 u32 result_size)
{
	int ret;
	struct dxgvmbuspacket *packet = NULL;
	struct dxgkvmb_command_vm_to_host *cmd1;
	struct dxgkvmb_command_vgpu_to_host *cmd2;

	if (cmd_size > DXG_MAX_VM_BUS_PACKET_SIZE ||
	    result_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		DXG_ERR("%s invalid data size", __func__);
		return -EINVAL;
	}

	packet = kmem_cache_alloc(channel->packet_cache, 0);
	if (packet == NULL) {
		DXG_ERR("kmem_cache_alloc failed");
		return -ENOMEM;
	}

	if (channel->adapter == NULL) {
		cmd1 = command;
		DXG_TRACE("send_sync_msg global: %d %p %d %d",
			cmd1->command_type, command, cmd_size, result_size);
	} else {
		cmd2 = command;
		DXG_TRACE("send_sync_msg adapter: %d %p %d %d",
			cmd2->command_type, command, cmd_size, result_size);
	}

	packet->request_id = atomic64_inc_return(&channel->packet_request_id);
	init_completion(&packet->wait);
	packet->buffer = result;
	packet->buffer_length = result_size;
	packet->status = 0;
	packet->completed = false;
	spin_lock_irq(&channel->packet_list_mutex);
	list_add_tail(&packet->packet_list_entry, &channel->packet_list_head);
	spin_unlock_irq(&channel->packet_list_mutex);

	ret = vmbus_sendpacket(channel->channel, command, cmd_size,
			       packet->request_id, VM_PKT_DATA_INBAND,
			       VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if (ret) {
		DXG_ERR("vmbus_sendpacket failed: %x", ret);
		spin_lock_irq(&channel->packet_list_mutex);
		list_del(&packet->packet_list_entry);
		spin_unlock_irq(&channel->packet_list_mutex);
		goto cleanup;
	}

	DXG_TRACE("waiting completion: %llu", packet->request_id);
	ret = wait_for_completion_killable(&packet->wait);
	if (ret) {
		DXG_ERR("wait_for_completion failed: %x", ret);
		spin_lock_irq(&channel->packet_list_mutex);
		if (!packet->completed)
			list_del(&packet->packet_list_entry);
		spin_unlock_irq(&channel->packet_list_mutex);
		goto cleanup;
	}
	DXG_TRACE("completion done: %llu %x",
		packet->request_id, packet->status);
	ret = packet->status;

cleanup:

	kmem_cache_free(channel->packet_cache, packet);
	if (ret < 0)
		DXG_TRACE("Error: %x", ret);
	return ret;
}

int dxgvmb_send_async_msg(struct dxgvmbuschannel *channel,
			  void *command,
			  u32 cmd_size)
{
	int ret;
	int try_count = 0;

	if (cmd_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		DXG_ERR("%s invalid data size", __func__);
		return -EINVAL;
	}

	if (channel->adapter) {
		DXG_ERR("Async message sent to the adapter channel");
		return -EINVAL;
	}

	do {
		ret = vmbus_sendpacket(channel->channel, command, cmd_size,
				0, VM_PKT_DATA_INBAND, 0);
		/*
		 * -EAGAIN is returned when the VM bus ring buffer if full.
		 * Wait 2ms to allow the host to process messages and try again.
		 */
		if (ret == -EAGAIN) {
			usleep_range(1000, 2000);
			try_count++;
		}
	} while (ret == -EAGAIN && try_count < 5000);
	if (ret < 0)
		DXG_ERR("vmbus_sendpacket failed: %x", ret);

	return ret;
}

static int
dxgvmb_send_sync_msg_ntstatus(struct dxgvmbuschannel *channel,
			      void *command, u32 cmd_size)
{
	struct ntstatus status;
	int ret;

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   &status, sizeof(status));
	if (ret >= 0)
		ret = ntstatus2int(status);
	return ret;
}

/*
 * Global messages to the host
 */

int dxgvmb_send_set_iospace_region(u64 start, u64 len)
{
	int ret;
	struct dxgkvmb_command_setiospaceregion *command;
	struct dxgvmbusmsg msg;
	struct dxgglobal *dxgglobal = dxggbl();

	ret = init_message(&msg, NULL, NULL, sizeof(*command));
	if (ret)
		return ret;
	command = (void *)msg.msg;

	ret = dxgglobal_acquire_channel_lock();
	if (ret < 0)
		goto cleanup;

	command_vm_to_host_init1(&command->hdr,
				 DXGK_VMBCOMMAND_SETIOSPACEREGION);
	command->start = start;
	command->length = len;
	ret = dxgvmb_send_sync_msg_ntstatus(&dxgglobal->channel, msg.hdr,
					    msg.size);
	if (ret < 0)
		DXG_ERR("send_set_iospace_region failed %x", ret);

	dxgglobal_release_channel_lock();
cleanup:
	free_message(&msg, NULL);
	if (ret)
		DXG_TRACE("Error: %d", ret);
	return ret;
}

int dxgvmb_send_create_process(struct dxgprocess *process)
{
	int ret;
	struct dxgkvmb_command_createprocess *command;
	struct dxgkvmb_command_createprocess_return result = { 0 };
	struct dxgvmbusmsg msg;
	char s[WIN_MAX_PATH];
	int i;
	struct dxgglobal *dxgglobal = dxggbl();

	ret = init_message(&msg, NULL, process, sizeof(*command));
	if (ret)
		return ret;
	command = (void *)msg.msg;

	ret = dxgglobal_acquire_channel_lock();
	if (ret < 0)
		goto cleanup;

	command_vm_to_host_init1(&command->hdr, DXGK_VMBCOMMAND_CREATEPROCESS);
	command->process = process;
	command->process_id = process->pid;
	command->linux_process = 1;
	s[0] = 0;
	__get_task_comm(s, WIN_MAX_PATH, current);
	for (i = 0; i < WIN_MAX_PATH; i++) {
		command->process_name[i] = s[i];
		if (s[i] == 0)
			break;
	}

	ret = dxgvmb_send_sync_msg(&dxgglobal->channel, msg.hdr, msg.size,
				   &result, sizeof(result));
	if (ret < 0) {
		DXG_ERR("create_process failed %d", ret);
	} else if (result.hprocess.v == 0) {
		DXG_ERR("create_process returned 0 handle");
		ret = -ENOTRECOVERABLE;
	} else {
		process->host_handle = result.hprocess;
		DXG_TRACE("create_process returned %x",
			process->host_handle.v);
	}

	dxgglobal_release_channel_lock();

cleanup:
	free_message(&msg, process);
	if (ret)
		DXG_TRACE("err: %d", ret);
	return ret;
}

int dxgvmb_send_destroy_process(struct d3dkmthandle process)
{
	int ret;
	struct dxgkvmb_command_destroyprocess *command;
	struct dxgvmbusmsg msg;
	struct dxgglobal *dxgglobal = dxggbl();

	ret = init_message(&msg, NULL, NULL, sizeof(*command));
	if (ret)
		return ret;
	command = (void *)msg.msg;

	ret = dxgglobal_acquire_channel_lock();
	if (ret < 0)
		goto cleanup;
	command_vm_to_host_init2(&command->hdr, DXGK_VMBCOMMAND_DESTROYPROCESS,
				 process);
	ret = dxgvmb_send_sync_msg_ntstatus(&dxgglobal->channel,
					    msg.hdr, msg.size);
	dxgglobal_release_channel_lock();

cleanup:
	free_message(&msg, NULL);
	if (ret)
		DXG_TRACE("err: %d", ret);
	return ret;
}

/*
 * Virtual GPU messages to the host
 */

int dxgvmb_send_open_adapter(struct dxgadapter *adapter)
{
	int ret;
	struct dxgkvmb_command_openadapter *command;
	struct dxgkvmb_command_openadapter_return result = { };
	struct dxgvmbusmsg msg;
	struct dxgglobal *dxgglobal = dxggbl();

	ret = init_message(&msg, adapter, NULL, sizeof(*command));
	if (ret)
		return ret;
	command = (void *)msg.msg;

	command_vgpu_to_host_init1(&command->hdr, DXGK_VMBCOMMAND_OPENADAPTER);
	command->vmbus_interface_version = dxgglobal->vmbus_ver;
	command->vmbus_last_compatible_interface_version =
	    DXGK_VMBUS_LAST_COMPATIBLE_INTERFACE_VERSION;

	ret = dxgvmb_send_sync_msg(msg.channel, msg.hdr, msg.size,
				   &result, sizeof(result));
	if (ret < 0)
		goto cleanup;

	ret = ntstatus2int(result.status);
	adapter->host_handle = result.host_adapter_handle;

cleanup:
	free_message(&msg, NULL);
	if (ret)
		DXG_ERR("Failed to open adapter: %d", ret);
	return ret;
}

int dxgvmb_send_close_adapter(struct dxgadapter *adapter)
{
	int ret;
	struct dxgkvmb_command_closeadapter *command;
	struct dxgvmbusmsg msg;

	ret = init_message(&msg, adapter, NULL, sizeof(*command));
	if (ret)
		return ret;
	command = (void *)msg.msg;

	command_vgpu_to_host_init1(&command->hdr, DXGK_VMBCOMMAND_CLOSEADAPTER);
	command->host_handle = adapter->host_handle;

	ret = dxgvmb_send_sync_msg(msg.channel, msg.hdr, msg.size,
				   NULL, 0);
	free_message(&msg, NULL);
	if (ret)
		DXG_ERR("Failed to close adapter: %d", ret);
	return ret;
}

int dxgvmb_send_get_internal_adapter_info(struct dxgadapter *adapter)
{
	int ret;
	struct dxgkvmb_command_getinternaladapterinfo *command;
	struct dxgkvmb_command_getinternaladapterinfo_return result = { };
	struct dxgvmbusmsg msg;
	u32 result_size = sizeof(result);
	struct dxgglobal *dxgglobal = dxggbl();

	ret = init_message(&msg, adapter, NULL, sizeof(*command));
	if (ret)
		return ret;
	command = (void *)msg.msg;

	command_vgpu_to_host_init1(&command->hdr,
				   DXGK_VMBCOMMAND_GETINTERNALADAPTERINFO);
	if (dxgglobal->vmbus_ver < DXGK_VMBUS_INTERFACE_VERSION)
		result_size -= sizeof(struct winluid);

	ret = dxgvmb_send_sync_msg(msg.channel, msg.hdr, msg.size,
				   &result, result_size);
	if (ret >= 0) {
		adapter->host_adapter_luid = result.host_adapter_luid;
		adapter->host_vgpu_luid = result.host_vgpu_luid;
		wcsncpy(adapter->device_description, result.device_description,
			sizeof(adapter->device_description) / sizeof(u16));
		wcsncpy(adapter->device_instance_id, result.device_instance_id,
			sizeof(adapter->device_instance_id) / sizeof(u16));
		dxgglobal->async_msg_enabled = result.async_msg_enabled != 0;
	}
	free_message(&msg, NULL);
	if (ret)
		DXG_ERR("Failed to get adapter info: %d", ret);
	return ret;
}

struct d3dkmthandle dxgvmb_send_create_device(struct dxgadapter *adapter,
					struct dxgprocess *process,
					struct d3dkmt_createdevice *args)
{
	int ret;
	struct dxgkvmb_command_createdevice *command;
	struct dxgkvmb_command_createdevice_return result = { };
	struct dxgvmbusmsg msg;

	ret = init_message(&msg, adapter, process, sizeof(*command));
	if (ret)
		goto cleanup;
	command = (void *)msg.msg;

	command_vgpu_to_host_init2(&command->hdr, DXGK_VMBCOMMAND_CREATEDEVICE,
				   process->host_handle);
	command->flags = args->flags;

	ret = dxgvmb_send_sync_msg(msg.channel, msg.hdr, msg.size,
				   &result, sizeof(result));
	if (ret < 0)
		result.device.v = 0;
	free_message(&msg, process);
cleanup:
	if (ret)
		DXG_TRACE("err: %d", ret);
	return result.device;
}

int dxgvmb_send_destroy_device(struct dxgadapter *adapter,
			       struct dxgprocess *process,
			       struct d3dkmthandle h)
{
	int ret;
	struct dxgkvmb_command_destroydevice *command;
	struct dxgvmbusmsg msg = {.hdr = NULL};

	ret = init_message(&msg, adapter, process, sizeof(*command));
	if (ret)
		goto cleanup;
	command = (void *)msg.msg;

	command_vgpu_to_host_init2(&command->hdr, DXGK_VMBCOMMAND_DESTROYDEVICE,
				   process->host_handle);
	command->device = h;

	ret = dxgvmb_send_sync_msg_ntstatus(msg.channel, msg.hdr, msg.size);
cleanup:
	free_message(&msg, process);
	if (ret)
		DXG_TRACE("err: %d", ret);
	return ret;
}

int dxgvmb_send_flush_device(struct dxgdevice *device,
			     enum dxgdevice_flushschedulerreason reason)
{
	int ret;
	struct dxgkvmb_command_flushdevice *command = NULL;
	struct dxgvmbusmsg msg = {.hdr = NULL};
	struct dxgprocess *process = device->process;

	ret = init_message(&msg, device->adapter, process, sizeof(*command));
	if (ret)
		goto cleanup;
	command = (void *)msg.msg;

	command_vgpu_to_host_init2(&command->hdr, DXGK_VMBCOMMAND_FLUSHDEVICE,
				   process->host_handle);
	command->device = device->handle;
	command->reason = reason;

	ret = dxgvmb_send_sync_msg_ntstatus(msg.channel, msg.hdr, msg.size);

cleanup:
	free_message(&msg, process);
	if (ret)
		DXG_TRACE("err: %d", ret);
	return ret;
}

struct d3dkmthandle
dxgvmb_send_create_context(struct dxgadapter *adapter,
			   struct dxgprocess *process,
			   struct d3dkmt_createcontextvirtual *args)
{
	struct dxgkvmb_command_createcontextvirtual *command = NULL;
	u32 cmd_size;
	int ret;
	struct d3dkmthandle context = {};
	struct dxgvmbusmsg msg = {.hdr = NULL};

	if (args->priv_drv_data_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		DXG_ERR("PrivateDriverDataSize is invalid");
		ret = -EINVAL;
		goto cleanup;
	}
	cmd_size = sizeof(struct dxgkvmb_command_createcontextvirtual) +
	    args->priv_drv_data_size - 1;

	ret = init_message(&msg, adapter, process, cmd_size);
	if (ret)
		goto cleanup;
	command = (void *)msg.msg;

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_CREATECONTEXTVIRTUAL,
				   process->host_handle);
	command->device = args->device;
	command->node_ordinal = args->node_ordinal;
	command->engine_affinity = args->engine_affinity;
	command->flags = args->flags;
	command->client_hint = args->client_hint;
	command->priv_drv_data_size = args->priv_drv_data_size;
	if (args->priv_drv_data_size) {
		ret = copy_from_user(command->priv_drv_data,
				     args->priv_drv_data,
				     args->priv_drv_data_size);
		if (ret) {
			DXG_ERR("Faled to copy private data");
			ret = -EINVAL;
			goto cleanup;
		}
	}
	/* Input command is returned back as output */
	ret = dxgvmb_send_sync_msg(msg.channel, msg.hdr, msg.size,
				   command, cmd_size);
	if (ret < 0) {
		goto cleanup;
	} else {
		context = command->context;
		if (args->priv_drv_data_size) {
			ret = copy_to_user(args->priv_drv_data,
					   command->priv_drv_data,
					   args->priv_drv_data_size);
			if (ret) {
				dev_err(DXGDEV,
					"Faled to copy private data to user");
				ret = -EINVAL;
				dxgvmb_send_destroy_context(adapter, process,
							    context);
				context.v = 0;
			}
		}
	}

cleanup:
	free_message(&msg, process);
	if (ret)
		DXG_TRACE("err: %d", ret);
	return context;
}

int dxgvmb_send_destroy_context(struct dxgadapter *adapter,
				struct dxgprocess *process,
				struct d3dkmthandle h)
{
	int ret;
	struct dxgkvmb_command_destroycontext *command;
	struct dxgvmbusmsg msg = {.hdr = NULL};

	ret = init_message(&msg, adapter, process, sizeof(*command));
	if (ret)
		goto cleanup;
	command = (void *)msg.msg;

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_DESTROYCONTEXT,
				   process->host_handle);
	command->context = h;

	ret = dxgvmb_send_sync_msg_ntstatus(msg.channel, msg.hdr, msg.size);
cleanup:
	free_message(&msg, process);
	if (ret)
		DXG_TRACE("err: %d", ret);
	return ret;
}

int dxgvmb_send_query_adapter_info(struct dxgprocess *process,
				   struct dxgadapter *adapter,
				   struct d3dkmt_queryadapterinfo *args)
{
	struct dxgkvmb_command_queryadapterinfo *command;
	u32 cmd_size = sizeof(*command) + args->private_data_size - 1;
	int ret;
	u32 private_data_size;
	void *private_data;
	struct dxgvmbusmsg msg = {.hdr = NULL};
	struct dxgglobal *dxgglobal = dxggbl();

	ret = init_message(&msg, adapter, process, cmd_size);
	if (ret)
		goto cleanup;
	command = (void *)msg.msg;

	ret = copy_from_user(command->private_data,
			     args->private_data, args->private_data_size);
	if (ret) {
		DXG_ERR("Faled to copy private data");
		ret = -EINVAL;
		goto cleanup;
	}

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_QUERYADAPTERINFO,
				   process->host_handle);
	command->private_data_size = args->private_data_size;
	command->query_type = args->type;

	if (dxgglobal->vmbus_ver >= DXGK_VMBUS_INTERFACE_VERSION) {
		private_data = msg.msg;
		private_data_size = command->private_data_size +
				    sizeof(struct ntstatus);
	} else {
		private_data = command->private_data;
		private_data_size = command->private_data_size;
	}

	ret = dxgvmb_send_sync_msg(msg.channel, msg.hdr, msg.size,
				   private_data, private_data_size);
	if (ret < 0)
		goto cleanup;

	if (dxgglobal->vmbus_ver >= DXGK_VMBUS_INTERFACE_VERSION) {
		ret = ntstatus2int(*(struct ntstatus *)private_data);
		if (ret < 0)
			goto cleanup;
		private_data = (char *)private_data + sizeof(struct ntstatus);
	}

	switch (args->type) {
	case _KMTQAITYPE_ADAPTERTYPE:
	case _KMTQAITYPE_ADAPTERTYPE_RENDER:
		{
			struct d3dkmt_adaptertype *adapter_type =
			    (void *)private_data;
			adapter_type->paravirtualized = 1;
			adapter_type->display_supported = 0;
			adapter_type->post_device = 0;
			adapter_type->indirect_display_device = 0;
			adapter_type->acg_supported = 0;
			adapter_type->support_set_timings_from_vidpn = 0;
			break;
		}
	default:
		break;
	}
	ret = copy_to_user(args->private_data, private_data,
			   args->private_data_size);
	if (ret) {
		DXG_ERR("Faled to copy private data to user");
		ret = -EINVAL;
	}

cleanup:
	free_message(&msg, process);
	if (ret)
		DXG_TRACE("err: %d", ret);
	return ret;
}
