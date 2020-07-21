// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@microsoft.com>
 *
 * Dxgkrnl Graphics Port Driver
 * VM bus interface implementation
 *
 */

#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/eventfd.h>
#include <linux/hyperv.h>
#include <linux/mman.h>

#include "dxgkrnl.h"
#include "dxgvmbus.h"

/*
 * The interface version is used to ensure that the host and the guest use the
 * same VM bus protocol. It needs to be incremented every time the VM bus
 * interface changes. DXGK_VMBUS_LAST_COMPATIBLE_INTERFACE_VERSION is
 * incremented each time the earlier versions of the interface are no longer
 * compatible with the current version.
 */
const uint DXGK_VMBUS_INTERFACE_VERSION = 27;
const uint DXGK_VMBUS_LAST_COMPATIBLE_INTERFACE_VERSION = 16;

#define RING_BUFSIZE (256 * 1024)

struct dxgvmbuspacket {
	struct list_head packet_list_entry;
	u64 request_id;
	struct completion wait;
	void *buffer;
	u32 buffer_length;
	int status;
};

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
		pr_err("packet_cache alloc failed");
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	ret = vmbus_open(hdev->channel, RING_BUFSIZE, RING_BUFSIZE,
			 NULL, 0, dxgvmbuschannel_receive, ch);
	if (ret) {
		pr_err("vmbus_open failed: %d", ret);
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

static inline void command_vm_to_host_init0(struct dxgkvmb_command_vm_to_host
					    *command)
{
	command->command_type = DXGK_VMBCOMMAND_INVALID_VM_TO_HOST;
	command->process = 0;
	command->command_id = 0;
	command->channel_type = DXGKVMB_VM_TO_HOST;
}

static inline void command_vm_to_host_init1(struct dxgkvmb_command_vm_to_host
					    *command,
					    enum dxgkvmb_commandtype_global
					    type)
{
	command->command_type = type;
	command->process = 0;
	command->command_id = 0;
	command->channel_type = DXGKVMB_VM_TO_HOST;
}

void signal_guest_event(struct dxgkvmb_command_host_to_vm *packet,
			u32 packet_length)
{
	struct dxgkvmb_command_signalguestevent *command = (void *)packet;

	TRACE_DEBUG(1, "%s global packet", __func__);

	if (packet_length < sizeof(struct dxgkvmb_command_signalguestevent)) {
		pr_err("invalid packet size");
		return;
	}
	if (command->event == 0) {
		pr_err("invalid event pointer");
		return;
	}
	dxgglobal_signal_host_event(command->event);
}

void process_inband_packet(struct dxgvmbuschannel *channel,
			   struct vmpacket_descriptor *desc)
{
	u32 packet_length = hv_pkt_datalen(desc);

	if (channel->adapter == NULL) {
		if (packet_length < sizeof(struct dxgkvmb_command_host_to_vm)) {
			pr_err("Invalid global packet");
		} else {
			struct dxgkvmb_command_host_to_vm *packet =
			    hv_pkt_data(desc);
			TRACE_DEBUG(1, "global packet %d",
				    packet->command_type);
			switch (packet->command_type) {
			case DXGK_VMBCOMMAND_SETGUESTDATA:
				break;
			case DXGK_VMBCOMMAND_SIGNALGUESTEVENT:
			case DXGK_VMBCOMMAND_SIGNALGUESTEVENTPASSIVE:
				signal_guest_event(packet, packet_length);
				break;
			case DXGK_VMBCOMMAND_SENDWNFNOTIFICATION:
				break;
			default:
				pr_err("unexpected host message %d",
					   packet->command_type);
			}
		}
	} else {
		pr_err("Unexpected packet for adapter channel");
	}
}

void process_completion_packet(struct dxgvmbuschannel *channel,
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
			break;
		}
	}
	spin_unlock_irqrestore(&channel->packet_list_mutex, flags);

	if (packet) {
		if (packet->buffer_length) {
			if (packet_length < packet->buffer_length) {
				TRACE_DEBUG(1, "invalid size %d Expected:%d",
					    packet_length,
					    packet->buffer_length);
				packet->status = STATUS_BUFFER_OVERFLOW;
			} else {
				memcpy(packet->buffer, hv_pkt_data(desc),
				       packet->buffer_length);
			}
		}
		complete(&packet->wait);
	} else {
		pr_err("did not find packet to complete");
	}
}

/* Receive callback for messages from the host */
void dxgvmbuschannel_receive(void *ctx)
{
	struct dxgvmbuschannel *channel = ctx;
	struct vmpacket_descriptor *desc;

	TRACE_DEBUG(1, "%s %p", __func__, channel->adapter);
	foreach_vmbus_pkt(desc, channel->channel) {
		TRACE_DEFINE(u32 packet_length = hv_pkt_datalen(desc);
		    )
		    TRACE_DEBUG(1, "next packet (id, size, type): %llu %d %d",
				desc->trans_id, packet_length, desc->type);
		if (desc->type == VM_PKT_COMP) {
			process_completion_packet(channel, desc);
		} else {
			if (desc->type != VM_PKT_DATA_INBAND)
				pr_err("unexpected packet type");
			process_inband_packet(channel, desc);
		}
	}
}

int dxgvmb_send_sync_msg(struct dxgvmbuschannel *channel,
			 void *command,
			 u32 cmd_size, void *result, u32 result_size)
{
	int ret = 0;
	unsigned long t;
	struct dxgvmbuspacket *packet = NULL;

	if (cmd_size > DXG_MAX_VM_BUS_PACKET_SIZE ||
	    result_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		pr_err("%s invalid data size", __func__);
		return STATUS_INVALID_PARAMETER;
	}

	packet = kmem_cache_alloc(channel->packet_cache, 0);
	if (packet == NULL) {
		pr_err("kmem_cache_alloc failed");
		return STATUS_NO_MEMORY;
	}

	if (channel->adapter == NULL) {
		TRACE_DEFINE(struct dxgkvmb_command_vm_to_host *cmd = command;
		    )
		    TRACE_DEBUG(1, "send_sync_msg global: %d %p %d %d",
				cmd->command_type, command, cmd_size,
				result_size);
	} else {
		TRACE_DEFINE(struct dxgkvmb_command_vgpu_to_host *cmd = command;
		    )
		    TRACE_DEBUG(1, "send_sync_msg adapter: %d %p %d %d",
				cmd->command_type, command, cmd_size,
				result_size);
	}

	packet->request_id = atomic64_inc_return(&channel->packet_request_id);
	init_completion(&packet->wait);
	packet->buffer = result;
	packet->buffer_length = result_size;
	packet->status = 0;
	spin_lock_irq(&channel->packet_list_mutex);
	list_add_tail(&packet->packet_list_entry, &channel->packet_list_head);
	spin_unlock_irq(&channel->packet_list_mutex);

	ret = vmbus_sendpacket(channel->channel, command, cmd_size,
			       packet->request_id, VM_PKT_DATA_INBAND,
			       VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if (ret) {
		pr_err("vmbus_sendpacket failed");
		goto cleanup;
	}

	TRACE_DEBUG(1, "waiting for completion: %llu", packet->request_id);
	t = wait_for_completion_timeout(&packet->wait, (1000 * HZ));
	if (!t) {
		TRACE_DEBUG(1, "timeout waiting for completion");
		ret = STATUS_TIMEOUT;
	} else {
		TRACE_DEBUG(1, "completion done: %llu %x",
			    packet->request_id, packet->status);
		if (!NT_SUCCESS(packet->status))
			ret = packet->status;
	}

cleanup:

	kmem_cache_free(channel->packet_cache, packet);
	return ret;
}

static ntstatus dxgvmb_send_sync_msg_ntstatus(struct dxgvmbuschannel *channel,
					      void *command, u32 cmd_size)
{
	ntstatus status = STATUS_SUCCESS;
	int ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				       &status, sizeof(ntstatus));
	if (ret)
		status = STATUS_UNSUCCESSFUL;
	return status;
}

static int check_iospace_address(unsigned long address, uint size)
{
	if (address < dxgglobal->mmiospace_base ||
	    size > dxgglobal->mmiospace_size ||
	    address >= (dxgglobal->mmiospace_base +
			dxgglobal->mmiospace_size - size)) {
		pr_err("invalid iospace address %lx", address);
		return STATUS_INVALID_PARAMETER;
	}
	return 0;
}

int dxg_unmap_iospace(void *va, uint size)
{
	int ret = 0;

	TRACE_DEBUG(1, "%s %p %x", __func__, va, size);

	/*
	 * When an app calls exit(), dxgkrnl is called to close the device
	 * with current->mm equal to NULL.
	 */
	if (current->mm) {
		ret = vm_munmap((unsigned long)va, size);
		if (ret)
			pr_err("vm_munmap failed %d", ret);
	}
	return ret;
}

static uint8_t *dxg_map_iospace(uint64_t iospace_address, uint size,
				unsigned long protection, bool cached)
{
	struct vm_area_struct *vma;
	unsigned long va;
	int ret = 0;

	TRACE_DEBUG(1, "%s: %llx %x %lx",
		    __func__, iospace_address, size, protection);
	if (check_iospace_address(iospace_address, size)) {
		pr_err("%s: invalid address", __func__);
		return NULL;
	}

	va = vm_mmap(NULL, 0, size, protection, MAP_SHARED | MAP_ANONYMOUS, 0);
	if ((long)va <= 0) {
		pr_err("vm_mmap failed %lx %d", va, size);
		return NULL;
	}

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, (unsigned long)va);
	if (vma) {
		pgprot_t prot = vma->vm_page_prot;

		if (!cached)
			prot = pgprot_writecombine(prot);
		TRACE_DEBUG(1, "vma: %lx %lx %lx",
			    vma->vm_start, vma->vm_end, va);
		vma->vm_pgoff = iospace_address >> PAGE_SHIFT;
		ret = io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
					 size, prot);
		if (ret)
			pr_err("io_remap_pfn_range failed: %d", ret);
	} else {
		pr_err("failed to find vma: %p %lx", vma, va);
		ret = STATUS_NO_MEMORY;
	}
	up_read(&current->mm->mmap_sem);

	if (ret) {
		dxg_unmap_iospace((void *)va, size);
		return NULL;
	}
	TRACE_DEBUG(1, "%s end: %lx", __func__, va);
	return (uint8_t *) va;
}

/*
 * Messages to the host
 */

int dxgvmb_send_set_iospace_region(u64 start, u64 len, u32 shared_mem_gpadl)
{
	ntstatus status;
	struct dxgkvmb_command_setiospaceregion command = { };
	int ret = dxgglobal_acquire_channel_lock();

	if (ret)
		goto cleanup;

	command_vm_to_host_init1(&command.hdr,
				 DXGK_VMBCOMMAND_SETIOSPACEREGION);
	command.start = start;
	command.length = len;
	command.shared_page_gpadl = shared_mem_gpadl;
	status = dxgvmb_send_sync_msg_ntstatus(&dxgglobal->channel, &command,
					       sizeof(command));
	if (!NT_SUCCESS(status)) {
		pr_err("send_set_iospace_region failed %x", status);
		ret = status;
	}

	dxgglobal_release_channel_lock();
cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_create_process(struct dxgprocess *process)
{
	int ret = 0;
	struct dxgkvmb_command_createprocess command = { 0 };
	struct dxgkvmb_command_createprocess_return result = { 0 };
	char s[W_MAX_PATH];
	int i;

	ret = dxgglobal_acquire_channel_lock();
	if (ret)
		goto cleanup;

	TRACE_DEBUG(1, "%s", __func__);
	command_vm_to_host_init1(&command.hdr, DXGK_VMBCOMMAND_CREATEPROCESS);
	command.process = process;
	command.process_id = process->process->pid;
	command.linux_process = 1;
	s[0] = 0;
	__get_task_comm(s, W_MAX_PATH, process->process);
	for (i = 0; i < W_MAX_PATH; i++) {
		command.process_name[i] = s[i];
		if (s[i] == 0)
			break;
	}

	TRACE_DEBUG(1, "create_process msg %d %d",
		    command.hdr.command_type, (u32) sizeof(command));
	ret = dxgvmb_send_sync_msg(&dxgglobal->channel, &command,
				   sizeof(command), &result, sizeof(result));
	if (ret) {
		pr_err("create_process failed %d", ret);
	} else if (result.hprocess == 0) {
		pr_err("create_process returned 0 handle");
		ret = STATUS_INTERNAL_ERROR;
	} else {
		process->host_handle = result.hprocess;
		TRACE_DEBUG(1, "create_process returned %x",
			    process->host_handle);
	}

	dxgglobal_release_channel_lock();

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_destroy_process(d3dkmt_handle process)
{
	ntstatus status;
	struct dxgkvmb_command_destroyprocess command = { 0 };

	status = dxgglobal_acquire_channel_lock();
	if (!NT_SUCCESS(status))
		goto cleanup;
	command_vm_to_host_init2(&command.hdr, DXGK_VMBCOMMAND_DESTROYPROCESS,
				 process);
	status = dxgvmb_send_sync_msg_ntstatus(&dxgglobal->channel,
					       &command, sizeof(command));
	dxgglobal_release_channel_lock();

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_open_adapter(struct dxgadapter *adapter)
{
	int ret;
	struct dxgkvmb_command_openadapter command = { };
	struct dxgkvmb_command_openadapter_return result = { };

	command_vgpu_to_host_init1(&command.hdr, DXGK_VMBCOMMAND_OPENADAPTER);
	command.vmbus_interface_version = DXGK_VMBUS_INTERFACE_VERSION,
	    command.vmbus_last_compatible_interface_version =
	    DXGK_VMBUS_LAST_COMPATIBLE_INTERFACE_VERSION;

	ret = dxgvmb_send_sync_msg(&adapter->channel, &command, sizeof(command),
				   &result, sizeof(result));
	if (ret)
		goto cleanup;

	ret = result.status;
	adapter->host_handle = result.host_adapter_handle;

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_close_adapter(struct dxgadapter *adapter)
{
	int ret = 0;
	struct dxgkvmb_command_closeadapter command;

	command_vgpu_to_host_init1(&command.hdr, DXGK_VMBCOMMAND_CLOSEADAPTER);
	command.host_handle = adapter->host_handle;

	ret = dxgvmb_send_sync_msg(&adapter->channel, &command, sizeof(command),
				   NULL, 0);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_get_internal_adapter_info(struct dxgadapter *adapter)
{
	int ret = 0;
	struct dxgkvmb_command_getinternaladapterinfo command = { };
	struct dxgkvmb_command_getinternaladapterinfo_return result = { };

	command_vgpu_to_host_init1(&command.hdr,
				   DXGK_VMBCOMMAND_GETINTERNALADAPTERINFO);

	ret = dxgvmb_send_sync_msg(&adapter->channel, &command, sizeof(command),
				   &result, sizeof(result));
	if (NT_SUCCESS(ret)) {
		adapter->host_adapter_luid = result.host_adapter_luid;
		wcsncpy(adapter->device_description, result.device_description,
			sizeof(adapter->device_description) / sizeof(winwchar));
		wcsncpy(adapter->device_instance_id, result.device_instance_id,
			sizeof(adapter->device_instance_id) / sizeof(winwchar));
	}
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

d3dkmt_handle dxgvmb_send_create_device(struct dxgadapter *adapter,
					struct dxgprocess *process,
					struct d3dkmt_createdevice *args)
{
	int ret;
	struct dxgkvmb_command_createdevice command = { };
	uint cmd_size = sizeof(command);
	struct dxgkvmb_command_createdevice_return result = { };

	command_vgpu_to_host_init2(&command.hdr, DXGK_VMBCOMMAND_CREATEDEVICE,
				   process->host_handle);
	command.flags = args->flags;
	ret = dxgvmb_send_sync_msg(&adapter->channel, &command, cmd_size,
				   &result, sizeof(result));
	if (ret)
		result.device = 0;
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return result.device;
}

int dxgvmb_send_destroy_device(struct dxgadapter *adapter,
			       struct dxgprocess *process, d3dkmt_handle h)
{
	ntstatus status;
	struct dxgkvmb_command_destroydevice command = { };
	uint cmd_size = sizeof(command);

	command_vgpu_to_host_init2(&command.hdr, DXGK_VMBCOMMAND_DESTROYDEVICE,
				   process->host_handle);
	command.device = h;

	status = dxgvmb_send_sync_msg_ntstatus(&adapter->channel, &command,
					       cmd_size);
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

d3dkmt_handle dxgvmb_send_create_context(struct dxgadapter *adapter,
					 struct dxgprocess *process,
					 struct d3dkmt_createcontextvirtual
					 *args)
{
	struct dxgkvmb_command_createcontextvirtual *command = NULL;
	uint cmd_size;
	int ret;
	d3dkmt_handle context = 0;

	if (args->priv_drv_data_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		pr_err("PrivateDriverDataSize is invalid");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	cmd_size = sizeof(struct dxgkvmb_command_createcontextvirtual) +
	    args->priv_drv_data_size - 1;
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		pr_err("failed to allocate memory for command");
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
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
		ret = dxg_copy_from_user(command->priv_drv_data,
					 args->priv_drv_data,
					 args->priv_drv_data_size);
		if (ret)
			goto cleanup;
	}
	/* Input command is returned back as output */
	ret = dxgvmb_send_sync_msg(&adapter->channel, command, cmd_size,
				   command, cmd_size);
	if (ret) {
		goto cleanup;
	} else {
		context = command->context;
		if (args->priv_drv_data_size) {
			ret = dxg_copy_to_user(args->priv_drv_data,
					       command->priv_drv_data,
					       args->priv_drv_data_size);
			if (ret) {
				dxgvmb_send_destroy_context(adapter, process,
							    context);
				context = 0;
			}
		}
	}

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	return context;
}

int dxgvmb_send_destroy_context(struct dxgadapter *adapter,
				struct dxgprocess *process, d3dkmt_handle h)
{
	ntstatus status;
	struct dxgkvmb_command_destroycontext command = { };
	uint cmd_size = sizeof(command);

	command_vgpu_to_host_init2(&command.hdr, DXGK_VMBCOMMAND_DESTROYCONTEXT,
				   process->host_handle);
	command.context = h;

	status = dxgvmb_send_sync_msg_ntstatus(&adapter->channel, &command,
					       cmd_size);
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_create_paging_queue(struct dxgprocess *process,
				    struct dxgvmbuschannel *channel,
				    struct dxgdevice *device,
				    struct d3dkmt_createpagingqueue *args,
				    struct dxgpagingqueue *pqueue)
{
	struct dxgkvmb_command_createpagingqueue_return result;
	struct dxgkvmb_command_createpagingqueue command;
	int ret;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_CREATEPAGINGQUEUE,
				   process->host_handle);
	command.args = *args;
	args->paging_queue = 0;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command), &result,
				   sizeof(result));
	if (ret) {
		pr_err("send_create_paging_queue failed %x", ret);
		goto cleanup;
	}

	args->paging_queue = result.paging_queue;
	args->sync_object = result.sync_object;
	args->fence_cpu_virtual_address =
	    dxg_map_iospace(result.fence_storage_physical_address, PAGE_SIZE,
			    PROT_READ | PROT_WRITE, true);
	if (args->fence_cpu_virtual_address == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	pqueue->mapped_address = args->fence_cpu_virtual_address;
	pqueue->handle = args->paging_queue;

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_destroy_paging_queue(struct dxgprocess *process,
				     struct dxgvmbuschannel *channel,
				     d3dkmt_handle h)
{
	int ret;
	struct dxgkvmb_command_destroypagingqueue command;
	uint cmd_size = sizeof(command);

	ret = dxgglobal_acquire_channel_lock();
	if (ret)
		goto cleanup;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_DESTROYPAGINGQUEUE,
				   process->host_handle);
	command.paging_queue = h;

	ret = dxgvmb_send_sync_msg(channel, &command, cmd_size, NULL, 0);

	dxgglobal_release_channel_lock();

cleanup:

	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

static int copy_private_data(struct d3dkmt_createallocation *args,
			     struct dxgkvmb_command_createallocation *command,
			     struct d3dddi_allocationinfo2 *input_alloc_info,
			     struct d3dkmt_createstandardallocation
			     *standard_alloc)
{
	struct dxgkvmb_command_createallocation_allocinfo *alloc_info;
	struct d3dddi_allocationinfo2 *input_alloc;
	int ret = 0;
	int i;
	uint8_t *private_data_dest = (uint8_t *) &command[1] +
	    (args->alloc_count *
	     sizeof(struct dxgkvmb_command_createallocation_allocinfo));

	if (args->private_runtime_data_size) {
		ret = dxg_copy_from_user(private_data_dest,
					 args->private_runtime_data,
					 args->private_runtime_data_size);
		if (ret)
			goto cleanup;
		private_data_dest += args->private_runtime_data_size;
	}

	if (args->flags.standard_allocation) {
		TRACE_DEBUG2(1, 1, "private data offset %d",
			     (uint) (private_data_dest - (uint8_t *) command));

		args->priv_drv_data_size = sizeof(*args->standard_allocation);
		memcpy(private_data_dest, standard_alloc,
		       sizeof(*standard_alloc));
		private_data_dest += args->priv_drv_data_size;
	} else if (args->priv_drv_data_size) {
		ret = dxg_copy_from_user(private_data_dest,
					 args->priv_drv_data,
					 args->priv_drv_data_size);
		if (ret)
			goto cleanup;
		private_data_dest += args->priv_drv_data_size;
	}

	alloc_info = (void *)&command[1];
	input_alloc = input_alloc_info;
	if (input_alloc_info[0].sysmem)
		command->flags.existing_sysmem = 1;
	for (i = 0; i < args->alloc_count; i++) {
		alloc_info->flags = input_alloc->flags.value;
		alloc_info->vidpn_source_id = input_alloc->vidpn_source_id;
		alloc_info->priv_drv_data_size =
		    input_alloc->priv_drv_data_size;
		if (input_alloc->priv_drv_data_size) {
			ret = dxg_copy_from_user(private_data_dest,
						 input_alloc->priv_drv_data,
						 input_alloc->
						 priv_drv_data_size);
			if (ret)
				goto cleanup;
			private_data_dest += input_alloc->priv_drv_data_size;
		}
		alloc_info++;
		input_alloc++;
	}

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int create_existing_sysmem(struct dxgdevice *device,
			   struct dxgkvmb_command_allocinfo_return *host_alloc,
			   struct dxgallocation *dxgalloc,
			   bool read_only,
			   const void *sysmem)
{
	int ret = 0;
	void *kmem = NULL;
	struct dxgkvmb_command_setexistingsysmemstore set_store_command = { };
	u64 alloc_size = host_alloc->allocation_size;
	uint npages = alloc_size >> PAGE_SHIFT;
	struct dxgvmbuschannel *channel = &device->adapter->channel;

	/*
	 * Create a guest physical address list and set it as the allocation
	 * backing store in the host. This is done after creating the host
	 * allocation, because only now the allocation size is known.
	 */

	TRACE_DEBUG(2, "alloc size: %lld", alloc_size);

	dxgalloc->cpu_address = (void *)sysmem;
	dxgalloc->pages = dxgmem_alloc(dxgalloc->process, DXGMEM_ALLOCATION,
				       npages * sizeof(void *));
	if (dxgalloc->pages == NULL) {
		pr_err("failed to allocate pages");
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	ret = get_user_pages_fast((unsigned long)sysmem, npages, !read_only,
				  dxgalloc->pages);
	if (ret != npages) {
		pr_err("get_user_pages_fast failed: %d", ret);
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	kmem = vmap(dxgalloc->pages, npages, VM_MAP, PAGE_KERNEL);
	if (kmem == NULL) {
		pr_err("vmap failed");
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	ret = vmbus_establish_gpadl(dxgglobal_get_vmbus(), kmem,
				    alloc_size, &dxgalloc->gpadl);
	if (ret) {
		pr_err("establish_gpadl failed: %d", ret);
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	TRACE_DEBUG(1, "New gpadl %d", dxgalloc->gpadl);

	command_vgpu_to_host_init2(&set_store_command.hdr,
				   DXGK_VMBCOMMAND_SETEXISTINGSYSMEMSTORE,
				   device->process->host_handle);
	set_store_command.device = device->handle;
	set_store_command.allocation = host_alloc->allocation;
	set_store_command.gpadl = dxgalloc->gpadl;
	ret = dxgvmb_send_sync_msg_ntstatus(channel, &set_store_command,
					    sizeof(set_store_command));
	if (!NT_SUCCESS(ret)) {
		pr_err("failed to set existing store: %x", ret);
		goto cleanup;
	}

cleanup:
	if (kmem)
		vunmap(kmem);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

static int process_allocation_handles(struct dxgprocess *process,
				      struct dxgdevice *device,
				      struct d3dkmt_createallocation *args,
				      struct
				      dxgkvmb_command_createallocation_return
				      *result, struct dxgallocation **dxgalloc,
				      struct dxgresource *resource)
{
	int ret = 0, i;

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	if (args->flags.create_resource) {
		ret = hmgrtable_assign_handle(&process->handle_table, resource,
					      HMGRENTRY_TYPE_DXGRESOURCE,
					      result->resource);
		if (ret) {
			pr_err("failed to assign resource handle %x",
				   result->resource);
		} else {
			resource->handle = result->resource;
			resource->handle_valid = 1;
		}
	}
	for (i = 0; i < args->alloc_count; i++) {
		struct dxgkvmb_command_allocinfo_return *host_alloc;

		host_alloc = &result->allocation_info[i];
		ret = hmgrtable_assign_handle(&process->handle_table,
					      dxgalloc[i],
					      HMGRENTRY_TYPE_DXGALLOCATION,
					      host_alloc->allocation);
		if (ret) {
			pr_err("failed to assign alloc handle %x %d %d",
				   host_alloc->allocation,
				   args->alloc_count, i);
			break;
		}
		dxgalloc[i]->alloc_handle = host_alloc->allocation;
		dxgalloc[i]->handle_valid = 1;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (ret)
		goto cleanup;

	if (args->flags.create_shared && !args->flags.nt_security_sharing) {
		struct dxgsharedresource *shared_resource =
		    resource->shared_owner;
		shared_resource->host_shared_handle = result->global_share;
		shared_resource->global_handle =
		    hmgrtable_alloc_handle_safe(&dxgglobal->handle_table,
						shared_resource,
						HMGRENTRY_TYPE_DXGSHAREDRESOURCE,
						true);
		if (shared_resource->global_handle == 0) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		args->global_share = shared_resource->global_handle;
		TRACE_DEBUG(1, "Shared resource global handles: %x %x",
			    shared_resource->global_handle,
			    shared_resource->host_shared_handle);
	}

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

static int create_local_allocations(struct dxgprocess *process,
				    struct dxgdevice *device,
				    struct d3dkmt_createallocation *args,
				    struct d3dkmt_createallocation *__user
				    input_args,
				    struct d3dddi_allocationinfo2 *alloc_info,
				    struct
				    dxgkvmb_command_createallocation_return
				    *result, struct dxgresource *resource,
				    struct dxgallocation **dxgalloc,
				    struct dxgkvmb_command_destroyallocation
				    *destroy_buffer, uint destroy_buffer_size)
{
	int i;
	int alloc_count = args->alloc_count;
	uint8_t *alloc_private_data = NULL;
	int ret = 0;
	ntstatus status = STATUS_SUCCESS;
	struct dxgvmbuschannel *channel = &device->adapter->channel;

	/* Prepare the command to destroy allocation in case of failure */
	command_vgpu_to_host_init2(&destroy_buffer->hdr,
				   DXGK_VMBCOMMAND_DESTROYALLOCATION,
				   process->host_handle);
	destroy_buffer->device = args->device;
	destroy_buffer->resource = args->resource;
	destroy_buffer->alloc_count = alloc_count;
	destroy_buffer->flags.assume_not_in_use = 1;
	for (i = 0; i < alloc_count; i++) {
		TRACE_DEBUG2(1, 1, "host allocation: %d %x",
			     i, result->allocation_info[i].allocation);
		destroy_buffer->allocations[i] =
		    result->allocation_info[i].allocation;
	}

	if (args->flags.create_resource) {
		TRACE_DEBUG(1, "created resource: %x", result->resource);
		ret = dxg_copy_to_user(&input_args->resource, &result->resource,
				       sizeof(d3dkmt_handle));
		if (ret)
			goto cleanup;
	}

	alloc_private_data = (uint8_t *) result +
	    sizeof(struct dxgkvmb_command_createallocation_return) +
	    sizeof(struct dxgkvmb_command_allocinfo_return) * (alloc_count - 1);

	for (i = 0; i < alloc_count; i++) {
		struct dxgkvmb_command_allocinfo_return *host_alloc;
		struct d3dddi_allocationinfo2 *user_alloc;

		host_alloc = &result->allocation_info[i];
		user_alloc = &alloc_info[i];
		if (alloc_info->sysmem) {
			ret = create_existing_sysmem(device, host_alloc,
						     dxgalloc[i],
						     args->flags.read_only != 0,
						     alloc_info->sysmem);
			if (ret)
				goto cleanup;
		}
		dxgalloc[i]->num_pages =
		    host_alloc->allocation_size >> PAGE_SHIFT;
		dxgalloc[i]->cached = host_alloc->allocation_flags.cached;
		if (host_alloc->priv_drv_data_size) {
			ret = dxg_copy_to_user(user_alloc->priv_drv_data,
					       alloc_private_data,
					       host_alloc->priv_drv_data_size);
			if (ret)
				goto cleanup;
			alloc_private_data += host_alloc->priv_drv_data_size;
		}
		ret = dxg_copy_to_user(&args->allocation_info[i].allocation,
				       &host_alloc->allocation,
				       sizeof(d3dkmt_handle));
		if (ret)
			goto cleanup;
	}

	ret = process_allocation_handles(process, device, args, result,
					 dxgalloc, resource);
	if (ret)
		goto cleanup;

	ret = dxg_copy_to_user(&input_args->global_share, &args->global_share,
			       sizeof(d3dkmt_handle));

cleanup:

	if (ret) {
		/* Free local handles before freeing the handles in the host */
		dxgdevice_acquire_alloc_list_lock(device);
		if (dxgalloc)
			for (i = 0; i < alloc_count; i++)
				if (dxgalloc[i])
					dxgallocation_free_handle(dxgalloc[i]);
		if (resource && args->flags.create_resource)
			dxgresource_free_handle(resource);
		dxgdevice_release_alloc_list_lock(device);

		/* Destroy allocations in the host to unmap gpadls */
		status = dxgvmb_send_sync_msg_ntstatus(channel, destroy_buffer,
						       destroy_buffer_size);
		if (!NT_SUCCESS(status))
			pr_err("failed to destroy allocations: %x", status);

		dxgdevice_acquire_alloc_list_lock(device);
		if (dxgalloc) {
			for (i = 0; i < alloc_count; i++) {
				if (dxgalloc[i]) {
					dxgalloc[i]->alloc_handle = 0;
					dxgallocation_destroy(dxgalloc[i]);
					dxgalloc[i] = NULL;
				}
			}
		}
		if (resource && args->flags.create_resource) {
			/*
			 * Prevent the resource memory from freeing.
			 * It will be freed in the top level function.
			 */
			dxgresource_acquire_reference(resource);
			dxgresource_destroy(resource);
		}
		dxgdevice_release_alloc_list_lock(device);
	}

	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_create_allocation(struct dxgprocess *process,
				  struct dxgdevice *device,
				  struct d3dkmt_createallocation *args,
				  struct d3dkmt_createallocation *__user
				  input_args, struct dxgresource *resource,
				  struct dxgallocation **dxgalloc,
				  struct d3dddi_allocationinfo2 *alloc_info,
				  struct d3dkmt_createstandardallocation
				  *standard_alloc)
{
	struct dxgkvmb_command_createallocation *command = NULL;
	struct dxgkvmb_command_destroyallocation *destroy_buffer = NULL;
	struct dxgkvmb_command_createallocation_return *result = NULL;
	int ret;
	int i;
	uint result_size = 0;
	uint cmd_size = 0;
	uint destroy_buffer_size = 0;
	uint priv_drv_data_size;
	struct dxgvmbuschannel *channel = &device->adapter->channel;

	if (args->private_runtime_data_size >= DXG_MAX_VM_BUS_PACKET_SIZE ||
	    args->priv_drv_data_size >= DXG_MAX_VM_BUS_PACKET_SIZE) {
		ret = STATUS_BUFFER_OVERFLOW;
		goto cleanup;
	}

	/*
	 * Preallocate the buffer, which will be used for destruction in case
	 * of a failure
	 */
	destroy_buffer_size = sizeof(struct dxgkvmb_command_destroyallocation) +
	    args->alloc_count * sizeof(d3dkmt_handle);
	destroy_buffer = dxgmem_alloc(process, DXGMEM_TMP, destroy_buffer_size);
	if (destroy_buffer == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	/* Compute the total private driver size */

	priv_drv_data_size = 0;

	for (i = 0; i < args->alloc_count; i++) {
		if (alloc_info[i].priv_drv_data_size >=
		    DXG_MAX_VM_BUS_PACKET_SIZE) {
			ret = STATUS_BUFFER_OVERFLOW;
			goto cleanup;
		} else {
			priv_drv_data_size += alloc_info[i].priv_drv_data_size;
		}
		if (priv_drv_data_size >= DXG_MAX_VM_BUS_PACKET_SIZE) {
			ret = STATUS_BUFFER_OVERFLOW;
			goto cleanup;
		}
	}

	/*
	 * Private driver data for the result includes only per allocation
	 * private data
	 */
	result_size = sizeof(struct dxgkvmb_command_createallocation_return) +
	    (args->alloc_count - 1) *
	    sizeof(struct dxgkvmb_command_allocinfo_return) +
	    priv_drv_data_size;
	result = dxgmem_alloc(process, DXGMEM_VMBUS, result_size);
	if (result == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	/* Private drv data for the command includes the global private data */
	priv_drv_data_size += args->priv_drv_data_size;

	cmd_size = sizeof(struct dxgkvmb_command_createallocation) +
	    args->alloc_count *
	    sizeof(struct dxgkvmb_command_createallocation_allocinfo) +
	    args->private_runtime_data_size + priv_drv_data_size;
	if (cmd_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		ret = STATUS_BUFFER_OVERFLOW;
		goto cleanup;
	}

	TRACE_DEBUG(1, "command size, driver_data_size %d %d %ld %ld",
		    cmd_size, priv_drv_data_size,
		    sizeof(struct dxgkvmb_command_createallocation),
		    sizeof(struct dxgkvmb_command_createallocation_allocinfo));

	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_CREATEALLOCATION,
				   process->host_handle);
	command->device = args->device;
	command->flags = args->flags;
	command->resource = args->resource;
	command->private_runtime_resource_handle =
	    args->private_runtime_resource_handle;
	command->alloc_count = args->alloc_count;
	command->private_runtime_data_size = args->private_runtime_data_size;
	command->priv_drv_data_size = args->priv_drv_data_size;
	if (args->flags.standard_allocation) {
		/*
		 * Flags.ExistingSysMem cannot be set from user mode, so it
		 * needs to be set it here.
		 */
		command->flags.existing_sysmem = 1;
	}

	ret = copy_private_data(args, command, alloc_info, standard_alloc);
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   result, result_size);
	if (ret) {
		pr_err("send_create_allocation failed %x", ret);
		goto cleanup;
	}

	ret = create_local_allocations(process, device, args, input_args,
				       alloc_info, result, resource, dxgalloc,
				       destroy_buffer, destroy_buffer_size);
	if (ret)
		goto cleanup;

cleanup:

	if (destroy_buffer)
		dxgmem_free(process, DXGMEM_TMP, destroy_buffer);
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	if (result)
		dxgmem_free(process, DXGMEM_VMBUS, result);

	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_destroy_allocation(struct dxgprocess *process,
				   struct dxgdevice *device,
				   struct dxgvmbuschannel *channel,
				   struct d3dkmt_destroyallocation2 *args,
				   d3dkmt_handle *alloc_handles)
{
	struct dxgkvmb_command_destroyallocation *destroy_buffer = NULL;
	uint destroy_buffer_size = 0;
	int ret = 0;
	int allocations_size = args->alloc_count * sizeof(d3dkmt_handle);

	destroy_buffer_size = sizeof(struct dxgkvmb_command_destroyallocation) +
	    allocations_size;
	destroy_buffer = dxgmem_alloc(process, DXGMEM_TMP, destroy_buffer_size);
	if (destroy_buffer == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	command_vgpu_to_host_init2(&destroy_buffer->hdr,
				   DXGK_VMBCOMMAND_DESTROYALLOCATION,
				   process->host_handle);
	destroy_buffer->device = args->device;
	destroy_buffer->resource = args->resource;
	destroy_buffer->alloc_count = args->alloc_count;
	destroy_buffer->flags = args->flags;
	if (allocations_size)
		memcpy(destroy_buffer->allocations, alloc_handles,
		       allocations_size);

	ret = dxgvmb_send_sync_msg_ntstatus(channel, destroy_buffer,
					    destroy_buffer_size);

cleanup:

	if (destroy_buffer)
		dxgmem_free(process, DXGMEM_TMP, destroy_buffer);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_make_resident(struct dxgprocess *process,
			      struct dxgdevice *device,
			      struct dxgvmbuschannel *channel,
			      struct d3dddi_makeresident *args)
{
	int ret = 0;
	uint cmd_size;
	struct dxgkvmb_command_makeresident_return result = { };
	struct dxgkvmb_command_makeresident *command = NULL;

	cmd_size = (args->alloc_count - 1) * sizeof(d3dkmt_handle) +
	    sizeof(struct dxgkvmb_command_makeresident);
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	ret = dxg_copy_from_user(command->allocations, args->allocation_list,
				 args->alloc_count * sizeof(d3dkmt_handle));
	if (ret)
		goto cleanup;
	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_MAKERESIDENT,
				   process->host_handle);
	command->alloc_count = args->alloc_count;
	command->paging_queue = args->paging_queue;
	if (device)
		command->device = device->handle;
	command->flags = args->flags;

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   &result, sizeof(result));
	if (ret) {
		pr_err("send_make_resident failed %x", ret);
		goto cleanup;
	}

	args->paging_fence_value = result.paging_fence_value;
	args->num_bytes_to_trim = result.num_bytes_to_trim;
	ret = result.status;

cleanup:

	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_evict(struct dxgprocess *process,
		      struct dxgvmbuschannel *channel,
		      struct d3dkmt_evict *args)
{
	int ret = 0;
	uint cmd_size;
	struct dxgkvmb_command_evict_return result = { };
	struct dxgkvmb_command_evict *command = NULL;

	cmd_size = (args->alloc_count - 1) * sizeof(d3dkmt_handle) +
	    sizeof(struct dxgkvmb_command_evict);
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	ret = dxg_copy_from_user(command->allocations, args->allocations,
				 args->alloc_count * sizeof(d3dkmt_handle));
	if (ret)
		goto cleanup;
	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_EVICT, process->host_handle);
	command->alloc_count = args->alloc_count;
	command->device = args->device;
	command->flags = args->flags;

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   &result, sizeof(result));
	if (ret) {
		pr_err("send_evict failed %x", ret);
		goto cleanup;
	}
	args->num_bytes_to_trim = result.num_bytes_to_trim;

cleanup:

	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_submit_command(struct dxgprocess *process,
			       struct dxgvmbuschannel *channel,
			       struct d3dkmt_submitcommand *args)
{
	int ret = 0;
	uint cmd_size;
	struct dxgkvmb_command_submitcommand *command = NULL;
	uint hbufsize = args->num_history_buffers * sizeof(d3dkmt_handle);

	cmd_size = sizeof(struct dxgkvmb_command_submitcommand) +
	    hbufsize + args->priv_drv_data_size;
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	ret = dxg_copy_from_user(&command[1], args->history_buffer_array,
				 hbufsize);
	if (ret)
		goto cleanup;
	ret = dxg_copy_from_user((uint8_t *) &command[1] + hbufsize,
				 args->priv_drv_data, args->priv_drv_data_size);
	if (ret)
		goto cleanup;

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_SUBMITCOMMAND,
				   process->host_handle);
	command->args = *args;

	ret = dxgvmb_send_sync_msg_ntstatus(channel, command, cmd_size);

cleanup:

	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_map_gpu_va(struct dxgprocess *process,
			   d3dkmt_handle device,
			   struct dxgvmbuschannel *channel,
			   struct d3dddi_mapgpuvirtualaddress *args)
{
	struct dxgkvmb_command_mapgpuvirtualaddress command;
	struct dxgkvmb_command_mapgpuvirtualaddress_return result;
	int ret = 0;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_MAPGPUVIRTUALADDRESS,
				   process->host_handle);
	command.args = *args;
	command.device = device;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command), &result,
				   sizeof(result));
	if (ret) {
		pr_err("%s failed %x", __func__, ret);
		goto cleanup;
	}
	args->virtual_address = result.virtual_address;
	args->paging_fence_value = result.paging_fence_value;
	ret = result.status;

cleanup:

	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_reserve_gpu_va(struct dxgprocess *process,
			       struct dxgvmbuschannel *channel,
			       struct d3dddi_reservegpuvirtualaddress *args)
{
	struct dxgkvmb_command_reservegpuvirtualaddress command;
	struct dxgkvmb_command_reservegpuvirtualaddress_return result;
	int ret = 0;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_RESERVEGPUVIRTUALADDRESS,
				   process->host_handle);
	command.args = *args;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command), &result,
				   sizeof(result));
	args->virtual_address = result.virtual_address;

	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_free_gpu_va(struct dxgprocess *process,
			    struct dxgvmbuschannel *channel,
			    struct d3dkmt_freegpuvirtualaddress *args)
{
	struct dxgkvmb_command_freegpuvirtualaddress command;
	ntstatus status;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_FREEGPUVIRTUALADDRESS,
				   process->host_handle);
	command.args = *args;

	status = dxgvmb_send_sync_msg_ntstatus(channel, &command,
					       sizeof(command));
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_update_gpu_va(struct dxgprocess *process,
			      struct dxgvmbuschannel *channel,
			      struct d3dkmt_updategpuvirtualaddress *args)
{
	struct dxgkvmb_command_updategpuvirtualaddress *command = NULL;
	uint cmd_size;
	uint op_size;
	int ret = 0;

	if (args->num_operations == 0 ||
	    (DXG_MAX_VM_BUS_PACKET_SIZE /
	     sizeof(struct d3dddi_updategpuvirtualaddress_operation)) <
	    args->num_operations) {
		ret = STATUS_INVALID_PARAMETER;
		pr_err("Invalid number of operations: %d",
			   args->num_operations);
		goto cleanup;
	}

	op_size = args->num_operations *
	    sizeof(struct d3dddi_updategpuvirtualaddress_operation);
	cmd_size = sizeof(struct dxgkvmb_command_updategpuvirtualaddress) +
	    op_size - sizeof(args->operations[0]);
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		pr_err("Failed to allocate command");
		goto cleanup;
	}

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_UPDATEGPUVIRTUALADDRESS,
				   process->host_handle);
	command->fence_value = args->fence_value;
	command->device = args->device;
	command->context = args->context;
	command->fence_object = args->fence_object;
	command->num_operations = args->num_operations;
	command->flags = args->flags.value;
	ret = dxg_copy_from_user(command->operations, args->operations,
				 op_size);
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg_ntstatus(channel, command, cmd_size);

cleanup:

	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

static void set_result(struct d3dkmt_createsynchronizationobject2 *args,
		       d3dgpu_virtual_address fence_gpu_va, uint8_t *va)
{
	args->info.periodic_monitored_fence.fence_gpu_virtual_address =
	    fence_gpu_va;
	args->info.periodic_monitored_fence.fence_cpu_virtual_address = va;
}

int dxgvmb_send_create_sync_object(struct dxgprocess *process,
				   struct dxgvmbuschannel *channel,
				   struct d3dkmt_createsynchronizationobject2
				   *args, struct dxgsyncobject *syncobj)
{
	struct dxgkvmb_command_createsyncobject_return result = { };
	struct dxgkvmb_command_createsyncobject command = { };
	int ret = 0;
	uint8_t *va = 0;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_CREATESYNCOBJECT,
				   process->host_handle);
	command.args = *args;
	command.client_hint = 1;	/* CLIENTHINT_UMD */

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command), &result,
				   sizeof(result));
	if (ret) {
		pr_err("%s failed %d", __func__, ret);
		goto cleanup;
	}
	args->sync_object = result.sync_object;
	if (syncobj->shared) {
		if (result.global_sync_object == 0) {
			pr_err("shared handle is 0");
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		args->info.shared_handle = result.global_sync_object;
	}

	if (syncobj->monitored_fence) {
		va = dxg_map_iospace(result.fence_storage_address, PAGE_SIZE,
				     PROT_READ | PROT_WRITE, true);
		if (va == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		if (args->info.type == D3DDDI_MONITORED_FENCE) {
			args->info.monitored_fence.fence_gpu_virtual_address =
			    result.fence_gpu_va;
			args->info.monitored_fence.fence_cpu_virtual_address =
			    va;
			{
				unsigned long value;

				TRACE_DEBUG(1, "fence cpu address: %p", va);
				ret = dxg_copy_from_user(&value, va,
							 sizeof(uint64_t));
				if (ret)
					pr_err("failed to read fence");
				else
					TRACE_DEBUG(1, "fence value: %lx",
						    value);
			}
		} else {
			set_result(args, result.fence_gpu_va, va);
		}
		syncobj->mapped_address = va;
	}

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_destroy_sync_object(struct dxgprocess *process,
				    d3dkmt_handle sync_object)
{
	struct dxgkvmb_command_destroysyncobject command = { };
	ntstatus status;

	status = dxgglobal_acquire_channel_lock();
	if (status)
		goto cleanup;

	command_vm_to_host_init2(&command.hdr,
				 DXGK_VMBCOMMAND_DESTROYSYNCOBJECT,
				 process->host_handle);
	command.sync_object = sync_object;

	status = dxgvmb_send_sync_msg_ntstatus(dxgglobal_get_dxgvmbuschannel(),
					       &command, sizeof(command));

	dxgglobal_release_channel_lock();

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_signal_sync_object(struct dxgprocess *process,
				   struct dxgvmbuschannel *channel,
				   struct d3dddicb_signalflags flags,
				   uint64_t legacy_fence_value,
				   d3dkmt_handle context,
				   uint object_count,
				   d3dkmt_handle __user *objects,
				   uint context_count,
				   d3dkmt_handle __user *contexts,
				   uint fence_count,
				   uint64_t __user *fences,
				   struct eventfd_ctx *cpu_event_handle,
				   d3dkmt_handle device)
{
	int ret = 0;
	struct dxgkvmb_command_signalsyncobject *command = NULL;
	uint object_size = object_count * sizeof(d3dkmt_handle);
	uint context_size = context_count * sizeof(d3dkmt_handle);
	uint fence_size = fences ? fence_count * sizeof(uint64_t) : 0;
	uint8_t *current_pos;
	uint cmd_size = sizeof(struct dxgkvmb_command_signalsyncobject) +
	    object_size + context_size + fence_size;

	if (context)
		cmd_size += sizeof(d3dkmt_handle);

	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_SIGNALSYNCOBJECT,
				   process->host_handle);

	if (flags.enqueue_cpu_event)
		command->cpu_event_handle = (winhandle) cpu_event_handle;
	else
		command->device = device;
	command->flags = flags;
	command->fence_value = legacy_fence_value;
	command->object_count = object_count;
	command->context_count = context_count;
	current_pos = (uint8_t *) &command[1];
	ret = dxg_copy_from_user(current_pos, objects, object_size);
	if (ret) {
		pr_err("Failed to read objects %p %d",
			   objects, object_size);
		goto cleanup;
	}
	current_pos += object_size;
	if (context) {
		command->context_count++;
		*(d3dkmt_handle *) current_pos = context;
		current_pos += sizeof(d3dkmt_handle);
	}
	if (context_size) {
		ret = dxg_copy_from_user(current_pos, contexts, context_size);
		if (ret) {
			pr_err("Failed to read contexts %p %d",
				   contexts, context_size);
			goto cleanup;
		}
		current_pos += context_size;
	}
	if (fence_size) {
		ret = dxg_copy_from_user(current_pos, fences, fence_size);
		if (ret) {
			pr_err("Failed to read fences %p %d",
				   fences, fence_size);
			goto cleanup;
		}
	}

	ret = dxgvmb_send_sync_msg_ntstatus(channel, command, cmd_size);

cleanup:
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_wait_sync_object_cpu(struct dxgprocess *process,
				     struct dxgvmbuschannel *channel,
				     struct
				     d3dkmt_waitforsynchronizationobjectfromcpu
				     *args, u64 cpu_event)
{
	int ret = 0;
	struct dxgkvmb_command_waitforsyncobjectfromcpu *command = NULL;
	uint object_size = args->object_count * sizeof(d3dkmt_handle);
	uint fence_size = args->object_count * sizeof(uint64_t);
	uint8_t *current_pos;
	uint cmd_size = sizeof(*command) + object_size + fence_size;

	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_WAITFORSYNCOBJECTFROMCPU,
				   process->host_handle);
	command->device = args->device;
	command->flags = args->flags;
	command->object_count = args->object_count;
	command->guest_event_pointer = (uint64_t) cpu_event;
	current_pos = (uint8_t *) &command[1];
	ret = dxg_copy_from_user(current_pos, args->objects, object_size);
	if (ret)
		goto cleanup;
	current_pos += object_size;
	ret = dxg_copy_from_user(current_pos, args->fence_values, fence_size);
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg_ntstatus(channel, command, cmd_size);

cleanup:
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_wait_sync_object_gpu(struct dxgprocess *process,
				     struct dxgvmbuschannel *channel,
				     d3dkmt_handle context, uint object_count,
				     d3dkmt_handle *objects, uint64_t *fences,
				     bool legacy_fence)
{
	ntstatus status;
	struct dxgkvmb_command_waitforsyncobjectfromgpu *command = NULL;
	uint fence_size = object_count * sizeof(uint64_t);
	uint object_size = object_count * sizeof(d3dkmt_handle);
	uint8_t *current_pos;
	uint cmd_size = object_size + fence_size - sizeof(uint64_t) +
	    sizeof(struct dxgkvmb_command_waitforsyncobjectfromgpu);

	if (object_count == 0 || object_count > D3DDDI_MAX_OBJECT_WAITED_ON) {
		status = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		status = STATUS_NO_MEMORY;
		goto cleanup;
	}
	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_WAITFORSYNCOBJECTFROMGPU,
				   process->host_handle);
	command->context = context;
	command->object_count = object_count;
	command->legacy_fence_object = legacy_fence;
	current_pos = (uint8_t *) command->fence_values;
	memcpy(current_pos, fences, fence_size);
	current_pos += fence_size;
	memcpy(current_pos, objects, object_size);

	status = dxgvmb_send_sync_msg_ntstatus(channel, command, cmd_size);

cleanup:
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_lock2(struct dxgprocess *process,
		      struct dxgvmbuschannel *channel,
		      struct d3dkmt_lock2 *args,
		      struct d3dkmt_lock2 *__user outargs)
{
	int ret = 0;
	struct dxgkvmb_command_lock2 command = { };
	struct dxgkvmb_command_lock2_return result = { };
	struct dxgallocation *alloc = NULL;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_LOCK2, process->host_handle);
	command.args = *args;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command),
				   &result, sizeof(result));
	if (ret)
		goto cleanup;
	if (!NT_SUCCESS(result.status)) {
		ret = result.status;
		goto cleanup;
	}

	hmgrtable_lock(&process->handle_table, DXGLOCK_SHARED);
	alloc = hmgrtable_get_object_by_type(&process->handle_table,
					     HMGRENTRY_TYPE_DXGALLOCATION,
					     args->allocation);
	if (alloc == NULL || alloc->cpu_address || alloc->cpu_address_refcount
	    || alloc->cpu_address_mapped) {
		pr_err("%s invalid alloc", __func__);
		ret = STATUS_INVALID_PARAMETER;
	} else {
		args->data = dxg_map_iospace((uint64_t) result.
					     cpu_visible_buffer_offset,
					     alloc->num_pages << PAGE_SHIFT,
					     PROT_READ | PROT_WRITE,
					     alloc->cached);
		if (args->data == NULL) {
			ret = STATUS_NO_MEMORY;
		} else {
			ret = dxg_copy_to_user(&outargs->data, &args->data,
					       sizeof(args->data));
			if (!ret) {
				alloc->cpu_address = args->data;
				alloc->cpu_address_mapped = true;
				alloc->cpu_address_refcount = 1;
			} else {
				dxg_unmap_iospace(alloc->cpu_address,
						  alloc->
						  num_pages << PAGE_SHIFT);
			}
		}
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_SHARED);

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_unlock2(struct dxgprocess *process,
			struct dxgvmbuschannel *channel,
			struct d3dkmt_unlock2 *args)
{
	ntstatus status;
	struct dxgkvmb_command_unlock2 command = { };

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_UNLOCK2,
				   process->host_handle);
	command.args = *args;

	status = dxgvmb_send_sync_msg_ntstatus(channel, &command,
					       sizeof(command));
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_update_alloc_property(struct dxgprocess *process,
				      struct dxgvmbuschannel *channel,
				      struct d3dddi_updateallocproperty *args,
				      struct d3dddi_updateallocproperty *__user
				      inargs)
{
	int ret;
	ntstatus status;
	struct dxgkvmb_command_updateallocationproperty command = { };
	struct dxgkvmb_command_updateallocationproperty_return result = { };

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_UPDATEALLOCATIONPROPERTY,
				   process->host_handle);
	command.args = *args;

	status = dxgvmb_send_sync_msg(channel, &command, sizeof(command),
				      &result, sizeof(result));
	if (status == STATUS_PENDING) {
		ret = dxg_copy_to_user(&inargs->paging_fence_value,
				       &result.paging_fence_value,
				       sizeof(uint64_t));
		if (ret)
			status = ret;
	}
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_mark_device_as_error(struct dxgprocess *process,
				     struct dxgvmbuschannel *channel,
				     struct d3dkmt_markdeviceaserror *args)
{
	struct dxgkvmb_command_markdeviceaserror command = { };
	ntstatus status;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_MARKDEVICEASERROR,
				   process->host_handle);
	command.args = *args;
	status = dxgvmb_send_sync_msg_ntstatus(channel, &command,
					       sizeof(command));
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_set_allocation_priority(struct dxgprocess *process,
					struct dxgvmbuschannel *channel,
					struct d3dkmt_setallocationpriority
					*args)
{
	uint cmd_size = sizeof(struct dxgkvmb_command_setallocationpriority);
	uint alloc_size = 0;
	uint priority_size = 0;
	struct dxgkvmb_command_setallocationpriority *command = NULL;
	int ret = 0;
	d3dkmt_handle *allocations;

	if (args->allocation_count > DXG_MAX_VM_BUS_PACKET_SIZE) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	if (args->resource) {
		priority_size = sizeof(uint);
		if (args->allocation_count != 0) {
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
	} else {
		if (args->allocation_count == 0) {
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		alloc_size = args->allocation_count * sizeof(d3dkmt_handle);
		cmd_size += alloc_size;
		priority_size = sizeof(uint) * args->allocation_count;
	}
	cmd_size += priority_size;
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_SETALLOCATIONPRIORITY,
				   process->host_handle);
	command->device = args->device;
	command->allocation_count = args->allocation_count;
	command->resource = args->resource;
	allocations = (d3dkmt_handle *) &command[1];
	ret = dxg_copy_from_user(allocations, args->allocation_list,
				 alloc_size);
	if (ret)
		goto cleanup;
	ret = dxg_copy_from_user((uint8_t *) allocations + alloc_size,
				 args->priorities, priority_size);
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg_ntstatus(channel, command, cmd_size);

cleanup:
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_get_allocation_priority(struct dxgprocess *process,
					struct dxgvmbuschannel *channel,
					struct d3dkmt_getallocationpriority
					*args)
{
	uint cmd_size = sizeof(struct dxgkvmb_command_getallocationpriority);
	uint result_size;
	uint alloc_size = 0;
	uint priority_size = 0;
	struct dxgkvmb_command_getallocationpriority *command = NULL;
	struct dxgkvmb_command_getallocationpriority_return *result;
	int ret = 0;
	d3dkmt_handle *allocations;

	if (args->allocation_count > DXG_MAX_VM_BUS_PACKET_SIZE) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	if (args->resource) {
		priority_size = sizeof(uint);
		if (args->allocation_count != 0) {
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
	} else {
		if (args->allocation_count == 0) {
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup;
		}
		alloc_size = args->allocation_count * sizeof(d3dkmt_handle);
		cmd_size += alloc_size;
		priority_size = sizeof(uint) * args->allocation_count;
	}
	result_size =
	    sizeof(struct dxgkvmb_command_getallocationpriority_return) +
	    priority_size;
	cmd_size += result_size;
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_GETALLOCATIONPRIORITY,
				   process->host_handle);
	command->device = args->device;
	command->allocation_count = args->allocation_count;
	command->resource = args->resource;
	allocations = (d3dkmt_handle *) &command[1];
	ret = dxg_copy_from_user(allocations, args->allocation_list,
				 alloc_size);
	if (ret)
		goto cleanup;

	result = (void *)((uint8_t *) &command[1] + alloc_size);

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   result, result_size);
	if (ret)
		goto cleanup;
	if (!NT_SUCCESS(result->status)) {
		ret = result->status;
		goto cleanup;
	}

	ret = dxg_copy_to_user(args->priorities, (uint8_t *) result +
			       sizeof(struct
				      dxgkvmb_command_getallocationpriority_return),
			       priority_size);

cleanup:
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_set_context_scheduling_priority(struct dxgprocess *process,
						struct dxgvmbuschannel *channel,
						d3dkmt_handle context,
						int priority, bool in_process)
{
	struct dxgkvmb_command_setcontextschedulingpriority2 command = { };
	ntstatus status;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_SETCONTEXTSCHEDULINGPRIORITY,
				   process->host_handle);
	command.context = context;
	command.priority = priority;
	command.in_process = in_process;
	status = dxgvmb_send_sync_msg_ntstatus(channel, &command,
					       sizeof(command));
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_get_context_scheduling_priority(struct dxgprocess *process,
						struct dxgvmbuschannel *channel,
						d3dkmt_handle context,
						int *priority, bool in_process)
{
	struct dxgkvmb_command_getcontextschedulingpriority command = { };
	struct dxgkvmb_command_getcontextschedulingpriority_return result = { };
	int ret;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_GETCONTEXTSCHEDULINGPRIORITY,
				   process->host_handle);
	command.context = context;
	command.in_process = in_process;
	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command),
				   &result, sizeof(result));
	if (!ret) {
		ret = result.status;
		*priority = result.priority;
	}
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_offer_allocations(struct dxgprocess *process,
				  struct dxgvmbuschannel *channel,
				  struct d3dkmt_offerallocations *args)
{
	struct dxgkvmb_command_offerallocations *command;
	int ret = 0;
	uint alloc_size = sizeof(d3dkmt_handle) * args->allocation_count;
	uint cmd_size = sizeof(struct dxgkvmb_command_offerallocations) +
	    alloc_size - sizeof(d3dkmt_handle);

	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_OFFERALLOCATIONS,
				   process->host_handle);
	command->flags = args->flags;
	command->priority = args->priority;
	command->device = args->device;
	command->allocation_count = args->allocation_count;
	if (args->resources) {
		command->resources = true;
		ret = dxg_copy_from_user(command->allocations, args->resources,
					 alloc_size);
	} else {
		ret = dxg_copy_from_user(command->allocations,
					 args->allocations, alloc_size);
	}
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg_ntstatus(channel, command, cmd_size);

cleanup:
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_reclaim_allocations(struct dxgprocess *process,
				    struct dxgvmbuschannel *channel,
				    d3dkmt_handle device,
				    struct d3dkmt_reclaimallocations2 *args,
				    uint64_t * __user paging_fence_value)
{
	struct dxgkvmb_command_reclaimallocations *command = NULL;
	struct dxgkvmb_command_reclaimallocations_return *result = NULL;
	int ret = 0;
	uint alloc_size = sizeof(d3dkmt_handle) * args->allocation_count;
	uint cmd_size = sizeof(struct dxgkvmb_command_reclaimallocations) +
	    alloc_size - sizeof(d3dkmt_handle);
	uint result_size = sizeof(*result);

	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_RECLAIMALLOCATIONS,
				   process->host_handle);
	command->device = device;
	command->paging_queue = args->paging_queue;
	command->allocation_count = args->allocation_count;
	command->write_results = args->results != NULL;
	if (args->resources) {
		command->resources = true;
		ret = dxg_copy_from_user(command->allocations, args->resources,
					 alloc_size);
	} else {
		ret = dxg_copy_from_user(command->allocations,
					 args->allocations, alloc_size);
	}
	if (ret)
		goto cleanup;

	if (command->write_results)
		result_size += (args->allocation_count - 1) *
		    sizeof(enum d3dddi_reclaim_result);
	result = dxgmem_alloc(process, DXGMEM_VMBUS, result_size);
	if (result == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   result, result_size);
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(paging_fence_value,
			       &result->paging_fence_value, sizeof(uint64_t));
	if (ret)
		goto cleanup;

	ret = result->status;
	if (NT_SUCCESS(result->status) && args->results)
		ret = dxg_copy_to_user(args->results, result->discarded,
				       sizeof(result->discarded[0]) *
				       args->allocation_count);

cleanup:
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	if (result)
		dxgmem_free(process, DXGMEM_VMBUS, result);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_change_vidmem_reservation(struct dxgprocess *process,
					  struct dxgvmbuschannel *channel,
					  d3dkmt_handle other_process,
					  struct
					  d3dkmt_changevideomemoryreservation
					  *args)
{
	struct dxgkvmb_command_changevideomemoryreservation command = { };
	ntstatus status;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_CHANGEVIDEOMEMORYRESERVATION,
				   process->host_handle);
	command.args = *args;
	command.args.process = other_process;

	status = dxgvmb_send_sync_msg_ntstatus(channel, &command,
					       sizeof(command));
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_create_hwqueue(struct dxgprocess *process,
			       struct dxgvmbuschannel *channel,
			       struct d3dkmt_createhwqueue *args,
			       struct d3dkmt_createhwqueue *__user inargs,
			       struct dxghwqueue *hwqueue)
{
	struct dxgkvmb_command_createhwqueue command_on_stack = { };
	struct dxgkvmb_command_createhwqueue *command = &command_on_stack;
	uint cmd_size = sizeof(struct dxgkvmb_command_createhwqueue);
	int ret = 0;
	bool command_allocated = false;

	if (args->priv_drv_data_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		pr_err("invalid private driver data size");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args->priv_drv_data_size)
		cmd_size += args->priv_drv_data_size - 1;

	/* Input command is returned back as output */
	cmd_size = DXGK_DECL_VMBUS_ALIGN_FOR_OUTPUT(cmd_size);

	if (args->priv_drv_data_size) {
		command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
		if (command == NULL) {
			pr_err("failed to allocate memory");
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		command_allocated = true;
	}

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_CREATEHWQUEUE,
				   process->host_handle);
	command->context = args->context;
	command->flags = args->flags;
	command->priv_drv_data_size = args->priv_drv_data_size;
	if (args->priv_drv_data_size) {
		ret = dxg_copy_from_user(command->priv_drv_data,
					 args->priv_drv_data,
					 args->priv_drv_data_size);
		if (ret)
			goto cleanup;
	}

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   command, cmd_size);
	if (ret)
		goto cleanup;

	if (!NT_SUCCESS(command->status)) {
		ret = command->status;
		goto cleanup;
	}

	ret = hmgrtable_assign_handle_safe(&process->handle_table, hwqueue,
					   HMGRENTRY_TYPE_DXGHWQUEUE,
					   command->hwqueue);
	if (ret)
		goto cleanup;

	hwqueue->handle = command->hwqueue;

	hwqueue->progress_fence_mapped_address =
	    dxg_map_iospace((unsigned long)command->
			    hwqueue_progress_fence_cpuva, PAGE_SIZE,
			    PROT_READ | PROT_WRITE, true);
	if (hwqueue->progress_fence_mapped_address == NULL)
		goto cleanup;

	hwqueue->progress_fence_sync_object = command->hwqueue_progress_fence;

	ret = dxg_copy_to_user(&inargs->queue, &command->hwqueue,
			       sizeof(d3dkmt_handle));
	ret |= dxg_copy_to_user(&inargs->queue_progress_fence,
				&command->hwqueue_progress_fence,
				sizeof(d3dkmt_handle));
	ret |=
	    dxg_copy_to_user(&inargs->queue_progress_fence_cpu_va,
			     &hwqueue->progress_fence_mapped_address,
			     sizeof(inargs->queue_progress_fence_cpu_va));
	ret |=
	    dxg_copy_to_user(&inargs->queue_progress_fence_gpu_va,
			     &command->hwqueue_progress_fence_gpuva,
			     sizeof(uint64_t));
	if (args->priv_drv_data_size)
		ret |= dxg_copy_to_user(args->priv_drv_data,
					command->priv_drv_data,
					args->priv_drv_data_size);

cleanup:
	if (ret) {
		pr_err("%s failed %x", __func__, ret);
		if (hwqueue->handle) {
			hmgrtable_free_handle_safe(&process->handle_table,
						   HMGRENTRY_TYPE_DXGHWQUEUE,
						   hwqueue->handle);
			hwqueue->handle = 0;
		}
		if (command->hwqueue)
			dxgvmb_send_destroy_hwqueue(process, channel,
						    command->hwqueue);
	}
	if (command_allocated)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	return ret;
}

int dxgvmb_send_destroy_hwqueue(struct dxgprocess *process,
				struct dxgvmbuschannel *channel,
				d3dkmt_handle handle)
{
	ntstatus status;
	struct dxgkvmb_command_destroyhwqueue command = { };

	command_vgpu_to_host_init2(&command.hdr, DXGK_VMBCOMMAND_DESTROYHWQUEUE,
				   process->host_handle);
	command.hwqueue = handle;

	status = dxgvmb_send_sync_msg_ntstatus(channel, &command,
					       sizeof(command));
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_query_adapter_info(struct dxgprocess *process,
				   struct dxgvmbuschannel *channel,
				   struct d3dkmt_queryadapterinfo *args)
{
	struct dxgkvmb_command_queryadapterinfo *command = NULL;
	uint cmd_size;
	int ret = 0;

	cmd_size = sizeof(*command) + args->private_data_size - 1;
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	ret = dxg_copy_from_user(command->private_data,
				 args->private_data, args->private_data_size);
	if (ret)
		goto cleanup;

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_QUERYADAPTERINFO,
				   process->host_handle);
	command->private_data_size = args->private_data_size;
	command->query_type = args->type;

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   command->private_data,
				   command->private_data_size);
	if (ret)
		goto cleanup;
	switch (args->type) {
	case KMTQAITYPE_ADAPTERTYPE:
	case KMTQAITYPE_ADAPTERTYPE_RENDER:
		{
			struct d3dkmt_adaptertype *adapter_type =
			    (void *)command->private_data;
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
	ret = dxg_copy_to_user(args->private_data, command->private_data,
			       args->private_data_size);

cleanup:
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_submit_command_to_hwqueue(struct dxgprocess *process,
					  struct dxgvmbuschannel *channel,
					  struct d3dkmt_submitcommandtohwqueue
					  *args)
{
	int ret = 0;
	uint cmd_size;
	struct dxgkvmb_command_submitcommandtohwqueue *command = NULL;
	uint primaries_size = args->num_primaries * sizeof(d3dkmt_handle);

	cmd_size = sizeof(*command) + args->priv_drv_data_size + primaries_size;
	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	if (primaries_size) {
		ret = dxg_copy_from_user(&command[1], args->written_primaries,
					 primaries_size);
		if (ret)
			goto cleanup;
	}
	if (args->priv_drv_data_size) {
		ret = dxg_copy_from_user((char *)&command[1] + primaries_size,
					 args->priv_drv_data,
					 args->priv_drv_data_size);
		if (ret)
			goto cleanup;
	}

	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_SUBMITCOMMANDTOHWQUEUE,
				   process->host_handle);
	command->args = *args;

	ret = dxgvmb_send_sync_msg_ntstatus(channel, command, cmd_size);

cleanup:
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_query_clock_calibration(struct dxgprocess *process,
					struct dxgvmbuschannel *channel,
					struct d3dkmt_queryclockcalibration
					*args,
					struct d3dkmt_queryclockcalibration
					*__user inargs)
{
	struct dxgkvmb_command_queryclockcalibration command;
	struct dxgkvmb_command_queryclockcalibration_return result;
	int ret;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_QUERYCLOCKCALIBRATION,
				   process->host_handle);
	command.args = *args;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command),
				   &result, sizeof(result));
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(&inargs->clock_data, &result.clock_data,
			       sizeof(result.clock_data));
	if (ret)
		goto cleanup;
	ret = result.status;

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_flush_heap_transitions(struct dxgprocess *process,
				       struct dxgvmbuschannel *channel,
				       struct d3dkmt_flushheaptransitions *args)
{
	struct dxgkvmb_command_flushheaptransitions command;
	ntstatus status;

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_FLUSHHEAPTRANSITIONS,
				   process->host_handle);
	status =
	    dxgvmb_send_sync_msg_ntstatus(channel, &command, sizeof(command));
	TRACE_FUNC_EXIT_ERR(__func__, status);
	return status;
}

int dxgvmb_send_query_alloc_residency(struct dxgprocess *process,
				      struct dxgvmbuschannel *channel,
				      struct d3dkmt_queryallocationresidency
				      *args)
{
	int ret = 0;
	struct dxgkvmb_command_queryallocationresidency *command = NULL;
	uint cmd_size = sizeof(*command);
	uint alloc_size = 0;
	uint result_allocation_size = 0;
	struct dxgkvmb_command_queryallocationresidency_return *result = NULL;
	uint result_size = sizeof(*result);

	if (args->allocation_count > DXG_MAX_VM_BUS_PACKET_SIZE) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	if (args->allocation_count) {
		alloc_size = args->allocation_count * sizeof(d3dkmt_handle);
		cmd_size += alloc_size;
		result_allocation_size = args->allocation_count *
		    sizeof(args->residency_status[0]);
	} else {
		result_allocation_size = sizeof(args->residency_status[0]);
	}
	result_size += result_allocation_size;

	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_QUERYALLOCATIONRESIDENCY,
				   process->host_handle);
	command->args = *args;
	if (alloc_size) {
		ret = dxg_copy_from_user(&command[1], args->allocations,
					 alloc_size);
		if (ret)
			goto cleanup;
	}

	result = dxgmem_alloc(process, DXGMEM_VMBUS, result_size);
	if (result == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   result, result_size);
	if (ret)
		goto cleanup;
	if (!NT_SUCCESS(result->status)) {
		ret = result->status;
		goto cleanup;
	}
	ret = dxg_copy_to_user(args->residency_status, &result[1],
			       result_allocation_size);

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	if (result)
		dxgmem_free(process, DXGMEM_VMBUS, result);
	return ret;
}

int dxgvmb_send_escape(struct dxgprocess *process,
		       struct dxgvmbuschannel *channel,
		       struct d3dkmt_escape *args)
{
	int ret = 0;
	struct dxgkvmb_command_escape *command = NULL;
	uint cmd_size = sizeof(*command);

	if (args->priv_drv_data_size > DXG_MAX_VM_BUS_PACKET_SIZE) {
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	cmd_size = cmd_size - sizeof(args->priv_drv_data[0]) +
	    args->priv_drv_data_size;

	command = dxgmem_alloc(process, DXGMEM_VMBUS, cmd_size);
	if (command == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}
	command_vgpu_to_host_init2(&command->hdr,
				   DXGK_VMBCOMMAND_ESCAPE,
				   process->host_handle);
	command->adapter = args->adapter;
	command->device = args->device;
	command->type = args->type;
	command->flags = args->flags;
	command->priv_drv_data_size = args->priv_drv_data_size;
	command->context = args->context;
	if (args->priv_drv_data_size)
		ret = dxg_copy_from_user(command->priv_drv_data,
					 args->priv_drv_data,
					 args->priv_drv_data_size);
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg(channel, command, cmd_size,
				   command->priv_drv_data,
				   args->priv_drv_data_size);
	if (ret)
		goto cleanup;

	if (args->priv_drv_data_size)
		ret = dxg_copy_to_user(args->priv_drv_data,
				       command->priv_drv_data,
				       args->priv_drv_data_size);

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	if (command)
		dxgmem_free(process, DXGMEM_VMBUS, command);
	return ret;
}

int dxgvmb_send_query_vidmem_info(struct dxgprocess *process,
				  struct dxgvmbuschannel *channel,
				  struct d3dkmt_queryvideomemoryinfo *args,
				  struct d3dkmt_queryvideomemoryinfo *__user
				  output)
{
	int ret = 0;
	struct dxgkvmb_command_queryvideomemoryinfo command = { };
	struct dxgkvmb_command_queryvideomemoryinfo_return result = { };

	command_vgpu_to_host_init2(&command.hdr,
				   dxgk_vmbcommand_queryvideomemoryinfo,
				   process->host_handle);
	command.adapter = args->adapter;
	command.memory_segment_group = args->memory_segment_group;
	command.physical_adapter_index = args->physical_adapter_index;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command),
				   &result, sizeof(result));
	if (ret)
		goto cleanup;

	ret = dxg_copy_to_user(&output->budget, &result.budget,
			       sizeof(output->budget));
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(&output->current_usage, &result.current_usage,
			       sizeof(output->current_usage));
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(&output->current_reservation,
			       &result.current_reservation,
			       sizeof(output->current_reservation));
	if (ret)
		goto cleanup;
	ret = dxg_copy_to_user(&output->available_for_reservation,
			       &result.available_for_reservation,
			       sizeof(output->available_for_reservation));

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_get_device_state(struct dxgprocess *process,
				 struct dxgvmbuschannel *channel,
				 struct d3dkmt_getdevicestate *args,
				 struct d3dkmt_getdevicestate *__user output)
{
	int ret;
	struct dxgkvmb_command_getdevicestate command = { };
	struct dxgkvmb_command_getdevicestate_return result = { };

	command_vgpu_to_host_init2(&command.hdr,
				   dxgk_vmbcommand_getdevicestate,
				   process->host_handle);
	command.args = *args;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command),
				   &result, sizeof(result));
	if (ret)
		goto cleanup;

	if (!NT_SUCCESS(result.status)) {
		ret = result.status;
		goto cleanup;
	}
	ret = dxg_copy_to_user(output, &result.args, sizeof(result.args));

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_open_sync_object(struct dxgprocess *process,
				 struct dxgvmbuschannel *channel,
				 d3dkmt_handle shared_handle,
				 d3dkmt_handle *host_handle)
{
	struct dxgkvmb_command_opensyncobject command = { };
	struct dxgkvmb_command_opensyncobject_return result = { };
	int ret = 0;

	command_vm_to_host_init2(&command.hdr, DXGK_VMBCOMMAND_OPENSYNCOBJECT,
				 process->host_handle);
	command.global_sync_object = shared_handle;

	ret = dxgglobal_acquire_channel_lock();
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command),
				   &result, sizeof(result));

	dxgglobal_release_channel_lock();

	if (ret)
		goto cleanup;

	if (!NT_SUCCESS(result.status)) {
		ret = result.status;
		goto cleanup;
	}

	*host_handle = result.sync_object;

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_open_sync_object_nt(struct dxgprocess *process,
				    struct dxgvmbuschannel *channel,
				    struct d3dkmt_opensyncobjectfromnthandle2
				    *args, struct dxgsyncobject *syncobj)
{
	struct dxgkvmb_command_opensyncobject command = { };
	struct dxgkvmb_command_opensyncobject_return result = { };
	int ret = 0;

	command_vm_to_host_init2(&command.hdr, DXGK_VMBCOMMAND_OPENSYNCOBJECT,
				 process->host_handle);
	command.device = args->device;
	command.global_sync_object = syncobj->shared_owner->host_shared_handle;
	command.flags = args->flags;
	if (syncobj->monitored_fence)
		command.engine_affinity = args->monitored_fence.engine_affinity;

	ret = dxgglobal_acquire_channel_lock();
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command),
				   &result, sizeof(result));

	dxgglobal_release_channel_lock();

	if (ret)
		goto cleanup;

	if (!NT_SUCCESS(result.status)) {
		ret = result.status;
		goto cleanup;
	}

	args->sync_object = result.sync_object;
	if (syncobj->monitored_fence) {
		void *va = dxg_map_iospace(result.guest_cpu_physical_address,
					   PAGE_SIZE, PROT_READ | PROT_WRITE,
					   true);
		if (va == NULL) {
			ret = STATUS_NO_MEMORY;
			goto cleanup;
		}
		args->monitored_fence.fence_value_cpu_va = va;
		args->monitored_fence.fence_value_gpu_va =
		    result.gpu_virtual_address;
		syncobj->mapped_address = va;
	}

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_create_nt_shared_object(struct dxgprocess *process,
					d3dkmt_handle object,
					d3dkmt_handle *shared_handle)
{
	struct dxgkvmb_command_createntsharedobject command = { };
	int ret;

	command_vm_to_host_init2(&command.hdr,
				 DXGK_VMBCOMMAND_CREATENTSHAREDOBJECT,
				 process->host_handle);
	command.object = object;

	ret = dxgglobal_acquire_channel_lock();
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg(dxgglobal_get_dxgvmbuschannel(),
				   &command, sizeof(command), shared_handle,
				   sizeof(*shared_handle));

	dxgglobal_release_channel_lock();

	if (ret)
		goto cleanup;
	if (*shared_handle == 0) {
		pr_err("failed to create NT shared object");
		ret = STATUS_INTERNAL_ERROR;
	}

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_destroy_nt_shared_object(d3dkmt_handle shared_handle)
{
	struct dxgkvmb_command_destroyntsharedobject command = { };
	int ret;

	command_vm_to_host_init1(&command.hdr,
				 DXGK_VMBCOMMAND_DESTROYNTSHAREDOBJECT);
	command.shared_handle = shared_handle;

	ret = dxgglobal_acquire_channel_lock();
	if (ret)
		goto cleanup;

	ret = dxgvmb_send_sync_msg_ntstatus(dxgglobal_get_dxgvmbuschannel(),
					    &command, sizeof(command));

	dxgglobal_release_channel_lock();

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}

int dxgvmb_send_open_resource(struct dxgprocess *process,
			      struct dxgvmbuschannel *channel,
			      d3dkmt_handle device,
			      bool nt_security_sharing,
			      d3dkmt_handle global_share,
			      uint allocation_count,
			      uint total_priv_drv_data_size,
			      d3dkmt_handle *resource_handle,
			      d3dkmt_handle *alloc_handles)
{
	struct dxgkvmb_command_openresource command = { };
	struct dxgkvmb_command_openresource_return *result = NULL;
	d3dkmt_handle *handles;
	int ret = 0;
	int i;
	uint result_size = allocation_count * sizeof(d3dkmt_handle) +
	    sizeof(*result);

	result = dxgmem_alloc(process, DXGMEM_VMBUS, result_size);
	if (result == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	command_vgpu_to_host_init2(&command.hdr, DXGK_VMBCOMMAND_OPENRESOURCE,
				   process->host_handle);
	command.device = device;
	command.nt_security_sharing = nt_security_sharing;
	command.global_share = global_share;
	command.allocation_count = allocation_count;
	command.total_priv_drv_data_size = total_priv_drv_data_size;

	ret = dxgvmb_send_sync_msg(channel, &command, sizeof(command),
				   result, result_size);
	if (ret)
		goto cleanup;
	if (!NT_SUCCESS(result->status)) {
		ret = result->status;
		goto cleanup;
	}

	*resource_handle = result->resource;
	handles = (d3dkmt_handle *) &result[1];
	for (i = 0; i < allocation_count; i++)
		alloc_handles[i] = handles[i];

cleanup:
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	if (result)
		dxgmem_free(process, DXGMEM_VMBUS, result);
	return ret;
}

int dxgvmb_send_get_standard_alloc_priv_data(struct dxgdevice *device,
					     enum d3dkmdt_standardallocationtype
					     alloc_type,
					     struct d3dkmdt_gdisurfacedata
					     *alloc_data,
					     uint physical_adapter_index,
					     uint *alloc_priv_driver_size,
					     void *priv_alloc_data)
{
	struct dxgkvmb_command_getstandardallocprivdata command = { };
	struct dxgkvmb_command_getstandardallocprivdata_return *result = NULL;
	uint result_size = sizeof(*result);
	int ret = 0;

	TRACE_DEBUG(1, "%s", __func__);

	if (priv_alloc_data) {
		result_size = *alloc_priv_driver_size;
	}
	result = dxgmem_alloc(device->process, DXGMEM_VMBUS, result_size);
	if (result == NULL) {
		ret = STATUS_NO_MEMORY;
		goto cleanup;
	}

	command_vgpu_to_host_init2(&command.hdr,
				   DXGK_VMBCOMMAND_DDIGETSTANDARDALLOCATIONDRIVERDATA,
				   device->process->host_handle);

	command.alloc_type = alloc_type;
	command.priv_driver_data_size = *alloc_priv_driver_size;
	command.physical_adapter_index = physical_adapter_index;
	switch (alloc_type) {
	case D3DKMDT_STANDARDALLOCATION_GDISURFACE:
		command.gdi_surface = *alloc_data;
		break;
	case D3DKMDT_STANDARDALLOCATION_SHAREDPRIMARYSURFACE:
	case D3DKMDT_STANDARDALLOCATION_SHADOWSURFACE:
	case D3DKMDT_STANDARDALLOCATION_STAGINGSURFACE:
	default:
		pr_err("Invalid standard alloc type");
		goto cleanup;
	}

	ret = dxgvmb_send_sync_msg(&device->adapter->channel,
				   &command, sizeof(command), result,
				   result_size);
	if (ret)
		goto cleanup;
	if (!NT_SUCCESS(result->status)) {
		ret = result->status;
		goto cleanup;
	}
	if (*alloc_priv_driver_size &&
	    result->priv_driver_data_size != *alloc_priv_driver_size) {
		pr_err("Priv data size mismatch");
		goto cleanup;
	}
	*alloc_priv_driver_size = result->priv_driver_data_size;
	if (priv_alloc_data) {
		memcpy(priv_alloc_data, &result[1],
		       result->priv_driver_data_size);
	}

cleanup:

	if (result)
		dxgmem_free(device->process, DXGMEM_VMBUS, result);
	TRACE_FUNC_EXIT_ERR(__func__, ret);
	return ret;
}
