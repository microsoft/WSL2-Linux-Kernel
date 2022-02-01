// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2022, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@linux.microsoft.com>
 *
 * Dxgkrnl Graphics Driver
 * Implementation of dxgadapter and its objects
 *
 */

#include <linux/module.h>
#include <linux/hyperv.h>
#include <linux/pagemap.h>
#include <linux/eventfd.h>

#include "dxgkrnl.h"

#undef pr_fmt
#define pr_fmt(fmt)	"dxgk: " fmt

int dxgadapter_set_vmbus(struct dxgadapter *adapter, struct hv_device *hdev)
{
	int ret;

	guid_to_luid(&hdev->channel->offermsg.offer.if_instance,
		     &adapter->luid);
	DXG_TRACE("%x:%x %p %pUb",
		adapter->luid.b, adapter->luid.a, hdev->channel,
		&hdev->channel->offermsg.offer.if_instance);

	ret = dxgvmbuschannel_init(&adapter->channel, hdev);
	if (ret)
		goto cleanup;

	adapter->channel.adapter = adapter;
	adapter->hv_dev = hdev;

	ret = dxgvmb_send_open_adapter(adapter);
	if (ret < 0) {
		DXG_ERR("dxgvmb_send_open_adapter failed: %d", ret);
		goto cleanup;
	}

	ret = dxgvmb_send_get_internal_adapter_info(adapter);

cleanup:
	if (ret)
		DXG_ERR("Failed to set vmbus: %d", ret);
	return ret;
}

void dxgadapter_start(struct dxgadapter *adapter)
{
	struct dxgvgpuchannel *ch = NULL;
	struct dxgvgpuchannel *entry;
	int ret;
	struct dxgglobal *dxgglobal = dxggbl();

	DXG_TRACE("%x-%x", adapter->luid.a, adapter->luid.b);

	/* Find the corresponding vGPU vm bus channel */
	list_for_each_entry(entry, &dxgglobal->vgpu_ch_list_head,
			    vgpu_ch_list_entry) {
		if (memcmp(&adapter->luid,
			   &entry->adapter_luid,
			   sizeof(struct winluid)) == 0) {
			ch = entry;
			break;
		}
	}
	if (ch == NULL) {
		DXG_TRACE("vGPU chanel is not ready");
		return;
	}

	/* The global channel is initialized when the first adapter starts */
	if (!dxgglobal->global_channel_initialized) {
		ret = dxgglobal_init_global_channel();
		if (ret) {
			dxgglobal_destroy_global_channel();
			return;
		}
		dxgglobal->global_channel_initialized = true;
	}

	/* Initialize vGPU vm bus channel */
	ret = dxgadapter_set_vmbus(adapter, ch->hdev);
	if (ret) {
		DXG_ERR("Failed to start adapter %p", adapter);
		adapter->adapter_state = DXGADAPTER_STATE_STOPPED;
		return;
	}

	adapter->adapter_state = DXGADAPTER_STATE_ACTIVE;
	DXG_TRACE("Adapter started %p", adapter);
}

void dxgadapter_stop(struct dxgadapter *adapter)
{
	struct dxgprocess_adapter *entry;
	bool adapter_stopped = false;

	down_write(&adapter->core_lock);
	if (!adapter->stopping_adapter)
		adapter->stopping_adapter = true;
	else
		adapter_stopped = true;
	up_write(&adapter->core_lock);

	if (adapter_stopped)
		return;

	dxgglobal_acquire_process_adapter_lock();

	list_for_each_entry(entry, &adapter->adapter_process_list_head,
			    adapter_process_list_entry) {
		dxgprocess_adapter_stop(entry);
	}

	dxgglobal_release_process_adapter_lock();

	if (dxgadapter_acquire_lock_exclusive(adapter) == 0) {
		dxgvmb_send_close_adapter(adapter);
		dxgadapter_release_lock_exclusive(adapter);
	}
	dxgvmbuschannel_destroy(&adapter->channel);

	adapter->adapter_state = DXGADAPTER_STATE_STOPPED;
}

void dxgadapter_release(struct kref *refcount)
{
	struct dxgadapter *adapter;

	adapter = container_of(refcount, struct dxgadapter, adapter_kref);
	DXG_TRACE("%p", adapter);
	kfree(adapter);
}

bool dxgadapter_is_active(struct dxgadapter *adapter)
{
	return adapter->adapter_state == DXGADAPTER_STATE_ACTIVE;
}

/* Protected by dxgglobal_acquire_process_adapter_lock */
void dxgadapter_add_process(struct dxgadapter *adapter,
			    struct dxgprocess_adapter *process_info)
{
	DXG_TRACE("%p %p", adapter, process_info);
	list_add_tail(&process_info->adapter_process_list_entry,
		      &adapter->adapter_process_list_head);
}

void dxgadapter_remove_process(struct dxgprocess_adapter *process_info)
{
	DXG_TRACE("%p %p", process_info->adapter, process_info);
	list_del(&process_info->adapter_process_list_entry);
}

void dxgadapter_add_syncobj(struct dxgadapter *adapter,
			    struct dxgsyncobject *object)
{
	down_write(&adapter->shared_resource_list_lock);
	list_add_tail(&object->syncobj_list_entry, &adapter->syncobj_list_head);
	up_write(&adapter->shared_resource_list_lock);
}

void dxgadapter_remove_syncobj(struct dxgsyncobject *object)
{
	down_write(&object->adapter->shared_resource_list_lock);
	if (object->syncobj_list_entry.next) {
		list_del(&object->syncobj_list_entry);
		object->syncobj_list_entry.next = NULL;
	}
	up_write(&object->adapter->shared_resource_list_lock);
}

int dxgadapter_acquire_lock_exclusive(struct dxgadapter *adapter)
{
	down_write(&adapter->core_lock);
	if (adapter->adapter_state != DXGADAPTER_STATE_ACTIVE) {
		dxgadapter_release_lock_exclusive(adapter);
		return -ENODEV;
	}
	return 0;
}

void dxgadapter_acquire_lock_forced(struct dxgadapter *adapter)
{
	down_write(&adapter->core_lock);
}

void dxgadapter_release_lock_exclusive(struct dxgadapter *adapter)
{
	up_write(&adapter->core_lock);
}

int dxgadapter_acquire_lock_shared(struct dxgadapter *adapter)
{
	down_read(&adapter->core_lock);
	if (adapter->adapter_state == DXGADAPTER_STATE_ACTIVE)
		return 0;
	dxgadapter_release_lock_shared(adapter);
	return -ENODEV;
}

void dxgadapter_release_lock_shared(struct dxgadapter *adapter)
{
	up_read(&adapter->core_lock);
}

struct dxgdevice *dxgdevice_create(struct dxgadapter *adapter,
				   struct dxgprocess *process)
{
	struct dxgdevice *device;
	int ret;

	device = kzalloc(sizeof(struct dxgdevice), GFP_KERNEL);
	if (device) {
		kref_init(&device->device_kref);
		device->adapter = adapter;
		device->process = process;
		kref_get(&adapter->adapter_kref);
		INIT_LIST_HEAD(&device->context_list_head);
		INIT_LIST_HEAD(&device->alloc_list_head);
		INIT_LIST_HEAD(&device->resource_list_head);
		init_rwsem(&device->device_lock);
		init_rwsem(&device->context_list_lock);
		init_rwsem(&device->alloc_list_lock);
		INIT_LIST_HEAD(&device->pqueue_list_head);
		INIT_LIST_HEAD(&device->syncobj_list_head);
		device->object_state = DXGOBJECTSTATE_CREATED;
		device->execution_state = _D3DKMT_DEVICEEXECUTION_ACTIVE;

		ret = dxgprocess_adapter_add_device(process, adapter, device);
		if (ret < 0) {
			kref_put(&device->device_kref, dxgdevice_release);
			device = NULL;
		}
	}
	return device;
}

void dxgdevice_stop(struct dxgdevice *device)
{
	struct dxgallocation *alloc;
	struct dxgsyncobject *syncobj;

	DXG_TRACE("Destroying device: %p", device);
	dxgdevice_acquire_alloc_list_lock(device);
	list_for_each_entry(alloc, &device->alloc_list_head, alloc_list_entry) {
		dxgallocation_stop(alloc);
	}
	dxgdevice_release_alloc_list_lock(device);

	hmgrtable_lock(&device->process->handle_table, DXGLOCK_EXCL);
	list_for_each_entry(syncobj, &device->syncobj_list_head,
			    syncobj_list_entry) {
		dxgsyncobject_stop(syncobj);
	}
	hmgrtable_unlock(&device->process->handle_table, DXGLOCK_EXCL);
	DXG_TRACE("Device stopped: %p", device);
}

void dxgdevice_mark_destroyed(struct dxgdevice *device)
{
	down_write(&device->device_lock);
	device->object_state = DXGOBJECTSTATE_DESTROYED;
	up_write(&device->device_lock);
}

void dxgdevice_destroy(struct dxgdevice *device)
{
	struct dxgprocess *process = device->process;
	struct dxgadapter *adapter = device->adapter;
	struct d3dkmthandle device_handle = {};

	DXG_TRACE("Destroying device: %p", device);

	down_write(&device->device_lock);

	if (device->object_state != DXGOBJECTSTATE_ACTIVE)
		goto cleanup;

	device->object_state = DXGOBJECTSTATE_DESTROYED;

	dxgdevice_stop(device);

	dxgdevice_acquire_alloc_list_lock(device);

	while (!list_empty(&device->syncobj_list_head)) {
		struct dxgsyncobject *syncobj =
		    list_first_entry(&device->syncobj_list_head,
				     struct dxgsyncobject,
				     syncobj_list_entry);
		list_del(&syncobj->syncobj_list_entry);
		syncobj->syncobj_list_entry.next = NULL;
		dxgdevice_release_alloc_list_lock(device);

		dxgsyncobject_destroy(process, syncobj);

		dxgdevice_acquire_alloc_list_lock(device);
	}

	{
		struct dxgallocation *alloc;
		struct dxgallocation *tmp;

		DXG_TRACE("destroying allocations");
		list_for_each_entry_safe(alloc, tmp, &device->alloc_list_head,
					 alloc_list_entry) {
			dxgallocation_destroy(alloc);
		}
	}

	{
		struct dxgresource *resource;
		struct dxgresource *tmp;

		DXG_TRACE("destroying resources");
		list_for_each_entry_safe(resource, tmp,
					 &device->resource_list_head,
					 resource_list_entry) {
			dxgresource_destroy(resource);
		}
	}

	dxgdevice_release_alloc_list_lock(device);

	{
		struct dxgcontext *context;
		struct dxgcontext *tmp;

		DXG_TRACE("destroying contexts");
		dxgdevice_acquire_context_list_lock(device);
		list_for_each_entry_safe(context, tmp,
					 &device->context_list_head,
					 context_list_entry) {
			dxgcontext_destroy(process, context);
		}
		dxgdevice_release_context_list_lock(device);
	}

	/* Guest handles need to be released before the host handles */
	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	if (device->handle_valid) {
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGDEVICE, device->handle);
		device_handle = device->handle;
		device->handle_valid = 0;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (device_handle.v) {
		up_write(&device->device_lock);
		if (dxgadapter_acquire_lock_shared(adapter) == 0) {
			dxgvmb_send_destroy_device(adapter, process,
						   device_handle);
			dxgadapter_release_lock_shared(adapter);
		}
		down_write(&device->device_lock);
	}

cleanup:

	if (device->adapter) {
		dxgprocess_adapter_remove_device(device);
		kref_put(&device->adapter->adapter_kref, dxgadapter_release);
		device->adapter = NULL;
	}

	up_write(&device->device_lock);

	kref_put(&device->device_kref, dxgdevice_release);
	DXG_TRACE("Device destroyed");
}

int dxgdevice_acquire_lock_shared(struct dxgdevice *device)
{
	down_read(&device->device_lock);
	if (!dxgdevice_is_active(device)) {
		up_read(&device->device_lock);
		return -ENODEV;
	}
	return 0;
}

void dxgdevice_release_lock_shared(struct dxgdevice *device)
{
	up_read(&device->device_lock);
}

bool dxgdevice_is_active(struct dxgdevice *device)
{
	return device->object_state == DXGOBJECTSTATE_ACTIVE;
}

void dxgdevice_acquire_context_list_lock(struct dxgdevice *device)
{
	down_write(&device->context_list_lock);
}

void dxgdevice_release_context_list_lock(struct dxgdevice *device)
{
	up_write(&device->context_list_lock);
}

void dxgdevice_acquire_alloc_list_lock(struct dxgdevice *device)
{
	down_write(&device->alloc_list_lock);
}

void dxgdevice_release_alloc_list_lock(struct dxgdevice *device)
{
	up_write(&device->alloc_list_lock);
}

void dxgdevice_acquire_alloc_list_lock_shared(struct dxgdevice *device)
{
	down_read(&device->alloc_list_lock);
}

void dxgdevice_release_alloc_list_lock_shared(struct dxgdevice *device)
{
	up_read(&device->alloc_list_lock);
}

void dxgdevice_add_context(struct dxgdevice *device, struct dxgcontext *context)
{
	down_write(&device->context_list_lock);
	list_add_tail(&context->context_list_entry, &device->context_list_head);
	up_write(&device->context_list_lock);
}

void dxgdevice_remove_context(struct dxgdevice *device,
			      struct dxgcontext *context)
{
	if (context->context_list_entry.next) {
		list_del(&context->context_list_entry);
		context->context_list_entry.next = NULL;
	}
}

void dxgdevice_add_alloc(struct dxgdevice *device, struct dxgallocation *alloc)
{
	dxgdevice_acquire_alloc_list_lock(device);
	list_add_tail(&alloc->alloc_list_entry, &device->alloc_list_head);
	kref_get(&device->device_kref);
	alloc->owner.device = device;
	dxgdevice_release_alloc_list_lock(device);
}

void dxgdevice_remove_alloc(struct dxgdevice *device,
			    struct dxgallocation *alloc)
{
	if (alloc->alloc_list_entry.next) {
		list_del(&alloc->alloc_list_entry);
		alloc->alloc_list_entry.next = NULL;
		kref_put(&device->device_kref, dxgdevice_release);
	}
}

void dxgdevice_remove_alloc_safe(struct dxgdevice *device,
				 struct dxgallocation *alloc)
{
	dxgdevice_acquire_alloc_list_lock(device);
	dxgdevice_remove_alloc(device, alloc);
	dxgdevice_release_alloc_list_lock(device);
}

void dxgdevice_add_resource(struct dxgdevice *device, struct dxgresource *res)
{
	dxgdevice_acquire_alloc_list_lock(device);
	list_add_tail(&res->resource_list_entry, &device->resource_list_head);
	kref_get(&device->device_kref);
	dxgdevice_release_alloc_list_lock(device);
}

void dxgdevice_remove_resource(struct dxgdevice *device,
			       struct dxgresource *res)
{
	if (res->resource_list_entry.next) {
		list_del(&res->resource_list_entry);
		res->resource_list_entry.next = NULL;
		kref_put(&device->device_kref, dxgdevice_release);
	}
}

struct dxgresource *dxgresource_create(struct dxgdevice *device)
{
	struct dxgresource *resource;

	resource = kzalloc(sizeof(struct dxgresource), GFP_KERNEL);
	if (resource) {
		kref_init(&resource->resource_kref);
		resource->device = device;
		resource->process = device->process;
		resource->object_state = DXGOBJECTSTATE_ACTIVE;
		mutex_init(&resource->resource_mutex);
		INIT_LIST_HEAD(&resource->alloc_list_head);
		dxgdevice_add_resource(device, resource);
	}
	return resource;
}

void dxgresource_free_handle(struct dxgresource *resource)
{
	struct dxgallocation *alloc;
	struct dxgprocess *process;

	if (resource->handle_valid) {
		process = resource->device->process;
		hmgrtable_free_handle_safe(&process->handle_table,
					   HMGRENTRY_TYPE_DXGRESOURCE,
					   resource->handle);
		resource->handle_valid = 0;
	}
	list_for_each_entry(alloc, &resource->alloc_list_head,
			    alloc_list_entry) {
		dxgallocation_free_handle(alloc);
	}
}

void dxgresource_destroy(struct dxgresource *resource)
{
	/* device->alloc_list_lock is held */
	struct dxgallocation *alloc;
	struct dxgallocation *tmp;
	struct d3dkmt_destroyallocation2 args = { };
	int destroyed = test_and_set_bit(0, &resource->flags);
	struct dxgdevice *device = resource->device;

	if (!destroyed) {
		dxgresource_free_handle(resource);
		if (resource->handle.v) {
			args.device = device->handle;
			args.resource = resource->handle;
			dxgvmb_send_destroy_allocation(device->process,
						       device, &args, NULL);
			resource->handle.v = 0;
		}
		list_for_each_entry_safe(alloc, tmp, &resource->alloc_list_head,
					 alloc_list_entry) {
			dxgallocation_destroy(alloc);
		}
		dxgdevice_remove_resource(device, resource);
	}
	kref_put(&resource->resource_kref, dxgresource_release);
}

void dxgresource_release(struct kref *refcount)
{
	struct dxgresource *resource;

	resource = container_of(refcount, struct dxgresource, resource_kref);
	kfree(resource);
}

bool dxgresource_is_active(struct dxgresource *resource)
{
	return resource->object_state == DXGOBJECTSTATE_ACTIVE;
}

int dxgresource_add_alloc(struct dxgresource *resource,
				      struct dxgallocation *alloc)
{
	int ret = -ENODEV;
	struct dxgdevice *device = resource->device;

	dxgdevice_acquire_alloc_list_lock(device);
	if (dxgresource_is_active(resource)) {
		list_add_tail(&alloc->alloc_list_entry,
			      &resource->alloc_list_head);
		alloc->owner.resource = resource;
		ret = 0;
	}
	alloc->resource_owner = 1;
	dxgdevice_release_alloc_list_lock(device);
	return ret;
}

void dxgresource_remove_alloc(struct dxgresource *resource,
			      struct dxgallocation *alloc)
{
	if (alloc->alloc_list_entry.next) {
		list_del(&alloc->alloc_list_entry);
		alloc->alloc_list_entry.next = NULL;
	}
}

void dxgresource_remove_alloc_safe(struct dxgresource *resource,
				   struct dxgallocation *alloc)
{
	dxgdevice_acquire_alloc_list_lock(resource->device);
	dxgresource_remove_alloc(resource, alloc);
	dxgdevice_release_alloc_list_lock(resource->device);
}

void dxgdevice_release(struct kref *refcount)
{
	struct dxgdevice *device;

	device = container_of(refcount, struct dxgdevice, device_kref);
	kfree(device);
}

void dxgdevice_add_syncobj(struct dxgdevice *device,
			   struct dxgsyncobject *syncobj)
{
	dxgdevice_acquire_alloc_list_lock(device);
	list_add_tail(&syncobj->syncobj_list_entry, &device->syncobj_list_head);
	kref_get(&syncobj->syncobj_kref);
	dxgdevice_release_alloc_list_lock(device);
}

void dxgdevice_remove_syncobj(struct dxgsyncobject *entry)
{
	struct dxgdevice *device = entry->device;

	dxgdevice_acquire_alloc_list_lock(device);
	if (entry->syncobj_list_entry.next) {
		list_del(&entry->syncobj_list_entry);
		entry->syncobj_list_entry.next = NULL;
		kref_put(&entry->syncobj_kref, dxgsyncobject_release);
	}
	dxgdevice_release_alloc_list_lock(device);
	kref_put(&device->device_kref, dxgdevice_release);
	entry->device = NULL;
}

struct dxgcontext *dxgcontext_create(struct dxgdevice *device)
{
	struct dxgcontext *context;

	context = kzalloc(sizeof(struct dxgcontext), GFP_KERNEL);
	if (context) {
		kref_init(&context->context_kref);
		context->device = device;
		context->process = device->process;
		context->device_handle = device->handle;
		kref_get(&device->device_kref);
		INIT_LIST_HEAD(&context->hwqueue_list_head);
		init_rwsem(&context->hwqueue_list_lock);
		dxgdevice_add_context(device, context);
		context->object_state = DXGOBJECTSTATE_ACTIVE;
	}
	return context;
}

/*
 * Called when the device context list lock is held
 */
void dxgcontext_destroy(struct dxgprocess *process, struct dxgcontext *context)
{
	DXG_TRACE("Destroying context %p", context);
	context->object_state = DXGOBJECTSTATE_DESTROYED;
	if (context->device) {
		if (context->handle.v) {
			hmgrtable_free_handle_safe(&process->handle_table,
						   HMGRENTRY_TYPE_DXGCONTEXT,
						   context->handle);
		}
		dxgdevice_remove_context(context->device, context);
		kref_put(&context->device->device_kref, dxgdevice_release);
	}
	kref_put(&context->context_kref, dxgcontext_release);
}

void dxgcontext_destroy_safe(struct dxgprocess *process,
			     struct dxgcontext *context)
{
	struct dxgdevice *device = context->device;

	dxgdevice_acquire_context_list_lock(device);
	dxgcontext_destroy(process, context);
	dxgdevice_release_context_list_lock(device);
}

bool dxgcontext_is_active(struct dxgcontext *context)
{
	return context->object_state == DXGOBJECTSTATE_ACTIVE;
}

void dxgcontext_release(struct kref *refcount)
{
	struct dxgcontext *context;

	context = container_of(refcount, struct dxgcontext, context_kref);
	kfree(context);
}

struct dxgallocation *dxgallocation_create(struct dxgprocess *process)
{
	struct dxgallocation *alloc;

	alloc = kzalloc(sizeof(struct dxgallocation), GFP_KERNEL);
	if (alloc)
		alloc->process = process;
	return alloc;
}

void dxgallocation_stop(struct dxgallocation *alloc)
{
	if (alloc->pages) {
		release_pages(alloc->pages, alloc->num_pages);
		vfree(alloc->pages);
		alloc->pages = NULL;
	}
}

void dxgallocation_free_handle(struct dxgallocation *alloc)
{
	dxgprocess_ht_lock_exclusive_down(alloc->process);
	if (alloc->handle_valid) {
		hmgrtable_free_handle(&alloc->process->handle_table,
				      HMGRENTRY_TYPE_DXGALLOCATION,
				      alloc->alloc_handle);
		alloc->handle_valid = 0;
	}
	dxgprocess_ht_lock_exclusive_up(alloc->process);
}

void dxgallocation_destroy(struct dxgallocation *alloc)
{
	struct dxgprocess *process = alloc->process;
	struct d3dkmt_destroyallocation2 args = { };

	dxgallocation_stop(alloc);
	if (alloc->resource_owner)
		dxgresource_remove_alloc(alloc->owner.resource, alloc);
	else if (alloc->owner.device)
		dxgdevice_remove_alloc(alloc->owner.device, alloc);
	dxgallocation_free_handle(alloc);
	if (alloc->alloc_handle.v && !alloc->resource_owner) {
		args.device = alloc->owner.device->handle;
		args.alloc_count = 1;
		dxgvmb_send_destroy_allocation(process,
					       alloc->owner.device,
					       &args, &alloc->alloc_handle);
	}
#ifdef _MAIN_KERNEL_
	if (alloc->gpadl.gpadl_handle) {
		DXG_TRACE("Teardown gpadl %d",
			alloc->gpadl.gpadl_handle);
		vmbus_teardown_gpadl(dxgglobal_get_vmbus(), &alloc->gpadl);
		alloc->gpadl.gpadl_handle = 0;
	}
else
	if (alloc->gpadl) {
		DXG_TRACE("Teardown gpadl %d",
			alloc->gpadl);
		vmbus_teardown_gpadl(dxgglobal_get_vmbus(), alloc->gpadl);
		alloc->gpadl = 0;
	}
#endif
	if (alloc->priv_drv_data)
		vfree(alloc->priv_drv_data);
	kfree(alloc);
}

struct dxgprocess_adapter *dxgprocess_adapter_create(struct dxgprocess *process,
						     struct dxgadapter *adapter)
{
	struct dxgprocess_adapter *adapter_info;

	adapter_info = kzalloc(sizeof(*adapter_info), GFP_KERNEL);
	if (adapter_info) {
		if (kref_get_unless_zero(&adapter->adapter_kref) == 0) {
			DXG_ERR("failed to acquire adapter reference");
			goto cleanup;
		}
		adapter_info->adapter = adapter;
		adapter_info->process = process;
		adapter_info->refcount = 1;
		mutex_init(&adapter_info->device_list_mutex);
		INIT_LIST_HEAD(&adapter_info->device_list_head);
		list_add_tail(&adapter_info->process_adapter_list_entry,
			      &process->process_adapter_list_head);
		dxgadapter_add_process(adapter, adapter_info);
	}
	return adapter_info;
cleanup:
	if (adapter_info)
		kfree(adapter_info);
	return NULL;
}

void dxgprocess_adapter_stop(struct dxgprocess_adapter *adapter_info)
{
	struct dxgdevice *device;

	mutex_lock(&adapter_info->device_list_mutex);
	list_for_each_entry(device, &adapter_info->device_list_head,
			    device_list_entry) {
		dxgdevice_stop(device);
	}
	mutex_unlock(&adapter_info->device_list_mutex);
}

void dxgprocess_adapter_destroy(struct dxgprocess_adapter *adapter_info)
{
	struct dxgdevice *device;

	mutex_lock(&adapter_info->device_list_mutex);
	while (!list_empty(&adapter_info->device_list_head)) {
		device = list_first_entry(&adapter_info->device_list_head,
					  struct dxgdevice, device_list_entry);
		list_del(&device->device_list_entry);
		device->device_list_entry.next = NULL;
		mutex_unlock(&adapter_info->device_list_mutex);
		dxgvmb_send_flush_device(device,
			DXGDEVICE_FLUSHSCHEDULER_DEVICE_TERMINATE);
		dxgdevice_destroy(device);
		mutex_lock(&adapter_info->device_list_mutex);
	}
	mutex_unlock(&adapter_info->device_list_mutex);

	dxgadapter_remove_process(adapter_info);
	kref_put(&adapter_info->adapter->adapter_kref, dxgadapter_release);
	list_del(&adapter_info->process_adapter_list_entry);
	kfree(adapter_info);
}

/*
 * Must be called when dxgglobal::process_adapter_mutex is held
 */
void dxgprocess_adapter_release(struct dxgprocess_adapter *adapter_info)
{
	adapter_info->refcount--;
	if (adapter_info->refcount == 0)
		dxgprocess_adapter_destroy(adapter_info);
}

int dxgprocess_adapter_add_device(struct dxgprocess *process,
				  struct dxgadapter *adapter,
				  struct dxgdevice *device)
{
	struct dxgprocess_adapter *entry;
	struct dxgprocess_adapter *adapter_info = NULL;
	int ret = 0;

	dxgglobal_acquire_process_adapter_lock();

	list_for_each_entry(entry, &process->process_adapter_list_head,
			    process_adapter_list_entry) {
		if (entry->adapter == adapter) {
			adapter_info = entry;
			break;
		}
	}
	if (adapter_info == NULL) {
		DXG_ERR("failed to find process adapter info");
		ret = -EINVAL;
		goto cleanup;
	}
	mutex_lock(&adapter_info->device_list_mutex);
	list_add_tail(&device->device_list_entry,
		      &adapter_info->device_list_head);
	device->adapter_info = adapter_info;
	mutex_unlock(&adapter_info->device_list_mutex);

cleanup:

	dxgglobal_release_process_adapter_lock();
	return ret;
}

void dxgprocess_adapter_remove_device(struct dxgdevice *device)
{
	DXG_TRACE("Removing device: %p", device);
	mutex_lock(&device->adapter_info->device_list_mutex);
	if (device->device_list_entry.next) {
		list_del(&device->device_list_entry);
		device->device_list_entry.next = NULL;
	}
	mutex_unlock(&device->adapter_info->device_list_mutex);
}

struct dxgsyncobject *dxgsyncobject_create(struct dxgprocess *process,
					   struct dxgdevice *device,
					   struct dxgadapter *adapter,
					   enum
					   d3dddi_synchronizationobject_type
					   type,
					   struct
					   d3dddi_synchronizationobject_flags
					   flags)
{
	struct dxgsyncobject *syncobj;

	syncobj = kzalloc(sizeof(*syncobj), GFP_KERNEL);
	if (syncobj == NULL)
		goto cleanup;
	syncobj->type = type;
	syncobj->process = process;
	switch (type) {
	case _D3DDDI_MONITORED_FENCE:
	case _D3DDDI_PERIODIC_MONITORED_FENCE:
		syncobj->monitored_fence = 1;
		break;
	default:
		break;
	}
	if (flags.shared) {
		syncobj->shared = 1;
		if (!flags.nt_security_sharing) {
			DXG_ERR("nt_security_sharing must be set");
			goto cleanup;
		}
	}

	kref_init(&syncobj->syncobj_kref);

	if (syncobj->monitored_fence) {
		syncobj->device = device;
		syncobj->device_handle = device->handle;
		kref_get(&device->device_kref);
		dxgdevice_add_syncobj(device, syncobj);
	} else {
		dxgadapter_add_syncobj(adapter, syncobj);
	}
	syncobj->adapter = adapter;
	kref_get(&adapter->adapter_kref);

	DXG_TRACE("Syncobj created: %p", syncobj);
	return syncobj;
cleanup:
	if (syncobj)
		kfree(syncobj);
	return NULL;
}

void dxgsyncobject_destroy(struct dxgprocess *process,
			   struct dxgsyncobject *syncobj)
{
	int destroyed;

	DXG_TRACE("Destroying syncobj: %p", syncobj);

	dxgsyncobject_stop(syncobj);

	destroyed = test_and_set_bit(0, &syncobj->flags);
	if (!destroyed) {
		DXG_TRACE("Deleting handle: %x", syncobj->handle.v);
		hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
		if (syncobj->handle.v) {
			hmgrtable_free_handle(&process->handle_table,
					      HMGRENTRY_TYPE_DXGSYNCOBJECT,
					      syncobj->handle);
			syncobj->handle.v = 0;
			kref_put(&syncobj->syncobj_kref, dxgsyncobject_release);
		}
		hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

		if (syncobj->monitored_fence)
			dxgdevice_remove_syncobj(syncobj);
		else
			dxgadapter_remove_syncobj(syncobj);
		if (syncobj->adapter) {
			kref_put(&syncobj->adapter->adapter_kref,
				 dxgadapter_release);
			syncobj->adapter = NULL;
		}
	}
	kref_put(&syncobj->syncobj_kref, dxgsyncobject_release);
}

void dxgsyncobject_stop(struct dxgsyncobject *syncobj)
{
	int stopped = test_and_set_bit(1, &syncobj->flags);

	if (!stopped) {
		DXG_TRACE("Stopping syncobj");
		if (syncobj->monitored_fence) {
			if (syncobj->mapped_address) {
				int ret =
				    dxg_unmap_iospace(syncobj->mapped_address,
						      PAGE_SIZE);

				(void)ret;
				DXG_TRACE("unmap fence %d %p",
					ret, syncobj->mapped_address);
				syncobj->mapped_address = NULL;
			}
		}
	}
}

void dxgsyncobject_release(struct kref *refcount)
{
	struct dxgsyncobject *syncobj;

	syncobj = container_of(refcount, struct dxgsyncobject, syncobj_kref);
	kfree(syncobj);
}
