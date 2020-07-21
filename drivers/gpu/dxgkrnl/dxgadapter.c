// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2019, Microsoft Corporation.
 *
 * Author:
 *   Iouri Tarassov <iourit@microsoft.com>
 *
 * Dxgkrnl Graphics Port Driver
 * dxgadapter  implementation
 *
 */

#include <linux/module.h>
#include <linux/hyperv.h>
#include <linux/pagemap.h>
#include <linux/eventfd.h>

#include "dxgkrnl.h"

int dxgadapter_init(struct dxgadapter *adapter, struct hv_device *hdev)
{
	int ret = 0;
	char s[80];

	UNUSED(s);
	guid_to_luid(&hdev->channel->offermsg.offer.if_instance,
		     &adapter->luid);
	TRACE_DEBUG(1, "%s: %x:%x %p %pUb\n",
		    __func__, adapter->luid.b, adapter->luid.a, hdev->channel,
		    &hdev->channel->offermsg.offer.if_instance);

	adapter->adapter_state = DXGADAPTER_STATE_STOPPED;
	refcount_set(&adapter->refcount, 1);
	init_rwsem(&adapter->core_lock);

	INIT_LIST_HEAD(&adapter->adapter_process_list_head);
	INIT_LIST_HEAD(&adapter->shared_resource_list_head);
	INIT_LIST_HEAD(&adapter->adapter_shared_syncobj_list_head);
	INIT_LIST_HEAD(&adapter->syncobj_list_head);
	init_rwsem(&adapter->shared_resource_list_lock);

	ret = dxgvmbuschannel_init(&adapter->channel, hdev);
	if (ret)
		goto cleanup;

	adapter->channel.adapter = adapter;

	ret = dxgvmb_send_open_adapter(adapter);
	if (ret) {
		pr_err("dxgvmb_send_open_adapter failed: %d\n", ret);
		goto cleanup;
	}

	adapter->adapter_state = DXGADAPTER_STATE_ACTIVE;

	ret = dxgvmb_send_get_internal_adapter_info(adapter);
	if (ret) {
		pr_err("get_internal_adapter_info failed: %d\n", ret);
		goto cleanup;
	}

cleanup:

	return ret;
}

void dxgadapter_stop(struct dxgadapter *adapter)
{
	struct dxgprocess_adapter *entry;

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
}

void dxgadapter_destroy(struct dxgadapter *adapter)
{
	TRACE_DEBUG(1, "%s %p\n", __func__, adapter);
	dxgmem_free(NULL, DXGMEM_ADAPTER, adapter);
}

bool dxgadapter_acquire_reference(struct dxgadapter *adapter)
{
	return refcount_inc_not_zero(&adapter->refcount);
}

void dxgadapter_release_reference(struct dxgadapter *adapter)
{
	if (refcount_dec_and_test(&adapter->refcount))
		dxgadapter_destroy(adapter);
}

bool dxgadapter_is_active(struct dxgadapter *adapter)
{
	return adapter->adapter_state == DXGADAPTER_STATE_ACTIVE;
}

/* Protected by dxgglobal_acquire_process_adapter_lock */
void dxgadapter_add_process(struct dxgadapter *adapter,
			    struct dxgprocess_adapter *process_info)
{
	TRACE_DEBUG(1, "%s %p %p", __func__, adapter, process_info);
	list_add_tail(&process_info->adapter_process_list_entry,
		      &adapter->adapter_process_list_head);
}

void dxgadapter_remove_process(struct dxgprocess_adapter *process_info)
{
	TRACE_DEBUG(1, "%s %p %p", __func__,
		    process_info->adapter, process_info);
	list_del(&process_info->adapter_process_list_entry);
	process_info->adapter_process_list_entry.next = NULL;
	process_info->adapter_process_list_entry.prev = NULL;
}

void dxgadapter_add_shared_resource(struct dxgadapter *adapter,
				    struct dxgsharedresource *object)
{
	/* Adapter lock is held */
	down_write(&adapter->shared_resource_list_lock);
	list_add_tail(&object->shared_resource_list_entry,
		      &adapter->shared_resource_list_head);
	up_write(&adapter->shared_resource_list_lock);
}

void dxgadapter_remove_shared_resource(struct dxgadapter *adapter,
				       struct dxgsharedresource *object)
{
	down_write(&adapter->shared_resource_list_lock);
	if (object->shared_resource_list_entry.next) {
		list_del(&object->shared_resource_list_entry);
		object->shared_resource_list_entry.next = NULL;
	}
	up_write(&adapter->shared_resource_list_lock);
}

void dxgadapter_add_shared_syncobj(struct dxgadapter *adapter,
				   struct dxgsharedsyncobject *object)
{
	down_write(&adapter->shared_resource_list_lock);
	list_add_tail(&object->adapter_shared_syncobj_list_entry,
		      &adapter->adapter_shared_syncobj_list_head);
	up_write(&adapter->shared_resource_list_lock);
}

void dxgadapter_remove_shared_syncobj(struct dxgadapter *adapter,
				      struct dxgsharedsyncobject *object)
{
	down_write(&adapter->shared_resource_list_lock);
	if (object->adapter_shared_syncobj_list_entry.next) {
		list_del(&object->adapter_shared_syncobj_list_entry);
		object->adapter_shared_syncobj_list_entry.next = NULL;
	}
	up_write(&adapter->shared_resource_list_lock);
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
	TRACE_DEBUG(1, "%s", __func__);
	dxglockorder_acquire(DXGLOCK_ADAPTER);
	down_write(&adapter->core_lock);
	if (adapter->adapter_state != DXGADAPTER_STATE_ACTIVE) {
		dxgadapter_release_lock_exclusive(adapter);
		return STATUS_DEVICE_REMOVED;
	}
	return 0;
}

void dxgadapter_acquire_lock_forced(struct dxgadapter *adapter)
{
	dxglockorder_acquire(DXGLOCK_ADAPTER);
	down_write(&adapter->core_lock);
}

void dxgadapter_release_lock_exclusive(struct dxgadapter *adapter)
{
	TRACE_DEBUG(1, "%s", __func__);
	up_write(&adapter->core_lock);
	dxglockorder_release(DXGLOCK_ADAPTER);
}

int dxgadapter_acquire_lock_shared(struct dxgadapter *adapter)
{
	TRACE_DEBUG(1, "%s", __func__);
	dxglockorder_acquire(DXGLOCK_ADAPTER);
	down_read(&adapter->core_lock);
	if (adapter->adapter_state == DXGADAPTER_STATE_ACTIVE)
		return 0;
	dxgadapter_release_lock_shared(adapter);
	return STATUS_DEVICE_REMOVED;
}

void dxgadapter_release_lock_shared(struct dxgadapter *adapter)
{
	TRACE_DEBUG(1, "dxgadapter_release_lock\n");
	up_read(&adapter->core_lock);
	dxglockorder_release(DXGLOCK_ADAPTER);
}

struct dxgdevice *dxgdevice_create(struct dxgadapter *adapter,
				   struct dxgprocess *process)
{
	struct dxgdevice *device = dxgmem_alloc(process, DXGMEM_DEVICE,
						sizeof(struct dxgdevice));
	if (device) {
		refcount_set(&device->refcount, 1);
		device->adapter = adapter;
		device->process = process;
		dxgadapter_acquire_reference(adapter);
		INIT_LIST_HEAD(&device->context_list_head);
		INIT_LIST_HEAD(&device->alloc_list_head);
		INIT_LIST_HEAD(&device->resource_list_head);
		init_rwsem(&device->device_lock);
		init_rwsem(&device->context_list_lock);
		init_rwsem(&device->alloc_list_lock);
		INIT_LIST_HEAD(&device->pqueue_list_head);
		INIT_LIST_HEAD(&device->syncobj_list_head);
		device->object_state = DXGOBJECTSTATE_CREATED;

		dxgprocess_adapter_add_device(process, adapter, device);
	}
	return device;
}

void dxgdevice_stop(struct dxgdevice *device)
{
	struct dxgallocation *alloc;
	struct dxgpagingqueue *pqueue;
	struct dxgsyncobject *syncobj;

	TRACE_DEBUG(1, "%s: DXGKDEBUG %p", __func__, device);
	dxgdevice_acquire_alloc_list_lock(device);
	list_for_each_entry(alloc, &device->alloc_list_head, alloc_list_entry) {
		dxgallocation_stop(alloc);
	}
	dxgdevice_release_alloc_list_lock(device);

	hmgrtable_lock(&device->process->handle_table, DXGLOCK_EXCL);
	list_for_each_entry(pqueue, &device->pqueue_list_head,
			    pqueue_list_entry) {
		dxgpagingqueue_stop(pqueue);
	}
	list_for_each_entry(syncobj, &device->syncobj_list_head,
			    syncobj_list_entry) {
		dxgsyncobject_stop(syncobj);
	}
	hmgrtable_unlock(&device->process->handle_table, DXGLOCK_EXCL);
	TRACE_DEBUG(1, "%s: end %p\n", __func__, device);
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
	d3dkmt_handle device_handle = 0;

	TRACE_DEBUG(1, "%s: %p\n", __func__, device);

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

		TRACE_DEBUG(1, "destroying allocations\n");
		list_for_each_entry_safe(alloc, tmp, &device->alloc_list_head,
					 alloc_list_entry) {
			dxgallocation_destroy(alloc);
		}
	}

	{
		struct dxgresource *resource;
		struct dxgresource *tmp;

		TRACE_DEBUG(1, "destroying resources\n");
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

		TRACE_DEBUG(1, "destroying contexts\n");
		dxgdevice_acquire_context_list_lock(device);
		list_for_each_entry_safe(context, tmp,
					 &device->context_list_head,
					 context_list_entry) {
			dxgcontext_destroy(process, context);
		}
		dxgdevice_release_context_list_lock(device);
	}

	{
		struct dxgpagingqueue *tmp;
		struct dxgpagingqueue *pqueue;

		TRACE_DEBUG(1, "destroying paging queues\n");
		list_for_each_entry_safe(pqueue, tmp, &device->pqueue_list_head,
					 pqueue_list_entry) {
			dxgpagingqueue_destroy(pqueue);
		}
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

	if (device_handle) {
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
		dxgadapter_release_reference(device->adapter);
	}

	up_write(&device->device_lock);

	dxgdevice_release_reference(device);
	TRACE_DEBUG(1, "dxgdevice_destroy_end\n");
}

int dxgdevice_acquire_lock_shared(struct dxgdevice *device)
{
	down_read(&device->device_lock);
	if (!dxgdevice_is_active(device)) {
		up_read(&device->device_lock);
		return STATUS_DEVICE_REMOVED;
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
	dxglockorder_acquire(DXGLOCK_DEVICE_CONTEXTLIST);
	down_write(&device->context_list_lock);
}

void dxgdevice_release_context_list_lock(struct dxgdevice *device)
{
	up_write(&device->context_list_lock);
	dxglockorder_release(DXGLOCK_DEVICE_CONTEXTLIST);
}

void dxgdevice_acquire_alloc_list_lock(struct dxgdevice *device)
{
	dxglockorder_acquire(DXGLOCK_DEVICE_ALLOCLIST);
	down_write(&device->alloc_list_lock);
}

void dxgdevice_release_alloc_list_lock(struct dxgdevice *device)
{
	dxglockorder_release(DXGLOCK_DEVICE_ALLOCLIST);
	up_write(&device->alloc_list_lock);
}

void dxgdevice_acquire_alloc_list_lock_shared(struct dxgdevice *device)
{
	dxglockorder_acquire(DXGLOCK_DEVICE_ALLOCLIST);
	down_read(&device->alloc_list_lock);
}

void dxgdevice_release_alloc_list_lock_shared(struct dxgdevice *device)
{
	dxglockorder_release(DXGLOCK_DEVICE_ALLOCLIST);
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
	dxgdevice_acquire_reference(device);
	alloc->owner.device = device;
	dxgdevice_release_alloc_list_lock(device);
}

void dxgdevice_remove_alloc(struct dxgdevice *device,
			    struct dxgallocation *alloc)
{
	if (alloc->alloc_list_entry.next) {
		list_del(&alloc->alloc_list_entry);
		alloc->alloc_list_entry.next = NULL;
		dxgdevice_release_reference(device);
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
	dxgdevice_acquire_reference(device);
	dxgdevice_release_alloc_list_lock(device);
}

void dxgdevice_remove_resource(struct dxgdevice *device,
			       struct dxgresource *res)
{
	if (res->resource_list_entry.next) {
		list_del(&res->resource_list_entry);
		res->resource_list_entry.next = NULL;
		dxgdevice_release_reference(device);
	}
}

struct dxgsharedresource *dxgsharedresource_create(struct dxgadapter *adapter)
{
	struct dxgsharedresource *resource = dxgmem_alloc(NULL,
							  DXGMEM_SHAREDRESOURCE,
							  sizeof(struct
								 dxgsharedresource));
	if (resource) {
		INIT_LIST_HEAD(&resource->resource_list_head);
		refcount_set(&resource->refcount, 1);
		dxgmutex_init(&resource->fd_mutex, DXGLOCK_FDMUTEX);
		resource->adapter = adapter;
	}
	return resource;
}

bool dxgsharedresource_acquire_reference(struct dxgsharedresource *resource)
{
	return refcount_inc_not_zero(&resource->refcount);
}

void dxgsharedresource_release_reference(struct dxgsharedresource *resource)
{
	if (!refcount_dec_and_test(&resource->refcount))
		return;
	if (resource->global_handle)
		hmgrtable_free_handle_safe(&dxgglobal->handle_table,
					   HMGRENTRY_TYPE_DXGSHAREDRESOURCE,
					   resource->global_handle);
	if (resource->runtime_private_data)
		dxgmem_free(NULL, DXGMEM_RUNTIMEPRIVATE,
			    resource->runtime_private_data);
	if (resource->resource_private_data)
		dxgmem_free(NULL, DXGMEM_RESOURCEPRIVATE,
			    resource->resource_private_data);
	if (resource->alloc_private_data_sizes)
		dxgmem_free(NULL, DXGMEM_ALLOCPRIVATE,
			    resource->alloc_private_data_sizes);
	if (resource->alloc_private_data)
		dxgmem_free(NULL, DXGMEM_ALLOCPRIVATE,
			    resource->alloc_private_data);
	dxgmem_free(NULL, DXGMEM_SHAREDRESOURCE, resource);
}

void dxgsharedresource_add_resource(struct dxgsharedresource *shared_resource,
				    struct dxgresource *resource)
{
	down_write(&shared_resource->adapter->shared_resource_list_lock);
	TRACE_DEBUG(1, "%s: %p %p", __func__, shared_resource, resource);
	list_add_tail(&resource->shared_resource_list_entry,
		      &shared_resource->resource_list_head);
	dxgsharedresource_acquire_reference(shared_resource);
	dxgresource_acquire_reference(resource);
	resource->shared_owner = shared_resource;
	up_write(&shared_resource->adapter->shared_resource_list_lock);
}

void dxgsharedresource_remove_resource(struct dxgsharedresource
				       *shared_resource,
				       struct dxgresource *resource)
{
	down_write(&shared_resource->adapter->shared_resource_list_lock);
	TRACE_DEBUG(1, "%s: %p %p", __func__, shared_resource, resource);
	if (resource->shared_resource_list_entry.next) {
		list_del(&resource->shared_resource_list_entry);
		resource->shared_resource_list_entry.next = NULL;
		dxgsharedresource_release_reference(shared_resource);
		resource->shared_owner = NULL;
		dxgresource_release_reference(resource);
	}
	up_write(&shared_resource->adapter->shared_resource_list_lock);
}

struct dxgresource *dxgresource_create(struct dxgdevice *device)
{
	struct dxgresource *resource = dxgmem_alloc(device->process,
						    DXGMEM_RESOURCE,
						    sizeof(struct dxgresource));
	if (resource) {
		refcount_set(&resource->refcount, 1);
		resource->device = device;
		resource->process = device->process;
		resource->object_state = DXGOBJECTSTATE_ACTIVE;
		dxgmutex_init(&resource->resource_mutex, DXGLOCK_RESOURCE);
		INIT_LIST_HEAD(&resource->alloc_list_head);
		dxgdevice_add_resource(device, resource);
	}
	return resource;
}

void dxgresource_free_handle(struct dxgresource *resource)
{
	struct dxgallocation *alloc;

	if (resource->handle_valid) {
		hmgrtable_free_handle_safe(&resource->device->process->
					   handle_table,
					   HMGRENTRY_TYPE_DXGRESOURCE,
					   resource->handle);
		resource->handle_valid = 0;
	}
	list_for_each_entry(alloc, &resource->alloc_list_head, alloc_list_entry) {
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
		if (resource->handle) {
			args.device = device->handle;
			args.resource = resource->handle;
			args.flags.assume_not_in_use = 1;
			dxgvmb_send_destroy_allocation(device->process,
						       device,
						       &device->adapter->
						       channel, &args, NULL);
			resource->handle = 0;
		}
		list_for_each_entry_safe(alloc, tmp, &resource->alloc_list_head,
					 alloc_list_entry) {
			dxgallocation_destroy(alloc);
		}
		dxgdevice_remove_resource(device, resource);
		if (resource->shared_owner) {
			dxgsharedresource_remove_resource(resource->
							  shared_owner,
							  resource);
			resource->shared_owner = NULL;
		}
	}
	dxgresource_release_reference(resource);
}

void dxgresource_acquire_reference(struct dxgresource *resource)
{
	refcount_inc_not_zero(&resource->refcount);
}

void dxgresource_release_reference(struct dxgresource *resource)
{
	if (refcount_dec_and_test(&resource->refcount))
		dxgmem_free(resource->process, DXGMEM_RESOURCE, resource);
}

bool dxgresource_is_active(struct dxgresource *resource)
{
	return resource->object_state == DXGOBJECTSTATE_ACTIVE;
}

int dxgresource_add_alloc(struct dxgresource *resource,
			  struct dxgallocation *alloc)
{
	int ret = STATUS_DEVICE_REMOVED;
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

bool dxgdevice_acquire_reference(struct dxgdevice *device)
{
	return refcount_inc_not_zero(&device->refcount);
}

void dxgdevice_release_reference(struct dxgdevice *device)
{
	if (refcount_dec_and_test(&device->refcount))
		dxgmem_free(device->process, DXGMEM_DEVICE, device);
}

void dxgdevice_add_paging_queue(struct dxgdevice *device,
				struct dxgpagingqueue *entry)
{
	dxgdevice_acquire_alloc_list_lock(device);
	list_add_tail(&entry->pqueue_list_entry, &device->pqueue_list_head);
	dxgdevice_release_alloc_list_lock(device);
}

void dxgdevice_remove_paging_queue(struct dxgpagingqueue *pqueue)
{
	struct dxgdevice *device = pqueue->device;

	dxgdevice_acquire_alloc_list_lock(device);
	if (pqueue->pqueue_list_entry.next) {
		list_del(&pqueue->pqueue_list_entry);
		pqueue->pqueue_list_entry.next = NULL;
	}
	dxgdevice_release_alloc_list_lock(device);
}

void dxgdevice_add_syncobj(struct dxgdevice *device,
			   struct dxgsyncobject *syncobj)
{
	dxgdevice_acquire_alloc_list_lock(device);
	list_add_tail(&syncobj->syncobj_list_entry, &device->syncobj_list_head);
	dxgsyncobject_acquire_reference(syncobj);
	dxgdevice_release_alloc_list_lock(device);
}

void dxgdevice_remove_syncobj(struct dxgsyncobject *entry)
{
	struct dxgdevice *device = entry->device;

	dxgdevice_acquire_alloc_list_lock(device);
	if (entry->syncobj_list_entry.next) {
		list_del(&entry->syncobj_list_entry);
		entry->syncobj_list_entry.next = NULL;
		dxgsyncobject_release_reference(entry);
	}
	dxgdevice_release_alloc_list_lock(device);
	dxgdevice_release_reference(device);
	entry->device = NULL;
}

struct dxgcontext *dxgcontext_create(struct dxgdevice *device)
{
	struct dxgcontext *context = dxgmem_alloc(device->process,
						  DXGMEM_CONTEXT,
						  sizeof(struct dxgcontext));
	if (context) {
		refcount_set(&context->refcount, 1);
		context->device = device;
		context->process = device->process;
		context->device_handle = device->handle;
		dxgdevice_acquire_reference(device);
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
	struct dxghwqueue *hwqueue;
	struct dxghwqueue *tmp;

	TRACE_DEBUG(1, "%s %p\n", __func__, context);
	context->object_state = DXGOBJECTSTATE_DESTROYED;
	if (context->device) {
		if (context->handle) {
			hmgrtable_free_handle_safe(&context->process->
						   handle_table,
						   HMGRENTRY_TYPE_DXGCONTEXT,
						   context->handle);
		}
		dxgdevice_remove_context(context->device, context);
		dxgdevice_release_reference(context->device);
	}
	list_for_each_entry_safe(hwqueue, tmp, &context->hwqueue_list_head,
				 hwqueue_list_entry) {
		dxghwqueue_destroy(process, hwqueue);
	}
	dxgcontext_release_reference(context);
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

bool dxgcontext_acquire_reference(struct dxgcontext *context)
{
	return refcount_inc_not_zero(&context->refcount);
}

void dxgcontext_release_reference(struct dxgcontext *context)
{
	if (refcount_dec_and_test(&context->refcount))
		dxgmem_free(context->process, DXGMEM_CONTEXT, context);
}

int dxgcontext_add_hwqueue(struct dxgcontext *context,
			   struct dxghwqueue *hwqueue)
{
	int ret = 0;

	down_write(&context->hwqueue_list_lock);
	if (dxgcontext_is_active(context))
		list_add_tail(&hwqueue->hwqueue_list_entry,
			      &context->hwqueue_list_head);
	else
		ret = STATUS_DEVICE_REMOVED;
	up_write(&context->hwqueue_list_lock);
	return ret;
}

void dxgcontext_remove_hwqueue(struct dxgcontext *context,
			       struct dxghwqueue *hwqueue)
{
	if (hwqueue->hwqueue_list_entry.next) {
		list_del(&hwqueue->hwqueue_list_entry);
		hwqueue->hwqueue_list_entry.next = NULL;
	}
}

void dxgcontext_remove_hwqueue_safe(struct dxgcontext *context,
				    struct dxghwqueue *hwqueue)
{
	down_write(&context->hwqueue_list_lock);
	dxgcontext_remove_hwqueue(context, hwqueue);
	up_write(&context->hwqueue_list_lock);
}

struct dxgallocation *dxgallocation_create(struct dxgprocess *process)
{
	struct dxgallocation *alloc = dxgmem_alloc(process, DXGMEM_ALLOCATION,
						   sizeof(struct
							  dxgallocation));
	if (alloc)
		alloc->process = process;
	return alloc;
}

void dxgallocation_stop(struct dxgallocation *alloc)
{
	if (alloc->pages) {
		release_pages(alloc->pages, alloc->num_pages);
		dxgmem_free(alloc->process, DXGMEM_ALLOCATION, alloc->pages);
		alloc->pages = NULL;
	}
	dxgprocess_ht_lock_exclusive_down(alloc->process);
	if (alloc->cpu_address_mapped) {
		dxg_unmap_iospace(alloc->cpu_address,
				  alloc->num_pages << PAGE_SHIFT);
		alloc->cpu_address_mapped = false;
		alloc->cpu_address = NULL;
	}
	dxgprocess_ht_lock_exclusive_up(alloc->process);
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
	if (alloc->alloc_handle && !alloc->resource_owner) {
		args.device = alloc->owner.device->handle;
		args.alloc_count = 1;
		args.flags.assume_not_in_use = 1;
		dxgvmb_send_destroy_allocation(process,
					       alloc->owner.device,
					       &alloc->owner.device->adapter->
					       channel, &args,
					       &alloc->alloc_handle);
	}
	if (alloc->gpadl) {
		TRACE_DEBUG(1, "Teardown gpadl %d", alloc->gpadl);
		vmbus_teardown_gpadl(dxgglobal_get_vmbus(), alloc->gpadl);
		TRACE_DEBUG(1, "Teardown gpadl end");
		alloc->gpadl = 0;
	}
	if (alloc->priv_drv_data)
		dxgmem_free(alloc->process, DXGMEM_ALLOCPRIVATE,
			    alloc->priv_drv_data);
	if (alloc->cpu_address_mapped)
		pr_err("Alloc IO space is mapped: %p", alloc);
	dxgmem_free(alloc->process, DXGMEM_ALLOCATION, alloc);
}

struct dxgpagingqueue *dxgpagingqueue_create(struct dxgdevice *device)
{
	struct dxgpagingqueue *pqueue;

	pqueue = dxgmem_alloc(device->process, DXGMEM_PQUEUE, sizeof(*pqueue));
	if (pqueue) {
		pqueue->device = device;
		pqueue->process = device->process;
		pqueue->device_handle = device->handle;
		dxgdevice_add_paging_queue(device, pqueue);
	}
	return pqueue;
}

void dxgpagingqueue_stop(struct dxgpagingqueue *pqueue)
{
	if (pqueue->mapped_address) {
		int ret = dxg_unmap_iospace(pqueue->mapped_address, PAGE_SIZE);

		UNUSED(ret);
		TRACE_DEBUG(1, "fence is unmapped %d %p",
			    ret, pqueue->mapped_address);
		pqueue->mapped_address = NULL;
	}
}

void dxgpagingqueue_destroy(struct dxgpagingqueue *pqueue)
{
	struct dxgprocess *process = pqueue->process;

	TRACE_DEBUG(1, "%s %p %x\n", __func__, pqueue, pqueue->handle);

	dxgpagingqueue_stop(pqueue);

	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	if (pqueue->handle) {
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGPAGINGQUEUE,
				      pqueue->handle);
		pqueue->handle = 0;
	}
	if (pqueue->syncobj_handle) {
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_MONITOREDFENCE,
				      pqueue->syncobj_handle);
		pqueue->syncobj_handle = 0;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);
	if (pqueue->device)
		dxgdevice_remove_paging_queue(pqueue);
	dxgmem_free(process, DXGMEM_PQUEUE, pqueue);
}

struct dxgprocess_adapter *dxgprocess_adapter_create(struct dxgprocess *process,
						     struct dxgadapter *adapter)
{
	struct dxgprocess_adapter *adapter_info = dxgmem_alloc(process,
							       DXGMEM_PROCESS_ADAPTER,
							       sizeof
							       (*adapter_info));
	if (adapter_info) {
		if (!dxgadapter_acquire_reference(adapter)) {
			pr_err("failed to acquire adapter reference");
			goto cleanup;
		}
		adapter_info->adapter = adapter;
		adapter_info->process = process;
		adapter_info->refcount = 1;
		dxgmutex_init(&adapter_info->device_list_mutex,
			      DXGLOCK_PROCESSADAPTERDEVICELIST);
		INIT_LIST_HEAD(&adapter_info->device_list_head);
		list_add_tail(&adapter_info->process_adapter_list_entry,
			      &process->process_adapter_list_head);
		dxgadapter_add_process(adapter, adapter_info);
	}
	return adapter_info;
cleanup:
	if (adapter_info)
		dxgmem_free(process, DXGMEM_PROCESS_ADAPTER, adapter_info);
	return NULL;
}

void dxgprocess_adapter_stop(struct dxgprocess_adapter *adapter_info)
{
	struct dxgdevice *device;

	dxgmutex_lock(&adapter_info->device_list_mutex);
	list_for_each_entry(device, &adapter_info->device_list_head,
			    device_list_entry) {
		dxgdevice_stop(device);
	}
	dxgmutex_unlock(&adapter_info->device_list_mutex);
}

void dxgprocess_adapter_destroy(struct dxgprocess_adapter *adapter_info)
{
	struct dxgdevice *device;

	dxgmutex_lock(&adapter_info->device_list_mutex);
	while (!list_empty(&adapter_info->device_list_head)) {
		device = list_first_entry(&adapter_info->device_list_head,
					  struct dxgdevice, device_list_entry);
		list_del(&device->device_list_entry);
		device->device_list_entry.next = NULL;
		dxgmutex_unlock(&adapter_info->device_list_mutex);
		dxgdevice_destroy(device);
		dxgmutex_lock(&adapter_info->device_list_mutex);
	}
	dxgmutex_unlock(&adapter_info->device_list_mutex);

	dxgadapter_remove_process(adapter_info);
	dxgadapter_release_reference(adapter_info->adapter);
	list_del(&adapter_info->process_adapter_list_entry);
	dxgmem_free(adapter_info->process, DXGMEM_PROCESS_ADAPTER,
		    adapter_info);
}

/*
 * Must be called when dxgglobal::process_adapter_mutex is held
 */
void dxgprocess_adapter_release(struct dxgprocess_adapter *adapter_info)
{
	TRACE_DEBUG(1, "%s %p %d",
		    __func__, adapter_info, adapter_info->refcount);
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
		pr_err("failed to find process adapter info\n");
		ret = STATUS_INVALID_PARAMETER;
		goto cleanup;
	}
	dxgmutex_lock(&adapter_info->device_list_mutex);
	list_add_tail(&device->device_list_entry,
		      &adapter_info->device_list_head);
	device->adapter_info = adapter_info;
	dxgmutex_unlock(&adapter_info->device_list_mutex);

cleanup:

	dxgglobal_release_process_adapter_lock();
	return ret;
}

void dxgprocess_adapter_remove_device(struct dxgdevice *device)
{
	TRACE_DEBUG(1, "%s %p\n", __func__, device);
	dxgmutex_lock(&device->adapter_info->device_list_mutex);
	if (device->device_list_entry.next) {
		list_del(&device->device_list_entry);
		device->device_list_entry.next = NULL;
	}
	dxgmutex_unlock(&device->adapter_info->device_list_mutex);
}

struct dxgsharedsyncobject *dxgsharedsyncobj_create(struct dxgadapter *adapter,
						    struct dxgsyncobject *so)
{
	struct dxgsharedsyncobject *syncobj;

	syncobj = dxgmem_alloc(NULL, DXGMEM_SHAREDSYNCOBJ, sizeof(*syncobj));
	if (syncobj) {
		refcount_set(&syncobj->refcount, 1);
		INIT_LIST_HEAD(&syncobj->shared_syncobj_list_head);
		syncobj->adapter = adapter;
		syncobj->type = so->type;
		syncobj->monitored_fence = so->monitored_fence;
		dxgadapter_add_shared_syncobj(adapter, syncobj);
		dxgadapter_acquire_reference(adapter);
		init_rwsem(&syncobj->syncobj_list_lock);
		dxgmutex_init(&syncobj->fd_mutex, DXGLOCK_FDMUTEX);
	}
	return syncobj;
}

bool dxgsharedsyncobj_acquire_reference(struct dxgsharedsyncobject *syncobj)
{
	TRACE_DEBUG(1, "%s 0x%p %d", __func__, syncobj,
		    refcount_read(&syncobj->refcount));
	return refcount_inc_not_zero(&syncobj->refcount);
}

void dxgsharedsyncobj_release_reference(struct dxgsharedsyncobject *syncobj)
{
	TRACE_DEBUG(1, "%s 0x%p %d", __func__, syncobj,
		    refcount_read(&syncobj->refcount));
	if (refcount_dec_and_test(&syncobj->refcount)) {
		TRACE_DEBUG(1, "Destroying");
		if (syncobj->global_shared_handle) {
			hmgrtable_lock(&dxgglobal->handle_table, DXGLOCK_EXCL);
			hmgrtable_free_handle(&dxgglobal->handle_table,
					      HMGRENTRY_TYPE_DXGSYNCOBJECT,
					      syncobj->global_shared_handle);
			hmgrtable_unlock(&dxgglobal->handle_table,
					 DXGLOCK_EXCL);
		}
		if (syncobj->adapter) {
			dxgadapter_remove_shared_syncobj(syncobj->adapter,
							 syncobj);
			dxgadapter_release_reference(syncobj->adapter);
		}
		dxgmem_free(NULL, DXGMEM_SHAREDSYNCOBJ, syncobj);
	}
	TRACE_DEBUG(1, "%s end", __func__);
}

void dxgsharedsyncobj_add_syncobj(struct dxgsharedsyncobject *shared,
				  struct dxgsyncobject *syncobj)
{
	TRACE_DEBUG(1, "%s 0x%p 0x%p", __func__, shared, syncobj);
	dxgsharedsyncobj_acquire_reference(shared);
	down_write(&shared->syncobj_list_lock);
	list_add(&syncobj->shared_syncobj_list_entry,
		 &shared->shared_syncobj_list_head);
	syncobj->shared_owner = shared;
	up_write(&shared->syncobj_list_lock);
}

void dxgsharedsyncobj_remove_syncobj(struct dxgsharedsyncobject *shared,
				     struct dxgsyncobject *syncobj)
{
	TRACE_DEBUG(1, "%s 0x%p", __func__, shared);
	down_write(&shared->syncobj_list_lock);
	list_del(&syncobj->shared_syncobj_list_entry);
	up_write(&shared->syncobj_list_lock);
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

	syncobj = dxgmem_alloc(process, DXGMEM_SYNCOBJ, sizeof(*syncobj));
	if (syncobj == NULL)
		goto cleanup;
	syncobj->type = type;
	syncobj->process = process;
	switch (type) {
	case D3DDDI_MONITORED_FENCE:
	case D3DDDI_PERIODIC_MONITORED_FENCE:
		syncobj->monitored_fence = 1;
		break;
	case D3DDDI_CPU_NOTIFICATION:
		syncobj->cpu_event = 1;
		syncobj->host_event = dxgmem_alloc(process, DXGMEM_HOSTEVENT,
						   sizeof(struct dxghostevent));
		if (syncobj->host_event == NULL)
			goto cleanup;
		break;
	default:
		break;
	}
	if (flags.shared) {
		syncobj->shared = 1;
		if (flags.nt_security_sharing)
			syncobj->shared_nt = 1;
	}

	refcount_set(&syncobj->refcount, 1);

	if (syncobj->monitored_fence) {
		syncobj->device = device;
		syncobj->device_handle = device->handle;
		dxgdevice_acquire_reference(device);
		dxgdevice_add_syncobj(device, syncobj);
	} else {
		dxgadapter_add_syncobj(adapter, syncobj);
	}
	syncobj->adapter = adapter;
	dxgadapter_acquire_reference(adapter);

	TRACE_DEBUG(1, "%s 0x%p\n", __func__, syncobj);
	return syncobj;
cleanup:
	if (syncobj->host_event)
		dxgmem_free(process, DXGMEM_HOSTEVENT, syncobj->host_event);
	if (syncobj)
		dxgmem_free(process, DXGMEM_SYNCOBJ, syncobj);
	return NULL;
}

void dxgsyncobject_destroy(struct dxgprocess *process,
			   struct dxgsyncobject *syncobj)
{
	int destroyed;

	TRACE_DEBUG(1, "%s 0x%p", __func__, syncobj);

	dxgsyncobject_stop(syncobj);

	destroyed = test_and_set_bit(0, &syncobj->flags);
	if (!destroyed) {
		TRACE_DEBUG(1, "Deleting handle: %x", syncobj->handle);
		hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
		if (syncobj->handle) {
			hmgrtable_free_handle(&process->handle_table,
					      HMGRENTRY_TYPE_DXGSYNCOBJECT,
					      syncobj->handle);
			syncobj->handle = 0;
			dxgsyncobject_release_reference(syncobj);
		}
		hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

		if (syncobj->cpu_event) {
			if (syncobj->host_event->cpu_event) {
				eventfd_ctx_put(syncobj->host_event->cpu_event);
				if (syncobj->host_event->event_id) {
					dxgglobal_remove_host_event(syncobj->
								    host_event);
				}
				syncobj->host_event->cpu_event = NULL;
			}
		}
		if (syncobj->monitored_fence)
			dxgdevice_remove_syncobj(syncobj);
		else
			dxgadapter_remove_syncobj(syncobj);
		if (syncobj->adapter) {
			dxgadapter_release_reference(syncobj->adapter);
			syncobj->adapter = NULL;
		}
	}
	dxgsyncobject_release_reference(syncobj);

	TRACE_DEBUG(1, "%s end", __func__);
}

void dxgsyncobject_stop(struct dxgsyncobject *syncobj)
{
	int stopped = test_and_set_bit(1, &syncobj->flags);

	TRACE_DEBUG(1, "%s", __func__);
	if (!stopped) {
		TRACE_DEBUG(1, "stopping");
		if (syncobj->monitored_fence) {
			if (syncobj->mapped_address) {
				int ret =
				    dxg_unmap_iospace(syncobj->mapped_address,
						      PAGE_SIZE);

				(void)ret;
				TRACE_DEBUG(1, "fence is unmapped %d %p\n",
					    ret, syncobj->mapped_address);
				syncobj->mapped_address = NULL;
			}
		}
	}
	TRACE_DEBUG(1, "%s end", __func__);
}

void dxgsyncobject_acquire_reference(struct dxgsyncobject *syncobj)
{
	TRACE_DEBUG(1, "%s 0x%p %d",
		    __func__, syncobj, refcount_read(&syncobj->refcount));
	refcount_inc_not_zero(&syncobj->refcount);
}

void dxgsyncobject_release_reference(struct dxgsyncobject *syncobj)
{
	TRACE_DEBUG(1, "%s 0x%p %d",
		    __func__, syncobj, refcount_read(&syncobj->refcount));
	if (refcount_dec_and_test(&syncobj->refcount)) {
		if (syncobj->shared_owner) {
			dxgsharedsyncobj_remove_syncobj(syncobj->shared_owner,
							syncobj);
			dxgsharedsyncobj_release_reference(syncobj->
							   shared_owner);
		}
		if (syncobj->host_event)
			dxgmem_free(syncobj->process, DXGMEM_HOSTEVENT,
				    syncobj->host_event);
		dxgmem_free(syncobj->process, DXGMEM_SYNCOBJ, syncobj);
	}
}

struct dxghwqueue *dxghwqueue_create(struct dxgcontext *context)
{
	struct dxgprocess *process = context->device->process;
	struct dxghwqueue *hwqueue =
	    dxgmem_alloc(process, DXGMEM_HWQUEUE, sizeof(*hwqueue));
	if (hwqueue) {
		refcount_set(&hwqueue->refcount, 1);
		hwqueue->context = context;
		hwqueue->process = process;
		hwqueue->device_handle = context->device->handle;
		if (dxgcontext_add_hwqueue(context, hwqueue)) {
			dxghwqueue_release_reference(hwqueue);
			hwqueue = NULL;
		} else {
			dxgcontext_acquire_reference(context);
		}
	}
	return hwqueue;
}

void dxghwqueue_destroy(struct dxgprocess *process, struct dxghwqueue *hwqueue)
{
	TRACE_DEBUG(1, "%s %p\n", __func__, hwqueue);
	hmgrtable_lock(&process->handle_table, DXGLOCK_EXCL);
	if (hwqueue->handle) {
		hmgrtable_free_handle(&process->handle_table,
				      HMGRENTRY_TYPE_DXGHWQUEUE,
				      hwqueue->handle);
		hwqueue->handle = 0;
	}
	hmgrtable_unlock(&process->handle_table, DXGLOCK_EXCL);

	if (hwqueue->progress_fence_mapped_address) {
		dxg_unmap_iospace(hwqueue->progress_fence_mapped_address,
				  PAGE_SIZE);
		hwqueue->progress_fence_mapped_address = NULL;
	}
	dxgcontext_remove_hwqueue_safe(hwqueue->context, hwqueue);

	dxgcontext_release_reference(hwqueue->context);
	dxghwqueue_release_reference(hwqueue);
}

bool dxghwqueue_acquire_reference(struct dxghwqueue *hwqueue)
{
	return refcount_inc_not_zero(&hwqueue->refcount);
}

void dxghwqueue_release_reference(struct dxghwqueue *hwqueue)
{
	if (refcount_dec_and_test(&hwqueue->refcount))
		dxgmem_free(hwqueue->process, DXGMEM_HWQUEUE, hwqueue);
}
