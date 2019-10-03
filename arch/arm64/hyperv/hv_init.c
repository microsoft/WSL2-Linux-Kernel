// SPDX-License-Identifier: GPL-2.0

/*
 * Initialization of the interface with Microsoft's Hyper-V hypervisor,
 * and various low level utility routines for interacting with Hyper-V.
 *
 * Copyright (C) 2019, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */


#include <linux/types.h>
#include <linux/version.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/hyperv.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/string.h>
#include <asm-generic/bug.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>


/*
 * Functions for allocating and freeing memory with size and
 * alignment HV_HYP_PAGE_SIZE. These functions are needed because
 * the guest page size may not be the same as the Hyper-V page
 * size. And while kalloc() could allocate the memory, it does not
 * guarantee the required alignment. So a separate small memory
 * allocator is needed.  The free function is rarely used, so it
 * does not try to combine freed pages into larger chunks.
 *
 * These functions are used by arm64 specific code as well as
 * arch independent Hyper-V drivers.
 */

static DEFINE_SPINLOCK(free_list_lock);
static struct list_head free_list = LIST_HEAD_INIT(free_list);

void *hv_alloc_hyperv_page(void)
{
	int i;
	struct list_head *hv_page;
	unsigned long addr;

	BUILD_BUG_ON(HV_HYP_PAGE_SIZE > PAGE_SIZE);

	spin_lock(&free_list_lock);
	if (list_empty(&free_list)) {
		spin_unlock(&free_list_lock);
		addr = __get_free_page(GFP_KERNEL);
		spin_lock(&free_list_lock);
		for (i = 0; i < PAGE_SIZE; i += HV_HYP_PAGE_SIZE)
			list_add_tail((struct list_head *)(addr + i),
					&free_list);
	}
	hv_page = free_list.next;
	list_del(hv_page);
	spin_unlock(&free_list_lock);

	return hv_page;
}
EXPORT_SYMBOL_GPL(hv_alloc_hyperv_page);

void *hv_alloc_hyperv_zeroed_page(void)
{
	void *memp;

	memp = hv_alloc_hyperv_page();
	memset(memp, 0, HV_HYP_PAGE_SIZE);

	return memp;
}
EXPORT_SYMBOL_GPL(hv_alloc_hyperv_zeroed_page);


void hv_free_hyperv_page(unsigned long addr)
{
	if (!addr)
		return;
	spin_lock(&free_list_lock);
	list_add((struct list_head *)addr, &free_list);
	spin_unlock(&free_list_lock);
}
EXPORT_SYMBOL_GPL(hv_free_hyperv_page);


/*
 * hv_do_hypercall- Invoke the specified hypercall
 */
u64 hv_do_hypercall(u64 control, void *input, void *output)
{
	u64 input_address;
	u64 output_address;

	input_address = input ? virt_to_phys(input) : 0;
	output_address = output ? virt_to_phys(output) : 0;
	return hv_do_hvc(control, input_address, output_address);
}
EXPORT_SYMBOL_GPL(hv_do_hypercall);

/*
 * hv_do_fast_hypercall8 -- Invoke the specified hypercall
 * with arguments in registers instead of physical memory.
 * Avoids the overhead of virt_to_phys for simple hypercalls.
 */

u64 hv_do_fast_hypercall8(u16 code, u64 input)
{
	u64 control;

	control = (u64)code | HV_HYPERCALL_FAST_BIT;
	return hv_do_hvc(control, input);
}
EXPORT_SYMBOL_GPL(hv_do_fast_hypercall8);


/*
 * Set a single VP register to a 64-bit value.
 */
void hv_set_vpreg(u32 msr, u64 value)
{
	union hv_hypercall_status status;

	status.as_uint64 = hv_do_hvc(
		HVCALL_SET_VP_REGISTERS | HV_HYPERCALL_FAST_BIT |
			HV_HYPERCALL_REP_COUNT_1,
		HV_PARTITION_ID_SELF,
		HV_VP_INDEX_SELF,
		msr,
		0,
		value,
		0);

	/*
	 * Something is fundamentally broken in the hypervisor if
	 * setting a VP register fails. There's really no way to
	 * continue as a guest VM, so panic.
	 */
	BUG_ON(status.status != HV_STATUS_SUCCESS);
}
EXPORT_SYMBOL_GPL(hv_set_vpreg);


/*
 * Get the value of a single VP register, and only the low order 64 bits.
 */
u64 hv_get_vpreg(u32 msr)
{
	union hv_hypercall_status status;
	struct hv_get_vp_register_output output;

	status.as_uint64 = hv_do_hvc_fast_get(
		HVCALL_GET_VP_REGISTERS | HV_HYPERCALL_FAST_BIT |
			HV_HYPERCALL_REP_COUNT_1,
		HV_PARTITION_ID_SELF,
		HV_VP_INDEX_SELF,
		msr,
		&output);

	/*
	 * Something is fundamentally broken in the hypervisor if
	 * getting a VP register fails. There's really no way to
	 * continue as a guest VM, so panic.
	 */
	BUG_ON(status.status != HV_STATUS_SUCCESS);

	return output.registervaluelow;
}
EXPORT_SYMBOL_GPL(hv_get_vpreg);

/*
 * Get the value of a single VP register that is 128 bits in size.  This is a
 * separate call in order to avoid complicating the calling sequence for
 * the much more frequently used 64-bit version.
 */
void hv_get_vpreg_128(u32 msr, struct hv_get_vp_register_output *result)
{
	union hv_hypercall_status status;

	status.as_uint64 = hv_do_hvc_fast_get(
		HVCALL_GET_VP_REGISTERS | HV_HYPERCALL_FAST_BIT |
			HV_HYPERCALL_REP_COUNT_1,
		HV_PARTITION_ID_SELF,
		HV_VP_INDEX_SELF,
		msr,
		result);

	/*
	 * Something is fundamentally broken in the hypervisor if
	 * getting a VP register fails. There's really no way to
	 * continue as a guest VM, so panic.
	 */
	BUG_ON(status.status != HV_STATUS_SUCCESS);

	return;

}
EXPORT_SYMBOL_GPL(hv_get_vpreg_128);

void hyperv_report_panic(struct pt_regs *regs, long err)
{
	static bool panic_reported;
	u64 guest_id;

	/*
	 * We prefer to report panic on 'die' chain as we have proper
	 * registers to report, but if we miss it (e.g. on BUG()) we need
	 * to report it on 'panic'.
	 */
	if (panic_reported)
		return;
	panic_reported = true;

	guest_id = hv_get_vpreg(HV_REGISTER_GUEST_OSID);

	/*
	 * Hyper-V provides the ability to store only 5 values.
	 * Pick the passed in error value, the guest_id, and the PC.
	 * The first two general registers are added arbitrarily.
	 */
	hv_set_vpreg(HV_REGISTER_CRASH_P0, err);
	hv_set_vpreg(HV_REGISTER_CRASH_P1, guest_id);
	hv_set_vpreg(HV_REGISTER_CRASH_P2, regs->pc);
	hv_set_vpreg(HV_REGISTER_CRASH_P3, regs->regs[0]);
	hv_set_vpreg(HV_REGISTER_CRASH_P4, regs->regs[1]);

	/*
	 * Let Hyper-V know there is crash data available
	 */
	hv_set_vpreg(HV_REGISTER_CRASH_CTL, HV_CRASH_CTL_CRASH_NOTIFY);
}
EXPORT_SYMBOL_GPL(hyperv_report_panic);

/*
 * hyperv_report_panic_msg - report panic message to Hyper-V
 * @pa: physical address of the panic page containing the message
 * @size: size of the message in the page
 */
void hyperv_report_panic_msg(phys_addr_t pa, size_t size)
{
	/*
	 * P3 to contain the physical address of the panic page & P4 to
	 * contain the size of the panic data in that page. Rest of the
	 * registers are no-op when the NOTIFY_MSG flag is set.
	 */
	hv_set_vpreg(HV_REGISTER_CRASH_P0, 0);
	hv_set_vpreg(HV_REGISTER_CRASH_P1, 0);
	hv_set_vpreg(HV_REGISTER_CRASH_P2, 0);
	hv_set_vpreg(HV_REGISTER_CRASH_P3, pa);
	hv_set_vpreg(HV_REGISTER_CRASH_P4, size);

	/*
	 * Let Hyper-V know there is crash data available along with
	 * the panic message.
	 */
	hv_set_vpreg(HV_REGISTER_CRASH_CTL,
	       (HV_CRASH_CTL_CRASH_NOTIFY | HV_CRASH_CTL_CRASH_NOTIFY_MSG));
}
EXPORT_SYMBOL_GPL(hyperv_report_panic_msg);
