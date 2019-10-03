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
#include <asm-generic/bug.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>

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
