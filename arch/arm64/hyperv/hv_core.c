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
#include <linux/log2.h>
#include <linux/version.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/hyperv.h>
#include <linux/arm-smccc.h>
#include <asm-generic/bug.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>


/*
 * Functions for allocating and freeing memory with size and
 * alignment HV_HYP_PAGE_SIZE. These functions are needed because
 * the guest page size may not be the same as the Hyper-V page
 * size. We depend upon kmalloc() aligning power-of-two size
 * allocations to the allocation size boundary, so that the
 * allocated memory appears to Hyper-V as a page of the size
 * it expects.
 *
 * These functions are used by arm64 specific code as well as
 * arch independent Hyper-V drivers.
 */

void *hv_alloc_hyperv_page(void)
{
	BUILD_BUG_ON(PAGE_SIZE <  HV_HYP_PAGE_SIZE);

	if (PAGE_SIZE == HV_HYP_PAGE_SIZE)
		return (void *)__get_free_page(GFP_KERNEL);
	else
		return kmalloc(HV_HYP_PAGE_SIZE, GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(hv_alloc_hyperv_page);

void *hv_alloc_hyperv_zeroed_page(void)
{
	if (PAGE_SIZE == HV_HYP_PAGE_SIZE)
		return (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	else
		return kzalloc(HV_HYP_PAGE_SIZE, GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(hv_alloc_hyperv_zeroed_page);

void hv_free_hyperv_page(unsigned long addr)
{
	if (PAGE_SIZE == HV_HYP_PAGE_SIZE)
		free_page(addr);
	else
		kfree((void *)addr);
}
EXPORT_SYMBOL_GPL(hv_free_hyperv_page);


/*
 * hv_do_hypercall- Invoke the specified hypercall
 */
u64 hv_do_hypercall(u64 control, void *input, void *output)
{
	u64 input_address;
	u64 output_address;
	struct arm_smccc_res res;

	input_address = input ? virt_to_phys(input) : 0;
	output_address = output ? virt_to_phys(output) : 0;

	arm_smccc_1_1_hvc(HV_FUNC_ID, control,
			  input_address, output_address, &res);
	return res.a0;
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
	struct arm_smccc_res res;

	control = (u64)code | HV_HYPERCALL_FAST_BIT;

	arm_smccc_1_1_hvc(HV_FUNC_ID, control, input, &res);
	return res.a0;
}
EXPORT_SYMBOL_GPL(hv_do_fast_hypercall8);


/*
 * Set a single VP register to a 64-bit value.
 */
void hv_set_vpreg(u32 msr, u64 value)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_hvc(
		HV_FUNC_ID,
		HVCALL_SET_VP_REGISTERS | HV_HYPERCALL_FAST_BIT |
			HV_HYPERCALL_REP_COMP_1,
		HV_PARTITION_ID_SELF,
		HV_VP_INDEX_SELF,
		msr,
		0,
		value,
		0,
		&res);

	/*
	 * Something is fundamentally broken in the hypervisor if
	 * setting a VP register fails. There's really no way to
	 * continue as a guest VM, so panic.
	 */
	BUG_ON((res.a0 & HV_HYPERCALL_RESULT_MASK) != HV_STATUS_SUCCESS);
}
EXPORT_SYMBOL_GPL(hv_set_vpreg);

/*
 * Get the value of a single VP register.  One version
 * returns just 64 bits and another returns the full 128 bits.
 * The two versions are separate to avoid complicating the
 * calling sequence for the more frequently used 64 bit version.
 */

static void __hv_get_vpreg_128(u32 msr, struct hv_get_vp_registers_output *res)
{
	struct hv_get_vp_registers_input	*input;
	u64					status;

	/*
	 * Allocate a power of 2 size so alignment to that size is
	 * guaranteed, since the hypercall input area must not cross
	 * a page boundary.
	 */

	input = kzalloc(roundup_pow_of_two(sizeof(input->header) +
				sizeof(input->element[0])), GFP_ATOMIC);

	input->header.partitionid = HV_PARTITION_ID_SELF;
	input->header.vpindex = HV_VP_INDEX_SELF;
	input->header.inputvtl = 0;
	input->element[0].name0 = msr;
	input->element[0].name1 = 0;


	status = hv_do_hypercall(
		HVCALL_GET_VP_REGISTERS | HV_HYPERCALL_REP_COMP_1,
		input, res);

	/*
	 * Something is fundamentally broken in the hypervisor if
	 * getting a VP register fails. There's really no way to
	 * continue as a guest VM, so panic.
	 */
	BUG_ON((status & HV_HYPERCALL_RESULT_MASK) != HV_STATUS_SUCCESS);

	kfree(input);
}

u64 hv_get_vpreg(u32 msr)
{
	struct hv_get_vp_registers_output	*output;
	u64					result;

	/*
	 * Allocate a power of 2 size so alignment to that size is
	 * guaranteed, since the hypercall output area must not cross
	 * a page boundary.
	 */
	output = kmalloc(roundup_pow_of_two(sizeof(*output)), GFP_ATOMIC);

	__hv_get_vpreg_128(msr, output);

	result = output->as64.low;
	kfree(output);
	return result;
}
EXPORT_SYMBOL_GPL(hv_get_vpreg);

void hv_get_vpreg_128(u32 msr, struct hv_get_vp_registers_output *res)
{
	struct hv_get_vp_registers_output	*output;

	/*
	 * Allocate a power of 2 size so alignment to that size is
	 * guaranteed, since the hypercall output area must not cross
	 * a page boundary.
	 */
	output = kmalloc(roundup_pow_of_two(sizeof(*output)), GFP_ATOMIC);

	__hv_get_vpreg_128(msr, output);

	res->as64.low = output->as64.low;
	res->as64.high = output->as64.high;
	kfree(output);
}
EXPORT_SYMBOL_GPL(hv_get_vpreg_128);
