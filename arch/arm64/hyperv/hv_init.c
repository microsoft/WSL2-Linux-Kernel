// SPDX-License-Identifier: GPL-2.0

/*
 * Initialization of the interface with Microsoft's Hyper-V hypervisor,
 * and various low level utility routines for interacting with Hyper-V.
 *
 * Copyright (C) 2018, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 */


#include <linux/types.h>
#include <linux/version.h>
#include <linux/export.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/clocksource.h>
#include <linux/sched_clock.h>
#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/hyperv.h>
#include <linux/slab.h>
#include <linux/cpuhotplug.h>
#include <linux/psci.h>
#include <asm-generic/bug.h>
#include <asm/hypervisor.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>
#include <asm/sysreg.h>
#include <clocksource/arm_arch_timer.h>

static bool	hyperv_initialized;
struct		ms_hyperv_info ms_hyperv;
EXPORT_SYMBOL_GPL(ms_hyperv);

static struct ms_hyperv_tsc_page *tsc_pg;

struct ms_hyperv_tsc_page *hv_get_tsc_page(void)
{
	return tsc_pg;
}
EXPORT_SYMBOL_GPL(hv_get_tsc_page);

static u64 read_hv_sched_clock_tsc(void)
{
	u64 current_tick = hv_read_tsc_page(tsc_pg);

	if (current_tick == U64_MAX)
		current_tick = hv_get_vpreg(HV_REGISTER_TIME_REFCOUNT);

	return current_tick;
}

static u64 read_hv_clock_tsc(struct clocksource *arg)
{
	u64 current_tick = hv_read_tsc_page(tsc_pg);

	if (current_tick == U64_MAX)
		current_tick = hv_get_vpreg(HV_REGISTER_TIME_REFCOUNT);

	return current_tick;
}

static struct clocksource hyperv_cs_tsc = {
		.name		= "hyperv_clocksource_tsc_page",
		.rating		= 400,
		.read		= read_hv_clock_tsc,
		.mask		= CLOCKSOURCE_MASK(64),
		.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

static u64 read_hv_sched_clock_msr(void)
{
	return hv_get_vpreg(HV_REGISTER_TIME_REFCOUNT);
}

static u64 read_hv_clock_msr(struct clocksource *arg)
{
	return hv_get_vpreg(HV_REGISTER_TIME_REFCOUNT);
}

static struct clocksource hyperv_cs_msr = {
	.name		= "hyperv_clocksource_msr",
	.rating		= 400,
	.read		= read_hv_clock_msr,
	.mask		= CLOCKSOURCE_MASK(64),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

struct clocksource *hyperv_cs;
EXPORT_SYMBOL_GPL(hyperv_cs);

u32 *hv_vp_index;
EXPORT_SYMBOL_GPL(hv_vp_index);

u32 hv_max_vp_index;

static int hv_cpu_init(unsigned int cpu)
{
	u64 msr_vp_index;

	hv_get_vp_index(msr_vp_index);

	hv_vp_index[smp_processor_id()] = msr_vp_index;

	if (msr_vp_index > hv_max_vp_index)
		hv_max_vp_index = msr_vp_index;

	return 0;
}

/*
 * This function is invoked via the ACPI clocksource probe mechanism. We
 * don't actually use any values from the ACPI GTDT table, but we set up
 * the Hyper-V synthetic clocksource and do other initialization for
 * interacting with Hyper-V the first time.  Using early_initcall to invoke
 * this function is too late because interrupts are already enabled at that
 * point, and sched_clock_register must run before interrupts are enabled.
 *
 * 1. Setup the guest ID.
 * 2. Get features and hints info from Hyper-V
 * 3. Setup per-cpu VP indices.
 * 4. Register Hyper-V specific clocksource.
 * 5. Register the scheduler clock.
 */

static int __init hyperv_init(struct acpi_table_header *table)
{
	struct hv_get_vp_register_output result;
	u32	a, b, c, d;
	u64	guest_id;
	int	i;

	/*
	 * If we're in a VM on Hyper-V, the ACPI hypervisor_id field will
	 * have the string "MsHyperV".
	 */
	if (strncmp((char *)&acpi_gbl_FADT.hypervisor_id, "MsHyperV", 8))
		return 1;

	/* Setup the guest ID */
	guest_id = generate_guest_id(0, LINUX_VERSION_CODE, 0);
	hv_set_vpreg(HV_REGISTER_GUEST_OSID, guest_id);

	/* Get the features and hints from Hyper-V */
	hv_get_vpreg_128(HV_REGISTER_PRIVILEGES_AND_FEATURES, &result);
	ms_hyperv.features = lower_32_bits(result.registervaluelow);
	ms_hyperv.misc_features = upper_32_bits(result.registervaluehigh);

	hv_get_vpreg_128(HV_REGISTER_FEATURES, &result);
	ms_hyperv.hints = lower_32_bits(result.registervaluelow);

	pr_info("Hyper-V: Features 0x%x, hints 0x%x\n",
		ms_hyperv.features, ms_hyperv.hints);

	/*
	 * Direct mode is the only option for STIMERs provided Hyper-V
	 * on ARM64, so Hyper-V doesn't actually set the flag.  But add the
	 * flag so the architecture independent code in drivers/hv/hv.c
	 * will correctly use that mode.
	 */
	ms_hyperv.misc_features |= HV_STIMER_DIRECT_MODE_AVAILABLE;

	/*
	 * Hyper-V on ARM64 doesn't support AutoEOI.  Add the hint
	 * that tells architecture independent code not to use this
	 * feature.
	 */
	ms_hyperv.hints |= HV_DEPRECATING_AEOI_RECOMMENDED;

	/* Get information about the Hyper-V host version */
	hv_get_vpreg_128(HV_REGISTER_HYPERVISOR_VERSION, &result);
	a = lower_32_bits(result.registervaluelow);
	b = upper_32_bits(result.registervaluelow);
	c = lower_32_bits(result.registervaluehigh);
	d = upper_32_bits(result.registervaluehigh);
	pr_info("Hyper-V: Host Build %d.%d.%d.%d-%d-%d\n",
		b >> 16, b & 0xFFFF, a, d & 0xFFFFFF, c, d >> 24);

	/* Allocate percpu VP index */
	hv_vp_index = kmalloc_array(num_possible_cpus(), sizeof(*hv_vp_index),
				    GFP_KERNEL);
	if (!hv_vp_index)
		return 1;

	for (i = 0; i < num_possible_cpus(); i++)
		hv_vp_index[i] = VP_INVAL;

	if (cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "arm64/hyperv_init:online",
			      hv_cpu_init, NULL) < 0)
		goto free_vp_index;

	/*
	 * Try to set up what Hyper-V calls the "TSC reference page", which
	 * uses the ARM Generic Timer virtual counter with some scaling
	 * information to provide a fast and stable guest VM clocksource.
	 * If the TSC reference page can't be set up, fall back to reading
	 * the guest clock provided by Hyper-V's synthetic reference time
	 * register.
	 */
	if (ms_hyperv.features & HV_MSR_REFERENCE_TSC_AVAILABLE) {

		u64		tsc_msr;
		phys_addr_t	phys_addr;

		tsc_pg = __vmalloc(HV_HYP_PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL);
		if (tsc_pg) {
			phys_addr = page_to_phys(vmalloc_to_page(tsc_pg));
			tsc_msr = hv_get_vpreg(HV_REGISTER_REFERENCE_TSC);
			tsc_msr &= GENMASK_ULL(11, 0);
			tsc_msr = tsc_msr | 0x1 | (u64)phys_addr;
			hv_set_vpreg(HV_REGISTER_REFERENCE_TSC, tsc_msr);
			hyperv_cs = &hyperv_cs_tsc;
			sched_clock_register(read_hv_sched_clock_tsc,
						64, HV_CLOCK_HZ);
		}
	}

	if (!hyperv_cs &&
	    (ms_hyperv.features & HV_MSR_TIME_REF_COUNT_AVAILABLE)) {
		hyperv_cs = &hyperv_cs_msr;
		sched_clock_register(read_hv_sched_clock_msr,
						64, HV_CLOCK_HZ);
	}

	if (hyperv_cs) {
		hyperv_cs->archdata.vdso_direct = false;
		clocksource_register_hz(hyperv_cs, HV_CLOCK_HZ);
	}

	hyperv_initialized = true;
	return 0;

free_vp_index:
	kfree(hv_vp_index);
	hv_vp_index = NULL;
	return 1;
}
TIMER_ACPI_DECLARE(hyperv, ACPI_SIG_GTDT, hyperv_init);

/*
 * This routine is called before kexec/kdump, it does the required cleanup.
 */
void hyperv_cleanup(void)
{
	/* Reset our OS id */
	hv_set_vpreg(HV_REGISTER_GUEST_OSID, 0);

}
EXPORT_SYMBOL_GPL(hyperv_cleanup);

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

bool hv_is_hyperv_initialized(void)
{
	return hyperv_initialized;
}
EXPORT_SYMBOL_GPL(hv_is_hyperv_initialized);
