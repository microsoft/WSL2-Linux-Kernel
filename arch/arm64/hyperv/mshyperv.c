// SPDX-License-Identifier: GPL-2.0

/*
 * Core routines for interacting with Microsoft's Hyper-V hypervisor.
 * Includes hypervisor initialization, and handling of crashes and
 * kexecs through a set of static "handler" variables set by the
 * architecture independent VMbus driver.
 *
 * Copyright (C) 2021, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#include <linux/types.h>
#include <linux/export.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/acpi.h>
#include <linux/version.h>
#include <linux/cpuhotplug.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <asm/mshyperv.h>

static bool		hyperv_initialized;
struct ms_hyperv_info	ms_hyperv __ro_after_init;
EXPORT_SYMBOL_GPL(ms_hyperv);

u32	*hv_vp_index;
EXPORT_SYMBOL_GPL(hv_vp_index);

u32	hv_max_vp_index;
EXPORT_SYMBOL_GPL(hv_max_vp_index);

static int hv_cpu_init(unsigned int cpu)
{
	hv_vp_index[cpu] = hv_get_vpreg(HV_REGISTER_VP_INDEX);
	return 0;
}

void __init hyperv_early_init(void)
{
	struct hv_get_vp_registers_output	result;
	u32	a, b, c, d;
	u64	guest_id;

	/*
	 * If we're in a VM on Hyper-V, the ACPI hypervisor_id field will
	 * have the string "MsHyperV".
	 */
	if (strncmp((char *)&acpi_gbl_FADT.hypervisor_id, "MsHyperV", 8))
		return;

	/* Setup the guest ID */
	guest_id = generate_guest_id(0, LINUX_VERSION_CODE, 0);
	hv_set_vpreg(HV_REGISTER_GUEST_OSID, guest_id);

	/* Get the features and hints from Hyper-V */
	hv_get_vpreg_128(HV_REGISTER_FEATURES, &result);
	ms_hyperv.features = result.as32.a;
	ms_hyperv.misc_features = result.as32.c;

	hv_get_vpreg_128(HV_REGISTER_ENLIGHTENMENTS, &result);
	ms_hyperv.hints = result.as32.a;

	pr_info("Hyper-V: Features 0x%x, hints 0x%x, misc 0x%x\n",
		ms_hyperv.features, ms_hyperv.hints, ms_hyperv.misc_features);

	/*
	 * If Hyper-V has crash notifications, set crash_kexec_post_notifiers
	 * so that we will report the panic to Hyper-V before running kdump.
	 */
	if (ms_hyperv.misc_features & HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE)
		crash_kexec_post_notifiers = true;

	/* Get information about the Hyper-V host version */
	hv_get_vpreg_128(HV_REGISTER_HYPERVISOR_VERSION, &result);
	a = result.as32.a;
	b = result.as32.b;
	c = result.as32.c;
	d = result.as32.d;
	pr_info("Hyper-V: Host Build %d.%d.%d.%d-%d-%d\n",
		b >> 16, b & 0xFFFF, a,	d & 0xFFFFFF, c, d >> 24);

	hyperv_initialized = true;
}

static int __init hyperv_init(void)
{
	int	i;

	/*
	 * Return if not running as a Hyper-V guest.
	 */
	if (!hyperv_initialized)
		return 0;

	/* Allocate and initialize percpu VP index array */
	hv_max_vp_index = num_possible_cpus();
	hv_vp_index = kmalloc_array(hv_max_vp_index, sizeof(*hv_vp_index),
				    GFP_KERNEL);
	if (!hv_vp_index) {
		hv_max_vp_index = 0;
		return -ENOMEM;
	}

	for (i = 0; i < hv_max_vp_index; i++)
		hv_vp_index[i] = VP_INVAL;

	if (cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "arm64/hyperv_init:online",
					hv_cpu_init, NULL) < 0) {
		hv_max_vp_index = 0;
		kfree(hv_vp_index);
		hv_vp_index = NULL;
		return -EINVAL;
	}

	return 0;
}

early_initcall(hyperv_init);

/* This routine is called before kexec/kdump. It does required cleanup. */
void hyperv_cleanup(void)
{
	hv_set_vpreg(HV_REGISTER_GUEST_OSID, 0);

}
EXPORT_SYMBOL_GPL(hyperv_cleanup);

bool hv_is_hyperv_initialized(void)
{
	return hyperv_initialized;
}
EXPORT_SYMBOL_GPL(hv_is_hyperv_initialized);

bool hv_is_hibernation_supported(void)
{
	return false;
}
EXPORT_SYMBOL_GPL(hv_is_hibernation_supported);

/*
 * The VMbus handler functions are no-ops on ARM64 because
 * VMbus interrupts are handled as percpu IRQs.
 */
void hv_setup_vmbus_handler(void (*handler)(void))
{
}
EXPORT_SYMBOL_GPL(hv_setup_vmbus_handler);

void hv_remove_vmbus_handler(void)
{
}
EXPORT_SYMBOL_GPL(hv_remove_vmbus_handler);

/*
 * The kexec and crash handler functions are
 * currently no-ops on ARM64.
 */
void hv_setup_kexec_handler(void (*handler)(void))
{
}
EXPORT_SYMBOL_GPL(hv_setup_kexec_handler);

void hv_remove_kexec_handler(void)
{
}
EXPORT_SYMBOL_GPL(hv_remove_kexec_handler);

void hv_setup_crash_handler(void (*handler)(struct pt_regs *regs))
{
}
EXPORT_SYMBOL_GPL(hv_setup_crash_handler);

void hv_remove_crash_handler(void)
{
}
EXPORT_SYMBOL_GPL(hv_remove_crash_handler);
