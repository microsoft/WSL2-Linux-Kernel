/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Linux-specific definitions for managing interactions with Microsoft's
 * Hyper-V hypervisor. The definitions in this file are specific to
 * the ARM64 architecture.  See include/asm-generic/mshyperv.h for
 * definitions are that architecture independent.
 *
 * Definitions that are specified in the Hyper-V Top Level Functional
 * Spec (TLFS) should not go in this file, but should instead go in
 * hyperv-tlfs.h.
 *
 * Copyright (C) 2021, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#ifndef _ASM_MSHYPERV_H
#define _ASM_MSHYPERV_H

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/arm-smccc.h>
#include <linux/msi.h>
#include <asm/hyperv-tlfs.h>
#include <asm/msi.h>
#include <clocksource/arm_arch_timer.h>

#if IS_ENABLED(CONFIG_HYPERV)
void __init hyperv_early_init(void);
#else
static inline void hyperv_early_init(void) {};
#endif

extern u64 hv_do_hvc(u64 control, ...);
extern u64 hv_do_hvc_fast_get(u64 control, u64 input1, u64 input2, u64 input3,
		struct hv_get_vp_registers_output *output);

/*
 * Declare calls to get and set Hyper-V VP register values on ARM64, which
 * requires a hypercall.
 */

extern void hv_set_vpreg(u32 reg, u64 value);
extern u64 hv_get_vpreg(u32 reg);
extern void hv_get_vpreg_128(u32 reg, struct hv_get_vp_registers_output *result);
extern void __percpu **hyperv_pcpu_input_arg;

static inline void hv_set_register(unsigned int reg, u64 value)
{
	hv_set_vpreg(reg, value);
}

static inline u64 hv_get_register(unsigned int reg)
{
	return hv_get_vpreg(reg);
}

/* Define the interrupt ID used by STIMER0 Direct Mode interrupts. This
 * value can't come from ACPI tables because it is needed before the
 * Linux ACPI subsystem is initialized.
 */
#define HYPERV_STIMER0_VECTOR	31

static inline u64 hv_get_raw_timer(void)
{
	return arch_timer_read_counter();
}

/* SMCCC hypercall parameters */
#define HV_SMCCC_FUNC_NUMBER	1
#define HV_FUNC_ID	ARM_SMCCC_CALL_VAL(			\
				ARM_SMCCC_STD_CALL,		\
				ARM_SMCCC_SMC_64,		\
				ARM_SMCCC_OWNER_VENDOR_HYP,	\
				HV_SMCCC_FUNC_NUMBER)

#define hv_msi_handler NULL
#define hv_msi_handler_name NULL

/* Architecture specific Hyper-V PCI MSI initialization and cleanup routines. */
int hv_pci_arch_init(void);
void hv_pci_arch_free(void);

/* Returns the Hyper-V PCI parent MSI vector domain. */
struct irq_domain *hv_msi_parent_vector_domain(void);

/* Returns the interrupt vector mapped to the given IRQ. */
unsigned int hv_msi_get_int_vector(struct irq_data *data);

/* Returns the H/W interrupt vector mapped to the given MSI. */
static inline irq_hw_number_t
hv_msi_domain_ops_get_hwirq(struct msi_domain_info *info,
			    msi_alloc_info_t *arg)
{
	return arg->hwirq;
}

/* Get the IRQ delivery mode. */
static inline u8 hv_msi_irq_delivery_mode(void)
{
	return 0;
}

#define hv_msi_prepare NULL

static inline void hv_set_msi_entry_from_desc(union hv_msi_entry *msi_entry,
					      struct msi_desc *msi_desc)
{
	msi_entry->address = ((u64)msi_desc->msg.address_hi << 32) |
			      msi_desc->msg.address_lo;
	msi_entry->data = msi_desc->msg.data;
}

#include <asm-generic/mshyperv.h>

#endif
