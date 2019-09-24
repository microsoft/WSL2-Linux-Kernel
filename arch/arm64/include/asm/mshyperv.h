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

#ifndef _ASM_ARM64_MSHYPERV_H
#define _ASM_ARM64_MSHYPERV_H

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/clocksource.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <asm/hyperv-tlfs.h>

/*
 * Define the IRQ numbers/vectors used by Hyper-V VMbus interrupts
 * and by STIMER0 Direct Mode interrupts. Hyper-V should be supplying
 * these values through ACPI, but there are no other interrupting
 * devices in a Hyper-V VM on ARM64, so it's OK to hard code for now.
 * The "CALLBACK_VECTOR" terminology is a left-over from the x86/x64
 * world that is used in architecture independent Hyper-V code.
 */
#define HYPERVISOR_CALLBACK_VECTOR 16
#define	HV_STIMER0_IRQNR	   17

extern u64 hv_do_hvc(u64 control, ...);
extern u64 hv_do_hvc_fast_get(u64 control, u64 input1, u64 input2, u64 input3,
		struct hv_get_vp_register_output *output);

/*
 * Declare calls to get and set Hyper-V VP register values on ARM64, which
 * requires a hypercall.
 */
extern void hv_set_vpreg(u32 reg, u64 value);
extern u64 hv_get_vpreg(u32 reg);
extern void hv_get_vpreg_128(u32 reg, struct hv_get_vp_register_output *result);

/*
 * Use the Hyper-V provided stimer0 as the timer that is made
 * available to the architecture independent Hyper-V drivers.
 */
#define hv_init_timer(timer, tick) \
		hv_set_vpreg(HV_REGISTER_STIMER0_COUNT + (2*timer), tick)
#define hv_init_timer_config(timer, val) \
		hv_set_vpreg(HV_REGISTER_STIMER0_CONFIG + (2*timer), val)
#define hv_get_current_tick(tick) \
		(tick = hv_get_vpreg(HV_REGISTER_TIME_REFCOUNT))

#define hv_get_simp(val) (val = hv_get_vpreg(HV_REGISTER_SIPP))
#define hv_set_simp(val) hv_set_vpreg(HV_REGISTER_SIPP, val)

#define hv_get_siefp(val) (val = hv_get_vpreg(HV_REGISTER_SIFP))
#define hv_set_siefp(val) hv_set_vpreg(HV_REGISTER_SIFP, val)

#define hv_get_synic_state(val) (val = hv_get_vpreg(HV_REGISTER_SCONTROL))
#define hv_set_synic_state(val) hv_set_vpreg(HV_REGISTER_SCONTROL, val)

#define hv_get_vp_index(index) (index = hv_get_vpreg(HV_REGISTER_VPINDEX))

#define hv_signal_eom()	hv_set_vpreg(HV_REGISTER_EOM, 0)

/*
 * Hyper-V SINT registers are numbered sequentially, so we can just
 * add the SINT number to the register number of SINT0
 */
#define hv_get_synint_state(sint_num, val) \
		(val = hv_get_vpreg(HV_REGISTER_SINT0 + sint_num))
#define hv_set_synint_state(sint_num, val) \
		hv_set_vpreg(HV_REGISTER_SINT0 + sint_num, val)

#define hv_get_crash_ctl(val) \
		(val = hv_get_vpreg(HV_REGISTER_CRASH_CTL))

#if IS_ENABLED(CONFIG_HYPERV)
#define hv_enable_stimer0_percpu_irq(irq)	enable_percpu_irq(irq, 0)
#define hv_disable_stimer0_percpu_irq(irq)	disable_percpu_irq(irq)
extern void  __percpu  **hyperv_pcpu_input_arg;
#endif

/* ARM64 specific code to read the hardware clock */
static inline u64 hv_read_hwclock(void)
{
	u64 result;

	isb();
	result = read_sysreg(cntvct_el0);
	isb();

	return result;
}

#include <asm-generic/mshyperv.h>

#endif
