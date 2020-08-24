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
 * Copyright (C) 2019, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#ifndef _ASM_MSHYPERV_H
#define _ASM_MSHYPERV_H

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/clocksource.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/arm-smccc.h>
#include <asm/hyperv-tlfs.h>

/*
 * Declare calls to get and set Hyper-V VP register values on ARM64, which
 * requires a hypercall.
 */
extern void hv_set_vpreg(u32 reg, u64 value);
extern u64 hv_get_vpreg(u32 reg);
extern void hv_get_vpreg_128(u32 reg, struct hv_get_vp_registers_output *result);

/* Access various Hyper-V synthetic registers */
static inline void hv_set_simp(u64 val)
{
	hv_set_vpreg(HV_REGISTER_SIPP, val);
}

#define hv_get_simp(val) (val = hv_get_vpreg(HV_REGISTER_SIPP))

static inline void hv_set_siefp(u64 val)
{
	hv_set_vpreg(HV_REGISTER_SIFP, val);
}

#define hv_get_siefp(val) (val = hv_get_vpreg(HV_REGISTER_SIFP))

static inline void hv_set_synic_state(u64 val)
{
	hv_set_vpreg(HV_REGISTER_SCONTROL, val);
}

#define hv_get_synic_state(val) (val = hv_get_vpreg(HV_REGISTER_SCONTROL))

static inline bool hv_recommend_using_aeoi(void)
{
	return false;
}

static inline void hv_signal_eom(void)
{
	hv_set_vpreg(HV_REGISTER_EOM, 0);
}

/*
 * Hyper-V SINT registers are numbered sequentially, so we can just
 * add the SINT number to the register number of SINT0
 */

static inline void hv_set_synint_state(u32 sint_num, u64 val)
{
	hv_set_vpreg(HV_REGISTER_SINT0 + sint_num, val);
}

#define hv_get_synint_state(sint_num, val) \
		(val = hv_get_vpreg(HV_REGISTER_SINT0 + sint_num))


/* SMCCC hypercall parameters */
#define HV_SMCCC_FUNC_NUMBER	1
#define HV_FUNC_ID	ARM_SMCCC_CALL_VAL(			\
				ARM_SMCCC_STD_CALL,		\
				ARM_SMCCC_SMC_64,		\
				ARM_SMCCC_OWNER_VENDOR_HYP,	\
				HV_SMCCC_FUNC_NUMBER)

#include <asm-generic/mshyperv.h>

#endif
