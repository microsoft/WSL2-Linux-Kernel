// SPDX-License-Identifier: GPL-2.0

/*
 * Core routines for interacting with Microsoft's Hyper-V hypervisor,
 * including setting up VMbus and STIMER interrupts, and handling
 * crashes and kexecs. These interactions are through a set of
 * static "handler" variables set by the architecture independent
 * VMbus and STIMER drivers.  This design is used to meet x86/x64
 * requirements for avoiding direct linkages and allowing the VMbus
 * and STIMER drivers to be unloaded and reloaded.
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
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/kexec.h>
#include <linux/acpi.h>
#include <linux/ptrace.h>
#include <asm/hyperv-tlfs.h>
#include <asm/mshyperv.h>

static void (*vmbus_handler)(void);
static void (*hv_stimer0_handler)(void);
static void (*hv_kexec_handler)(void);
static void (*hv_crash_handler)(struct pt_regs *regs);

static int vmbus_irq;
static long __percpu *vmbus_evt;
static long __percpu *stimer0_evt;

irqreturn_t hyperv_vector_handler(int irq, void *dev_id)
{
	if (vmbus_handler)
		vmbus_handler();
	return IRQ_HANDLED;
}

/* Must be done just once */
void hv_setup_vmbus_irq(void (*handler)(void))
{
	int result;

	vmbus_handler = handler;
	vmbus_irq = acpi_register_gsi(NULL, HYPERVISOR_CALLBACK_VECTOR,
				 ACPI_LEVEL_SENSITIVE, ACPI_ACTIVE_HIGH);
	if (vmbus_irq <= 0) {
		pr_err("Can't register Hyper-V VMBus GSI. Error %d",
			vmbus_irq);
		vmbus_irq = 0;
		return;
	}
	vmbus_evt = alloc_percpu(long);
	result = request_percpu_irq(vmbus_irq, hyperv_vector_handler,
			"Hyper-V VMbus", vmbus_evt);
	if (result) {
		pr_err("Can't request Hyper-V VMBus IRQ %d. Error %d",
			vmbus_irq, result);
		free_percpu(vmbus_evt);
		acpi_unregister_gsi(vmbus_irq);
		vmbus_irq = 0;
	}
}
EXPORT_SYMBOL_GPL(hv_setup_vmbus_irq);

/* Must be done just once */
void hv_remove_vmbus_irq(void)
{
	if (vmbus_irq) {
		free_percpu_irq(vmbus_irq, vmbus_evt);
		free_percpu(vmbus_evt);
		acpi_unregister_gsi(vmbus_irq);
	}
}
EXPORT_SYMBOL_GPL(hv_remove_vmbus_irq);

/* Must be done by each CPU */
void hv_enable_vmbus_irq(void)
{
	enable_percpu_irq(vmbus_irq, 0);
}
EXPORT_SYMBOL_GPL(hv_enable_vmbus_irq);

/* Must be done by each CPU */
void hv_disable_vmbus_irq(void)
{
	disable_percpu_irq(vmbus_irq);
}
EXPORT_SYMBOL_GPL(hv_disable_vmbus_irq);

/* Routines to do per-architecture handling of STIMER0 when in Direct Mode */

static irqreturn_t hv_stimer0_vector_handler(int irq, void *dev_id)
{
	if (hv_stimer0_handler)
		hv_stimer0_handler();
	return IRQ_HANDLED;
}

int hv_setup_stimer0_irq(int *irq, int *vector, void (*handler)(void))
{
	int localirq;
	int result;

	localirq = acpi_register_gsi(NULL, HV_STIMER0_IRQNR,
			ACPI_LEVEL_SENSITIVE, ACPI_ACTIVE_HIGH);
	if (localirq <= 0) {
		pr_err("Can't register Hyper-V stimer0 GSI. Error %d",
			localirq);
		*irq = 0;
		return -1;
	}
	stimer0_evt = alloc_percpu(long);
	result = request_percpu_irq(localirq, hv_stimer0_vector_handler,
					 "Hyper-V stimer0", stimer0_evt);
	if (result) {
		pr_err("Can't request Hyper-V stimer0 IRQ %d. Error %d",
			localirq, result);
		free_percpu(stimer0_evt);
		acpi_unregister_gsi(localirq);
		*irq = 0;
		return -1;
	}

	hv_stimer0_handler = handler;
	*vector = HV_STIMER0_IRQNR;
	*irq = localirq;
	return 0;
}
EXPORT_SYMBOL_GPL(hv_setup_stimer0_irq);

void hv_remove_stimer0_irq(int irq)
{
	hv_stimer0_handler = NULL;
	if (irq) {
		free_percpu_irq(irq, stimer0_evt);
		free_percpu(stimer0_evt);
		acpi_unregister_gsi(irq);
	}
}
EXPORT_SYMBOL_GPL(hv_remove_stimer0_irq);

void hv_setup_kexec_handler(void (*handler)(void))
{
	hv_kexec_handler = handler;
}
EXPORT_SYMBOL_GPL(hv_setup_kexec_handler);

void hv_remove_kexec_handler(void)
{
	hv_kexec_handler = NULL;
}
EXPORT_SYMBOL_GPL(hv_remove_kexec_handler);

void hv_setup_crash_handler(void (*handler)(struct pt_regs *regs))
{
	hv_crash_handler = handler;
}
EXPORT_SYMBOL_GPL(hv_setup_crash_handler);

void hv_remove_crash_handler(void)
{
	hv_crash_handler = NULL;
}
EXPORT_SYMBOL_GPL(hv_remove_crash_handler);
