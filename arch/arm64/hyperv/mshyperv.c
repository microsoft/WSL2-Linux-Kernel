// SPDX-License-Identifier: GPL-2.0

/*
 * Core routines for interacting with Microsoft's Hyper-V hypervisor,
 * including setting up VMbus and STIMER interrupts, and handling
 * crashes and kexecs. These interactions are through a set of
 * static "handler" variables set by the architecture independent
 * VMbus and STIMER drivers.
 *
 * Copyright (C) 2019, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
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
	vmbus_handler();
	return IRQ_HANDLED;
}

/* Must be done just once */
int hv_setup_vmbus_irq(int irq, void (*handler)(void))
{
	int result;

	vmbus_handler = handler;

	vmbus_evt = alloc_percpu(long);
	result = request_percpu_irq(irq, hyperv_vector_handler,
			"Hyper-V VMbus", vmbus_evt);
	if (result) {
		pr_err("Can't request Hyper-V VMBus IRQ %d. Error %d",
			irq, result);
		free_percpu(vmbus_evt);
		return result;
	}

	vmbus_irq = irq;
	return 0;
}
EXPORT_SYMBOL_GPL(hv_setup_vmbus_irq);

/* Must be done just once */
void hv_remove_vmbus_irq(void)
{
	if (vmbus_irq) {
		free_percpu_irq(vmbus_irq, vmbus_evt);
		free_percpu(vmbus_evt);
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

	localirq = acpi_register_gsi(NULL, HV_STIMER0_INTID,
			ACPI_EDGE_SENSITIVE, ACPI_ACTIVE_HIGH);
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
		return result;
	}

	hv_stimer0_handler = handler;
	*vector = HV_STIMER0_INTID;
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
