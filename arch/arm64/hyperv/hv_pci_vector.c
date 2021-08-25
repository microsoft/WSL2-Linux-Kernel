// SPDX-License-Identifier: GPL-2.0

/*
 * Architecture specific vector management for the Hyper-V vPCI.
 *
 * Copyright (C) 2018, Microsoft, Inc.
 *
 * Author : Sunil Muthuswamy <sunilmut@microsoft.com>
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

#include <asm/mshyperv.h>
#include <linux/acpi.h>
#include <linux/irqdomain.h>
#include <linux/irq.h>
#include <acpi/acpi_bus.h>

/*
 * Hyper-V ARM64 host uses 32 SPI's for vPCI.
 * Currently, starting from 40 and limiting it to 32
 * since there is an overlap in the 30s range.
 */
#define HV_PCI_MSI_SPI_START	40
#define HV_PCI_MSI_SPI_NR	32

struct hv_pci_chip_data {
	spinlock_t lock; /* Protects this struct */
	struct irq_domain *domain;
	unsigned long bm;
};

extern struct irq_domain *gicv3_vector_domain;
static struct hv_pci_chip_data *chip_data;
static struct irq_chip hv_msi_irq_chip = {
	.name = "Hyper-V ARM64 PCI MSI",
	.irq_set_affinity = irq_chip_set_affinity_parent,
	.irq_eoi = irq_chip_eoi_parent,
	.irq_mask = irq_chip_mask_parent,
	.irq_unmask = irq_chip_unmask_parent
};

/**
 * Frees the specified number of interrupts.
 * @domain: The IRQ domain
 * @virq: The virtual IRQ number.
 * @nr_irqs: Number of IRQ's to free.
 */
static void hv_pci_vec_irq_domain_free(struct irq_domain *domain,
				       unsigned int virq, unsigned int nr_irqs)
{
	unsigned long flags;
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *irqd = irq_domain_get_irq_data(domain,
								virq + i);
		spin_lock_irqsave(&chip_data->lock, flags);
		clear_bit(irqd->hwirq - HV_PCI_MSI_SPI_START, &chip_data->bm);
		spin_unlock_irqrestore(&chip_data->lock, flags);
		irq_domain_reset_irq_data(irqd);
	}

	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

/**
 * Allocate an interrupt from the domain.
 * @hwirq: Will be set to the allocated H/W IRQ.
 *
 * Return: 0 on success and error value on failure.
 */
static int hv_pci_vec_alloc_device_irq(irq_hw_number_t *hwirq)
{
	unsigned long flags;
	int index;

	spin_lock_irqsave(&chip_data->lock, flags);
	index = find_first_zero_bit(&chip_data->bm, HV_PCI_MSI_SPI_NR);
	if (index == HV_PCI_MSI_SPI_NR) {
		spin_unlock_irqrestore(&chip_data->lock, flags);
		pr_err("No more free IRQ vector available\n");
		return -ENOSPC;
	}

	set_bit(index, &chip_data->bm);
	spin_unlock_irqrestore(&chip_data->lock, flags);
	*hwirq = index + HV_PCI_MSI_SPI_START;
	return 0;
}

/**
 * Allocate an interrupt from the parent GIC domain.
 * @domain: The IRQ domain.
 * @virq: The virtual IRQ number.
 * @hwirq: The H/W IRQ number that needs to be allocated.
 *
 * Return: 0 on success and error value on failure.
 */
static int hv_pci_vec_irq_gic_domain_alloc(struct irq_domain *domain,
					   unsigned int virq,
					   irq_hw_number_t hwirq)
{
	struct irq_fwspec fwspec;

	fwspec.fwnode = domain->parent->fwnode;
	fwspec.param_count = 2;
	fwspec.param[0] = hwirq;
	fwspec.param[1] = IRQ_TYPE_EDGE_RISING;

	return irq_domain_alloc_irqs_parent(domain, virq, 1, &fwspec);
}

/**
 * Allocate specfied number of interrupt from the domain.
 * @domain: The IRQ domain.
 * @virq: The starting virtual IRQ number.
 * @nr_irqs: Number of IRQ's to allocate.
 * @args: The MSI alloc information.
 *
 * Return: 0 on success and error value on failure.
 */
static int hv_pci_vec_irq_domain_alloc(struct irq_domain *domain,
				       unsigned int virq, unsigned int nr_irqs,
				       void *args)
{
	irq_hw_number_t hwirq;
	int i;
	int ret;

	for (i = 0; i < nr_irqs; i++) {
		ret = hv_pci_vec_alloc_device_irq(&hwirq);
		if (ret)
			goto free_irq;

		ret = hv_pci_vec_irq_gic_domain_alloc(domain, virq + i, hwirq);
		if (ret)
			goto free_irq;

		ret = irq_domain_set_hwirq_and_chip(domain, virq + i,
				hwirq, &hv_msi_irq_chip,
				domain->host_data);
		if (ret)
			goto free_irq;

		irqd_set_single_target(irq_desc_get_irq_data(irq_to_desc(virq + i)));
		pr_debug("pID:%d vID:%d\n", (int)hwirq, virq + i);
	}

	return 0;

free_irq:
	hv_pci_vec_irq_domain_free(domain, virq, nr_irqs);
	return ret;
}

/**
 * Activate the interrupt.
 * @domain: The IRQ domain.
 * @irqd: IRQ data.
 * @reserve: Indicates whether the IRQ's can be reserved.
 *
 * Return: 0 on success and error value on failure.
 */
static int hv_pci_vec_irq_domain_activate(struct irq_domain *domain,
					  struct irq_data *irqd, bool reserve)
{
	/* Bind the SPI to all available online CPUs */
	irq_data_update_effective_affinity(irqd, cpu_online_mask);
	return 0;
}

/**
 * Deactivate the interrupt.
 * @domain: The IRQ domain.
 * @irqd: IRQ data pertaining to the interrupt..
 */
static void hv_pci_vec_irq_domain_deactivate(struct irq_domain *domain,
					     struct irq_data *irqd)
{
	/* TODO */
	//clear_irq_vector(irqd);
}

static const struct irq_domain_ops hv_pci_domain_ops = {
	.alloc	= hv_pci_vec_irq_domain_alloc,
	.free	= hv_pci_vec_irq_domain_free,
	.activate = hv_pci_vec_irq_domain_activate,
	.deactivate = hv_pci_vec_irq_domain_deactivate
};


/**
 * This routine performs the arechitecture specific initialization for vector
 * domain to operate. It allocates an IRQ domain tree as a child of the GIC
 * IRQ domain.
 *
 * Return: 0 on success and error value on failure.
 */
int hv_pci_vector_init(void)
{
	struct fwnode_handle *fn;
	int ret;

	if (!is_fwnode_irqchip(gicv3_vector_domain->fwnode)) {
		pr_err("Unexpected parent IRQ chip\n");
		return -EINVAL;
	}

	ret = -ENOMEM;
	chip_data = kzalloc(sizeof(*chip_data), GFP_KERNEL);
	if (!chip_data)
		return ret;

	spin_lock_init(&chip_data->lock);
	fn = irq_domain_alloc_named_fwnode("Hyper-V ARM64 vPCI");
	if (!fn)
		goto free_chip;

	chip_data->domain = irq_domain_create_tree(fn, &hv_pci_domain_ops,
						   NULL);
	irq_domain_free_fwnode(fn);
	if (!chip_data->domain) {
		pr_err("Failed to create IRQ domain\n");
		goto free_chip;
	}

	chip_data->domain->parent = gicv3_vector_domain;
	chip_data->domain->host_data = chip_data;
	return 0;

free_chip:
	kfree(chip_data);
	chip_data = NULL;
	return ret;
}

/* This routine performs the cleanup for the IRQ domain. */
void hv_pci_vector_free(void)
{
	if (!chip_data)
		return;

	if (chip_data->domain)
		irq_domain_remove(chip_data->domain);

	kfree(chip_data);
}

/* Performs the architecture specific initialization for Hyper-V PCI. */
int hv_pci_arch_init(void)
{
	return hv_pci_vector_init();
}
EXPORT_SYMBOL_GPL(hv_pci_arch_init);

/* Architecture specific cleanup for Hyper-V PCI. */
void hv_pci_arch_free(void)
{
	hv_pci_vector_free();
}
EXPORT_SYMBOL_GPL(hv_pci_arch_free);

struct irq_domain *hv_msi_parent_vector_domain(void)
{
	return chip_data->domain;
}
EXPORT_SYMBOL_GPL(hv_msi_parent_vector_domain);

unsigned int hv_msi_get_int_vector(struct irq_data *irqd)
{
	irqd = irq_domain_get_irq_data(chip_data->domain, irqd->irq);
	return irqd->hwirq;
}
EXPORT_SYMBOL_GPL(hv_msi_get_int_vector);
