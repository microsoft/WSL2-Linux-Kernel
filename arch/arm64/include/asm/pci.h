/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_PCI_H
#define __ASM_PCI_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>

#include <asm/io.h>

#define PCIBIOS_MIN_IO		0x1000
#define PCIBIOS_MIN_MEM		0

/*
 * Set to 1 if the kernel should re-assign all PCI bus numbers
 */
#define pcibios_assign_all_busses() \
	(pci_has_flag(PCI_REASSIGN_ALL_BUS))

#define arch_can_pci_mmap_wc() 1
#define ARCH_GENERIC_PCI_MMAP_RESOURCE	1

extern int isa_dma_bridge_buggy;

struct pci_sysdata {
	int domain;	/* PCI domain */
	int node;	/* NUMA Node */
#ifdef CONFIG_ACPI
	struct acpi_device *companion;	/* ACPI companion device */
#endif
#ifdef CONFIG_PCI_MSI_IRQ_DOMAIN
	void *fwnode;			/* IRQ domain for MSI assignment */
#endif
};

#ifdef CONFIG_PCI
static inline int pci_get_legacy_ide_irq(struct pci_dev *dev, int channel)
{
	/* no legacy IRQ on arm64 */
	return -ENODEV;
}

static inline int pci_proc_domain(struct pci_bus *bus)
{
	if (bus->ops->use_arch_sysdata)
		return pci_domain_nr(bus);

	return 1;
}

#ifdef CONFIG_PCI_MSI_IRQ_DOMAIN
static inline void *_pci_root_bus_fwnode(struct pci_bus *bus)
{
	struct pci_sysdata *sd = bus->sysdata;

	if (bus->ops->use_arch_sysdata)
		return sd->fwnode;

	/*
	 * bus->sysdata is not struct pci_sysdata, fwnode should be able to
	 * be queried from of/acpi.
	 */
	return NULL;
}
#define pci_root_bus_fwnode	_pci_root_bus_fwnode
#endif /* CONFIG_PCI_MSI_IRQ_DOMAIN */

#endif  /* CONFIG_PCI */

#endif  /* __ASM_PCI_H */
