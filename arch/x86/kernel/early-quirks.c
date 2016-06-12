/* Various workarounds for chipset bugs.
   This code runs very early and can't use the regular PCI subsystem
   The entries are keyed to PCI bridges which usually identify chipsets
   uniquely.
   This is only for whole classes of chipsets with specific problems which
   need early invasive action (e.g. before the timers are initialized).
   Most PCI device specific workarounds can be done later and should be
   in standard PCI quirks
   Mainboard specific bugs should be handled by DMI entries.
   CPU specific bugs in setup.c */

#include <linux/pci.h>
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/dmi.h>
#include <linux/pci_ids.h>
#include <linux/bcma/bcma.h>
#include <linux/bcma/bcma_regs.h>
#include <asm/pci-direct.h>
#include <asm/dma.h>
#include <asm/io_apic.h>
#include <asm/apic.h>
#include <asm/iommu.h>
#include <asm/gart.h>
#include <asm/io.h>

#define dev_err(msg)  pr_err("pci 0000:%02x:%02x.%d: %s", bus, slot, func, msg)

static void __init fix_hypertransport_config(int num, int slot, int func)
{
	u32 htcfg;
	/*
	 * we found a hypertransport bus
	 * make sure that we are broadcasting
	 * interrupts to all cpus on the ht bus
	 * if we're using extended apic ids
	 */
	htcfg = read_pci_config(num, slot, func, 0x68);
	if (htcfg & (1 << 18)) {
		printk(KERN_INFO "Detected use of extended apic ids "
				 "on hypertransport bus\n");
		if ((htcfg & (1 << 17)) == 0) {
			printk(KERN_INFO "Enabling hypertransport extended "
					 "apic interrupt broadcast\n");
			printk(KERN_INFO "Note this is a bios bug, "
					 "please contact your hw vendor\n");
			htcfg |= (1 << 17);
			write_pci_config(num, slot, func, 0x68, htcfg);
		}
	}


}

static void __init via_bugs(int  num, int slot, int func)
{
#ifdef CONFIG_GART_IOMMU
	if ((max_pfn > MAX_DMA32_PFN ||  force_iommu) &&
	    !gart_iommu_aperture_allowed) {
		printk(KERN_INFO
		       "Looks like a VIA chipset. Disabling IOMMU."
		       " Override with iommu=allowed\n");
		gart_iommu_aperture_disabled = 1;
	}
#endif
}

#ifdef CONFIG_ACPI
#ifdef CONFIG_X86_IO_APIC

static int __init nvidia_hpet_check(struct acpi_table_header *header)
{
	return 0;
}
#endif /* CONFIG_X86_IO_APIC */
#endif /* CONFIG_ACPI */

static void __init nvidia_bugs(int num, int slot, int func)
{
#ifdef CONFIG_ACPI
#ifdef CONFIG_X86_IO_APIC
	/*
	 * Only applies to Nvidia root ports (bus 0) and not to
	 * Nvidia graphics cards with PCI ports on secondary buses.
	 */
	if (num)
		return;

	/*
	 * All timer overrides on Nvidia are
	 * wrong unless HPET is enabled.
	 * Unfortunately that's not true on many Asus boards.
	 * We don't know yet how to detect this automatically, but
	 * at least allow a command line override.
	 */
	if (acpi_use_timer_override)
		return;

	if (acpi_table_parse(ACPI_SIG_HPET, nvidia_hpet_check)) {
		acpi_skip_timer_override = 1;
		printk(KERN_INFO "Nvidia board "
		       "detected. Ignoring ACPI "
		       "timer override.\n");
		printk(KERN_INFO "If you got timer trouble "
			"try acpi_use_timer_override\n");
	}
#endif
#endif
	/* RED-PEN skip them on mptables too? */

}

#if defined(CONFIG_ACPI) && defined(CONFIG_X86_IO_APIC)
static u32 __init ati_ixp4x0_rev(int num, int slot, int func)
{
	u32 d;
	u8  b;

	b = read_pci_config_byte(num, slot, func, 0xac);
	b &= ~(1<<5);
	write_pci_config_byte(num, slot, func, 0xac, b);

	d = read_pci_config(num, slot, func, 0x70);
	d |= 1<<8;
	write_pci_config(num, slot, func, 0x70, d);

	d = read_pci_config(num, slot, func, 0x8);
	d &= 0xff;
	return d;
}

static void __init ati_bugs(int num, int slot, int func)
{
	u32 d;
	u8  b;

	if (acpi_use_timer_override)
		return;

	d = ati_ixp4x0_rev(num, slot, func);
	if (d  < 0x82)
		acpi_skip_timer_override = 1;
	else {
		/* check for IRQ0 interrupt swap */
		outb(0x72, 0xcd6); b = inb(0xcd7);
		if (!(b & 0x2))
			acpi_skip_timer_override = 1;
	}

	if (acpi_skip_timer_override) {
		printk(KERN_INFO "SB4X0 revision 0x%x\n", d);
		printk(KERN_INFO "Ignoring ACPI timer override.\n");
		printk(KERN_INFO "If you got timer trouble "
		       "try acpi_use_timer_override\n");
	}
}

static u32 __init ati_sbx00_rev(int num, int slot, int func)
{
	u32 d;

	d = read_pci_config(num, slot, func, 0x8);
	d &= 0xff;

	return d;
}

static void __init ati_bugs_contd(int num, int slot, int func)
{
	u32 d, rev;

	rev = ati_sbx00_rev(num, slot, func);
	if (rev >= 0x40)
		acpi_fix_pin2_polarity = 1;

	/*
	 * SB600: revisions 0x11, 0x12, 0x13, 0x14, ...
	 * SB700: revisions 0x39, 0x3a, ...
	 * SB800: revisions 0x40, 0x41, ...
	 */
	if (rev >= 0x39)
		return;

	if (acpi_use_timer_override)
		return;

	/* check for IRQ0 interrupt swap */
	d = read_pci_config(num, slot, func, 0x64);
	if (!(d & (1<<14)))
		acpi_skip_timer_override = 1;

	if (acpi_skip_timer_override) {
		printk(KERN_INFO "SB600 revision 0x%x\n", rev);
		printk(KERN_INFO "Ignoring ACPI timer override.\n");
		printk(KERN_INFO "If you got timer trouble "
		       "try acpi_use_timer_override\n");
	}
}
#else
static void __init ati_bugs(int num, int slot, int func)
{
}

static void __init ati_bugs_contd(int num, int slot, int func)
{
}
#endif

#define BCM4331_MMIO_SIZE	16384
#define BCM4331_PM_CAP		0x40
#define bcma_aread32(reg)	ioread32(mmio + 1 * BCMA_CORE_SIZE + reg)
#define bcma_awrite32(reg, val)	iowrite32(val, mmio + 1 * BCMA_CORE_SIZE + reg)

static void __init apple_airport_reset(int bus, int slot, int func)
{
	void __iomem *mmio;
	u16 pmcsr;
	u64 addr;
	int i;

	if (!dmi_match(DMI_SYS_VENDOR, "Apple Inc."))
		return;

	/* Card may have been put into PCI_D3hot by grub quirk */
	pmcsr = read_pci_config_16(bus, slot, func, BCM4331_PM_CAP + PCI_PM_CTRL);

	if ((pmcsr & PCI_PM_CTRL_STATE_MASK) != PCI_D0) {
		pmcsr &= ~PCI_PM_CTRL_STATE_MASK;
		write_pci_config_16(bus, slot, func, BCM4331_PM_CAP + PCI_PM_CTRL, pmcsr);
		mdelay(10);

		pmcsr = read_pci_config_16(bus, slot, func, BCM4331_PM_CAP + PCI_PM_CTRL);
		if ((pmcsr & PCI_PM_CTRL_STATE_MASK) != PCI_D0) {
			dev_err("Cannot power up Apple AirPort card\n");
			return;
		}
	}

	addr  =      read_pci_config(bus, slot, func, PCI_BASE_ADDRESS_0);
	addr |= (u64)read_pci_config(bus, slot, func, PCI_BASE_ADDRESS_1) << 32;
	addr &= PCI_BASE_ADDRESS_MEM_MASK;

	mmio = early_ioremap(addr, BCM4331_MMIO_SIZE);
	if (!mmio) {
		dev_err("Cannot iomap Apple AirPort card\n");
		return;
	}

	pr_info("Resetting Apple AirPort card (left enabled by EFI)\n");

	for (i = 0; bcma_aread32(BCMA_RESET_ST) && i < 30; i++)
		udelay(10);

	bcma_awrite32(BCMA_RESET_CTL, BCMA_RESET_CTL_RESET);
	bcma_aread32(BCMA_RESET_CTL);
	udelay(1);

	bcma_awrite32(BCMA_RESET_CTL, 0);
	bcma_aread32(BCMA_RESET_CTL);
	udelay(10);

	early_iounmap(mmio, BCM4331_MMIO_SIZE);
}

#define QFLAG_APPLY_ONCE 	0x1
#define QFLAG_APPLIED		0x2
#define QFLAG_DONE		(QFLAG_APPLY_ONCE|QFLAG_APPLIED)
struct chipset {
	u32 vendor;
	u32 device;
	u32 class;
	u32 class_mask;
	u32 flags;
	void (*f)(int num, int slot, int func);
};

static struct chipset early_qrk[] __initdata = {
	{ PCI_VENDOR_ID_NVIDIA, PCI_ANY_ID,
	  PCI_CLASS_BRIDGE_PCI, PCI_ANY_ID, QFLAG_APPLY_ONCE, nvidia_bugs },
	{ PCI_VENDOR_ID_VIA, PCI_ANY_ID,
	  PCI_CLASS_BRIDGE_PCI, PCI_ANY_ID, QFLAG_APPLY_ONCE, via_bugs },
	{ PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_K8_NB,
	  PCI_CLASS_BRIDGE_HOST, PCI_ANY_ID, 0, fix_hypertransport_config },
	{ PCI_VENDOR_ID_ATI, PCI_DEVICE_ID_ATI_IXP400_SMBUS,
	  PCI_CLASS_SERIAL_SMBUS, PCI_ANY_ID, 0, ati_bugs },
	{ PCI_VENDOR_ID_ATI, PCI_DEVICE_ID_ATI_SBX00_SMBUS,
	  PCI_CLASS_SERIAL_SMBUS, PCI_ANY_ID, 0, ati_bugs_contd },
	{ PCI_VENDOR_ID_BROADCOM, 0x4331,
	  PCI_CLASS_NETWORK_OTHER, PCI_ANY_ID, 0, apple_airport_reset},
	{}
};

static void __init early_pci_scan_bus(int bus);

/**
 * check_dev_quirk - apply early quirks to a given PCI device
 * @num: bus number
 * @slot: slot number
 * @func: PCI function
 *
 * Check the vendor & device ID against the early quirks table.
 *
 * If the device is single function, let early_pci_scan_bus() know so we don't
 * poke at this device again.
 */
static int __init check_dev_quirk(int num, int slot, int func)
{
	u16 class;
	u16 vendor;
	u16 device;
	u8 type;
	u8 sec;
	int i;

	class = read_pci_config_16(num, slot, func, PCI_CLASS_DEVICE);

	if (class == 0xffff)
		return -1; /* no class, treat as single function */

	vendor = read_pci_config_16(num, slot, func, PCI_VENDOR_ID);

	device = read_pci_config_16(num, slot, func, PCI_DEVICE_ID);

	for (i = 0; early_qrk[i].f != NULL; i++) {
		if (((early_qrk[i].vendor == PCI_ANY_ID) ||
			(early_qrk[i].vendor == vendor)) &&
			((early_qrk[i].device == PCI_ANY_ID) ||
			(early_qrk[i].device == device)) &&
			(!((early_qrk[i].class ^ class) &
			    early_qrk[i].class_mask))) {
				if ((early_qrk[i].flags &
				     QFLAG_DONE) != QFLAG_DONE)
					early_qrk[i].f(num, slot, func);
				early_qrk[i].flags |= QFLAG_APPLIED;
			}
	}

	type = read_pci_config_byte(num, slot, func,
				    PCI_HEADER_TYPE);

	if ((type & 0x7f) == PCI_HEADER_TYPE_BRIDGE) {
		sec = read_pci_config_byte(num, slot, func, PCI_SECONDARY_BUS);
		if (sec > num)
			early_pci_scan_bus(sec);
	}

	if (!(type & 0x80))
		return -1;

	return 0;
}

static void __init early_pci_scan_bus(int bus)
{
	int slot, func;

	/* Poor man's PCI discovery */
	for (slot = 0; slot < 32; slot++)
		for (func = 0; func < 8; func++) {
			/* Only probe function 0 on single fn devices */
			if (check_dev_quirk(bus, slot, func))
				break;
		}
}

void __init early_quirks(void)
{
	if (!early_pci_allowed())
		return;

	early_pci_scan_bus(0);
}
