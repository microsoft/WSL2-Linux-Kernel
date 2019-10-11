// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Broadcom
 */
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>

#define IDM_CTRL_OFFSET              0x000
#define IDM_CTRL_TIMEOUT_ENABLE      BIT(9)
#define IDM_CTRL_TIMEOUT_EXP_SHIFT   4
#define IDM_CTRL_TIMEOUT_EXP_MASK    (0x1f << 4)
#define IDM_CTRL_TIMEOUT_IRQ         BIT(3)
#define IDM_CTRL_TIMEOUT_RESET       BIT(2)
#define IDM_CTRL_BUS_ERR_IRQ         BIT(1)
#define IDM_CTRL_BUS_ERR_RESET       BIT(0)

#define IDM_COMP_OFFSET              0x004
#define IDM_COMP_OVERFLOW            BIT(1)
#define IDM_COMP_ERR                 BIT(0)

#define IDM_STATUS_OFFSET            0x008
#define IDM_STATUS_OVERFLOW          BIT(2)
#define IDM_STATUS_CAUSE_MASK        0x03

#define IDM_ADDR_LSB_OFFSET          0x00c
#define IDM_ADDR_MSB_OFFSET          0x010
#define IDM_ID_OFFSET                0x014
#define IDM_FLAGS_OFFSET             0x01c

#define IDM_ISR_STATUS_OFFSET        0x100
#define IDM_ISR_STATUS_TIMEOUT       BIT(1)
#define IDM_ISR_STATUS_ERR_LOG       BIT(0)

struct iproc_idm {
	struct device *dev;
	void __iomem *base;
	char name[25];
	bool no_panic;
};

static ssize_t no_panic_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct iproc_idm *idm = platform_get_drvdata(pdev);
	unsigned int no_panic;
	int ret;

	ret = kstrtouint(buf, 0, &no_panic);
	if (ret)
		return ret;

	idm->no_panic = no_panic ? true : false;

	return count;
}

static ssize_t no_panic_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct iproc_idm *idm = platform_get_drvdata(pdev);

	return sprintf(buf, "%u\n", idm->no_panic ? 1 : 0);
}

static DEVICE_ATTR_RW(no_panic);

static irqreturn_t iproc_idm_irq_handler(int irq, void *data)
{
	struct iproc_idm *idm = data;
	struct device *dev = idm->dev;
	char *name = idm->name;
	u32 isr_status, log_status;

	isr_status = readl(idm->base + IDM_ISR_STATUS_OFFSET);
	log_status = readl(idm->base + IDM_STATUS_OFFSET);

	/* quit if the interrupt is not for IDM */
	if (!isr_status)
		return IRQ_NONE;

	/* ACK the interrupt */
	if (log_status & IDM_STATUS_OVERFLOW)
		writel(IDM_COMP_OVERFLOW, idm->base + IDM_COMP_OFFSET);

	if (log_status & IDM_STATUS_CAUSE_MASK)
		writel(IDM_COMP_ERR, idm->base + IDM_COMP_OFFSET);

	/* dump critical IDM information */
	if (isr_status & IDM_ISR_STATUS_TIMEOUT)
		dev_err(dev, "[%s] IDM timeout\n", name);

	if (isr_status & IDM_ISR_STATUS_ERR_LOG)
		dev_err(dev, "[%s] IDM error log\n", name);

	dev_err(dev, "Cause: 0x%08x\n", log_status);
	dev_err(dev, "Address LSB: 0x%08x\n",
		readl(idm->base + IDM_ADDR_LSB_OFFSET));
	dev_err(dev, "Address MSB: 0x%08x\n",
		readl(idm->base + IDM_ADDR_MSB_OFFSET));
	dev_err(dev, "Master ID: 0x%08x\n",
		readl(idm->base + IDM_ID_OFFSET));
	dev_err(dev, "Flag: 0x%08x\n",
		readl(idm->base + IDM_FLAGS_OFFSET));

	/* IDM timeout is fatal and non-recoverable. Panic the kernel */
	if (!idm->no_panic)
		panic("Fatal bus error detected by IDM");

	return IRQ_HANDLED;
}

static int iproc_idm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct iproc_idm *idm;
	int ret = 0;
	u32 val;

	idm = devm_kzalloc(dev, sizeof(*idm), GFP_KERNEL);
	if (!idm)
		return -ENOMEM;

	platform_set_drvdata(pdev, idm);
	idm->dev = dev;
	strncpy(idm->name, np->name, sizeof(idm->name));
	idm->base = of_iomap(np, 0);
	if (!idm->base) {
		dev_err(dev, "Unable to map I/O\n");
		ret = -ENOMEM;
		goto err_exit;
	}

	ret = of_irq_get(np, 0);
	if (ret <= 0) {
		dev_err(dev, "Unable to find IRQ number. ret=%d\n", ret);
		goto err_iounmap;
	}

	ret = devm_request_irq(dev, ret, iproc_idm_irq_handler, IRQF_SHARED,
			       idm->name, idm);
	if (ret < 0) {
		dev_err(dev, "Unable to request irq. ret=%d\n", ret);
		goto err_iounmap;
	}

	/* enable IDM timeout and its interrupt */
	val = readl(idm->base + IDM_CTRL_OFFSET);
	val |= IDM_CTRL_TIMEOUT_EXP_MASK | IDM_CTRL_TIMEOUT_ENABLE |
	       IDM_CTRL_TIMEOUT_IRQ;
	writel(val, idm->base + IDM_CTRL_OFFSET);

	ret = device_create_file(dev, &dev_attr_no_panic);
	if (ret < 0)
		goto err_iounmap;

	pr_info("Stingray IDM device %s registered\n", idm->name);

	return 0;

err_iounmap:
	iounmap(idm->base);

err_exit:
	return ret;
}

static const struct of_device_id iproc_idm_of_match[] = {
	{ .compatible = "brcm,iproc-idm", },
	{ .compatible = "brcm,sr-idm-paxb0-axi", },
	{ .compatible = "brcm,sr-idm-paxb1-axi", },
	{ .compatible = "brcm,sr-idm-paxb2-axi", },
	{ .compatible = "brcm,sr-idm-paxb3-axi", },
	{ .compatible = "brcm,sr-idm-pcie-axi", },
	{ .compatible = "brcm,sr-idm-paxb4-axi", },
	{ .compatible = "brcm,sr-idm-paxb5-axi", },
	{ .compatible = "brcm,sr-idm-paxb6-axi", },
	{ .compatible = "brcm,sr-idm-paxb7-axi", },
	{ .compatible = "brcm,sr-idm-mhb-nitro-axi", },
	{ .compatible = "brcm,sr-idm-mhb-pcie-axi", },
	{ .compatible = "brcm,sr-idm-mhb-ep-apb", },
	{ .compatible = "brcm,sr-idm-mhb-paxc-axi", },
	{ .compatible = "brcm,sr-idm-mhb-apb", },
	{ .compatible = "brcm,sr-idm-mhb-paxc-apb", },
	{ .compatible = "brcm,sr-idm-nic-axi2apb", },
	{ .compatible = "brcm,sr-idm-nic-chimp", },
	{ .compatible = "brcm,sr-idm-nic-ds0", },
	{ .compatible = "brcm,sr-idm-scr-pcie0", },
	{ .compatible = "brcm,sr-idm-scr-pcie1", },
	{ .compatible = "brcm,sr-idm-scr-paxc", },
	{ .compatible = "brcm,sr-idm-scr-fs", },
	{ .compatible = "brcm,sr-idm-scr-hsls", },
	{ .compatible = "brcm,sr-idm-scr-crmu", },
	{ .compatible = "brcm,sr-idm-scr-usb", },
	{ .compatible = "brcm,sr-idm-scr-axi2apb-div4", },
	{ .compatible = "brcm,sr-idm-scr-axi2apb-div4-emem", },
	{ .compatible = "brcm,sr-idm-scr-axi2apb-cssys", },
	{ .compatible = "brcm,sr-idm-scr-smmu", },
	{ .compatible = "brcm,sr-idm-scr-gic500", },
	{ .compatible = "brcm,sr-idm-scr-sata", },
	{ .compatible = "brcm,sr-idm-scr-cssys-stm-axi", },
	{ .compatible = "brcm,sr-idm-scr-ds0", },
	{ .compatible = "brcm,sr-idm-fs4-axi2apb-div2", },
	{ .compatible = "brcm,sr-idm-fs4-axi2apb", },
	{ .compatible = "brcm,sr-idm-fs4-sram", },
	{ .compatible = "brcm,sr-idm-fs4-crypto", },
	{ .compatible = "brcm,sr-idm-fs4-raid", },
	{ .compatible = "brcm,sr-idm-sata-apbt0", },
	{ .compatible = "brcm,sr-idm-sata-apbt1", },
	{ .compatible = "brcm,sr-idm-sata-reodrder-bridge", },
	{ .compatible = "brcm,sr-idm-sata-apbs", },
	{ .compatible = "brcm,sr-idm-drdu3", },
	{ .compatible = "brcm,sr-idm-drdu2", },
	{ .compatible = "brcm,sr-idm-usb3h", },
	{ .compatible = "brcm,sr-idm-gbridge", },
	{ .compatible = "brcm,sr-idm-rom-s0", },
	{ .compatible = "brcm,sr-idm-nand", },
	{ .compatible = "brcm,sr-idm-pnor", },
	{ .compatible = "brcm,sr-idm-qspi", },
	{ .compatible = "brcm,sr-idm-apbr", },
	{ .compatible = "brcm,sr-idm-apbspi", },
	{ .compatible = "brcm,sr-idm-apbx", },
	{ .compatible = "brcm,sr-idm-apby", },
	{ .compatible = "brcm,sr-idm-apbz", },
	{ .compatible = "brcm,sr-idm-sdio0-axi2ahb", },
	{ .compatible = "brcm,sr-idm-sdio1-axi2ahb", },
	{ }
};

static struct platform_driver iproc_idm_driver = {
	.probe = iproc_idm_probe,
	.driver = {
		.name = "iproc-idm",
		.of_match_table = of_match_ptr(iproc_idm_of_match),
	},
};

static int __init iproc_idm_init(void)
{
	return platform_driver_register(&iproc_idm_driver);
}
arch_initcall(iproc_idm_init);

static void __exit iproc_idm_exit(void)
{
	platform_driver_unregister(&iproc_idm_driver);
}
module_exit(iproc_idm_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("iProc IDM driver");
