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
#include <linux/of_platform.h>
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

#define ELOG_SIG_OFFSET              0x000
#define ELOG_SIG_VAL                 0x49444d45

#define ELOG_CUR_OFFSET              0x004
#define ELOG_LEN_OFFSET              0x008
#define ELOG_HEADER_LEN              12
#define ELOG_EVENT_LEN               64

#define ELOG_IDM_NAME_OFFSET         0x000
#define ELOG_IDM_ADDR_LSB_OFFSET     0x010
#define ELOG_IDM_ADDR_MSB_OFFSET     0x014
#define ELOG_IDM_ID_OFFSET           0x018
#define ELOG_IDM_CAUSE_OFFSET        0x020
#define ELOG_IDM_FLAG_OFFSET         0x028

#define ELOG_IDM_MAX_NAME_LEN        16

#define ELOG_IDM_COMPAT_STR          "brcm,iproc-idm-elog"

struct iproc_idm_elog {
	struct device *dev;
	void __iomem *buf;
	u32 len;
	spinlock_t lock;

	int (*idm_event_log)(struct iproc_idm_elog *elog, const char *name,
			     u32 cause, u32 addr_lsb, u32 addr_msb, u32 id,
			     u32 flag);
};

struct iproc_idm {
	struct device *dev;
	struct iproc_idm_elog *elog;
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

static int iproc_idm_event_log(struct iproc_idm_elog *elog, const char *name,
			       u32 cause, u32 addr_lsb, u32 addr_msb, u32 id,
			       u32 flag)
{
	u32 val, cur, len;
	void *event;
	unsigned long flags;

	spin_lock_irqsave(&elog->lock, flags);

	/*
	 * Check if signature is already there. If not, clear and restart
	 * everything
	 */
	val = readl(elog->buf + ELOG_SIG_OFFSET);
	if (val != ELOG_SIG_VAL) {
		memset_io(elog->buf, 0, elog->len);
		writel(ELOG_SIG_VAL, elog->buf + ELOG_SIG_OFFSET);
		writel(ELOG_HEADER_LEN, elog->buf + ELOG_CUR_OFFSET);
		writel(0, elog->buf + ELOG_LEN_OFFSET);
	}

	/* determine offset and length */
	cur = readl(elog->buf + ELOG_CUR_OFFSET);
	len = readl(elog->buf + ELOG_LEN_OFFSET);

	/*
	 * Based on the design and how kernel panic is triggered after an IDM
	 * event, it's practically impossible for the storage to be full. In
	 * case if it does happen, we can simply bail out since it's likely
	 * the same category of events that have already been logged
	 */
	if (cur + ELOG_EVENT_LEN > elog->len) {
		dev_warn(elog->dev, "IDM ELOG buffer is now full\n");
		spin_unlock_irqrestore(&elog->lock, flags);
		return -ENOMEM;
	}

	/* now log the IDM event */
	event = elog->buf + cur;
	strncpy(event, name, ELOG_IDM_MAX_NAME_LEN);
	writel(addr_lsb, event + ELOG_IDM_ADDR_LSB_OFFSET);
	writel(addr_msb, event + ELOG_IDM_ADDR_MSB_OFFSET);
	writel(id, event + ELOG_IDM_ID_OFFSET);
	writel(cause, event + ELOG_IDM_CAUSE_OFFSET);
	writel(flag, event + ELOG_IDM_FLAG_OFFSET);

	cur += ELOG_EVENT_LEN;
	len += ELOG_EVENT_LEN;

	/* update offset and length */
	writel(cur, elog->buf + ELOG_CUR_OFFSET);
	writel(len, elog->buf + ELOG_LEN_OFFSET);

	spin_unlock_irqrestore(&elog->lock, flags);

	return 0;
}

static irqreturn_t iproc_idm_irq_handler(int irq, void *data)
{
	struct iproc_idm *idm = data;
	struct device *dev = idm->dev;
	char *name = idm->name;
	u32 isr_status, log_status, lsb, msb, id, flag;
	struct iproc_idm_elog *elog = idm->elog;

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

	lsb = readl(idm->base + IDM_ADDR_LSB_OFFSET);
	msb = readl(idm->base + IDM_ADDR_MSB_OFFSET);
	id = readl(idm->base + IDM_ID_OFFSET);
	flag = readl(idm->base + IDM_FLAGS_OFFSET);

	dev_err(dev, "Cause: 0x%08x\n", log_status);
	dev_err(dev, "Address LSB: 0x%08x\n", lsb);
	dev_err(dev, "Address MSB: 0x%08x\n", msb);
	dev_err(dev, "Master ID: 0x%08x\n", id);
	dev_err(dev, "Flag: 0x%08x\n\n", flag);

	/* if elog service is available, log the event */
	if (elog) {
		elog->idm_event_log(elog, name, log_status, lsb, msb, id, flag);
		dev_err(dev, "IDM event logged\n\n");
	}

	/* IDM timeout is fatal and non-recoverable. Panic the kernel */
	if (!idm->no_panic)
		panic("Fatal bus error detected by IDM");

	return IRQ_HANDLED;
}

static int iproc_idm_dev_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;

	struct platform_device *elog_pdev;
	struct device_node *elog_np;

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

	/*
	 * ELOG phandle is optional. If ELOG phandle is specified, it indicates
	 * ELOG logging needs to be enabled
	 */
	elog_np = of_parse_phandle(dev->of_node, ELOG_IDM_COMPAT_STR, 0);
	if (elog_np) {
		elog_pdev = of_find_device_by_node(elog_np);
		if (!elog_pdev) {
			dev_err(dev, "Unable to find IDM ELOG device\n");
			ret = -ENODEV;
			goto err_iounmap;
		}

		idm->elog = platform_get_drvdata(elog_pdev);
		if (!idm->elog) {
			dev_err(dev, "Unable to get IDM ELOG driver data\n");
			ret = -EINVAL;
			goto err_iounmap;
		}
	}

	/* enable IDM timeout and its interrupt */
	val = readl(idm->base + IDM_CTRL_OFFSET);
	val |= IDM_CTRL_TIMEOUT_EXP_MASK | IDM_CTRL_TIMEOUT_ENABLE |
	       IDM_CTRL_TIMEOUT_IRQ;
	writel(val, idm->base + IDM_CTRL_OFFSET);

	ret = device_create_file(dev, &dev_attr_no_panic);
	if (ret < 0)
		goto err_iounmap;

	pr_info("iProc IDM device %s registered\n", idm->name);

	return 0;

err_iounmap:
	iounmap(idm->base);

err_exit:
	return ret;
}

static int iproc_idm_elog_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct iproc_idm_elog *elog;
	struct resource *res;

	elog = devm_kzalloc(dev, sizeof(*elog), GFP_KERNEL);
	if (!elog)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	elog->buf = (void __iomem *)devm_memremap(dev, res->start,
						  resource_size(res),
						  MEMREMAP_WB);
	if (IS_ERR(elog->buf)) {
		dev_err(dev, "Unable to map ELOG buffer\n");
		return PTR_ERR(elog->buf);
	}

	elog->dev = dev;
	elog->len = resource_size(res);
	elog->idm_event_log = iproc_idm_event_log;

	/* clear all logs */
	memset_io(elog->buf, 0, elog->len);

	spin_lock_init(&elog->lock);
	platform_set_drvdata(pdev, elog);

	dev_info(dev, "iProc IDM ELOG registered\n");

	return 0;
}

static int iproc_idm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	int ret;

	if (of_device_is_compatible(np, ELOG_IDM_COMPAT_STR))
		ret = iproc_idm_elog_probe(pdev);
	else
		ret = iproc_idm_dev_probe(pdev);

	return ret;
}

static const struct of_device_id iproc_idm_of_match[] = {
	{ .compatible = "brcm,iproc-idm", },
	{ .compatible = "brcm,iproc-idm-elog", },
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
