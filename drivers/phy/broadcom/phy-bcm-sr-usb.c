// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016-2018 Broadcom
 */

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>

enum bcm_usb_phy_version {
	BCM_USB_PHY_V1,
	BCM_USB_PHY_V2,
};

enum bcm_usb_phy_reg {
	PLL_NDIV_FRAC,
	PLL_NDIV_INT,
	PLL_CTRL,
	PHY_CTRL,
	PHY_PLL_CTRL,
};

/* USB PHY registers */

static const u8 bcm_usb_u3phy_v1[] = {
	[PLL_CTRL]		= 0x18,
	[PHY_CTRL]		= 0x14,
};

static const u8 bcm_usb_u2phy_v1[] = {
	[PLL_NDIV_FRAC]	= 0x04,
	[PLL_NDIV_INT]	= 0x08,
	[PLL_CTRL]	= 0x0c,
	[PHY_CTRL]	= 0x10,
};

#define HSPLL_NDIV_INT_VAL	0x13
#define HSPLL_NDIV_FRAC_VAL	0x1005

static const u8 bcm_usb_u2phy_v2[] = {
	[PLL_NDIV_FRAC]	= 0x0,
	[PLL_NDIV_INT]	= 0x4,
	[PLL_CTRL]	= 0x8,
	[PHY_CTRL]	= 0xc,
};

enum pll_ctrl_bits {
	PLL_RESETB,
	SSPLL_SUSPEND_EN,
	PLL_SEQ_START,
	PLL_LOCK,
	PLL_PDIV,
};

static const u8 u3pll_ctrl[] = {
	[PLL_RESETB]		= 0,
	[SSPLL_SUSPEND_EN]	= 1,
	[PLL_SEQ_START]		= 2,
	[PLL_LOCK]		= 3,
};

#define HSPLL_PDIV_MASK		0xF
#define HSPLL_PDIV_VAL		0x1

static const u8 u2pll_ctrl[] = {
	[PLL_PDIV]	= 1,
	[PLL_RESETB]	= 5,
	[PLL_LOCK]	= 6,
};

enum bcm_usb_phy_ctrl_bits {
	CORERDY,
	AFE_LDO_PWRDWNB,
	AFE_PLL_PWRDWNB,
	AFE_BG_PWRDWNB,
	PHY_ISO,
	PHY_RESETB,
	PHY_PCTL,
};

#define PHY_PCTL_MASK	0xffff
/*
 * 0x0806 of PCTL_VAL has below bits set
 * BIT-8 : refclk divider 1
 * BIT-3:2: device mode; mode is not effect
 * BIT-1: soft reset active low
 */
#define HSPHY_PCTL_VAL	0x0806
#define SSPHY_PCTL_VAL	0x0006

static const u8 u3phy_ctrl[] = {
	[PHY_RESETB]	= 1,
	[PHY_PCTL]	= 2,
};

static const u8 u2phy_ctrl[] = {
	[CORERDY]		= 0,
	[AFE_LDO_PWRDWNB]	= 1,
	[AFE_PLL_PWRDWNB]	= 2,
	[AFE_BG_PWRDWNB]	= 3,
	[PHY_ISO]		= 4,
	[PHY_RESETB]		= 5,
	[PHY_PCTL]		= 6,
};

struct bcm_usb_phy_cfg {
	uint32_t type;
	uint32_t ver;
	void __iomem *regs;
	struct phy *phy;
	const u8 *offset;
};

#define PLL_LOCK_RETRY_COUNT	1000

enum bcm_usb_phy_type {
	USB_HS_PHY,
	USB_SS_PHY,
};

static inline void bcm_usb_reg32_clrbits(void __iomem *addr, uint32_t clear)
{
	writel(readl(addr) & ~clear, addr);
}

static inline void bcm_usb_reg32_setbits(void __iomem *addr, uint32_t set)
{
	writel(readl(addr) | set, addr);
}

static int bcm_usb_pll_lock_check(void __iomem *addr, u32 bit)
{
	int retry;
	u32 rd_data;

	retry = PLL_LOCK_RETRY_COUNT;
	do {
		rd_data = readl(addr);
		if (rd_data & bit)
			return 0;
		udelay(1);
	} while (--retry > 0);

	pr_err("%s: FAIL\n", __func__);
	return -ETIMEDOUT;
}

static int bcm_usb_ss_phy_init(struct bcm_usb_phy_cfg *phy_cfg)
{
	int ret = 0;
	void __iomem *regs = phy_cfg->regs;
	const u8 *offset;
	u32 rd_data;

	offset = phy_cfg->offset;

	/* Set pctl with mode and soft reset */
	rd_data = readl(regs + offset[PHY_CTRL]);
	rd_data &= ~(PHY_PCTL_MASK << u3phy_ctrl[PHY_PCTL]);
	rd_data |= (SSPHY_PCTL_VAL << u3phy_ctrl[PHY_PCTL]);
	writel(rd_data, regs + offset[PHY_CTRL]);

	bcm_usb_reg32_clrbits(regs + offset[PLL_CTRL],
			      BIT(u3pll_ctrl[SSPLL_SUSPEND_EN]));
	bcm_usb_reg32_setbits(regs + offset[PLL_CTRL],
			      BIT(u3pll_ctrl[PLL_SEQ_START]));
	bcm_usb_reg32_setbits(regs + offset[PLL_CTRL],
			      BIT(u3pll_ctrl[PLL_RESETB]));

	/* Maximum timeout for PLL reset done */
	msleep(30);

	ret = bcm_usb_pll_lock_check(regs + offset[PLL_CTRL],
				     BIT(u3pll_ctrl[PLL_LOCK]));

	return ret;
}

static int bcm_usb_hs_phy_init(struct bcm_usb_phy_cfg *phy_cfg)
{
	int ret = 0;
	void __iomem *regs = phy_cfg->regs;
	const u8 *offset;
	u32 rd_data;

	offset = phy_cfg->offset;

	writel(HSPLL_NDIV_INT_VAL, regs + offset[PLL_NDIV_INT]);
	writel(HSPLL_NDIV_FRAC_VAL, regs + offset[PLL_NDIV_FRAC]);

	rd_data = readl(regs + offset[PLL_CTRL]);
	rd_data &= ~(HSPLL_PDIV_MASK << u2pll_ctrl[PLL_PDIV]);
	rd_data |= (HSPLL_PDIV_VAL << u2pll_ctrl[PLL_PDIV]);
	writel(rd_data, regs + offset[PLL_CTRL]);

	/* Set Core Ready high */
	bcm_usb_reg32_setbits(regs + offset[PHY_CTRL],
			      BIT(u2phy_ctrl[CORERDY]));

	/* Maximum timeout for Core Ready done */
	msleep(30);

	bcm_usb_reg32_setbits(regs + offset[PLL_CTRL],
			      BIT(u2pll_ctrl[PLL_RESETB]));
	bcm_usb_reg32_setbits(regs + offset[PHY_CTRL],
			      BIT(u2phy_ctrl[PHY_RESETB]));


	rd_data = readl(regs + offset[PHY_CTRL]);
	rd_data &= ~(PHY_PCTL_MASK << u2phy_ctrl[PHY_PCTL]);
	rd_data |= (HSPHY_PCTL_VAL << u2phy_ctrl[PHY_PCTL]);
	writel(rd_data, regs + offset[PHY_CTRL]);

	/* Maximum timeout for PLL reset done */
	msleep(30);

	ret = bcm_usb_pll_lock_check(regs + offset[PLL_CTRL],
				     BIT(u2pll_ctrl[PLL_LOCK]));

	return ret;
}

static int bcm_usb_phy_reset(struct phy *phy)
{
	struct bcm_usb_phy_cfg *phy_cfg = phy_get_drvdata(phy);
	void __iomem *regs = phy_cfg->regs;
	const u8 *offset;

	offset = phy_cfg->offset;

	if (phy_cfg->type == USB_HS_PHY) {
		bcm_usb_reg32_clrbits(regs + offset[PHY_CTRL],
				      BIT(u2phy_ctrl[CORERDY]));
		bcm_usb_reg32_setbits(regs + offset[PHY_CTRL],
				      BIT(u2phy_ctrl[CORERDY]));
	}

	return 0;
}

static int bcm_usb_phy_init(struct phy *phy)
{
	struct bcm_usb_phy_cfg *phy_cfg = phy_get_drvdata(phy);
	int ret = -EINVAL;

	if (phy_cfg->type == USB_SS_PHY)
		ret = bcm_usb_ss_phy_init(phy_cfg);
	else if (phy_cfg->type == USB_HS_PHY)
		ret = bcm_usb_hs_phy_init(phy_cfg);

	return ret;
}

static struct phy_ops sr_phy_ops = {
	.init		= bcm_usb_phy_init,
	.reset		= bcm_usb_phy_reset,
	.owner		= THIS_MODULE,
};

static int bcm_usb_phy_create(struct device *dev, struct device_node *node,
			     void __iomem *regs, uint32_t version)
{
	struct bcm_usb_phy_cfg *phy_cfg;
	struct phy_provider *phy_provider;

	phy_cfg = devm_kzalloc(dev, sizeof(struct bcm_usb_phy_cfg), GFP_KERNEL);
	if (!phy_cfg)
		return -ENOMEM;

	phy_cfg->regs = regs;
	phy_cfg->ver = version;

	if (phy_cfg->ver == BCM_USB_PHY_V1) {
		unsigned int id;

		if (of_property_read_u32(node, "reg", &id)) {
			dev_err(dev, "missing reg property in node %s\n",
				node->name);
			return -EINVAL;
		}

		if (id == 0) {
			phy_cfg->offset = bcm_usb_u2phy_v1;
			phy_cfg->type = USB_HS_PHY;
		} else if (id == 1) {
			phy_cfg->offset = bcm_usb_u3phy_v1;
			phy_cfg->type = USB_SS_PHY;
		} else {
			return -ENODEV;
		}
	} else if (phy_cfg->ver == BCM_USB_PHY_V2) {
		phy_cfg->offset = bcm_usb_u2phy_v2;
		phy_cfg->type = USB_HS_PHY;
	}

	phy_cfg->phy = devm_phy_create(dev, node, &sr_phy_ops);
	if (IS_ERR(phy_cfg->phy))
		return PTR_ERR(phy_cfg->phy);

	phy_set_drvdata(phy_cfg->phy, phy_cfg);
	phy_provider = devm_of_phy_provider_register(&phy_cfg->phy->dev,
						     of_phy_simple_xlate);
	if (IS_ERR(phy_provider)) {
		dev_err(dev, "Failed to register phy provider\n");
		return PTR_ERR(phy_provider);
	}

	return 0;
}

static const struct of_device_id bcm_usb_phy_of_match[] = {
	{
		.compatible = "brcm,sr-usb-phy",
		.data = (void *)BCM_USB_PHY_V1,
	},
	{
		.compatible = "brcm,sr-usb-phy-v2",
		.data = (void *)BCM_USB_PHY_V2,
	},
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, bcm_usb_phy_of_match);

static int bcm_usb_phy_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *dn = dev->of_node, *child;
	const struct of_device_id *of_id;
	struct resource *res;
	void __iomem *regs;
	int ret;
	enum bcm_usb_phy_version version;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(regs))
		return PTR_ERR(regs);

	of_id = of_match_node(bcm_usb_phy_of_match, dn);
	if (of_id)
		version = (enum bcm_usb_phy_version)of_id->data;
	else
		return -ENODEV;

	if (of_get_child_count(dn) == 0)
		return bcm_usb_phy_create(dev, dn, regs, version);

	for_each_available_child_of_node(dn, child) {
		ret = bcm_usb_phy_create(dev, child, regs, version);
		if (ret) {
			of_node_put(child);
			return ret;
		}
	}

	return 0;
}

static struct platform_driver bcm_usb_phy_driver = {
	.driver = {
		.name = "phy-bcm-sr-usb",
		.of_match_table = bcm_usb_phy_of_match,
	},
	.probe = bcm_usb_phy_probe,
};
module_platform_driver(bcm_usb_phy_driver);

MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("Broadcom stingray USB Phy driver");
MODULE_LICENSE("GPL v2");
