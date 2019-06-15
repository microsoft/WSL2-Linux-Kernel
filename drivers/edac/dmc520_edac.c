// SPDX-License-Identifier: GPL-2.0
/* EDAC driver for DMC-520 */


#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/edac.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/interrupt.h>
#include <linux/bitfield.h>
#include "edac_mc.h"

/* DMC-520 registers */
#define REG_OFFSET_FEATURE_CONFIG		0x130
#define REG_OFFSET_ECC_ERRC_COUNT_31_00		0x158
#define REG_OFFSET_ECC_ERRC_COUNT_63_32		0x15C
#define REG_OFFSET_ECC_ERRD_COUNT_31_00		0x160
#define REG_OFFSET_ECC_ERRD_COUNT_63_32		0x164
#define REG_OFFSET_FEATURE_CONTROL_NEXT		0x1F0
#define REG_OFFSET_INTERRUPT_CONTROL		0x500
#define REG_OFFSET_INTERRUPT_CLR		0x508
#define REG_OFFSET_INTERRUPT_STATUS		0x510
#define REG_OFFSET_DRAM_ECC_ERRC_INT_INFO_31_00	0x528
#define REG_OFFSET_DRAM_ECC_ERRC_INT_INFO_63_32	0x52C
#define REG_OFFSET_DRAM_ECC_ERRD_INT_INFO_31_00	0x530
#define REG_OFFSET_DRAM_ECC_ERRD_INT_INFO_63_32	0x534
#define REG_OFFSET_ADDRESS_CONTROL_NOW		0x1010
#define REG_OFFSET_DECODE_CONTROL_NOW		0x1014
#define REG_OFFSET_MEMORY_TYPE_NOW		0x1128
#define REG_OFFSET_SCRUB_CONTROL0_NOW		0x1170

/* DMC-520 types, masks and bitfields */
#define DRAM_ECC_INT_CE_MASK			BIT(2)
#define DRAM_ECC_INT_UE_MASK			BIT(3)
#define ALL_INT_MASK				GENMASK(9, 0)
#define SCRUB_CONTROL_MASK			GENMASK(1, 0)

#define REG_FIELD_DRAM_ECC_ENABLED		GENMASK(1, 0)
#define REG_FIELD_MEMORY_TYPE			GENMASK(2, 0)
#define REG_FIELD_DEVICE_WIDTH			GENMASK(9, 8)
#define REG_FIELD_ADDRESS_CONTROL_COL		GENMASK(2, 0)
#define REG_FIELD_ADDRESS_CONTROL_ROW		GENMASK(10, 8)
#define REG_FIELD_ADDRESS_CONTROL_BANK		GENMASK(18, 16)
#define REG_FIELD_ADDRESS_CONTROL_RANK		GENMASK(25, 24)
#define REG_FIELD_ERR_INFO_LOW_VALID		BIT(0)
#define REG_FIELD_ERR_INFO_LOW_COL		GENMASK(10, 1)
#define REG_FIELD_ERR_INFO_LOW_ROW		GENMASK(28, 11)
#define REG_FIELD_ERR_INFO_LOW_RANK		GENMASK(31, 29)
#define REG_FIELD_ERR_INFO_HIGH_BANK		GENMASK(3, 0)
#define REG_FIELD_ERR_INFO_HIGH_VALID		BIT(31)

#define DRAM_ADDRESS_CONTROL_MIN_COL_BITS	8
#define DRAM_ADDRESS_CONTROL_MIN_ROW_BITS	11
#define DMC520_EDAC_ERR_GRAIN			1
#define DMC520_BUS_WIDTH			8	/* Data bus width is 64bits/8Bytes */

#define DMC520_SCRUB_TRIGGER_ERR_DETECT		2
#define DMC520_SCRUB_TRIGGER_IDLE			3

/* Driver settings */
/* The max-length message would be: "rank:7 bank:15 row:262143 col:1023".
 * Max length is 34. Using a 40-size buffer is enough.
 */
#define EDAC_MSG_BUF_SIZE			40
#define EDAC_MOD_NAME				"dmc520-edac"
#define EDAC_CTL_NAME				"dmc520"

/* memory type */
enum dmc520_mem_type {
	mem_type_ddr3 = 1,
	mem_type_ddr4 = 2
};

/* memory device width */
enum dmc520_dev_width {
	dev_width_x4 = 0,
	dev_width_x8 = 1,
	dev_width_x16 = 2
};

struct ecc_error_info {
	u32 col;
	u32 row;
	u32 bank;
	u32 rank;
};

/* The EDAC driver private data */
struct dmc520_edac {
	void __iomem *reg_base;
	u32 nintr;
	u32 interrupt_mask_all;
	spinlock_t ecc_lock;
	u32 interrupt_masks[0];
};

static int dmc520_mc_idx;

static irqreturn_t
dmc520_edac_dram_all_isr(int irq, void *data, u32 interrupt_mask);

#define DECLARE_ISR(index) \
static irqreturn_t dmc520_isr_##index (int irq, void *data) \
{ \
	struct mem_ctl_info *mci; \
	struct dmc520_edac *edac; \
	mci = data; \
	edac = mci->pvt_info; \
	return dmc520_edac_dram_all_isr(irq, data, edac->interrupt_masks[index]); \
}

DECLARE_ISR(0)
DECLARE_ISR(1)
/* More DECLARE_ISR(index) can be added to support more interrupt lines. */

irq_handler_t dmc520_isr_array[] = {
	dmc520_isr_0,
	dmc520_isr_1
	/* More dmc520_isr_index can be added to support more interrupt lines. */
};

static u32 dmc520_read_reg(struct dmc520_edac *edac, u32 offset)
{
	return readl(edac->reg_base + offset);
}

static void dmc520_write_reg(struct dmc520_edac *edac, u32 val, u32 offset)
{
	writel(val, edac->reg_base + offset);
}

static u32 dmc520_calc_dram_ecc_error(u32 value)
{
	u32 total = 0;

	/* Each rank's error counter takes one byte */
	while (value > 0) {
		total += (value & 0xFF);
		value >>= 8;
	}
	return total;
}

static u32 dmc520_get_dram_ecc_error_count(struct dmc520_edac *edac,
					   bool is_ce)
{
	u32 reg_offset_low, reg_offset_high;
	u32 err_low, err_high;
	u32 err_count;

	reg_offset_low = is_ce ? REG_OFFSET_ECC_ERRC_COUNT_31_00 :
				 REG_OFFSET_ECC_ERRD_COUNT_31_00;
	reg_offset_high = is_ce ? REG_OFFSET_ECC_ERRC_COUNT_63_32 :
				  REG_OFFSET_ECC_ERRD_COUNT_63_32;

	err_low = dmc520_read_reg(edac, reg_offset_low);
	err_high = dmc520_read_reg(edac, reg_offset_high);
	/* Reset error counters */
	dmc520_write_reg(edac, 0, reg_offset_low);
	dmc520_write_reg(edac, 0, reg_offset_high);

	err_count = dmc520_calc_dram_ecc_error(err_low) +
		   dmc520_calc_dram_ecc_error(err_high);

	return err_count;
}

static bool dmc520_get_dram_ecc_error_info(struct dmc520_edac *edac,
					   bool is_ce,
					   struct ecc_error_info *info)
{
	u32 reg_offset_low, reg_offset_high;
	u32 reg_val_low, reg_val_high;
	bool valid;

	reg_offset_low = is_ce ? REG_OFFSET_DRAM_ECC_ERRC_INT_INFO_31_00 :
				 REG_OFFSET_DRAM_ECC_ERRD_INT_INFO_31_00;
	reg_offset_high = is_ce ? REG_OFFSET_DRAM_ECC_ERRC_INT_INFO_63_32 :
				  REG_OFFSET_DRAM_ECC_ERRD_INT_INFO_63_32;

	reg_val_low = dmc520_read_reg(edac, reg_offset_low);
	reg_val_high = dmc520_read_reg(edac, reg_offset_high);

	valid = (FIELD_GET(REG_FIELD_ERR_INFO_LOW_VALID, reg_val_low) != 0) &&
		(FIELD_GET(REG_FIELD_ERR_INFO_HIGH_VALID, reg_val_high) != 0);

	if (valid) {
		info->col = FIELD_GET(REG_FIELD_ERR_INFO_LOW_COL, reg_val_low);
		info->row = FIELD_GET(REG_FIELD_ERR_INFO_LOW_ROW, reg_val_low);
		info->rank = FIELD_GET(REG_FIELD_ERR_INFO_LOW_RANK, reg_val_low);
		info->bank = FIELD_GET(REG_FIELD_ERR_INFO_HIGH_BANK, reg_val_high);
	} else {
		memset(info, 0, sizeof(struct ecc_error_info));
	}

	return valid;
}

static bool dmc520_is_ecc_enabled(void __iomem *reg_base)
{
	u32 reg_val = readl(reg_base + REG_OFFSET_FEATURE_CONFIG);

	return (FIELD_GET(REG_FIELD_DRAM_ECC_ENABLED, reg_val) != 0);
}

static bool dmc520_get_scrub_type(struct dmc520_edac *edac)
{
	enum scrub_type type = SCRUB_NONE;
	u32 reg_val, scrub_cfg;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_SCRUB_CONTROL0_NOW);
	scrub_cfg = FIELD_GET(SCRUB_CONTROL_MASK, reg_val);

	if (DMC520_SCRUB_TRIGGER_ERR_DETECT == scrub_cfg ||
		DMC520_SCRUB_TRIGGER_IDLE == scrub_cfg)
		type = SCRUB_HW_PROG;

	return type;
}

static enum mem_type dmc520_get_mtype(struct dmc520_edac *edac)
{
	enum mem_type mt = MEM_UNKNOWN;
	u32 reg_val;
	enum dmc520_mem_type type;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_MEMORY_TYPE_NOW);
	type = FIELD_GET(REG_FIELD_MEMORY_TYPE, reg_val);

	switch (type) {
	case mem_type_ddr3:
		mt = MEM_DDR3;
		break;

	case mem_type_ddr4:
		mt = MEM_DDR4;
		break;
	}

	return mt;
}

static enum dev_type dmc520_get_dtype(struct dmc520_edac *edac)
{
	enum dev_type dt = DEV_UNKNOWN;
	u32 reg_val;
	enum dmc520_dev_width device_width;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_MEMORY_TYPE_NOW);
	device_width = FIELD_GET(REG_FIELD_DEVICE_WIDTH, reg_val);

	switch (device_width) {
	case dev_width_x4:
		dt = DEV_X4;
		break;

	case dev_width_x8:
		dt = DEV_X8;
		break;

	case dev_width_x16:
		dt = DEV_X16;
		break;
	}

	return dt;
}

static u32 dmc520_get_rank_count(void __iomem *reg_base)
{
	u32 reg_val, rank_bits;

	reg_val = readl(reg_base + REG_OFFSET_ADDRESS_CONTROL_NOW);
	rank_bits = FIELD_GET(REG_FIELD_ADDRESS_CONTROL_RANK, reg_val);

	return (1 << rank_bits);
}

static u64 dmc520_get_rank_size(struct dmc520_edac *edac)
{
	u32 reg_val, col_bits, row_bits, bank_bits;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_ADDRESS_CONTROL_NOW);

	col_bits = FIELD_GET(REG_FIELD_ADDRESS_CONTROL_COL, reg_val) +
		   DRAM_ADDRESS_CONTROL_MIN_COL_BITS;
	row_bits = FIELD_GET(REG_FIELD_ADDRESS_CONTROL_ROW, reg_val) +
		   DRAM_ADDRESS_CONTROL_MIN_ROW_BITS;
	bank_bits = FIELD_GET(REG_FIELD_ADDRESS_CONTROL_BANK, reg_val);

	return (u64)DMC520_BUS_WIDTH << (col_bits + row_bits + bank_bits);
}

static void dmc520_handle_dram_ecc_errors(struct mem_ctl_info *mci,
					  bool is_ce)
{
	struct ecc_error_info info;
	struct dmc520_edac *edac;
	u32 cnt;
	char message[EDAC_MSG_BUF_SIZE];
	unsigned long flags;

	edac = mci->pvt_info;
	dmc520_get_dram_ecc_error_info(edac, is_ce, &info);

	cnt = dmc520_get_dram_ecc_error_count(edac, is_ce);

	if (cnt > 0) {
		snprintf(message, ARRAY_SIZE(message),
			 "rank:%d bank:%d row:%d col:%d",
			 info.rank, info.bank,
			 info.row, info.col);

		spin_lock_irqsave(&edac->ecc_lock, flags);
		edac_mc_handle_error((is_ce ? HW_EVENT_ERR_CORRECTED :
				     HW_EVENT_ERR_UNCORRECTED),
				     mci, cnt, 0, 0, 0, info.rank, -1, -1,
				     message, "");
		spin_unlock_irqrestore(&edac->ecc_lock, flags);
	}
}

static irqreturn_t dmc520_edac_dram_ecc_isr(int irq, void *data, bool is_ce)
{
	u32 i_mask;
	struct mem_ctl_info *mci;
	struct dmc520_edac *edac;

	mci = data;
	edac = mci->pvt_info;

	i_mask = is_ce ? DRAM_ECC_INT_CE_MASK : DRAM_ECC_INT_UE_MASK;

	dmc520_handle_dram_ecc_errors(mci, is_ce);

	dmc520_write_reg(edac, i_mask, REG_OFFSET_INTERRUPT_CLR);

	return IRQ_HANDLED;
}

static irqreturn_t
dmc520_edac_dram_all_isr(int irq, void *data, u32 interrupt_mask)
{
	struct mem_ctl_info *mci;
	struct dmc520_edac *edac;
	u32 status;
	irqreturn_t irq_ret = IRQ_NONE;

	mci = data;
	edac = mci->pvt_info;

	status = dmc520_read_reg(edac, REG_OFFSET_INTERRUPT_STATUS);

	if ((interrupt_mask & DRAM_ECC_INT_CE_MASK) &&
		(status & DRAM_ECC_INT_CE_MASK))
		irq_ret = dmc520_edac_dram_ecc_isr(irq, data, true);

	if ((interrupt_mask & DRAM_ECC_INT_UE_MASK) &&
		(status & DRAM_ECC_INT_UE_MASK))
		irq_ret = dmc520_edac_dram_ecc_isr(irq, data, false);

	/* If in the future there are more supported interrupts in a different
	 * platform, more condition statements can be added here for each
	 * interrupt flag, together with its corresponding isr implementations.
	 */

	return irq_ret;
}

static void dmc520_init_csrow(struct mem_ctl_info *mci)
{
	struct csrow_info *csi;
	struct dimm_info *dimm;
	int row, ch;
	enum dev_type dt;
	enum mem_type mt;
	u64 rs;
	u32 pages_per_rank;
	struct dmc520_edac *edac = mci->pvt_info;

	dt = dmc520_get_dtype(edac);
	mt = dmc520_get_mtype(edac);
	rs = dmc520_get_rank_size(edac);
	pages_per_rank = rs >> PAGE_SHIFT;

	for (row = 0; row < mci->nr_csrows; row++) {
		csi = mci->csrows[row];

		for (ch = 0; ch < csi->nr_channels; ch++) {
			dimm		= csi->channels[ch]->dimm;
			dimm->grain	= DMC520_EDAC_ERR_GRAIN;
			dimm->dtype	= dt;
			dimm->mtype	= mt;
			dimm->edac_mode	= EDAC_FLAG_SECDED;
			dimm->nr_pages	= pages_per_rank / csi->nr_channels;
		}
	}
}

static int dmc520_edac_probe(struct platform_device *pdev)
{
	struct device *dev;
	struct dmc520_edac *edac;
	struct mem_ctl_info *mci;
	struct edac_mc_layer layers[1];
	int ret, intr_index, nintr, nintr_registered = 0;
	struct resource *res;
	void __iomem *reg_base;
	u32 reg_val;

	/* Parsing the device node */
	dev = &pdev->dev;

	nintr = of_property_count_u32_elems(dev->of_node, "interrupt-config");
	if (nintr <= 0) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			"Invalid device node configuration: at least one interrupt "
			"line & config is expected.\n");
		return -EINVAL;
	}

	if (nintr > ARRAY_SIZE(dmc520_isr_array)) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			"Invalid device node configuration: # of interrupt config "
			"elements (%d) can not exeed %ld.\n",
			nintr, ARRAY_SIZE(dmc520_isr_array));
		return -EINVAL;
	}

	/* Initialize dmc520 edac */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	reg_base = devm_ioremap_resource(dev, res);
	if (IS_ERR(reg_base))
		return PTR_ERR(reg_base);

	if (!dmc520_is_ecc_enabled(reg_base))
		return -ENXIO;

	layers[0].type = EDAC_MC_LAYER_CHIP_SELECT;
	layers[0].size = dmc520_get_rank_count(reg_base);
	layers[0].is_virt_csrow = true;

	mci = edac_mc_alloc(dmc520_mc_idx++, ARRAY_SIZE(layers), layers,
			    sizeof(struct dmc520_edac) + sizeof(u32) * nintr);
	if (!mci) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			    "Failed to allocate memory for mc instance\n");
		return -ENOMEM;
	}

	edac = mci->pvt_info;
	edac->reg_base = reg_base;
	edac->nintr = nintr;
	edac->interrupt_mask_all = 0;
	spin_lock_init(&edac->ecc_lock);

	ret = of_property_read_u32_array(dev->of_node, "interrupt-config",
			edac->interrupt_masks, nintr);
	if (ret) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			"Failed to get interrupt-config arrays.\n");
		goto err_free_mc;
	}

	for (intr_index = 0; intr_index < nintr; ++intr_index) {
		if (edac->interrupt_mask_all & edac->interrupt_masks[intr_index]) {
			edac_printk(KERN_ERR, EDAC_MC,
				"interrupt-config error: "
				"element %d's interrupt mask %d has overlap.\n",
				intr_index, edac->interrupt_masks[intr_index]);
			goto err_free_mc;
		}

		edac->interrupt_mask_all |= edac->interrupt_masks[intr_index];
	}

	edac->interrupt_mask_all &= ALL_INT_MASK;

	platform_set_drvdata(pdev, mci);

	mci->pdev = dev;
	mci->mtype_cap = MEM_FLAG_DDR3 | MEM_FLAG_DDR4;
	mci->edac_ctl_cap = EDAC_FLAG_NONE | EDAC_FLAG_SECDED;
	mci->edac_cap = EDAC_FLAG_SECDED;
	mci->scrub_cap = SCRUB_FLAG_HW_SRC;
	mci->scrub_mode = dmc520_get_scrub_type(edac);
	mci->ctl_name = EDAC_CTL_NAME;
	mci->dev_name = dev_name(mci->pdev);
	mci->mod_name = EDAC_MOD_NAME;
	mci->ctl_page_to_phys = NULL;

	edac_op_state = EDAC_OPSTATE_INT;

	dmc520_init_csrow(mci);

	ret = edac_mc_add_mc(mci);
	if (ret) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			"Failed to register with EDAC core\n");
		goto err_free_mc;
	}

	/* Clear interrupts */
	reg_val = dmc520_read_reg(edac, REG_OFFSET_INTERRUPT_CONTROL);
	dmc520_write_reg(edac, reg_val & (~(edac->interrupt_mask_all)),
			REG_OFFSET_INTERRUPT_CONTROL);
	dmc520_write_reg(edac, edac->interrupt_mask_all, REG_OFFSET_INTERRUPT_CLR);

	for (intr_index = 0; intr_index < nintr; ++intr_index) {
		int irq_id = platform_get_irq(pdev, intr_index);
		if (irq_id < 0) {
			edac_printk(KERN_ERR, EDAC_MC,
				    "Failed to get irq #%d\n", intr_index);
			ret = -ENODEV;
			goto err_free_irq;
		}

		ret = devm_request_irq(&pdev->dev, irq_id,
					dmc520_isr_array[intr_index], IRQF_SHARED,
					dev_name(&pdev->dev), mci);
		if (ret < 0) {
			edac_printk(KERN_ERR, EDAC_MC,
				    "Failed to request irq %d\n", irq_id);
			goto err_free_irq;
		}

		++nintr_registered;
	}

	/* Reset DRAM CE/UE counters */
	if (edac->interrupt_mask_all & DRAM_ECC_INT_CE_MASK)
		dmc520_get_dram_ecc_error_count(edac, true);

	if (edac->interrupt_mask_all & DRAM_ECC_INT_UE_MASK)
		dmc520_get_dram_ecc_error_count(edac, false);

	/* Enable interrupts */
	dmc520_write_reg(edac, edac->interrupt_mask_all, REG_OFFSET_INTERRUPT_CONTROL);

	return 0;

err_free_irq:
	for (intr_index = 0; intr_index < nintr_registered; ++intr_index) {
		int irq_id = platform_get_irq(pdev, intr_index);
		devm_free_irq(&pdev->dev, irq_id, mci);
	}
	edac_mc_del_mc(&pdev->dev);
err_free_mc:
	edac_mc_free(mci);

	return ret;
}

static int dmc520_edac_remove(struct platform_device *pdev)
{
	struct dmc520_edac *edac;
	struct mem_ctl_info *mci;
	u32 reg_val, intr_index;

	mci = platform_get_drvdata(pdev);
	edac = mci->pvt_info;

	/* Disable interrupts */
	reg_val = dmc520_read_reg(edac, REG_OFFSET_INTERRUPT_CONTROL);
	dmc520_write_reg(edac, reg_val & (~(edac->interrupt_mask_all)),
			REG_OFFSET_INTERRUPT_CONTROL);

	/* free irq's */
	for (intr_index = 0; intr_index < edac->nintr; ++intr_index) {
		int irq_id = platform_get_irq(pdev, intr_index);
		devm_free_irq(&pdev->dev, irq_id, mci);
	}

	edac_mc_del_mc(&pdev->dev);
	edac_mc_free(mci);

	return 0;
}

static const struct of_device_id dmc520_edac_driver_id[] = {
	{ .compatible = "brcm,dmc-520", },
	{ .compatible = "arm,dmc-520", },
	{ /* end of table */ }
};

MODULE_DEVICE_TABLE(of, dmc520_edac_driver_id);

static struct platform_driver dmc520_edac_driver = {
	.driver = {
		.name = "dmc520",
		.of_match_table = dmc520_edac_driver_id,
	},

	.probe = dmc520_edac_probe,
	.remove = dmc520_edac_remove
};

module_platform_driver(dmc520_edac_driver);

MODULE_AUTHOR(
	"Rui Zhao <ruizhao@microsoft.com>, Lei Wang <lewan@microsoft.com>");
MODULE_DESCRIPTION("DMC-520 ECC driver");
MODULE_LICENSE("GPL v2");
