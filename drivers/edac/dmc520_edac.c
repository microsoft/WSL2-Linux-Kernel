// SPDX-License-Identifier: GPL-2.0

/*
 * EDAC driver for DMC-520 memory controller.
 *
 * The driver currently supports up to 2 interrupt lines.
 * More interrupt lines support can be added by:
 * 1. Adding more DECLARE_ISR(index) macros, and dmc520_isr_x fields
 *    into dmc520_isr_array.
 * 2. In dmc520_edac_dram_all_isr, adding condition statements
 *    to match interrupt flags for these newly added interrupt
 *    lines.
 * 3. Implementing isr's for the new interrupt lines.
 *
 * Authors:	Rui Zhao <ruizhao@microsoft.com>
 *		Lei Wang <lewan@microsoft.com>
 */

#include <linux/bitfield.h>
#include <linux/edac.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "edac_mc.h"

/* DMC-520 registers */
#define REG_OFFSET_FEATURE_CONFIG		0x130
#define REG_OFFSET_ECC_ERRC_COUNT_31_00		0x158
#define REG_OFFSET_ECC_ERRC_COUNT_63_32		0x15C
#define REG_OFFSET_ECC_ERRD_COUNT_31_00		0x160
#define REG_OFFSET_ECC_ERRD_COUNT_63_32		0x164
#define REG_OFFSET_INTERRUPT_CONTROL		0x500
#define REG_OFFSET_INTERRUPT_CLR		0x508
#define REG_OFFSET_INTERRUPT_STATUS		0x510
#define REG_OFFSET_DRAM_ECC_ERRC_INT_INFO_31_00	0x528
#define REG_OFFSET_DRAM_ECC_ERRC_INT_INFO_63_32	0x52C
#define REG_OFFSET_DRAM_ECC_ERRD_INT_INFO_31_00	0x530
#define REG_OFFSET_DRAM_ECC_ERRD_INT_INFO_63_32	0x534
#define REG_OFFSET_ADDRESS_CONTROL_NOW		0x1010
#define REG_OFFSET_MEMORY_TYPE_NOW		0x1128
#define REG_OFFSET_SCRUB_CONTROL0_NOW		0x1170
#define REG_OFFSET_FORMAT_CONTROL		0x18

/* DMC-520 types, masks and bitfields */
#define DRAM_ECC_INT_CE_BIT			BIT(2)
#define DRAM_ECC_INT_UE_BIT			BIT(3)
#define ALL_INT_MASK				GENMASK(9, 0)
#define MEMORY_WIDTH_MASK			GENMASK(1, 0)
#define SCRUB_TRIGGER0_NEXT_MASK		GENMASK(1, 0)
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

#define DMC520_SCRUB_TRIGGER_ERR_DETECT		2
#define DMC520_SCRUB_TRIGGER_IDLE		3

/* Driver settings */
/*
 * The max-length message would be: "rank:7 bank:15 row:262143 col:1023".
 * Max length is 34. Using a 40-size buffer is enough.
 */
#define DMC520_MSG_BUF_SIZE			40
#define EDAC_MOD_NAME				"dmc520-edac"
#define EDAC_CTL_NAME				"dmc520"

/* the data bus width for the attached memory chips. */
enum dmc520_mem_width {
	MEM_WIDTH_X32 = 2,
	MEM_WIDTH_X64 = 3
};

/* memory type */
enum dmc520_mem_type {
	MEM_TYPE_DDR3 = 1,
	MEM_TYPE_DDR4 = 2
};

/* memory device width */
enum dmc520_dev_width {
	DEV_WIDTH_X4 = 0,
	DEV_WIDTH_X8 = 1,
	DEV_WIDTH_X16 = 2
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
dmc520_edac_dram_all_isr(
	int irq, struct mem_ctl_info *mci, u32 interrupt_mask);

#define DECLARE_ISR(index) \
static irqreturn_t dmc520_isr_##index(int irq, void *data) \
{ \
	struct mem_ctl_info *mci; \
	struct dmc520_edac *edac; \
	mci = data; \
	edac = mci->pvt_info; \
	return dmc520_edac_dram_all_isr( \
		irq, mci, edac->interrupt_masks[index]); \
}

DECLARE_ISR(0)
DECLARE_ISR(1)

irq_handler_t dmc520_isr_array[] = {
	dmc520_isr_0,
	dmc520_isr_1
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

	/* Each rank's error counter takes one byte. */
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

static void dmc520_get_dram_ecc_error_info(struct dmc520_edac *edac,
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
		info->col =
			FIELD_GET(REG_FIELD_ERR_INFO_LOW_COL, reg_val_low);
		info->row =
			FIELD_GET(REG_FIELD_ERR_INFO_LOW_ROW, reg_val_low);
		info->rank =
			FIELD_GET(REG_FIELD_ERR_INFO_LOW_RANK, reg_val_low);
		info->bank =
			FIELD_GET(REG_FIELD_ERR_INFO_HIGH_BANK, reg_val_high);
	} else {
		memset(info, 0, sizeof(struct ecc_error_info));
	}
}

static bool dmc520_is_ecc_enabled(void __iomem *reg_base)
{
	u32 reg_val = readl(reg_base + REG_OFFSET_FEATURE_CONFIG);

	return FIELD_GET(REG_FIELD_DRAM_ECC_ENABLED, reg_val);
}

static enum scrub_type dmc520_get_scrub_type(struct dmc520_edac *edac)
{
	enum scrub_type type = SCRUB_NONE;
	u32 reg_val, scrub_cfg;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_SCRUB_CONTROL0_NOW);
	scrub_cfg = FIELD_GET(SCRUB_TRIGGER0_NEXT_MASK, reg_val);

	if (scrub_cfg == DMC520_SCRUB_TRIGGER_ERR_DETECT ||
		scrub_cfg == DMC520_SCRUB_TRIGGER_IDLE)
		type = SCRUB_HW_PROG;

	return type;
}

/* Get the memory data bus width, in number of bytes. */
static u32 dmc520_get_memory_width(struct dmc520_edac *edac)
{
	enum dmc520_mem_width mem_width_field;
	static u32 mem_width_in_bytes;
	u32 reg_val;

	if (mem_width_in_bytes)
		return mem_width_in_bytes;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_FORMAT_CONTROL);
	mem_width_field = FIELD_GET(MEMORY_WIDTH_MASK, reg_val);

	if (mem_width_field == MEM_WIDTH_X32)
		mem_width_in_bytes = 4;
	else if (mem_width_field == MEM_WIDTH_X64)
		mem_width_in_bytes = 8;
	return mem_width_in_bytes;
}

static enum mem_type dmc520_get_mtype(struct dmc520_edac *edac)
{
	enum mem_type mt = MEM_UNKNOWN;
	enum dmc520_mem_type type;
	u32 reg_val;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_MEMORY_TYPE_NOW);
	type = FIELD_GET(REG_FIELD_MEMORY_TYPE, reg_val);

	switch (type) {
	case MEM_TYPE_DDR3:
		mt = MEM_DDR3;
		break;

	case MEM_TYPE_DDR4:
		mt = MEM_DDR4;
		break;
	}

	return mt;
}

static enum dev_type dmc520_get_dtype(struct dmc520_edac *edac)
{
	enum dmc520_dev_width device_width;
	enum dev_type dt = DEV_UNKNOWN;
	u32 reg_val;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_MEMORY_TYPE_NOW);
	device_width = FIELD_GET(REG_FIELD_DEVICE_WIDTH, reg_val);

	switch (device_width) {
	case DEV_WIDTH_X4:
		dt = DEV_X4;
		break;

	case DEV_WIDTH_X8:
		dt = DEV_X8;
		break;

	case DEV_WIDTH_X16:
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

	return BIT(rank_bits);
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

	return (u64)dmc520_get_memory_width(edac) <<
			(col_bits + row_bits + bank_bits);
}

static void dmc520_handle_dram_ecc_errors(struct mem_ctl_info *mci,
					  bool is_ce)
{
	char message[DMC520_MSG_BUF_SIZE];
	struct ecc_error_info info;
	struct dmc520_edac *edac;
	u32 cnt;

	edac = mci->pvt_info;
	dmc520_get_dram_ecc_error_info(edac, is_ce, &info);

	cnt = dmc520_get_dram_ecc_error_count(edac, is_ce);

	if (!cnt)
		return;

	snprintf(message, ARRAY_SIZE(message),
		 "rank:%d bank:%d row:%d col:%d",
		 info.rank, info.bank,
		 info.row, info.col);

	spin_lock(&edac->ecc_lock);
	edac_mc_handle_error((is_ce ? HW_EVENT_ERR_CORRECTED :
			     HW_EVENT_ERR_UNCORRECTED),
			     mci, cnt, 0, 0, 0, info.rank, -1, -1,
			     message, "");
	spin_unlock(&edac->ecc_lock);
}

static irqreturn_t dmc520_edac_dram_ecc_isr(
	int irq, struct mem_ctl_info *mci, bool is_ce)
{
	struct dmc520_edac *edac;
	u32 i_mask;

	edac = mci->pvt_info;

	i_mask = is_ce ? DRAM_ECC_INT_CE_BIT : DRAM_ECC_INT_UE_BIT;

	dmc520_handle_dram_ecc_errors(mci, is_ce);

	dmc520_write_reg(edac, i_mask, REG_OFFSET_INTERRUPT_CLR);

	return IRQ_HANDLED;
}

static irqreturn_t dmc520_edac_dram_all_isr(
	int irq, struct mem_ctl_info *mci, u32 interrupt_mask)
{
	irqreturn_t irq_ret = IRQ_NONE;
	struct dmc520_edac *edac;
	u32 status;

	edac = mci->pvt_info;

	status = dmc520_read_reg(edac, REG_OFFSET_INTERRUPT_STATUS);

	if ((interrupt_mask & DRAM_ECC_INT_CE_BIT) &&
		(status & DRAM_ECC_INT_CE_BIT))
		irq_ret = dmc520_edac_dram_ecc_isr(irq, mci, true);

	if ((interrupt_mask & DRAM_ECC_INT_UE_BIT) &&
		(status & DRAM_ECC_INT_UE_BIT))
		irq_ret = dmc520_edac_dram_ecc_isr(irq, mci, false);

	return irq_ret;
}

static void dmc520_init_csrow(struct mem_ctl_info *mci)
{
	struct dmc520_edac *edac = mci->pvt_info;
	struct csrow_info *csi;
	struct dimm_info *dimm;
	u32 pages_per_rank;
	enum dev_type dt;
	enum mem_type mt;
	int row, ch;
	u64 rs;

	dt = dmc520_get_dtype(edac);
	mt = dmc520_get_mtype(edac);
	rs = dmc520_get_rank_size(edac);
	pages_per_rank = rs >> PAGE_SHIFT;

	for (row = 0; row < mci->nr_csrows; row++) {
		csi = mci->csrows[row];

		for (ch = 0; ch < csi->nr_channels; ch++) {
			dimm		= csi->channels[ch]->dimm;
			dimm->grain	= dmc520_get_memory_width(edac);
			dimm->dtype	= dt;
			dimm->mtype	= mt;
			dimm->edac_mode	= EDAC_FLAG_SECDED;
			dimm->nr_pages	= pages_per_rank / csi->nr_channels;
		}
	}
}

static int dmc520_edac_probe(struct platform_device *pdev)
{
	int ret, intr_index, nintr, nintr_registered = 0;
	struct dmc520_edac *edac, *edac_local;
	struct mem_ctl_info *mci = NULL;
	struct edac_mc_layer layers[1];
	void __iomem *reg_base;
	u32 reg_val, edac_size;
	struct resource *res;
	struct device *dev;

	/* Parsing the device node */
	dev = &pdev->dev;

	nintr = of_property_count_u32_elems(dev->of_node, "interrupt-config");
	if (nintr <= 0) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			"Invalid device node configuration:\n"
			"At least one interrupt line/config is expected.\n");
		return -EINVAL;
	}

	if (nintr > ARRAY_SIZE(dmc520_isr_array)) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			"Invalid device node configuration:\n"
			"# of intr config elements(%d) can not exceed %ld.\n",
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

	edac_size = sizeof(struct dmc520_edac) + sizeof(u32) * nintr;
	edac_local = kmalloc(edac_size, GFP_KERNEL);
	if (!edac_local)
		return -ENOMEM;
	memset(edac_local, 0, edac_size);

	ret = of_property_read_u32_array(dev->of_node, "interrupt-config",
			edac_local->interrupt_masks, nintr);
	if (ret) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			"Failed to get interrupt-config arrays.\n");
		goto err;
	}

	for (intr_index = 0; intr_index < nintr; ++intr_index) {
		if (edac_local->interrupt_mask_all &
			edac_local->interrupt_masks[intr_index]) {
			edac_printk(KERN_ERR, EDAC_MC,
				"Interrupt-config error:\n"
				"Element %d's intr mask %d has overlap.\n",
				intr_index,
				edac_local->interrupt_masks[intr_index]);
			ret = -ENXIO;
			goto err;
		}

		edac_local->interrupt_mask_all |=
			edac_local->interrupt_masks[intr_index];
	}

	if ((edac_local->interrupt_mask_all | ALL_INT_MASK) != ALL_INT_MASK) {
		edac_printk(KERN_WARNING, EDAC_MOD_NAME,
			"Interrupt-config warning:\n"
			"Interrupt mask (0x%x) is not supported.(0x%lx).\n",
			edac_local->interrupt_mask_all, ALL_INT_MASK);
	}
	edac_local->interrupt_mask_all &= ALL_INT_MASK;

	mci = edac_mc_alloc(dmc520_mc_idx++, ARRAY_SIZE(layers), layers,
			    edac_size);
	if (!mci) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			    "Failed to allocate memory for mc instance\n");
		ret = -ENOMEM;
		goto err;
	}

	edac = mci->pvt_info;
	memcpy(edac, edac_local, edac_size);
	kfree(edac_local);
	edac_local = NULL;
	edac->reg_base = reg_base;
	edac->nintr = nintr;
	spin_lock_init(&edac->ecc_lock);

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

	/* Clear interrupts, not affecting other unrelated interrupts */
	reg_val = dmc520_read_reg(edac, REG_OFFSET_INTERRUPT_CONTROL);
	dmc520_write_reg(edac, reg_val & (~(edac->interrupt_mask_all)),
			 REG_OFFSET_INTERRUPT_CONTROL);
	dmc520_write_reg(edac, edac->interrupt_mask_all,
			 REG_OFFSET_INTERRUPT_CLR);

	for (intr_index = 0; intr_index < nintr; ++intr_index) {
		int irq_id = platform_get_irq(pdev, intr_index);

		if (irq_id < 0) {
			edac_printk(KERN_ERR, EDAC_MC,
				    "Failed to get irq #%d\n", intr_index);
			ret = -ENODEV;
			goto err;
		}

		ret = devm_request_irq(&pdev->dev, irq_id,
				dmc520_isr_array[intr_index], IRQF_SHARED,
				dev_name(&pdev->dev), mci);
		if (ret < 0) {
			edac_printk(KERN_ERR, EDAC_MC,
				    "Failed to request irq %d\n", irq_id);
			goto err;
		}

		++nintr_registered;
	}

	/* Reset DRAM CE/UE counters */
	if (edac->interrupt_mask_all & DRAM_ECC_INT_CE_BIT)
		dmc520_get_dram_ecc_error_count(edac, true);

	if (edac->interrupt_mask_all & DRAM_ECC_INT_UE_BIT)
		dmc520_get_dram_ecc_error_count(edac, false);

	/* Enable interrupts, not affecting other unrelated interrupts */
	dmc520_write_reg(edac, reg_val | edac->interrupt_mask_all,
			 REG_OFFSET_INTERRUPT_CONTROL);

	ret = edac_mc_add_mc(mci);
	if (ret) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			"Failed to register with EDAC core\n");
		goto err;
	}

	return 0;

err:
	kfree(edac_local);
	for (intr_index = 0; intr_index < nintr_registered; ++intr_index) {
		int irq_id = platform_get_irq(pdev, intr_index);

		devm_free_irq(&pdev->dev, irq_id, mci);
	}
	if (mci)
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

MODULE_AUTHOR("Rui Zhao <ruizhao@microsoft.com>, Lei Wang <lewan@microsoft.com>");
MODULE_DESCRIPTION("DMC-520 ECC driver");
MODULE_LICENSE("GPL v2");
