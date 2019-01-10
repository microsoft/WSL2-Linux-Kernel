// SPDX-License-Identifier: GPL-2.0+
// EDAC driver for DMC-520

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/edac.h>
#include <asm/io.h>
#include <linux/of.h>
#include <linux/interrupt.h>
#include <linux/bitfield.h>
#include <edac_mc.h>

// DMC-520 registers
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

// DMC-520 types, masks and bitfields
#define MEMORY_TYPE_LPDDR3			0
#define MEMORY_TYPE_DDR3			1
#define MEMORY_TYPE_DDR4			2
#define MEMORY_TYPE_LPDDR4			3

#define MEMORY_DEV_WIDTH_X4			0
#define MEMORY_DEV_WIDTH_X8			1
#define MEMORY_DEV_WIDTH_X16			2
#define MEMORY_DEV_WIDTH_X32			3

#define DRAM_ECC_INT_CE_MASK			BIT(2)
#define DRAM_ECC_INT_UE_MASK			BIT(3)
#define DRAM_ECC_INT_CE_OVERFLOW_MASK		BIT(18)
#define DRAM_ECC_INT_UE_OVERFLOW_MASK		BIT(19)

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

#define DRAM_ECC_MIN_INT_OVERFLOW_ERROR_COUNT	256
#define DRAM_ADDRESS_CONTROL_MIN_COL_BITS	8
#define DRAM_ADDRESS_CONTROL_MIN_ROW_BITS	11

// Driver settings
#define DMC520_EDAC_CHANS			1
#define DMC520_EDAC_ERR_GRAIN			1
#define DMC520_EDAC_INT_COUNT			2
#define DMC520_EDAC_BUS_WIDTH			8

#define EDAC_MSG_BUF_SIZE			128
#define EDAC_MOD_NAME				"dmc520-edac"
#define EDAC_CTL_NAME				"dmc520"

struct ecc_error_info {
	u32 col;
	u32 row;
	u32 bank;
	u32 rank;
};

struct dmc520_edac {
	void __iomem *reg_base;
	char message[EDAC_MSG_BUF_SIZE];
};

static int dmc520_mc_idx;

static u32 dmc520_read_reg(struct dmc520_edac *edac, u32 offset)
{
	return readl(edac->reg_base + offset);
}

static void dmc520_write_reg(struct dmc520_edac *edac, u32 val, u32 offset)
{
	writel(val, edac->reg_base + offset);
}

static u32 dmc520_calc_ecc_error(u32 value)
{
	u32 total = 0;

	// Each rank's error counter takes one byte
	while (value > 0) {
		total += (value & 0xFF);
		value >>= 8;
	}
	return total;
}

static u32 dmc520_get_ecc_error_count(struct dmc520_edac *edac, bool is_ce)
{
	u32 reg_offset_low, reg_offset_high;
	u32 err_low, err_high;
	u32 ce_count;

	reg_offset_low = is_ce ? REG_OFFSET_ECC_ERRC_COUNT_31_00 :
				 REG_OFFSET_ECC_ERRD_COUNT_31_00;
	reg_offset_high = is_ce ? REG_OFFSET_ECC_ERRC_COUNT_63_32 :
				  REG_OFFSET_ECC_ERRD_COUNT_63_32;

	err_low = dmc520_read_reg(edac, reg_offset_low);
	err_high = dmc520_read_reg(edac, reg_offset_high);

	ce_count = dmc520_calc_ecc_error(err_low) +
		   dmc520_calc_ecc_error(err_high);

	// Reset error counters
	dmc520_write_reg(edac, 0, reg_offset_low);
	dmc520_write_reg(edac, 0, reg_offset_high);

	return ce_count;
}

static bool dmc520_get_ecc_error_info(struct dmc520_edac *edac,
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

	if (info) {
		if (valid) {
			info->col = FIELD_GET(REG_FIELD_ERR_INFO_LOW_COL,
					      reg_val_low);
			info->row = FIELD_GET(REG_FIELD_ERR_INFO_LOW_ROW,
					      reg_val_low);
			info->rank = FIELD_GET(REG_FIELD_ERR_INFO_LOW_RANK,
					       reg_val_low);
			info->bank = FIELD_GET(REG_FIELD_ERR_INFO_HIGH_BANK,
					       reg_val_high);
		} else {
			memset(info, 0, sizeof(struct ecc_error_info));
		}
	}

	return valid;
}

static bool dmc520_is_ecc_enabled(struct dmc520_edac *edac)
{
	u32 reg_val = dmc520_read_reg(edac, REG_OFFSET_FEATURE_CONFIG);

	return (FIELD_GET(REG_FIELD_DRAM_ECC_ENABLED, reg_val) != 0);
}

static enum mem_type dmc520_get_mtype(struct dmc520_edac *edac)
{
	enum mem_type mt;
	u32 reg_val, type;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_MEMORY_TYPE_NOW);
	type = FIELD_GET(REG_FIELD_MEMORY_TYPE, reg_val);

	switch (type) {
	case MEMORY_TYPE_LPDDR3:
	case MEMORY_TYPE_DDR3:
		mt = MEM_DDR3;
		break;

	case MEMORY_TYPE_DDR4:
	case MEMORY_TYPE_LPDDR4:
	default:
		mt = MEM_DDR4;
		break;
	}
	return mt;
}

static enum dev_type dmc520_get_dtype(struct dmc520_edac *edac)
{
	enum dev_type dt;
	u32 reg_val, device_width;

	reg_val = dmc520_read_reg(edac, REG_OFFSET_MEMORY_TYPE_NOW);
	device_width = FIELD_GET(REG_FIELD_DEVICE_WIDTH, reg_val);

	switch (device_width) {
	case MEMORY_DEV_WIDTH_X4:
		dt = DEV_X4;
		break;

	case MEMORY_DEV_WIDTH_X8:
		dt = DEV_X8;
		break;

	case MEMORY_DEV_WIDTH_X16:
		dt = DEV_X16;
		break;

	case MEMORY_DEV_WIDTH_X32:
		dt = DEV_X32;
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

	return (u64)DMC520_EDAC_BUS_WIDTH << (col_bits + row_bits + bank_bits);
}

static void dmc520_handle_ecc_errors(struct mem_ctl_info *mci,
				     bool is_ce,
				     bool overflow)
{
	struct ecc_error_info info;
	struct dmc520_edac *edac;
	u32 cnt;

	edac = mci->pvt_info;
	dmc520_get_ecc_error_info(edac, is_ce, &info);

	cnt = dmc520_get_ecc_error_count(edac, is_ce);

	if (overflow)
		cnt += DRAM_ECC_MIN_INT_OVERFLOW_ERROR_COUNT;

	if (cnt > 0) {
		snprintf(edac->message, ARRAY_SIZE(edac->message),
			 "rank:%d bank:%d row:%d col:%d",
			 info.rank, info.bank,
			 info.row, info.col);

		edac_mc_handle_error((is_ce ? HW_EVENT_ERR_CORRECTED :
				     HW_EVENT_ERR_UNCORRECTED),
				     mci, cnt, 0, 0, 0, info.rank, 0, -1,
				     edac->message, "");
	}
}

static irqreturn_t dmc520_edac_isr(int irq, void *data, bool is_ce)
{
	u32 i_mask, o_mask, status;
	bool overflow;
	struct mem_ctl_info *mci;
	struct dmc520_edac *edac;

	mci = data;
	edac = mci->pvt_info;

	i_mask = is_ce ? DRAM_ECC_INT_CE_MASK : DRAM_ECC_INT_UE_MASK;
	o_mask = is_ce ? DRAM_ECC_INT_CE_OVERFLOW_MASK :
			 DRAM_ECC_INT_UE_OVERFLOW_MASK;

	status = dmc520_read_reg(edac, REG_OFFSET_INTERRUPT_STATUS);
	overflow = ((status & o_mask) != 0);

	dmc520_handle_ecc_errors(mci, is_ce, overflow);

	dmc520_write_reg(edac, i_mask, REG_OFFSET_INTERRUPT_CLR);

	return IRQ_HANDLED;
}

static irqreturn_t dmc520_edac_ce_isr(int irq, void *data)
{
	return dmc520_edac_isr(irq, data, true);
}

static irqreturn_t dmc520_edac_ue_isr(int irq, void *data)
{
	return dmc520_edac_isr(irq, data, false);
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
			dimm->edac_mode	= EDAC_FLAG_SECDED;
			dimm->mtype	= mt;
			dimm->nr_pages	= pages_per_rank / csi->nr_channels;
			dimm->grain	= DMC520_EDAC_ERR_GRAIN;
			dimm->dtype	= dt;
		}
	}
}

static int dmc520_edac_probe(struct platform_device *pdev)
{
	struct dmc520_edac *edac;
	struct mem_ctl_info *mci;
	struct edac_mc_layer layers[2];
	int ret, irq;
	struct resource *res;
	void __iomem *reg_base;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	reg_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(reg_base))
		return PTR_ERR(reg_base);

	layers[0].type = EDAC_MC_LAYER_CHIP_SELECT;
	layers[0].size = dmc520_get_rank_count(reg_base);
	layers[0].is_virt_csrow = true;

	layers[1].type = EDAC_MC_LAYER_CHANNEL;
	layers[1].size = DMC520_EDAC_CHANS;
	layers[1].is_virt_csrow = false;

	mci = edac_mc_alloc(dmc520_mc_idx++, ARRAY_SIZE(layers), layers,
			    sizeof(struct dmc520_edac));
	if (!mci) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME,
			    "Failed to allocate memory for mc instance\n");
		return -ENOMEM;
	}

	edac = mci->pvt_info;
	edac->reg_base = reg_base;

	if (!dmc520_is_ecc_enabled(edac)) {
		edac_printk(KERN_ERR, EDAC_MOD_NAME, "ECC not enabled\n");
		ret = -ENXIO;
		goto err;
	}

	platform_set_drvdata(pdev, mci);

	mci->pdev = &pdev->dev;
	mci->mtype_cap = MEM_FLAG_DDR3 | MEM_FLAG_DDR4;
	mci->edac_ctl_cap = EDAC_FLAG_NONE | EDAC_FLAG_SECDED;
	mci->scrub_cap = SCRUB_HW_SRC;
	mci->scrub_mode = SCRUB_NONE;
	mci->edac_cap = EDAC_FLAG_SECDED;
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
		goto err;
	}

	for (irq = 0; irq < DMC520_EDAC_INT_COUNT; ++irq) {
		irq_handler_t dmc520_edac_isr;
		int irq_id = platform_get_irq(pdev, irq);
		if (irq_id < 0) {
			edac_printk(KERN_ERR, EDAC_MC,
				    "Failed to get %s irq\n",
				    irq == 0 ? "CE" : "UE");
			ret = -ENODEV;
			goto err;
		}

		dmc520_edac_isr = (irq == 0 ? dmc520_edac_ce_isr :
					      dmc520_edac_ue_isr);

		ret = devm_request_irq(&pdev->dev,
				       irq_id,
				       dmc520_edac_isr,
				       0,
				       dev_name(&pdev->dev),
				       mci);
		if (ret < 0) {
			edac_printk(KERN_ERR, EDAC_MC,
				    "Failed to request irq %d\n", irq_id);
			goto err;
		}
	}

	// Check ECC CE/UE errors
	dmc520_handle_ecc_errors(mci, true, false);
	dmc520_handle_ecc_errors(mci, false, false);

	// Enable interrupts
	dmc520_write_reg(edac,
			 DRAM_ECC_INT_CE_MASK | DRAM_ECC_INT_UE_MASK,
			 REG_OFFSET_INTERRUPT_CONTROL);

	return 0;

err:
	edac_mc_free(mci);

	return ret;
}

static int dmc520_edac_remove(struct platform_device *pdev)
{
	struct dmc520_edac *edac;
	struct mem_ctl_info *mci;

	mci = platform_get_drvdata(pdev);
	edac = mci->pvt_info;

	// Diable interrupts
	dmc520_write_reg(edac,
			 DRAM_ECC_INT_CE_MASK | DRAM_ECC_INT_UE_MASK,
			 REG_OFFSET_INTERRUPT_CONTROL);

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

MODULE_AUTHOR("Rui Zhao <ruizhao@microsoft.com>");
MODULE_DESCRIPTION("DMC-520 ECC driver");
MODULE_LICENSE("GPL v2");
