// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Microsoft Corporation.
 */

#include <linux/slab.h>
#include <linux/kexec.h>
#include <linux/of.h>
#include <linux/memblock.h>
#include <linux/libfdt.h>

/**
 * delete_fdt_mem_rsv - delete memory reservation with given address and size
 * @fdt - pointer to the fdt.
 * @start - start address of the memory.
 * @size - number of cells to be deletd.
 *
 * Return: 0 on success, or negative errno on error.
 */
int fdt_delete_mem_rsv(void *fdt, unsigned long start, unsigned long size)
{
	int i, ret, num_rsvs = fdt_num_mem_rsv(fdt);

	for (i = 0; i < num_rsvs; i++) {
		uint64_t rsv_start, rsv_size;

		ret = fdt_get_mem_rsv(fdt, i, &rsv_start, &rsv_size);
		if (ret < 0) {
			pr_err("Malformed device tree\n");
			return ret;
		}

		if (rsv_start == start && rsv_size == size) {
			ret = fdt_del_mem_rsv(fdt, i);
			if (ret < 0) {
				pr_err("Error deleting device tree reservation\n");
				return ret;
			}

			return 0;
		}
	}

	return -ENOENT;
}

/**
 * of_get_ima_buffer_properties - get the properties for ima buffer
 * @ima_buf_start - start of the ima buffer
 * @ima_buf_end - end of the ima buffer
 *	If any one of the properties is not found. The device tree
 *	is malformed or something went wrong.
 *
 * Return: 0 on success, negative errno on error.
 */
int of_get_ima_buffer_properties(void **ima_buf_start, void **ima_buf_end)
{
	struct property *pproperty;

	pproperty = of_find_property(of_chosen, "linux,ima-kexec-buffer",
				    NULL);
	*ima_buf_start = pproperty ? pproperty->value : NULL;

	pproperty = of_find_property(of_chosen, "linux,ima-kexec-buffer-end",
				    NULL);
	*ima_buf_end = pproperty ? pproperty->value : NULL;

	if (!*ima_buf_start || !*ima_buf_end)
		return -EINVAL;

	return 0;
}

/**
 * of_remove_ima_buffer - free memory used by the IMA buffer
 *
 * Return: 0 on success, negative errno on error.
 */
int of_remove_ima_buffer(void)
{
	int ret;
	void *ima_buf_start, *ima_buf_end;
	uint64_t buf_start, buf_end;

	ret = of_get_ima_buffer_properties(&ima_buf_start, &ima_buf_end);
	if (ret < 0)
		return ret;

	buf_start = fdt64_to_cpu(*((const fdt64_t *) ima_buf_start));
	buf_end = fdt64_to_cpu(*((const fdt64_t *) ima_buf_end));

	ret = of_remove_property(of_chosen, ima_buf_start);
	if (ret < 0)
		return ret;

	ret = of_remove_property(of_chosen, ima_buf_end);
	if (ret < 0)
		return ret;

	return memblock_free(buf_start, buf_end - buf_start);
}

/**
 * of_get_ima_buffer - get IMA buffer from the previous kernel
 * @addr:	On successful return, set to point to the buffer contents.
 * @size:	On successful return, set to the buffer size.
 *
 * Return: 0 on success, negative errno on error.
 */
int of_get_ima_buffer(void **addr, size_t *size)
{
	int ret;
	void *ima_buf_start, *ima_buf_end;
	uint64_t buf_start, buf_end;

	ret = of_get_ima_buffer_properties(&ima_buf_start, &ima_buf_end);
	if (ret < 0)
		return ret;

	buf_start = fdt64_to_cpu(*((const fdt64_t *) ima_buf_start));
	buf_end = fdt64_to_cpu(*((const fdt64_t *) ima_buf_end));

	*addr = __va(buf_start);
	*size = buf_end - buf_start;

	return 0;
}

/**
 * fdt_remove_ima_buffer - remove the IMA buffer property and reservation
 * @fdt - pointer the fdt.
 * @chosen_node - node under which property can be found.
 *
 * The IMA measurement buffer is either read by now and freeed or a kexec call
 * needs to replace the ima measurement buffer, clear the property and memory
 * reservation.
 */
void fdt_remove_ima_buffer(void *fdt, int chosen_node)
{
	int ret, len;
	const void *prop;
	uint64_t tmp_start, tmp_end;

	prop = fdt_getprop(fdt, chosen_node, "linux,ima-kexec-buffer", &len);
	if (prop) {
		tmp_start = fdt64_to_cpu(*((const fdt64_t *) prop));

		prop = fdt_getprop(fdt, chosen_node,
				   "linux,ima-kexec-buffer-end", &len);
		if (!prop)
			return;

		tmp_end = fdt64_to_cpu(*((const fdt64_t *) prop));

		ret = fdt_delete_mem_rsv(fdt, tmp_start, tmp_end - tmp_start);

		if (ret == 0)
			pr_debug("Removed old IMA buffer reservation.\n");
		else if (ret != -ENOENT)
			return;

		fdt_delprop(fdt, chosen_node, "linux,ima-kexec-buffer");
		fdt_delprop(fdt, chosen_node, "linux,ima-kexec-buffer-end");
	}
}

/**
 * fdt_setup_ima_buffer - update the fdt to contain the ima mesasurement log
 * @image: - pointer to the kimage, containing the address and size of
 *	     the IMA measurement log.
 * @fdt: - pointer to the fdt.
 * @chosen_node: - node under which property is to be defined.
 *
 * Return: 0 on success, negative errno on error.
 */
int fdt_setup_ima_buffer(const phys_addr_t ima_buffer_addr,
	const size_t ima_buffer_size,
	void *fdt, int chosen_node)
{
	int ret;

	fdt_remove_ima_buffer(fdt, chosen_node);

	if (!ima_buffer_addr)
		return 0;

	ret = fdt_setprop_u64(fdt, chosen_node, "linux,ima-kexec-buffer",
			      ima_buffer_addr);
	if (ret < 0)
		return ret;

	ret = fdt_setprop_u64(fdt, chosen_node, "linux,ima-kexec-buffer-end",
			      ima_buffer_addr +
			      ima_buffer_size);
	if (ret < 0)
		return ret;

	ret = fdt_add_mem_rsv(fdt, ima_buffer_addr,
			      ima_buffer_size);
	if (ret < 0)
		return ret;

	return 0;
}
