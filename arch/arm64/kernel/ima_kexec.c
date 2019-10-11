// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Microsoft Corporation.
 *
 * Authors:
 * Prakhar Srivastava <prsriva@linux.microsoft.com>
 */

#include <linux/kexec.h>
#include <linux/of.h>

/**
 * remove_ima_buffer - remove the IMA buffer property and reservation from @fdt
 * The IMA measurement buffer once read needs to be freed.
 */
void remove_ima_buffer(void *fdt, int chosen_node)
{
	fdt_remove_ima_buffer(fdt, chosen_node);
}

/**
 * ima_get_kexec_buffer - get IMA buffer from the previous kernel
 * @addr:	On successful return, set to point to the buffer contents.
 * @size:	On successful return, set to the buffer size.
 *
 * Return: 0 on success, negative errno on error.
 */
int ima_get_kexec_buffer(void **addr, size_t *size)
{
	return of_get_ima_buffer(addr, size);
}

/**
 * ima_free_kexec_buffer - free memory used by the IMA buffer
 *
 * Return: 0 on success, negative errno on error.
 */
int ima_free_kexec_buffer(void)
{
	return of_remove_ima_buffer();
}

#ifdef CONFIG_IMA_KEXEC
/**
 * arch_ima_add_kexec_buffer - do arch-specific steps to add the IMA
 *	measurement log.
 * @image: - pointer to the kimage, to store the address and size of the
 *	IMA measurement log.
 * @load_addr: - the address where the IMA measurement log is stored.
 * @size - size of the IMA measurement log.
 *
 * Return: 0 on success, negative errno on error.
 */
int arch_ima_add_kexec_buffer(struct kimage *image, unsigned long load_addr,
			      size_t size)
{
	image->arch.ima_buffer_addr = load_addr;
	image->arch.ima_buffer_size = size;
	return 0;
}

/**
 * setup_ima_buffer - update the fdt to contain the ima mesasurement log
 * @image: - pointer to the kimage, containing the address and size of
 *	     the IMA measurement log.
 * @fdt: - pointer to the fdt.
 * @chosen_node: - node under which property is to be defined.
 *
 * Return: 0 on success, negative errno on error.
 */
int setup_ima_buffer(const struct kimage *image, void *fdt, int chosen_node)
{
	return fdt_setup_ima_buffer(image->arch.ima_buffer_addr,
				    image->arch.ima_buffer_size,
				    fdt, chosen_node);

}
#endif /* CONFIG_IMA_KEXEC */
