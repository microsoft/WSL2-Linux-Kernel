/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_REPORTING_H
#define _LINUX_PAGE_REPORTING_H

#include <linux/mmzone.h>

struct page_reporting_dev_info {
	/* function that alters pages to make them "reported" */
	void (*report)(struct page_reporting_dev_info *phdev,
		       unsigned int nents);

	/* scatterlist containing pages to be processed */
	struct scatterlist *sg;

	/*
	 * Upper limit on the number of pages that the react function
	 * expects to be placed into the batch list to be processed.
	 */
	unsigned long capacity;

	/* work struct for processing reports */
	struct delayed_work work;

	/* The number of zones requesting reporting */
	atomic_t refcnt;
};

/* Tear-down and bring-up for page reporting devices */
void page_reporting_unregister(struct page_reporting_dev_info *phdev);
int page_reporting_register(struct page_reporting_dev_info *phdev);
#endif /*_LINUX_PAGE_REPORTING_H */
