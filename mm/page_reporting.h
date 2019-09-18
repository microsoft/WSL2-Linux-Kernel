/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_PAGE_REPORTING_H
#define _MM_PAGE_REPORTING_H

#include <linux/mmzone.h>
#include <linux/pageblock-flags.h>
#include <linux/page-isolation.h>
#include <linux/jump_label.h>
#include <linux/slab.h>
#include <asm/pgtable.h>

#define PAGE_REPORTING_MIN_ORDER	pageblock_order
#define PAGE_REPORTING_HWM		32

#ifdef CONFIG_PAGE_REPORTING
/* Reported page accessors, defined in page_alloc.c */
void free_reported_page(struct page *page, unsigned int order);

/* Free reported_pages and reset reported page tracking count to 0 */
static inline void page_reporting_reset_zone(struct zone *zone)
{
	kfree(zone->reported_pages);
	zone->reported_pages = NULL;
}

DECLARE_STATIC_KEY_FALSE(page_reporting_notify_enabled);
void __page_reporting_request(struct zone *zone);

/**
 * page_reporting_notify_free - Free page notification to start page processing
 * @zone: Pointer to current zone of last page processed
 * @order: Order of last page added to zone
 *
 * This function is meant to act as a screener for __page_reporting_request
 * which will determine if a give zone has crossed over the high-water mark
 * that will justify us beginning page treatment. If we have crossed that
 * threshold then it will start the process of pulling some pages and
 * placing them in the batch list for treatment.
 */
static inline void page_reporting_notify_free(struct zone *zone, int order)
{
	unsigned long nr_reported;

	/* Called from hot path in __free_one_page() */
	if (!static_branch_unlikely(&page_reporting_notify_enabled))
		return;

	/* Limit notifications only to higher order pages */
	if (order < PAGE_REPORTING_MIN_ORDER)
		return;

	/* Do not bother with tests if we have already requested reporting */
	if (test_bit(ZONE_PAGE_REPORTING_REQUESTED, &zone->flags))
		return;

	/* If reported_pages is not populated, assume 0 */
	nr_reported = zone->reported_pages ?
		    zone->reported_pages[order - PAGE_REPORTING_MIN_ORDER] : 0;

	/* Only request it if we have enough to begin the page reporting */
	if (zone->free_area[order].nr_free < nr_reported + PAGE_REPORTING_HWM)
		return;

	/* This is slow, but should be called very rarely */
	__page_reporting_request(zone);
}

/* Boundary functions */
static inline pgoff_t
get_reporting_index(unsigned int order, unsigned int migratetype)
{
	/*
	 * We will only ever be dealing with pages greater-than or equal to
	 * PAGE_REPORTING_MIN_ORDER. Since that is the case we can avoid
	 * allocating unused space by limiting our index range to only the
	 * orders that are supported for page reporting.
	 */
	return (order - PAGE_REPORTING_MIN_ORDER) * MIGRATE_TYPES + migratetype;
}

extern struct list_head **reported_boundary __read_mostly;

static inline void
page_reporting_reset_boundary(struct zone *zone, unsigned int order, int mt)
{
	int index;

	if (order < PAGE_REPORTING_MIN_ORDER)
		return;
	if (!test_bit(ZONE_PAGE_REPORTING_ACTIVE, &zone->flags))
		return;

	index = get_reporting_index(order, mt);
	reported_boundary[index] = &zone->free_area[order].free_list[mt];
}

static inline void page_reporting_disable_boundaries(struct zone *zone)
{
	/* zone lock should be held when this function is called */
	lockdep_assert_held(&zone->lock);

	__clear_bit(ZONE_PAGE_REPORTING_ACTIVE, &zone->flags);
}

static inline void
page_reporting_free_area_release(struct zone *zone, unsigned int order, int mt)
{
	page_reporting_reset_boundary(zone, order, mt);
}

/*
 * Method for obtaining the tail of the free list. Using this allows for
 * tail insertions of unreported pages into the region that is currently
 * being scanned so as to avoid interleaving reported and unreported pages.
 */
static inline struct list_head *
get_unreported_tail(struct zone *zone, unsigned int order, int migratetype)
{
	if (order >= PAGE_REPORTING_MIN_ORDER &&
	    test_bit(ZONE_PAGE_REPORTING_ACTIVE, &zone->flags))
		return reported_boundary[get_reporting_index(order,
							     migratetype)];

	return &zone->free_area[order].free_list[migratetype];
}

/*
 * Functions for adding/removing reported pages to the freelist.
 * All of them expect the zone lock to be held to maintain
 * consistency of the reported list as a subset of the free list.
 */
static inline void
add_page_to_reported_list(struct page *page, struct zone *zone,
			  unsigned int order, unsigned int mt)
{
	/*
	 * Default to using index 0, this will be updated later if the zone
	 * is still being processed.
	 */
	page->index = 0;

	/* flag page as reported */
	__SetPageReported(page);

	/* update areated page accounting */
	zone->reported_pages[order - PAGE_REPORTING_MIN_ORDER]++;
}

static inline void page_reporting_pull_boundary(struct page *page)
{
	struct list_head **tail = &reported_boundary[page->index];

	if (*tail == &page->lru)
		*tail = page->lru.next;
}

static inline void
__del_page_from_reported_list(struct page *page, struct zone *zone)
{
	/*
	 * Since the page is being pulled from the list we need to update
	 * the boundary, after that we can just update the index so that
	 * the correct boundary will be checked in the future.
	 */
	if (test_bit(ZONE_PAGE_REPORTING_ACTIVE, &zone->flags))
		page_reporting_pull_boundary(page);
}

static inline void
del_page_from_reported_list(struct page *page, struct zone *zone,
			    unsigned int order)
{
	__del_page_from_reported_list(page, zone);

	/* page_private will contain the page order, so just use it directly */
	zone->reported_pages[order - PAGE_REPORTING_MIN_ORDER]--;

	/* clear the flag so we can report on it when it returns */
	__ClearPageReported(page);
}

#else /* CONFIG_PAGE_REPORTING */
static inline void page_reporting_reset_zone(struct zone *zone)
{
}

static inline void page_reporting_notify_free(struct zone *zone, int order)
{
}

static inline void
page_reporting_free_area_release(struct zone *zone, unsigned int order, int mt)
{
}

static inline struct list_head *
get_unreported_tail(struct zone *zone, unsigned int order, int migratetype)
{
	return &zone->free_area[order].free_list[migratetype];
}

static inline void
add_page_to_reported_list(struct page *page, struct zone *zone,
			  int order, int migratetype)
{
}

static inline void
__del_page_from_reported_list(struct page *page, struct zone *zone)
{
}

static inline void
del_page_from_reported_list(struct page *page, struct zone *zone,
			    unsigned int order)
{
}

static inline void
move_page_to_reported_list(struct page *page, struct zone *zone, int dest_mt)
{
}
#endif /* CONFIG_PAGE_REPORTING */
#endif /*_MM_PAGE_REPORTING_H */
