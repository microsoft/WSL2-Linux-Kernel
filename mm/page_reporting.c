// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/page_reporting.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>

#include "page_reporting.h"
#include "internal.h"

static struct page_reporting_dev_info __rcu *ph_dev_info __read_mostly;
struct list_head **reported_boundary __read_mostly;

#define for_each_reporting_migratetype_order(_order, _type) \
	for (_order = MAX_ORDER; _order-- != PAGE_REPORTING_MIN_ORDER;) \
		for (_type = MIGRATE_TYPES; _type--;) \
			if (!is_migrate_isolate(_type))

static void page_reporting_populate_metadata(struct zone *zone)
{
	size_t size;
	int node;

	/*
	 * We need to make sure we have somewhere to store the tracking
	 * data for how many reported pages are in the zone. To do that
	 * we need to make certain zone->reported_pages is populated.
	 */
	if (zone->reported_pages)
		return;

	node = zone_to_nid(zone);
	size = (MAX_ORDER - PAGE_REPORTING_MIN_ORDER) * sizeof(unsigned long);
	zone->reported_pages = kzalloc_node(size, GFP_KERNEL, node);
}

static void page_reporting_reset_all_boundaries(struct zone *zone)
{
	unsigned int order, mt;

	/* Update boundary data to reflect the zone we are currently working */
	for_each_reporting_migratetype_order(order, mt)
		page_reporting_reset_boundary(zone, order, mt);
}

static struct page *
get_unreported_page(struct zone *zone, unsigned int order, int mt)
{
	struct list_head *list = &zone->free_area[order].free_list[mt];
	struct list_head *tail = get_unreported_tail(zone, order, mt);
	unsigned long index = get_reporting_index(order, mt);
	struct page *page;

	/* Find a page of the appropriate size in the preferred list */
	page = list_last_entry(tail, struct page, lru);
	list_for_each_entry_from_reverse(page, list, lru) {
		/* If we entered this loop then the "raw" list isn't empty */

		/*
		 * We are going to skip over the reported pages. Make
		 * certain that the index of those pages are correct
		 * as we will later be moving the boundary into place
		 * above them.
		 */
		if (PageReported(page)) {
			page->index = index;
			tail = &page->lru;
			continue;
		}

		/* Drop reference to page if isolate fails */
		if (__isolate_free_page(page, order))
			goto out;

		break;
	}

	page = NULL;
out:
	/* Update the boundary */
	reported_boundary[index] = tail;

	return page;
}

static void
__page_reporting_cancel(struct zone *zone,
			struct page_reporting_dev_info *phdev)
{
	/* processing of the zone is complete, we can disable boundaries */
	page_reporting_disable_boundaries(zone);

	/*
	 * If there are no longer enough free pages to fully populate
	 * the scatterlist, then we can just shut it down for this zone.
	 */
	__clear_bit(ZONE_PAGE_REPORTING_REQUESTED, &zone->flags);
	atomic_dec(&phdev->refcnt);
}

static unsigned int
page_reporting_fill(struct zone *zone, struct page_reporting_dev_info *phdev)
{
	struct scatterlist *sg = phdev->sg;
	unsigned int order, mt, count = 0;

	sg_init_table(phdev->sg, phdev->capacity);

	/* Make sure the boundaries are enabled */
	if (!__test_and_set_bit(ZONE_PAGE_REPORTING_ACTIVE, &zone->flags))
		page_reporting_reset_all_boundaries(zone);

	for_each_reporting_migratetype_order(order, mt) {
		struct page *page;

		/*
		 * Pull pages from free list until we have drained
		 * it or we have reached capacity.
		 */
		while ((page = get_unreported_page(zone, order, mt))) {
			sg_set_page(&sg[count], page, PAGE_SIZE << order, 0);

			if (++count == phdev->capacity)
				return phdev->capacity;
		}
	}

	/* mark end of scatterlist due to underflow */
	if (count)
		sg_mark_end(&sg[count - 1]);

	/* We ran out of pages so we can stop now */
	__page_reporting_cancel(zone, phdev);

	return count;
}

static void page_reporting_drain(struct page_reporting_dev_info *phdev)
{
	struct scatterlist *sg = phdev->sg;

	/*
	 * Drain the now reported pages back into their respective
	 * free lists/areas. We assume at least one page is populated.
	 */
	do {
		free_reported_page(sg_page(sg), get_order(sg->length));
	} while (!sg_is_last(sg++));
}

/*
 * The page reporting cycle consists of 4 stages, fill, report, drain, and
 * idle. We will cycle through the first 3 stages until we fail to obtain any
 * pages, in that case we will switch to idle.
 */
static void
page_reporting_cycle(struct zone *zone, struct page_reporting_dev_info *phdev)
{
	/*
	 * Guarantee boundaries and stats are populated before we
	 * start placing reported pages in the zone.
	 */
	page_reporting_populate_metadata(zone);

	spin_lock_irq(&zone->lock);

	/* Cancel the request if we failed to populate zone metadata */
	if (!zone->reported_pages) {
		__page_reporting_cancel(zone, phdev);
		goto zone_not_ready;
	}

	do {
		/* Pull pages out of allocator into a scaterlist */
		unsigned int nents = page_reporting_fill(zone, phdev);

		/* no pages were acquired, give up */
		if (!nents)
			break;

		spin_unlock_irq(&zone->lock);

		/* begin processing pages in local list */
		phdev->report(phdev, nents);

		spin_lock_irq(&zone->lock);

		/*
		 * We should have a scatterlist of pages that have been
		 * processed. Return them to their original free lists.
		 */
		page_reporting_drain(phdev);

		/* keep pulling pages till there are none to pull */
	} while (test_bit(ZONE_PAGE_REPORTING_REQUESTED, &zone->flags));
zone_not_ready:
	spin_unlock_irq(&zone->lock);
}

static void page_reporting_process(struct work_struct *work)
{
	struct delayed_work *d_work = to_delayed_work(work);
	struct page_reporting_dev_info *phdev =
		container_of(d_work, struct page_reporting_dev_info, work);
	struct zone *zone = first_online_pgdat()->node_zones;

	do {
		if (test_bit(ZONE_PAGE_REPORTING_REQUESTED, &zone->flags))
			page_reporting_cycle(zone, phdev);

		/* Move to next zone, if at end of list start over */
		zone = next_zone(zone) ? : first_online_pgdat()->node_zones;

		/*
		 * As long as refcnt has not reached zero there are still
		 * zones to be processed.
		 */
	} while (atomic_read(&phdev->refcnt));
}

/* request page reporting on this zone */
void __page_reporting_request(struct zone *zone)
{
	struct page_reporting_dev_info *phdev;

	rcu_read_lock();

	/*
	 * We use RCU to protect the ph_dev_info pointer. In almost all
	 * cases this should be present, however in the unlikely case of
	 * a shutdown this will be NULL and we should exit.
	 */
	phdev = rcu_dereference(ph_dev_info);
	if (unlikely(!phdev))
		goto out;

	/*
	 * We can use separate test and set operations here as there
	 * is nothing else that can set or clear this bit while we are
	 * holding the zone lock. The advantage to doing it this way is
	 * that we don't have to dirty the cacheline unless we are
	 * changing the value.
	 */
	__set_bit(ZONE_PAGE_REPORTING_REQUESTED, &zone->flags);

	/*
	 * Delay the start of work to allow a sizable queue to
	 * build. For now we are limiting this to running no more
	 * than 10 times per second.
	 */
	if (!atomic_fetch_inc(&phdev->refcnt))
		schedule_delayed_work(&phdev->work, HZ / 10);
out:
	rcu_read_unlock();
}

static DEFINE_MUTEX(page_reporting_mutex);
DEFINE_STATIC_KEY_FALSE(page_reporting_notify_enabled);

void page_reporting_unregister(struct page_reporting_dev_info *phdev)
{
	mutex_lock(&page_reporting_mutex);

	if (rcu_access_pointer(ph_dev_info) == phdev) {
		/* Disable page reporting notification */
		static_branch_disable(&page_reporting_notify_enabled);
		RCU_INIT_POINTER(ph_dev_info, NULL);
		synchronize_rcu();

		/* Flush any existing work, and lock it out */
		cancel_delayed_work_sync(&phdev->work);

		/* Free scatterlist */
		kfree(phdev->sg);
		phdev->sg = NULL;

		/* Free boundaries */
		kfree(reported_boundary);
		reported_boundary = NULL;
	}

	mutex_unlock(&page_reporting_mutex);
}
EXPORT_SYMBOL_GPL(page_reporting_unregister);

int page_reporting_register(struct page_reporting_dev_info *phdev)
{
	struct zone *zone;
	int err = 0;

	/* No point in enabling this if it cannot handle any pages */
	if (WARN_ON(!phdev->capacity))
		return -EINVAL;

	mutex_lock(&page_reporting_mutex);

	/* nothing to do if already in use */
	if (rcu_access_pointer(ph_dev_info)) {
		err = -EBUSY;
		goto err_out;
	}

	/*
	 * Allocate space to store the boundaries for the zone we are
	 * actively reporting on. We will need to store one boundary
	 * pointer per migratetype, and then we need to have one of these
	 * arrays per order for orders greater than or equal to
	 * PAGE_REPORTING_MIN_ORDER.
	 */
	reported_boundary = kcalloc(get_reporting_index(MAX_ORDER, 0),
				    sizeof(struct list_head *), GFP_KERNEL);
	if (!reported_boundary) {
		err = -ENOMEM;
		goto err_out;
	}

	/* allocate scatterlist to store pages being reported on */
	phdev->sg = kcalloc(phdev->capacity, sizeof(*phdev->sg), GFP_KERNEL);
	if (!phdev->sg) {
		err = -ENOMEM;

		kfree(reported_boundary);
		reported_boundary = NULL;

		goto err_out;
	}


	/* initialize refcnt and work structures */
	atomic_set(&phdev->refcnt, 0);
	INIT_DELAYED_WORK(&phdev->work, &page_reporting_process);

	/* assign device, and begin initial flush of populated zones */
	rcu_assign_pointer(ph_dev_info, phdev);
	for_each_populated_zone(zone) {
		spin_lock_irq(&zone->lock);
		__page_reporting_request(zone);
		spin_unlock_irq(&zone->lock);
	}

	/* enable page reporting notification */
	static_branch_enable(&page_reporting_notify_enabled);
err_out:
	mutex_unlock(&page_reporting_mutex);

	return err;
}
EXPORT_SYMBOL_GPL(page_reporting_register);
