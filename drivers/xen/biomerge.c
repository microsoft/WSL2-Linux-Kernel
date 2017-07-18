#include <linux/bio.h>
#include <linux/io.h>
#include <linux/export.h>
#include <xen/page.h>

bool xen_biovec_phys_mergeable(const struct bio_vec *vec1,
			       const struct bio_vec *vec2)
{
	unsigned long mfn1 = pfn_to_mfn(page_to_pfn(vec1->bv_page));
	unsigned long mfn2 = pfn_to_mfn(page_to_pfn(vec2->bv_page));

	return mfn1 + PFN_DOWN(vec1->bv_offset + vec1->bv_len) == mfn2;
}
EXPORT_SYMBOL(xen_biovec_phys_mergeable);
