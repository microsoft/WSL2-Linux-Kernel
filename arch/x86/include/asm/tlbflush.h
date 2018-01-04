#ifndef _ASM_X86_TLBFLUSH_H
#define _ASM_X86_TLBFLUSH_H

#include <linux/mm.h>
#include <linux/sched.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/smp.h>

static inline void __invpcid(unsigned long pcid, unsigned long addr,
			     unsigned long type)
{
	struct { u64 d[2]; } desc = { { pcid, addr } };

	/*
	 * The memory clobber is because the whole point is to invalidate
	 * stale TLB entries and, especially if we're flushing global
	 * mappings, we don't want the compiler to reorder any subsequent
	 * memory accesses before the TLB flush.
	 *
	 * The hex opcode is invpcid (%ecx), %eax in 32-bit mode and
	 * invpcid (%rcx), %rax in long mode.
	 */
	asm volatile (".byte 0x66, 0x0f, 0x38, 0x82, 0x01"
		      : : "m" (desc), "a" (type), "c" (&desc) : "memory");
}

#define INVPCID_TYPE_INDIV_ADDR		0
#define INVPCID_TYPE_SINGLE_CTXT	1
#define INVPCID_TYPE_ALL_INCL_GLOBAL	2
#define INVPCID_TYPE_ALL_NON_GLOBAL	3

/* Flush all mappings for a given pcid and addr, not including globals. */
static inline void invpcid_flush_one(unsigned long pcid,
				     unsigned long addr)
{
	__invpcid(pcid, addr, INVPCID_TYPE_INDIV_ADDR);
}

/* Flush all mappings for a given PCID, not including globals. */
static inline void invpcid_flush_single_context(unsigned long pcid)
{
	__invpcid(pcid, 0, INVPCID_TYPE_SINGLE_CTXT);
}

/* Flush all mappings, including globals, for all PCIDs. */
static inline void invpcid_flush_all(void)
{
	__invpcid(0, 0, INVPCID_TYPE_ALL_INCL_GLOBAL);
}

/* Flush all mappings for all PCIDs except globals. */
static inline void invpcid_flush_all_nonglobals(void)
{
	__invpcid(0, 0, INVPCID_TYPE_ALL_NON_GLOBAL);
}

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else
#define __flush_tlb() __native_flush_tlb()
#define __flush_tlb_global() __native_flush_tlb_global()
#define __flush_tlb_single(addr) __native_flush_tlb_single(addr)
#endif

/*
 * Declare a couple of kaiser interfaces here for convenience,
 * to avoid the need for asm/kaiser.h in unexpected places.
 */
#ifdef CONFIG_PAGE_TABLE_ISOLATION
extern int kaiser_enabled;
extern void kaiser_setup_pcid(void);
extern void kaiser_flush_tlb_on_return_to_user(void);
#else
#define kaiser_enabled 0
static inline void kaiser_setup_pcid(void)
{
}
static inline void kaiser_flush_tlb_on_return_to_user(void)
{
}
#endif

static inline void __native_flush_tlb(void)
{
	/*
	 * If current->mm == NULL then we borrow a mm which may change during a
	 * task switch and therefore we must not be preempted while we write CR3
	 * back:
	 */
	preempt_disable();
	if (kaiser_enabled)
		kaiser_flush_tlb_on_return_to_user();
	native_write_cr3(native_read_cr3());
	preempt_enable();
}

static inline void __native_flush_tlb_global(void)
{
	unsigned long flags;
	unsigned long cr4;

	if (this_cpu_has(X86_FEATURE_INVPCID)) {
		/*
		 * Using INVPCID is considerably faster than a pair of writes
		 * to CR4 sandwiched inside an IRQ flag save/restore.
		 *
	 	 * Note, this works with CR4.PCIDE=0 or 1.
		 */
		invpcid_flush_all();
		return;
	}

	/*
	 * Read-modify-write to CR4 - protect it from preemption and
	 * from interrupts. (Use the raw variant because this code can
	 * be called from deep inside debugging code.)
	 */
	raw_local_irq_save(flags);

	cr4 = native_read_cr4();
	if (cr4 & X86_CR4_PGE) {
		/* clear PGE and flush TLB of all entries */
		native_write_cr4(cr4 & ~X86_CR4_PGE);
		/* restore PGE as it was before */
		native_write_cr4(cr4);
	} else {
		/* do it with cr3, letting kaiser flush user PCID */
		__native_flush_tlb();
	}

	raw_local_irq_restore(flags);
}

static inline void __native_flush_tlb_single(unsigned long addr)
{
	/*
	 * SIMICS #GP's if you run INVPCID with type 2/3
	 * and X86_CR4_PCIDE clear.  Shame!
	 *
	 * The ASIDs used below are hard-coded.  But, we must not
	 * call invpcid(type=1/2) before CR4.PCIDE=1.  Just call
	 * invlpg in the case we are called early.
	 */

	if (!this_cpu_has(X86_FEATURE_INVPCID_SINGLE)) {
		if (kaiser_enabled)
			kaiser_flush_tlb_on_return_to_user();
		asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
		return;
	}
	/* Flush the address out of both PCIDs. */
	/*
	 * An optimization here might be to determine addresses
	 * that are only kernel-mapped and only flush the kernel
	 * ASID.  But, userspace flushes are probably much more
	 * important performance-wise.
	 *
	 * Make sure to do only a single invpcid when KAISER is
	 * disabled and we have only a single ASID.
	 */
	if (kaiser_enabled)
		invpcid_flush_one(X86_CR3_PCID_ASID_USER, addr);
	invpcid_flush_one(X86_CR3_PCID_ASID_KERN, addr);
}

static inline void __flush_tlb_all(void)
{
	__flush_tlb_global();
	/*
	 * Note: if we somehow had PCID but not PGE, then this wouldn't work --
	 * we'd end up flushing kernel translations for the current ASID but
	 * we might fail to flush kernel translations for other cached ASIDs.
	 *
	 * To avoid this issue, we force PCID off if PGE is off.
	 */
}

static inline void __flush_tlb_one(unsigned long addr)
{
	if (cpu_has_invlpg)
		__flush_tlb_single(addr);
	else
		__flush_tlb();
}

#ifdef CONFIG_X86_32
# define TLB_FLUSH_ALL	0xffffffff
#else
# define TLB_FLUSH_ALL	-1ULL
#endif

/*
 * TLB flushing:
 *
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes a range of kernel pages
 *  - flush_tlb_others(cpumask, mm, va) flushes TLBs on other cpus
 *
 * ..but the i386 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */

#define local_flush_tlb() __flush_tlb()

extern void flush_tlb_all(void);
extern void flush_tlb_current_task(void);
extern void flush_tlb_mm(struct mm_struct *);
extern void flush_tlb_page(struct vm_area_struct *, unsigned long);

#define flush_tlb()	flush_tlb_current_task()

static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	flush_tlb_mm(vma->vm_mm);
}

void native_flush_tlb_others(const struct cpumask *cpumask,
			     struct mm_struct *mm, unsigned long va);

#define TLBSTATE_OK	1
#define TLBSTATE_LAZY	2

struct tlb_state {
	struct mm_struct *active_mm;
	int state;
};
DECLARE_PER_CPU_SHARED_ALIGNED(struct tlb_state, cpu_tlbstate);

static inline void reset_lazy_tlbstate(void)
{
	percpu_write(cpu_tlbstate.state, 0);
	percpu_write(cpu_tlbstate.active_mm, &init_mm);
}

#ifndef CONFIG_PARAVIRT
#define flush_tlb_others(mask, mm, va)	native_flush_tlb_others(mask, mm, va)
#endif

static inline void flush_tlb_kernel_range(unsigned long start,
					  unsigned long end)
{
	flush_tlb_all();
}

#endif /* _ASM_X86_TLBFLUSH_H */
