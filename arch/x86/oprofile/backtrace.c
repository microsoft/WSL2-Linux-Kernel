/**
 * @file backtrace.c
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author David Smith
 */

#include <linux/oprofile.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/highmem.h>

#include <asm/ptrace.h>
#include <asm/uaccess.h>
#include <asm/stacktrace.h>

static void backtrace_warning_symbol(void *data, char *msg,
				     unsigned long symbol)
{
	/* Ignore warnings */
}

static void backtrace_warning(void *data, char *msg)
{
	/* Ignore warnings */
}

static int backtrace_stack(void *data, char *name)
{
	/* Yes, we want all stacks */
	return 0;
}

static void backtrace_address(void *data, unsigned long addr, int reliable)
{
	unsigned int *depth = data;

	if ((*depth)--)
		oprofile_add_trace(addr);
}

static struct stacktrace_ops backtrace_ops = {
	.warning = backtrace_warning,
	.warning_symbol = backtrace_warning_symbol,
	.stack = backtrace_stack,
	.address = backtrace_address,
};

/* from arch/x86/kernel/cpu/perf_event.c: */

/*
 * best effort, GUP based copy_from_user() that assumes IRQ or NMI context
 */
static unsigned long
copy_from_user_nmi(void *to, const void __user *from, unsigned long n)
{
	unsigned long offset, addr = (unsigned long)from;
	unsigned long size, len = 0;
	struct page *page;
	void *map;
	int ret;

	do {
		ret = __get_user_pages_fast(addr, 1, 0, &page);
		if (!ret)
			break;

		offset = addr & (PAGE_SIZE - 1);
		size = min(PAGE_SIZE - offset, n - len);

		map = kmap_atomic(page, KM_USER0);
		memcpy(to, map+offset, size);
		kunmap_atomic(map, KM_USER0);
		put_page(page);

		len  += size;
		to   += size;
		addr += size;

	} while (len < n);

	return len;
}

struct frame_head {
	struct frame_head *bp;
	unsigned long ret;
} __attribute__((packed));

static struct frame_head *dump_user_backtrace(struct frame_head *head)
{
	/* Also check accessibility of one struct frame_head beyond: */
	struct frame_head bufhead[2];
	unsigned long bytes;

	bytes = copy_from_user_nmi(bufhead, head, sizeof(bufhead));
	if (bytes != sizeof(bufhead))
		return NULL;

	oprofile_add_trace(bufhead[0].ret);

	/* frame pointers should strictly progress back up the stack
	 * (towards higher addresses) */
	if (head >= bufhead[0].bp)
		return NULL;

	return bufhead[0].bp;
}

void
x86_backtrace(struct pt_regs * const regs, unsigned int depth)
{
	struct frame_head *head = (struct frame_head *)frame_pointer(regs);

	if (!user_mode_vm(regs)) {
		unsigned long stack = kernel_stack_pointer(regs);
		if (depth)
			dump_trace(NULL, regs, (unsigned long *)stack, 0,
				   &backtrace_ops, &depth);
		return;
	}

	while (depth-- && head)
		head = dump_user_backtrace(head);
}
