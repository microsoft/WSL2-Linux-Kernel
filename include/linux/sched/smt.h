/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_SMT_H
#define _LINUX_SCHED_SMT_H

#include <linux/atomic.h>

#ifdef CONFIG_SCHED_SMT
extern atomic_t sched_smt_present;

static __always_inline bool sched_smt_active(void)
{
	return atomic_read(&sched_smt_present);
}
#else
static inline bool sched_smt_active(void) { return false; }
#endif

void arch_smt_update(void);

#endif
