// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 */

#include <linux/crash_core.h>
#include <asm/memory.h>

static inline u64 get_tcr_el1_t1sz(void);

static inline u64 get_tcr_el1_t1sz(void)
{
	return (read_sysreg(tcr_el1) & TCR_T1SZ_MASK) >> TCR_T1SZ_OFFSET;
}

void arch_crash_save_vmcoreinfo(void)
{
	VMCOREINFO_NUMBER(VA_BITS);
	/* Please note VMCOREINFO_NUMBER() uses "%d", not "%x" */
	vmcoreinfo_append_str("NUMBER(kimage_voffset)=0x%llx\n",
						kimage_voffset);
	vmcoreinfo_append_str("NUMBER(PHYS_OFFSET)=0x%llx\n",
						PHYS_OFFSET);
	vmcoreinfo_append_str("NUMBER(tcr_el1_t1sz)=0x%llx\n",
						get_tcr_el1_t1sz());
	vmcoreinfo_append_str("KERNELOFFSET=%lx\n", kaslr_offset());
}
