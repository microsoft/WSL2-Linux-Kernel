/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Microsoft Hyper-V hypervisor invocation routines
 *
 * Copyright (C) 2018, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

	.text
/*
 * Do the HVC instruction.  For Hyper-V the argument is always 1.
 * x0 contains the hypercall control value, while additional registers
 * vary depending on the hypercall, and whether the hypercall arguments
 * are in memory or in registers (a "fast" hypercall per the Hyper-V
 * TLFS).  When the arguments are in memory x1 is the guest physical
 * address of the input arguments, and x2 is the guest physical
 * address of the output arguments.  When the arguments are in
 * registers, the register values depends on the hypercall.  Note
 * that this version cannot return any values in registers.
 */
SYM_FUNC_START(hv_do_hvc)
	hvc #1
	ret
SYM_FUNC_END(hv_do_hvc)

/*
 * This variant of HVC invocation is for hv_get_vpreg and
 * hv_get_vpreg_128. The input parameters are passed in registers
 * along with a pointer in x4 to where the output result should
 * be stored. The output is returned in x15 and x16. x19 is used as
 * scratch space to avoid buildng a stack frame, as Hyper-V does
 * not preserve registers x0-x17.
 */
SYM_FUNC_START(hv_do_hvc_fast_get)
	/*
	 * Stash away x19 register so that it can be used as a scratch
	 * register and pop it at the end.
	 */
	str x19, [sp, #-16]!
	mov x19, x4
	hvc #1
	str x15,[x19]
	str x16,[x19,#8]
	ldr x19, [sp], #16
	ret
SYM_FUNC_END(hv_do_hvc_fast_get)
