/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_LINKAGE_H
#define _ASM_X86_LINKAGE_H

#include <linux/stringify.h>

#undef notrace
#define notrace __attribute__((no_instrument_function))

#ifdef CONFIG_X86_32
#define asmlinkage CPP_ASMLINKAGE __attribute__((regparm(0)))
#endif /* CONFIG_X86_32 */

#define __ALIGN		.balign CONFIG_FUNCTION_ALIGNMENT, 0x90;
#define __ALIGN_STR	__stringify(__ALIGN)

#define ASM_FUNC_ALIGN		__ALIGN_STR
#define __FUNC_ALIGN		__ALIGN
#define SYM_F_ALIGN		__FUNC_ALIGN

#ifdef __ASSEMBLY__

#if defined(CONFIG_RETHUNK) && !defined(__DISABLE_EXPORTS) && !defined(BUILD_VDSO)
#define RET	jmp __x86_return_thunk
#else /* CONFIG_RETPOLINE */
#ifdef CONFIG_SLS
#define RET	ret; int3
#else
#define RET	ret
#endif
#endif /* CONFIG_RETPOLINE */

#else /* __ASSEMBLY__ */

#if defined(CONFIG_RETHUNK) && !defined(__DISABLE_EXPORTS) && !defined(BUILD_VDSO)
#define ASM_RET	"jmp __x86_return_thunk\n\t"
#else /* CONFIG_RETPOLINE */
#ifdef CONFIG_SLS
#define ASM_RET	"ret; int3\n\t"
#else
#define ASM_RET	"ret\n\t"
#endif
#endif /* CONFIG_RETPOLINE */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_LINKAGE_H */

