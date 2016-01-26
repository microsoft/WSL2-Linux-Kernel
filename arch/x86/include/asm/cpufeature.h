/*
 * Defines x86 CPU feature bits
 */
#ifndef _ASM_X86_CPUFEATURE_H
#define _ASM_X86_CPUFEATURE_H

#include <asm/processor.h>

#if defined(__KERNEL__) && !defined(__ASSEMBLY__)

#include <asm/asm.h>
#include <linux/bitops.h>

extern const char * const x86_cap_flags[NCAPINTS*32];
extern const char * const x86_power_flags[32];

/*
 * In order to save room, we index into this array by doing
 * X86_BUG_<name> - NCAPINTS*32.
 */
extern const char * const x86_bug_flags[NBUGINTS*32];

#define test_cpu_cap(c, bit)						\
	 test_bit(bit, (unsigned long *)((c)->x86_capability))

#define REQUIRED_MASK_BIT_SET(bit)					\
	 ( (((bit)>>5)==0 && (1UL<<((bit)&31) & REQUIRED_MASK0)) ||	\
	   (((bit)>>5)==1 && (1UL<<((bit)&31) & REQUIRED_MASK1)) ||	\
	   (((bit)>>5)==2 && (1UL<<((bit)&31) & REQUIRED_MASK2)) ||	\
	   (((bit)>>5)==3 && (1UL<<((bit)&31) & REQUIRED_MASK3)) ||	\
	   (((bit)>>5)==4 && (1UL<<((bit)&31) & REQUIRED_MASK4)) ||	\
	   (((bit)>>5)==5 && (1UL<<((bit)&31) & REQUIRED_MASK5)) ||	\
	   (((bit)>>5)==6 && (1UL<<((bit)&31) & REQUIRED_MASK6)) ||	\
	   (((bit)>>5)==7 && (1UL<<((bit)&31) & REQUIRED_MASK7)) ||	\
	   (((bit)>>5)==8 && (1UL<<((bit)&31) & REQUIRED_MASK8)) ||	\
	   (((bit)>>5)==9 && (1UL<<((bit)&31) & REQUIRED_MASK9)) )

#define cpu_has(c, bit)							\
	(__builtin_constant_p(bit) && REQUIRED_MASK_BIT_SET(bit) ? 1 :	\
	 test_cpu_cap(c, bit))

#define this_cpu_has(bit)						\
	(__builtin_constant_p(bit) && REQUIRED_MASK_BIT_SET(bit) ? 1 : 	\
	 x86_this_cpu_test_bit(bit, (unsigned long *)&cpu_info.x86_capability))

#define boot_cpu_has(bit)	cpu_has(&boot_cpu_data, bit)

#define set_cpu_cap(c, bit)	set_bit(bit, (unsigned long *)((c)->x86_capability))
#define clear_cpu_cap(c, bit)	clear_bit(bit, (unsigned long *)((c)->x86_capability))
#define setup_clear_cpu_cap(bit) do { \
	clear_cpu_cap(&boot_cpu_data, bit);	\
	set_bit(bit, (unsigned long *)cpu_caps_cleared); \
} while (0)
#define setup_force_cpu_cap(bit) do { \
	set_cpu_cap(&boot_cpu_data, bit);	\
	set_bit(bit, (unsigned long *)cpu_caps_set);	\
} while (0)

#define setup_force_cpu_bug(bit) setup_force_cpu_cap(bit)

#define cpu_has_fpu		boot_cpu_has(X86_FEATURE_FPU)
#define cpu_has_vme		boot_cpu_has(X86_FEATURE_VME)
#define cpu_has_de		boot_cpu_has(X86_FEATURE_DE)
#define cpu_has_pse		boot_cpu_has(X86_FEATURE_PSE)
#define cpu_has_tsc		boot_cpu_has(X86_FEATURE_TSC)
#define cpu_has_pae		boot_cpu_has(X86_FEATURE_PAE)
#define cpu_has_pge		boot_cpu_has(X86_FEATURE_PGE)
#define cpu_has_apic		boot_cpu_has(X86_FEATURE_APIC)
#define cpu_has_sep		boot_cpu_has(X86_FEATURE_SEP)
#define cpu_has_mtrr		boot_cpu_has(X86_FEATURE_MTRR)
#define cpu_has_mmx		boot_cpu_has(X86_FEATURE_MMX)
#define cpu_has_fxsr		boot_cpu_has(X86_FEATURE_FXSR)
#define cpu_has_xmm		boot_cpu_has(X86_FEATURE_XMM)
#define cpu_has_xmm2		boot_cpu_has(X86_FEATURE_XMM2)
#define cpu_has_xmm3		boot_cpu_has(X86_FEATURE_XMM3)
#define cpu_has_ssse3		boot_cpu_has(X86_FEATURE_SSSE3)
#define cpu_has_aes		boot_cpu_has(X86_FEATURE_AES)
#define cpu_has_avx		boot_cpu_has(X86_FEATURE_AVX)
#define cpu_has_avx2		boot_cpu_has(X86_FEATURE_AVX2)
#define cpu_has_ht		boot_cpu_has(X86_FEATURE_HT)
#define cpu_has_mp		boot_cpu_has(X86_FEATURE_MP)
#define cpu_has_nx		boot_cpu_has(X86_FEATURE_NX)
#define cpu_has_k6_mtrr		boot_cpu_has(X86_FEATURE_K6_MTRR)
#define cpu_has_cyrix_arr	boot_cpu_has(X86_FEATURE_CYRIX_ARR)
#define cpu_has_centaur_mcr	boot_cpu_has(X86_FEATURE_CENTAUR_MCR)
#define cpu_has_xstore		boot_cpu_has(X86_FEATURE_XSTORE)
#define cpu_has_xstore_enabled	boot_cpu_has(X86_FEATURE_XSTORE_EN)
#define cpu_has_xcrypt		boot_cpu_has(X86_FEATURE_XCRYPT)
#define cpu_has_xcrypt_enabled	boot_cpu_has(X86_FEATURE_XCRYPT_EN)
#define cpu_has_ace2		boot_cpu_has(X86_FEATURE_ACE2)
#define cpu_has_ace2_enabled	boot_cpu_has(X86_FEATURE_ACE2_EN)
#define cpu_has_phe		boot_cpu_has(X86_FEATURE_PHE)
#define cpu_has_phe_enabled	boot_cpu_has(X86_FEATURE_PHE_EN)
#define cpu_has_pmm		boot_cpu_has(X86_FEATURE_PMM)
#define cpu_has_pmm_enabled	boot_cpu_has(X86_FEATURE_PMM_EN)
#define cpu_has_ds		boot_cpu_has(X86_FEATURE_DS)
#define cpu_has_pebs		boot_cpu_has(X86_FEATURE_PEBS)
#define cpu_has_clflush		boot_cpu_has(X86_FEATURE_CLFLUSH)
#define cpu_has_bts		boot_cpu_has(X86_FEATURE_BTS)
#define cpu_has_gbpages		boot_cpu_has(X86_FEATURE_GBPAGES)
#define cpu_has_arch_perfmon	boot_cpu_has(X86_FEATURE_ARCH_PERFMON)
#define cpu_has_pat		boot_cpu_has(X86_FEATURE_PAT)
#define cpu_has_xmm4_1		boot_cpu_has(X86_FEATURE_XMM4_1)
#define cpu_has_xmm4_2		boot_cpu_has(X86_FEATURE_XMM4_2)
#define cpu_has_x2apic		boot_cpu_has(X86_FEATURE_X2APIC)
#define cpu_has_xsave		boot_cpu_has(X86_FEATURE_XSAVE)
#define cpu_has_xsaveopt	boot_cpu_has(X86_FEATURE_XSAVEOPT)
#define cpu_has_osxsave		boot_cpu_has(X86_FEATURE_OSXSAVE)
#define cpu_has_hypervisor	boot_cpu_has(X86_FEATURE_HYPERVISOR)
#define cpu_has_pclmulqdq	boot_cpu_has(X86_FEATURE_PCLMULQDQ)
#define cpu_has_perfctr_core	boot_cpu_has(X86_FEATURE_PERFCTR_CORE)
#define cpu_has_perfctr_nb	boot_cpu_has(X86_FEATURE_PERFCTR_NB)
#define cpu_has_perfctr_l2	boot_cpu_has(X86_FEATURE_PERFCTR_L2)
#define cpu_has_cx8		boot_cpu_has(X86_FEATURE_CX8)
#define cpu_has_cx16		boot_cpu_has(X86_FEATURE_CX16)
#define cpu_has_eager_fpu	boot_cpu_has(X86_FEATURE_EAGER_FPU)
#define cpu_has_topoext		boot_cpu_has(X86_FEATURE_TOPOEXT)

#ifdef CONFIG_X86_64

#undef  cpu_has_vme
#define cpu_has_vme		0

#undef  cpu_has_pae
#define cpu_has_pae		___BUG___

#undef  cpu_has_mp
#define cpu_has_mp		1

#undef  cpu_has_k6_mtrr
#define cpu_has_k6_mtrr		0

#undef  cpu_has_cyrix_arr
#define cpu_has_cyrix_arr	0

#undef  cpu_has_centaur_mcr
#define cpu_has_centaur_mcr	0

#endif /* CONFIG_X86_64 */

#if __GNUC__ >= 4
extern void warn_pre_alternatives(void);
extern bool __static_cpu_has_safe(u16 bit);

/*
 * Static testing of CPU features.  Used the same as boot_cpu_has().
 * These are only valid after alternatives have run, but will statically
 * patch the target code for additional performance.
 */
static __always_inline __pure bool __static_cpu_has(u16 bit)
{
#ifdef CC_HAVE_ASM_GOTO

#ifdef CONFIG_X86_DEBUG_STATIC_CPU_HAS

		/*
		 * Catch too early usage of this before alternatives
		 * have run.
		 */
		asm_volatile_goto("1: jmp %l[t_warn]\n"
			 "2:\n"
			 ".section .altinstructions,\"a\"\n"
			 " .long 1b - .\n"
			 " .long 0\n"		/* no replacement */
			 " .word %P0\n"		/* 1: do replace */
			 " .byte 2b - 1b\n"	/* source len */
			 " .byte 0\n"		/* replacement len */
			 " .byte 0\n"		/* pad len */
			 ".previous\n"
			 /* skipping size check since replacement size = 0 */
			 : : "i" (X86_FEATURE_ALWAYS) : : t_warn);

#endif

		asm_volatile_goto("1: jmp %l[t_no]\n"
			 "2:\n"
			 ".section .altinstructions,\"a\"\n"
			 " .long 1b - .\n"
			 " .long 0\n"		/* no replacement */
			 " .word %P0\n"		/* feature bit */
			 " .byte 2b - 1b\n"	/* source len */
			 " .byte 0\n"		/* replacement len */
			 " .byte 0\n"		/* pad len */
			 ".previous\n"
			 /* skipping size check since replacement size = 0 */
			 : : "i" (bit) : : t_no);
		return true;
	t_no:
		return false;

#ifdef CONFIG_X86_DEBUG_STATIC_CPU_HAS
	t_warn:
		warn_pre_alternatives();
		return false;
#endif

#else /* CC_HAVE_ASM_GOTO */

		u8 flag;
		/* Open-coded due to __stringify() in ALTERNATIVE() */
		asm volatile("1: movb $0,%0\n"
			     "2:\n"
			     ".section .altinstructions,\"a\"\n"
			     " .long 1b - .\n"
			     " .long 3f - .\n"
			     " .word %P1\n"		/* feature bit */
			     " .byte 2b - 1b\n"		/* source len */
			     " .byte 4f - 3f\n"		/* replacement len */
			     " .byte 0\n"		/* pad len */
			     ".previous\n"
			     ".section .discard,\"aw\",@progbits\n"
			     " .byte 0xff + (4f-3f) - (2b-1b)\n" /* size check */
			     ".previous\n"
			     ".section .altinstr_replacement,\"ax\"\n"
			     "3: movb $1,%0\n"
			     "4:\n"
			     ".previous\n"
			     : "=qm" (flag) : "i" (bit));
		return flag;

#endif /* CC_HAVE_ASM_GOTO */
}

#define static_cpu_has(bit)					\
(								\
	__builtin_constant_p(boot_cpu_has(bit)) ?		\
		boot_cpu_has(bit) :				\
	__builtin_constant_p(bit) ?				\
		__static_cpu_has(bit) :				\
		boot_cpu_has(bit)				\
)

static __always_inline __pure bool _static_cpu_has_safe(u16 bit)
{
#ifdef CC_HAVE_ASM_GOTO
		asm_volatile_goto("1: jmp %l[t_dynamic]\n"
			 "2:\n"
			 ".skip -(((5f-4f) - (2b-1b)) > 0) * "
			         "((5f-4f) - (2b-1b)),0x90\n"
			 "3:\n"
			 ".section .altinstructions,\"a\"\n"
			 " .long 1b - .\n"		/* src offset */
			 " .long 4f - .\n"		/* repl offset */
			 " .word %P1\n"			/* always replace */
			 " .byte 3b - 1b\n"		/* src len */
			 " .byte 5f - 4f\n"		/* repl len */
			 " .byte 3b - 2b\n"		/* pad len */
			 ".previous\n"
			 ".section .altinstr_replacement,\"ax\"\n"
			 "4: jmp %l[t_no]\n"
			 "5:\n"
			 ".previous\n"
			 ".section .altinstructions,\"a\"\n"
			 " .long 1b - .\n"		/* src offset */
			 " .long 0\n"			/* no replacement */
			 " .word %P0\n"			/* feature bit */
			 " .byte 3b - 1b\n"		/* src len */
			 " .byte 0\n"			/* repl len */
			 " .byte 0\n"			/* pad len */
			 ".previous\n"
			 : : "i" (bit), "i" (X86_FEATURE_ALWAYS)
			 : : t_dynamic, t_no);
		return true;
	t_no:
		return false;
	t_dynamic:
		return __static_cpu_has_safe(bit);
#else
		u8 flag;
		/* Open-coded due to __stringify() in ALTERNATIVE() */
		asm volatile("1: movb $2,%0\n"
			     "2:\n"
			     ".section .altinstructions,\"a\"\n"
			     " .long 1b - .\n"		/* src offset */
			     " .long 3f - .\n"		/* repl offset */
			     " .word %P2\n"		/* always replace */
			     " .byte 2b - 1b\n"		/* source len */
			     " .byte 4f - 3f\n"		/* replacement len */
			     " .byte 0\n"		/* pad len */
			     ".previous\n"
			     ".section .discard,\"aw\",@progbits\n"
			     " .byte 0xff + (4f-3f) - (2b-1b)\n" /* size check */
			     ".previous\n"
			     ".section .altinstr_replacement,\"ax\"\n"
			     "3: movb $0,%0\n"
			     "4:\n"
			     ".previous\n"
			     ".section .altinstructions,\"a\"\n"
			     " .long 1b - .\n"		/* src offset */
			     " .long 5f - .\n"		/* repl offset */
			     " .word %P1\n"		/* feature bit */
			     " .byte 4b - 3b\n"		/* src len */
			     " .byte 6f - 5f\n"		/* repl len */
			     " .byte 0\n"		/* pad len */
			     ".previous\n"
			     ".section .discard,\"aw\",@progbits\n"
			     " .byte 0xff + (6f-5f) - (4b-3b)\n" /* size check */
			     ".previous\n"
			     ".section .altinstr_replacement,\"ax\"\n"
			     "5: movb $1,%0\n"
			     "6:\n"
			     ".previous\n"
			     : "=qm" (flag)
			     : "i" (bit), "i" (X86_FEATURE_ALWAYS));
		return (flag == 2 ? __static_cpu_has_safe(bit) : flag);
#endif /* CC_HAVE_ASM_GOTO */
}

#define static_cpu_has_safe(bit)				\
(								\
	__builtin_constant_p(boot_cpu_has(bit)) ?		\
		boot_cpu_has(bit) :				\
		_static_cpu_has_safe(bit)			\
)
#else
/*
 * gcc 3.x is too stupid to do the static test; fall back to dynamic.
 */
#define static_cpu_has(bit)		boot_cpu_has(bit)
#define static_cpu_has_safe(bit)	boot_cpu_has(bit)
#endif

#define cpu_has_bug(c, bit)	cpu_has(c, (bit))
#define set_cpu_bug(c, bit)	set_cpu_cap(c, (bit))
#define clear_cpu_bug(c, bit)	clear_cpu_cap(c, (bit));

#define static_cpu_has_bug(bit)	static_cpu_has((bit))
#define boot_cpu_has_bug(bit)	cpu_has_bug(&boot_cpu_data, (bit))

#define MAX_CPU_FEATURES	(NCAPINTS * 32)
#define cpu_have_feature	boot_cpu_has

#define CPU_FEATURE_TYPEFMT	"x86,ven%04Xfam%04Xmod%04X"
#define CPU_FEATURE_TYPEVAL	boot_cpu_data.x86_vendor, boot_cpu_data.x86, \
				boot_cpu_data.x86_model

#endif /* defined(__KERNEL__) && !defined(__ASSEMBLY__) */

#endif /* _ASM_X86_CPUFEATURE_H */
