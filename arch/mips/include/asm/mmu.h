#ifndef __ASM_MMU_H
#define __ASM_MMU_H

typedef struct {
	u64 asid[NR_CPUS];
	void *vdso;
} mm_context_t;

#endif /* __ASM_MMU_H */
