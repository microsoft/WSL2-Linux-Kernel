#include <linux/linkage.h>

#ifdef CONFIG_RETPOLINE
#ifdef CONFIG_X86_32
#define INDIRECT_THUNK(reg) extern asmlinkage void __x86_indirect_thunk_e ## reg(void); EXPORT_SYMBOL(__x86_indirect_thunk_e ## reg);
#else
#define INDIRECT_THUNK(reg) extern asmlinkage void __x86_indirect_thunk_r ## reg(void); EXPORT_SYMBOL(__x86_indirect_thunk_r ## reg);
INDIRECT_THUNK(8)
INDIRECT_THUNK(9)
INDIRECT_THUNK(10)
INDIRECT_THUNK(11)
INDIRECT_THUNK(12)
INDIRECT_THUNK(13)
INDIRECT_THUNK(14)
INDIRECT_THUNK(15)
#endif
INDIRECT_THUNK(ax)
INDIRECT_THUNK(bx)
INDIRECT_THUNK(cx)
INDIRECT_THUNK(dx)
INDIRECT_THUNK(si)
INDIRECT_THUNK(di)
INDIRECT_THUNK(bp)
#endif /* CONFIG_RETPOLINE */
