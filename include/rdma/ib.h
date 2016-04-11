#if !defined(_RDMA_IB_H)
#define _RDMA_IB_H

#include <linux/sched.h>

/*
 * The IB interfaces that use write() as bi-directional ioctl() are
 * fundamentally unsafe, since there are lots of ways to trigger "write()"
 * calls from various contexts with elevated privileges. That includes the
 * traditional suid executable error message writes, but also various kernel
 * interfaces that can write to file descriptors.
 *
 * This function provides protection for the legacy API by restricting the
 * calling context.
 */
static inline bool ib_safe_file_access(struct file *filp)
{
	return filp->f_cred == current_cred() && segment_eq(get_fs(), USER_DS);
}

#endif /* _RDMA_IB_H */
