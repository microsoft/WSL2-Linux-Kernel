/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_CLOCKSOURCE_H
#define _ASM_CLOCKSOURCE_H

#define VCLOCK_NONE	0	/* No vDSO clock available.		*/
#define VCLOCK_CNTVCT	1	/* vDSO should use cntvcnt		*/
#define VCLOCK_MAX	1

struct arch_clocksource_data {
	int vclock_mode;
};

#endif
