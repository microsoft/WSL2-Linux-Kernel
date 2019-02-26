/*
 * Copyright (C) 2012 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/cpuidle.h>
#include <linux/module.h>
#include <asm/cpuidle.h>
#include <asm/proc-fns.h>

#include "common.h"
#include "cpuidle.h"
#include "hardware.h"

static int num_idle_cpus = 0;
static DEFINE_SPINLOCK(cpuidle_lock);

static int imx6q_enter_wait(struct cpuidle_device *dev,
			    struct cpuidle_driver *drv, int index)
{
	spin_lock(&cpuidle_lock);
	if (++num_idle_cpus == num_online_cpus())
		imx6q_set_lpm(WAIT_UNCLOCKED);
	spin_unlock(&cpuidle_lock);

	cpu_do_idle();

	spin_lock(&cpuidle_lock);
	if (num_idle_cpus-- == num_online_cpus())
		imx6q_set_lpm(WAIT_CLOCKED);
	spin_unlock(&cpuidle_lock);

	return index;
}

static struct cpuidle_driver imx6q_cpuidle_driver = {
	.name = "imx6q_cpuidle",
	.owner = THIS_MODULE,
	.states = {
		/* WFI */
		ARM_CPUIDLE_WFI_STATE,
		/* WAIT */
		{
			.exit_latency = 50,
			.target_residency = 75,
			.flags = CPUIDLE_FLAG_TIME_VALID |
			         CPUIDLE_FLAG_TIMER_STOP,
			.enter = imx6q_enter_wait,
			.name = "WAIT",
			.desc = "Clock off",
		},
	},
	.state_count = 2,
	.safe_state_index = 0,
};

int __init imx6q_cpuidle_init(void)
{
	/* Set INT_MEM_CLK_LPM bit to get a reliable WAIT mode support */
	imx6q_set_int_mem_clk_lpm(true);

	return cpuidle_register(&imx6q_cpuidle_driver, NULL);
}
