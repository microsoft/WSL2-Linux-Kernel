/* SPDX-License-Identifier: GPL-2.0 */

#include <string.h>
#include "evlist.h"
#include "env.h"
#include "sample-raw.h"
#include <sys/utsname.h>
#define fldsz(name, field)  (sizeof(((struct name *)0)->field))
/*
 * Check platform the perf data file was created on and perform platform
 * specific interpretation.
 */
void perf_evlist__init_trace_event_sample_raw(struct evlist *evlist)
{
  char arch_name_buf[fldsz(utsname, machine)];
  const char* arch_pf = perf_env__arch(evlist->env, arch_name_buf);

  if (arch_pf && !strcmp("s390", arch_pf))
    evlist->trace_event_sample_raw = perf_evlist__s390_sample_raw;
}
