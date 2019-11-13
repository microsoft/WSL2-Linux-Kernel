#ifndef _ASM_POWERPC_ASM_PROTOTYPES_H
#define _ASM_POWERPC_ASM_PROTOTYPES_H
/*
 * This file is for prototypes of C functions that are only called
 * from asm, and any associated variables.
 *
 * Copyright 2016, Daniel Axtens, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

/* Patch sites */
extern s32 patch__call_flush_count_cache;
extern s32 patch__flush_count_cache_return;
extern s32 patch__flush_link_stack_return;
extern s32 patch__call_kvm_flush_link_stack;

extern long flush_count_cache;
extern long kvm_flush_link_stack;

#endif /* _ASM_POWERPC_ASM_PROTOTYPES_H */
