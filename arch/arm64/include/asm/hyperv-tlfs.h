/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file contains definitions from the Hyper-V Hypervisor Top-Level
 * Functional Specification (TLFS):
 * https://na01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fdocs.microsoft.com%2Fen-us%2Fvirtualization%2Fhyper-v-on-windows%2Freference%2Ftlfs&amp;data=02%7C01%7Ckys%40microsoft.com%7Cc831a45fd63e4a4b083908d641216aa8%7C72f988bf86f141af91ab2d7cd011db47%7C1%7C0%7C636768009113747528&amp;sdata=jRSrs9ZWXdmeS7LQUEpoSyUfBS7a5KLYy%2FolFdE2tI0%3D&amp;reserved=0
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

#ifndef _ASM_ARM64_HYPERV_H
#define _ASM_ARM64_HYPERV_H

#include <linux/types.h>

/*
 * These Hyper-V registers provide information equivalent to the CPUID
 * instruction on x86/x64.
 */
#define HV_REGISTER_HYPERVISOR_VERSION		0x00000100 /*CPUID 0x40000002 */
#define	HV_REGISTER_PRIVILEGES_AND_FEATURES	0x00000200 /*CPUID 0x40000003 */
#define	HV_REGISTER_FEATURES			0x00000201 /*CPUID 0x40000004 */
#define	HV_REGISTER_IMPLEMENTATION_LIMITS	0x00000202 /*CPUID 0x40000005 */
#define HV_ARM64_REGISTER_INTERFACE_VERSION	0x00090006 /*CPUID 0x40000001 */

/*
 * Feature identification. HvRegisterPrivilegesAndFeaturesInfo returns a
 * 128-bit value with flags indicating which features are available to the
 * partition based upon the current partition privileges. The 128-bit
 * value is broken up with different portions stored in different 32-bit
 * fields in the ms_hyperv structure.
 */

/* Partition Reference Counter available*/
#define HV_MSR_TIME_REF_COUNT_AVAILABLE		(1 << 1)

/*
 * Synthetic Timers available
 */
#define HV_MSR_SYNTIMER_AVAILABLE		(1 << 3)

/* Frequency MSRs available */
#define HV_FEATURE_FREQUENCY_MSRS_AVAILABLE	(1 << 8)

/* Reference TSC available */
#define HV_MSR_REFERENCE_TSC_AVAILABLE		(1 << 9)

/* Crash MSR available */
#define HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE	(1 << 10)


/*
 * This group of flags is in the high order 64-bits of the returned
 * 128-bit value.
 */

/* STIMER direct mode is available */
#define HV_STIMER_DIRECT_MODE_AVAILABLE		(1 << 19)

/*
 * Implementation recommendations in register
 * HvRegisterFeaturesInfo. Indicates which behaviors the hypervisor
 * recommends the OS implement for optimal performance.
 */

/*
 * Recommend not using Auto EOI
 */
#define HV_DEPRECATING_AEOI_RECOMMENDED		(1 << 9)

/*
 * Synthetic register definitions equivalent to MSRs on x86/x64
 */
#define HV_REGISTER_CRASH_P0		0x00000210
#define HV_REGISTER_CRASH_P1		0x00000211
#define HV_REGISTER_CRASH_P2		0x00000212
#define HV_REGISTER_CRASH_P3		0x00000213
#define HV_REGISTER_CRASH_P4		0x00000214
#define HV_REGISTER_CRASH_CTL		0x00000215

#define HV_REGISTER_GUEST_OSID		0x00090002
#define HV_REGISTER_VPINDEX		0x00090003
#define HV_REGISTER_TIME_REFCOUNT	0x00090004
#define HV_REGISTER_REFERENCE_TSC	0x00090017

#define HV_REGISTER_SINT0		0x000A0000
#define HV_REGISTER_SINT1		0x000A0001
#define HV_REGISTER_SINT2		0x000A0002
#define HV_REGISTER_SINT3		0x000A0003
#define HV_REGISTER_SINT4		0x000A0004
#define HV_REGISTER_SINT5		0x000A0005
#define HV_REGISTER_SINT6		0x000A0006
#define HV_REGISTER_SINT7		0x000A0007
#define HV_REGISTER_SINT8		0x000A0008
#define HV_REGISTER_SINT9		0x000A0009
#define HV_REGISTER_SINT10		0x000A000A
#define HV_REGISTER_SINT11		0x000A000B
#define HV_REGISTER_SINT12		0x000A000C
#define HV_REGISTER_SINT13		0x000A000D
#define HV_REGISTER_SINT14		0x000A000E
#define HV_REGISTER_SINT15		0x000A000F
#define HV_REGISTER_SCONTROL		0x000A0010
#define HV_REGISTER_SVERSION		0x000A0011
#define HV_REGISTER_SIFP		0x000A0012
#define HV_REGISTER_SIPP		0x000A0013
#define HV_REGISTER_EOM			0x000A0014
#define HV_REGISTER_SIRBP		0x000A0015

#define HV_REGISTER_STIMER0_CONFIG	0x000B0000
#define HV_REGISTER_STIMER0_COUNT	0x000B0001
#define HV_REGISTER_STIMER1_CONFIG	0x000B0002
#define HV_REGISTER_STIMER1_COUNT	0x000B0003
#define HV_REGISTER_STIMER2_CONFIG	0x000B0004
#define HV_REGISTER_STIMER2_COUNT	0x000B0005
#define HV_REGISTER_STIMER3_CONFIG	0x000B0006
#define HV_REGISTER_STIMER3_COUNT	0x000B0007

/*
 * Crash notification flags.
 */
#define HV_CRASH_CTL_CRASH_NOTIFY_MSG	BIT_ULL(62)
#define HV_CRASH_CTL_CRASH_NOTIFY	BIT_ULL(63)

/*
 * The guest OS needs to register the guest ID with the hypervisor.
 * The guest ID is a 64 bit entity and the structure of this ID is
 * specified in the Hyper-V specification:
 *
 * msdn.microsoft.com/en-us/library/windows/hardware/ff542653%28v=vs.85%29.aspx
 *
 * While the current guideline does not specify how Linux guest ID(s)
 * need to be generated, our plan is to publish the guidelines for
 * Linux and other guest operating systems that currently are hosted
 * on Hyper-V. The implementation here conforms to this yet
 * unpublished guidelines.
 *
 *
 * Bit(s)
 * 63 - Indicates if the OS is Open Source or not; 1 is Open Source
 * 62:56 - Os Type; Linux is 0x100
 * 55:48 - Distro specific identification
 * 47:16 - Linux kernel version number
 * 15:0  - Distro specific identification
 *
 *
 */
#define HV_LINUX_VENDOR_ID              0x8100

/* Declare the various hypercall operations. */
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE	0x0002
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST	0x0003
#define HVCALL_NOTIFY_LONG_SPIN_WAIT		0x0008
#define HVCALL_SEND_IPI				0x000b
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX	0x0013
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX	0x0014
#define HVCALL_SEND_IPI_EX			0x0015
#define HVCALL_GET_VP_REGISTERS			0x0050
#define HVCALL_SET_VP_REGISTERS			0x0051
#define HVCALL_POST_MESSAGE			0x005c
#define HVCALL_SIGNAL_EVENT			0x005d
#define HVCALL_RETARGET_INTERRUPT		0x007e
#define HVCALL_START_VIRTUAL_PROCESSOR		0x0099
#define HVCALL_GET_VP_INDEX_FROM_APICID		0x009a
#define HVCALL_QUERY_CAPABILITIES		0x8001
#define HVCALL_MEMORY_HEAT_HINT			0x8003

/* Declare standard hypercall field values. */
#define HV_PARTITION_ID_SELF                    ((u64)-1)
#define HV_VP_INDEX_SELF                        ((u32)-2)

#define HV_HYPERCALL_FAST_BIT                   BIT(16)
#define HV_HYPERCALL_REP_COUNT_1                BIT_ULL(32)
#define HV_HYPERCALL_RESULT_MASK                GENMASK_ULL(15, 0)
#define HV_HYPERCALL_VARHEAD_OFFSET		17
#define HV_HYPERCALL_REP_COMP_OFFSET		32
#define HV_HYPERCALL_REP_COMP_MASK		GENMASK_ULL(43, 32)
#define HV_HYPERCALL_REP_START_OFFSET		48
#define HV_HYPERCALL_REP_START_MASK		GENMASK_ULL(59, 48)

/* Define the hypercall status result */

union hv_hypercall_status {
	u64 as_uint64;
	struct {
		u16 status;
		u16 reserved;
		u16 reps_completed;  /* Low 12 bits */
		u16 reserved2;
	};
};

/* hypercall status code */
#define HV_STATUS_SUCCESS			0
#define HV_STATUS_INVALID_HYPERCALL_CODE	2
#define HV_STATUS_INVALID_HYPERCALL_INPUT	3
#define HV_STATUS_INVALID_ALIGNMENT		4
#define HV_STATUS_INSUFFICIENT_MEMORY		11
#define HV_STATUS_INVALID_CONNECTION_ID		18
#define HV_STATUS_INSUFFICIENT_BUFFERS		19

/* Define output layout for Get VP Register hypercall */
struct hv_get_vp_register_output {
	u64 registervaluelow;
	u64 registervaluehigh;
};

#define HV_FLUSH_ALL_PROCESSORS			BIT(0)
#define HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES	BIT(1)
#define HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY	BIT(2)
#define HV_FLUSH_USE_EXTENDED_RANGE_FORMAT	BIT(3)

enum HV_GENERIC_SET_FORMAT {
	HV_GENERIC_SET_SPARSE_4K,
	HV_GENERIC_SET_ALL,
};

/*
 * The Hyper-V TimeRefCount register and the TSC
 * page provide a guest VM clock with 100ns tick rate
 */
#define HV_CLOCK_HZ (NSEC_PER_SEC/100)

/*
 * The fields in this structure are set by Hyper-V and read
 * by the Linux guest.  They should be accessed with READ_ONCE()
 * so the compiler doesn't optimize in a way that will cause
 * problems.
 */
struct ms_hyperv_tsc_page {
	u32 tsc_sequence;
	u32 reserved1;
	u64 tsc_scale;
	s64 tsc_offset;
	u64 reserved2[509];
};

/* Define the number of synthetic interrupt sources. */
#define HV_SYNIC_SINT_COUNT		(16)
/* Define the expected SynIC version. */
#define HV_SYNIC_VERSION_1		(0x1)

#define HV_SYNIC_CONTROL_ENABLE		(1ULL << 0)
#define HV_SYNIC_SIMP_ENABLE		(1ULL << 0)
#define HV_SYNIC_SIEFP_ENABLE		(1ULL << 0)
#define HV_SYNIC_SINT_MASKED		(1ULL << 16)
#define HV_SYNIC_SINT_AUTO_EOI		(1ULL << 17)
#define HV_SYNIC_SINT_VECTOR_MASK	(0xFF)

#define HV_SYNIC_STIMER_COUNT		(4)

/* Define synthetic interrupt controller message constants. */
#define HV_MESSAGE_SIZE			(256)
#define HV_MESSAGE_PAYLOAD_BYTE_COUNT	(240)
#define HV_MESSAGE_PAYLOAD_QWORD_COUNT	(30)

/* Define hypervisor message types. */
enum hv_message_type {
	HVMSG_NONE			= 0x00000000,

	/* Memory access messages. */
	HVMSG_UNMAPPED_GPA		= 0x80000000,
	HVMSG_GPA_INTERCEPT		= 0x80000001,

	/* Timer notification messages. */
	HVMSG_TIMER_EXPIRED		= 0x80000010,

	/* Error messages. */
	HVMSG_INVALID_VP_REGISTER_VALUE	= 0x80000020,
	HVMSG_UNRECOVERABLE_EXCEPTION	= 0x80000021,
	HVMSG_UNSUPPORTED_FEATURE	= 0x80000022,

	/* Trace buffer complete messages. */
	HVMSG_EVENTLOG_BUFFERCOMPLETE	= 0x80000040,
};

/* Define synthetic interrupt controller message flags. */
union hv_message_flags {
	__u8 asu8;
	struct {
		__u8 msg_pending:1;
		__u8 reserved:7;
	};
};

/* Define port identifier type. */
union hv_port_id {
	__u32 asu32;
	struct {
		__u32 id:24;
		__u32 reserved:8;
	} u;
};

/* Define synthetic interrupt controller message header. */
struct hv_message_header {
	__u32 message_type;
	__u8 payload_size;
	union hv_message_flags message_flags;
	__u8 reserved[2];
	union {
		__u64 sender;
		union hv_port_id port;
	};
};

/* Define synthetic interrupt controller message format. */
struct hv_message {
	struct hv_message_header header;
	union {
		__u64 payload[HV_MESSAGE_PAYLOAD_QWORD_COUNT];
	} u;
};

/* Define the synthetic interrupt message page layout. */
struct hv_message_page {
	struct hv_message sint_message[HV_SYNIC_SINT_COUNT];
};

/* Define timer message payload structure. */
struct hv_timer_message_payload {
	__u32 timer_index;
	__u32 reserved;
	__u64 expiration_time;	/* When the timer expired */
	__u64 delivery_time;	/* When the message was delivered */
};

#define HV_STIMER_ENABLE		(1ULL << 0)
#define HV_STIMER_PERIODIC		(1ULL << 1)
#define HV_STIMER_LAZY			(1ULL << 2)
#define HV_STIMER_AUTOENABLE		(1ULL << 3)
#define HV_STIMER_SINT(config)		(__u8)(((config) >> 16) & 0x0F)

/*
 *  HV_MAX_FLUSH_PAGES = "additional_pages" + 1. It's limited
 *  by the bitwidth of "additional_pages" in union hv_gpa_page_range.
 */
#define HV_MAX_FLUSH_PAGES (2048)

/* HvFlushGuestPhysicalAddressList hypercall */
union hv_gpa_page_range {
	u64 address_space;
	struct {
		u64 additional_pages:11;
		u64 largepage:1;
		u64 basepfn:52;
	} page;
	struct {
		u64:12;
		u64 page_size:1;
		u64 reserved:8;
		u64 base_large_pfn:43;
	};
};

#ifdef CONFIG_PAGE_REPORTING
#define HV_CAPABILITY_MEMORY_COLD_DISCARD_HINT	BIT(8)

// The whole argument should fit in a page to be able to pass to the hypervisor
// in one hypercall.
#define HV_MAX_GPA_PAGE_RANGES ((PAGE_SIZE - 8)/sizeof(union hv_gpa_page_range))

/* HvExtMemoryHeatHint hypercall */
#define HV_MEMORY_HINT_TYPE_COLD_DISCARD	BIT(1)
struct hv_memory_hint {
	u64 type:2;
	u64 reserved:62;
	union hv_gpa_page_range ranges[1];
};

#endif // CONFIG_PAGE_REPORTING

#endif
