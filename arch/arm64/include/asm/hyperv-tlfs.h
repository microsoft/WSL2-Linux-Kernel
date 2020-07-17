/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file contains definitions from the Hyper-V Hypervisor Top-Level
 * Functional Specification (TLFS):
 * https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs
 *
 * Copyright (C) 2019, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#ifndef _ASM_HYPERV_TLFS_H
#define _ASM_HYPERV_TLFS_H

#include <linux/types.h>

/*
 * All data structures defined in the TLFS that are shared between Hyper-V
 * and a guest VM use Little Endian byte ordering.  This matches the default
 * byte ordering of Linux running on ARM64, so no special handling is required.
 */


/*
 * While not explicitly listed in the TLFS, Hyper-V always runs with a page
 * size of 4096. These definitions are used when communicating with Hyper-V
 * using guest physical pages and guest physical page addresses, since the
 * guest page size may not be 4096 on ARM64.
 */
#define HV_HYP_PAGE_SHIFT	12
#define HV_HYP_PAGE_SIZE	(1 << HV_HYP_PAGE_SHIFT)
#define HV_HYP_PAGE_MASK	(~(HV_HYP_PAGE_SIZE - 1))

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
#define HV_MSR_TIME_REF_COUNT_AVAILABLE		BIT(1)

/*
 * Synthetic Timers available
 */
#define HV_MSR_SYNTIMER_AVAILABLE		BIT(3)

/* Frequency MSRs available */
#define HV_FEATURE_FREQUENCY_MSRS_AVAILABLE	BIT(8)

/* Reference TSC available */
#define HV_MSR_REFERENCE_TSC_AVAILABLE		BIT(9)

/* Crash MSR available */
#define HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE	BIT(10)


/*
 * This group of flags is in the high order 64-bits of the returned
 * 128-bit value.
 */

/* STIMER direct mode is available */
#define HV_STIMER_DIRECT_MODE_AVAILABLE		BIT(19)

/*
 * Implementation recommendations in register
 * HvRegisterFeaturesInfo. Indicates which behaviors the hypervisor
 * recommends the OS implement for optimal performance.
 */

/*
 * Recommend not using Auto EOI
 */
#define HV_DEPRECATING_AEOI_RECOMMENDED		BIT(9)

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
 * specified in the Hyper-V TLFS.
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

/* Declare standard hypercall field values. */
#define HV_PARTITION_ID_SELF                    ((u64)-1)
#define HV_VP_INDEX_SELF                        ((u32)-2)

#define HV_HYPERCALL_FAST_BIT                   BIT(16)
#define HV_HYPERCALL_REP_COUNT_1                BIT_ULL(32)
#define HV_HYPERCALL_RESULT_MASK                GENMASK_ULL(15, 0)

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
 * problems.  The union pads the size out to the page size
 * used in communication with Hyper-V.
 */
struct ms_hyperv_tsc_page {
	union {
		struct {
			u32 tsc_sequence;
			u32 reserved1;
			u64 tsc_scale;
			s64 tsc_offset;
		} __packed;
		u8 reserved2[HV_HYP_PAGE_SIZE];
	};
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
	} __packed;
};

/* Define port identifier type. */
union hv_port_id {
	__u32 asu32;
	struct {
		__u32 id:24;
		__u32 reserved:8;
	}  __packed u;
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
} __packed;

/* Define synthetic interrupt controller message format. */
struct hv_message {
	struct hv_message_header header;
	union {
		__u64 payload[HV_MESSAGE_PAYLOAD_QWORD_COUNT];
	} u;
} __packed;

/* Define the synthetic interrupt message page layout. */
struct hv_message_page {
	struct hv_message sint_message[HV_SYNIC_SINT_COUNT];
} __packed;

/* Define timer message payload structure. */
struct hv_timer_message_payload {
	__u32 timer_index;
	__u32 reserved;
	__u64 expiration_time;	/* When the timer expired */
	__u64 delivery_time;	/* When the message was delivered */
} __packed;

#define HV_STIMER_ENABLE		(1ULL << 0)
#define HV_STIMER_PERIODIC		(1ULL << 1)
#define HV_STIMER_LAZY			(1ULL << 2)
#define HV_STIMER_AUTOENABLE		(1ULL << 3)
#define HV_STIMER_SINT(config)		(__u8)(((config) >> 16) & 0x0F)


/* Define synthetic interrupt controller flag constants. */
#define HV_EVENT_FLAGS_COUNT		(256 * 8)
#define HV_EVENT_FLAGS_LONG_COUNT	(256 / sizeof(unsigned long))

/*
 * Timer configuration register.
 */
union hv_stimer_config {
	u64 as_uint64;
	struct {
		u64 enable:1;
		u64 periodic:1;
		u64 lazy:1;
		u64 auto_enable:1;
		u64 apic_vector:8;
		u64 direct_mode:1;
		u64 reserved_z0:3;
		u64 sintx:4;
		u64 reserved_z1:44;
	} __packed;
};


/* Define the synthetic interrupt controller event flags format. */
union hv_synic_event_flags {
	unsigned long flags[HV_EVENT_FLAGS_LONG_COUNT];
};

/* Define SynIC control register. */
union hv_synic_scontrol {
	u64 as_uint64;
	struct {
		u64 enable:1;
		u64 reserved:63;
	} __packed;
};

/* Define synthetic interrupt source. */
union hv_synic_sint {
	u64 as_uint64;
	struct {
		u64 vector:8;
		u64 reserved1:8;
		u64 masked:1;
		u64 auto_eoi:1;
		u64 reserved2:46;
	} __packed;
};

/* Define the format of the SIMP register */
union hv_synic_simp {
	u64 as_uint64;
	struct {
		u64 simp_enabled:1;
		u64 preserved:11;
		u64 base_simp_gpa:52;
	} __packed;
};

/* Define the format of the SIEFP register */
union hv_synic_siefp {
	u64 as_uint64;
	struct {
		u64 siefp_enabled:1;
		u64 preserved:11;
		u64 base_siefp_gpa:52;
	} __packed;
};

struct hv_vpset {
	u64 format;
	u64 valid_bank_mask;
	u64 bank_contents[];
} __packed;


#endif
