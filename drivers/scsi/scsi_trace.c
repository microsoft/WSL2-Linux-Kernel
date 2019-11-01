/*
 * Copyright (C) 2010 FUJITSU LIMITED
 * Copyright (C) 2010 Tomohiro Kusumi <kusumi.tomohiro@jp.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <linux/kernel.h>
#include <linux/trace_seq.h>
#include <asm/unaligned.h>
#include <trace/events/scsi.h>

#define SERVICE_ACTION16(cdb) (cdb[1] & 0x1f)
#define SERVICE_ACTION32(cdb) (get_unaligned_be16(&cdb[8]))

static const char *
scsi_trace_misc(struct trace_seq *, unsigned char *, int);

static const char *
scsi_trace_rw6(struct trace_seq *p, unsigned char *cdb, int len)
{
	const char *ret = trace_seq_buffer_ptr(p);
	u32 lba = 0, txlen;

	lba |= ((cdb[1] & 0x1F) << 16);
	lba |=  (cdb[2] << 8);
	lba |=   cdb[3];
	/*
	 * From SBC-2: a TRANSFER LENGTH field set to zero specifies that 256
	 * logical blocks shall be read (READ(6)) or written (WRITE(6)).
	 */
	txlen = cdb[4] ? cdb[4] : 256;

	trace_seq_printf(p, "lba=%u txlen=%u", lba, txlen);
	trace_seq_putc(p, 0);

	return ret;
}

static const char *
scsi_trace_rw10(struct trace_seq *p, unsigned char *cdb, int len)
{
	const char *ret = trace_seq_buffer_ptr(p);
	u32 lba, txlen;

	lba = get_unaligned_be32(&cdb[2]);
	txlen = get_unaligned_be16(&cdb[7]);

	trace_seq_printf(p, "lba=%u txlen=%u protect=%u", lba, txlen,
			 cdb[1] >> 5);

	if (cdb[0] == WRITE_SAME)
		trace_seq_printf(p, " unmap=%u", cdb[1] >> 3 & 1);

	trace_seq_putc(p, 0);

	return ret;
}

static const char *
scsi_trace_rw12(struct trace_seq *p, unsigned char *cdb, int len)
{
	const char *ret = trace_seq_buffer_ptr(p);
	u32 lba, txlen;

	lba = get_unaligned_be32(&cdb[2]);
	txlen = get_unaligned_be32(&cdb[6]);

	trace_seq_printf(p, "lba=%u txlen=%u protect=%u", lba, txlen,
			 cdb[1] >> 5);
	trace_seq_putc(p, 0);

	return ret;
}

static const char *
scsi_trace_rw16(struct trace_seq *p, unsigned char *cdb, int len)
{
	const char *ret = trace_seq_buffer_ptr(p);
	u64 lba;
	u32 txlen;

	lba = get_unaligned_be64(&cdb[2]);
	txlen = get_unaligned_be32(&cdb[10]);

	trace_seq_printf(p, "lba=%llu txlen=%u protect=%u", lba, txlen,
			 cdb[1] >> 5);

	if (cdb[0] == WRITE_SAME_16)
		trace_seq_printf(p, " unmap=%u", cdb[1] >> 3 & 1);

	trace_seq_putc(p, 0);

	return ret;
}

static const char *
scsi_trace_rw32(struct trace_seq *p, unsigned char *cdb, int len)
{
	const char *ret = trace_seq_buffer_ptr(p), *cmd;
	u64 lba;
	u32 ei_lbrt, txlen;

	switch (SERVICE_ACTION32(cdb)) {
	case READ_32:
		cmd = "READ";
		break;
	case VERIFY_32:
		cmd = "VERIFY";
		break;
	case WRITE_32:
		cmd = "WRITE";
		break;
	case WRITE_SAME_32:
		cmd = "WRITE_SAME";
		break;
	default:
		trace_seq_puts(p, "UNKNOWN");
		goto out;
	}

	lba = get_unaligned_be64(&cdb[12]);
	ei_lbrt = get_unaligned_be32(&cdb[20]);
	txlen = get_unaligned_be32(&cdb[28]);

	trace_seq_printf(p, "%s_32 lba=%llu txlen=%u protect=%u ei_lbrt=%u",
			 cmd, lba, txlen, cdb[10] >> 5, ei_lbrt);

	if (SERVICE_ACTION32(cdb) == WRITE_SAME_32)
		trace_seq_printf(p, " unmap=%u", cdb[10] >> 3 & 1);

out:
	trace_seq_putc(p, 0);

	return ret;
}

static const char *
scsi_trace_unmap(struct trace_seq *p, unsigned char *cdb, int len)
{
	const char *ret = trace_seq_buffer_ptr(p);
	unsigned int regions = get_unaligned_be16(&cdb[7]);

	trace_seq_printf(p, "regions=%u", (regions - 8) / 16);
	trace_seq_putc(p, 0);

	return ret;
}

static const char *
scsi_trace_service_action_in(struct trace_seq *p, unsigned char *cdb, int len)
{
	const char *ret = trace_seq_buffer_ptr(p), *cmd;
	u64 lba;
	u32 alloc_len;

	switch (SERVICE_ACTION16(cdb)) {
	case SAI_READ_CAPACITY_16:
		cmd = "READ_CAPACITY_16";
		break;
	case SAI_GET_LBA_STATUS:
		cmd = "GET_LBA_STATUS";
		break;
	default:
		trace_seq_puts(p, "UNKNOWN");
		goto out;
	}

	lba = get_unaligned_be64(&cdb[2]);
	alloc_len = get_unaligned_be32(&cdb[10]);

	trace_seq_printf(p, "%s lba=%llu alloc_len=%u", cmd, lba, alloc_len);

out:
	trace_seq_putc(p, 0);

	return ret;
}

static const char *
scsi_trace_varlen(struct trace_seq *p, unsigned char *cdb, int len)
{
	switch (SERVICE_ACTION32(cdb)) {
	case READ_32:
	case VERIFY_32:
	case WRITE_32:
	case WRITE_SAME_32:
		return scsi_trace_rw32(p, cdb, len);
	default:
		return scsi_trace_misc(p, cdb, len);
	}
}

static const char *
scsi_trace_misc(struct trace_seq *p, unsigned char *cdb, int len)
{
	const char *ret = trace_seq_buffer_ptr(p);

	trace_seq_putc(p, '-');
	trace_seq_putc(p, 0);

	return ret;
}

const char *
scsi_trace_parse_cdb(struct trace_seq *p, unsigned char *cdb, int len)
{
	switch (cdb[0]) {
	case READ_6:
	case WRITE_6:
		return scsi_trace_rw6(p, cdb, len);
	case READ_10:
	case VERIFY:
	case WRITE_10:
	case WRITE_SAME:
		return scsi_trace_rw10(p, cdb, len);
	case READ_12:
	case VERIFY_12:
	case WRITE_12:
		return scsi_trace_rw12(p, cdb, len);
	case READ_16:
	case VERIFY_16:
	case WRITE_16:
	case WRITE_SAME_16:
		return scsi_trace_rw16(p, cdb, len);
	case UNMAP:
		return scsi_trace_unmap(p, cdb, len);
	case SERVICE_ACTION_IN_16:
		return scsi_trace_service_action_in(p, cdb, len);
	case VARIABLE_LENGTH_CMD:
		return scsi_trace_varlen(p, cdb, len);
	default:
		return scsi_trace_misc(p, cdb, len);
	}
}
