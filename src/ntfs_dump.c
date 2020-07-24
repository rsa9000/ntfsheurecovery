/**
 * Routines, which help to dump to stdout various NTFS structures
 *
 * Copyright (c) 2015-2016, Sergey Ryazanov <ryazanov.s.a@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "ntfs_struct.h"
#include "ntfs.h"
#include "ntfs_dump.h"
#include "misc.h"

struct ntfs_dump_enum_title {
	unsigned val;
	const char * const title;
};

const char *ntfs_dump_enum2title(const struct ntfs_dump_enum_title *titles,
				 const unsigned val)
{
	unsigned i;

	for (i = 0; titles[i].title; ++i)
		if (titles[i].val == val)
			return titles[i].title;

	return "Unknown";
}

const char *ntfs_time2str(const uint64_t time)
{
	static unsigned buf_idx;
	static char __buf[4][0x20];
	char *buf = __buf[buf_idx];
	time_t ts = ntfs_time2ts(time);

	buf_idx = (buf_idx + 1) % (sizeof(__buf)/sizeof(__buf[0]));

	ctime_r(&ts, buf);
	memcpy(buf + 24, " UTC", 5);

	return buf;
}

void ntfs_dump_logfile_rec(const char *ident, struct ntfs_log_rec_hdr *rec,
			   int deep)
{
	static const struct ntfs_dump_enum_title op_types[] = {
		{NTFS_LOG_OP_NOOP, "Noop"},
		{NTFS_LOG_OP_COMPLOGREC, "CompensationLogRecord"},
		{NTFS_LOG_OP_INITFILERECSEG, "InitializeFileRecordSegment"},
		{NTFS_LOG_OP_DEALLOCFILERECSEG, "DeallocateFileRecordSegment"},
		{NTFS_LOG_OP_WREOFRECSEG, "WriteEndOfFileRecordSegment"},
		{NTFS_LOG_OP_CREATEATTR, "CreateAttribute"},
		{NTFS_LOG_OP_DELETEATTR, "DeleteAttribute"},
		{NTFS_LOG_OP_UPDRESIDENT, "UpdateResidentValue"},
		{NTFS_LOG_OP_UPDNONRESIDENT, "UpdateNonresidentValue"},
		{NTFS_LOG_OP_UPDMP, "UpdateMappingPairs"},
		{NTFS_LOG_OP_DELDIRTYCLS, "DeleteDirtyClusters"},
		{NTFS_LOG_OP_SETNEWATTRSZS, "SetNewAttributeSizes"},
		{NTFS_LOG_OP_ADDIDXROOT, "AddIndexEntryRoot"},
		{NTFS_LOG_OP_DELIDXROOT, "DeleteIndexEntryRoot"},
		{NTFS_LOG_OP_ADDIDXALLOC, "AddIndexEntryAllocation"},
		{NTFS_LOG_OP_DELIDXALLOC, "DeleteIndexEntryAllocation"},
		{NTFS_LOG_OP_WREOFIDX, "WriteEndOfIndexBuffer"},
		{NTFS_LOG_OP_SETIDXROOT, "SetIndexEntryVcnRoot"},
		{NTFS_LOG_OP_SETIDXALLOC, "SetIndexEntryVcnAllocation"},
		{NTFS_LOG_OP_UPDFNROOT, "UpdateFileNameRoot"},
		{NTFS_LOG_OP_UPDFNALLOC, "UpdateFileNameAllocation"},
		{NTFS_LOG_OP_BMSETBITS, "SetBitsInNonresidentBitMap"},
		{NTFS_LOG_OP_BMCLRBITS, "ClearBitsInNonresidentBitMap"},
		{NTFS_LOG_OP_HOTFIX, "HotFix"},
		{NTFS_LOG_OP_ENDTOPACTION, "EndTopLevelAction"},
		{NTFS_LOG_OP_PREPTRANSACTION, "PrepareTransaction"},
		{NTFS_LOG_OP_COMMITTRANSACTION, "CommitTransaction"},
		{NTFS_LOG_OP_FORGETTRANSACTION, "ForgetTransaction"},
		{NTFS_LOG_OP_OPENNONRESATTR, "OpenNonresidentAttribute"},
		{NTFS_LOG_OP_OPENATTRTBLDUMP, "OpenAttributeTableDump"},
		{NTFS_LOG_OP_ATTRNAMESDUMP, "AttributeNamesDump"},
		{NTFS_LOG_OP_DIRTYPGTBLDUMP, "DirtyPageTableDump"},
		{NTFS_LOG_OP_TRANSACTIONTBLDUMP, "TransactionTableDump"},
		{NTFS_LOG_OP_UPDRECDATAROOT, "UpdateRecordDataRoot"},
		{NTFS_LOG_OP_UPDRECDATAALLOC, "UpdateRecordDataAllocation"},
		{0, NULL}
	};

	printf("%sredo_op  = 0x%02X (%s)\n", ident, rec->redo_op,
	       ntfs_dump_enum2title(op_types, rec->redo_op));
	printf("%sredo_off = %u (0x%04X)\n", ident, rec->redo_off,
	       rec->redo_off);
	printf("%sredo_sz  = %u (0x%04X)\n", ident, rec->redo_sz, rec->redo_sz);
	printf("%sundo_op  = 0x%02X (%s)\n", ident, rec->undo_op,
	       ntfs_dump_enum2title(op_types, rec->undo_op));
	printf("%sundo_off = %u (0x%04X)\n", ident, rec->undo_off,
	       rec->undo_off);
	printf("%sundo_sz  = %u (0x%04X)\n", ident, rec->undo_sz, rec->undo_sz);
	printf("%slcn_num = %u\n", ident, rec->lcn_num);
	printf("%stgt_attr = %u\n", ident, rec->tgt_attr);
	printf("%srec_off = %u\n", ident, rec->rec_off);
	printf("%sattr_off = %u\n", ident, rec->attr_off);
	printf("%scls_boff = %u\n", ident, rec->cls_boff);
	printf("%stgt_vcn = 0x%08"PRIX64"\n", ident, rec->tgt_vcn);
	printf("%stgt_lcn = 0x%08"PRIX64"\n", ident, rec->tgt_lcn);
}

void ntfs_dump_logfile_rec_cmn(const char *ident,
			       struct ntfs_log_rec_cmn_hdr *rec,
			       int deep)
{
	static const struct ntfs_dump_enum_title rec_types[] = {
		{NTFS_LOG_REC_T_NORMAL, "Normal"},
		{NTFS_LOG_REC_T_CHECKPOINT, "Checkpoint"},
		{0, NULL}
	};

	printf("%sthis_lsn = 0x%"PRIX64"\n", ident, rec->this_lsn);
	printf("%sprev_lsn = 0x%"PRIX64"\n", ident, rec->prev_lsn);
	printf("%sundo_lsn = 0x%"PRIX64"\n", ident, rec->undo_lsn);
	printf("%sdata_sz = %u (0x%08X)\n", ident, rec->data_sz, rec->data_sz);
	printf("%sclient_id(idx.seqno) = %u.%u\n", ident,
	       rec->client_id.client_idx, rec->client_id.seqno);
	printf("%srec_type = %u (%s)\n", ident, rec->rec_type,
	       ntfs_dump_enum2title(rec_types, rec->rec_type));
	printf("%stransaction_id = %u (0x%08X)\n", ident, rec->transaction_id,
	       rec->transaction_id);
	printf("%sflags = 0x%04X\n", ident, rec->flags);

	if (!deep)
		return;

	ntfs_dump_logfile_rec(ident, (struct ntfs_log_rec_hdr *)rec->data,
			      deep);
}

void ntfs_dump_logfile_rec_cmn_short(const char *ident,
				     struct ntfs_log_rec_cmn_hdr *rec)
{
	struct ntfs_log_rec_hdr *rh = (void *)rec->data;

	printf("%sLSN: 0x%"PRIX64" Datasz: %u Redo/Undo: 0x%02X/0x%02X\n",
	       ident, rec->this_lsn, rec->data_sz, rh->redo_op, rh->undo_op);
}

void ntfs_dump_logfile_rec_page(const char *ident,
				struct ntfs_log_rec_pg_hdr *rpg)
{
	printf("%spage_lsn = 0x%"PRIX64"\n", ident, rpg->last_lsn);
	printf("%spage_flags = 0x%08X\n", ident, rpg->flags);
	printf("%spage_pg_count = %u\n", ident, rpg->pg_count);
	printf("%spage_pg_pos = %u\n", ident, rpg->pg_pos);
	printf("%spage_rec_off = %u\n", ident, rpg->rec_off);
	printf("%spage_lsn_end = 0x%"PRIX64"\n", ident, rpg->last_end_lsn);
}

void ntfs_dump_logfile_rec_page_short(const char *ident,
				      struct ntfs_log_rec_pg_hdr *rpg)
{
	printf("%spage: LSN: 0x%010"PRIX64"-0x%010"PRIX64" Flags: 0x%04X Page: %2u/%-2u RecOff: %u\n",
	       ident, rpg->last_lsn, rpg->last_end_lsn, rpg->flags,
	       rpg->pg_pos, rpg->pg_count, rpg->rec_off);
}

void ntfs_dump_logfile_client(const char *ident, struct ntfs_log_client *lc)
{
	printf("%soldest_lst = 0x%"PRIX64"\n", ident, lc->oldest_lsn);
	printf("%srst_lsn = 0x%"PRIX64"\n", ident, lc->rst_lsn);
	printf("%sprev_client = %u\n", ident, lc->prev_client);
	printf("%snext_client = %u\n", ident, lc->next_client);
	printf("%sseqnum = %u\n", ident, lc->seqnum);
	printf("%sname_len = %u\n", ident, lc->name_len);
	printf("%sname = %ls\n", ident, name2wchar(lc->name, lc->name_len));
}

void ntfs_dump_logfile_rst(const char *ident, struct ntfs_log_rst *rst,
			   int deep)
{
	char *__ident;
	unsigned __ident_len;
	struct ntfs_log_client *lc;
	unsigned i;

	printf("%scurr_lsn = 0x%08"PRIX64"\n", ident, rst->curr_lsn);
	printf("%slog_clients = %u\n", ident, rst->log_clients);
	printf("%sclient_free_list = %u (0x%04X)\n", ident,
	       rst->client_free_list, rst->client_free_list);
	printf("%sclient_inuse_list  = %u (0x%04X)\n", ident,
	       rst->client_inuse_list, rst->client_inuse_list);
	printf("%sflags = 0x%04X\n", ident, rst->flags);
	printf("%sseqnum_bits = %u\n", ident, rst->seqnum_bits);
	printf("%srst_len = %u\n", ident, rst->rst_len);
	printf("%sclients_off = %u\n", ident, rst->clients_off);
	printf("%sfile_sz = %"PRIu64"\n", ident, rst->file_sz);
	printf("%slast_lsn_data_sz = %u\n", ident, rst->last_lsn_data_sz);
	printf("%srec_sz = %u\n", ident, rst->rec_sz);
	printf("%slog_pg_data_off = %u\n", ident, rst->log_pg_data_off);

	if (!deep)
		return;

	__ident_len = strlen(ident) + 14;
	__ident = alloca(__ident_len);
	lc = (void *)rst + rst->clients_off;
	for (i = 0; i < rst->log_clients; ++i, ++lc) {
		snprintf(__ident, __ident_len, "%sclient[%d]: ", ident, i);
		ntfs_dump_logfile_client(__ident, lc);
	}
}

void ntfs_dump_logfile_rst_page(const char *ident,
				struct ntfs_log_rst_pg_hdr *rpg, int deep)
{
	struct ntfs_log_rst *rst;

	printf("%spage_chkdst_lsn = 0x%"PRIX64"\n", ident, rpg->chkdsk_lsn);
	printf("%spage_sys_page_size = %u\n", ident, rpg->sys_page_sz);
	printf("%spage_log_page_size = %u\n", ident, rpg->log_page_sz);
	printf("%spage_rst_off = %u\n", ident, rpg->rst_off);
	printf("%spage_version = %u.%d\n", ident, rpg->ver_min, rpg->ver_maj);

	if (!deep)
		return;

	rst = (void *)rpg + rpg->rst_off;
	ntfs_dump_logfile_rst(ident, rst, deep);
}

void ntfs_dump_sec_ace_file(const char *ident,
			    const struct ntfs_sec_ace_file *ace)
{
	char *sidstr = ntfs_sid2str(&ace->sid);

	printf("%smask = 0x%08X\n", ident, ace->mask);
	printf("%sSID = %s\n", ident, sidstr);

	free(sidstr);
}

/** Dump access control entry to terminal */
void ntfs_dump_sec_ace(const char *ident, const struct ntfs_sec_ace *ace,
		       int deep)
{
	static const struct ntfs_dump_enum_title ace_types[] = {
		{NTFS_SEC_ACE_T_ALLOW, "Allow"},
		{NTFS_SEC_ACE_T_DENY, "Deny"},
		{NTFS_SEC_ACE_T_AUDIT, "Audit"},
		{NTFS_SEC_ACE_T_ALARM, "Alarm"},
		{0, NULL}
	};

	printf("%stype = %u (%s)\n", ident, ace->type,
	       ntfs_dump_enum2title(ace_types, ace->type));
	printf("%sflags = 0x%X\n", ident, ace->flags);
	printf("%ssize = 0x%02X\n", ident, ace->size);

	if (!deep)
		return;

	switch (ace->type) {
	case NTFS_SEC_ACE_T_ALLOW:
	case NTFS_SEC_ACE_T_DENY:
	case NTFS_SEC_ACE_T_AUDIT:
	case NTFS_SEC_ACE_T_ALARM:
		ntfs_dump_sec_ace_file(ident, (struct ntfs_sec_ace_file *)ace);
		break;
	default:
		printf("%sunsupported ACE type\n", ident);
		break;
	}
}

/** Dump access control list to terminal */
void ntfs_dump_sec_acl(const char *ident, const struct ntfs_sec_acl *acl,
		       int deep)
{
	char *__ident = NULL;
	unsigned __ident_len;
	struct ntfs_sec_ace *ace;
	unsigned i;

	printf("%srev = %u\n", ident, acl->rev);
	printf("%ssize = 0x%04X\n", ident, acl->size);
	printf("%sace_num = %u\n", ident, acl->ace_num);

	if (!deep)
		return;

	__ident_len = strlen(ident) + 10;
	__ident = malloc(__ident_len);

	ace = NTFS_SEC_ACL_FIRST_ACE(acl);
	for (i = 0; i < acl->ace_num; ++i, ace = NTFS_SEC_ACE_NEXT(ace)) {
		snprintf(__ident, __ident_len, "%sACL[%u]:", ident, i);
		ntfs_dump_sec_ace(__ident, ace, deep);
	}

	free(__ident);
}

void ntfs_dump_sec_desc(const char *ident, const struct ntfs_sec_desc *sd,
			int deep)
{
	char *sidstr;
	char *__ident = NULL;
	unsigned __ident_len = 0;	/* Just make compiller happy */

	if (deep) {
		__ident_len = strlen(ident) + 6;
		__ident = malloc(__ident_len);
	}

	printf("%srev = %u\n", ident, sd->rev);
	printf("%sflags = 0x%04X\n", ident, sd->flags);
	if (!sd->owner_off) {
		printf("%sowner = <none>\n", ident);
	} else {
		sidstr = ntfs_sid2str((void *)sd + sd->owner_off);
		printf("%sowner = %s\n", ident, sidstr);
		free(sidstr);
	}
	if (!sd->group_off) {
		printf("%sgroup = <none>\n", ident);
	} else {
		sidstr = ntfs_sid2str((void *)sd + sd->group_off);
		printf("%sgroup = %s\n", ident, sidstr);
		free(sidstr);
	}
	if (!(sd->flags & NTFS_SEC_DESC_F_SACL)) {
		printf("%sSACL = <none>\n", ident);
	} else if (!sd->sacl_off) {
		printf("%sSACL = <null>\n", ident);
	} else if (!deep) {
		printf("%sSACL = at 0x%04X\n", ident, sd->sacl_off);
	} else {
		snprintf(__ident, __ident_len, "%sSACL:", ident);
		ntfs_dump_sec_acl(__ident, (void *)sd + sd->sacl_off, deep);
	}
	if (!(sd->flags & NTFS_SEC_DESC_F_DACL)) {
		printf("%sDACL = <none>\n", ident);
	} else if (!sd->dacl_off) {
		printf("%sDACL = <null>\n", ident);
	} else if (!deep) {
		printf("%sDACL = at 0x%04X\n", ident, sd->dacl_off);
	} else {
		snprintf(__ident, __ident_len, "%sDACL:", ident);
		ntfs_dump_sec_acl(__ident, (void *)sd + sd->dacl_off, deep);
	}

	free(__ident);
}

void ntfs_dump_sec_desc_hdr(const char *ident,
			    const struct ntfs_sec_desc_hdr *sdh, int deep)
{
	printf("%shash = 0x%08X\n", ident, sdh->hash);
	printf("%sid = %u (0x%X)\n", ident, sdh->id, sdh->id);
	printf("%svoff = 0x%08"PRIX64"\n", ident, sdh->voff);
	printf("%slen = 0x%04X\n", ident, sdh->len);

	return ntfs_dump_sec_desc(ident, (void *)sdh->data, deep);
}

void ntfs_dump_sec_desc_hdr_short(const char *ident,
				  const struct ntfs_sec_desc_hdr *sdh)
{
	printf("%sdeschdr: hash = 0x%08X id = %4u voff = 0x%08"PRIX64" len = 0x%04X\n",
	       ident, sdh->hash, sdh->id, sdh->voff, sdh->len);
}
