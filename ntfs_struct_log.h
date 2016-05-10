/**
 * On-disk NTFS $LogFile structures
 *
 * Copyright (c) 2015, Sergey Ryazanov <ryazanov.s.a@gmail.com>
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

#ifndef _NTFS_STRUCT_LOG_H_
#define _NTFS_STRUCT_LOG_H_

/** Current code assumes that log page size exactly 0x1000 */
#define NTFS_LOG_PG_SZ			0x1000

#define NTFS_LOG_PGNUM_RST1		0	/* Reset main page */
#define NTFS_LOG_PGNUM_RST2		1	/* Reset backup page */
#define NTFS_LOG_PGNUM_BUF1		2	/* Buffer main page */
#define NTFS_LOG_PGNUM_BUF2		3	/* Buffer backup page */
#define NTFS_LOG_PGNUM_LOGSTART		4	/* Logging area first page */

/** $LogFile restart page header */
struct ntfs_log_rst_pg_hdr {
/* 00 */struct ntfs_record r;	/* Should contains "RSTR" magic signature */
/* 08 */uint64_t chkdsk_lsn;
/* 10 */uint32_t sys_page_sz;	/* System page size, bytes */
/* 14 */uint32_t log_page_sz;	/* Log page size, bytes */
/* 18 */uint16_t rst_off;	/* Restart area offset, bytes */
/* 1A */int16_t ver_min;	/* Minor version */
/* 1C */uint16_t ver_maj;	/* Major version */
} __attribute__((packed));

/** $LogFile restart info */
struct ntfs_log_rst {
/* 00 */uint64_t curr_lsn;	/* Current LSN (indicates logical log end) */
/* 08 */uint16_t log_clients;	/* Maximum log clients */
/* 0A */uint16_t client_free_list;
/* 0C */uint16_t client_inuse_list;
/* 0E */uint16_t flags;
/* 10 */uint32_t seqnum_bits;
/* 14 */uint16_t rst_len;	/* Restart area length */
/* 16 */uint16_t clients_off;	/* Clients array offset */
/* 18 */uint64_t file_sz;	/* Total logfile size */
/* 20 */uint32_t last_lsn_data_sz;
/* 24 */uint16_t rec_sz;	/* This record size */
/* 26 */uint16_t log_pg_data_off;
} __attribute__((packed));

#define NTFS_LOG_CLIENT_NAME_MAX	64

/** $LogFile client */
struct ntfs_log_client {
/* 00 */uint64_t oldest_lsn;
/* 08 */uint64_t rst_lsn;
/* 10 */uint16_t prev_client;
/* 12 */uint16_t next_client;
/* 14 */uint16_t seqnum;
/* 16 */uint16_t align[3];
/* 1C */uint32_t name_len;
/* 20 */uint8_t name[NTFS_LOG_CLIENT_NAME_MAX];
} __attribute__((packed));

/** $LogFile record page header */
struct ntfs_log_rec_pg_hdr {
/* 00 */struct ntfs_record r;	/* Should contains "RCRD" magic signature */
/* 08 */union {
		uint64_t last_lsn;
		uint32_t file_offset;	/* Offset inside $LogFile (only for buffer pages) */
	};
/* 10 */uint32_t flags;
/* 14 */uint16_t pg_count;
/* 16 */uint16_t pg_pos;
/* 18 */uint16_t rec_off;	/* Next record offset */
/* 1A */uint16_t align[3];
/* 20 */uint64_t last_end_lsn;
} __attribute__((packed));

/** $LogFile record client identity */
struct ntfs_log_client_id {
/* 00 */uint16_t seqno;
/* 02 */uint16_t client_idx;
} __attribute__((packed));

#define NTFS_LOG_REC_T_NORMAL		1
#define NTFS_LOG_REC_T_CHECKPOINT	2

#define NTFS_LOG_REC_F_MULTIPAGE	0x0001	/* Record cross current page */

/** $LogFile record common header */
struct ntfs_log_rec_cmn_hdr {
/* 00 */uint64_t this_lsn;	/* This operation LSN */
/* 08 */uint64_t prev_lsn;	/* Previous operation LSN */
/* 10 */uint64_t undo_lsn;	/* Undo operations chaining */
/* 18 */uint32_t data_sz;	/* Logclient data length */
/* 1C */struct ntfs_log_client_id client_id;
/* 20 */uint32_t rec_type;	/* See NTFS_LOG_REC_T_xxx */
/* 24 */uint32_t transaction_id;
/* 28 */uint16_t flags;		/* See NTFS_LOG_REC_F_xxx */
/* 2A */uint16_t align1[3];
/* 30 */uint8_t data[];
};

#define NTFS_LOG_OP_NOOP		0x00	/* Noop */
#define NTFS_LOG_OP_COMPLOGREC		0x01	/* CompensationLogRecord */
#define NTFS_LOG_OP_INITFILERECSEG	0x02	/* InitializeFileRecordSegment (MFT entry) */
#define NTFS_LOG_OP_DEALLOCFILERECSEG	0x03	/* DeallocateFileRecordSegment */
#define NTFS_LOG_OP_WREOFRECSEG		0x04	/* WriteEndOfFileRecordSegment (attr hdr) */
#define NTFS_LOG_OP_CREATEATTR		0x05	/* CreateAttribute (attr hdr) */
#define NTFS_LOG_OP_DELETEATTR		0x06	/* DeleteAttribute */
#define NTFS_LOG_OP_UPDRESIDENT		0x07	/* UpdateResidentValue (raw data) */
#define NTFS_LOG_OP_UPDNONRESIDENT	0x08	/* UpdateNonresidentValue (raw data) */
#define NTFS_LOG_OP_UPDMP		0x09	/* UpdateMappingPairs (raw data) */
#define NTFS_LOG_OP_DELDIRTYCLS		0x0A	/* DeleteDirtyClusters (LCN ranges) */
#define NTFS_LOG_OP_SETNEWATTRSZS	0x0B	/* SetNewAttributeSizes (sizes) */
#define NTFS_LOG_OP_ADDIDXROOT		0x0C	/* AddIndexEntryRoot (idx entry) */
#define NTFS_LOG_OP_DELIDXROOT		0x0D	/* DeleteIndexEntryRoot */
#define NTFS_LOG_OP_ADDIDXALLOC		0x0E	/* AddIndexEntryAllocation (idx entry) */
#define NTFS_LOG_OP_DELIDXALLOC		0x0F	/* DeleteIndexEntryAllocation */
#define NTFS_LOG_OP_WREOFIDX		0x10	/* WriteEndOfIndexBuffer (idx entry) */
#define NTFS_LOG_OP_SETIDXROOT		0x11	/* SetIndexEntryVcnRoot (VCN) */
#define NTFS_LOG_OP_SETIDXALLOC		0x12	/* SetIndexEntryVcnAllocation (VCN) */
#define NTFS_LOG_OP_UPDFNROOT		0x13	/* UpdateFileNameRoot (file metadata) */
#define NTFS_LOG_OP_UPDFNALLOC		0x14	/* UpdateFileNameAllocation (file metadata) */
#define NTFS_LOG_OP_BMSETBITS		0x15	/* SetBitsInNonresidentBitMap (bits range) */
#define NTFS_LOG_OP_BMCLRBITS		0x16	/* ClearBitsInNonresidentBitMap (bits range) */
#define NTFS_LOG_OP_HOTFIX		0x17	/* HotFix */
#define NTFS_LOG_OP_ENDTOPACTION	0x18	/* EndTopLevelAction */
#define NTFS_LOG_OP_PREPTRANSACTION	0x19	/* PrepareTransaction */
#define NTFS_LOG_OP_COMMITTRANSACTION	0x1A	/* CommitTransaction */
#define NTFS_LOG_OP_FORGETTRANSACTION	0x1B	/* ForgetTransaction */
#define NTFS_LOG_OP_OPENNONRESATTR	0x1C	/* OpenNonresidentAttribute (open attrs w/ names) */
#define NTFS_LOG_OP_OPENATTRTBLDUMP	0x1D	/* OpenAttributeTableDump (open attrs) */
#define NTFS_LOG_OP_ATTRNAMESDUMP	0x1E	/* AttributeNamesDump (all attribute names) */
#define NTFS_LOG_OP_DIRTYPGTBLDUMP	0x1F	/* DirtyPageTableDump (dirty pages) */
#define NTFS_LOG_OP_TRANSACTIONTBLDUMP	0x20	/* TransactionTableDump (transaction entries) */
#define NTFS_LOG_OP_UPDRECDATAROOT	0x21	/* UpdateRecordDataRoot (raw data) */
#define NTFS_LOG_OP_UPDRECDATAALLOC	0x22	/* UpdateRecordDataAllocation (raw data) */

/* Used to calculate blocks offset inside cluster (looks like sector size) */
#define NTFS_LOG_BLK_SZ		0x200

/** $LogFile record header */
struct ntfs_log_rec_hdr {
/* 00 */uint16_t redo_op;	/* "Redo" opcode (see NTFS_LOG_OP_xxx) */
/* 02 */uint16_t undo_op;	/* "Undo" opcode (see NTFS_LOG_OP_xxx) */
/* 04 */uint16_t redo_off;	/* "Redo" data off */
/* 06 */uint16_t redo_sz;	/* "Redo" data size */
/* 08 */uint16_t undo_off;	/* "Undo" data off */
/* 0A */uint16_t undo_sz;	/* "Undo" data size */
/* 0C */uint16_t tgt_attr;	/* Target attribute index in cache */
/* 0E */uint16_t lcn_num;	/* Number of valid LCN (always 0 or 1) */
/* 10 */uint16_t rec_off;	/* Offset inside MFT record */
/* 12 */uint16_t attr_off;	/* Offset inside attribute */
/* 14 */uint16_t cls_boff;	/* Offset inside target cluster, NTFS_LOG_BLK_SZ */
/* 16 */uint16_t align2[1];
/* 18 */uint64_t tgt_vcn;	/* Target VCN */
/* 20 */uint64_t tgt_lcn;	/* Target LCN */
} __attribute__((packed));

#endif	/* _NTFS_STRUCT_LOG_H_ */
