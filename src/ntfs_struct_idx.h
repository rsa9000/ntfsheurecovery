/**
 * On-disk NTFS indexes structures
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

#ifndef _NTFS_STRUCT_IDX_H_
#define _NTFS_STRUCT_IDX_H_

/* Index sorting rules */
#define NTFS_IDX_SORT_FILENAME	1	/* Collate as strings (ignore case) */
#define NTFS_IDX_SORT_ULONG	16	/* Order by unsigned long */
#define NTFS_IDX_SORT_SDH	18	/* Order by hash and security_id */

struct ntfs_idx_objid_data {
/* 00 */uint64_t mref;			/* Target entry number and seqno */
/* 08 */struct ntfs_guid birth_vol_id;
/* 18 */struct ntfs_guid birth_obj_id;
/* 28 */struct ntfs_guid domain_id;
} __attribute__((packed));

/** $Secure file $SDH index entry key format */
struct ntfs_idx_sdh_key {
/* 00 */uint32_t hash;
/* 04 */uint32_t id;
} __attribute__((packed));

/** $Secure file $SII index entry key format */
struct ntfs_idx_sii_key {
/* 00 */uint32_t id;
} __attribute__((packed));

#define NTFS_IDX_ENTRY_F_CHILD	0x01	/* Entry has child node */
#define NTFS_IDX_ENTRY_F_LAST	0x02	/* Entry is the last in node */

struct ntfs_idx_entry_hdr {
	union {
/* 00 */	uint64_t val;		/* Index type specific */
		struct {
/* 00 */		uint16_t data_off;	/* Entry data offset */
/* 02 */		uint16_t data_sz;	/* Entry data size */
/* 04 */		uint8_t padding[4];
		} __attribute__((packed));
	};
/* 08 */uint16_t size;		/* Total entry size (aligned), bytes */
/* 0A */uint16_t key_sz;	/* Index key size, bytes */
/* 0C */uint32_t flags;		/* Associated flags */
/* 10 */uint8_t key[];		/* Index key data */
} __attribute__((packed));

#define ntfs_idx_entry_child_vcn(__ent)			\
		(*(uint64_t *)((void *)__ent + (__ent)->size - sizeof(uint64_t)))
#define ntfs_idx_entry_data(__ent)			\
		((void *)(__ent) + (__ent)->data_off)

#define NTFS_IDX_NODE_F_CHILD	0x01	/* Nodes entry have childs */

struct ntfs_idx_node_hdr {
/* 00 */uint32_t off;		/* Entries start offset, bytes */
/* 04 */uint32_t len;		/* Whole node size (hdr + entries), bytes */
/* 08 */uint32_t alloc_sz;	/* Allocated space size (w/ hdr), bytes */
/* 0C */uint32_t flags;
} __attribute__((packed));

struct ntfs_idx_rec_hdr {
/* 00 */struct ntfs_record r;	/* Should contains "INDX" magic signature */
/* 08 */uint64_t lsn;
/* 10 */uint64_t vcn;
/* 18 */uint8_t data[];
} __attribute__((packed));

#endif	/* _NTFS_STRUCT_IDX_H_ */
