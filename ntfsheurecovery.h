/**
 * Program wide common definitions
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

#ifndef _NTFSHEURECOVERY_H_
#define _NTFSHEURECOVERY_H_

#include <stdio.h>
#include <sqlite3.h>

#include "rbtree.h"
#include "ntfs.h"

/* Main runtime state */
struct nhr_state {
	int verbose;
	const char *fs_file_name;
	int fs_fd;
	off_t fs_file_sz;
	const char *bb_file_name;
	uint64_t bb_file_off;
	const char *hints_file_name;
	const char *db_file_name;
	const char *out_dir;	/* Output directory */
	struct sqlite3 *db;	/* SQLite DB handler */
	uint64_t db_last_rowid;
	struct rbtree bb_tree;
	struct rbtree hints;	/* Hints tree sorted by MFT entry number */
	struct ntfs_volume vol;
	unsigned mft_data_aid;	/* MFT $DATA attribute id */
	struct rbtree mft_cache;/* MFT entries cache */
	struct rbtree mft_eemap;/* MFT ext entries map */
	struct ntfs_mp *mft_data;/* MFT $DATA mapping pairs */
	unsigned mft_data_num;	/* MFT $DATA mapping pairs num */
	uint16_t *vol_upcase;	/* $UpCase copy */
	size_t vol_upcase_sz;	/* $upCase size, bytes */
	uint8_t *mft_bitmap;	/* MFT bitmap copy */
	size_t mft_bitmap_sz;	/* MFT bitmap size, bytes */
	struct rbtree img_overlay;
	struct rbtree cmap;	/* Clusters map */
};

/**
 * Non-resident attribute mapping pair descriptor (rbtree version)
 * NB: attribute VCN stored in the tree node key
 */
struct nhr_mpt {
	struct rbtree_head tree;
	uint64_t lcn;		/* Starting on disk cluster */
	uint64_t clen;		/* Length, clusters */
};

#define nhr_mpt_vcn(__mp)	(__mp)->tree.key

extern struct nhr_state nhr;

/* Information source (sorted by preference) */
enum nhr_info_src {
	NHR_SRC_NONE,		/* No data */
	NHR_SRC_HEUR,		/* Heuristic assumption */
	NHR_SRC_HINT,		/* From user's hint */
	NHR_SRC_FN,		/* From MFT entry $FILE_NAME attr */
	NHR_SRC_STDINF,		/* From MFT entry $STANDARD_INFO attr */
	NHR_SRC_ALIST,		/* From base MFT entry $ATTRIBUTE_LIST attr */
	NHR_SRC_IDX_OBJID,	/* From $ObjId index entry */
	NHR_SRC_I30,		/* From $I30 index entry */
	NHR_SRC_ATTR,		/* From attribute itself (e.g. data length) */
	NHR_SRC_MFT,		/* From MFT entry header */
};

/* Generic 64-bit field */
struct nhr_f64 {
	enum nhr_info_src src;	/* Value source */
	uint64_t val;		/* Field value */
};

/* Generic 32-bit field */
struct nhr_f32 {
	enum nhr_info_src src;	/* Value source */
	uint32_t val;		/* Field value */
};

/* Generic 16-bit field */
struct nhr_f16 {
	enum nhr_info_src src;	/* Value source */
	uint16_t val;		/* Field value */
};

#define NHR_FIELD_UPDATE(__f, __v, __s)			\
		if (__s > (__f)->src) {			\
			(__f)->src = __s;		\
			(__f)->val = __v;		\
		}

#define NHR_FIELD_VALID(__f)				\
		((__f)->src != NHR_SRC_NONE)

/* Index types (own private classification) */
#define NHR_IDX_T_DIR		0x00	/* Directory index aka $I30 */
#define NHR_IDX_T_SDH		0x01	/* Security descriptors indexed by hash */
#define NHR_IDX_T_SII		0x02	/* Security descriptors indexed by id */
#define NHR_IDX_T_MAX		0x02
#define NHR_IDX_T_UNKN		(-1)	/* Unknown index type */

#endif	/* _NTFSHEURECOVERY_H_ */
