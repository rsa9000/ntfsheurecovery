/**
 * NTFS entities cache interface
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

#ifndef _CACHE_H_
#define _CACHE_H_

#include <limits.h>
#include <wchar.h>

#include "list.h"
#include "rbtree.h"
#include "ntfs_struct.h"

/* Common flags */
#define NHR_MFT_FC_FREE		0x000001	/* MFT entry not allocated */
#define NHR_MFT_FC_FILE		0x000002	/* MFT entry allocated for file */
#define NHR_MFT_FC_DIR		0x000004	/* MFT entry allocated for directory */
#define NHR_MFT_FC_IDX		0x000008	/* MFT entry allocated for view index */
#define NHR_MFT_FC_FDI_MASK	0x00000E	/* MFT entry file/dir/idx type mask */
#define NHR_MFT_FC_BASE		0x000010	/* MFT entry is base */
#define NHR_MFT_FC_EXTENT	0x000020	/* MFT entry is extent */
#define NHR_MFT_FC_BASEEXT_MASK	0x000030	/* MFT entry base/extent mask */
#define NHR_MFT_FC_INTEG	0x000040	/* MFT entry have some integrity issues */

/* Corruption type flags */
#define NHR_MFT_FB_SELF		0x000001	/* MFT entry itself corrupted by BB */
#define NHR_MFT_FB_AIDX		0x000002	/* MFT entry index is corrupted */
#define NHR_MFT_FB_ADATA	0x000004	/* MFT entry data is corrupted */

struct nhr_alist_item;

/**
 * Stream segment info
 */
struct nhr_str_segm {
	struct list_head list;
	struct nhr_f64 firstvcn;
	struct nhr_f64 lastvcn;
	struct nhr_alist_item *ali;
};

/* Data flags */
#define NHR_DATA_F_VALID	0x10000	/* Data stream looks valid */
#define NHR_DATA_F_COMP		0x00001	/* Data stream compressed */

/**
 * Cached data chunk
 */
struct nhr_data_chunk {
	struct list_head list;		/* Chain all chunks */
	uint32_t voff;			/* Chunk virtual offset */
	uint32_t len;			/* Chunk length */
	enum nhr_info_src src;		/* Data source */
	uint8_t buf[];			/* Data buffer */
};

/**
 * Cached data stream
 */
struct nhr_data {
	unsigned flags;		/* Data stream flags, see NHR_DATA_F_xxx */
	unsigned name_len;	/* Data stream name length */
	uint8_t *name;		/* Data stream name */
	struct nhr_f64 sz_alloc;/* Data stream allocated space */
	struct nhr_f64 sz_used;	/* Data stream actual size */
	struct nhr_f64 sz_init;	/* Initialized part of data */
	struct ntfs_mp *mpl;	/* Data stream mapping pair list */
	struct list_head chunks;/* Data chunks list */
	struct list_head segments;/* Data stream segments list */
	uint8_t *digest;	/* Data stream digest */
};

/**
 * Cached attribute list item
 */
struct nhr_alist_item {
	struct list_head list;		/* Chain all attributes */
	enum nhr_info_src src;		/* Attribute source */
	uint32_t type;			/* Attribute type */
	uint16_t id;			/* Attribute id */
	uint8_t name_len;		/* Attribute name len */
	uint8_t *name;			/* Attribute name */
	struct nhr_mft_entry *mfte;	/* Container entry */
	uint64_t firstvcn;		/* First VCN in stream */
	void *entity;			/* Pointer to type specific entity */
};

#define NHR_IDXN_F_FREE		0x0001	/* Is node not used */
#define NHR_IDXN_F_INUSE	0x0002	/* Node in use */
#define NHR_IDXN_F_LEAF		0x0004	/* Node does not have childs */
#define NHR_IDXN_F_NODE		0x0008	/* Node is internal node (not leaf) */

#define NHR_IDXN_LVL_UNKN	(~0)	/* Node level is unknown */
#define NHR_IDXN_LVL_LEAF	0	/* Node is leaf */

#define NHR_IDXN_PTR_UNKN	((struct nhr_idx_node *)NULL)
#define NHR_IDXN_PTR_NONE	((struct nhr_idx_node *)~0LU)

#define NHR_IDXN_PTR_VALID(__idxn)					\
		((__idxn) != NHR_IDXN_PTR_UNKN && (__idxn) != NHR_IDXN_PTR_NONE)

#define NHR_IDXN_VCN_ROOT	(-1)
#define NHR_IDXN_VCN_UNKN	(-2)
#define NHR_IDXN_VCN_NONE	(-3)

/**
 * Index node (B+ tree node, which contains several index keys)
 */
struct nhr_idx_node {
	struct list_head list;	/* Chain all nodes of item index */
	int64_t vcn;		/* Position in stream (vcn < 0 for special nodes) */
	uint64_t lcn;		/* On disk position */
	uint32_t flags;		/* Node status flags (see NHR_IDXN_F_xxx) */
	int lvl;		/* Node level above leaf (see NHR_IDXN_LVL_xxx) */
	struct nhr_idx_node *parent;	/* Parent node */
	struct nhr_idx_entry *first;	/* First entry */
	struct nhr_idx_entry *last;	/* Last entry */
	uint16_t bb_map;	/* Bad blocks map */
	uint16_t bb_rec;	/* Recovered bad blocks map */
};

/**
 * Index entry
 */
struct nhr_idx_entry {
	struct list_head list;	/* Chain all entries of item index */
	struct nhr_idx_node *container;	/* Container idx node */
	struct nhr_idx_node *child;	/* Child (target) idx node */
	void *key;			/* Entry key */
	void *data;			/* Entry data */
	unsigned voff;			/* Virtual offset inside node */
};

/* Generic index flags */
#define NHR_IDX_F_VALID		0x0001	/* Index looks valid */

/**
 * Index
 */
struct nhr_idx {
	const struct nhr_idx_info *info;/* Index type info */
	unsigned flags;			/* Index flags (see NHR_IDX_F_xxx) */
	struct nhr_idx_node *root;	/* Root node pointer */
	void *root_buf;			/* On disk root node copy */
	unsigned root_buf_len;		/* Copy length */
	struct nhr_idx_entry *end;	/* Stream end entry */
	struct list_head nodes;		/* Index nodes list */
	struct list_head entries;	/* Index entries list */
};

/**
 * MFT entry internal descriptor
 * NB: entry number stored in the tree node key
 */
struct nhr_mft_entry {
	struct rbtree_head tree;
	unsigned f_cmn;		/* See NHR_MFT_FC_xxx */
	unsigned f_bad;		/* Corruption flags (see NHR_MFT_FB_xxx) */
	unsigned f_rec;		/* Recovery flags (see NHR_MFT_FB_xxx) */
	unsigned f_sum;		/* Corruption summary for base + extents */
	uint8_t bb_map;		/* Bad blocks map */
	uint8_t bb_rec;		/* Recovered BB map */
	struct list_head bb;	/* Bad blocks list */
	unsigned bb_cnt_data;	/* Number of unrecovered BB of $DATA */
	unsigned bb_cnt_idx;	/* Number of unrecovered BB of $INDEX_ALLOCATION */
	enum nhr_info_src base_src;	/* Source of base entry info */
	struct nhr_mft_entry *bmfte;	/* Base entry pointer */
	struct list_head ext;	/* Extent entries list */
	struct nhr_f64 parent;	/* Parent dir MFT entry */
	struct nhr_f16 seqno;	/* Entry sequence number */
	struct nhr_f64 time_create;	/* Creation timestamp */
	struct nhr_f64 time_change;	/* Change timestamp */
	struct nhr_f64 time_mft;	/* MFT entry change timestamp */
	struct nhr_f64 time_access;	/* Access timestamp */
	struct nhr_f32 fileflags;	/* File flags ($I30, compressed, etc) */
	struct nhr_f32 sid;		/* Security ID */
	struct list_head alist;		/* Attributes list */
	int alist_valid;		/* Attributes list valid */
	struct nhr_mfte_fn {
		uint16_t attr_id;	/* Attribute, which carry this name */
		enum nhr_info_src src;	/* Data source */
		unsigned len;		/* Name length */
		uint8_t *name;		/* Name (Unicode) */
	} names[NTFS_FNAME_T_MAX + 1];/* fname array (indexed by name type) */
	int names_valid;		/* Names set is valid */
	enum nhr_info_src oid_src;	/* Source of object id information */
	struct ntfs_attr_oid *oid;	/* Object id info */
	unsigned data_num;		/* Number of data streams */
	struct nhr_data **data;		/* Data streams array */
	unsigned idx_num;		/* Number of indexes */
	struct nhr_idx **idx;		/* Indexes pointers array */
};

#define nhr_mfte_num(__mfte)	(__mfte)->tree.key
#define nhr_mfte_bflags(__mfte)	((__mfte)->f_bad & ~(__mfte)->f_rec)

/**
 * MFT extent entries map
 * NB: entry number stored in the tree node key
 */
struct nhr_mft_eemap {
	struct rbtree_head tree;
	uint64_t base;		/* Base entry number */
};

#define nhr_mftee_num(__mftee)	(__mftee)->tree.key

struct nhr_bb;	/* Forward declaration */

struct nhr_mft_entry *cache_mfte_alloc(const uint64_t entnum);
struct nhr_mft_entry *cache_mfte_find(uint64_t entnum);
void cache_mfte_fbad_set(struct nhr_mft_entry *mfte, unsigned flags);
void cache_mfte_frec_set(struct nhr_mft_entry *mfte, unsigned flags);
void cache_mfte_base_set(struct nhr_mft_entry *mfte,
			 struct nhr_mft_entry *bmfte,
			 enum nhr_info_src src);
void cache_mfte_fileflags_upd(struct nhr_mft_entry *mfte, uint32_t fileflags,
			      enum nhr_info_src src);
const wchar_t *cache_mfte_name(const struct nhr_mft_entry *mfte);
void cache_mfte_bb_add(struct nhr_mft_entry *mfte, struct nhr_bb *bb);
void cache_mfte_bb_ok(struct nhr_bb *bb);
struct nhr_bb *cache_mfte_bb_find(const struct nhr_mft_entry *mfte,
				  uint32_t attr_type, const void *entity);
struct nhr_bb *cache_mfte_bb_next(struct nhr_bb *bb);
int cache_mfte_attrs_num(const struct nhr_mft_entry *mfte);
struct nhr_alist_item *cache_attr_alloc(struct nhr_mft_entry *mfte,
					uint32_t type, unsigned name_len,
					const uint8_t *name, uint64_t firstvcn);
struct nhr_alist_item *cache_attr_find_id(const struct nhr_mft_entry *mfte,
					  uint32_t type, uint16_t id);
struct nhr_alist_item *cache_attr_find_entity(const struct nhr_mft_entry *mfte,
					      uint32_t type, const void *entity);
struct nhr_alist_item *cache_attr_str_find(const struct nhr_mft_entry *mfte,
					   uint32_t type, unsigned name_len,
					   const uint8_t *name);
struct nhr_alist_item *cache_attr_str_next(const struct nhr_mft_entry *mfte,
					   struct nhr_alist_item *ali);
const wchar_t *cache_attr_name(const struct nhr_alist_item *ali);
int cache_alist_maxid(const struct nhr_mft_entry *mfte);

void __cache_data_merge(struct nhr_data *dst, struct nhr_data *src);
struct nhr_data *cache_data_alloc(struct nhr_mft_entry *mfte, unsigned name_len,
				  const uint8_t *name);
struct nhr_data *cache_data_find(const struct nhr_mft_entry *mfte,
				 unsigned name_len, const uint8_t *name);
unsigned cache_data_idx(const struct nhr_mft_entry *mfte,
			const struct nhr_data *data);
const wchar_t *cache_data_name(const struct nhr_data *data);
void __cache_data_segm_insert(struct nhr_data *data, struct nhr_str_segm *segm);
struct nhr_str_segm *cache_data_segm_alloc(struct nhr_data *data,
					   uint64_t firstvcn);
struct nhr_str_segm *cache_data_segm_find(const struct nhr_data *data,
					  uint64_t firstvcn);
struct nhr_str_segm *cache_data_segm_orph(const struct nhr_data *data);
struct nhr_cmask_elem *cache_data_bb_gen_mask(const struct nhr_mft_entry *mfte,
					      const struct nhr_data *data);

int __cache_idx_insert(struct nhr_mft_entry *mfte, struct nhr_idx *idx);
struct nhr_idx *cache_idx_alloc(struct nhr_mft_entry *mfte, int type);
struct nhr_idx *cache_idx_find(const struct nhr_mft_entry *mfte, int type);
int cache_idx_idx(const struct nhr_mft_entry *mfte, const struct nhr_idx *idx);
const wchar_t *cache_idx_name(const struct nhr_idx *idx);
struct nhr_idx_node *cache_idxn_alloc(struct nhr_idx *idx, int64_t vcn);
struct nhr_idx_node *cache_idxn_find(const struct nhr_idx *idx, int64_t vcn);
struct nhr_idx_node *cache_idxn_child_last(const struct nhr_idx *idx,
					   const struct nhr_idx_node *idxn);
struct nhr_idx_entry *cache_idxn_parent(const struct nhr_idx *idx,
					const struct nhr_idx_node *idxn);
const char *cache_idxn_name(const struct nhr_idx_node *idxn);
struct nhr_idx_entry *cache_idxe_alloc(struct nhr_idx *idx, void *key);
struct nhr_idx_entry *cache_idxe_find(const struct nhr_idx *idx,
				      const void *key);
int cache_idxe_pos_unkn(const struct nhr_idx *idx,
			const struct nhr_idx_entry *idxe);
void cache_idxe_container_set(struct nhr_idx_entry *idxe,
			      struct nhr_idx_node *idxn);
const wchar_t *cache_idxe_name(const struct nhr_idx *idx,
			       const struct nhr_idx_entry *idxe);

static inline struct nhr_idx_entry *cache_idxe_prev(const struct nhr_idx *idx,
						    struct nhr_idx_entry *idxe)
{
	return idxe->list.prev != &idx->entries ? list_prev_entry(idxe, list) :
						  NULL;
}

static inline struct nhr_idx_entry *cache_idxe_next(const struct nhr_idx *idx,
						    struct nhr_idx_entry *idxe)
{
	return idxe->list.next != &idx->entries ? list_next_entry(idxe, list) :
						  NULL;
}


void nhr_mft_eemap_add(uint64_t ext_entnum, uint64_t base_entnum);
void cache_sqlite_clean(void);
void cache_sqlite_dump(void);
void cache_init(void);

#endif	/* _CACHE_H_ */
