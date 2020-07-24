/**
 * Index data extraction functions
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
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "cache.h"
#include "misc.h"
#include "bb.h"
#include "img.h"
#include "hints.h"
#include "idx_aux.h"
#include "idx_fetch.h"

struct idx_fetch_blocks_ctx {
	struct nhr_mft_entry *mfte;
	struct ntfs_attr_idx aidx;
	uint8_t *idx_bm;	/* Index bitmap buffer */
	unsigned idx_bm_sz;	/* Index bitmap size */
	unsigned idx_bm_buf_sz;	/* Index bitmap buffer size */
	unsigned cnt_ent;
	unsigned cnt_blk;
};

/**
 * Process item entry from index record (block)
 */
static void idx_fetch_parse_idxe(struct nhr_mft_entry *mfte,
				 struct nhr_idx *idx,
				 struct nhr_idx_node *idxn,
				 const struct ntfs_idx_entry_hdr *ieh,
				 unsigned voff)
{
	struct nhr_idx_node *cidxn;
	struct nhr_idx_entry *idxe = NULL, *pidxe = NULL;
	uint64_t child_vcn;
	int correct_parent = 0, correct_child = 0;

	if (ieh->flags & NTFS_IDX_ENTRY_F_CHILD) {
		child_vcn = ntfs_idx_entry_child_vcn(ieh);
		cidxn = cache_idxn_find(idx, child_vcn);
		assert(cidxn);
		cidxn->flags |= NHR_IDXN_F_INUSE;
		cidxn->parent = idxn;
	} else {
		cidxn = NHR_IDXN_PTR_NONE;
	}
	if (ieh->key_sz) {
		idxe = cache_idxe_find(idx, (void *)ieh->key);
		if (!idxe) {
			if (nhr.verbose >= 3)
				printf("idxn[#%"PRIu64",%ls,%s]: could not find cached data for index entry at voff 0x%08X\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(idxn), voff);
			return;
		}
		idxe->voff = voff;
		cache_idxe_container_set(idxe, idxn);
		correct_child = 1;
	} else if (idxn->last && !idxn->last->key) {
		assert(0);	/* Should not happen */
	} else {
		pidxe = cache_idxn_parent(idx, idxn);
		idxe = calloc(1, sizeof(*idxe));
		idxe->voff = voff;
		if (idxn->flags & NHR_IDXN_F_LEAF && idxn->last &&
		    idxn->last->voff + idx_entry_len(idx, idxn->last) == voff) {
			list_add(&idxe->list, &idxn->last->list);	/* After last entry */
			correct_parent = 1;
		} else if (pidxe && !cache_idxe_pos_unkn(idx, pidxe)) {
			list_add_tail(&idxe->list, &pidxe->list);	/* Before parent */
			correct_child = 1;
		} else if (cidxn != NHR_IDXN_PTR_NONE && cidxn->last &&
		           !cidxn->last->key &&
			   !cache_idxe_pos_unkn(idx, cidxn->last)) {
			list_add(&idxe->list, &cidxn->last->list);	/* After child */
			correct_parent = 1;
		} else {
			list_add_tail(&idxe->list, &idx->entries);	/* List end */
		}
		cache_idxe_container_set(idxe, idxn);
	}
	if (idxe && idxe->child == NHR_IDXN_PTR_UNKN)
		idxe->child = cidxn;

	if (correct_parent && NHR_IDXN_PTR_VALID(idxn->parent)) {
		/* Correct parents end entry position */
		while (pidxe && cache_idxe_pos_unkn(idx, pidxe)) {
			list_del(&pidxe->list);
			list_add(&pidxe->list, &idxn->last->list);	/* After child */
			idxe = pidxe;
			idxn = idxe->container;
			if (!NHR_IDXN_PTR_VALID(idxn->parent))	/* Parent unknown */
				break;
			pidxe = list_next_entry(idxn->last, list);
			if (pidxe->child == idxn)	/* Nothing to correct */
				break;
			pidxe = cache_idxn_parent(idx, idxn);
		}
	} else if (correct_child) {
		/* Correct children end entry position */
		while (NHR_IDXN_PTR_VALID(idxe->child) &&
		       (cidxn = idxe->child)->last && !cidxn->last->key &&
		       list_prev_entry(idxe, list) != cidxn->last) {
			list_del(&cidxn->last->list);
			list_add_tail(&cidxn->last->list, &idxe->list);	/* Before us */
			idxe = cidxn->last;
		}
	}
}

/**
 * Process item corrupted (trancated) entry from index record (block)
 */
static void idx_fetch_parse_idxe_corrupted(struct nhr_mft_entry *mfte,
					   struct nhr_idx *idx,
					   struct nhr_idx_node *idxn,
					   const struct ntfs_idx_entry_hdr *ieh,
					   unsigned len, unsigned voff)
{
	struct nhr_idx_entry *idxe;

	idxe = idx->info->cache_idxe_find(idx, ieh, len);
	if (!idxe)
		return;

	idxe->voff = voff;
	cache_idxe_container_set(idxe, idxn);
	if (!(ieh->flags & NTFS_IDX_ENTRY_F_CHILD) &&
	    idxe->child == NHR_IDXN_PTR_UNKN)
		idxe->child = NHR_IDXN_PTR_NONE;
}

/**
 * Validate item index entry content
 *
 * iinfo - processed index type specific info
 * ieh - pointer to entry buffer
 * len - available buffer length
 *
 * Returns 0 or 1 or -1 if the entry is found, respectively, to be ivalid,
 * valid, valid but truncated.
 */
static int idx_fetch_validate_idxe(const struct nhr_idx_info *iinfo,
				   const struct ntfs_idx_entry_hdr *ieh,
				   size_t len)
{
	int res, sz;

	/* Verify val field */
	if (__builtin_offsetof(typeof(*ieh), val) > len)
		return -1;
	if (iinfo->data_sz) {
		if (ieh->data_off <= sizeof(*ieh))
			return 0;
		if (ieh->data_sz != iinfo->data_sz)
			return 0;
	} else {
		/* TODO: check value field somehow */
	}

	/* Verify index entry size field against min/max values */
	if (__builtin_offsetof(typeof(*ieh), size) > len)
		return -1;
	if (ieh->size < sizeof(*ieh) ||
	    ieh->size > sizeof(*ieh) + NTFS_ALIGN(iinfo->key_sz_max + iinfo->data_sz) + sizeof(uint64_t))
		return 0;

	/* Verify index entry key size field */
	if (__builtin_offsetof(typeof(*ieh), key_sz) > len)
		return -1;
	if (ieh->key_sz < iinfo->key_sz_min || ieh->key_sz > iinfo->key_sz_max)
		return 0;

	/* Verify sizes consistency */
	sz = sizeof(*ieh) + ieh->key_sz + (ieh->key_sz ? iinfo->data_sz : 0);
	if (ieh->size != NTFS_ALIGN(sz) &&
	    ieh->size != NTFS_ALIGN(sz) + sizeof(uint64_t))
		return 0;
	if (ieh->key_sz && iinfo->data_sz &&
	    ieh->data_off != sizeof(*ieh) + ieh->key_sz)
		return 0;

	/* Verify index entry flags field */
	if (__builtin_offsetof(typeof(*ieh), flags) > len)
		return -1;
	if (ieh->flags & ~(NTFS_IDX_ENTRY_F_LAST | NTFS_IDX_ENTRY_F_CHILD))
		return 0;

	/* Additional tests for flags, val and size consistency */
	if (ieh->flags & NTFS_IDX_ENTRY_F_LAST) {
		if (ieh->val != 0)		/* Last entry could not index file */
			return 0;
		if (ieh->key_sz != 0)	/* Last entry should not contain a key */
			return 0;
	} else {
		if (ieh->key_sz == 0)	/* Not last entry should contain a key */
			return 0;
	}
	sz = sizeof(*ieh) + ieh->key_sz + (ieh->key_sz ? iinfo->data_sz : 0);
	if (ieh->flags & NTFS_IDX_ENTRY_F_CHILD) {
		if (ieh->size != NTFS_ALIGN(sz) + sizeof(uint64_t))
			return 0;
	} else {
		if (ieh->size != NTFS_ALIGN(sz))
			return 0;
	}

	/* Verify key trancation */
	if (sizeof(*ieh) + ieh->key_sz > len)
		return -1;

	/* Index specific entry verification */
	if (ieh->key_sz) {
		res = iinfo->entry_validate(ieh);
		if (res <= 0)
			return res;
	}

	/* Verify child VCN and padding trancation */
	if (ieh->size > len)
		return -1;

	return 1;
}

/**
 * Validate index entries stream (sequence of entries inside item index
 * block)
 *
 * iinfo - processed index type specific info
 * buf - pointer to entries buffer
 * len - available buffer length
 * endp - pointer to first unused position after entries stream
 *
 * Returns 0 or 1 or -1 if the stream is found, respectively, to be ivalid,
 * valid, valid but truncated.
 *
 * Note:
 *  - invalid stream contains at least one invalid entry
 *  - valid stream contains only valid entries and has the END entry
 *  - trancated stream finishes by trancated entry or does not cotain the END
 *    entry
 */
static int idx_fetch_validate_idxe_stream(const struct nhr_idx_info *iinfo,
					  const void *buf, size_t len,
					  const void **endp)
{
	const struct ntfs_idx_entry_hdr *ieh;
	unsigned voff;
	int res;

	for (voff = 0; voff < len;) {
		ieh = buf + voff;

		res = idx_fetch_validate_idxe(iinfo, ieh, len - voff);
		if (res <= 0)
			return res;

		/* Check is this entry last? */
		if ((ieh->key_sz == 0) &&
		    (ieh->flags & NTFS_IDX_ENTRY_F_LAST)) {
			if (endp)
				*endp = buf + voff + ieh->size;
			return 1;
		}
		voff += ieh->size;
	}

	return -1;
}

/**
 * Parse index node corrupted by BB
 */
static void idx_fetch_parse_corrupted_node(struct nhr_mft_entry *mfte,
					   struct nhr_idx *idx,
					   struct nhr_idx_node *idxn,
					   const void *buf)
{
	const unsigned idx_blk_ssz = nhr.vol.idx_blk_sz / nhr.vol.sec_sz;
	const struct ntfs_idx_rec_hdr *irh = buf;
	const struct ntfs_idx_node_hdr *inh = (void *)irh->data;
	const struct ntfs_idx_entry_hdr *ieh;
	const unsigned idxn_voff = __builtin_offsetof(typeof(*irh), data);
	const unsigned idxn_vend = idxn_voff + inh->len;
	int good, res;
	unsigned i, voff, voff_bad = UINT_MAX, voff_good = UINT_MAX;

	if (inh->flags & NTFS_IDX_NODE_F_CHILD) {
		idxn->flags |= NHR_IDXN_F_NODE;
	} else {
		idxn->flags |= NHR_IDXN_F_LEAF;
		idxn->lvl = NHR_IDXN_LVL_LEAF;
	}

	voff_good = idxn_voff + inh->off;
	voff = voff_good;
	for (good = 1; voff < idxn_vend;) {
		if (voff_good == UINT_MAX) {
			for (i = voff_bad/nhr.vol.sec_sz + 1; i < idx_blk_ssz; ++i) {
				if (!(idxn->bb_map & (1 << i)))
					break;
			}
			voff_good = i * nhr.vol.sec_sz;
			if (voff_good >= idxn_vend)
				break;
			voff_bad = UINT_MAX;	/* Trigger next BB search */
		}
		if (voff_bad == UINT_MAX) {
			for (i = voff_good/nhr.vol.sec_sz + 1; i < idx_blk_ssz; ++i) {
				if (idxn->bb_map & (1 << i))
					break;
			}
			voff_bad = i * nhr.vol.sec_sz;
			if (voff_bad > idxn_vend)
				voff_bad = idxn_vend;
		}
		if (good) {
			if (voff + sizeof(*ieh) > voff_bad) {
				good = 0;
				voff_good = UINT_MAX;
				continue;
			}
			ieh = buf + voff;
			if (voff + ieh->size > voff_bad) {
				idx_fetch_parse_idxe_corrupted(mfte, idx, idxn,
							       ieh,
							       voff_bad - voff,
							       voff - idxn_voff - inh->off);

				good = 0;
				voff_good = UINT_MAX;
			} else {
				idx_fetch_parse_idxe(mfte, idx, idxn, ieh,
						     voff - idxn_voff - inh->off);
				if (ieh->flags & NTFS_IDX_ENTRY_F_LAST)
					break;
				voff += ieh->size;
			}
		} else {
			if (voff < voff_good)
				voff = voff_good;

			res = idx_fetch_validate_idxe_stream(idx->info,
							     buf + voff,
							     voff_bad - voff,
							     (void *)&ieh);
			if (res == 1 && ieh != buf + idxn_vend)
				res = 0;

			if (res) {
				good = 1;
				continue;
			}
			voff += NTFS_ALIGNTO;	/* Entries should be aligned */
			if (voff >= voff_bad)
				voff_good = UINT_MAX;
		}
	}
}

/**
 * Parse good (not corrupted) index block
 */
static void idx_fetch_parse_node(struct nhr_mft_entry *mfte,
				 struct nhr_idx *idx,
				 struct nhr_idx_node *idxn,
				 const struct ntfs_idx_node_hdr *inh)
{
	const struct ntfs_idx_entry_hdr *ieh_s = (void *)inh + inh->off;
	const struct ntfs_idx_entry_hdr *ieh_e = (void *)inh + inh->len;
	const struct ntfs_idx_entry_hdr *ieh;

	if (inh->flags & NTFS_IDX_NODE_F_CHILD) {
		idxn->flags |= NHR_IDXN_F_NODE;
	} else {
		idxn->flags |= NHR_IDXN_F_LEAF;
		idxn->lvl = NHR_IDXN_LVL_LEAF;
	}

	for (ieh = ieh_s; ieh < ieh_e; ieh = (void *)ieh + ieh->size)
		idx_fetch_parse_idxe(mfte, idx, idxn, ieh,
				     (void *)ieh - (void *)ieh_s);
}

/**
 * Process index record (block)
 */
static void idx_fetch_analyze_block(struct nhr_mft_entry *mfte,
				    struct nhr_idx *idx,
				    struct nhr_idx_node *idxn)
{
	const unsigned idx_blk_ssz = nhr.vol.idx_blk_sz / nhr.vol.sec_sz;
	struct nhr_bb *bb;
	uint8_t buf[nhr.vol.idx_blk_sz];
	struct ntfs_idx_rec_hdr *irh = (void *)buf;
	struct ntfs_usa *usa;
	void *p;
	unsigned i;

	for (i = 0; i < idx_blk_ssz; ++i) {
		bb = bb_find(idxn->lcn * nhr.vol.cls_sz + i * nhr.vol.sec_sz);
		if (!bb)
			continue;
		idxn->bb_map |= 1 << i;
	}

	if (idxn->flags & NHR_IDXN_F_FREE)
		return;

	if (idxn->bb_map & 1)		/* Could not process blocks without header */
		return;

	img_read_clusters(idxn->lcn, buf, nhr.vol.idx_blk_csz);
	assert(irh->vcn == idxn->vcn);
	assert(irh->r.usa_len - 1 == idx_blk_ssz);

	/* Manually verify integrity and apply markers */
	usa = ntfs_usa_ptr(&irh->r);
	p = buf + nhr.vol.sec_sz - sizeof(uint16_t);
	for (i = 0; i < idx_blk_ssz; ++i, p += nhr.vol.sec_sz) {
		if (idxn->bb_map & (1 << i))	/* Skip corrupted sectors */
			continue;
		if (*(uint16_t *)p != usa->usn) {
			bb = calloc(1, sizeof(*bb));
			nhr_bb_off(bb) = idxn->lcn * nhr.vol.cls_sz +
					 i * nhr.vol.sec_sz;
			bb->attr_type = NTFS_ATTR_IALLOC;
			/* How to get attribute id? */
			bb->voff = idxn->vcn * nhr.vol.cls_sz +
				   i * nhr.vol.sec_sz;
			bb->flags = NHR_BB_F_AUTO;
			bb->entity = idx;
			rbtree_insert(&nhr.bb_tree, &bb->tree);
			cache_mfte_bb_add(mfte, bb);
			idxn->bb_map |= 1 << i;
			continue;
		}
		*(uint16_t *)p = usa->sec[i];
	}

	if (idxn->bb_map)
		idx_fetch_parse_corrupted_node(mfte, idx, idxn, buf);
	else
		idx_fetch_parse_node(mfte, idx, idxn,
				     (struct ntfs_idx_node_hdr *)irh->data);
}

/**
 * Process $INDEX_ROOT data
 */
static void idx_fetch_analyze_iroot(struct nhr_mft_entry *mfte,
				    struct nhr_idx *idx, const void *data,
				    size_t len)
{
	const struct ntfs_attr_iroot *ir = data;

	idx_fetch_parse_node(mfte, idx, idx->root,
			     (struct ntfs_idx_node_hdr *)ir->data);
}

void idx_read_blocks(void)
{
	struct nhr_mft_entry *mfte;
	struct nhr_idx *idx;
	struct nhr_idx_node *idxn;
	unsigned ent_tot = 0, idx_tot = 0;
	unsigned i;

	if (nhr.verbose >= 1)
		printf("idx: read index blocks\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(mfte->f_cmn & NHR_MFT_FC_BASE))
			continue;
		if (mfte->idx_num)
			ent_tot++;
		for (i = 0; i < mfte->idx_num; ++i) {
			idx_tot++;
			idx = mfte->idx[i];
			if (idx->root_buf)
				idx_fetch_analyze_iroot(mfte, idx,
							idx->root_buf,
							idx->root_buf_len);
			list_for_each_entry(idxn, &idx->nodes, list) {
				if (idxn->vcn < 0)	/* Ignore special nodes */
					continue;
				idx_fetch_analyze_block(mfte, idx, idxn);
			}
		}
	}

	if (nhr.verbose >= 1)
		printf("idx: processed %u indexes in %u MFT entries\n", idx_tot,
		       ent_tot);
}
