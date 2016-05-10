/**
 * Index recovery procedures
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
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "cache.h"
#include "img.h"
#include "bb.h"
#include "misc.h"
#include "hints.h"
#include "idx.h"
#include "idx_cmp.h"
#include "idx_aux.h"
#include "idx_recover.h"

#if 0
/** Propagate node level info up and down by tree */
static void idx_recover_propagate_level(struct nhr_mft_entry *mfte,
					struct nhr_idx *idx,
					struct nhr_idx_node *idxn)
{
	struct nhr_idx_entry *idxe;

	if (NHR_IDXN_PTR_VALID(idxn->parent) &&
	    idxn->parent->lvl == NHR_IDXN_LVL_UNKN) {
		idxn->parent->lvl = idxn->lvl + 1;
		idx_recover_propagate_level(mfte, idx, idxn->parent);
	}

	if (idxn->flags & NHR_IDXN_F_NODE && idxn->first) {
		for (idxe = idxn->first;; idxe = list_next_entry(idxe, list)) {
			if (idxe->container == idxn &&
			    NHR_IDXN_PTR_VALID(idxe->child) &&
			    idxe->child->lvl == NHR_IDXN_LVL_UNKN) {
				idxe->child->lvl = idxn->lvl - 1;
				idx_recover_propagate_level(mfte, idx,
							    idxe->child);
			}
			if (idxe == idxn->last)
				break;
		}
	}
}
#endif

/**
 * Recover item index
 *
 * Process index and try to guess which entry belongs to which block and
 * create end entries for each block.
 *
 * Returns value less than zero if error ocure, greater than zero if index
 * recovered and zero if no recovery was required.
 */
static int idx_recover_idx(struct nhr_mft_entry *mfte, struct nhr_idx *idx,
			   unsigned *pcnt_idxe)
{
	struct nhr_idx_node *idxn;
	struct nhr_idx_entry *idxe, *idxe_prev, *idxe_next, *idxe_last;
	struct nhr_idx_entry *pidxe;
	unsigned level = 0;	/* How high we are off the leaf */
	struct {		/* Stack */
		struct nhr_idx_node *node;	/* Current/last processed node */
		struct nhr_idx_entry *entry;	/* Last node entry */
	} *st;
	unsigned st_sz = 4;	/* Current allocated stack size */
	unsigned len;
	unsigned cnt_idxe = 0;
	unsigned level2;
	int res = -1;

	/* Handle empty indexes as special case */
	if (idx->nodes.next == idx->nodes.prev &&
	    idx->entries.next == idx->entries.prev) {
		/* Correct root node metadata */
		idx->root->lvl = NHR_IDXN_LVL_LEAF;
		idx->root->flags |= NHR_IDXN_F_LEAF;
		/* Create end entry for root node */
		idxe_last = calloc(1, sizeof(*idxe_last));
		idxe_last->container = idx->root;
		idxe_last->child = NHR_IDXN_PTR_NONE;
		list_add(&idxe_last->list, &idx->entries);
		if (pcnt_idxe)
			*pcnt_idxe = 1;
		return 1;
	}

#if 0	/* Not so useful as expected */
	list_for_each_entry(idxn, &idx->nodes, list) {
		if (idxn->lvl == NHR_IDXN_LVL_UNKN)
			continue;
		idx_recover_propagate_level(mfte, idx, idxn);
	}
#endif

	st = calloc(1, st_sz * sizeof(st[0]));

	for (idxe = list_first_entry(&idx->entries, typeof(*idxe), list);
	     idxe != idx->end;
	     idxe = list_next_entry(idxe, list)) {
		if (idxe->container == NHR_IDXN_PTR_UNKN)
			idxe_prev = cache_idxe_prev(idx, idxe);
		if (idxe->container == NHR_IDXN_PTR_UNKN &&
		    st[level].entry != NULL) {
			if (level == 0) {
				idxe->child = NHR_IDXN_PTR_NONE;
			} else {
				idxe->child = idxe_prev->container;
				idxe->child->flags |= NHR_IDXN_F_INUSE;
				idxe_prev->container->parent = st[level].node;
			}
			idxe->voff = st[level].entry->voff +
				     idx_entry_len(idx, st[level].entry);
			cache_idxe_container_set(idxe, st[level].node);
			cnt_idxe++;
		}
		if (idxe->container == NHR_IDXN_PTR_UNKN &&
		    st[level].entry == NULL) {			/* Node start */
			len = idx_entry_len(idx, idxe);

			/* First, search for any non-leaf entry */
			level2 = 0;
			for (pidxe = list_next_entry(idxe, list);
			     &pidxe->list != &idx->entries;
			     pidxe = list_next_entry(pidxe, list)) {
				if (NHR_IDXN_PTR_VALID(pidxe->child))
					break;
				if (level2 == level)
					len += idx_entry_len(idx, pidxe);
				if (!pidxe->key)
					level2++;
				else if (level2)
					level2 = 0;
			}

#if 0
			printf("idx[#%"PRIu64",%ls,%u]: search done pidxe is %ls (node: %s, child: %s is %sempty)\n",
			       nhr_mfte_num(mfte), cache_idx_name(idx), level2,
			       cache_idxe_name(idx, pidxe),
			       cache_idxn_name(pidxe->container),
			       cache_idxn_name(pidxe->child),
			       pidxe->child->first ? "not" : "");
#endif

			if (cache_idxe_prev(idx, pidxe)->key)	/* Not end */
				len += idx_entry_len(idx, NULL);

			if (NHR_IDXN_PTR_VALID(pidxe->container) &&
			    pidxe->container->lvl != NHR_IDXN_LVL_UNKN &&
			    pidxe->container->lvl != level + 1) {
				printf("idxn[#%"PRIu64",%ls,%s]: possible parent node is too hight (%u, expect %u)\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(pidxe->container),
				       pidxe->container->lvl, level + 1);
				goto exit_err;
			}

			idxn = pidxe->child;
			if (idxn->first != NULL) {
				printf("idx[#%"PRIu64",%ls]: possible container node %s for %ls entry is not empty\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(idxn),
				       cache_idxe_name(idx, idxe));
				goto exit_err;
			}

			if (len > nhr.vol.idx_blk_sz) {
				printf("idxn[#%"PRIu64",%ls,%s]: desired node content is too large (%u bytes), splitting not yet implemented\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(idxn), len);
				goto exit_err;
			}

			if (level == 0) {
				idxn->flags |= NHR_IDXN_F_LEAF;
				idxe->child = NHR_IDXN_PTR_NONE;
			} else {
				idxn->flags |= NHR_IDXN_F_NODE;
				idxe->child = idxe_prev->container;
				idxe_prev->container->flags |= NHR_IDXN_F_INUSE;
				idxe_prev->container->parent = idxn;
			}
			idxn->lvl = level;
			idxe->voff = 0;
			cache_idxe_container_set(idxe, idxn);
			cnt_idxe++;
		}

#if 0
		printf("idx[#%"PRIu64",%ls,%u]: node: %-4s child: %-4s voff: %4d key: %ls\n",
		       nhr_mfte_num(mfte), cache_idx_name(idx), level,
		       cache_idxn_name(idxe->container),
		       cache_idxn_name(idxe->child), (int)idxe->voff,
		       cache_idxe_name(idx, idxe));
#endif

		if (idxe->container == NHR_IDXN_PTR_UNKN)	/* No reasons to continue */
			goto exit_err;

		/* Recover (or verify) index nodes level */
		/* TODO: make level check less hardcore :D */
		if (idxe->container->lvl == NHR_IDXN_LVL_UNKN)
			idxe->container->lvl = level;
		else
			assert(idxe->container->lvl == level);

		if (!st[level].entry)
			st[level].node = idxe->container;
		st[level].entry = idxe;

		if (!idxe->key) {
			st[level].entry = NULL;
			level++;
			if (level + 1 >= st_sz) {
				st_sz++;
				st = realloc(st, st_sz * sizeof(st[0]));
				memset(&st[st_sz - 1], 0x00, sizeof(st[0]));
			}
		} else if (NHR_IDXN_PTR_VALID(idxe->child)) {
			level = 0;
		}

		/* Recover node end entries */
		if (idxe->container->last == idxe) {
			idxe_next = cache_idxe_next(idx, idxe);
			/* Recover leaf node end entry */
			if (idxe->container->last->key &&
			    idxe->child == NHR_IDXN_PTR_NONE &&
			    idxe_next->container != NHR_IDXN_PTR_UNKN &&
			    idxe->container != idxe_next->container) {
				idxe_last = calloc(1, sizeof(*idxe_last));
				list_add(&idxe_last->list, &idxe->list);	/* After us */
			}
			/* Recover parent node end entry */
			if (!idxe->container->last->key &&
			    idxe_next->container != NHR_IDXN_PTR_UNKN &&
			    NHR_IDXN_PTR_VALID(idxe_next->child) &&
			    idxe_next->child != idxe->container) {
				idxn = idxe->container;
				/* If parent node not empty (NB: level already incremented) */
				if (level < st_sz && st[level].entry) {
					idxe_last = calloc(1, sizeof(*idxe_last));
					list_add(&idxe_last->list, &idxe->list);
				} else
				/* Special case for emtpy root node */
				if (idxn != idx->root &&
				    idxe_next->child == idx->root) {
					idxe_last = calloc(1, sizeof(*idxe_last));
					list_add(&idxe_last->list, &idxe->list);
				}
			}
		}
	}

	res = 0;
	goto exit;

exit_err:
	res = -1;

exit:
	if (pcnt_idxe)
		*pcnt_idxe = cnt_idxe;

	free(st);

	return res ? -1 : cnt_idxe ? 1 : 0;
}

void idx_recover_indexes(void)
{
	struct nhr_mft_entry *mfte;
	unsigned ent_tot = 0, idx_tot = 0, idx_ok = 0, idx_rec = 0;
	unsigned idxe_rec = 0, idxe_rec_item;
	unsigned i;
	int res;

	if (nhr.verbose >= 1)
		printf("idx: recover indexes themself\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!mfte->idx_num)
			continue;
		ent_tot++;
		for (i = 0; i < mfte->idx_num; ++i) {
			idx_tot++;
			res = idx_recover_idx(mfte, mfte->idx[i],
					      &idxe_rec_item);
			if (res > 0) {
				idx_rec++;
				idxe_rec += idxe_rec_item;
			} else if (res == 0) {
				idx_ok++;
			} else {
				idxe_rec += idxe_rec_item;
			}
		}
	}

	if (nhr.verbose >= 1)
		printf("idx: processed %u indexes in %u MFT entries (Ok: %u indexes, recovered: %u entries, %u indexes)\n",
		       idx_tot, ent_tot, idx_ok, idxe_rec, idx_rec);
}

static void idx_recover_create_overlay(struct nhr_mft_entry *mfte,
				       struct nhr_idx_node *idxn,
				       const uint8_t *rec_buf)
{
	const unsigned idx_blk_ssz = nhr.vol.idx_blk_sz / nhr.vol.sec_sz;
	unsigned i, voff;
	struct nhr_bb *bb;
	struct nhr_ob *ob;

	for (i = 0; i < idx_blk_ssz; ++i) {
		if (!(idxn->bb_map & (1 << i)))
			continue;
		voff = i * nhr.vol.sec_sz;
		bb = bb_find(idxn->lcn * nhr.vol.cls_sz + voff);
		assert(bb);

		ob = img_overlay_alloc(nhr.vol.sec_sz);
		nhr_ob_off(ob) = nhr_bb_off(bb);
		memcpy(ob->buf, rec_buf + voff, nhr.vol.sec_sz);
		img_overlay_add(ob);

		bb->flags |= NHR_BB_F_REC;
		idxn->bb_rec |= 1 << i;
		cache_mfte_bb_ok(bb);
	}
}

/**
 * Build index block as we image it
 */
static void idx_recover_build_block(const struct nhr_mft_entry *mfte,
				    const struct nhr_idx *idx,
				    const struct nhr_idx_node *idxn,
				    uint64_t lsn, uint16_t usn, void *buf)
{
	struct ntfs_idx_rec_hdr *irh = buf;
	struct ntfs_idx_node_hdr *inh = (void *)irh->data;
	struct ntfs_usa *usa;
	uint16_t *usa_ptr;
	struct ntfs_idx_entry_hdr *ieh;
	unsigned i;
	unsigned voff;
	const struct nhr_idx_entry *idxe;
	struct hint *h;

	/**
	 * Index block layout:
	 *  - index block (record) header
	 *  - index node header
	 *  - USA (update sequence array)
	 *  - paddign (if needed)
	 *  - index entry 1
	 *  - index entry 2
	 *  ...
	 *  - index entry N (the END entry)
	 */

	/* Index block (record) header */
	memcpy(irh->r.magic, "INDX", 4);
	irh->r.usa_off = sizeof(*irh) + sizeof(*inh);
	irh->r.usa_len = nhr.vol.idx_blk_sz / nhr.vol.sec_sz + 1;
	irh->lsn = lsn;
	irh->vcn = idxn->vcn;

	/* Index node header */
	inh->off = sizeof(*inh) + ntfs_usa_blen(&irh->r);
	inh->off = NTFS_ALIGN(inh->off);
	h = hints_find_hint_idxn(nhr_mfte_num(mfte), idx->info->type, idxn->vcn,
				 HINT_IDXN_RESERVE);
	if (h) {
		memcpy(&voff, h->data, sizeof(voff));
		inh->off += voff;
	}
	inh->alloc_sz = nhr.vol.idx_blk_sz - sizeof(*irh);
	inh->flags = 0x00;
	if (!(idxn->flags & NHR_IDXN_F_LEAF))
		inh->flags = NTFS_IDX_NODE_F_CHILD;

	/* Index entries stream */
	ieh = (void *)inh + inh->off;
	voff = (void *)ieh - buf;
	list_for_each_entry(idxe, &idx->entries, list) {
		if (idxe->container != idxn)
			continue;
		voff += sizeof(*ieh);
		assert(voff < nhr.vol.idx_blk_sz);
		ieh->size = sizeof(*ieh);
		ieh->flags = 0x00;

		if (idxe->key) {
			ieh->key_sz = idx_key_sz(idx, idxe->key);
			voff += ieh->key_sz;
			assert(voff < nhr.vol.idx_blk_sz);
			memcpy(ieh->key, idxe->key, ieh->key_sz);
			ieh->size += ieh->key_sz;
		} else {
			ieh->key_sz = 0;
			ieh->flags |= NTFS_IDX_ENTRY_F_LAST;
		}

		if (idxe->data) {
			if (!idx->info->data_sz) {
				memcpy(&ieh->val, idxe->data, sizeof(ieh->val));
			} else {
				ieh->data_off = ieh->size;
				ieh->data_sz = idx->info->data_sz;
				voff += ieh->data_sz;
				assert(voff < nhr.vol.idx_blk_sz);
				memcpy(ntfs_idx_entry_data(ieh), idxe->data,
				       ieh->data_sz);
				ieh->size += ieh->data_sz;
			}
		} else {
			ieh->val = 0;
		}

		ieh->size = NTFS_ALIGN(ieh->size);

		if (idxe->child != NHR_IDXN_PTR_UNKN &&
		    idxe->child != NHR_IDXN_PTR_NONE) {
			ieh->size += sizeof(uint64_t);
			voff += sizeof(uint64_t);
			assert(voff < nhr.vol.idx_blk_sz);
			ntfs_idx_entry_child_vcn(ieh) = idxe->child->vcn;
			ieh->flags |= NTFS_IDX_ENTRY_F_CHILD;
		}

		ieh = (void *)ieh + ieh->size;
		if (!idxe->key)
			break;
	}

	/* Set actual entries stream length */
	inh->len = (void *)ieh - (void *)inh;

	/* Reconstruct USA */
	usa = ntfs_usa_ptr(&irh->r);
	usa->usn = usn;
	for (i = 0; i < nhr.vol.idx_blk_sz/nhr.vol.sec_sz; ++i) {
		usa_ptr = buf + (i + 1) * nhr.vol.sec_sz - sizeof(uint16_t);
		usa->sec[i] = *usa_ptr;
		*usa_ptr = usa->usn;
	}
}

static int idx_recover_block(struct nhr_mft_entry *mfte,
			     struct nhr_idx *idx,
			     struct nhr_idx_node *idxn)
{
	const unsigned idx_blk_ssz = nhr.vol.idx_blk_sz / nhr.vol.sec_sz;
	const unsigned bb_map_mask = ~(~0 << idx_blk_ssz);
	uint8_t buf_rec[nhr.vol.idx_blk_sz];
	uint8_t buf_img[nhr.vol.idx_blk_sz];
	const struct ntfs_idx_rec_hdr *irh = (void *)buf_img;
	uint64_t lsn;
	uint16_t usn;
	int i;

	if (nhr.verbose >= 3)
		printf("idx[#%"PRIu64",%ls,#%"PRIu64"]: start block recovery (bb_map = 0x%02X)\n",
		       nhr_mfte_num(mfte), cache_idx_name(idx), idxn->vcn,
		       idxn->bb_map);

	img_read_clusters(idxn->lcn, buf_img, nhr.vol.idx_blk_csz);

	/* Attempt to fetch some non-critical data */
	if ((idxn->bb_map & bb_map_mask) == bb_map_mask) {
		lsn = 1;		/* Could we guess it? */
		usn = 0xCDAB;		/* Could not recover */
	} else if (idxn->bb_map & 1) {
		lsn = 1;		/* Could we guess it? */
		usn = 0xCDAB;		/* Make compiller happy */
		for (i = 1; i < idx_blk_ssz; ++i) {
			if (idxn->bb_map & (1 << i))
				continue;
			usn = *(uint16_t *)(buf_img + (i + 1) * nhr.vol.sec_sz - sizeof(uint16_t));
			break;
		}
	} else {
		lsn = irh->lsn;
		usn = *(uint16_t *)(buf_img + irh->r.usa_off);
	}

	/* Rebuild index block */
	memset(buf_rec, 0x00, sizeof(buf_rec));
	idx_recover_build_block(mfte, idx, idxn, lsn, usn, buf_rec);

	/* Verify rebuilded block against valid on disk data */
	if (idx_idxb_cmp(idx->info, buf_img, buf_rec, idxn->bb_map)) {
		if (nhr.verbose >= 2) {
			printf("idx[#%"PRIu64",%ls,#%"PRIu64"]: compare with on disk data failed\n",
			       nhr_mfte_num(mfte), cache_idx_name(idx), idxn->vcn);
			printf("idx[#%"PRIu64",%ls,#%"PRIu64"]: on disk data hexdump:\n",
			       nhr_mfte_num(mfte), cache_idx_name(idx), idxn->vcn);
			hexdump(buf_img, sizeof(buf_img));
			printf("idx[#%"PRIu64",%ls,#%"PRIu64"]: recovery buffer data:\n",
			       nhr_mfte_num(mfte), cache_idx_name(idx), idxn->vcn);
			hexdump(buf_rec, sizeof(buf_rec));
		}
		return -1;
	}

	idx_recover_create_overlay(mfte, idxn, buf_rec);

	return 0;
}

static int idx_recover_blocks_idx(struct nhr_mft_entry *mfte,
				  struct nhr_idx *idx,
				  unsigned *cnt_blk_tot, unsigned *cnt_blk_ok)
{
	struct nhr_idx_node *idxn;
	int res = 0;

	list_for_each_entry(idxn, &idx->nodes, list) {
		if (idxn->bb_map == 0)
			continue;
		if (!res)
			res = 1;
		assert(idxn->bb_rec == 0);
		*cnt_blk_tot += 1;
		if (idx_recover_block(mfte, idx, idxn) != 0)
			res = -1;
		else
			*cnt_blk_ok += 1;
	}

	return res;
}

void idx_recover_blocks(void)
{
	struct nhr_mft_entry *mfte;
	struct nhr_idx *idx;
	int i, res;
	unsigned cnt_blk_tot = 0, cnt_blk_ok = 0;
	unsigned cnt_idx_tot = 0, cnt_idx_ok = 0;

	if (nhr.verbose >= 1)
		printf("idx: recover broken index blocks\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!mfte->idx_num)
			continue;
		if (!(mfte->f_sum & NHR_MFT_FB_AIDX))
			continue;
		for (i = 0; i < mfte->idx_num; ++i) {
			idx = mfte->idx[i];
			if (!(idx->flags & NHR_IDX_F_VALID))
				continue;
			res = idx_recover_blocks_idx(mfte, idx, &cnt_blk_tot,
						     &cnt_blk_ok);
			if (res != 0)
				cnt_idx_tot++;
			if (res > 0)
				cnt_idx_ok++;
		}
	}

	if (nhr.verbose >= 1)
		printf("idx: recovered %u of %u blocks (%u of %u indexes)\n",
		       cnt_blk_ok, cnt_blk_tot, cnt_idx_ok, cnt_idx_tot);
}
