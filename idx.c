/**
 * Generic index functions
 *
 * Copyright (c) 2016, Sergey Ryazanov <ryazanov.s.a@gmail.com>
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
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "cache.h"
#include "idx_aux.h"
#include "idx_i30.h"
#include "idx_secure.h"
#include "idx.h"

static const struct nhr_idx_info idx_infos[] = {
	[NHR_IDX_T_DIR] = {
		.type = NHR_IDX_T_DIR,
		.name = {'$', 0, 'I', 0, '3', 0, '0', 0},
		.name_len = 4,
		.desc = "directory entries",
		.attr = NTFS_ATTR_FNAME,
		.sort = NTFS_IDX_SORT_FILENAME,
		.key_sz_min = sizeof(struct ntfs_attr_fname) + 2 * 1,
		.key_sz_max = sizeof(struct ntfs_attr_fname) + 2 * 255,
		.key_cmp = idx_i30_key_cmp,
		.key_sz = idx_i30_key_sz,
		.key_match = idx_i30_key_match,
		.entry_name = idx_i30_entry_name,
		.blk_mfte_detect = idx_i30_blk_mfte_detect,
		.entry_validate = idx_i30_entry_validate,
		.cache_idxe_find = idx_i30_cache_idxe_find,
	},
	[NHR_IDX_T_SDH] = {
		.type = NHR_IDX_T_SDH,
		.name = {'$', 0, 'S', 0, 'D', 0, 'H', 0},
		.name_len = 4,
		.desc = "security descriptors hash",
		.sort = NTFS_IDX_SORT_SDH,
		.key_sz_min = sizeof(struct ntfs_idx_sdh_key),
		.key_sz_max = sizeof(struct ntfs_idx_sdh_key),
		.key_cmp = idx_sdh_key_cmp,
		.data_sz = sizeof(struct ntfs_sec_desc_hdr),
		.entry_name = idx_sdh_entry_name,
		.blk_mfte_detect = idx_sec_blk_mfte_detect,
		.entry_validate = idx_sdh_entry_validate,
		.cache_idxe_find = idx_sdh_cache_idxe_find,
	},
	[NHR_IDX_T_SII] = {
		.type = NHR_IDX_T_SII,
		.name = {'$', 0, 'S', 0, 'I', 0, 'I', 0},
		.name_len = 4,
		.desc = "security descriptors id",
		.sort = NTFS_IDX_SORT_ULONG,
		.key_sz_min = sizeof(struct ntfs_idx_sii_key),
		.key_sz_max = sizeof(struct ntfs_idx_sii_key),
		.key_cmp = idx_sii_key_cmp,
		.data_sz = sizeof(struct ntfs_sec_desc_hdr),
		.entry_name = idx_sii_entry_name,
		.blk_mfte_detect = idx_sec_blk_mfte_detect,
		.entry_validate = idx_sii_entry_validate,
		.cache_idxe_find = idx_sii_cache_idxe_find,
	},
};

static const int idx_infos_len = sizeof(idx_infos)/sizeof(idx_infos[0]);

const struct nhr_idx_info *idx_info_get(int type)
{
	if (type >= idx_infos_len || !idx_infos[type].name_len)
		return NULL;

	return &idx_infos[type];
}

int idx_info_foreach_cb(int (*cb)(const struct nhr_idx_info *, void *),
			void *priv)
{
	int res, i;

	for (i = 0; i < idx_infos_len; ++i) {
		if (!idx_infos[i].name_len)
			continue;
		res = cb(&idx_infos[i], priv);
		if (res)
			return res;
	}

	return 0;
}

int idx_detect_type(unsigned name_len, const uint8_t *name)
{
	int i;

	if (!name_len)
		return NHR_IDX_T_UNKN;

	for (i = 0; i < idx_infos_len; ++i) {
		if (idx_infos[i].name_len != name_len)
			continue;
		if (memcmp(idx_infos[i].name, name, name_len * 2) == 0)
			return idx_infos[i].type;
	}

	return NHR_IDX_T_UNKN;
}

static int idx_verify(const struct nhr_mft_entry *mfte,
		      struct nhr_idx *idx)
{
	const struct nhr_idx_node *idxn;
	const struct nhr_idx_entry *idxe;
	uint64_t idxn_vcn = NHR_IDXN_VCN_ROOT;
	int have_last, have_parent;
	unsigned voff;

	/* Verify index nodes stream integrity */
	list_for_each_entry(idxn, &idx->nodes, list) {
		if (idxn_vcn != idxn->vcn) {
			if (nhr.verbose >= 3)
				printf("idx[#%"PRIu64",%ls]: index nodes from #%"PRIu64" to #%"PRIu64" are missed\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       idxn_vcn, idxn->vcn - 1);
			return -1;
		}
		idxn_vcn++;

		if (!idxn->lcn && idxn->vcn != NHR_IDXN_VCN_ROOT) {
			if (nhr.verbose >= 3)
				printf("idxn[#%"PRIu64",%ls,#%"PRIu64"]: disk cluster is unknown\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       idxn->vcn);
			return -1;
		}

		if (!(idxn->flags & (NHR_IDXN_F_FREE | NHR_IDXN_F_INUSE))) {
			if (nhr.verbose >= 3)
				printf("idxn[#%"PRIu64",%ls,%s]: used/free state is unknown\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(idxn));
			return -1;
		}

		if (idxn->flags & NHR_IDXN_F_FREE) {
			if (idxn->parent != NHR_IDXN_PTR_UNKN) {
				if (nhr.verbose >= 3)
					printf("idxn[#%"PRIu64",%ls,%s]: free node treats %s as parent\n",
					       nhr_mfte_num(mfte),
					       cache_idx_name(idx),
					       cache_idxn_name(idxn),
					       cache_idxn_name(idxn->parent));
				return -1;
			}
		} else {
			if (!(idxn->flags & (NHR_IDXN_F_LEAF | NHR_IDXN_F_NODE))) {
				if (nhr.verbose >= 3)
					printf("idxn[#%"PRIu64",%ls,%s]: leaf/node state is unknown\n",
					       nhr_mfte_num(mfte),
					       cache_idx_name(idx),
					       cache_idxn_name(idxn));
				return -1;
			}
			if (idxn->lvl == NHR_IDXN_LVL_UNKN) {
				if (nhr.verbose >= 3)
					printf("idxn[#%"PRIu64",%ls,%s]: level is unknown\n",
					       nhr_mfte_num(mfte),
					       cache_idx_name(idx),
					       cache_idxn_name(idxn));
				return -1;
			}
			if (idxn->parent == NHR_IDXN_PTR_UNKN) {
				if (nhr.verbose >= 3)
					printf("idxn[#%"PRIu64",%ls,%s]: orphaned node\n",
					       nhr_mfte_num(mfte),
					       cache_idx_name(idx),
					       cache_idxn_name(idxn));
				return -1;
			}
		}
	}

	/* Verify index entries */
	list_for_each_entry(idxe, &idx->entries, list) {
		if (idxe->container == NHR_IDXN_PTR_NONE) {
			if (idxe == list_last_entry(&idx->entries, typeof(*idxe), list))
				continue;
			if (nhr.verbose >= 3)
				printf("idx[#%"PRIu64",%ls]: wrong stream end marker position\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx));
			return -1;
		}
		if (idxe->container == NHR_IDXN_PTR_UNKN) {
			if (nhr.verbose >= 3)
				printf("idx[#%"PRIu64",%ls]: orphaned index entry: %ls\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxe_name(idx, idxe));
			return -1;
		}
		if (idxe->child == NHR_IDXN_PTR_UNKN) {
			if (nhr.verbose >= 3)
				printf("idxn[#%"PRIu64",%ls,%s]: child unknown for entry: %ls\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(idxe->container),
				       cache_idxe_name(idx, idxe));
			return -1;
		}
		if (idxe->child == idx->root) {
			if (nhr.verbose >= 3)
				printf("idxn[#%"PRIu64",%ls,%s]: link to root node from entry: %ls\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(idxe->container),
				       cache_idxe_name(idx, idxe));
			return -1;
		}
		if (idxe->child != NHR_IDXN_PTR_NONE) {
			if (idxe->container->flags & NHR_IDXN_F_LEAF) {
				if (nhr.verbose >= 3)
					printf("idxn[#%"PRIu64",%ls,%s]: link from leaf to child node %s via entry %ls\n",
					       nhr_mfte_num(mfte), cache_idx_name(idx),
					       cache_idxn_name(idxe->container),
					       cache_idxn_name(idxe->child),
					       cache_idxe_name(idx, idxe));
				return -1;
			}
			if (idxe->child->parent != idxe->container) {
				if (nhr.verbose >= 3)
					printf("idxn[#%"PRIu64",%ls,%s]: inconsistent nodes interlinking (child: %s, child's parent: %s) via entry %ls\n",
					       nhr_mfte_num(mfte), cache_idx_name(idx),
					       cache_idxn_name(idxe->container),
					       cache_idxn_name(idxe->child),
					       cache_idxn_name(idxe->child->parent),
					       cache_idxe_name(idx, idxe));
				return -1;
			}
		}
	}

	/* Do detailed analysis of nodes <-> entries linking */
	list_for_each_entry(idxn, &idx->nodes, list) {
		if (idxn->flags & NHR_IDXN_F_FREE)
			continue;
		have_last = 0;
		have_parent = 0;
		voff = 0;
		list_for_each_entry(idxe, &idx->entries, list) {
			if (idxe->container == idxn && have_last) {
				if (nhr.verbose >= 3)
					printf("idxn[#%"PRIu64",%ls,%s]: entry %ls located after node end marker\n",
					       nhr_mfte_num(mfte),
					       cache_idx_name(idx),
					       cache_idxn_name(idxn),
					       cache_idxe_name(idx, idxe));
				return -1;
			}
			if (idxe->container == idxn && !idxe->key)
				have_last = 1;
			if (idxe->container == idxn && idxe->voff != voff) {
				if (nhr.verbose >= 3)
					printf("idxn[#%"PRIu64",%ls,%s]: entry %ls has invalid offset (got %u, expect %u)\n",
					       nhr_mfte_num(mfte),
					       cache_idx_name(idx),
					       cache_idxn_name(idxn),
					       cache_idxe_name(idx, idxe),
					       idxe->voff, voff);
				return -1;
			}
			if (idxe->container == idxn && idxe->voff == voff) {
				voff += idx_entry_len(idx, idxe);
			}
			if (idxe->child == idxn && have_parent) {
				if (nhr.verbose >= 3)
					printf("idx[#%"PRIu64",%ls]: multiple links to node %s\n",
					       nhr_mfte_num(mfte),
					       cache_idx_name(idx),
					       cache_idxn_name(idxn));
				return -1;
			}
			if (idxe->child == idxn && !have_parent)
				have_parent = 1;
		}
		if (!have_parent && idxn->vcn != NHR_IDXN_VCN_ROOT) {
			if (nhr.verbose >= 3)
				printf("idxn[#%"PRIu64",%ls,%s]: have no incoming links from %s\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(idxn),
				       cache_idxn_name(idxn->parent));
			return -1;
		}
		if (!have_last) {
			if (nhr.verbose >= 3)
				printf("idxn[#%"PRIu64",%ls,%s]: does not have end marker\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(idxn));
			return -1;
		}
		if ((idxn->vcn != NHR_IDXN_VCN_ROOT &&
		     voff > nhr.vol.idx_blk_sz) ||
		    (idxn->vcn == NHR_IDXN_VCN_ROOT &&
		     voff > nhr.vol.mft_ent_sz * 2 / 3)) {
			if (nhr.verbose >= 3)
				printf("idxn[#%"PRIu64",%ls,%s]: too big (%u bytes)\n",
				       nhr_mfte_num(mfte), cache_idx_name(idx),
				       cache_idxn_name(idxn), voff);
			return -1;
		}
	}

	return 0;
}

void idx_verify_all(void)
{
	struct nhr_mft_entry *mfte;
	unsigned i;
	unsigned ent_tot = 0, ent_ok = 0;
	unsigned idx_tot = 0, idx_ok = 0;
	int idx_res, ent_res;

	if (nhr.verbose >= 1)
		printf("idx: verify indexes\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!mfte->idx_num)
			continue;

		ent_tot++;

		ent_res = 0;
		for (i = 0; i < mfte->idx_num; ++i) {
			idx_tot++;
			idx_res = idx_verify(mfte, mfte->idx[i]);
			if (idx_res) {
				ent_res = -1;
			} else {
				idx_ok++;
				mfte->idx[i]->flags |= NHR_IDX_F_VALID;
			}
		}
		if (!ent_res)
			ent_ok++;
	}

	if (nhr.verbose >= 1)
		printf("idx: checked %u MFT entries (%u indexes), %u MFT entries (%u indexes) valid\n",
		       ent_tot, idx_tot, ent_ok, idx_ok);
}
