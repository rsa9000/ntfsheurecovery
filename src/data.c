/**
 * $DATA streams functions
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
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "img.h"
#include "ntfs.h"
#include "cache.h"
#include "cmap.h"
#include "bb.h"
#include "hints.h"
#include "misc.h"
#include "data.h"

static int data_verify_stream(const struct nhr_mft_entry *mfte,
			      const struct nhr_data *data)
{
	struct nhr_str_segm *curr, *prev;
	uint64_t lclen, vclen, vcn;
	int has_unmapped;
	uint8_t digest[16];

	if (!NHR_FIELD_VALID(&data->sz_init))
		return -1;

	if (!data->mpl)
		return -1;

	if (data->sz_init.val > data->sz_used.val) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: initialized stream size greater than used stream size\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}

	has_unmapped = ntfs_mpl_has_unmapped(data->mpl);
	if (has_unmapped && !(data->flags & NHR_DATA_F_COMP)) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: stream has unmapped clusters but not marked as compressed\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}

	if (ntfs_mpl_has_gap(data->mpl)) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: stream has gaps\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}

	lclen = ntfs_mpl_lclen(data->mpl);
	if (lclen * nhr.vol.cls_sz != data->sz_alloc.val) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: not all disk clusters are known\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}

	vclen = ntfs_mpl_vclen(data->mpl);
	if ((data->flags & NHR_DATA_F_COMP) &&
	    (vclen * nhr.vol.cls_sz) % nhr.vol.com_blk_sz) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: compressed stream length not aligned\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}

	if (list_empty(&data->segments)) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: stream segmentation info missed\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}

	prev = NULL;
	vcn = 0;
	list_for_each_entry(curr, &data->segments, list) {
		assert(curr->firstvcn.src != NHR_SRC_NONE);
		if (curr->lastvcn.src == NHR_SRC_NONE) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: segment [0x%"PRIX64":0x????????] end is unknown\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       curr->firstvcn.val);
			return -1;
		}
		if (curr->firstvcn.val < vcn) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: segments [0x%08"PRIX64":0x%08"PRIX64"] and [0x%08"PRIX64":0x%08"PRIX64"] overlaps\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       prev->firstvcn.val, prev->lastvcn.val,
				       curr->firstvcn.val, curr->lastvcn.val);
			return -1;
		}
		if (curr->firstvcn.val > vcn && !prev) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: no segment from begining to 0x%08"PRIX64"\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       curr->firstvcn.val);
			return -1;
		}
		if (curr->firstvcn.val > vcn && prev) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: no segments between [0x%08"PRIX64":0x%08"PRIX64"] and [0x%08"PRIX64":0x%08"PRIX64"]\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       prev->firstvcn.val, prev->lastvcn.val,
				       curr->firstvcn.val, curr->lastvcn.val);
			return -1;
		}
		if (curr->lastvcn.val >= vclen) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: segment [0x%08"PRIX64":0x%08"PRIX64"] overrides allocated space (0x%08"PRIX64" cluster)\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       curr->firstvcn.val, curr->lastvcn.val,
				       vclen);
			return -1;
		}
		prev = curr;
		vcn = curr->lastvcn.val + 1;
	}
	if (prev->lastvcn.val + 1 != vclen) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: no segment from [0x%08"PRIX64":0x%08"PRIX64"] to the end of stream at 0x%08"PRIX64"\n",
			       nhr_mfte_num(mfte), cache_data_name(data),
			       prev->firstvcn.val, prev->lastvcn.val, vclen);
		return -1;
	}

	if (data->digest) {
		img_make_digest(data->mpl, data->sz_used.val, digest);
		if (memcmp(digest, data->digest, sizeof(digest)) != 0) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: proposed data digest mismatch (got %s)\n",
				       nhr_mfte_num(mfte), cache_data_name(data),
				       digest2str(digest));
			return -1;
		}
	}

	return 0;
}

static int data_verify_resident(const struct nhr_mft_entry *mfte,
				const struct nhr_data *data)
{
	const struct nhr_data_chunk *curr, *prev;
	uint32_t voff;
	int res = 0;

	if (list_empty(&data->chunks)) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: resident data completely missed\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}

	prev = NULL;
	voff = 0;
	list_for_each_entry(curr, &data->chunks, list) {
		if (curr->voff < voff) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: chunks [0x%04X:0x%04X] and [0x%04X:0x%04X] overlaps\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       prev->voff, prev->voff + prev->len - 1,
				       curr->voff, curr->voff + curr->len - 1);
			res = -1;
		}
		if (curr->voff > voff && !prev) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: resident data from begining to [0x%04X:0x%04X] is missed\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       curr->voff, curr->voff + curr->len - 1);
			res = -1;
		}
		if (curr->voff > voff && prev) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: resident data between [0x%04X:0x%04X] and [0x%04X:0x%04X] is missed\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       prev->voff, prev->voff + prev->len - 1,
				       curr->voff, curr->voff + curr->len - 1);
			res = -1;
		}
		if (curr->voff + curr->len > data->sz_used.val) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: chunk [0x%04X:0x%04X] overrides data size (%"PRIu64" bytes)\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       curr->voff, curr->voff + curr->len - 1,
				       data->sz_used.val);
			res = -1;
		}
		prev = curr;
		voff += curr->voff + curr->len;
	}

	if (prev->voff + prev->len < data->sz_used.val) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: resident data from [0x%04X:0x%04X] to end of stream at 0x%04"PRIX64" is missed\n",
			       nhr_mfte_num(mfte), cache_data_name(data),
			       prev->voff, prev->voff + prev->len - 1,
			       data->sz_used.val);
		res = -1;
	}

	return res;
}

static int data_verify(const struct nhr_mft_entry *mfte,
		       const struct nhr_data *data)
{
	if (!NHR_FIELD_VALID(&data->sz_alloc))
		return -1;
	if (!NHR_FIELD_VALID(&data->sz_used))
		return -1;

	if (data->sz_alloc.val == 0)
		return 0;	/* Nothing more to check */

	if (data->sz_alloc.val >= nhr.vol.cls_sz)
		return data_verify_stream(mfte, data);
	else
		return data_verify_resident(mfte, data);
}

void data_verify_all(void)
{
	struct nhr_mft_entry *mfte;
	unsigned i;
	unsigned ent_tot = 0, ent_ok = 0;
	unsigned str_tot = 0, str_ok = 0;
	int str_res, ent_res;

	if (nhr.verbose >= 1)
		printf("data: verify streams\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(mfte->f_cmn & NHR_MFT_FC_BASE))
			continue;
		if (!mfte->data_num)
			continue;

		ent_tot++;

		ent_res = 0;
		for (i = 0; i < mfte->data_num; ++i) {
			str_tot++;
			str_res = data_verify(mfte, mfte->data[i]);
			if (str_res) {
				ent_res = -1;
			} else {
				mfte->data[i]->flags |= NHR_DATA_F_VALID;
				str_ok++;
			}
		}
		if (!ent_res)
			ent_ok++;
	}

	if (nhr.verbose >= 1)
		printf("data: checked %u entries (%u streams), %u entries (%u streams) is valid\n",
		       ent_tot, str_tot, ent_ok, str_ok);
}

/**
 * Apply data clusters hints
 */
static int data_apply_hints_mpl(struct nhr_mft_entry *mfte,
				struct nhr_data *data, struct hint *h)
{
	struct ntfs_mp *hint_mpl = (void *)h->data, *res_mpl, *mp;
	struct nhr_str_segm *segm;
	uint64_t vclen, cls_off, cls_blk_end;
	struct nhr_cb *cb;
	struct nhr_bb *bb;

	/* Check proposed clustes */
	for (mp = hint_mpl; mp->clen; ++mp) {
		if (mp->lcn == NTFS_LCN_NONE)	/* Ignore holes */
			continue;
		cb = cmap_find(mp->lcn);
		if (!cb) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: proposed data clusters [0x%08"PRIX64":0x%08"PRIX64"] are not exists\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       mp->lcn, mp->lcn + mp->clen - 1);
			return -1;
		}
		if (cb->flags || mp->lcn + mp->clen > nhr_cb_end(cb)) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: proposed data clusters [0x%08"PRIX64":0x%08"PRIX64"] are not orphaned\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       mp->lcn, mp->lcn + mp->clen - 1);
			return -1;
		}
	}

	/* Copy clusters info into the cached MFT entry */
	res_mpl = ntfs_mpl_merge(data->mpl, hint_mpl);
	if (!res_mpl) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: mapping pairs from hints could not be merged\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}
	data->mpl = res_mpl;

	/* Update segmentation info */
	segm = cache_data_segm_find(data, hint_mpl->vcn);
	if (!segm)
		segm = cache_data_segm_alloc(data, hint_mpl->vcn);
	vclen = ntfs_mpl_vclen(hint_mpl);
	NHR_FIELD_UPDATE(&segm->firstvcn, hint_mpl->vcn, NHR_SRC_HINT);
	NHR_FIELD_UPDATE(&segm->lastvcn, hint_mpl->vcn + vclen - 1,
			 NHR_SRC_HINT);

	/* Mark all clusters as busy and detects bad blocks */
	for (mp = hint_mpl; mp->clen; ++mp) {
		cmap_block_mark(mp->lcn, mp->clen, NHR_CB_F_ALLOC);
		cls_off = mp->lcn * nhr.vol.cls_sz;
		cls_blk_end = (mp->lcn + mp->clen) * nhr.vol.cls_sz;
		for (; cls_off < cls_blk_end; cls_off += nhr.vol.sec_sz) {
			bb = bb_find(cls_off);
			if (!bb)
				continue;

			bb->attr_type = NTFS_ATTR_DATA;
			bb->voff = mp->vcn * nhr.vol.cls_sz + cls_off - mp->lcn * nhr.vol.cls_sz;
			bb->entity = data;
			cache_mfte_bb_add(mfte, bb);
		}
	}

	return 0;
}

static int data_apply_hints_raw_resident(struct nhr_mft_entry *mfte,
					 struct nhr_data *data, struct hint *h)
{
	const struct hint_args_data_raw *ha = h->args;
	struct nhr_data_chunk *chunk, *new;

	new = malloc(sizeof(*chunk) + ha->len);
	new->voff = ha->voff;
	new->len = ha->len;
	new->src = NHR_SRC_HINT;
	memcpy(new->buf, h->data, new->len);

	/* Keep ordered by virtual offset */
	list_for_each_entry(chunk, &data->chunks, list) {
		if (new->voff > chunk->voff)
			continue;
		list_add_tail(&new->list, &chunk->list);	/* Add before */
		return 0;
	}

	list_add_tail(&new->list, &data->chunks);

	return 0;
}

static int data_apply_hints_raw_nonresident(struct nhr_mft_entry *mfte,
					    struct nhr_data *data,
					    struct hint *h)
{
	const struct hint_args_data_raw *ha = h->args;
	uint64_t voff, off;
	struct nhr_bb *bb;
	unsigned buf_off, buf_len;
	struct nhr_ob *ob;

	if (!data->mpl) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: could not apply raw data hint since stream clusters is not known\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}
	if (ha->voff % nhr.vol.sec_sz) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: raw hint block [0x%08"PRIX64":0x%08"PRIX64"] start is not aligned onto 0x%04X boundry\n",
			       nhr_mfte_num(mfte), cache_data_name(data),
			       ha->voff, ha->voff + ha->len - 1,
			       nhr.vol.sec_sz);
		return -1;
	}
	if ((ha->voff + ha->len) % nhr.vol.sec_sz &&
	    (data->sz_used.src == NHR_SRC_NONE ||
	     ha->voff + ha->len != data->sz_used.val)) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: raw hint block [0x%08"PRIX64":0x%08"PRIX64"] end is not aligned onto 0x%04X boundry\n",
			       nhr_mfte_num(mfte), cache_data_name(data),
			       ha->voff, ha->voff + ha->len - 1,
			       nhr.vol.sec_sz);
		return -1;
	}

	for (voff = ha->voff, buf_off = 0;
	     buf_off < ha->len;
	     voff += nhr.vol.sec_sz, buf_off += nhr.vol.sec_sz) {
		off = ntfs_mpl_voff2off(data->mpl, nhr.vol.cls_sz, voff);
		if (off == ~0LLU) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: could not get offset of 0x%08"PRIX64" address for [0x%08"PRIX64":0x%08"PRIX64"] raw data hint\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       voff, ha->voff, ha->voff + ha->len - 1);
			return -1;
		}
		bb = bb_find(off);
		if (!bb) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: could not find BB at 0x%08"PRIX64" (voff: 0x%08"PRIX64") for [0x%08"PRIX64":0x%08"PRIX64"] raw data hint\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       off, voff, ha->voff,
				       ha->voff + ha->len - 1);
			continue;
		}
		if (bb->flags & ~NHR_BB_F_AUTO) {
			if (nhr.verbose >= 3)
				printf("data[#%"PRIu64",%ls]: BB at 0x%08"PRIX64" (voff: 0x%08"PRIX64", flags: 0x%04X) does not require recovery, claimed by [0x%08"PRIX64":0x%08"PRIX64"] raw data hint\n",
				       nhr_mfte_num(mfte),
				       cache_data_name(data),
				       off, voff, bb->flags,
				       ha->voff, ha->voff + ha->len - 1);
			continue;
		}
		buf_len = ha->len - buf_off < nhr.vol.sec_sz ?
		          ha->len - buf_off : nhr.vol.sec_sz;
		ob = img_overlay_alloc(nhr.vol.sec_sz);
		nhr_ob_off(ob) = nhr_bb_off(bb);
		memcpy(ob->buf, h->data + buf_off, buf_len);
		if (buf_len != nhr.vol.sec_sz)
			memset(ob->buf + buf_len, 0x00, nhr.vol.sec_sz - buf_len);
		img_overlay_add(ob);

		bb->flags |= NHR_BB_F_REC;
		cache_mfte_bb_ok(bb);
	}

	return 0;
}

static int data_apply_hints_raw(struct nhr_mft_entry *mfte,
				struct nhr_data *data, struct hint *h)
{
	struct hint_args_data_raw *ha = h->args;

	if (data->sz_alloc.src == NHR_SRC_NONE) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: could not apply RAW data hints, since allocation size is unknown\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	} else if (ha->voff + ha->len > data->sz_alloc.val) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: raw hint block [0x%08"PRIX64":0x%08"PRIX64"] is greater than stream size (0x%08"PRIX64" bytes)\n",
			       nhr_mfte_num(mfte), cache_data_name(data),
			       ha->voff, ha->voff + ha->len - 1,
			       data->sz_alloc.val);
		return -1;
	}

	if (data->sz_alloc.val < nhr.vol.cls_sz)
		return data_apply_hints_raw_resident(mfte, data, h);
	else
		return data_apply_hints_raw_nonresident(mfte, data, h);
}

static int data_apply_hints_bbign(struct nhr_mft_entry *mfte,
				  struct nhr_data *data)
{
	struct nhr_bb *bb;

	if (data->sz_alloc.src == NHR_SRC_NONE) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: could not apply ignore BB hint, since allocation size is unknown\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	} else if (data->sz_alloc.val < nhr.vol.sec_sz) {
		if (nhr.verbose >= 3)
			printf("data[#%"PRIu64",%ls]: could not apply ignore BB hint to resident data stream\n",
			       nhr_mfte_num(mfte), cache_data_name(data));
		return -1;
	}

	for (bb = cache_mfte_bb_find(mfte, NTFS_ATTR_DATA, data); bb != NULL;
	     bb = cache_mfte_bb_next(bb)) {
		if (bb->flags & ~NHR_BB_F_AUTO)
			continue;
		bb->flags |= NHR_BB_F_IGNORE | NHR_BB_F_FORCE;
		cache_mfte_bb_ok(bb);
	}

	return 0;
}

static void data_apply_hints_mfte(struct nhr_mft_entry *mfte,
				  struct hint_entry *he,
				  unsigned *cnt_tot, unsigned *cnt_cls)
{
	struct hint *h;
	struct hint_cargs_data *hca;
	struct nhr_data *data = NULL;
	uint64_t val64;

	list_for_each_entry(h, &he->hints, list) {
		if (h->class < HINT_DATA)
			continue;
		if (h->class > HINT_DATA)
			break;

		hca = h->cargs;
		if (!data || data->name_len != hca->name_len ||
		    memcmp(data->name, hca->name, data->name_len)) {
			data = cache_data_find(mfte, hca->name_len, hca->name);
			if (!data)
				data = cache_data_alloc(mfte, hca->name_len,
							hca->name);
		}

		switch (h->type) {
		case HINT_DATA_SZ_ALLOC:
			memcpy(&val64, h->data, sizeof(val64));
			NHR_FIELD_UPDATE(&data->sz_alloc, val64, NHR_SRC_HINT);
			break;
		case HINT_DATA_SZ_USED:
			memcpy(&val64, h->data, sizeof(val64));
			NHR_FIELD_UPDATE(&data->sz_used, val64, NHR_SRC_HINT);
			break;
		case HINT_DATA_SZ_INIT:
			memcpy(&val64, h->data, sizeof(val64));
			NHR_FIELD_UPDATE(&data->sz_init, val64, NHR_SRC_HINT);
			break;
		case HINT_DATA_DIGEST:
			if (!data->digest) {
				data->digest = malloc(16);
				memcpy(data->digest, h->data, 16);
			}
			break;
		case HINT_DATA_CLS:
			(*cnt_tot)++;

			if (data_apply_hints_mpl(mfte, data, h) == 0)
				(*cnt_cls)++;
			break;
		case HINT_DATA_RAW:
			/**
			 * NB: since hints list ordered by hint type we process
			 * RAW data hints last and we could be shure that size
			 * and mapping pairs related hints already applied.
			 */
			data_apply_hints_raw(mfte, data, h);
			break;
		case HINT_DATA_BBIGN:
			data_apply_hints_bbign(mfte, data);
			break;
		}
	}
}

/**
 * Apply data streams related hints
 */
void data_apply_hints(void)
{
	struct hint_entry *he;
	struct nhr_mft_entry *mfte;
	unsigned cnt_tot = 0, cnt_cls = 0;

	if (nhr.verbose >= 1)
		printf("data: apply hints\n");

	rbt_inorder_walk_entry(he, &nhr.hints, tree) {
		if (!hints_have_class(he, HINT_DATA))
			continue;
		mfte = cache_mfte_find(hint_entry_num(he));
		if (!mfte)
			continue;

		if (!(nhr_mfte_bflags(mfte) & NHR_MFT_FB_SELF) &&
		    !(mfte->f_sum & NHR_MFT_FB_ADATA))
			continue;

		data_apply_hints_mfte(mfte, he, &cnt_tot, &cnt_cls);
	}

	if (nhr.verbose >= 1)
		printf("data: processed %u MFT entries, clusters stream recovered for %u of them\n",
		       cnt_tot, cnt_cls);
}

/**
 * Attempt to recover data streams integrity
 *
 * Now this function only set compressed flags for streams, which include
 * unmapped clusters and if initialized size is missed then set it to the same
 * value as used size.
 */
void data_recover(void)
{
	struct nhr_mft_entry *mfte;
	struct nhr_data *data;
	unsigned i;
	unsigned cnt_tot = 0, cnt_flags = 0, cnt_size = 0;

	if (nhr.verbose >= 1)
		printf("data: recover streams\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(mfte->f_cmn & NHR_MFT_FC_BASE))
			continue;
		for (i = 0; i < mfte->data_num; ++i) {
			cnt_tot++;
			data = mfte->data[i];
			if (NHR_FIELD_VALID(&data->sz_alloc) &&
			    data->sz_alloc.val >= nhr.vol.cls_sz &&
			    NHR_FIELD_VALID(&data->sz_used) &&
			    !NHR_FIELD_VALID(&data->sz_init)) {
				NHR_FIELD_UPDATE(&data->sz_init,
						 data->sz_used.val,
						 NHR_SRC_HEUR);
				cnt_size++;
			}
			if (NHR_FIELD_VALID(&mfte->fileflags) &&
			    mfte->fileflags.val & NTFS_FILE_F_COMP &&
			    !(data->flags & NHR_DATA_F_COMP) && data->mpl &&
			    ntfs_mpl_has_unmapped(data->mpl)) {
				data->flags |= NHR_DATA_F_COMP;
				cnt_flags++;
			}
		}
	}

	if (nhr.verbose >= 1)
		printf("data: processed %u streams (recover flags for %u of them, size for %u of them)\n",
		       cnt_tot, cnt_flags, cnt_size);
}

/** Detect BB in unused regions and ignore */
void data_bb_ignore(void)
{
	struct nhr_mft_entry *mfte;
	struct nhr_data *data;
	struct nhr_bb *bb;
	unsigned i;
	unsigned cnt_tot = 0, cnt_ign = 0;

	if (nhr.verbose >= 1)
		printf("data: detect ignorable BB\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(mfte->f_cmn & NHR_MFT_FC_BASE))
			continue;
		if (!(mfte->f_sum & NHR_MFT_FB_ADATA))
			continue;
		for (i = 0; i < mfte->data_num; ++i) {
			data = mfte->data[i];
			if (data->flags & NHR_DATA_F_COMP ||
			    !NHR_FIELD_VALID(&data->sz_init))
				continue;
			cnt_tot++;

			bb = cache_mfte_bb_find(mfte, NTFS_ATTR_DATA, data);
			for (; bb; bb = cache_mfte_bb_next(bb)) {
				if (bb->voff < data->sz_init.val)
					continue;
				cnt_ign++;
				bb->flags |= NHR_BB_F_IGNORE;
				cache_mfte_bb_ok(bb);
			}
		}
	}

	if (nhr.verbose >= 1)
		printf("data: processed %u streams (%u BB could be ignored)\n",
		       cnt_tot, cnt_ign);
}
