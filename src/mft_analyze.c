/**
 * MFT analysis functions
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "img.h"
#include "bb.h"
#include "idx.h"
#include "cmap.h"
#include "misc.h"
#include "cache.h"
#include "mft_aux.h"
#include "mft_analyze.h"

struct mft_analyze_ctx {
	uint64_t entnum;
	struct ntfs_mft_entry *ent;
	int ent_is_dir:1;
	int ent_is_idx:1;
	struct ntfs_attr_idx aidx;
	struct idx_bm {
		uint8_t *buf;	/* Index bitmap buffer */
		unsigned sz;	/* Index bitmap size */
		unsigned buf_sz;/* Index bitmap buffer size */
	} idx_bm[NHR_IDX_T_MAX + 1];
	struct nhr_mft_entry *mfte;
	struct nhr_data *data;
	int idx_type;
	struct nhr_idx *idx;
	struct nhr_mft_entry **reload;	/* List of entries for reload */
	unsigned reload_num;
	unsigned reload_len_max;
	unsigned cnt_tot;
	unsigned cnt_base;
	unsigned cnt_ext;
	unsigned cnt_file;
	unsigned cnt_dir;
	unsigned cnt_idx;
};

static void mft_entry_reload_schedule(struct nhr_mft_entry *mfte,
				      struct mft_analyze_ctx *actx)
{
	unsigned i;

	for (i = 0; i < actx->reload_num; ++i)
		if (actx->reload[i] == mfte)
			return;

	if (actx->reload_num + 1 > actx->reload_len_max)
		actx->reload = realloc(actx->reload, (actx->reload_num + 1) *
						     sizeof(actx->reload[0]));

	actx->reload[actx->reload_num] = mfte;
	actx->reload_num++;
}

static void mft_entry_base_update(struct nhr_mft_entry *emfte, uint64_t mref,
				  enum nhr_info_src src,
				  struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *bmfte = cache_mfte_find(NTFS_MREF_ENTNUM(mref));

	if (!bmfte) {
		bmfte = cache_mfte_alloc(NTFS_MREF_ENTNUM(mref));
		mft_entry_reload_schedule(bmfte, actx);
	}

	if (NTFS_MREF_SEQNO(mref))
		NHR_FIELD_UPDATE(&bmfte->seqno, NTFS_MREF_SEQNO(mref), src);

	cache_mfte_base_set(emfte, bmfte, src);
}

static void mft_analyze_alist_parse(const void *buf, const unsigned len,
				    struct mft_analyze_ctx *actx)
{
	const struct ntfs_attr_alist_item *ali = buf;
	const struct ntfs_attr_alist_item *end = buf + len;
	struct nhr_mft_entry *emfte;

	for (; ali < end; ali = (void *)ali + ali->size) {
		if (NTFS_MREF_ENTNUM(ali->mref) == actx->entnum)
			continue;
		emfte = cache_mfte_find(NTFS_MREF_ENTNUM(ali->mref));
		if (!emfte)
			continue;
		NHR_FIELD_UPDATE(&emfte->seqno, NTFS_MREF_SEQNO(ali->mref),
				 NHR_SRC_ALIST);
		mft_entry_base_update(emfte, actx->entnum, NHR_SRC_ALIST, actx);
		if (actx->ent_is_dir)
			emfte->f_cmn |= NHR_MFT_FC_DIR;
		else if (actx->ent_is_idx)
			emfte->f_cmn |= NHR_MFT_FC_IDX;
		else
			emfte->f_cmn |= NHR_MFT_FC_FILE;
	}
}

void mft_analyze_fname_parse(const void *buf, const unsigned len,
			     enum nhr_info_src src,
			     struct nhr_mft_entry *mfte)
{
	const struct ntfs_attr_fname *fn = buf;
	struct nhr_mfte_fn *efn;
	struct nhr_data *data;

	if (len < __builtin_offsetof(typeof(*fn), parent) + sizeof(fn->parent))
		return;
	assert(!mfte->parent.val || mfte->parent.val == NTFS_MREF_ENTNUM(fn->parent));
	NHR_FIELD_UPDATE(&mfte->parent, NTFS_MREF_ENTNUM(fn->parent), src);
	mfte->f_cmn |= NHR_MFT_FC_BASE;

	if (len < __builtin_offsetof(typeof(*fn), time_create) + sizeof(fn->time_create))
		return;
	NHR_FIELD_UPDATE(&mfte->time_create, fn->time_create, src);

	if (len < __builtin_offsetof(typeof(*fn), time_change) + sizeof(fn->time_change))
		return;
	NHR_FIELD_UPDATE(&mfte->time_change, fn->time_change, src);

	if (len < __builtin_offsetof(typeof(*fn), time_mft) + sizeof(fn->time_mft))
		return;
	NHR_FIELD_UPDATE(&mfte->time_mft, fn->time_mft, src);

	if (len < __builtin_offsetof(typeof(*fn), time_access) + sizeof(fn->time_access))
		return;
	NHR_FIELD_UPDATE(&mfte->time_access, fn->time_access, src);

	if (len < __builtin_offsetof(typeof(*fn), alloc_sz) + sizeof(fn->alloc_sz))
		return;
	data = cache_data_find(mfte, 0, NULL);
	if (!data && (mfte->f_cmn & NHR_MFT_FC_FILE || fn->alloc_sz))
		data = cache_data_alloc(mfte, 0, NULL);
	if (data)
		NHR_FIELD_UPDATE(&data->sz_alloc, fn->alloc_sz, src);

	if (len < __builtin_offsetof(typeof(*fn), used_sz) + sizeof(fn->used_sz))
		return;
	if (data)
		NHR_FIELD_UPDATE(&data->sz_used, fn->used_sz, src);

	if (len < __builtin_offsetof(typeof(*fn), flags) + sizeof(fn->flags))
		return;
	cache_mfte_fileflags_upd(mfte, fn->flags, src);

	if (len < __builtin_offsetof(typeof(*fn), name) ||
	    len < __builtin_offsetof(typeof(*fn), name) + fn->name_len * 2)
		return;
	efn = &mfte->names[fn->name_type];
	if (src > efn->src) {
		if (efn->len != fn->name_len) {
			free(efn->name);
			efn->name = NULL;
		}
		if (!efn->name)
			efn->name = malloc(fn->name_len * 2);
		efn->len = fn->name_len;
		memcpy(efn->name, fn->name, fn->name_len * 2);
		efn->src = src;
	}
}

static void mft_analyze_i30_entry_parse(const struct ntfs_idx_entry_hdr *ieh)
{
	struct nhr_mft_entry *mfte;

	if (ieh->key_sz) {
		mfte = cache_mfte_find(NTFS_MREF_ENTNUM(ieh->val));
		if (mfte) {
			NHR_FIELD_UPDATE(&mfte->seqno, NTFS_MREF_SEQNO(ieh->val),
					 NHR_SRC_I30);
			mft_analyze_fname_parse(ieh->key, ieh->key_sz,
						NHR_SRC_I30, mfte);
		}
	}
}

/** Parse entry, which header is Ok, but key is partially missed */
static void mft_analyze_i30_entry_corrupted(const struct ntfs_idx_entry_hdr *ieh,
					    unsigned len)
{
	struct nhr_mft_entry *mfte;

	if (!ieh->key_sz)	/* Khm */
		return;

	mfte = cache_mfte_find(NTFS_MREF_ENTNUM(ieh->val));
	if (!mfte)
		return;

	NHR_FIELD_UPDATE(&mfte->seqno, NTFS_MREF_SEQNO(ieh->val), NHR_SRC_I30);
	mft_analyze_fname_parse(ieh->key, len - sizeof(*ieh), NHR_SRC_I30,
				mfte);
}

void mft_analyze_i30_node_parse(const void *buf, size_t len)
{
	const struct ntfs_idx_node_hdr *inh = buf;
	const struct ntfs_idx_entry_hdr *ieh = buf + inh->off;
	const struct ntfs_idx_entry_hdr *ieh_end = buf + inh->len;

	for (; ieh < ieh_end; ieh = (void *)ieh + ieh->size) {
		mft_analyze_i30_entry_parse(ieh);
	}
}

static void mft_analyze_idx_blk_parse(const uint64_t lcn,
				      struct mft_analyze_ctx *actx)
{
	uint8_t buf[nhr.vol.idx_blk_sz];
	struct ntfs_idx_rec_hdr *irh = (void *)buf;
	int res;

	/* Looks like index block could not be fragmented */
	img_read_clusters(lcn, buf, nhr.vol.idx_blk_csz);

	if (strncmp(irh->r.magic, "INDX", 4) != 0) {
		fprintf(stderr, "mft:idx:blk: invalid magic %s expect \"INDX\"\n",
			mft_rec_magic_dump(&irh->r));
		return;
	}

	res = ntfs_usa_apply(buf, nhr.vol.idx_blk_sz, nhr.vol.sec_sz);
	if (res) {
		fprintf(stderr, "mft:blk: markers itegrity check error\n");
		return;
	}

	mft_analyze_i30_node_parse(irh->data, nhr.vol.idx_blk_sz - sizeof(*irh));
}

static void mft_analyze_attr_stdinf(const struct ntfs_attr_hdr *attr,
				    struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *mfte = actx->mfte;
	const struct ntfs_attr_stdinf *si = NTFS_ATTR_RDATA(attr);

	NHR_FIELD_UPDATE(&mfte->time_create, si->time_create, NHR_SRC_STDINF);
	NHR_FIELD_UPDATE(&mfte->time_change, si->time_change, NHR_SRC_STDINF);
	NHR_FIELD_UPDATE(&mfte->time_mft, si->time_mft, NHR_SRC_STDINF);
	NHR_FIELD_UPDATE(&mfte->time_access, si->time_access, NHR_SRC_STDINF);

	cache_mfte_fileflags_upd(mfte, si->flags, NHR_SRC_STDINF);

	if (attr->data_sz < __builtin_offsetof(typeof(*si), security_id) +
			    sizeof(si->security_id))
		return;

	NHR_FIELD_UPDATE(&mfte->sid, si->security_id, NHR_SRC_STDINF);
}

static void mft_analyze_attr_alist(const struct ntfs_attr_hdr *attr,
				   const struct ntfs_mp *mpl,
				   struct mft_analyze_ctx *actx)
{
	void *buf;
	unsigned len;

	if (attr->nonresident) {
		buf = malloc(ntfs_mpl_vclen(mpl) * nhr.vol.cls_sz);
		img_fetch_mp_data(mpl, buf);
		len = attr->used_sz;
	} else {
		len = attr->data_sz;
		buf = NTFS_ATTR_RDATA(attr);
	}
	mft_analyze_alist_parse(buf, len, actx);
	if (attr->nonresident)
		free(buf);
}

static void mft_analyze_attr_fname(const struct ntfs_attr_hdr *attr,
				   struct mft_analyze_ctx *actx)
{
	struct ntfs_attr_fname *fn = NTFS_ATTR_RDATA(attr);
	struct nhr_mft_entry *pmfte = cache_mfte_find(NTFS_MREF_ENTNUM(fn->parent));

	/* Speedup directory ($I30) index creation */
	if (pmfte && pmfte->fileflags.src == NHR_SRC_NONE)
		cache_mfte_fileflags_upd(pmfte, NTFS_FILE_F_IDX_I30,
					 NHR_SRC_HEUR);

	if (actx->mfte) {
		mft_analyze_fname_parse(fn, attr->data_sz, NHR_SRC_FN,
					actx->mfte);
		actx->mfte->names[fn->name_type].attr_id = attr->id;
	}
}

static void mft_analyze_attr_data_cls(const struct ntfs_attr_hdr *attr,
				      const uint64_t vcn, const uint64_t lcn,
				      struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *mfte = actx->mfte;
	struct nhr_data *data;
	const uint64_t lcn_off = lcn * nhr.vol.cls_sz;
	const uint64_t sz = nhr.vol.cls_sz;
	uint64_t i;
	const void *attr_name;
	struct nhr_bb *bb;

	for (i = 0; i < sz; i += nhr.vol.sec_sz) {
		bb = bb_find(lcn_off + i);
		if (!bb)
			continue;
		if (!mfte) {
			mfte = cache_mfte_find(actx->entnum);
			if (!mfte)
				mfte = cache_mfte_alloc(actx->entnum);
			actx->mfte = mfte;
		}
		if (attr->type == NTFS_ATTR_DATA) {
			if (actx->data) {
				data = actx->data;
			} else {
				attr_name = NTFS_ATTR_NAME(attr);
				data = cache_data_find(mfte, attr->name_len,
						       attr_name);
				if (!data)
					data = cache_data_alloc(mfte,
								attr->name_len,
								attr_name);
				actx->data = data;
			}
		} else {
			data = NULL;
		}

		bb->attr_type = attr->type;
		bb->attr_id = attr->id;
		bb->voff = vcn * nhr.vol.cls_sz + i;
		bb->entity = data;
		cache_mfte_bb_add(mfte, bb);
	}
}

static void mft_analyze_attr_data_mpl(const struct ntfs_attr_hdr *attr,
				      const struct ntfs_mp *mpl,
				      struct mft_analyze_ctx *actx)
{
	uint64_t i;

	for (; mpl->clen; ++mpl) {
		if (mpl->lcn == NTFS_LCN_NONE)	/* Skip holes */
			continue;
		cmap_block_mark(mpl->lcn, mpl->clen, NHR_CB_F_ALLOC);
		for (i = 0; i < mpl->clen; ++i)
			mft_analyze_attr_data_cls(attr, mpl->vcn + i,
						  mpl->lcn + i, actx);
	}
}

static void mft_analyze_attr_data(const struct ntfs_attr_hdr *attr,
				  const struct ntfs_mp *mpl,
				  struct mft_analyze_ctx *actx)
{
	mft_analyze_attr_data_mpl(attr, mpl, actx);

	if (actx->mfte) {
		struct nhr_data *data = actx->data;
		const void *attr_name = NTFS_ATTR_NAME(attr);

		if (!data) {
			data = cache_data_find(actx->mfte, attr->name_len,
					       attr_name);
			if (!data)
				data = cache_data_alloc(actx->mfte,
							attr->name_len,
							attr_name);
			actx->data = data;
		}
	}

	if (actx->data) {
		struct ntfs_mp *res_mpl = actx->data->mpl;
		struct nhr_str_segm *segm;

		if (res_mpl)
			res_mpl = ntfs_mpl_find(res_mpl,
						ntfs_mpl_len(res_mpl),
						mpl->vcn);
		if (!res_mpl) {
			res_mpl = ntfs_mpl_merge(actx->data->mpl, mpl);
			assert(res_mpl);
			actx->data->mpl = res_mpl;
		}

		segm = cache_data_segm_find(actx->data, attr->firstvcn);
		if (!segm)
			segm = cache_data_segm_alloc(actx->data,
						     attr->firstvcn);
		NHR_FIELD_UPDATE(&segm->firstvcn, attr->firstvcn, NHR_SRC_ATTR);
		NHR_FIELD_UPDATE(&segm->lastvcn, attr->lastvcn, NHR_SRC_ATTR);
	}

	if (actx->data && attr->firstvcn == 0) {
		uint64_t alloc_sz;

		alloc_sz = attr->flags & NTFS_ATTR_F_COMP ?
			   attr->comp_sz : attr->alloc_sz;
		NHR_FIELD_UPDATE(&actx->data->sz_alloc, alloc_sz,
				 NHR_SRC_ATTR);
		NHR_FIELD_UPDATE(&actx->data->sz_used, attr->used_sz,
				 NHR_SRC_ATTR);
		NHR_FIELD_UPDATE(&actx->data->sz_init, attr->init_sz,
				 NHR_SRC_ATTR);
	}
}

/**
 * Analyze corrupted non-resident data attribute
 */
static void mft_analyze_attr_data_corrupted(const struct ntfs_attr_hdr *attr,
					    unsigned len,
					    struct mft_analyze_ctx *actx)
{
	struct nhr_data *data = cache_data_find(actx->mfte, attr->name_len,
						NTFS_ATTR_NAME(attr));
	struct nhr_str_segm *segm;

	if (!data)
		data = cache_data_alloc(actx->mfte, attr->name_len,
					NTFS_ATTR_NAME(attr));

	if (len < __builtin_offsetof(typeof(*attr), firstvcn) +
		  sizeof(attr->firstvcn))
		return;

	segm = cache_data_segm_find(data, attr->firstvcn);
	if (!segm)
		segm = cache_data_segm_alloc(data, attr->firstvcn);

	NHR_FIELD_UPDATE(&segm->firstvcn, attr->firstvcn, NHR_SRC_ATTR);

	if (len < __builtin_offsetof(typeof(*attr), lastvcn) +
		  sizeof(attr->lastvcn))
		return;

	NHR_FIELD_UPDATE(&segm->lastvcn, attr->lastvcn, NHR_SRC_ATTR);
}

/**
 * Extract resident data from $DATA attribute and put it to cache
 *
 * Should be called only for attribute with valid header and
 * attribute name (if name is not empty, caller must be shure that
 * space allocated for name is really valid)
 */
static void mft_analyze_cache_data(const struct ntfs_attr_hdr *attr,
				   unsigned valid_len,
				   struct mft_analyze_ctx *actx)
{
	const void *attr_name = NTFS_ATTR_NAME(attr);
	struct nhr_mft_entry *mfte = actx->mfte;
	struct nhr_data *data;
	struct nhr_data_chunk *chunk;
	unsigned chunk_len;

	data = cache_data_find(mfte, attr->name_len, attr_name);
	if (!data)
		data = cache_data_alloc(mfte, attr->name_len, attr_name);

	NHR_FIELD_UPDATE(&data->sz_alloc, attr->size - attr->data_off,
			 NHR_SRC_ATTR);
	NHR_FIELD_UPDATE(&data->sz_used, attr->data_sz, NHR_SRC_ATTR);

	if (valid_len < attr->data_off)
		return;

	chunk_len = attr->data_off + attr->data_sz > valid_len ?
		    valid_len - attr->data_off : attr->data_sz;

	chunk = list_empty(&data->chunks) ? NULL :
		list_first_entry(&data->chunks, typeof(*chunk), list);

	if (chunk && chunk->voff == 0 && chunk->len == chunk_len &&
	    chunk->src >= NHR_SRC_ATTR)
		return;

	if (chunk && chunk->voff == 0) {
		assert(chunk->len == chunk_len);	/* No resize support */
	} else {
		chunk = malloc(sizeof(*chunk) + chunk_len);
		list_add(&chunk->list, &data->chunks);
		chunk->voff = 0;
		chunk->len = chunk_len;
	}

	/* No overlap support */
	assert(chunk->list.next == &data->chunks ||
	       list_next_entry(chunk, list)->voff >= chunk->len);

	chunk->src = NHR_SRC_ATTR;
	memcpy(chunk->buf, NTFS_ATTR_RDATA(attr), chunk->len);
}

/** Fetch bitmap and cache it inside analysis context */
static void mft_analyze_load_bitmap(const struct ntfs_attr_hdr *attr,
				    const struct ntfs_mp *mpl,
				    struct mft_analyze_ctx *actx)
{
	int idx_type = idx_detect_type(attr->name_len, NTFS_ATTR_NAME(attr));
	struct idx_bm *bm;
	unsigned len;

	if (idx_type == NHR_IDX_T_UNKN)
		return;

	bm = &actx->idx_bm[idx_type];

	if (attr->nonresident) {
		len = ntfs_mpl_vclen(mpl) * nhr.vol.cls_sz;
		if (len > bm->buf_sz) {
			bm->buf_sz = len;
			free(bm->buf);
			bm->buf = malloc(len);
		}
		bm->sz = attr->used_sz;
		img_fetch_mp_data(mpl, bm->buf);
	} else {
		if (attr->data_sz > bm->buf_sz) {
			bm->buf_sz = attr->data_sz;
			free(bm->buf);
			bm->buf = malloc(attr->data_sz);
		}
		bm->sz = attr->data_sz;
		memcpy(bm->buf, NTFS_ATTR_RDATA(attr), attr->data_sz);
	}
}

/**
 * Get bitmap argument from base entry
 * entnum - base entry number
 * actx - analysis context
 */
static int mft_analyze_get_base_bitmap(uint64_t entnum,
				       struct mft_analyze_ctx *actx)
{
	uint8_t ent_buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)ent_buf;
	struct ntfs_attr_idx aidx;
	const struct ntfs_attr_hdr *attr;
	struct ntfs_mp *mp;
	int i, cnt = 0;

	if (mft_entry_read_and_preprocess(entnum, ent, 0) != 0)
		return -EIO;

	memset(&aidx, 0x00, sizeof(aidx));

	ntfs_mft_aidx_get(ent, &aidx);

	for (i = aidx.num - 1; i >= 0; --i) {
		attr = aidx.a[i];
		if (attr->type != NTFS_ATTR_BITMAP)
			continue;
		cnt++;

		if (attr->nonresident)
			mp = ntfs_attr_mp_unpack(attr);
		else
			mp = NULL;

		mft_analyze_load_bitmap(attr, mp, actx);
		free(mp);
	}

	ntfs_mft_aidx_clean(&aidx);

	return cnt ? 0 : -ENOENT;
}

static void mft_analyze_attr_iroot(const struct ntfs_attr_hdr *attr,
				   struct mft_analyze_ctx *actx)
{
	const struct ntfs_attr_iroot *ir = NTFS_ATTR_RDATA(attr);
	unsigned len = attr->data_sz;
	struct nhr_idx *idx;

	actx->idx_type = idx_detect_type(attr->name_len, NTFS_ATTR_NAME(attr));

	if (actx->idx_type == NHR_IDX_T_DIR)
		mft_analyze_i30_node_parse(ir->data, len - sizeof(*ir));

	if (actx->idx_type == NHR_IDX_T_UNKN)
		return;
	if (!actx->mfte)
		return;
	if (!(actx->mfte->f_sum & (NHR_MFT_FB_SELF | NHR_MFT_FB_AIDX)))
		return;
	idx = cache_idx_find(actx->mfte, actx->idx_type);
	if (!idx)
		idx = cache_idx_alloc(actx->mfte, actx->idx_type);
	if (idx->root_buf)
		return;
	idx->root_buf_len = len;
	idx->root_buf = malloc(len);
	memcpy(idx->root_buf, ir, len);
}

static void mft_analyze_iroot_i30_corrupted(const struct ntfs_attr_hdr *attr,
					    struct mft_analyze_ctx *actx,
					    unsigned valid_len)
{
	const struct ntfs_attr_iroot *ir = NTFS_ATTR_RDATA(attr);
	const struct ntfs_idx_node_hdr *inh = (void *)ir->data;
	const struct ntfs_idx_entry_hdr *ieh = (void *)inh + inh->off;
	const struct ntfs_idx_entry_hdr *ieh_end = (void *)inh + inh->len;
	int left = valid_len - attr->data_off - sizeof(*ir) - inh->off;

	if (left < 0)
		return;

	for (; ieh < ieh_end; ieh = (void *)ieh + ieh->size) {
		if (sizeof(*ieh) > left)
			break;
		if (ieh->size > left) {
			mft_analyze_i30_entry_corrupted(ieh, left);
			break;
		}
		mft_analyze_i30_entry_parse(ieh);
		left -= ieh->size;
	}
}

static void mft_analyze_attr_ialloc_blk(const struct ntfs_attr_hdr *attr,
					const uint64_t vcn, const uint64_t lcn,
					const uint8_t *bm,
					struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *mfte = actx->mfte;
	struct nhr_idx *idx;
	const uint64_t lcn_off = lcn * nhr.vol.cls_sz;
	const uint64_t sz = nhr.vol.idx_blk_sz;
	const unsigned blk_num = vcn / nhr.vol.idx_blk_csz;
	int blk_is_free = !bm || bm[blk_num / 8] & (1 << (blk_num % 8)) ? 0 : 1;
	int blk_is_bad = 0;
	uint64_t i;
	struct nhr_bb *bb;

	for (i = 0; i < sz; i += nhr.vol.sec_sz) {
		bb = bb_find(lcn_off + i);
		if (!bb)
			continue;
		blk_is_bad = 1;

		if (!mfte) {
			mfte = cache_mfte_find(actx->entnum);
			if (!mfte)
				mfte = cache_mfte_alloc(actx->entnum);
			actx->mfte = mfte;
		}
		if (actx->idx) {
			idx = actx->idx;
		} else {
			if (actx->idx_type != NHR_IDX_T_UNKN) {
				idx = cache_idx_find(mfte, actx->idx_type);
				if (!idx)
					idx = cache_idx_alloc(mfte, actx->idx_type);
				actx->idx = idx;
			} else {
				idx = NULL;
			}
		}

		bb->attr_type = attr->type;
		bb->attr_id = attr->id;
		bb->voff = vcn * nhr.vol.cls_sz + i;
		bb->entity = idx;
		cache_mfte_bb_add(mfte, bb);
		if (blk_is_free) {
			bb->flags |= NHR_BB_F_IGNORE;
			cache_mfte_bb_ok(bb);
		}
	}

	if (actx->ent_is_dir && bm && !blk_is_free && !blk_is_bad)
		mft_analyze_idx_blk_parse(lcn, actx);
}

static void mft_analyze_attr_ialloc(const struct ntfs_attr_hdr *attr,
				    const struct ntfs_mp *mpl,
				    struct mft_analyze_ctx *actx)
{
	const struct ntfs_mp *mp;
	uint64_t i, blk_num;
	int idx_type = idx_detect_type(attr->name_len, NTFS_ATTR_NAME(attr));
	const uint8_t *bm;
	struct nhr_idx *idx;
	struct nhr_idx_node *idxn;

	actx->idx_type = idx_type;
	if (idx_type != NHR_IDX_T_UNKN && !actx->idx_bm[idx_type].sz && actx->ent->base)
		mft_analyze_get_base_bitmap(NTFS_MREF_ENTNUM(actx->ent->base),
					    actx);
	if (idx_type != NHR_IDX_T_UNKN && actx->idx_bm[idx_type].sz)
		bm = actx->idx_bm[idx_type].buf;
	else
		bm = NULL;

	for (mp = mpl; mp->clen; ++mp) {
		assert(mp->lcn != NTFS_LCN_NONE);
		cmap_block_mark(mp->lcn, mp->clen, NHR_CB_F_ALLOC);
		for (i = 0; i < mp->clen; i += nhr.vol.idx_blk_csz)
			mft_analyze_attr_ialloc_blk(attr, mp->vcn + i,
						    mp->lcn + i, bm, actx);
	}

	if (!actx->mfte)
		return;
	if (!(actx->mfte->f_sum & (NHR_MFT_FB_SELF | NHR_MFT_FB_AIDX)))
		return;
	if (idx_type == NHR_IDX_T_UNKN)
		return;

	assert(bm);
	idx = actx->idx;
	if (!idx) {
		idx = cache_idx_find(actx->mfte, idx_type);
		if (!idx)
			idx = cache_idx_alloc(actx->mfte, idx_type);
	}

	blk_num = mpl->vcn / nhr.vol.idx_blk_csz - 1;
	for (mp = mpl; mp->clen; ++mp) {
		for (i = 0; i < mp->clen; i += nhr.vol.idx_blk_csz) {
			blk_num++;
			if (cache_idxn_find(idx, mp->vcn + i))
				continue;
			idxn = cache_idxn_alloc(idx, mp->vcn + i);
			idxn->lcn = mp->lcn + i;
			if (bm[blk_num / 8] & (1 << blk_num % 8))
				idxn->flags |= NHR_IDXN_F_INUSE;
			else
				idxn->flags |= NHR_IDXN_F_FREE;
		}
	}
}

static void mft_analyze_attr(const struct ntfs_attr_hdr *attr,
			     struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *mfte = actx->mfte;
	struct ntfs_mp *mp;

	if (attr->nonresident) {
		mp = ntfs_attr_mp_unpack(attr);
		assert(mp);
	} else {
		mp = NULL;
	}

	if (attr->type == NTFS_ATTR_STDINF) {
		if (mfte)
			mft_analyze_attr_stdinf(attr, actx);
	} else if (attr->type == NTFS_ATTR_ALIST) {
		mft_analyze_attr_alist(attr, mp, actx);
	} else if (attr->type == NTFS_ATTR_FNAME) {
		mft_analyze_attr_fname(attr, actx);
	} else if (attr->type == NTFS_ATTR_DATA) {
		if (mp) {
			mft_analyze_attr_data(attr, mp, actx);
			free(mp);
			mp = NULL;
			actx->data = NULL;
		} else if (actx->mfte && actx->mfte->f_bad & NHR_MFT_FB_SELF) {
			mft_analyze_cache_data(attr, attr->size, actx);
		}
	} else if (attr->type == NTFS_ATTR_IROOT) {
		mft_analyze_attr_iroot(attr, actx);
	} else if (attr->type == NTFS_ATTR_IALLOC) {
		mft_analyze_attr_ialloc(attr, mp, actx);
		free(mp);
		mp = NULL;
		actx->idx = NULL;
	} else if (attr->type == NTFS_ATTR_BITMAP) {
		mft_analyze_load_bitmap(attr, mp, actx);
	}

	if (mp) {
		mft_analyze_attr_data_mpl(attr, mp, actx);
		free(mp);
	}
}

static void mft_analyze_attr_corrupted(const struct ntfs_attr_hdr *attr,
				       unsigned len,
				       struct mft_analyze_ctx *actx)
{
	static const char dir_idx_name[] = {'$', 0, 'I', 0, '3', 0, '0', 0};
	int res;

	if (len < NTFS_ATTR_HDR_COMMON_LEN)
		return;

	/**
	 * Make shure that name space is valid. We either have unnamed attribute
	 * or attribute with name, which should be known to select appropriate
	 * cached entity (e.g. data stream or index).
	 */
	if (attr->name_len && len < attr->name_off + attr->name_len * 2)
		return;

	if (attr->nonresident) {
		if (attr->type == NTFS_ATTR_DATA) {
			mft_analyze_attr_data_corrupted(attr, len, actx);
		}
	} else {
		if (len < NTFS_ATTR_HDR_RESIDENT_LEN)
			return;

		if (attr->type == NTFS_ATTR_DATA) {
			mft_analyze_cache_data(attr, len, actx);
		} else if (attr->type == NTFS_ATTR_IROOT) {
			if (attr->name_len != sizeof(dir_idx_name)/2)
				return;
			res = memcmp(NTFS_ATTR_NAME(attr), dir_idx_name,
				     sizeof(dir_idx_name));
			if (res)
				return;
			mft_analyze_iroot_i30_corrupted(attr, actx, len);
		}
	}
}

/** Parse $ATTRIBUTES_LIST and fill attributes cache */
static void mft_entry_attr2cache_alist(struct nhr_mft_entry *bmfte,
				       const struct ntfs_attr_hdr *attr)
{
	struct nhr_mft_entry *mfte;
	struct nhr_alist_item *ali;
	struct ntfs_mp *mpl;
	void *alist_buf;
	unsigned alist_len;
	const struct ntfs_attr_alist_item *_ali;
	const struct ntfs_attr_alist_item *_end;

	if (attr->nonresident) {
		mpl = ntfs_attr_mp_unpack(attr);
		alist_buf = malloc(ntfs_mpl_vclen(mpl) * nhr.vol.cls_sz);
		img_fetch_mp_data(mpl, alist_buf);
		free(mpl);
		alist_len = attr->used_sz;
	} else {
		alist_buf = NTFS_ATTR_RDATA(attr);
		alist_len = attr->data_sz;
	}

	_ali = alist_buf;
	_end = alist_buf + alist_len;
	for (; _ali < _end; _ali = (void *)_ali + _ali->size) {
		mfte = cache_mfte_find(NTFS_MREF_ENTNUM(_ali->mref));
		if (!mfte) {
			mfte = cache_mfte_alloc(NTFS_MREF_ENTNUM(_ali->mref));
			cache_mfte_base_set(mfte, bmfte, NHR_SRC_ALIST);
		}
		ali = cache_attr_find_id(mfte, _ali->type, _ali->id);
		if (!ali) {
			ali = cache_attr_alloc(mfte, _ali->type,
					       _ali->name_len,
					       NTFS_ATTR_ALI_NAME(_ali),
					       _ali->firstvcn);
			ali->src = NHR_SRC_ALIST;
			ali->id = _ali->id;
		} else if (ali->src < NHR_SRC_ALIST) {
			ali->src = NHR_SRC_ALIST;
			if (ali->name_len != _ali->name_len) {
				free(ali->name);
				ali->name = malloc(_ali->name_len * 2);
				ali->name_len = _ali->name_len;
			}
			memcpy(ali->name, NTFS_ATTR_ALI_NAME(_ali),
			       ali->name_len * 2);
		}
	}

	if (attr->nonresident)
		free(alist_buf);
}

/** Parse attributes (using attributes index) and fill attributes cache */
static void mft_entry_attr2cache_aidx(struct nhr_mft_entry *mfte,
				      const struct ntfs_attr_idx *aidx)
{
	const struct ntfs_attr_hdr *attr;
	struct nhr_alist_item *ali;
	uint64_t firstvcn;
	int i;

	for (i = aidx->num - 1; i >= 0; --i) {
		attr = aidx->a[i];
		ali = cache_attr_find_id(mfte, attr->type, attr->id);
		if (!ali) {
			firstvcn = attr->nonresident ? attr->firstvcn : 0;
			ali = cache_attr_alloc(mfte, attr->type, attr->name_len,
					       NTFS_ATTR_NAME(attr), firstvcn);
			ali->src = NHR_SRC_ATTR;
			ali->id = attr->id;
		} else if (ali->src < NHR_SRC_ATTR) {
			ali->src = NHR_SRC_ATTR;
			if (ali->name_len != attr->name_len) {
				free(ali->name);
				ali->name = malloc(attr->name_len * 2);
				ali->name_len = attr->name_len;
			}
			memcpy(ali->name, NTFS_ATTR_NAME(attr),
			       ali->name_len * 2);
			ali->firstvcn = attr->nonresident ? attr->firstvcn : 0;
		}
	}
}

/** Check corrupted attribute and add it to cache if this is possible */
static void mft_entry_attr2cache_corrupted(struct nhr_mft_entry *mfte,
					   const struct ntfs_attr_hdr *attr,
					   unsigned len)
{
	struct nhr_alist_item *ali;
	uint64_t firstvcn;

	if (attr->type == NTFS_ATTR_END)
		return;
	if (len < NTFS_ATTR_HDR_COMMON_LEN)
		return;
	if (attr->nonresident && len < __builtin_offsetof(typeof(*attr), firstvcn))
		return;
	if (attr->name_len && len < attr->name_off + attr->name_len * 2)
		return;

	ali = cache_attr_find_id(mfte, attr->type, attr->id);
	if (!ali) {
		firstvcn = attr->nonresident ? attr->firstvcn : 0;
		ali = cache_attr_alloc(mfte, attr->type, attr->name_len,
				       NTFS_ATTR_NAME(attr), firstvcn);
		ali->src = NHR_SRC_ATTR;
		ali->id = attr->id;
	} else if (ali->src < NHR_SRC_ATTR) {
		ali->src = NHR_SRC_ATTR;
		if (ali->name_len != attr->name_len) {
			free(ali->name);
			ali->name = malloc(attr->name_len * 2);
			ali->name_len = attr->name_len;
		}
		memcpy(ali->name, NTFS_ATTR_NAME(attr), ali->name_len * 2);
	}
}

/**
 * Analyze corrupted entry and extract as much data as possible
 */
static void mft_entry_analyze_corrupted(struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *mfte = actx->mfte;
	const struct ntfs_mft_entry *ent = actx->ent;
	const void *bad_ptr, *p;
	const struct ntfs_attr_hdr *attr;
	const void * const attr_end = (void *)ent + ent->used_sz;
	struct ntfs_attr_idx *aidx = &actx->aidx;
	int i;

	/**
	 * Whole header usaly fit into first sector, so parse
	 * header first.
	 */

	if (actx->ent->flags & NTFS_MFT_ENTRY_F_DIR) {
		actx->cnt_dir++;
		actx->ent_is_dir = 1;
		actx->ent_is_idx = 0;
		mfte->f_cmn |= NHR_MFT_FC_DIR;
	} else if (actx->ent->flags & NTFS_MFT_ENTRY_F_VIEW) {
		actx->cnt_idx++;
		actx->ent_is_dir = 0;
		actx->ent_is_idx = 1;
		mfte->f_cmn |= NHR_MFT_FC_IDX;
	} else {
		actx->cnt_file++;
		actx->ent_is_dir = 0;
		actx->ent_is_idx = 0;
		mfte->f_cmn |= NHR_MFT_FC_FILE;
	}

	if (actx->ent->base) {
		actx->cnt_ext++;
		mft_entry_base_update(mfte, actx->ent->base, NHR_SRC_MFT, actx);
	} else {
		actx->cnt_base++;
		mfte->f_cmn |= NHR_MFT_FC_BASE;
	}

	NHR_FIELD_UPDATE(&mfte->seqno, actx->ent->seqno, NHR_SRC_MFT);

	/* Get first BB virtual offset */
	for (i = 0; i < nhr.vol.mft_ent_sz/nhr.vol.sec_sz; ++i)
		if (mfte->bb_map & (1 << i))
			break;
	bad_ptr = (void *)ent + i * nhr.vol.sec_sz;

	/* Parse attributes and build attributes index until we get first BB */
	p = (void *)ent + ent->attr_off;
	aidx->num = 0;
	while (1) {
		if ((attr_end - p) < NTFS_ATTR_HDR_MIN_LEN)
			break;
		if ((bad_ptr - p) < NTFS_ATTR_HDR_MIN_LEN)
			break;
		attr = p;
		if (attr->type == NTFS_ATTR_END)
			break;
		if ((attr_end - p) < attr->size)
			break;
		if ((bad_ptr - p) < attr->size) {
			mft_entry_attr2cache_corrupted(mfte, attr, bad_ptr - p);
			mft_analyze_attr_corrupted(attr, bad_ptr - p, actx);
			break;
		} else {
			if (aidx->num + 1 > aidx->size) {
				aidx->size += 4;
				aidx->a = realloc(aidx->a, aidx->size *
							   sizeof(aidx->a[0]));
			}
			aidx->a[aidx->num++] = attr;
		}
		p += attr->size;
	}

	/**
	 * Analyze valid attributes in reverse order to guarantee
	 * that bitmap exists at the moment we get index allocation
	 */
	for (i = aidx->num - 1; i >= 0; --i)
		mft_analyze_attr(aidx->a[i], actx);

	mft_entry_attr2cache_aidx(mfte, aidx);

	for (i = 0; i < sizeof(actx->idx_bm)/sizeof(actx->idx_bm[0]); ++i)
		actx->idx_bm[i].sz = 0;	/* Clean possibly loaded bitmap */
}

static void mft_entry_analyze_valid(struct mft_analyze_ctx *actx)
{
	int i;
	const struct ntfs_attr_hdr *alist = NULL;

	actx->cnt_tot++;

	if (actx->ent->base) {
		actx->cnt_ext++;
		nhr_mft_eemap_add(actx->entnum,
				  NTFS_MREF_ENTNUM(actx->ent->base));
	} else {
		actx->cnt_base++;
	}

	if (actx->ent->flags & NTFS_MFT_ENTRY_F_DIR) {
		actx->cnt_dir++;
		actx->ent_is_dir = 1;
		actx->ent_is_idx = 0;
	} else if (actx->ent->flags & NTFS_MFT_ENTRY_F_VIEW) {
		actx->cnt_idx++;
		actx->ent_is_dir = 0;
		actx->ent_is_idx = 1;
	} else {
		actx->cnt_file++;
		actx->ent_is_dir = 0;
		actx->ent_is_idx = 0;
	}

	ntfs_mft_aidx_get(actx->ent, &actx->aidx);
	for (i = actx->aidx.num - 1; i >= 0; --i) {
		mft_analyze_attr(actx->aidx.a[i], actx);
		if (actx->aidx.a[i]->type == NTFS_ATTR_ALIST)
			alist = actx->aidx.a[i];
	}

	if (actx->mfte) {
		if (actx->mfte->bmfte->f_sum & NHR_MFT_FB_SELF) {
			if (alist)
				mft_entry_attr2cache_alist(actx->mfte, alist);
			mft_entry_attr2cache_aidx(actx->mfte, &actx->aidx);
		}
		if (actx->ent_is_dir)
			actx->mfte->f_cmn |= NHR_MFT_FC_DIR;
		else if (actx->ent_is_idx)
			actx->mfte->f_cmn |= NHR_MFT_FC_IDX;
		else
			actx->mfte->f_cmn |= NHR_MFT_FC_FILE;
		if (actx->ent->base)
			mft_entry_base_update(actx->mfte, actx->ent->base,
					      NHR_SRC_MFT, actx);
		else
			actx->mfte->f_cmn |= NHR_MFT_FC_BASE;
		NHR_FIELD_UPDATE(&actx->mfte->seqno, actx->ent->seqno,
				 NHR_SRC_MFT);
	}

	for (i = 0; i < sizeof(actx->idx_bm)/sizeof(actx->idx_bm[0]); ++i)
		actx->idx_bm[i].sz = 0;	/* Clean possibly loaded bitmap */
}

/**
 * Add to cache base and parent entries of corrupted MFT entry
 *
 * NB: parse no more than first sector (since other could be corrupted)
 * NB: don't link base and parent with this entry (since it could be completely broken)
 * NB: also request reloading of these entries
 */
static void mft_entry_reload_parent_and_base(struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *mfte;
	const struct ntfs_mft_entry *ent = actx->ent;
	const void *bad_ptr = (void *)ent + nhr.vol.sec_sz;
	const void *p;
	const struct ntfs_attr_hdr *attr;
	const void * const attr_end = (void *)ent + ent->used_sz;
	const struct ntfs_attr_fname *fn;

	if (actx->ent->base) {
		mfte = cache_mfte_find(NTFS_MREF_ENTNUM(actx->ent->base));
		if (!mfte)
			mfte = cache_mfte_alloc(NTFS_MREF_ENTNUM(actx->ent->base));
		mft_entry_reload_schedule(mfte, actx);
		return;	/* No reasons to search parent */
	}

	/* Search $FILE_NAME attribute and schedule parent to reload */
	for (p = (void *)ent + ent->attr_off; ; p += attr->size) {
		if ((attr_end - p) < NTFS_ATTR_HDR_MIN_LEN)
			break;
		if ((bad_ptr - p) < NTFS_ATTR_HDR_MIN_LEN)
			break;
		attr = p;
		if (attr->type == NTFS_ATTR_END)
			break;
		if ((attr_end - p) < attr->size)
			break;
		if ((bad_ptr - p) < attr->size)
			break;
		if (attr->type < NTFS_ATTR_FNAME)
			continue;
		if (attr->type > NTFS_ATTR_FNAME)
			break;
		fn = NTFS_ATTR_RDATA(attr);
		mfte = cache_mfte_find(NTFS_MREF_ENTNUM(fn->parent));
		if (!mfte)
			mfte = cache_mfte_alloc(NTFS_MREF_ENTNUM(fn->parent));
		mft_entry_reload_schedule(mfte, actx);
	}
}

static int mft_entry_analyze(struct mft_analyze_ctx *actx)
{
	const unsigned mft_ent_ssz = nhr.vol.mft_ent_sz / nhr.vol.sec_sz;
	struct nhr_mft_entry *mfte = actx->mfte;
	unsigned bb_map;
	struct ntfs_usa *usa;
	void *p;
	int i, res;

	if (!mfte || nhr_mfte_num(mfte) != actx->entnum)
		mfte = cache_mfte_find(actx->entnum);

	if (mfte && (nhr_mfte_bflags(mfte) & NHR_MFT_FB_SELF)) {
		if (mfte->bb_map & 1) /* Could not process without header */
			return -1;
		else
			bb_map = mfte->bb_map;
	} else {
		bb_map = 0;
	}

	res = mft_entry_read(actx->entnum, actx->ent, NULL);
	if (res)
		return -1;
	res = memcmp("FILE", actx->ent->r.magic, 4);
	if (res)
		return -1;

	usa = ntfs_usa_ptr(&actx->ent->r);
	p = (void *)actx->ent + nhr.vol.sec_sz - sizeof(uint16_t);
	for (i = 0; i < mft_ent_ssz; ++i, p += nhr.vol.sec_sz) {
		if (bb_map & (1 << i))	/* Skip BB */
			continue;
		if (*(uint16_t *)p != usa->usn)
			break;
		*(uint16_t *)p = usa->sec[i];
	}

	actx->mfte = mfte;
	if (i != mft_ent_ssz) {
		if (!mfte) {
			mfte = cache_mfte_alloc(actx->entnum);
			actx->mfte = mfte;
		}
		if (!(mfte->f_cmn & NHR_MFT_FC_INTEG)) {	/* Parse only onece */
			mfte->f_cmn |= NHR_MFT_FC_INTEG;
			cache_mfte_fbad_set(mfte, NHR_MFT_FB_SELF);
			mft_entry_reload_parent_and_base(actx);
		}
	} else if (bb_map) {
		mft_entry_analyze_corrupted(actx);
	} else {
		mft_entry_analyze_valid(actx);
	}

	return 0;
}

/**
 * Decide whether we could trust to entry header or no
 *
 * First we verify does fields values make sens then compare field
 * values with already known (cached) data.
 */
static int mft_hdr_is_valid(const struct ntfs_mft_entry *ent,
			    const struct nhr_mft_entry *mfte)
{
	/* Allocated size should be equal to value in $Boot */
	if (ent->allocated_sz != nhr.vol.mft_ent_sz)
		return 0;

	/* Used size should be less or equal to allocated size */
	if (ent->used_sz > ent->allocated_sz)
		return 0;

	/* USA should fully lays inside entry */
	if (ent->r.usa_off + ntfs_usa_blen(&ent->r) >= ent->allocated_sz)
		return 0;

	/* USA length should be equal to sectors number + 1 */
	if (ent->r.usa_len != nhr.vol.mft_ent_sz / nhr.vol.sec_sz + 1)
		return 0;

	/* Verify entry sequence number */
	if (!NHR_FIELD_VALID(&mfte->seqno))
		return 0;
	if (mfte->seqno.val != ent->seqno)
		return 0;

	return 1;
}

/**
 * Do the per-sector MFT entry analysis
 *
 * Take entry with failed integrity (USA) check and attempt to decide which
 * sector is Ok and which is bad, then automatically create BB for each bad
 * sector.
 */
static void mft_analyze_entry_sectors(struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *mfte, *mfte_mft = NULL;
	uint8_t ent_buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)ent_buf;
	off_t off;
	const unsigned sec_num = nhr.vol.mft_ent_sz / nhr.vol.sec_sz;
	uint16_t usn, *p;
	struct nhr_bb *bb;
	int res, i;
	unsigned cnt_tot = 0, cnt_full = 0, cnt_part = 0;

	if (nhr.verbose >= 1)
		printf("mft: analyze corrupted entries\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(mfte->f_cmn & NHR_MFT_FC_INTEG))
			continue;
		if (mfte->bb_map != 0)
			continue;
		cnt_tot++;
		res = mft_entry_read(nhr_mfte_num(mfte), ent_buf, &off);
		if (res)
			continue;

		if (!mft_hdr_is_valid(ent, mfte))
			usn = 0;	/* Cause each sector became BB */
		else
			usn = ntfs_usa_ptr(&ent->r)->usn;

		p = (void *)ent_buf + nhr.vol.sec_sz - sizeof(*p);
		for (i = 0; i < sec_num; ++i, p += nhr.vol.sec_sz/sizeof(*p)) {
			if (usn && usn == *p)
				continue;

			mfte->bb_map |= 1 << i;

			if (!mfte_mft) {
				mfte_mft = cache_mfte_find(NTFS_ENTNUM_MFT);
				if (!mfte_mft)
					mfte_mft = cache_mfte_alloc(NTFS_ENTNUM_MFT);
			}

			bb = calloc(1, sizeof(*bb));
			nhr_bb_off(bb) = off + i * nhr.vol.sec_sz;
			bb->attr_type = NTFS_ATTR_DATA;
			bb->attr_id = nhr.mft_data_aid;
			bb->voff = nhr_mfte_num(mfte) * nhr.vol.mft_ent_sz +
				   i * nhr.vol.sec_sz;
			bb->flags = NHR_BB_F_AUTO;
			bb->entity = cache_data_find(mfte_mft, 0, NULL);
			rbtree_insert(&nhr.bb_tree, &bb->tree);
			cache_mfte_bb_add(mfte_mft, bb);
		}

		if (usn) {
			mft_entry_reload_schedule(mfte, actx);
			cnt_part++;
		} else {
			cnt_full++;
		}
	}

	if (nhr.verbose >= 1)
		printf("mft: processed %u entries, detect %u fully broken and %u partially broken entries\n",
		       cnt_tot, cnt_full, cnt_part);
}

static void mft_analyze_postproc_parent(struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *mfte, *lmfte, *pmfte;
	uint64_t parent;
	int res, i;

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!NHR_FIELD_VALID(&mfte->parent))
			continue;

		lmfte = mfte;
		parent = mfte->parent.val;
		do {
			pmfte = cache_mfte_find(parent);
			if (pmfte) {
				/**
				 * Even if we already have this entry in cache,
				 * we would like to reparse it again to get data
				 * from index for children entries.
				 *
				 * XXX: do we really need this data? Or it would
				 * be enought to have some outdated info from
				 * entry themself? In any case we need only
				 * filename for path reconstruction purpose, but
				 * the filename is the same in the MFT and in the
				 * index?
				 */
				for (i = 0; i < NTFS_FNAME_T_MAX + 1; ++i)
					if (lmfte->names[i].src == NHR_SRC_I30)
						break;
				if (i < NTFS_FNAME_T_MAX + 1)
					break;
			} else {
				pmfte = cache_mfte_alloc(parent);
			}

			actx->mfte = pmfte;
			actx->entnum = parent;
			res = mft_entry_analyze(actx);
			if (res)
				break;
			lmfte = pmfte;
			parent = pmfte->parent.val;
		} while (nhr_mfte_num(pmfte) != NTFS_ENTNUM_ROOT);
	}
}

/**
 * Fetch all extent entries if base entry corrupted
 */
static void mft_analyze_postproc_extent(struct mft_analyze_ctx *actx)
{
	struct nhr_mft_entry *bmfte, *emfte;
	struct nhr_mft_eemap *ee;

	rbt_inorder_walk_entry(bmfte, &nhr.mft_cache, tree) {
		if (!(bmfte->f_cmn & NHR_MFT_FC_BASE))
			continue;

		rbt_inorder_walk_entry(ee, &nhr.mft_eemap, tree) {
			if (ee->base != nhr_mfte_num(bmfte))
				continue;
			bmfte->f_cmn |= NHR_MFT_FC_BASE;

			emfte = cache_mfte_find(nhr_mftee_num(ee));
			if (!emfte)
				emfte = cache_mfte_alloc(nhr_mftee_num(ee));

			mft_entry_reload_schedule(emfte, actx);
			/* NB: EE map build from MFT hdr data */
			if (emfte->base_src == NHR_SRC_NONE)
				cache_mfte_base_set(emfte, bmfte, NHR_SRC_MFT);
		}
	}
}

/**
 * (re-)load pending MFT entries
 */
static void mft_load_pending(struct mft_analyze_ctx *actx)
{
	unsigned i;

	for (i = 0; i < actx->reload_num; ++i) {
		actx->mfte = actx->reload[i];
		actx->entnum = nhr_mfte_num(actx->reload[i]);
		mft_entry_analyze(actx);
	}
	actx->reload_num = 0;
}

void mft_analyze_all(void)
{
	struct mft_analyze_ctx actx;
	uint8_t ent_buf[nhr.vol.mft_ent_sz];
	uint64_t entnum, entnum_max = nhr.vol.mft_sz / nhr.vol.mft_ent_sz;
	int i;

	if (nhr.verbose >= 1)
		printf("mft: do detailed analysis of each entry\n");

	memset(&actx, 0x00, sizeof(actx));
	actx.ent = (void *)ent_buf;

	for (entnum = 0; entnum < entnum_max; ++entnum) {
		if (!(nhr.mft_bitmap[entnum / 8] & (1 << (entnum % 8))))
			continue;

		actx.entnum = entnum;
		mft_entry_analyze(&actx);
	}

	if (nhr.verbose >= 1)
		printf("mft: analysis done, processed %u entries (%u base %u extent %u file %u dir %u idx)\n",
		       actx.cnt_tot, actx.cnt_base, actx.cnt_ext, actx.cnt_file,
		       actx.cnt_dir, actx.cnt_idx);

	mft_load_pending(&actx);	/* Reload base or parent */
	mft_analyze_entry_sectors(&actx);/* Analyze broken entries */
	mft_load_pending(&actx);	/* Reparse broken entries */

	mft_analyze_postproc_parent(&actx);
	mft_analyze_postproc_extent(&actx);
	mft_load_pending(&actx);

	ntfs_mft_aidx_clean(&actx.aidx);
	for (i = 0; i < sizeof(actx.idx_bm)/sizeof(actx.idx_bm[0]); ++i)
		free(actx.idx_bm[i].buf);
	free(actx.reload);
}

/** Fetch entry attributes from disk and cache them */
int mft_entry_attr2cache(struct nhr_mft_entry *mfte)
{
	uint8_t ent_buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)ent_buf;
	struct ntfs_attr_idx aidx;
	unsigned i;
	int res = 0;

	/**
	 * Could not process corrupted entries, since we could read same info
	 * which we store few moments ago.
	 */
	if (mfte->f_bad & NHR_MFT_FB_SELF)
		return -1;

	res = mft_entry_read_and_preprocess(nhr_mfte_num(mfte), ent, 1);
	if (res)
		return -1;

	memset(&aidx, 0x00, sizeof(aidx));
	ntfs_mft_aidx_get(ent, &aidx);

	/* Try to find and process $ATTRIBUTES_LIST */
	for (i = 0; i < aidx.num; ++i) {
		if (aidx.a[i]->type != NTFS_ATTR_ALIST)
			continue;
		mft_entry_attr2cache_alist(mfte, aidx.a[i]);
		break;
	}

	/* Process attributes from this entry */
	mft_entry_attr2cache_aidx(mfte, &aidx);

	ntfs_mft_aidx_clean(&aidx);

	return 0;
}

int mft_fetch_data_info(struct nhr_mft_entry *bmfte, unsigned name_len,
			const uint8_t *name)
{
	uint8_t buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)buf;
	struct nhr_data *data;
	struct nhr_alist_item *ali;
	struct ntfs_attr_idx aidx;
	const struct ntfs_attr_hdr *attr;
	unsigned i;
	struct ntfs_mp *tmp_mpl;
	int res;

	data = cache_data_find(bmfte, name_len, name);
	if (data && NHR_FIELD_VALID(&data->sz_alloc) && data->mpl &&
	    data->sz_alloc.val == ntfs_mpl_lclen(data->mpl) * nhr.vol.cls_sz)
		return 0;

	ali = cache_attr_str_find(bmfte, NTFS_ATTR_DATA, name_len, name);
	if (!ali) {
		fprintf(stderr, "mft[#%"PRIu64"]: %ls data info fetch failed: attribute not found\n",
			nhr_mfte_num(bmfte),
			name_len ? name2wchar(name, name_len) : L"<default>");
		return -1;
	}

	if (!data)
		data = cache_data_alloc(bmfte, name_len, name);

	memset(&aidx, 0x00, sizeof(aidx));

	for (; ali; ali = cache_attr_str_next(bmfte, ali)) {
		if (!ali->entity)
			ali->entity = data;
		else
			assert(ali->entity == data);
		if (nhr_mfte_bflags(ali->mfte) & NHR_MFT_FB_SELF)
			continue;
		res = mft_entry_read_and_preprocess(nhr_mfte_num(ali->mfte),
						    ent, 1);
		assert(res == 0);
		ntfs_mft_aidx_get(ent, &aidx);
		for (i = 0; i < aidx.num; ++i) {
			attr = aidx.a[i];
			if (attr->id == ali->id)
				break;
		}
		assert(i != aidx.num);
		assert(attr->nonresident);
		if (ali->firstvcn == 0) {
			NHR_FIELD_UPDATE(&data->sz_alloc, attr->alloc_sz,
					 NHR_SRC_ATTR);
			NHR_FIELD_UPDATE(&data->sz_used, attr->used_sz,
					 NHR_SRC_ATTR);
		}
		tmp_mpl = ntfs_attr_mp_unpack(attr);
		data->mpl = ntfs_mpl_merge(data->mpl, tmp_mpl);
		free(tmp_mpl);
	}

	ntfs_mft_aidx_clean(&aidx);
	return 0;
}
