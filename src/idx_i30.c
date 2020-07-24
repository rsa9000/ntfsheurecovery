/**
 * Directory index specific functions
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

#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "ntfs_struct.h"
#include "ntfs.h"
#include "cache.h"
#include "misc.h"
#include "img.h"
#include "mft_aux.h"
#include "idx_i30.h"

int idx_i30_key_cmp(const void *k1, const void *k2)
{
	const struct ntfs_attr_fname *fn1 = k1;
	const struct ntfs_attr_fname *fn2 = k2;

	return ntfs_name_cmp((uint16_t *)fn1->name, fn1->name_len,
			     (uint16_t *)fn2->name, fn2->name_len,
			     nhr.vol_upcase, nhr.vol_upcase_sz);
}

int idx_i30_key_sz(const void *key)
{
	const struct ntfs_attr_fname *fn = key;

	return NTFS_ATTR_FNAME_LEN(fn);
}

/**
 * Compare two $FILE_NAME attributes from $I30 index entry
 *
 * k1 - data fetch from disk (could be broken)
 * k2 - reconstructed data (should be valid)
 * off_start - valid data start offset (for k1)
 * off_end - valid data end offset (for k2)
 *
 * Returns zero if attributes are equal
 *
 * NB: this function completely ignores access timestamp (see below), if entry
 * is really corrupted or mismatch then other fields will indicate that.
 */
int idx_i30_key_match(const void *k1, const void *k2, unsigned off_start,
		      unsigned off_end)
{
	const struct ntfs_attr_fname *fn = k2;
	int s, e;

	/* Compare part before access timestamp */
	s = 0;
	e = s + __builtin_offsetof(typeof(*fn), time_access);
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e) {
		if (memcmp(k1 + s, k2 + s, e - s) != 0)
			return -1;
	}

	/* Ignore access timestamp since it too oftenly broken :( */

	/* Compare part after access timestamp */
	s = __builtin_offsetof(typeof(*fn), alloc_sz);
	e = NTFS_ATTR_FNAME_LEN(fn);
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e) {
		if (memcmp(k1 + s, k2 + s, e - s) != 0)
			return -1;
	}

	return 0;
}

const wchar_t *idx_i30_entry_name(const struct nhr_idx_entry *idxe)
{
#define NAME_BUF_LEN	265
	static wchar_t buf[NAME_BUF_LEN + 1];
	const struct ntfs_attr_fname *fn = idxe->key;

	assert(fn);

	swprintf(buf, NAME_BUF_LEN, L"%"PRIu64":%ls",
		 NTFS_MREF_ENTNUM(*(uint64_t *)idxe->data),
		 name2wchar(fn->name, fn->name_len));

	return buf;
#undef NAME_BUF_LEN
}

uint64_t idx_i30_blk_mfte_detect(const struct ntfs_idx_rec_hdr *irh)
{
	const struct ntfs_idx_node_hdr *inh = (void *)irh->data;
	const struct ntfs_idx_entry_hdr *ieh_s = (void *)irh->data + inh->off;
	const struct ntfs_idx_entry_hdr *ieh_e = (void *)irh->data + inh->len;
	const struct ntfs_idx_entry_hdr *ieh;
	const struct ntfs_attr_fname *fn;
	uint64_t entnum = 0;

	for (ieh = ieh_s; ieh < ieh_e; ieh = (void *)ieh + ieh->size) {
		if (!ieh->key_sz)
			continue;
		fn = (struct ntfs_attr_fname *)ieh->key;
		if (!entnum)
			entnum = NTFS_MREF_ENTNUM(fn->parent);
		else if (entnum != NTFS_MREF_ENTNUM(fn->parent))
			return 0;
	}

	return entnum;
}

int idx_i30_entry_validate(const struct ntfs_idx_entry_hdr *ieh)
{
	const struct ntfs_attr_fname *fn = (void *)ieh->key;

	/* Verify name type id */
	if (fn->name_type > NTFS_FNAME_T_MAX)
		return 0;
	/* Verify name length value */
	if (ieh->key_sz != NTFS_ATTR_FNAME_LEN(fn))
		return 0;

	return 1;
}

/** Search cached index entry using corrupted index entry */
struct nhr_idx_entry *idx_i30_cache_idxe_find(const struct nhr_idx *idx,
					      const struct ntfs_idx_entry_hdr *ieh,
					      unsigned len)
{
	struct nhr_idx_entry *idxe;
	struct ntfs_attr_fname *fn;

	/**
	 * Manually search index entry using metadata
	 * (target MFT entry number and idx entry size)
	 */
	list_for_each_entry(idxe, &idx->entries, list) {
		if (!idxe->key)
			continue;
		if (*(uint64_t *)idxe->data != ieh->val)
			continue;
		fn = idxe->key;
		if (ieh->key_sz != NTFS_ATTR_FNAME_LEN(fn))
			continue;
		return idxe;
	}

	return NULL;
}

struct idx_i30_mft2ent_ctx {
	uint64_t entnum;
	struct ntfs_attr_idx aidx;
	unsigned cnt_ent;
};

static void idx_i30_mft2ent_proc_data(const struct ntfs_attr_hdr *attr,
				      uint64_t *alloc_sz, uint64_t *used_sz)
{
	if (attr->nonresident) {
		*alloc_sz = attr->flags & NTFS_ATTR_F_COMP ? attr->comp_sz :
							     attr->alloc_sz;
		*used_sz = attr->used_sz;
	} else {
		*alloc_sz = attr->size - attr->data_off;
		*used_sz = attr->data_sz;
	}
}

/** Process extent MFT entry and extract default data stream size */
static void idx_i30_mft2ent_proc_extent(uint64_t entnum, uint64_t *alloc_sz,
					uint64_t *used_sz)
{
	uint8_t buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)buf;
	const struct ntfs_attr_hdr *attr;
	struct ntfs_attr_idx aidx;
	unsigned i;
	int res;

	res = mft_entry_read_and_preprocess(entnum, ent, 1);
	assert(!res);

	memset(&aidx, 0x00, sizeof(aidx));
	ntfs_mft_aidx_get(ent, &aidx);

	for (i = 0; i < aidx.num; ++i) {
		attr = aidx.a[i];
		if (attr->type == NTFS_ATTR_DATA && !attr->name_len) {
			idx_i30_mft2ent_proc_data(attr, alloc_sz, used_sz);
			break;
		}
	}

	ntfs_mft_aidx_clean(&aidx);
}

/** Process base MFT entry and extract main data for directory index key */
static void idx_i30_mft2ent_proc_base(struct ntfs_mft_entry *ent,
				      struct idx_i30_mft2ent_ctx *ctx)
{
	uint64_t pent_num;
	const struct ntfs_attr_hdr *attr;
	const struct ntfs_attr_alist_item *ali_start, *ali_end, *ali;
	struct ntfs_attr_stdinf *si = NULL;
	struct ntfs_mp *alist_mpl;
	void *alist_buf = NULL;
	uint64_t data_entnum = ~0;
	uint64_t data_alloc_sz = 0, data_used_sz = 0;
	struct ntfs_attr_fname *fn;
	struct nhr_mft_entry *pmfte = NULL;
	struct nhr_idx *idx = NULL;
	struct nhr_idx_entry *idxe;
	unsigned i;

	ntfs_mft_aidx_get(ent, &ctx->aidx);

	for (i = 0; i < ctx->aidx.num; ++i) {
		attr = ctx->aidx.a[i];
		if (attr->type == NTFS_ATTR_STDINF) {
			si = NTFS_ATTR_RDATA(attr);
		} else if (attr->type == NTFS_ATTR_ALIST) {
			if (attr->nonresident) {
				alist_mpl = ntfs_attr_mp_unpack(attr);
				alist_buf = malloc(ntfs_mpl_vclen(alist_mpl) *
						   nhr.vol.cls_sz);
				img_fetch_mp_data(alist_mpl, alist_buf);
				free(alist_mpl);
				ali_start = alist_buf;
				ali_end = alist_buf + attr->used_sz;
			} else {
				ali_start = NTFS_ATTR_RDATA(attr);
				ali_end = NTFS_ATTR_RDATA(attr) + attr->data_sz;
			}

			for (ali = ali_start; ali < ali_end;
			     ali = (void *)ali + ali->size) {
				if (ali->type == NTFS_ATTR_DATA &&
				    ali->name_len == 0 && ali->firstvcn == 0) {
					data_entnum = NTFS_MREF_ENTNUM(ali->mref);
					break;
				}
			}

			if (attr->nonresident)
				free(alist_buf);

			if (data_entnum != ctx->entnum)
				break;
			else
				data_entnum = ~0;
		} else if (attr->type == NTFS_ATTR_DATA && !attr->name_len) {
			idx_i30_mft2ent_proc_data(attr, &data_alloc_sz,
						  &data_used_sz);
		}
	}

	if (data_entnum != ~0)
		idx_i30_mft2ent_proc_extent(data_entnum, &data_alloc_sz,
					    &data_used_sz);

	assert(si);

	for (i = 0; i < ctx->aidx.num; ++i) {
		attr = ctx->aidx.a[i];
		if (attr->type < NTFS_ATTR_FNAME)
			continue;
		if (attr->type > NTFS_ATTR_FNAME)
			break;
		fn = NTFS_ATTR_RDATA(attr);
		if (!pmfte) {
			pent_num = NTFS_MREF_ENTNUM(fn->parent);
			pmfte = cache_mfte_find(pent_num);
			if (!pmfte)
				break;
			idx = cache_idx_find(pmfte, NHR_IDX_T_DIR);
			if (!idx)
				break;
		}

		fn = malloc(attr->data_sz);
		memcpy(fn, NTFS_ATTR_RDATA(attr), attr->data_sz);
		fn->time_create = si->time_create;
		fn->time_change = si->time_change;
		fn->time_mft = si->time_mft;
		fn->time_access = si->time_access;
		fn->flags = si->flags;
		if (ent->flags & NTFS_MFT_ENTRY_F_DIR)
			fn->flags |= NTFS_FILE_F_IDX_I30;
		fn->alloc_sz = data_alloc_sz;
		fn->used_sz = data_used_sz;
		idxe = cache_idxe_alloc(idx, fn);
		*(uint64_t *)idxe->data = NTFS_MREF_MAKE(ent->seqno,
							 ctx->entnum);
		ctx->cnt_ent++;
	}
}

/** Process MFT and generate $I30 index entries for indexes of parent entries */
void idx_i30_mft2ent(void)
{
	struct idx_i30_mft2ent_ctx ctx;
	uint8_t ent_buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)ent_buf;
	uint64_t entnum;
	const uint64_t ent_num_max = nhr.vol.mft_sz / nhr.vol.mft_ent_sz;
	struct nhr_mft_entry *mfte;
	unsigned mfte_bflags;
	int res;

	if (nhr.verbose >= 1)
		printf("idx:i30: parse MFT and generate directory entries\n");

	memset(&ctx, 0x00, sizeof(ctx));

	for (entnum = 0; entnum < ent_num_max; ++entnum) {
		if (!(nhr.mft_bitmap[entnum / 8] & (1 << (entnum % 8))))
			continue;
		mfte = cache_mfte_find(entnum);
		mfte_bflags = mfte ? nhr_mfte_bflags(mfte) : 0;

		if (mfte_bflags & NHR_MFT_FB_SELF)
			continue;

		res = mft_entry_read_and_preprocess(entnum, ent, 1);
		assert(!res);

		if (ent->base)
			continue;

		ctx.entnum = entnum;
		idx_i30_mft2ent_proc_base(ent, &ctx);
	}

	ntfs_mft_aidx_clean(&ctx.aidx);

	if (nhr.verbose >= 1)
		printf("idx:i30: generated %u index entries\n", ctx.cnt_ent);
}

/**
 * Process filenames of item cached MFT entry and generate index entries
 * Returns number of generated index entries
 */
static int idx_i30_cache2ent_proc_mfte(struct nhr_mft_entry *pmfte,
				       struct nhr_idx *idx,
				       struct nhr_mft_entry *mfte)
{
	const struct nhr_data *data = cache_data_find(mfte, 0, NULL);	/* Def $DATA stream */
	struct nhr_idx_entry *idxe;
	struct ntfs_attr_fname *fn;
	unsigned i, fnlen;
	int res = 0;

	for (i = 0; i < sizeof(mfte->names)/sizeof(mfte->names[0]); ++i) {
		if (mfte->names[i].src == NHR_SRC_NONE)
			continue;

		fnlen = sizeof(*fn) + mfte->names[i].len * 2;
		fn = calloc(1, fnlen);
		fn->parent = NTFS_MREF_MAKE(pmfte->seqno.val,
					    nhr_mfte_num(pmfte));
		if (NHR_FIELD_VALID(&mfte->time_create))
			fn->time_create = mfte->time_create.val;
		if (NHR_FIELD_VALID(&mfte->time_change))
			fn->time_change = mfte->time_change.val;
		if (NHR_FIELD_VALID(&mfte->time_mft))
			fn->time_mft = mfte->time_mft.val;
		if (NHR_FIELD_VALID(&mfte->time_access))
			fn->time_access = mfte->time_access.val;
		if (data) {
			if (NHR_FIELD_VALID(&data->sz_alloc))
				fn->alloc_sz = data->sz_alloc.val;
			if (NHR_FIELD_VALID(&data->sz_used))
				fn->used_sz = data->sz_used.val;
		}
		if (NHR_FIELD_VALID(&mfte->fileflags))
			fn->flags = mfte->fileflags.val;
		fn->name_type = i;
		fn->name_len = mfte->names[i].len;
		memcpy(fn->name, mfte->names[i].name,
		       mfte->names[i].len * 2);
		idxe = cache_idxe_alloc(idx, fn);
		*(uint64_t *)idxe->data = NTFS_MREF_MAKE(mfte->seqno.val,
							 nhr_mfte_num(mfte));
		res++;
	}

	return res;
}

/** Process MFT entries cache and generates $I30 index entries */
void idx_i30_cache2ent(void)
{
	struct nhr_mft_entry *mfte;
	struct nhr_mft_entry *pmfte;
	struct nhr_idx *idx;
	unsigned ent_tot = 0, ent_ok = 0, idxe_ok = 0;
	int res;

	if (nhr.verbose >= 1)
		printf("idx:i30: build entries from MFT cache\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(nhr_mfte_bflags(mfte) & NHR_MFT_FB_SELF))
			continue;
		if (!(mfte->f_cmn & NHR_MFT_FC_BASE))
			continue;
		ent_tot++;
		if (!NHR_FIELD_VALID(&mfte->parent))
			continue;
		pmfte = cache_mfte_find(mfte->parent.val);
		if (!pmfte)
			continue;
		idx = cache_idx_find(pmfte, NHR_IDX_T_DIR);
		if (!idx)
			continue;
		res = idx_i30_cache2ent_proc_mfte(pmfte, idx, mfte);
		if (res > 0) {
			ent_ok++;
			idxe_ok++;
		}
	}

	if (nhr.verbose >= 1)
		printf("idx:i30: processed %u cached MFT entries, generated %u index entries for %u of them\n",
		       ent_tot, ent_ok, idxe_ok);
}
