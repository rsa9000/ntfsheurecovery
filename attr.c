/**
 * MFT entry attributes handling code (except parsing)
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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "ntfs_struct.h"
#include "cache.h"
#include "idx.h"
#include "idx_aux.h"
#include "misc.h"
#include "attr.h"

/** Checks whether we can recover $ATTRIBUTE_LIST or no */
static int attr_alist_recover_prerequisite(const struct nhr_mft_entry *mfte,
					   const struct nhr_alist_item *ali)
{
	const struct nhr_mft_entry *__mfte;
	int res = 0;

	if (ali->mfte != mfte->bmfte) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: attribute should be allocated within base entry\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	if (list_empty(&mfte->ext)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: file does not have extent entries\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	list_for_each_entry(__mfte, &mfte->ext, ext) {
		if (__mfte->seqno.src != NHR_SRC_NONE)
			continue;
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: required seqno for extent entry #%"PRIu64" is unknown\n",
			       nhr_mfte_num(mfte), ali->type, ali->id,
			       nhr_mfte_num(__mfte));
		res = -1;
	}

	return res;
}

/** Build $ATTRIBUTE_LIST attribute data */
static int attr_alist_recover_data(const struct nhr_mft_entry *mfte,
				   const struct nhr_alist_item *ali,
				   struct ntfs_attr_hdr *attr, int size)
{
	int __size = size;
	const struct nhr_alist_item *__ali;
	struct ntfs_attr_alist_item *_ali = NTFS_ATTR_RDATA(attr);

	list_for_each_entry(__ali, &mfte->alist, list) {
		if (__ali->type == NTFS_ATTR_ALIST)
			continue;
		if (__size < sizeof(*_ali) + __ali->name_len * 2)
			return -1;
		_ali->type = __ali->type;
		_ali->size = NTFS_ALIGN(sizeof(*_ali) + __ali->name_len * 2);
		_ali->name_len = __ali->name_len;
		if (_ali->name_len) {
			_ali->name_off = sizeof(*_ali);
			memcpy(NTFS_ATTR_ALI_NAME(_ali), __ali->name,
			       __ali->name_len * 2);
		}
		_ali->firstvcn = __ali->firstvcn;
		_ali->mref = NTFS_MREF_MAKE(__ali->mfte->seqno.val,
					    nhr_mfte_num(__ali->mfte));
		_ali->id = __ali->id;

		__size -= _ali->size;
		_ali = (void *)_ali + _ali->size;
	}

	return size - __size;
}

/**
 * Checks whether we can recover $STANDARD_INFO attribute or no
 */
static int attr_stdinf_recover_prerequisite(const struct nhr_mft_entry *mfte,
					    const struct nhr_alist_item *ali)
{
	if (!NHR_FIELD_VALID(&mfte->time_create)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: create time info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	if (!NHR_FIELD_VALID(&mfte->time_change)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: change time info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	if (!NHR_FIELD_VALID(&mfte->time_mft)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: MFT change time info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	if (!NHR_FIELD_VALID(&mfte->time_access)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: access time info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	if (!NHR_FIELD_VALID(&mfte->fileflags)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: file flags info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	if (!NHR_FIELD_VALID(&mfte->sid)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: security identifier (SID) info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}

	return 0;
}

/**
 * Build $STANDARD_INFO attribute data
 */
static int attr_stdinf_recover_data(const struct nhr_mft_entry *mfte,
				    const struct nhr_alist_item *ali,
				    struct ntfs_attr_hdr *attr, int size)
{
	struct ntfs_attr_stdinf *si = NTFS_ATTR_RDATA(attr);

	if (size < sizeof(*si))
		return -1;

	si->time_create = mfte->time_create.val;
	si->time_change = mfte->time_change.val;
	si->time_mft = mfte->time_mft.val;
	si->time_access = mfte->time_access.val;
	si->flags = mfte->fileflags.val & ~(NTFS_FILE_F_IDX_I30 | NTFS_FILE_F_IDX_VIEW);
	si->ver_max = 0;	/* ??? */
	si->ver_num = 0;	/* ??? */
	si->class_id = 0;	/* Always */
	si->owner_id = 0;	/* TODO */
	si->security_id = mfte->sid.val;
	si->quotta = 0;		/* TODO */
	si->usn = 0;		/* TODO */

	return sizeof(*si);
}

/** Find file name for item $FILE_NAME attribute */
static int attr_fname_entity_bind(struct nhr_mft_entry *mfte,
				  struct nhr_alist_item *ali)
{
	const struct nhr_alist_item *ali_prev = NULL;
	const struct nhr_alist_item *ali_next = NULL;
	unsigned i;

	for (i = 0; i < sizeof(mfte->names)/sizeof(mfte->names[0]); ++i) {
		if (ali->id == mfte->names[i].attr_id) {
			ali->entity = &mfte->names[i];
			break;
		}
	}
	if (ali->entity)
		return 0;

	ali_prev = list_prev_entry(ali, list);
	if (&ali_prev->list == &mfte->alist || ali_prev->type != NTFS_ATTR_FNAME)
		ali_prev = NULL;
	ali_next = list_next_entry(ali, list);
	if (&ali_next->list == &mfte->alist || ali_next->type != NTFS_ATTR_FNAME)
		ali_prev = NULL;

	if (ali_prev == NULL && ali_next == NULL) {
		ali->entity = &mfte->names[NTFS_FNAME_T_WIN32DOS];
	} else if (ali_prev == NULL && ali_next &&
		   (!ali_next->entity ||
		    ali_next->entity == &mfte->names[NTFS_FNAME_T_WIN32])) {
		ali->entity = &mfte->names[NTFS_FNAME_T_DOS];
	} else if (ali_prev && ali_next == NULL &&
		   ali_prev->entity == &mfte->names[NTFS_FNAME_T_DOS]) {
		ali->entity = &mfte->names[NTFS_FNAME_T_WIN32];
	} else {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: unsupported name attributes combination case\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}

	return 0;
}

/** Get index of specified file name */
static int attr_fname_entity_idx(const struct nhr_mft_entry *mfte,
				 const void *entity)
{
	return (struct nhr_mfte_fn *)entity - &mfte->names[0];
}

/** Check whether attribute reffer correct filename or no */
static int attr_fname_entity_check(const struct nhr_mft_entry *mfte,
				   const struct nhr_alist_item *ali)
{
	return 0;
}

/**
 * Checks whether we can recover $FILE_NAME attribute or no
 */
static int attr_fname_recover_prerequisite(const struct nhr_mft_entry *mfte,
					   const struct nhr_alist_item *ali)
{
	struct nhr_mft_entry *pmfte;
	struct nhr_mfte_fn *mfn = ali->entity;

	if (mfn->src == NHR_SRC_NONE) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: name of type %"PRIuPTR" is unknown\n",
			       nhr_mfte_num(mfte), ali->type, ali->id,
			       mfn - &mfte->names[0]);
		return -1;
	}
	if (!NHR_FIELD_VALID(&mfte->parent)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: parent entry info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	pmfte = cache_mfte_find(mfte->parent.val);
	if (!pmfte) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: parent entry not found in cache\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	if (!NHR_FIELD_VALID(&pmfte->seqno)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: parent entry seqno info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	if (!NHR_FIELD_VALID(&mfte->time_create)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: create time info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}
	if (!NHR_FIELD_VALID(&mfte->fileflags)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: file flags info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}

	return 0;
}

/**
 * Build $FILE_NAME attribute data
 */
static int attr_fname_recover_data(const struct nhr_mft_entry *mfte,
				   const struct nhr_alist_item *ali,
				   struct ntfs_attr_hdr *attr, int size)
{
	struct nhr_mft_entry *pmfte = cache_mfte_find(mfte->parent.val);
	struct ntfs_attr_fname *fn = NTFS_ATTR_RDATA(attr);
	struct nhr_mfte_fn *mfn = ali->entity;

	assert(pmfte);

	if (size < sizeof(*fn) + NTFS_ALIGN(mfn->len * 2))
		return -1;

	attr->rflags |= NTFS_ATTR_RF_IDX;	/* $FILE_NAME always indexed */

	fn->parent = NTFS_MREF_MAKE(pmfte->seqno.val, nhr_mfte_num(pmfte));
	fn->time_create = mfte->time_create.val;
	fn->time_change = mfte->time_create.val;
	fn->time_mft = mfte->time_create.val;
	fn->time_access = mfte->time_create.val;
	fn->alloc_sz = 0;
	fn->used_sz = 0;
	fn->flags = mfte->fileflags.val;
	fn->reparse_point = 0;
	fn->name_type = mfn - &mfte->names[0];
	fn->name_len = mfn->len;
	memcpy(fn->name, mfn->name, fn->name_len * 2);

	return NTFS_ATTR_FNAME_LEN(fn);
}

/**
 * Checks whether we can recover $OBJECT_IDENTITY attribute or no
 */
static int attr_oid_recover_prerequisite(const struct nhr_mft_entry *mfte,
					 const struct nhr_alist_item *ali)
{
	if (mfte->oid_src == NHR_SRC_NONE) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u]: object id info missed\n",
			       nhr_mfte_num(mfte), ali->type, ali->id);
		return -1;
	}

	return 0;
}

/**
 * Build $OBJECT_IDENTITY attribute data
 */
static int attr_oid_recover_data(const struct nhr_mft_entry *mfte,
				 const struct nhr_alist_item *ali,
				 struct ntfs_attr_hdr *attr, int size)
{
	struct ntfs_attr_oid *oid = NTFS_ATTR_RDATA(attr);

	if (size < sizeof(oid->obj_id))
		return -1;

	/* When we should fill other fields? */
	memcpy(&oid->obj_id, &mfte->oid->obj_id, sizeof(oid->obj_id));

	return sizeof(oid->obj_id);
}

/** Find coresponding data stream and assign to attribute */
static int attr_data_entity_bind(struct nhr_mft_entry *mfte,
				 struct nhr_alist_item *ali)
{
	struct nhr_data *data;
	struct nhr_str_segm *segm;

	data = cache_data_find(mfte, ali->name_len, ali->name);
	if (!data) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u,%ls]: could not find corresponding data stream\n",
			       nhr_mfte_num(mfte), ali->type, ali->id,
			       cache_attr_name(ali));
		return -1;
	}

	ali->entity = data;

	segm = cache_data_segm_find(data, ali->firstvcn);
	if (segm) {
		segm->ali = ali;
	} else {
		assert(!(data->flags & NHR_DATA_F_VALID) || data->sz_alloc.val < nhr.vol.cls_sz);
	}

	return 0;
}

/** Get index of specified data stream */
static int attr_data_entity_idx(const struct nhr_mft_entry *mfte,
				const void *entity)
{
	return cache_data_idx(mfte, entity);
}

/** Check whether attribute reffer correct data stream or no */
static int attr_data_entity_check(const struct nhr_mft_entry *mfte,
				  const struct nhr_alist_item *ali)
{
	const struct nhr_data *data = ali->entity;

	if (data->name_len != ali->name_len ||
	    memcmp(data->name, ali->name, data->name_len) != 0) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64"(#%"PRIu64",%u),0x%02X,%ls]: invalid name, expect '%ls'\n",
			       nhr_mfte_num(mfte), nhr_mfte_num(ali->mfte),
			       ali->id, ali->type, cache_attr_name(ali),
			       cache_data_name(data));
		return -1;
	}

	return 0;
}

/**
 * Checks whether we can recover $DATA attribute or no
 */
static int attr_data_recover_prerequisite(const struct nhr_mft_entry *mfte,
					  const struct nhr_alist_item *ali)
{
	const struct nhr_data *data = ali->entity;
	const struct nhr_str_segm *segm;
	const struct ntfs_mp *mp;
	unsigned mpl_len;

	if (!(data->flags & NHR_DATA_F_VALID)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u,%ls]: data stream not marked as valid\n",
			       nhr_mfte_num(mfte), ali->type, ali->id,
			       cache_attr_name(ali));
		return -1;
	}

	if (data->sz_alloc.val >= nhr.vol.cls_sz) {
		segm = cache_data_segm_find(data, ali->firstvcn);
		assert(segm);
		mpl_len = ntfs_mpl_len(data->mpl);
		mp = ntfs_mpl_find(data->mpl, mpl_len, segm->firstvcn.val);
		if (mp->vcn != segm->firstvcn.val) {
			if (nhr.verbose >= 3)
				printf("attr[#%"PRIu64",0x%02X,%u,%ls]: first VCN 0x%08"PRIX64" points inside mapping pair [0x%08"PRIX64":0x%08"PRIX64"]\n",
				       nhr_mfte_num(mfte), ali->type, ali->id,
				       cache_attr_name(ali), segm->firstvcn.val,
				       mp->vcn, mp->vcn + mp->clen - 1);
			return -1;
		}
		mp = ntfs_mpl_find(data->mpl, mpl_len, segm->lastvcn.val);
		if (mp->vcn + mp->clen - 1 != segm->lastvcn.val) {
			if (nhr.verbose >= 3)
				printf("attr[#%"PRIu64",0x%02X,%u,%ls]: last VCN 0x%08"PRIX64" points inside mapping pair [0x%08"PRIX64":0x%08"PRIX64"]\n",
				       nhr_mfte_num(mfte), ali->type, ali->id,
				       cache_attr_name(ali), segm->lastvcn.val,
				       mp->vcn, mp->vcn + mp->clen - 1);
			return -1;
		}
	}

	return 0;
}

/**
 * Begin $DATA attribute recover
 */
static int attr_data_recover_hdr(const struct nhr_mft_entry *mfte,
				 const struct nhr_alist_item *ali,
				 struct ntfs_attr_hdr *attr)
{
	const struct nhr_data *data = ali->entity;

	if (data->sz_alloc.val >= nhr.vol.cls_sz) {
		attr->nonresident = 1;
		if (data->flags & NHR_DATA_F_COMP)
			attr->flags |= NTFS_ATTR_F_COMP;
	} else {
		attr->nonresident = 0;
	}

	return 0;
}

/**
 * Build $DATA attribute main content
 */
static int attr_data_recover_data(const struct nhr_mft_entry *mfte,
				  const struct nhr_alist_item *ali,
				  struct ntfs_attr_hdr *attr, int size)
{
	const struct nhr_data *data = ali->entity;
	struct ntfs_mp *mpl;
	const struct nhr_str_segm *segm;
	const struct nhr_data_chunk *chunk;
	void *p;
	int res;

	if (attr->nonresident) {
		assert(data && data->mpl);
		segm = cache_data_segm_find(data, ali->firstvcn);
		if (segm->firstvcn.val == 0 &&
		    segm->lastvcn.val == ntfs_mpl_vclen(data->mpl) - 1)
			mpl = data->mpl;
		else
			mpl = ntfs_mpl_extr(data->mpl, segm->firstvcn.val,
					    segm->lastvcn.val);
		res = ntfs_mpl_packed_len(mpl);
		if (res < 0 || size < res) {
			if (mpl != data->mpl)
				free(mpl);
			return -1;
		}
		attr->firstvcn = segm->firstvcn.val;
		attr->lastvcn = segm->lastvcn.val;
		if (data->flags & NHR_DATA_F_COMP)
			attr->cblk_sz = 4;	/* 2^4 = 16 clusters */
		if (attr->firstvcn == 0) {
			if (data->flags & NHR_DATA_F_COMP) {
				attr->alloc_sz = ntfs_mpl_vclen(data->mpl) *
						 nhr.vol.cls_sz;
				attr->comp_sz = data->sz_alloc.val;
			} else {
				attr->alloc_sz = data->sz_alloc.val;
			}
			attr->used_sz = data->sz_used.val;
			attr->init_sz = data->sz_init.val;
		}
		res = ntfs_mpl_pack(mpl, NTFS_ATTR_MPL(attr));
		if (mpl != data->mpl)
			free(mpl);
		return res;
	} else {
		if (data->sz_alloc.val > size)
			return -1;

		/* Looks like $DATA attribute should always have name_off */
		if (attr->name_len == 0)
			attr->name_off = attr->data_off;

		p = NTFS_ATTR_RDATA(attr);
		list_for_each_entry(chunk, &data->chunks, list) {
			memcpy(p, chunk->buf, chunk->len);
			p += chunk->len;
		}

		return p - NTFS_ATTR_RDATA(attr);
	}
}

/** Find coresponding index (by name) and assign to attribute */
static int attr_idx_entity_bind(struct nhr_mft_entry *mfte,
				struct nhr_alist_item *ali)
{
	int type = idx_detect_type(ali->name_len, ali->name);
	struct nhr_idx *idx;

	if (type == NHR_IDX_T_UNKN) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u,%ls]: unknown index type\n",
			       nhr_mfte_num(mfte), ali->type, ali->id,
			       cache_attr_name(ali));
		return -1;
	}

	idx = cache_idx_find(mfte, type);
	if (!idx) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u,%ls]: could not find corresponding index\n",
			       nhr_mfte_num(mfte), ali->type, ali->id,
			       cache_attr_name(ali));
		return -1;
	}

	ali->entity = idx;

	return 0;
}

/** Get index of specified index */
static int attr_idx_entity_idx(const struct nhr_mft_entry *mfte,
			       const void *entity)
{
	return cache_idx_idx(mfte, entity);
}

/** Check whether attribute reffer to correct index or no */
static int attr_idx_entity_check(const struct nhr_mft_entry *mfte,
				 const struct nhr_alist_item *ali)
{
	const struct nhr_idx *idx = ali->entity;

	if (idx->info->name_len != ali->name_len ||
	    memcmp(idx->info->name, ali->name, ali->name_len * 2) != 0) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64"(#%"PRIu64",%u),0x%02X,%ls]: invalid name, expect '%ls'\n",
			       nhr_mfte_num(mfte), nhr_mfte_num(ali->mfte),
			       ali->id, ali->type, cache_attr_name(ali),
			       cache_idx_name(idx));
		return -1;
	}

	return 0;
}

/** Checks whether we can recover index related attribute or no */
static int attr_idx_recover_prerequisite(const struct nhr_mft_entry *mfte,
					 const struct nhr_alist_item *ali,
					 const struct nhr_idx *idx)
{
	if (!(idx->flags & NHR_IDX_F_VALID)) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u,%ls]: index not marked as valid\n",
			       nhr_mfte_num(mfte), ali->type, ali->id,
			       cache_attr_name(ali));
		return -1;
	}

	return 0;
}

/** Checks whether we can recover $INDEX_ROOT attribute or no */
static int attr_iroot_recover_prerequisite(const struct nhr_mft_entry *mfte,
					   const struct nhr_alist_item *ali)
{
	const struct nhr_idx *idx = ali->entity;
	int res;

	res = attr_idx_recover_prerequisite(mfte, ali, idx);
	if (res)
		return res;

	return 0;
}

/** Build $INDEX_ROOT attribute main content */
static int attr_iroot_recover_data(const struct nhr_mft_entry *mfte,
				   const struct nhr_alist_item *ali,
				   struct ntfs_attr_hdr *attr, int size)
{
	const struct nhr_idx *idx = ali->entity;
	const struct nhr_idx_entry *idxe;
	struct ntfs_attr_iroot *ir = NTFS_ATTR_RDATA(attr);
	struct ntfs_idx_node_hdr *inh = (void *)ir->data;
	struct ntfs_idx_entry_hdr *ieh;

	/* Fill $INDEX_ROOT attribute header */
	if (size < sizeof(*ir))
		return -1;

	ir->idx_attr = idx->info->attr;
	ir->idx_sort = idx->info->sort;
	ir->idx_blk_sz = nhr.vol.idx_blk_sz;
	ir->idx_blk_csz = nhr.vol.idx_blk_csz;
	size -= sizeof(*ir);

	/* Fill index node header */
	if (size < sizeof(*inh))
		return -1;

	inh->off = sizeof(*inh);
	inh->flags = idx->root->flags & NHR_IDXN_F_NODE ?
		     NTFS_IDX_NODE_F_CHILD : 0;
	size -= sizeof(*inh);

	/* Generate index entries */
	ieh = (void *)inh + inh->off;
	list_for_each_entry(idxe, &idx->entries, list) {
		if (idxe->container != idx->root)
			continue;
		/* Fill index entry header */
		if (size < sizeof(*ieh))
			return -1;
		ieh->size = sizeof(*ieh);
		if (idxe->key) {
			ieh->key_sz = idx_key_sz(idx, idxe->key);
			ieh->size += ieh->key_sz;
			if (idx->info->data_sz) {
				ieh->data_off = ieh->size;
				ieh->data_sz = idx->info->data_sz;
				ieh->size += ieh->data_sz;
			}
		} else {
			ieh->key_sz = 0;
			ieh->flags |= NTFS_IDX_ENTRY_F_LAST;
		}
		ieh->size = NTFS_ALIGN(ieh->size);
		if (NHR_IDXN_PTR_VALID(idxe->child)) {
			ieh->size += sizeof(uint64_t);
			ieh->flags |= NTFS_IDX_ENTRY_F_CHILD;
		}
		/* Add key and data */
		size -= ieh->size;
		if (size < 0)
			return -1;
		if (idxe->key) {
			memcpy(ieh->key, idxe->key, ieh->key_sz);
			if (idx->info->data_sz)
				memcpy(ntfs_idx_entry_data(ieh), idxe->data,
				       ieh->data_sz);
			else
				memcpy(&ieh->val, idxe->data, sizeof(ieh->val));
		} else {
			ieh->val = 0;
		}
		/* Add child index record link */
		if (NHR_IDXN_PTR_VALID(idxe->child))
			ntfs_idx_entry_child_vcn(ieh) = idxe->child->vcn;
		/* Go to next index entry */
		ieh = (void *)ieh + ieh->size;
		if (!idxe->key)
			break;
	}

	/* Finish index node header filling */
	inh->len = (void *)ieh - (void *)inh;
	inh->alloc_sz = inh->len;

	return sizeof(*ir) + inh->len;
}

/** Checks whether we can recover $INDEX_ALLOCATION attribute or no */
static int attr_ialloc_recover_prerequisite(const struct nhr_mft_entry *mfte,
					    const struct nhr_alist_item *ali)
{
	const struct nhr_idx *idx = ali->entity;
	int res;

	res = attr_idx_recover_prerequisite(mfte, ali, idx);
	if (res)
		return res;

	if (ali->firstvcn) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64",0x%02X,%u,%ls]: fragmented streams not supported\n",
			       nhr_mfte_num(mfte), ali->type, ali->id,
			       cache_attr_name(ali));
		return -1;
	}

	return 0;
}

/** Begin $INDEX_ALLOCATION attribute recover */
static int attr_ialloc_recover_hdr(const struct nhr_mft_entry *mfte,
				   const struct nhr_alist_item *ali,
				   struct ntfs_attr_hdr *attr)
{
	attr->nonresident = 1;	/* Always non-resident */

	return 0;
}

/** Build $INDEX_ALLOCATION attribute main content */
static int attr_ialloc_recover_data(const struct nhr_mft_entry *mfte,
				    const struct nhr_alist_item *ali,
				    struct ntfs_attr_hdr *attr, int size)
{
	const struct nhr_idx *idx = ali->entity;
	struct ntfs_mp *mpl = idx_blocks2mpl(idx);
	uint64_t clen;
	int res;

	assert(ali->firstvcn == 0);

	if (!mpl)
		return -1;

	res = ntfs_mpl_packed_len(mpl);
	if (res < 0 || size < res) {
		free(mpl);
		return -1;
	}

	clen = ntfs_mpl_lclen(mpl);

	attr->firstvcn = mpl->vcn;
	attr->lastvcn = attr->firstvcn + clen - 1;
	attr->alloc_sz = clen * nhr.vol.cls_sz;
	attr->used_sz = attr->alloc_sz;
	attr->init_sz = attr->alloc_sz;

	res = ntfs_mpl_pack(mpl, NTFS_ATTR_MPL(attr));

	free(mpl);

	return res;
}

/** Checks whether we can recover $BITMAP attribute or no */
static int attr_bitmap_recover_prerequisite(const struct nhr_mft_entry *mfte,
					    const struct nhr_alist_item *ali)
{
	const struct nhr_idx *idx = ali->entity;
	int res;

	res = attr_idx_recover_prerequisite(mfte, ali, idx);
	if (res)
		return res;

	return 0;
}

/** Build $BITMAP attribute main content */
static int attr_bitmap_recover_data(const struct nhr_mft_entry *mfte,
				    const struct nhr_alist_item *ali,
				    struct ntfs_attr_hdr *attr, int size)
{
	const struct nhr_idx *idx = ali->entity;
	const struct nhr_idx_node *idxn;
	uint8_t *bm = NTFS_ATTR_RDATA(attr);
	int len = 0;

	idxn = list_last_entry(&idx->nodes, typeof(*idxn), list);
	if (idxn->vcn < 0)
		return -1;

	len = (idxn->vcn + 1 + 7) / 8;
	len = NTFS_ALIGN(len);
	if (len > size)
		return -1;

	list_for_each_entry(idxn, &idx->nodes, list) {
		if (idxn->vcn < 0 || !(idxn->flags & NHR_IDXN_F_INUSE))
			continue;
		bm[idxn->vcn / 8] |= 1 << idxn->vcn % 8;
	}

	return len;
}

static const struct nhr_attr_info attr_infos[] = {
	[NTFS_ATTR_STDINF / 0x10] = {
		.type = NTFS_ATTR_STDINF,
		.title = "$STANDARD_INFORMATION",
		.flags = NHR_ATTR_F_UNIQ | NHR_ATTR_F_RESIDENT | NHR_ATTR_F_MANDATORY,
		.recover_prerequisite = attr_stdinf_recover_prerequisite,
		.recover_data = attr_stdinf_recover_data,
	},
	[NTFS_ATTR_ALIST / 0x10] = {
		.type = NTFS_ATTR_ALIST,
		.title = "$ATTRIBUTE_LIST",
		.flags = NHR_ATTR_F_UNIQ,
		.recover_prerequisite = attr_alist_recover_prerequisite,
		.recover_data = attr_alist_recover_data,
	},
	[NTFS_ATTR_FNAME / 0x10] = {
		.type = NTFS_ATTR_FNAME,
		.title = "$FILE_NAME",
		.flags = NHR_ATTR_F_RESIDENT | NHR_ATTR_F_MANDATORY,
		.entity_bind = attr_fname_entity_bind,
		.entity_idx = attr_fname_entity_idx,
		.entity_check = attr_fname_entity_check,
		.recover_prerequisite = attr_fname_recover_prerequisite,
		.recover_data = attr_fname_recover_data,
	},
	[NTFS_ATTR_OID / 0x10] = {
		.type = NTFS_ATTR_OID,
		.title = "$OBJECT_ID",
		.flags = NHR_ATTR_F_UNIQ | NHR_ATTR_F_RESIDENT,
		.recover_prerequisite = attr_oid_recover_prerequisite,
		.recover_data = attr_oid_recover_data,
	},
	[NTFS_ATTR_DATA / 0x10] = {
		.type = NTFS_ATTR_DATA,
		.title = "$DATA",
		.entity_bind = attr_data_entity_bind,
		.entity_idx = attr_data_entity_idx,
		.entity_check = attr_data_entity_check,
		.recover_prerequisite = attr_data_recover_prerequisite,
		.recover_hdr = attr_data_recover_hdr,
		.recover_data = attr_data_recover_data,
	},
	[NTFS_ATTR_IROOT / 0x10] = {
		.type = NTFS_ATTR_IROOT,
		.title = "$INDEX_ROOT",
		.flags = NHR_ATTR_F_RESIDENT,
		.entity_bind = attr_idx_entity_bind,
		.entity_idx = attr_idx_entity_idx,
		.entity_check = attr_idx_entity_check,
		.recover_prerequisite = attr_iroot_recover_prerequisite,
		.recover_data = attr_iroot_recover_data,
	},
	[NTFS_ATTR_IALLOC / 0x10] = {
		.type = NTFS_ATTR_IALLOC,
		.title = "$INDEX_ALLOCATION",
		.entity_bind = attr_idx_entity_bind,
		.entity_idx = attr_idx_entity_idx,
		.entity_check = attr_idx_entity_check,
		.recover_prerequisite = attr_ialloc_recover_prerequisite,
		.recover_hdr = attr_ialloc_recover_hdr,
		.recover_data = attr_ialloc_recover_data,
	},
	[NTFS_ATTR_BITMAP / 0x10] = {
		.type = NTFS_ATTR_BITMAP,
		.title = "$BITMAP",
		.entity_bind = attr_idx_entity_bind,
		.entity_idx = attr_idx_entity_idx,
		.entity_check = attr_idx_entity_check,
		.recover_prerequisite = attr_bitmap_recover_prerequisite,
		.recover_data = attr_bitmap_recover_data,
	},
};

static const int attr_infos_len = sizeof(attr_infos)/sizeof(attr_infos[0]);

const struct nhr_attr_info *attr_get_info(unsigned type)
{
	unsigned idx;

	if (type % 0x10)
		return NULL;

	idx = type / 0x10;
	if (idx >= attr_infos_len)
		return NULL;

	if (attr_infos[idx].type != type)
		return NULL;

	return &attr_infos[idx];
}

/** Get attribute type code by attribute title (name) */
uint16_t attr_title2type(const char *title)
{
	unsigned i;

	for (i = 0; i < attr_infos_len; ++i) {
		if (!attr_infos[i].type)
			continue;
		if (strcmp(attr_infos[i].title, title) == 0)
			return attr_infos[i].type;
	}

	return 0;
}

/**
 * Checks whether attribute list Ok or no
 *
 * This function should do several kinds of checks:
 * - check that list valid themself (no duplicates, etc)
 * - check that attributes list contains all mandatory attributes
 * - check that appropriate attributes exists for each known entity (data,
 *   indexes, etc.)
 *
 * Returns zero if attributes list Ok and -1 otherwise
 */
static int attr_verify_mfte(const struct nhr_mft_entry *mfte)
{
	unsigned i;
	unsigned types_mask = 0;
	unsigned last_type = 0;
	const struct nhr_attr_info *ai;
	const struct nhr_alist_item *ali, *__ali, *ali_prev = NULL;

	list_for_each_entry(ali, &mfte->alist, list) {
		ai = attr_get_info(ali->type);
		if (!ai) {
			if (nhr.verbose >= 3)
				printf("attr[#%"PRIu64"(#%"PRIu64",%u),0x%02X]: uknown attribute type\n",
				       nhr_mfte_num(mfte),
				       nhr_mfte_num(ali->mfte), ali->id,
				       ali->type);
			return -1;
		}

		/* Check attribute singleness */
		if (ai->flags & NHR_ATTR_F_UNIQ) {
			if (types_mask & (1 << ali->type / 0x10)) {
				if (nhr.verbose >= 3)
					printf("attr[#%"PRIu64"]: multiple occurance of %s (0x%02X) attribute, which should be unique\n",
					       nhr_mfte_num(mfte), ai->title,
					       ali->type);
				return -1;
			}
		} else {
			if (!ali->entity) {
				if (nhr.verbose >= 3)
					printf("attr[#%"PRIu64"(#%"PRIu64",%u),0x%02X,%ls]: unbinded attribute\n",
					       nhr_mfte_num(mfte),
					       nhr_mfte_num(ali->mfte), ali->id,
					       ali->type, cache_attr_name(ali));
				return -1;
			}
			if (ai->entity_check(mfte, ali) != 0) {
				if (nhr.verbose >= 3)
					printf("attr[#%"PRIu64"(#%"PRIu64",%u),0x%02X,%ls]: invalid entity bind\n",
					       nhr_mfte_num(mfte),
					       nhr_mfte_num(ali->mfte), ali->id,
					       ali->type, cache_attr_name(ali));
				return -1;
			}
		}
		types_mask |= 1 << ali->type / 0x10;

		/* Check attributes by-type ordering */
		if (ali->type < last_type) {
			if (nhr.verbose >= 3)
				printf("attr[#%"PRIu64"]: invalid attributes order: 0x%02X goes after 0x%02X\n",
				       nhr_mfte_num(mfte), ali->type,
				       last_type);
			return -1;
		}
		last_type = ali->type;

		/* Check attributes by-VCN ordering */
		if (ai->flags & NHR_ATTR_F_RESIDENT) {
			ali_prev = NULL;
		} else {
			if (ali_prev && (ali_prev->type != ali->type ||
			    ali_prev->name_len != ali->name_len ||
			    memcmp(ali_prev->name, ali->name, ali->name_len)))
					ali_prev = NULL;
			if (ali_prev) {	/* Stream continuation */
				if (ali->firstvcn <= ali_prev->firstvcn) {
					if (nhr.verbose >= 3)
						printf("attr[#%"PRIu64",0x%02X,%ls]: invalid attributes order: %"PRIu64" position goes after %"PRIu64" position\n",
						       nhr_mfte_num(mfte),
						       ali->type,
						       cache_attr_name(ali),
						       ali->firstvcn,
						       ali_prev->firstvcn);
					return -1;
				}
			} else {	/* Stream begining */
				if (ali->firstvcn) {
					if (nhr.verbose >= 3)
						printf("attr[#%"PRIu64",0x%02X,%ls]: stream begins from non-zero (%"PRIu64") cluster\n",
						       nhr_mfte_num(mfte),
						       ali->type,
						       cache_attr_name(ali),
						       ali->firstvcn);
					return -1;
				}
			}
			ali_prev = ali;
		}

		/* Check attributes id unique */
		for (__ali = list_next_entry(ali, list);
		     &__ali->list != &mfte->alist;
		     __ali = list_next_entry(__ali, list)) {
			if (ali->mfte != __ali->mfte)
				continue;
			if (ali->id != __ali->id)
				continue;
			if (nhr.verbose >= 3)
				printf("attr[#%"PRIu64"(#%"PRIu64")]: attributes 0x%02X and 0x%02X have the same id %u\n",
				       nhr_mfte_num(mfte),
				       nhr_mfte_num(ali->mfte), ali->type,
				       __ali->type, ali->id);
			return -1;
		}

		/* Search duplicated attribute */
		for (__ali = list_next_entry(ali, list);
		     &__ali->list != &mfte->alist;
		     __ali = list_next_entry(__ali, list)) {
			if (ali->type != __ali->type)
				continue;
			if (ali->firstvcn != __ali->firstvcn)
				continue;
			if (ali->entity != __ali->entity)
				continue;
			if (nhr.verbose >= 3)
				printf("attr[#%"PRIu64"]: detect duplicated attributes {#%"PRIu64",0x%02X,%u} and {#%"PRIu64",0x%02X,%u}, name: %ls, VCN: %"PRIu64"\n",
				       nhr_mfte_num(mfte),
				       nhr_mfte_num(ali->mfte), ali->type,
				       ali->id,
				       nhr_mfte_num(__ali->mfte), __ali->type,
				       __ali->id, cache_attr_name(ali),
				       ali->firstvcn);
			return -1;
		}
	}

	/* Check manatory arguments existance */
	for (i = 0; i < attr_infos_len; ++i) {
		ai = &attr_infos[i];
		if (!(ai->flags & NHR_ATTR_F_MANDATORY))
			continue;
		if (types_mask & (1 << ai->type / 0x10))
			continue;
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64"]: %s mandatory attribute missed\n",
			       nhr_mfte_num(mfte), ai->title);
		return -1;
	}

	/* Do the reverse check (entity -> attribute existance) */
	if (!list_empty(&mfte->ext) &&
	    !(types_mask & (1 << NTFS_ATTR_ALIST / 0x10))) {
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64"]: $ATTRIBUTE_LIST attribute missed\n",
			       nhr_mfte_num(mfte));
		return -1;
	}
	if (mfte->oid_src != NHR_SRC_NONE &&
	    !(types_mask & (1 << NTFS_ATTR_OID / 0x10))) {
		if (nhr.verbose >= 3) {
			ai = attr_get_info(NTFS_ATTR_OID);
			printf("attr[#%"PRIu64"]: %s attribute missed\n",
			       nhr_mfte_num(mfte), ai->title);
		}
		return -1;
	}
	for (i = 0; i < mfte->data_num; ++i) {
		ali = cache_attr_str_find(mfte, NTFS_ATTR_DATA,
					  mfte->data[i]->name_len,
					  mfte->data[i]->name);
		if (ali)
			continue;
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64"]: attribute for %ls data stream missed\n",
			       nhr_mfte_num(mfte),
			       cache_data_name(mfte->data[i]));
		return -1;
	}
	for (i = 0; i < sizeof(mfte->names)/sizeof(mfte->names[0]); ++i) {
		if (mfte->names[i].src == NHR_SRC_NONE)
			continue;
		ali = cache_attr_find_entity(mfte, NTFS_ATTR_FNAME,
					     &mfte->names[i]);
		if (ali)
			continue;
		if (nhr.verbose >= 3)
			printf("attr[#%"PRIu64"]: attribute for %ls filename missed\n",
			       nhr_mfte_num(mfte),
			       name2wchar(mfte->names[i].name, mfte->names[i].len));
		return -1;
	}
	for (i = 0; i < mfte->idx_num; ++i) {
		ali = cache_attr_find_entity(mfte, NTFS_ATTR_IROOT,
					     mfte->idx[i]);
		if (!ali) {
			if (nhr.verbose >= 3)
				printf("attr[#%"PRIu64"]: root attribute for %ls index missed\n",
				       nhr_mfte_num(mfte),
				       cache_idx_name(mfte->idx[i]));
			return -1;
		}
		if (mfte->idx[i]->root->flags & NHR_IDXN_F_LEAF)
			continue;
		ali = cache_attr_find_entity(mfte, NTFS_ATTR_IALLOC,
					     mfte->idx[i]);
		if (!ali) {
			if (nhr.verbose >= 3)
				printf("attr[#%"PRIu64"]: allocation attribute for %ls index missed\n",
				       nhr_mfte_num(mfte),
				       cache_idx_name(mfte->idx[i]));
			return -1;
		}
		ali = cache_attr_find_entity(mfte, NTFS_ATTR_BITMAP,
					     mfte->idx[i]);
		if (!ali) {
			if (nhr.verbose >= 3)
				printf("attr[#%"PRIu64"]: bitmap attribute for %ls index missed\n",
				       nhr_mfte_num(mfte),
				       cache_idx_name(mfte->idx[i]));
			return -1;
		}
	}

	return 0;
}

void attr_verify_all(void)
{
	struct nhr_mft_entry *mfte;
	unsigned cnt_tot = 0, cnt_ok = 0;
	int res;

	if (nhr.verbose >= 1)
		printf("attr: verify attributes lists\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(mfte->f_cmn & NHR_MFT_FC_BASE))	/* Only base entries */
			continue;
		if (!(mfte->f_sum & NHR_MFT_FB_SELF))	/* Only corrupted */
			continue;

		cnt_tot++;

		if (list_empty(&mfte->alist)) {
			if (nhr.verbose >= 2)
				printf("attr[#%"PRIu64"]: attributes list completely missed\n",
				       nhr_mfte_num(mfte));
			continue;
		}

		res = attr_verify_mfte(mfte);
		if (!res) {
			cnt_ok++;
			mfte->alist_valid = 1;
		}
	}

	if (nhr.verbose >= 1)
		printf("attr: checked %u MFT entries, %u of them is valid\n",
		       cnt_tot, cnt_ok);
}
