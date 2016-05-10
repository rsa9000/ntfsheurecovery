/**
 * $ObjId file related functions
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
#include "cache.h"
#include "mft_aux.h"
#include "img.h"
#include "objid.h"

struct objid_parse_ctx {
	uint64_t entnum;		/* Base MFT entry # */
	struct ntfs_mft_entry *ent;	/* Buffer for MFT entry */
	struct ntfs_attr_idx aidx;	/* Attr index */
	struct {
		uint16_t type;
		uint64_t firstvcn;
		uint64_t entnum;
	} *attrs;		/* Minimalistic $ATTRIBUTE_LIST :) */
	unsigned nattrs;
	uint8_t *idx_bm;	/* Index bitmap buffer */
	unsigned idx_bm_sz;	/* Index bitmap size */
};

static const char objid_filename[] = {'$', 0, 'O', 0, 'b', 0, 'j', 0, 'I', 0, 'd'};
static const char objid_idxname[] = {'$', 0, 'O', 0};

static int objid_parse_entry(const struct ntfs_idx_entry_hdr *ieh)
{
	const struct ntfs_guid *objid = (void *)ieh->key;
	const struct ntfs_idx_objid_data *idxod = ntfs_idx_entry_data(ieh);
	struct nhr_mft_entry *mfte;

	assert(ieh->key_sz == sizeof(*objid));
	assert(ieh->data_sz == sizeof(*idxod));

	mfte = cache_mfte_find(NTFS_MREF_ENTNUM(idxod->mref));
	if (!mfte)
		return 0;
	if (!(nhr_mfte_bflags(mfte) & NHR_MFT_FB_SELF))
		return 0;

	mfte->f_cmn |= NHR_MFT_FC_BASE;

	NHR_FIELD_UPDATE(&mfte->seqno, NTFS_MREF_SEQNO(idxod->mref),
			 NHR_SRC_IDX_OBJID);

	if (mfte->oid_src < NHR_SRC_IDX_OBJID) {
		mfte->oid_src = NHR_SRC_IDX_OBJID;
		if (!mfte->oid)
			mfte->oid = malloc(sizeof(*mfte->oid));
		memcpy(&mfte->oid->obj_id, objid, sizeof(mfte->oid->obj_id));
		memcpy(&mfte->oid->birth_vol_id, &idxod->birth_vol_id,
		       sizeof(mfte->oid->birth_vol_id));
		memcpy(&mfte->oid->birth_obj_id, &idxod->birth_obj_id,
		       sizeof(mfte->oid->birth_obj_id));
		memcpy(&mfte->oid->domain_id, &idxod->domain_id,
		       sizeof(mfte->oid->domain_id));
	}

	return 0;
}

static int objid_parse_node(const struct ntfs_idx_node_hdr *inh)
{
	const void *ptr = (void *)inh + inh->off;
	const void *end = (void *)inh + inh->len;
	const struct ntfs_idx_entry_hdr *ieh;
	int res = 0;

	for (ieh = ptr; ptr < end; ptr += ieh->size, ieh = ptr) {
		if (ieh->key_sz) {
			res = objid_parse_entry(ieh);
			if (res)
				break;
		}
		if (ieh->flags & NTFS_IDX_ENTRY_F_LAST)
			break;
	}

	return res;
}

static const struct ntfs_attr_hdr *objid_get_attr(struct objid_parse_ctx *octx,
						  uint64_t entnum,
						  uint16_t attr_type)
{
	const struct ntfs_attr_hdr *attr;
	int res, i;

	res = mft_entry_read_and_preprocess(entnum, octx->ent, 0);
	if (res)
		return NULL;

	ntfs_mft_aidx_get(octx->ent, &octx->aidx);
	for (i = 0; i < octx->aidx.num; ++i) {
		attr = octx->aidx.a[i];
		if (attr->type != attr_type)
			continue;
		if (attr->name_len != sizeof(objid_idxname)/2)
			continue;
		if (memcmp(NTFS_ATTR_NAME(attr), objid_idxname,
			   sizeof(objid_idxname)) != 0)
			continue;

		return attr;
	}

	return NULL;
}

static int objid_parse_ialloc_blk(struct objid_parse_ctx *octx,
				  const uint64_t lcn)
{
	uint8_t buf[nhr.vol.idx_blk_sz];
	const struct ntfs_idx_rec_hdr *irh = (void *)buf;
	int res;

	img_read_clusters(lcn, buf, nhr.vol.idx_blk_csz);

	if (strncmp(irh->r.magic, "INDX", 4) != 0)
		return -EINVAL;

	res = ntfs_usa_apply(buf, nhr.vol.idx_blk_sz, nhr.vol.sec_sz);
	if (res)
		return -EINVAL;

	return objid_parse_node((void *)irh->data);
}

static int objid_parse_ialloc(struct objid_parse_ctx *octx, uint64_t entnum,
			      uint64_t blk_base)
{
	const struct ntfs_attr_hdr *attr;
	struct ntfs_mp *mpl = NULL, *mp;
	uint64_t i, num;
	int res = 0;

	attr = objid_get_attr(octx, entnum, NTFS_ATTR_IALLOC);
	assert(attr);
	assert(attr->nonresident);

	mpl = ntfs_attr_mp_unpack(attr);
	for (mp = mpl; mp->clen; mp++) {
		for (i = 0; i < mp->clen; i += nhr.vol.idx_blk_csz) {
			num = (mp->vcn + i) / nhr.vol.idx_blk_csz;
			if (!(octx->idx_bm[num / 8] & (1 << (num % 8))))
				continue;
			res = objid_parse_ialloc_blk(octx, mp->lcn + i);
			if (res)
				goto exit;
		}
	}

exit:
	free(mpl);

	return res;
}

static int objid_parse_iroot(struct objid_parse_ctx *octx, uint64_t entnum)
{
	const struct ntfs_attr_hdr *attr;
	const struct ntfs_attr_iroot *ir;

	attr = objid_get_attr(octx, entnum, NTFS_ATTR_IROOT);
	assert(attr);
	assert(!attr->nonresident);

	ir = NTFS_ATTR_RDATA(attr);

	return objid_parse_node((struct ntfs_idx_node_hdr *)ir->data);
}

static int objid_load_bitmap(struct objid_parse_ctx *octx, uint64_t entnum)
{
	const struct ntfs_attr_hdr *attr;

	attr = objid_get_attr(octx, entnum, NTFS_ATTR_BITMAP);
	assert(attr);

	if (attr->nonresident) {
		struct ntfs_mp *mpl = ntfs_attr_mp_unpack(attr);
		unsigned sz = ntfs_mpl_vclen(mpl) * nhr.vol.cls_sz;

		assert(attr->firstvcn * nhr.vol.cls_sz == octx->idx_bm_sz);
		octx->idx_bm = realloc(octx->idx_bm, octx->idx_bm_sz + sz);
		img_fetch_mp_data(mpl, octx->idx_bm + octx->idx_bm_sz);
		octx->idx_bm_sz += sz;
		free(mpl);
	} else {
		assert(octx->idx_bm_sz == 0);
		octx->idx_bm = malloc(attr->data_sz);
		memcpy(octx->idx_bm, NTFS_ATTR_RDATA(attr), attr->data_sz);
		octx->idx_bm_sz = attr->data_sz;
	}

	return 0;
}

/**
 * Parse attribute list and extract necessary entries
 */
static void objid_parse_alist(struct objid_parse_ctx *octx, const void *buf,
			      unsigned len)
{
	const struct ntfs_attr_alist_item *ali;
	const struct ntfs_attr_alist_item *end = buf + len;

	for (ali = buf; ali < end; ali = (void *)ali + ali->size) {
		assert((void *)ali - buf < 0x1000);
		if (ali->type != NTFS_ATTR_IROOT &&
		    ali->type != NTFS_ATTR_IALLOC &&
		    ali->type != NTFS_ATTR_BITMAP)
			continue;
		if (ali->name_len != 2)
			continue;
		if (memcmp(NTFS_ATTR_ALI_NAME(ali), objid_idxname,
			   sizeof(objid_idxname)) != 0)
			continue;
		octx->attrs = realloc(octx->attrs, (octx->nattrs + 1) *
						   sizeof(octx->attrs[0]));
		octx->attrs[octx->nattrs].type = ali->type;
		octx->attrs[octx->nattrs].firstvcn = ali->firstvcn;
		octx->attrs[octx->nattrs].entnum = NTFS_MREF_ENTNUM(ali->mref);
		octx->nattrs++;
	}
}

/**
 * Build attribute list based from attributes of base MFT entry
 */
static void objid_build_alist(struct objid_parse_ctx *octx,
			      const struct ntfs_attr_idx *aidx)
{
	const struct ntfs_attr_hdr *attr;
	unsigned i;

	for (i = 0; i < aidx->num; ++i) {
		attr = aidx->a[i];
		if (attr->type != NTFS_ATTR_IROOT &&
		    attr->type != NTFS_ATTR_IALLOC &&
		    attr->type != NTFS_ATTR_BITMAP)
			continue;
		if (attr->name_len != 2)
			continue;
		if (memcmp(NTFS_ATTR_NAME(attr), objid_idxname,
			   sizeof(objid_idxname)) != 0)
			continue;
		octx->attrs = realloc(octx->attrs, (octx->nattrs + 1) *
						   sizeof(octx->attrs[0]));
		octx->attrs[octx->nattrs].type = attr->type;
		octx->attrs[octx->nattrs].firstvcn = attr->firstvcn;
		octx->attrs[octx->nattrs].entnum = octx->entnum;
		octx->nattrs++;
	}
}

/**
 * Find $ObjId file MFT entry number
 *
 * XXX: this realization is pretty simple and ugly :D
 */
static int objid_find(struct objid_parse_ctx *octx)
{
	unsigned entnum;
	struct nhr_mft_entry *mfte;
	int i;
	const struct ntfs_attr_hdr *attr;
	struct ntfs_attr_fname *fn;
	int res;

	for (entnum = NTFS_ENTNUM_USER; entnum < 100; ++entnum) {
		if (!(nhr.mft_bitmap[entnum / 8] & (1 << (entnum % 8))))
			continue;

		mfte = cache_mfte_find(entnum);
		if (mfte) {
			if (mfte->names[NTFS_FNAME_T_WIN32DOS].src == NHR_SRC_NONE)
				continue;
			if (mfte->names[NTFS_FNAME_T_WIN32DOS].len != 6)
				continue;
			res = memcmp(mfte->names[NTFS_FNAME_T_WIN32DOS].name,
				     objid_filename, sizeof(objid_filename));
			if (res != 0)
				continue;
			if (mfte->f_bad) {
				fprintf(stderr, "objid: error: base entry (#%u) corrupted, aborting\n",
					entnum);
				return -ENOENT;
			}
		}

		res = mft_entry_read_and_preprocess(entnum, octx->ent, 0);
		if (res)
			continue;

		ntfs_mft_aidx_get(octx->ent, &octx->aidx);
		for (i = 0, res = -ENOENT; i < octx->aidx.num; ++i) {
			attr = octx->aidx.a[i];
			if (attr->type != NTFS_ATTR_FNAME)
				continue;
			fn = NTFS_ATTR_RDATA(attr);
			if (fn->name_type != NTFS_FNAME_T_WIN32DOS)
				break;
			if (fn->name_len != 6)
				break;
			res = memcmp(fn->name, objid_filename,
				     sizeof(objid_filename));
			break;
		}
		if (res == 0)
			break;	/* Ok, we found base entry */
	}
	if (entnum == 100)
		return -ENOENT;

	assert(octx->ent->base == 0);		/* Oops */
	assert(octx->aidx.num >= 2);		/* Oops#2 */

	octx->entnum = entnum;

	/**
	 * $ATTRIBUTE_LIST should follows immediatly after
	 * $STANDARD_INFO so check only that position
	 */
	attr = octx->aidx.a[1];
	if (attr->type == NTFS_ATTR_ALIST) {
		assert(!attr->nonresident);
		objid_parse_alist(octx, NTFS_ATTR_RDATA(attr), attr->data_sz);
	} else {
		objid_build_alist(octx, &octx->aidx);
	}

	return 0;
}

void objid_analyze(void)
{
	struct objid_parse_ctx octx;
	uint8_t ent_buf[nhr.vol.mft_ent_sz];
	unsigned i;
	int res;

	if (nhr.verbose >= 1)
		printf("objid: start analysis\n");

	memset(&octx, 0x00, sizeof(octx));
	octx.ent = (struct ntfs_mft_entry *)ent_buf;

	res = objid_find(&octx);
	if (res) {
		fprintf(stderr, "objid: error: could not find $ObjId file\n");
		goto exit;
	}

	/**
	 * Now we assume that we know each entity (root, nodes, etc.) locations
	 * and each of which is not corrupted.
	 */

	for (i = 0; i < octx.nattrs; ++i) {
		if (octx.attrs[i].type != NTFS_ATTR_BITMAP)
			continue;
		res = objid_load_bitmap(&octx, octx.attrs[i].entnum);
		if (res) {
			fprintf(stderr, "objid: error: could not load bitmap from #%"PRIu64" entry\n",
				octx.attrs[i].entnum);
			goto exit;
		}
	}

	assert(octx.attrs[0].type == NTFS_ATTR_IROOT);
	res = objid_parse_iroot(&octx, octx.attrs[0].entnum);
	if (res) {
		fprintf(stderr, "objid: error: could not parse index root in #%"PRIu64"\n",
			octx.attrs[0].entnum);
		goto exit;
	}

	for (i = 0; i < octx.nattrs; ++i) {
		if (octx.attrs[i].type != NTFS_ATTR_IALLOC)
			continue;
		res = objid_parse_ialloc(&octx, octx.attrs[i].entnum,
					 octx.attrs[i].firstvcn /
					 nhr.vol.idx_blk_csz);
		if (res) {
			fprintf(stderr, "objid: error: could not parse index nodes in #%"PRIu64"\n",
				octx.attrs[i].entnum);
			goto exit;
		}
	}

	if (nhr.verbose >= 1)
		printf("objid: analysis done\n");

exit:
	ntfs_mft_aidx_clean(&octx.aidx);
	free(octx.attrs);
	free(octx.idx_bm);
}
