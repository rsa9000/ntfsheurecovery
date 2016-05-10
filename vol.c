/**
 * Volume basic (actually unsorted) functions
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "mft_aux.h"
#include "cache.h"
#include "misc.h"
#include "bb.h"
#include "img.h"
#include "cmap.h"
#include "vol.h"

int vol_open(void)
{
	struct ntfs_boot bs;
	ssize_t len;

	len = read(nhr.fs_fd, &bs, sizeof(bs));
	if (-1 == len) {
		fprintf(stderr, "vol: could not read boot sector (err: %d): %s\n",
			errno, strerror(errno));
		return -errno;
	} else if (len != sizeof(bs)) {
		fprintf(stderr, "vol: read only %zd bytes of %zu bytes of boot sector\n",
			len, sizeof(bs));
		return -EIO;
	}

	if (bs.magic != 0xAA55) {
		fprintf(stderr, "vol: signature check error, expect %04X got %04X\n",
			0xAA55, bs.magic);
		return -EINVAL;
	}

	nhr.vol.sec_sz = bs.bytes_per_sect;
	nhr.vol.cls_ssz = bs.sect_per_clust;
	nhr.vol.cls_sz = bs.bytes_per_sect * bs.sect_per_clust;
	nhr.vol.sec_num = bs.sectors_num;
	nhr.vol.cls_num = bs.sectors_num / bs.sect_per_clust;
	nhr.vol.mft_lcn = bs.mft_offset;
	nhr.vol.mft_ent_sz = ntfs_sz_decode(bs.mft_entry_size,
					    nhr.vol.cls_sz);
	nhr.vol.idx_blk_sz = ntfs_sz_decode(bs.idx_record_size,
					    nhr.vol.cls_sz);
	nhr.vol.idx_blk_csz = bs.idx_record_size;

	/**
	 * According to:
	 * http://blogs.msdn.com/b/ntdebugging/archive/2008/05/20/understanding-ntfs-compression.aspx
	 * compression block (unit) is always 16 clusters long.
	 */
	if (nhr.vol.cls_sz <= 0x1000) {
		nhr.vol.com_blk_sz = nhr.vol.cls_sz * 16;
	} else {
		fprintf(stderr, "vol: cluster size too large, compression will not work\n");
	}

	if (nhr.verbose < 1)
		return 0;

	printf("vol: bytes per sector: %u\n", bs.bytes_per_sect);
	printf("vol: sectors per cluster: %u\n", bs.sect_per_clust);
	printf("vol: sectors number: %"PRIu64"\n", bs.sectors_num);
	printf("vol: clusters number: %"PRIu64"\n", bs.sectors_num / bs.sect_per_clust);
	printf("vol: total size: %s\n", int2sz(bs.sectors_num * bs.bytes_per_sect));
	printf("vol: serial: %016"PRIX64"\n", bs.serial);
	printf("vol: MFT offset: %"PRIu64"\n", bs.mft_offset);
	printf("vol: MFTmirr offset: %"PRIu64"\n", bs.mftmirr_offset);
	printf("vol: MFT entry size: %d (%u bytes)\n", bs.mft_entry_size,
	       nhr.vol.mft_ent_sz);
	printf("vol: Index record size: %d (%u bytes)\n", bs.idx_record_size,
	       nhr.vol.idx_blk_sz);
	printf("vol: compression block size: %s\n", int2sz(nhr.vol.com_blk_sz));

	return 0;
}

struct mft_open_ctx {
	struct nhr_mft_entry *mfte;	/* Cached pointer to $MFT */
	struct nhr_data *data;		/* Cached pointer to $MFT data */
};

static void mft_open_data_proc_cls(struct mft_open_ctx *octx,
				   const struct ntfs_attr_hdr *attr,
				   const uint64_t vcn, const uint64_t lcn)
{
	const uint64_t lcn_off = lcn * nhr.vol.cls_sz;
	const uint64_t sz = nhr.vol.cls_sz;
	uint64_t off, mft_voff, entnum;
	struct nhr_bb *bb;
	struct nhr_mft_entry *mfte;

	for (off = 0; off < sz; off += nhr.vol.sec_sz) {
		bb = bb_find(lcn_off + off);
		if (!bb)
			continue;

		mft_voff = vcn * nhr.vol.cls_sz + off;
		entnum = mft_voff / nhr.vol.mft_ent_sz;

		mfte = cache_mfte_find(entnum);
		if (!mfte)
			mfte = cache_mfte_alloc(entnum);

		mfte->bb_map |= 1 << (mft_voff % nhr.vol.mft_ent_sz /
				      nhr.vol.sec_sz);
		cache_mfte_fbad_set(mfte, NHR_MFT_FB_SELF);

		if (!octx->mfte) {
			octx->mfte = cache_mfte_find(NTFS_ENTNUM_MFT);
			if (!octx->mfte)
				octx->mfte = cache_mfte_alloc(NTFS_ENTNUM_MFT);
		}
		if (!octx->data) {
			octx->data = cache_data_find(octx->mfte, 0, NULL);
			if (!octx->data)
				octx->data = cache_data_alloc(octx->mfte, 0,
							      NULL);
		}

		bb->attr_type = attr->type;
		bb->attr_id = attr->id;
		bb->voff = mft_voff;
		bb->entity = octx->data;
		cache_mfte_bb_add(octx->mfte, bb);
	}
}

static void mft_open_data_proc_mpl(struct mft_open_ctx *octx,
				   const struct ntfs_attr_hdr *attr,
				   const struct ntfs_mp *mpl)
{
	uint64_t i;

	for (; mpl->clen; ++mpl) {
		for (i = 0; i < mpl->clen; ++i)
			mft_open_data_proc_cls(octx, attr, mpl->vcn + i,
					       mpl->lcn + i);
	}
}

static void mft_open_bitmap_proc_cls(struct mft_open_ctx *octx,
				     const struct ntfs_attr_hdr *attr,
				     const uint64_t vcn, const uint64_t lcn)
{
	const uint64_t lcn_off = lcn * nhr.vol.cls_sz;
	const uint64_t sz = nhr.vol.cls_sz;
	uint64_t off;
	struct nhr_bb *bb;
	int res;

	for (off = 0; off < sz; off += nhr.vol.sec_sz) {
		bb = bb_find(lcn_off + off);
		if (!bb)
			continue;

		if (!octx->mfte) {
			octx->mfte = cache_mfte_find(NTFS_ENTNUM_MFT);
			if (!octx->mfte)
				octx->mfte = cache_mfte_alloc(NTFS_ENTNUM_MFT);
		}

		bb->attr_type = attr->type;
		bb->attr_id = attr->id;
		bb->voff = vcn * nhr.vol.cls_sz + off;
		bb->entity = NULL;	/* Bitmaps not supported yet */
		cache_mfte_bb_add(octx->mfte, bb);

		printf("BB at 0x%08"PRIX64" corrupts MFT bitmap from %"PRIu64" to %"PRIu64"\n",
		       nhr_bb_off(bb), bb->voff * 8,
		       (bb->voff + nhr.vol.sec_sz) * 8 - 1);
	}

	res = img_read_cluster(lcn, nhr.mft_bitmap + vcn * nhr.vol.cls_sz);
	if (res) {
		fprintf(stderr, "mft:bitmap:could not read cluster %"PRIu64"\n",
			lcn);
	}
}

static void mft_open_bitmap_proc_mpl(struct mft_open_ctx *octx,
				     const struct ntfs_attr_hdr *attr,
				     const struct ntfs_mp *mpl)
{
	uint64_t i;

	for (; mpl->clen; ++mpl) {
		for (i = 0; i < mpl->clen; ++i)
			mft_open_bitmap_proc_cls(octx, attr, mpl->vcn + i,
						 mpl->lcn + i);
	}
}

static void mft_open_attr_proc(struct mft_open_ctx *octx,
			       const struct ntfs_attr_hdr *attr)
{
	size_t sz;
	struct ntfs_mp *mp;

	if (attr->nonresident) {
		mp = ntfs_attr_mp_unpack(attr);
		assert(mp);
	} else {
		mp = NULL;
	}

	if (attr->type == NTFS_ATTR_DATA && !attr->name_len) {
		nhr.mft_data_aid = attr->id;
		nhr.vol.mft_sz = attr->used_sz;
		mft_open_data_proc_mpl(octx, attr, mp);
		nhr.mft_data = mp;
		nhr.mft_data_num = ntfs_mpl_len(mp);
		mp = NULL;	/* Consume list */
	} else if (attr->type == NTFS_ATTR_BITMAP && !attr->name_len) {
		assert(attr->nonresident);

		/* Align buffer size on to cluster boundary */
		if (attr->used_sz % nhr.vol.cls_sz)
			sz = (attr->used_sz / nhr.vol.cls_sz + 1) * nhr.vol.cls_sz;
		else
			sz = attr->used_sz;
		nhr.mft_bitmap = malloc(sz);
		if (!nhr.mft_bitmap) {
			fprintf(stderr, "Could not allocate memory for MFT bitmap copy\n");
			return;
		}
		nhr.mft_bitmap_sz = attr->used_sz;
		mft_open_bitmap_proc_mpl(octx, attr, mp);
	}

	free(mp);
}

int mft_open(void)
{
	struct mft_open_ctx octx;
	off_t off = nhr.vol.mft_lcn * nhr.vol.cls_sz;
	unsigned num = nhr.vol.mft_ent_sz / nhr.vol.sec_sz;
	struct nhr_bb *bb;
	uint8_t buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)buf;
	int res;
	struct ntfs_attr_idx aidx;
	int i;

	memset(&octx, 0x00, sizeof(octx));
	memset(&aidx, 0x00, sizeof(aidx));

	for (i = 0; i < num; ++i) {
		bb = bb_find(off + i * nhr.vol.sec_sz);
		if (bb) {
			fprintf(stderr, "MFT 0 (main) entry damaged\n");
			return -EIO;
		}
	}

	res = img_read_sectors(off, buf, nhr.vol.mft_ent_sz / nhr.vol.sec_sz);
	if (res) {
		fprintf(stderr, "could not read main MFT entry (err: %d): %s\n",
			-res, strerror(-res));
		return res;
	}

	res = mft_entry_preprocess(NTFS_ENTNUM_MFT, ent);
	if (res < 0)
		return res;

	/* Parse attributes */
	ntfs_mft_aidx_get(ent, &aidx);
	for (i = 0; i < aidx.num; ++i) {
		mft_open_attr_proc(&octx, aidx.a[i]);
	}
	ntfs_mft_aidx_clean(&aidx);

	if (!nhr.vol.mft_sz)
		fprintf(stderr, "MFT size not detected\n");
	else if (nhr.verbose >= 1)
		printf("vol: MFT size: %"PRIu64" (%"PRIu64" entries)\n",
		       nhr.vol.mft_sz, nhr.vol.mft_sz / nhr.vol.mft_ent_sz);

	return 0;
}

void mft_bitmap_process(void)
{
	unsigned i, j, k;
	uint64_t entnum, mft_off;
	struct nhr_mft_entry *mfte;
	struct nhr_bb *bb;
	const unsigned mft_ent_ssz = nhr.vol.mft_ent_sz / nhr.vol.sec_sz;

	for (i = 0; i < nhr.mft_bitmap_sz; ++i) {
		if (nhr.mft_bitmap[i] == 0xff)
			continue;
		for (j = 0; j < 8; ++j) {
			if (nhr.mft_bitmap[i] & (1 << j))
				continue;
			entnum = i * 8 + j;
			mfte = cache_mfte_find(entnum);
			if (!mfte)
				continue;
			mfte->f_cmn |= NHR_MFT_FC_FREE;
			mft_off = mft_entry_offset(entnum);
			for (k = 0; k < mft_ent_ssz; ++k) {
				if (!(mfte->bb_map & (1 << k)))
					continue;
				bb = bb_find(mft_off + k * nhr.vol.sec_sz);
				if (bb) {
					bb->flags |= NHR_BB_F_IGNORE;
					cache_mfte_bb_ok(bb);
				}
			}
		}
	}
}

struct vol_bitmap_ctx {
	struct nhr_mft_entry *mfte;	/* $BITMAP cache entry */
	struct nhr_data *data;		/* $BITMAP data cache entry */
	uint64_t blk_off;	/* Block offset, clusters */
	uint64_t blk_len;	/* Block lenght, clusters */
	int blk_alloc;		/* Is this block of allocated clusters */
};

/**
 * Postprocess detected block of clusters
 */
static void vol_bitmap_block_end(struct vol_bitmap_ctx *vctx)
{
	assert(vctx->blk_len);

	if (!vctx->blk_alloc)
		cmap_block_mark(vctx->blk_off, vctx->blk_len, NHR_CB_F_FREE);

	vctx->blk_off += vctx->blk_len;
	vctx->blk_len = 0;
	vctx->blk_alloc = !vctx->blk_alloc;
}

/**
 * Process item octet of volume bitmap
 * base - base cluster number of this part of bitmap
 * bitmap - octet content
 * vctx - parsing context
 */
static inline int vol_bitmap_data_proc_octet(uint64_t base, uint8_t bitmap,
					     struct vol_bitmap_ctx *vctx)
{
	unsigned i;

	/* Check each per-cluster bit */
	for (i = 0; i < 8; ++i, bitmap >>= 1) {
		if ((base + i) >= nhr.vol.cls_num)
			return 1;
		if (bitmap & 1) {
			if (!vctx->blk_alloc)
				vol_bitmap_block_end(vctx);
		} else {
			if (vctx->blk_alloc)
				vol_bitmap_block_end(vctx);
		}
		vctx->blk_len++;
	}

	return 0;
}

static void vol_bitmap_data_proc_cls(const struct ntfs_attr_hdr *attr,
				     const uint64_t vcn, const uint64_t lcn,
				     struct vol_bitmap_ctx *vctx)
{
	struct nhr_mft_entry *mfte = vctx->mfte;
	uint64_t base;
	unsigned i;
	struct nhr_bb *bb;
	uint8_t buf[nhr.vol.cls_sz];
	int res;

	res = img_read_cluster(lcn, buf);
	if (res) {
		fprintf(stderr, "vol:bitmap:could not read cluster %"PRIu64"\n",
			lcn);
		return;
	}
	base = vcn * nhr.vol.cls_sz * 8;
	for (i = 0; i < nhr.vol.cls_sz;) {
		bb = bb_find(lcn * nhr.vol.cls_sz + i);
		if (bb) {
			if (!mfte) {
				mfte = cache_mfte_find(NTFS_ENTNUM_BITMAP);
				if (!mfte) {
					mfte = cache_mfte_alloc(NTFS_ENTNUM_BITMAP);
					mfte->f_cmn |= NHR_MFT_FC_FILE;
					mfte->f_cmn |= NHR_MFT_FC_BASE;
				}
				vctx->mfte = mfte;
			}
			if (!vctx->data) {
				vctx->data = cache_data_find(mfte, 0, NULL);
				if (!vctx->data)
					vctx->data = cache_data_alloc(mfte, 0,
								      NULL);
			}

			bb->attr_type = attr->type;
			bb->attr_id = attr->id;
			bb->voff = vcn * nhr.vol.cls_sz + i;
			bb->entity = vctx->data;
			cache_mfte_bb_add(mfte, bb);

			/* Skip whole sector */
			i += nhr.vol.sec_sz;
			base += nhr.vol.sec_sz * 8;
			continue;
		}
		do {	/* Sector processing circle */
			if (buf[i] == 0xff) {
				if (!vctx->blk_alloc)
					vol_bitmap_block_end(vctx);
				if (base + 8 < nhr.vol.cls_num) {
					vctx->blk_len += 8;
				} else {
					vctx->blk_len += nhr.vol.cls_num - base;
					vol_bitmap_block_end(vctx);
					return;
				}
			} else {
				res = vol_bitmap_data_proc_octet(base, buf[i],
								 vctx);
				if (res)
					return;
			}

			base += 8;
		} while (++i % nhr.vol.sec_sz);	/* Until sector border */
	}
}

static void vol_bitmap_data_proc_mpl(const struct ntfs_attr_hdr *attr,
				     const struct ntfs_mp *mpl,
				     struct vol_bitmap_ctx *vctx)
{
	uint64_t i;

	for (; mpl->clen; ++mpl) {
		for (i = 0; i < mpl->clen; ++i)
			vol_bitmap_data_proc_cls(attr, mpl->vcn + i,
						 mpl->lcn + i, vctx);
	}
}

static void vol_bitmap_attr_parse(const struct ntfs_attr_hdr *attr,
				  struct vol_bitmap_ctx *vctx)
{
	struct ntfs_mp *mp;

	if (attr->type == NTFS_ATTR_DATA && attr->name_len == 0) {
		assert(attr->nonresident);
		mp = ntfs_attr_mp_unpack(attr);
		assert(mp);
		vol_bitmap_data_proc_mpl(attr, mp, vctx);
		free(mp);
	}
}

static void vol_bitmap_mft_entry_parse(struct ntfs_mft_entry *ent,
				       struct vol_bitmap_ctx *vctx)
{
	struct ntfs_attr_idx aidx;
	int i;

	memset(&aidx, 0x00, sizeof(aidx));
	ntfs_mft_aidx_get(ent, &aidx);

	for (i = 0; i < aidx.num; ++i) {
		vol_bitmap_attr_parse(aidx.a[i], vctx);
	}

	ntfs_mft_aidx_clean(&aidx);
}

void vol_bitmap_read(void)
{
	struct vol_bitmap_ctx vctx;
	uint8_t ent_buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)ent_buf;

	memset(&vctx, 0x00, sizeof(vctx));
	/*
	 * First cluster is boot and its always allocated, so we begin
	 * from allocated block
	 */
	vctx.blk_alloc = 1;

	if (mft_entry_read_and_preprocess(NTFS_ENTNUM_BITMAP, ent, 0))
		return;

	vol_bitmap_mft_entry_parse(ent, &vctx);
}

int vol_upcase_read(void)
{
	uint8_t ent_buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)ent_buf;
	struct ntfs_attr_idx aidx;
	const struct ntfs_attr_hdr *attr = NULL;
	int i;
	struct ntfs_mp *mpl;

	memset(&aidx, 0x00, sizeof(aidx));

	if (mft_entry_read_and_preprocess(NTFS_ENTNUM_UPCASE, ent, 0)) {
		fprintf(stderr, "vol: could not read $UpCase MFT entry\n");
		return -EIO;
	}

	ntfs_mft_aidx_get(ent, &aidx);
	for (i = 0; i < aidx.num; ++i) {
		if (aidx.a[i]->type != NTFS_ATTR_DATA || aidx.a[i]->name_len ||
		    !aidx.a[i]->nonresident)
			continue;
		attr = aidx.a[i];
		break;
	}
	ntfs_mft_aidx_clean(&aidx);

	if (!attr) {
		fprintf(stderr, "vol: could not find $UpCase data\n");
		return -ENOENT;
	}

	mpl = ntfs_attr_mp_unpack(attr);
	nhr.vol_upcase_sz = ntfs_mpl_vclen(mpl) * nhr.vol.cls_sz;
	nhr.vol_upcase = malloc(nhr.vol_upcase_sz);

	img_fetch_mp_data(mpl, nhr.vol_upcase);

	free(mpl);

	if (nhr.verbose >= 1) {
		printf("vol: UpCase table size: %zu bytes (%zu chars)\n",
		       nhr.vol_upcase_sz, nhr.vol_upcase_sz / 2);
	}

	return 0;
}
