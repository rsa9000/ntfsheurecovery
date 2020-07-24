/**
 * Various scanners
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

#include "list.h"
#include "img.h"
#include "ntfsheurecovery.h"
#include "cache.h"
#include "mft_analyze.h"
#include "ntfs_struct.h"
#include "cmap.h"
#include "bb.h"
#include "idx.h"
#include "misc.h"
#include "scan.h"

static int cls_scan_orph_idx_blk(const struct ntfs_idx_rec_hdr *irh,
				 const uint64_t lcn,
				 unsigned bb_map)
{
	const unsigned idx_blk_ssz = nhr.vol.idx_blk_sz / nhr.vol.sec_sz;
	const struct ntfs_idx_node_hdr *inh = (void *)irh->data;
	const struct ntfs_idx_entry_hdr *ieh_s = (void *)irh->data + inh->off;
	const struct ntfs_idx_entry_hdr *ieh_e = (void *)irh->data + inh->len;
	const struct ntfs_idx_entry_hdr *ieh;
	const struct nhr_idx_info *info;
	unsigned idx_type_cnt[NHR_IDX_T_MAX + 1], idx_type_cnt_tot;
	int idx_type, i;
	uint64_t entnum;
	struct nhr_mft_entry *mfte;
	struct nhr_idx *idx;
	struct nhr_idx_node *idxn;
	struct nhr_bb *bb;

	if (sizeof(*irh) + inh->off > nhr.vol.idx_blk_sz ||
	    sizeof(*irh) + inh->len > nhr.vol.idx_blk_sz) {
		if (nhr.verbose >= 1)
			printf("cmap: orph[0x%08"PRIX64"]: idx: node overrides index block boundry, skipping\n",
			       lcn);
		return -1;
	}

	if (!ieh_s->key_sz) {
		if (nhr.verbose >= 1)
			printf("cmap: orph[0x%08"PRIX64"]: idx: node is empty, skipping\n",
			       lcn);
		return -1;
	}

	/* Scan node to prepare statistic for index type detection */
	memset(&idx_type_cnt, 0x00, sizeof(idx_type_cnt));
	idx_type_cnt_tot = 0;
	for (ieh = ieh_s; ieh < ieh_e; ieh = (void *)ieh + ieh->size) {
		if (!ieh->key_sz)
			continue;
		idx_type_cnt_tot++;
		for (i = 0; i <= NHR_IDX_T_MAX; ++i) {
			info = idx_info_get(i);
			if (!info)
				continue;
			if (ieh->key_sz < info->key_sz_min)
				continue;
			if (ieh->key_sz > info->key_sz_max)
				continue;
			idx_type_cnt[i]++;
		}
	}

	/* Select index type as most probable variant */
	idx_type = 0;
	for (i = 0; i <= NHR_IDX_T_MAX; ++i) {
		if (idx_type_cnt[i] > idx_type_cnt[idx_type])
			idx_type = i;
	}
	info = idx_info_get(idx_type);

	if (idx_type_cnt[idx_type] != idx_type_cnt_tot && nhr.verbose >= 1)
		printf("cmap: orph[0x%08"PRIX64"]: idx: block belongs to %ls index with probability of %u/%u\n",
		       lcn, name2wchar(info->name, info->name_len),
		       idx_type_cnt[idx_type], idx_type_cnt_tot);

	entnum = info->blk_mfte_detect(irh);
	if (!entnum) {
		if (nhr.verbose >= 1)
			printf("cmap: orph[0x%08"PRIX64"]; idx: could not determine host MFT entry\n",
			       lcn);
		return -1;
	}

	if (idx_type == NHR_IDX_T_DIR)
		mft_analyze_i30_node_parse(inh, inh->len);

	mfte = cache_mfte_find(entnum);
	if (!mfte) {
		if (nhr.verbose >= 1)
			printf("cmap: orph[0x%08"PRIX64"]: idx: no host MFT entry (#%"PRIu64") in cache\n",
			       lcn, entnum);
		return -1;
	}

	idx = cache_idx_find(mfte, idx_type);
	if (!idx)
		idx = cache_idx_find(mfte, idx_type);

	idxn = cache_idxn_alloc(idx, irh->vcn);
	idxn->lcn = lcn;

	for (i = 0; i < idx_blk_ssz; ++i) {
		if (!(bb_map & (1 << i)))
			continue;
		bb = bb_find(lcn * nhr.vol.cls_sz + i * nhr.vol.sec_sz);
		bb->attr_type = NTFS_ATTR_IALLOC;
		bb->voff = irh->vcn * nhr.vol.cls_sz + i * nhr.vol.sec_sz;
		bb->entity = idx;
		cache_mfte_bb_add(mfte, bb);
	}

	return 0;
}

#if 0
static void cls_scan_corrupted_idx_blk(const struct ntfs_idx_rec_hdr *irh,
				       const uint64_t lcn, unsigned bb_map,
				       struct cls_oscan_ctx *octx)
{
	const void *p = irh;
	uint16_t mark, marks[8];
	unsigned marks_num = 0;
	unsigned marks_cnt[8] = {0}, marks_cnt_max;
	unsigned cnt_bb = 0;
	unsigned i, j;

	for (i = 0; i < 8; ++i) {
		if (bb_map & (1 << i)) {
			cnt_bb++;
			continue;
		}
		mark = *(uint16_t *)(p + 0x200 * (i + 1) - 2);
		for (j = 0; j < marks_num; ++j) {
			if (mark == marks[j]) {
				marks_cnt[j]++;
				break;
			}
		}
#if 0
		printf("%7llu: block #%u mark %04X cnt = %u\n", lcn, i, mark,
		       j == marks_num ? 1 : marks_cnt[j]);
#endif
		if (j == marks_num) {
			marks_cnt[marks_num] = 1;
			marks[marks_num] = mark;
			marks_num++;
		}
	}

	if (cnt_bb >= 7)
		return;

	marks_cnt_max = 0;
	for (i = 1; i < marks_num; ++i)
		if (marks_cnt[i] > marks_cnt[marks_cnt_max])
			marks_cnt_max = i;
	if (marks_cnt[marks_cnt_max] <= 1 || marks[marks_cnt_max] == 0)
		return;
	printf("cls[%7llu]: got %u of 8 similar marks 0x%04X (%u block(s) is broken: %02X)\n",
	       lcn, marks_cnt[marks_cnt_max], marks[marks_cnt_max], cnt_bb, bb_map);
}
#endif

void cls_scan_orph(void)
{
	uint8_t blk_buf[nhr.vol.idx_blk_sz];
	struct ntfs_idx_rec_hdr *irh = (void *)blk_buf;
	const struct ntfs_idx_node_hdr *inh = (void *)irh->data;
	const unsigned idx_blk_ssz = nhr.vol.idx_blk_sz / nhr.vol.sec_sz;
	struct nhr_cb *cb;
	uint64_t i, lcn, off;
	unsigned j, bb_map, bb_voff;
	const struct ntfs_usa *usa;
	void *p;
	unsigned cnt_tot = 0, cnt_blk = 0;
	int res;

	if (nhr.verbose >= 1)
		printf("cmap: scan orphaned clusters\n");

	rbt_inorder_walk_entry(cb, &nhr.cmap, tree) {
		if (cb->flags & (NHR_CB_F_FREE | NHR_CB_F_ALLOC))
			continue;
		for (i = 0; i < cb->len - (nhr.vol.idx_blk_csz - 1); ++i) {
			cnt_tot += nhr.vol.idx_blk_csz;
			lcn = nhr_cb_off(cb) + i;
			off = lcn * nhr.vol.cls_sz;
			bb_voff = ~0;
			for (bb_map = 0, j = 0; j < idx_blk_ssz; ++j) {
				if (bb_find(off + j * nhr.vol.sec_sz)) {
					bb_map |= 1 << j;
					if (bb_voff == ~0)
						bb_voff = nhr.vol.sec_sz * j;
				}
			}
			if (bb_map & 1)	/* Could not process block with corrupted header */
				continue;
			res = img_read_sectors(off, blk_buf, 1);
			if (res) {
				fprintf(stderr, "Could not read orphaned data from 0x%08"PRIX64" (err: %d): %s\n",
					off, -res, strerror(-res));
				continue;
			}
			if (memcmp("INDX", irh->r.magic, 4) != 0)
				continue;
			if (bb_map && sizeof(*irh) + inh->len > bb_voff) {
				if (nhr.verbose >= 2)
					printf("cmap: orph[0x%08"PRIX64"] idx: possible index block corrupted by BB (map: 0x%02X)\n",
					       lcn, bb_map);
				continue;
			}
			res = img_read_sectors(off + nhr.vol.sec_sz,
					       blk_buf + nhr.vol.sec_sz,
					       idx_blk_ssz - 1);
			if (res) {
				fprintf(stderr, "Could not continue reading of orphaned data from 0x%08"PRIX64" (err: %d): %s\n",
					off, -res, strerror(-res));
				continue;
			}
			usa = ntfs_usa_ptr(&irh->r);
			p = blk_buf + nhr.vol.sec_sz - sizeof(uint16_t);
			for (j = 0; j < idx_blk_ssz; ++j, p += nhr.vol.sec_sz) {
				if (bb_map & (1 << j))		/* Skip corrupted sectors */
					continue;
				*(uint16_t *)p = usa->sec[j];
			}
			if (nhr.verbose >= 2)
				printf("cmap: orph[0x%08"PRIX64"] idx: detect possible index block\n", lcn);
			res = cls_scan_orph_idx_blk(irh, lcn, bb_map);
			if (res)
				continue;

			cnt_blk += nhr.vol.idx_blk_csz;
			cmap_block_mark(lcn, nhr.vol.idx_blk_csz,
					NHR_CB_F_ALLOC);
			cb = cmap_find(lcn);	/* Get new pointer */
			break;			/* Respin search */
		}
	}

	if (nhr.verbose >= 2)
		printf("cmap: scanned %u clusters, %u clusters belong to index blocks\n",
		       cnt_tot, cnt_blk);
}

