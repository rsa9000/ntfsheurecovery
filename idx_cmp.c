/**
 * Index entities compare functions
 *
 * Copyright (c) 2015, Sergey Ryazanov <ryazanov.s.a@gmail.com>
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
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "ntfs_struct.h"
#include "misc.h"
#include "idx_cmp.h"

/**
 * Compare two index entries
 *
 * iinfo - index type specific descriptor
 * e1 - entry, which is fetched from disk (could be broken)
 * e2 - reconstructed entry (should be valid)
 * off_start - valid data start offset (for e1)
 * off_end - valid data end offset (for e1)
 * pm - padding mask
 *
 * Returns zero if entries are equal, otherwise returns -1
 *
 * This function compares only meaningful part of entries
 * and ignores padding.
 */
int idx_idxe_cmp(const struct nhr_idx_info *iinfo,
		 const struct ntfs_idx_entry_hdr *e1,
		 const struct ntfs_idx_entry_hdr *e2,
		 unsigned off_start, unsigned off_end,
		 struct nhr_cmask_elem **pm)
{
	const void *p1 = e1, *p2 = e2;
	int s, e, off, res, pmoff = 0;

	/* Compare entry header */
	s = 0;
	e = s + sizeof(*e1);
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e && memcmp(p1 + s, p2 + s, e - s) != 0) {
		if (nhr.verbose >= 3)
			printf("idxecmp[0x%"PRIX64"]: mismatch at [0x%04X:0x%04X]: entry header\n",
			       e2->val, s, e - 1);
		return -1;
	}
	if (pm) {
		if (s < e) {
			cmask_append(pm, 0, s - pmoff);
			cmask_append(pm, 1, e - s);
			cmask_append(pm, 0, pmoff + sizeof(*e1) - e);
		} else {
			cmask_append(pm, 0, sizeof(*e1));
		}
		pmoff += sizeof(*e1);
	}

	/* Compare entry keys */
	s = __builtin_offsetof(typeof(*e1), key);
	e = s + e2->key_sz;
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e) {
		off = __builtin_offsetof(typeof(*e1), key);

		if (iinfo && iinfo->key_match)	/* Specific comparition */
			res = iinfo->key_match(e1->key, e2->key, s - off,
					       e - off);
		else				/* Fallback to raw compare */
			res = memcmp((void *)e1->key + s - off,
				     (void *)e2->key + s - off, e - s);

		if (res) {
			if (nhr.verbose >= 3)
				printf("idxecmp[0x%"PRIX64"]: mismatch at [0x%04X:0x%04X]: key\n",
				       e2->val, s, e - 1);
			return -1;
		}
		if (pm) {
			cmask_append(pm, 0, s - pmoff);
			cmask_append(pm, 1, e - s);
			cmask_append(pm, 0, pmoff + e2->key_sz - e);
			pmoff += e2->key_sz;
		}
	} else if (pm) {
		cmask_append(pm, 0, e2->key_sz);
		pmoff += e2->key_sz;
	}

	/* Compare entry data (if exists and outside of header) */
	if (e2->key_sz && iinfo && iinfo->data_sz) {
		if (pm)
			assert(pmoff == e2->data_off);
		s = e2->data_off;
		e = e2->data_off + e2->data_sz;
		if (s < off_start)
			s = off_start;
		if (e > off_end)
			e = off_end;
		if (s < e && memcmp(p1 + s, p2 + s, e - s) != 0) {
			if (nhr.verbose >= 3)
				printf("idxecmp[0x%"PRIX64"]: mismatch at [0x%04X:0x%04X]: data\n",
				       e2->val, s, e - 1);
			return -1;
		}
		if (pm) {
			if (s < e) {
				cmask_append(pm, 0, s - pmoff);
				cmask_append(pm, 1, e - s);
				cmask_append(pm, 0, pmoff + e2->data_sz - e);
			} else {
				cmask_append(pm, 0, e2->data_sz);
			}
			pmoff += e2->data_sz;
		}
	}

	if (pm) {
		cmask_append(pm, 0, NTFS_ALIGN(pmoff) - pmoff);
		pmoff = NTFS_ALIGN(pmoff);
	}

	if (!(e2->flags & NTFS_IDX_ENTRY_F_CHILD))
		return 0;

	/* Compare child block VCN */
	s = e2->size - sizeof(uint64_t);
	e = e2->size;
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e && memcmp(p1 + s, p2 + s, e - s) != 0) {
		if (nhr.verbose >= 3)
			printf("idxecmp[0x%"PRIX64"]: mismatch at [0x%04X:0x%04X]: child VCN\n",
			       e2->val, s, e - 1);
		return -1;
	}
	if (pm) {
		if (s < e) {
			cmask_append(pm, 0, s - pmoff);
			cmask_append(pm, 1, e - s);
			cmask_append(pm, 0, pmoff + sizeof(uint64_t) - e);
		} else {
			cmask_append(pm, 0, sizeof(uint64_t));
		}
		pmoff += sizeof(uint64_t);
	}

	return 0;
}

/**
 * Compare on disk index node leftover with recovered (manually builded) index
 * node
 *
 * iinfo - index type specific descriptor
 * orig - buffer with on disk data
 * rec - buffer with recovered node
 * bbm - mask, which indicates, what regions of original data is valid
 * pm - padding mask
 */
int idx_idxn_cmp(const struct nhr_idx_info *iinfo, const void *orig,
		 const void *rec, const struct nhr_cmask_elem *bbm,
		 struct nhr_cmask_elem **pm)
{
	const struct ntfs_idx_node_hdr *inh = rec;
	const struct ntfs_idx_entry_hdr *ieh;
	const struct nhr_cmask_elem *bbme = bbm;
	unsigned voff, idxe_cnt = 0;
	int cmp_pos, cmp_len, res;

	if (pm)
		cmask_append(pm, 1, sizeof(*inh));

	/* Compare index node header */
	if (bbme->valid && sizeof(*inh) < bbme->len) {
		if (memcmp(orig, rec, sizeof(*inh)) != 0) {
			if (nhr.verbose >= 3)
				printf("idxncmp: mismatch at [0x%02X:0x%02X]: node header\n",
				       0, (unsigned)sizeof(*inh) - 1);
			return -1;
		}
	}

	if (pm)
		cmask_append(pm, 0, inh->off - sizeof(*inh));

	voff = inh->off;
	do {
		ieh = rec + voff;

		/**
		 * Calculate comparison region, assuming that the index entry
		 * crosses valid block only once.
		 */
		if (bbme->valid) {
			cmp_pos = voff;
			cmp_len = ieh->size;
			if (cmp_pos + cmp_len > bbme->off + bbme->len)
				cmp_len = bbme->off + bbme->len - cmp_pos;
		} else if (voff + ieh->size > bbme->off + bbme->len) {
			assert(!(bbme->end));
			cmp_pos = bbme->off + bbme->len;
			cmp_len = ieh->size - (cmp_pos - voff);
		} else {
			cmp_pos = 0;
			cmp_len = 0;
		}

		if (cmp_len > 0) {
			res = idx_idxe_cmp(iinfo, orig + voff, rec + voff,
					   cmp_pos - voff,
					   cmp_pos - voff + cmp_len, pm);
			if (res) {
				if (nhr.verbose >= 3)
					printf("idxncmp: mismatch at [0x%04X:0x%04X]: idx entry #%u\n",
					       cmp_pos, cmp_pos + cmp_len - 1,
					       idxe_cnt);
				return -1;
			}
		} else if (pm) {
			cmask_append(pm, 0, ieh->size);
		}

		idxe_cnt++;
		voff += ieh->size;
		while (voff > bbme->off + bbme->len)
			bbme++;
	} while (!(ieh->flags & NTFS_IDX_ENTRY_F_LAST));

	if (pm)
		cmask_append(pm, 0, inh->alloc_sz - inh->len);

	return 0;
}

/**
 * Compare on disk index block (record) leftover with recovered (manually
 * builded) index block (record)
 *
 * iinfo - index type specific descriptor
 * orig - buffer with on disk data
 * rec - buffer with recovered block
 * bb_map - bad blocks map
 */
int idx_idxb_cmp(const struct nhr_idx_info *iinfo, const void *orig,
		 const void *rec, unsigned bb_map)
{
	const struct ntfs_idx_rec_hdr *irh = rec;
	const struct ntfs_usa *usa1, *usa2;
	uint16_t usa_mask;
	unsigned cmp_pos, cmp_len;
	struct nhr_cmask_elem *bbm;
	struct nhr_cmask_elem *pm = NULL;/* padding mask (useless regions) */
	struct nhr_cmask_elem **ppm = NULL;
	int res, i;

	if (!(bb_map & 1)) {	/* Compare headers if first page is valid */
		cmp_pos = 0;
		cmp_len = sizeof(*irh);
		if (memcmp(orig + cmp_pos, rec + cmp_pos, cmp_len)) {
			if (nhr.verbose >= 3)
				printf("idxbcmp: mismatch at [0x%04X:0x%04X]: block header\n",
				       cmp_pos, cmp_pos + cmp_len - 1);
			return -1;
		}
		ppm = &pm;	/* Request padding mask creation */
	}

	if (ppm)
		cmask_append(ppm, 1, sizeof(*irh));

	bbm = cmask_from_bb_map(bb_map, nhr.vol.idx_blk_sz / nhr.vol.sec_sz,
				nhr.vol.sec_sz);
	cmask_rshift(bbm, sizeof(*irh));

	res = idx_idxn_cmp(iinfo, orig + sizeof(*irh), rec + sizeof(*irh),
			   bbm, ppm);
	if (res && nhr.verbose >= 3)
		printf("idxbcmp: mismatch at [0x%04X:0x%04X]: idx node\n",
		       (unsigned)sizeof(*irh), nhr.vol.idx_blk_sz - 1);

	cmask_free(bbm);

	if (!(bb_map & 1)) {	/* Compare USA if first page is valid */
		usa1 = orig + irh->r.usa_off;
		usa2 = rec + irh->r.usa_off;
		if (usa1->usn != usa2->usn) {
			if (nhr.verbose >= 3)
				printf("idxbcmp: mismatch at [0x%04X:0x%04X]: USN\n",
				       irh->r.usa_off,
				       irh->r.usa_off + (unsigned)sizeof(usa1->usn) - 1);
			res = -1;
		}
		for (i = 0; i < irh->r.usa_len; ++i) {
			cmask_unpack(pm, &usa_mask, nhr.vol.sec_sz * i +
				     nhr.vol.sec_sz - sizeof(usa_mask),
				     sizeof(usa_mask));
			if (((usa1->sec[i] ^ usa2->sec[i]) & usa_mask) == 0)
				continue;
			if (nhr.verbose >= 3) {
				cmp_pos = irh->r.usa_off + sizeof(usa1->usn);
				cmp_pos+= i * sizeof(usa1->sec[0]);
				cmp_len = sizeof(usa1->sec[0]);
				printf("idxbcmp: mismatch at [0x%04X:0x%04X]: USA#%d (mask = 0x%04X)\n",
				       cmp_pos, cmp_pos + cmp_len - 1, i, usa_mask);
			}
			res = -1;
		}
	}

	cmask_free(pm);

	return res;
}
