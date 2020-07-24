/**
 * MFT entries compare functions
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
#include <assert.h>

#include "ntfsheurecovery.h"
#include "ntfs_struct.h"
#include "cmask.h"
#include "idx_cmp.h"
#include "mft_cmp.h"

/**
 * Compare two $STANDARD_INFORMATION attributes
 *
 * p1 - attribute, which is readed from disk (could be broken)
 * p2 - reconstructed attribute (should be valid)
 * off_start - valid data start offset (for on disk attribute)
 * off_end - valid data end offset (for on disk attribute)
 *
 * Returns zero if info are equal
 *
 * NB: this function completely ignores access timestamp (see below), if entry
 * is really corrupted or mismatch then other fields will indicate that.
 */
int mft_attr_stdinf_cmp(const void *p1, const void *p2, unsigned off_start,
			unsigned off_end)
{
	const struct ntfs_attr_stdinf *si = p2;
	int s, e;

	/* Compare part before access timestamp */
	s = 0;
	e = s + __builtin_offsetof(typeof(*si), time_access);
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e && memcmp(p1 + s, p2 + s, e - s) != 0)
		return -1;

	/* Ignore access timestamp since it too oftenly broken :( */

	/* Compare part after access timestamp */
	s = __builtin_offsetof(typeof(*si), time_access) +
	    sizeof(si->time_access);
	e = sizeof(*si);
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e && memcmp(p1 + s, p2 + s, e - s) != 0)
		return -1;

	return 0;
}

/**
 * Compare two $FILE_NAME attributes
 *
 * p1 - attribute, which is readed from disk (could be broken)
 * p2 - reconstructed attribute (should be valid)
 * off_start - valid data start offset (for on disk attribute)
 * off_end - valid data end offset (for on disk attribute)
 *
 * Returns zero if info are equal
 *
 * NB: this function compares only most stable fields (parent, creation time,
 * filename, etc.) and ignore all other, since $FILE_NAME attribute updated only
 * on file creation/moving/renaming and so it could be totaly outdated.
 */
int mft_attr_fname_cmp(const void *p1, const void *p2, unsigned off_start,
		       unsigned off_end)
{
	const struct ntfs_attr_fname *fn = p2;
	int s, e;

	/* Compare parent and creation time */
	s = __builtin_offsetof(typeof(*fn), parent);
	e = __builtin_offsetof(typeof(*fn), time_create) +
	    sizeof(fn->time_create);
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e && memcmp(p1 + s, p1 + s, e - s) != 0)
		return -1;

	/* Ignore other timestamps, size and fileflags since they could be
	 * totaly outdated */

	/* Compare from reparse point till end */
	s = __builtin_offsetof(typeof(*fn), reparse_point);
	e = NTFS_ATTR_FNAME_LEN(fn);
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e && memcmp(p1 + s, p2 + s, e - s) != 0)
		return -1;

	return 0;
}

/**
 * Compare two $INDEX_ROOT attributes
 *
 * attr - reconstructed attribute header
 * ir1 - attribute data, which is readed from disk (could be broken)
 * ir2 - reconstructed attribute data (should be valid)
 * off_start - valid data start offset (for ir1)
 * off_end - valid data end offset (for ir1)
 *
 * Returns zero if index roots are equal
 */
int mft_attr_iroot_cmp(const struct ntfs_attr_hdr *attr,
		       const struct ntfs_attr_iroot *ir1,
		       const struct ntfs_attr_iroot *ir2,
		       unsigned off_start, unsigned off_end)
{
	const int idx_type = idx_detect_type(attr->name_len,
					     NTFS_ATTR_NAME(attr));
	const struct nhr_idx_info *iinfo = idx_info_get(idx_type);
	const int inh_off = __builtin_offsetof(typeof(*ir1), data);
	const struct ntfs_idx_node_hdr *inh;
	struct nhr_cmask_elem *cmask = NULL;
	int s, e, res;

	/* Compare $INDEX_ROOT header part (till last meaningful field) */
	s = 0;
	e = s + __builtin_offsetof(typeof(*ir1), reserved);
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e) {
		if (memcmp((void *)ir1 + s, (void *)ir2 + s, e - s))
			return -1;
	}

	if (off_end < inh_off)
		return 0;

	/* Compare index node part */
	inh = (void *)ir2 + inh_off;
	if (off_start > inh_off) {
		cmask_append(&cmask, 0, off_start - inh_off);
		cmask_append(&cmask, 1, off_end - off_start);
	} else {
		cmask_append(&cmask, 1, off_end - inh_off);
	}
	cmask_append(&cmask, 0, inh->len - (off_end - inh_off));
	res = idx_idxn_cmp(iinfo, (void *)ir1 + inh_off, (void *)ir2 + inh_off,
			   cmask, NULL);
	cmask_free(cmask);

	return res;
}

/**
 * Compare two attributes
 *
 * a1 - attribute, which is readed from disk (could be broken)
 * a2 - reconstructed attribute (should be valid)
 * off_start - valid data start offset (for a1)
 * off_end - valid data end offset (for a1)
 *
 * Returns zero if attributes are equal, otherwise returns -1
 *
 * NB: this function compares only meaningful parts of attributes
 * and ignores padding.
 */
static int mft_attr_cmp(const struct ntfs_attr_hdr *a1,
			const struct ntfs_attr_hdr *a2,
			unsigned off_start, unsigned off_end)
{
	const void *p1 = a1, *p2 = a2;
	int s, e, res;

	/* Compare attribute headers */
	s = 0;
	if (a2->nonresident) {
		e = s + NTFS_ATTR_HDR_NONRESIDENT_LEN;
		if (!(a2->flags & NTFS_ATTR_F_COMP) || a2->firstvcn)
			e -= sizeof(a2->comp_sz);
	} else {
		e = s + NTFS_ATTR_HDR_RESIDENT_LEN;
	}
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e && memcmp(p1 + s, p2 + s, e - s) != 0) {
		if (nhr.verbose >= 3)
			printf("attrcmp[0x%02X-%u]: mismatch at [0x%04X:0x%04X]: header\n",
			       a2->type, a2->id, s, e - 1);
		return -1;
	}

	/* Skip further processing, since END attr does not have header */
	if (a2->type == NTFS_ATTR_END)
		return 0;

	/* Compare attribute names */
	s = a2->name_off;
	e = s + a2->name_len * 2;
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s < e && memcmp(p1 + s, p2 + s, e - s) != 0) {
		if (nhr.verbose >= 3)
			printf("attrcmp[0x%02X-%u]: mismatch at [0x%04X:0x%04X]: name\n",
			       a2->type, a2->id, s, e - 1);
		return -1;
	}

	/* Compare attribute data */
	if (a2->nonresident) {
		s = a2->mp_off;
		e = s + ntfs_attr_mp_len(a2);
	} else {
		s = a2->data_off;
		e = s + a2->data_sz;
	}
	if (s < off_start)
		s = off_start;
	if (e > off_end)
		e = off_end;
	if (s >= e) {			/* Nothing to compare */
		res = 0;
	} else if (a2->nonresident) {	/* Only RAW compare is possible */
		res = 1;
	} else {
		switch (a2->type) {
		case NTFS_ATTR_STDINF:
			res = mft_attr_stdinf_cmp(p1 + a2->data_off,
						  p2 + a2->data_off,
						  s - a2->data_off,
						  e - a2->data_off);
			break;
		case NTFS_ATTR_FNAME:
			res = mft_attr_fname_cmp(p1 + a2->data_off,
						 p2 + a2->data_off,
						 s - a2->data_off,
						 e - a2->data_off);
			break;
		case NTFS_ATTR_IROOT:
			res = mft_attr_iroot_cmp(a2, p1 + a2->data_off,
						 p2 + a2->data_off,
						 s - a2->data_off,
						 e - a2->data_off);
			break;
		default:		/* No specific compare */
			res = 1;
		}
	}
	if (res > 0)
		res = memcmp(p1 + s, p2 + s, e - s);
	if (res) {
		if (nhr.verbose >= 3)
			printf("attrcmp[0x%02X-%u]: mismatch at [0x%04X:0x%04X]: data\n",
			       a2->type, a2->id, s, e - 1);
		return -1;
	}

	return 0;
}

/**
 * Compare on disk MFT entry leftover with recovered (manually builded)
 * MFT entry
 *
 * orig - buffer with on disk data
 * rec - buffer with recovered entry
 * bb_map - bad blocks map
 */
int mft_entry_cmp(const void *orig, const void *rec, unsigned bb_map)
{
	const struct ntfs_mft_entry *ent = rec;
	const struct ntfs_attr_hdr *attr;
	int cmp_pos, cmp_len, res = 0;
	struct nhr_cmask_elem *cmask, *cme;
	unsigned voff, attr_pos = 0;
	uint32_t attr_size;

	if (!(bb_map & 1)) {	/* Compare headers if first sector is valid */
		cmp_pos = 0;
		cmp_len = sizeof(*ent);
		if (memcmp(orig + cmp_pos, rec + cmp_pos, cmp_len)) {
			if (nhr.verbose >= 3)
				printf("mftcmp: mismatch at [0x%04X:0x%04X]: entry header\n",
				       cmp_pos, cmp_pos + cmp_len - 1);
			return -1;
		}
		cmp_pos = ent->r.usa_off;
		/* Calculate really meaningfull marks in USA */
		cmp_len = (ent->used_sz + (nhr.vol.sec_sz - 1)) / nhr.vol.sec_sz;
		if (memcmp(orig + cmp_pos, rec + cmp_pos, cmp_len)) {
			if (nhr.verbose >= 3)
				printf("mftcmp: mismatch at [0x%04X:0x%04X]: USA\n",
				       cmp_pos, cmp_pos + cmp_len - 1);
			return -1;
		}
	}

	cmask = cmask_from_bb_map(bb_map, nhr.vol.mft_ent_sz / nhr.vol.sec_sz,
				  nhr.vol.sec_sz);
	cme = cmask;
	voff = ent->attr_off;
	do {
		attr = rec + voff;

		/**
		 * END attribute could have any size and it value is sensless :(
		 * so compare only attribute type field.
		 *
		 * Another one issue is that entries passed to us as they are
		 * stored on disk and multisector write marker could damage
		 * attribute size field, this is not critical if we just compare
		 * two fields, but could lead to segfault if we use this field
		 * to detect next attribute position.
		 */
		if (attr->type == NTFS_ATTR_END) {
			attr_size = sizeof(attr->type);
		} else {
			unsigned sz_voff = voff + __builtin_offsetof(typeof(*attr), size);

			attr_size = attr->size;

			/* Recover actual attribute size if it overwrited by marker */
			if (sz_voff % nhr.vol.sec_sz + sizeof(attr->size) == nhr.vol.sec_sz)
				memcpy((void *)&attr_size + sizeof(attr->size) - sizeof(uint16_t),
				       ((uint16_t *)(rec + ent->r.usa_off)) + 1 + sz_voff / nhr.vol.sec_sz,
				       sizeof(uint16_t));
		}
		cmp_len = attr_size;

		/**
		 * Get comparison region, assuming that the item attribute
		 * crosses valid block boundary only once.
		 */
		if (cme->valid) {
			cmp_pos = voff;
			if (cmp_pos + cmp_len > cme->off + cme->len)
				cmp_len = cme->off + cme->len - cmp_pos;
		} else if (voff + cmp_len > cme->off + cme->len) {
			assert(!(cme->end));
			cmp_pos = cme->off + cme->len;
			cmp_len-= cmp_pos - voff;
		} else {
			cmp_pos = 0;
			cmp_len = 0;
		}

		if (cmp_len > 0) {
			res = mft_attr_cmp(orig + voff, rec + voff,
					   cmp_pos - voff,
					   cmp_pos - voff + cmp_len);
			if (res) {
				if (nhr.verbose >= 3)
					printf("mftcmp: mismatch at [0x%04X:0x%04X]: attribute #%u (0x%02X-%u) started at 0x%04X\n",
					       cmp_pos, cmp_pos + cmp_len - 1,
					       attr_pos, attr->type, attr->id,
					       voff);
				return -1;
			}
		}

		attr_pos++;
		voff += attr_size;
		while (voff > cme->off + cme->len)
			cme++;
	} while (attr->type != NTFS_ATTR_END);

	cmask_free(cmask);

	return res;
}
