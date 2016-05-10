/**
 * Auxilary code for MFT processing
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
#include <string.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "ntfs.h"
#include "img.h"
#include "mft_aux.h"

/**
 * Convert MFT entry number to the on disk offset
 * eid - MFT entry number
 * return mft entry offset or zero if nothing found
 */
off_t mft_entry_offset(uint64_t eid)
{
	uint64_t voff = eid * nhr.vol.mft_ent_sz;	/* Virtual offset */
	const uint64_t vcn = voff / nhr.vol.cls_sz;
	struct ntfs_mp *mp = ntfs_mpl_find(nhr.mft_data, nhr.mft_data_num, vcn);

	if (!mp)
		return 0;

	return (mp->lcn - mp->vcn) * nhr.vol.cls_sz + voff;
}

const char *mft_rec_magic_dump(const void *buf)
{
	static char strbuf[2 * 4 + 1];
	const uint8_t *magic = buf;

	snprintf(strbuf, sizeof(strbuf), "%02hhX%02hhX%02hhX%02hhX",
		 magic[0], magic[1], magic[2], magic[3]);

	return strbuf;
}

/**
 * Read one MFT entry
 * entnum - MFT entry number
 * buf - buffer for MFT entry
 * offp - location for entry offset value
 */
int mft_entry_read(uint64_t entnum, void *buf, off_t *offp)
{
	off_t off = mft_entry_offset(entnum);
	int res;

	if (!off) {
		fprintf(stderr, "Could not find cluster of MFT entry #%"PRIu64"\n",
			entnum);
		return -ENOENT;
	}

	res = img_read_sectors(off, buf, nhr.vol.mft_ent_sz / nhr.vol.sec_sz);
	if (res) {
		fprintf(stderr, "mft[#%"PRIu64"]: could not read entry from 0x%08"PRIX64" (err: %d): %s\n",
			entnum, (uint64_t)off, -res, strerror(-res));
		return res;
	}

	if (offp)
		*offp = off;

	return 0;
}

/**
 * Preprocess MFT entry
 * entnum - MFT entry number
 * ent - MFT entry buffer
 * Returns zero or negative error code
 */
int mft_entry_preprocess(uint64_t entnum, struct ntfs_mft_entry *ent)
{
	int res;

	if (strncmp("FILE", ent->r.magic, 4) != 0) {
		fprintf(stderr, "mft[#%"PRIu64"]: invalid magic %s expect \"FILE\"\n",
			entnum, mft_rec_magic_dump(&ent->r));
		return -EINVAL;
	}

	res = ntfs_usa_apply(ent, nhr.vol.mft_ent_sz, nhr.vol.sec_sz);
	if (res) {
		fprintf(stderr, "mft[#%"PRIu64"]: markers itegrity check error\n",
			entnum);
		return -errno;
	}

	return 0;
}

int mft_entry_read_and_preprocess(uint64_t entnum, struct ntfs_mft_entry *ent,
				  int use_overlay)
{
	off_t off;
	int res;

	res = mft_entry_read(entnum, ent, &off);
	if (res)
		return res;

	if (use_overlay)
		img_overlay_apply(off, ent, nhr.vol.mft_ent_sz);

	res = mft_entry_preprocess(entnum, ent);
	if (res)
		return res;

	return 0;
}
