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

#ifndef _MFT_AUX_H_
#define _MFT_AUX_H_

off_t mft_entry_offset(uint64_t eid);
const char *mft_rec_magic_dump(const void *buf);
int mft_entry_read(uint64_t entnum, void *buf, off_t *offp);
int mft_entry_preprocess(uint64_t entnum, struct ntfs_mft_entry *ent);
int mft_entry_read_and_preprocess(uint64_t entnum, struct ntfs_mft_entry *ent,
				  int use_overlay);

#endif	/* _MFT_AUX_H_ */
