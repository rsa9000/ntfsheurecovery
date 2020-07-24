/**
 * $Secure file indexes operations
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

#ifndef _IDX_SECURE_H_
#define _IDX_SECURE_H_

#include <wchar.h>

int idx_sdh_key_cmp(const void *k1, const void *k2);
const wchar_t *idx_sdh_entry_name(const struct nhr_idx_entry *idxe);
int idx_sdh_entry_validate(const struct ntfs_idx_entry_hdr *ieh);
struct nhr_idx_entry *idx_sdh_cache_idxe_find(const struct nhr_idx *idx,
					      const struct ntfs_idx_entry_hdr *ieh,
					      unsigned len);
int idx_sii_key_cmp(const void *k1, const void *k2);
const wchar_t *idx_sii_entry_name(const struct nhr_idx_entry *idxe);
int idx_sii_entry_validate(const struct ntfs_idx_entry_hdr *ieh);
struct nhr_idx_entry *idx_sii_cache_idxe_find(const struct nhr_idx *idx,
					      const struct ntfs_idx_entry_hdr *ieh,
					      unsigned len);
uint64_t idx_sec_blk_mfte_detect(const struct ntfs_idx_rec_hdr *irh);
void idx_sec_sds2ent(void);

#endif	/* _IDX_SECURE_H_ */
