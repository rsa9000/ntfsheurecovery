/**
 * Generic index functions interface
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

#ifndef _IDX_H_
#define _IDX_H_

#include <wchar.h>

/* Forward declaration */
struct nhr_idx;
struct nhr_idx_entry;

struct nhr_idx_info {
	int type;
	uint8_t name[10];
	unsigned name_len;
	const char const *desc;
	unsigned attr;		/* Attribute in index (or zero) */
	unsigned sort;		/* Sorting rule, see NTFS_IDX_SORT_xxx */
	unsigned key_sz_min;
	unsigned key_sz_max;
	int (*key_cmp)(const void *k1, const void *k2);
	int (*key_sz)(const void *key);
	int (*key_match)(const void *k1, const void *k2,
			 unsigned off_start, unsigned off_end);
	unsigned data_sz;	/* Size of the data associated with idx entry.
				 * If equal to 0 then data size is uint64_t
				 * and stored directly in the entry header, if
				 * greater than zero then data stored after
				 * index entry key. */
	const wchar_t *(*entry_name)(const struct nhr_idx_entry *idxe);
	uint64_t (*blk_mfte_detect)(const struct ntfs_idx_rec_hdr *irh);
	int (*entry_validate)(const struct ntfs_idx_entry_hdr *ieh);
	struct nhr_idx_entry *(*cache_idxe_find)(const struct nhr_idx *idx,
						 const struct ntfs_idx_entry_hdr *ieh,
						 unsigned len);
};

const struct nhr_idx_info *idx_info_get(int type);
int idx_info_foreach_cb(int (*cb)(const struct nhr_idx_info *, void *),
			void *priv);
int idx_detect_type(unsigned name_len, const uint8_t *name);
void idx_verify_all(void);

#endif	/* _IDX_H_ */
