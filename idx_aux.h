/**
 * Auxilary index processing functions interface
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

#ifndef _IDX_AUX_H_
#define _IDX_AUX_H_

#include "idx.h"

static inline int idx_key_sz(const struct nhr_idx *idx,
			     const void *key)
{
	if (idx->info->key_sz_min == idx->info->key_sz_max)
		return idx->info->key_sz_min;
	else
		return idx->info->key_sz(key);
}

struct ntfs_mp *idx_blocks2mpl(const struct nhr_idx *idx);
int idx_entry_len(const struct nhr_idx *idx, const struct nhr_idx_entry *idxe);

#endif	/* _IDX_AUX_H_ */
