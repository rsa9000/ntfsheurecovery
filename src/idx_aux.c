/**
 * Auxilary index processing functions
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

#include <stdlib.h>

#include "ntfsheurecovery.h"
#include "cache.h"
#include "idx.h"
#include "idx_aux.h"

struct ntfs_mp *idx_blocks2mpl(const struct nhr_idx *idx)
{
	const struct nhr_idx_node *idxn;
	struct ntfs_mp *mp_buf, *mp;
	unsigned mp_buf_sz = 2;	/* Optimized for compact indexes */

	idxn = list_first_entry(&idx->nodes, typeof(*idxn), list);
	while (&idxn->list != &idx->nodes && idxn->vcn < 0)
		idxn = list_next_entry(idxn, list);

	if (&idxn->list == &idx->nodes)	/* No blocks */
		return NULL;
	if (idxn->vcn != 0)		/* Wrong start block */
		return NULL;

	mp_buf = malloc(mp_buf_sz * sizeof(*mp));
	mp = mp_buf;

	mp->vcn = 0;
	mp->lcn = idxn->lcn;
	mp->clen = 1;

	for (idxn = list_next_entry(idxn, list);
	     &idxn->list != &idx->nodes;
	     idxn = list_next_entry(idxn, list)) {
		if (mp->vcn + mp->clen != idxn->vcn) {
			free(mp_buf);
			return NULL;
		}

		if (mp->lcn + mp->clen == idxn->lcn) {
			mp->clen++;
		} else {
			mp++;
			mp->vcn = idxn->vcn;
			mp->lcn = idxn->lcn;
			mp->clen = 1;

			if ((mp - mp_buf) + 1 == mp_buf_sz) {
				mp_buf_sz += 4;
				mp_buf = realloc(mp_buf, mp_buf_sz * sizeof(*mp));
				mp = mp_buf + mp_buf_sz - 4 - 1;
			}
		}
	}

	/* Set end marker */
	mp++;
	mp->vcn = 0;
	mp->lcn = 0;
	mp->clen = 0;

	return mp_buf;
}

int idx_entry_len(const struct nhr_idx *idx, const struct nhr_idx_entry *idxe)
{
	int len = sizeof(struct ntfs_idx_entry_hdr);

	if (!idxe)
		return len;

	if (idxe->key) {
		len += idx_key_sz(idx, idxe->key);
		len += idx->info->data_sz;
		len = NTFS_ALIGN(len);
	}

	/* We assume here that unknown child case equal to no child case */
	if (idxe->child != NHR_IDXN_PTR_NONE &&
	    idxe->child != NHR_IDXN_PTR_UNKN)
		len += sizeof(uint64_t);

	return len;
}

