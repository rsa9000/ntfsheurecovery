/**
 * Compressed mask handling functions
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
#include <stdint.h>
#include <assert.h>

#include "cmask.h"

/**
 * Right shift mask (drop some least significant bytes)
 */
void cmask_rshift(struct nhr_cmask_elem *cmask, unsigned nbytes)
{
	struct nhr_cmask_elem *cme = cmask;

	assert(cme->len > nbytes);
	cme->len -= nbytes;	/* Reduce first element */

	while (!cme->end) {	/* Shift all other elements */
		++cme;
		cme->off -= nbytes;
	}
}

/**
 * Append new block to the end (MSB part) of mask
 */
void cmask_append(struct nhr_cmask_elem **cmask, int valid, unsigned len)
{
	struct nhr_cmask_elem *tmp;
	unsigned i;

	if (!len)	/* Nothing to append - nothing to do */
		return;

	if (!*cmask) {
		tmp = malloc(sizeof(*tmp));
		assert(tmp);
		*cmask = tmp;
		i = 0;
		(*cmask)[i].off = 0;
	} else {
		for (i = 0; !(*cmask)[i].end; i++);
		if (!!(*cmask)[i].valid == !!valid) {
			(*cmask)[i].len += len;
			return;
		}
		tmp = realloc(*cmask, (i + 2) * sizeof(*tmp));
		assert(tmp);
		*cmask = tmp;
		(*cmask)[i].end = 0;
		i++;
		(*cmask)[i].off = (*cmask)[i - 1].off + (*cmask)[i - 1].len;
	}
	(*cmask)[i].valid = !!valid;
	(*cmask)[i].end = 1;
	(*cmask)[i].len = len;
}

/**
 * Build compressed mask from bad blocks map
 */
struct nhr_cmask_elem *cmask_from_bb_map(unsigned map, unsigned nbits,
					 unsigned elem_sz)
{
	struct nhr_cmask_elem *cmask = NULL;
	unsigned i;

	for (i = 0; i < nbits; ++i)
		cmask_append(&cmask, !(map & (1 << i)), elem_sz);

	return cmask;
}

void cmask_free(struct nhr_cmask_elem *cmask)
{
	free(cmask);
}

/**
 * Unpack compressed mask region
 *
 * Assume that each bit of cmask corresponds to octet in output buffer
 */
int cmask_unpack(const struct nhr_cmask_elem *cmask, void *output,
		 unsigned off, unsigned len)
{
	const struct nhr_cmask_elem *ce = cmask;
	uint8_t *out = output;
	unsigned opos = 0, epos = 0;

	/* Rewind to first element of interest */
	while (ce->off + ce->len < off && !ce->end)
		ce++;
	if (ce->off + ce->len < off)
		return -1;

	/* Unpack mask */
	epos = off - ce->off;
	do {
		out[opos] = ce->valid ? 0xff : 0x00;
		if (++epos == ce->len) {
			if (ce->end)
				return -1;
			ce++;
			epos = 0;
		}
	} while (++opos < len);

	return 0;
}
