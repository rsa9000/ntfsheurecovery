/**
 * Compressed mask handling functions interface
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

#ifndef _CMASK_H_
#define _CMASK_H_

/** Compressed mask element */
struct nhr_cmask_elem {
	int valid:1;		/* Is block contains valid data */
	int end:1;		/* Is block finishes sequence */
	unsigned off;		/* Block offset */
	unsigned len;		/* Block length */
};

void cmask_rshift(struct nhr_cmask_elem *cmask, unsigned nbytes);
void cmask_append(struct nhr_cmask_elem **cmask, int valid, unsigned len);
struct nhr_cmask_elem *cmask_from_bb_map(unsigned map, unsigned len,
					 unsigned elem_sz);
void cmask_free(struct nhr_cmask_elem *cmask);
int cmask_unpack(const struct nhr_cmask_elem *cmask, void *output,
		 unsigned off, unsigned len);

#endif	/* _CMASK_H_ */
