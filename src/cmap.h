/**
 * Clusters map interface code
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

#ifndef _CMAP_H_
#define _CMAP_H_

#define NHR_CB_F_FREE	0x0001	/* CB is free */
#define NHR_CB_F_ALLOC	0x0002	/* CB is allocated */

/**
 * Cluster block descriptor
 * NB: Block on disk offset (in clusters) stored in the tree node key
 */
struct nhr_cb {
	struct rbtree_head tree;
	uint64_t len;		/* Block length, clusters */
	unsigned flags;		/* See NHR_CB_F_xxx */
};

#define nhr_cb_off(__cb)	(__cb)->tree.key
#define nhr_cb_end(__cb)	((__cb)->tree.key + (__cb)->len)
#define nhr_cb_left(__cb)						\
		rbtree_entry((__cb)->tree.left, struct nhr_cb, tree)
#define nhr_cb_right(__cb)						\
		rbtree_entry((__cb)->tree.right, struct nhr_cb, tree)
#define nhr_cb_prev(__t, __cb)						\
		rbtree_entry(rbtree_predecessor(__t, &(__cb)->tree),	\
			     struct nhr_cb, tree)
#define nhr_cb_next(__t, __cb)						\
		rbtree_entry(rbtree_successor(__t, &(__cb)->tree),	\
			     struct nhr_cb, tree)

struct nhr_cb *cmap_find(const uint64_t off);
void cmap_block_mark(uint64_t off, uint64_t len, unsigned flags);
void cmap_sqlite_clean(void);
void cmap_sqlite_dump(void);
void cmap_init(const uint64_t cnum);

#endif	/* _CMAP_H_ */
