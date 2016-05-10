/**
 * Image I/O functions interface
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

#ifndef _IMG_H_
#define _IMG_H_

#include "ntfsheurecovery.h"

int img_open(void);
int img_read_sectors(off_t off, void *buf, size_t num);
void img_fetch_mp_data(const struct ntfs_mp *mpl, void *buf);
void img_make_digest(const struct ntfs_mp *mpl, size_t len, uint8_t *digest);

static inline int img_read_clusters(off_t lcn, void *buf, size_t num)
{
	return img_read_sectors(lcn * nhr.vol.cls_sz, buf,
			        num * nhr.vol.cls_ssz);
}

static inline int img_read_cluster(off_t lcn, void *buf)
{
	return img_read_clusters(lcn, buf, 1);
}

/**
 * Overlay block descriptor
 * NB: Block on disk offset stored in the tree node key
 */
struct nhr_ob {
	struct rbtree_head tree;
	unsigned len;		/* Block length, bytes */
	void *buf;		/* Block data buffer */
};

#define nhr_ob_off(__ob)	(__ob)->tree.key
#define nhr_ob_end(__ob)	((__ob)->tree.key + (__ob)->len)
#define nhr_ob_left(__ob)						\
		rbtree_entry((__ob)->tree.left, struct nhr_ob, tree)
#define nhr_ob_right(__ob)						\
		rbtree_entry((__ob)->tree.right, struct nhr_ob, tree)
#define nhr_ob_next(__t, __ob)						\
		rbtree_entry(rbtree_successor(__t, &(__ob)->tree),	\
			     struct nhr_ob, tree)

void img_overlay_apply(uint64_t off, void *buf, size_t len);
struct nhr_ob *img_overlay_alloc(size_t buf_sz);
void img_overlay_add(struct nhr_ob *ob);
int img_overlay_export(const char *outdir);

#endif	/* _IMG_H_ */
