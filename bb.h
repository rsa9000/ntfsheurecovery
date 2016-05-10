/**
 * Bad blocks (sectors) handling code interface
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

#ifndef _BB_H_
#define _BB_H_

#include "rbtree.h"
#include "list.h"

#define NHR_BB_F_AUTO	0x0001	/* BB autodiscovered */
#define NHR_BB_F_FREE	0x0002	/* BB fall into not used area */
#define NHR_BB_F_ORPH	0x0004	/* BB belongs to orphaned cluster */
#define NHR_BB_F_IGNORE	0x0008	/* BB could be ignored */
#define NHR_BB_F_REC	0x0010	/* Associated structure recovered */
#define NHR_BB_F_FORCE	0x0020	/* BB state change forced by user */

/**
 * Bad block descriptor
 * NB: Block on disk offset stored in the tree node key
 */
struct nhr_bb {
	struct rbtree_head tree;
	struct nhr_mft_entry *mfte;	/* Associated entry */
	struct list_head list;	/* Link all BB of item MFT entry */
	unsigned attr_type;	/* Attribute type */
	unsigned attr_id;	/* Attribute id */
	uint64_t voff;		/* Virtual offset inside attribute, bytes */
	unsigned flags;		/* See NHR_BB_F_xxx */
	void *entity;		/* Pointer to corrupted entity */
};

#define nhr_bb_off(__bb)	(__bb)->tree.key
#define nhr_bb_next(__t, __bb)						\
		rbtree_entry(rbtree_successor(__t, &(__bb)->tree),	\
			     struct nhr_bb, tree)

struct nhr_bb *bb_find(off_t off);
void bb_postproc(void);
void bb_sqlite_clean(void);
void bb_sqlite_dump(void);

#endif	/* _BB_H_ */
