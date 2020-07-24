/**
 * Red Black trees
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

#ifndef _RBTREE_H_
#define _RBTREE_H_

#include <stdint.h>

#define RBT_BLACK	0
#define RBT_RED		1

struct rbtree_head {
	uintptr_t p;			/* Parent pointr and color bit */
	struct rbtree_head *left;	/* Left child pointer */
	struct rbtree_head *right;	/* Right child pointer */
	uint64_t key;			/* Node key value */
};

/* Color bits mask inside p field */
#define RBT_C_M		((uintptr_t)1)
/* Parent pointer bits mask inside p field */
#define RBT_P_M		(~RBT_C_M)

#define rbt_set_p(__n, __p)		\
		(__n)->p = ((uintptr_t)(__p) & RBT_P_M) | ((__n)->p & RBT_C_M)
#define rbt_get_p(__n)			\
		((struct rbtree_head *)((__n)->p & RBT_P_M))
#define rbt_get_gp(__n)			\
		rbt_get_p(rbt_get_p(__n))

#define rbt_set_color(__n, __c)		\
		(__n)->p = ((__n)->p & RBT_P_M) | (__c & RBT_C_M)
#define rbt_get_color(__n)		\
		((__n)->p & RBT_C_M)
#define rbt_is_red(__n)			\
		rbt_get_color(__n) == RBT_RED
#define rbt_is_black(__n)		\
		rbt_get_color(__n) == RBT_BLACK
#define rbt_copy_color(__dst, __src)	\
		rbt_set_color(__dst, rbt_get_color(__src))

struct rbtree {
	struct rbtree_head *rbt_root;	/* Root node pointer */
	struct rbtree_head rbt_nil;	/* NIL (leaf) stub node */
};

static inline int rbt_is_nil(const struct rbtree *t,
			     const struct rbtree_head *node)
{
	return node == &t->rbt_nil;
}

void rbtree_init(struct rbtree *t);
struct rbtree_head *rbtree_minimum(const struct rbtree *t,
				   struct rbtree_head *node);
struct rbtree_head *rbtree_maximum(const struct rbtree *t,
				   struct rbtree_head *node);
struct rbtree_head *rbtree_predecessor(const struct rbtree *t,
				       const struct rbtree_head *node);
struct rbtree_head *rbtree_successor(const struct rbtree *t,
				     const struct rbtree_head *node);
void rbtree_left_rotate(struct rbtree *t, struct rbtree_head *node);
void rbtree_right_rotate(struct rbtree *t, struct rbtree_head *node);
void rbtree_insert(struct rbtree *t, struct rbtree_head *node);
void rbtree_delete(struct rbtree *t, struct rbtree_head *node);
struct rbtree_head *rbtree_lookup(struct rbtree *t, uint64_t key);

static inline int rbtree_empty(const struct rbtree *t)
{
	return t->rbt_root == &t->rbt_nil;
}

static inline struct rbtree_head *rbtree_inorder_first(struct rbtree *t)
{
	if (t->rbt_root == &t->rbt_nil)
		return &t->rbt_nil;

	return rbtree_minimum(t, t->rbt_root);
}

static inline struct rbtree_head *rbtree_inorder_next(const struct rbtree *t,
						      struct rbtree_head *node)
{
	return rbtree_successor(t, node);
}

#define rbtree_entry(ptr, type, field)				\
		((type *)((void *)(ptr) - __builtin_offsetof(type, field)))

#define rbt_inorder_walk(pos, tree)				\
		for (pos = rbtree_inorder_first(tree);		\
		     pos != &(tree)->rbt_nil;			\
		     pos = rbtree_inorder_next(tree, pos))

#define rbt_inorder_walk_entry(pos, tree, field)		\
		for (pos = rbtree_entry(rbtree_inorder_first(tree), typeof(*pos), field);\
		     &(pos->field) != &(tree)->rbt_nil;		\
		     pos = rbtree_entry(rbtree_inorder_next(tree, &pos->field), typeof(*pos), field))

#endif	/* _RBTREE_H_ */
