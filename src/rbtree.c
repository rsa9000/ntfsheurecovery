/**
 * Red Black tree
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

#include <string.h>

#include "rbtree.h"

void rbtree_init(struct rbtree *t)
{
	memset(&t->rbt_nil, 0x00, sizeof(t->rbt_nil));
	rbt_set_color(&t->rbt_nil, RBT_BLACK);
	t->rbt_root = &t->rbt_nil;
}

struct rbtree_head *rbtree_minimum(const struct rbtree *t,
				   struct rbtree_head *node)
{
	while (!rbt_is_nil(t, node->left))
		node = node->left;

	return node;
}

struct rbtree_head *rbtree_maximum(const struct rbtree *t,
				   struct rbtree_head *node)
{
	while (!rbt_is_nil(t, node->right))
		node = node->right;

	return node;
}

struct rbtree_head *rbtree_predecessor(const struct rbtree *t,
				       const struct rbtree_head *node)
{
	struct rbtree_head *tmp;

	if (!rbt_is_nil(t, node->left))
		return rbtree_maximum(t, node->left);

	tmp = rbt_get_p(node);
	while (!rbt_is_nil(t, tmp) && node == tmp->left) {
		node = tmp;
		tmp = rbt_get_p(tmp);
	}

	return tmp;
}

struct rbtree_head *rbtree_successor(const struct rbtree *t,
				     const struct rbtree_head *node)
{
	struct rbtree_head *tmp;

	if (!rbt_is_nil(t, node->right))
		return rbtree_minimum(t, node->right);

	tmp = rbt_get_p(node);
	while (!rbt_is_nil(t, tmp) && node == tmp->right) {
		node = tmp;
		tmp = rbt_get_p(tmp);
	}

	return tmp;
}

void rbtree_left_rotate(struct rbtree *t, struct rbtree_head *node)
{
	struct rbtree_head *n;

	if (rbt_is_nil(t, node->right))
		return;

	n = node->right;

	node->right = n->left;
	if (!rbt_is_nil(t, n->left))
		rbt_set_p(n->left, node);

	rbt_set_p(n, rbt_get_p(node));
	if (rbt_is_nil(t, rbt_get_p(node))) {
		t->rbt_root = n;
	} else {
		if (rbt_get_p(node)->left == node)
			rbt_get_p(node)->left = n;
		else
			rbt_get_p(node)->right = n;
	}

	n->left = node;
	rbt_set_p(node, n);
}

void rbtree_right_rotate(struct rbtree *t, struct rbtree_head *node)
{
	struct rbtree_head *n;

	if (rbt_is_nil(t, node->left))
		return;

	n = node->left;

	node->left = n->right;
	if (!rbt_is_nil(t, n->right))
		rbt_set_p(n->right, node);

	rbt_set_p(n, rbt_get_p(node));
	if (rbt_is_nil(t, rbt_get_p(node))) {
		t->rbt_root = n;
	} else {
		if (rbt_get_p(node)->left == node)
			rbt_get_p(node)->left = n;
		else
			rbt_get_p(node)->right = n;
	}

	n->right = node;
	rbt_set_p(node, n);
}

static void __rbtree_insert_fixup(struct rbtree *t, struct rbtree_head *node)
{
	struct rbtree_head *uncle;

	while (rbt_is_red(rbt_get_p(node))) {
		if (rbt_get_p(node) == rbt_get_gp(node)->left) {
			uncle = rbt_get_gp(node)->right;
			if (rbt_is_red(uncle)) {
				rbt_set_color(rbt_get_p(node), RBT_BLACK);
				rbt_set_color(uncle, RBT_BLACK);
				rbt_set_color(rbt_get_gp(node), RBT_RED);
				node = rbt_get_gp(node);
			} else {
				if (node == rbt_get_p(node)->right) {
					node = rbt_get_p(node);
					rbtree_left_rotate(t, node);
				}
				rbt_set_color(rbt_get_p(node), RBT_BLACK);
				rbt_set_color(rbt_get_gp(node), RBT_RED);
				rbtree_right_rotate(t, rbt_get_gp(node));
			}
		} else {
			uncle = rbt_get_gp(node)->left;
			if (rbt_is_red(uncle)) {
				rbt_set_color(rbt_get_p(node), RBT_BLACK);
				rbt_set_color(uncle, RBT_BLACK);
				rbt_set_color(rbt_get_gp(node), RBT_RED);
				node = rbt_get_gp(node);
			} else {
				if (node == rbt_get_p(node)->left) {
					node = rbt_get_p(node);
					rbtree_right_rotate(t, node);
				}
				rbt_set_color(rbt_get_p(node), RBT_BLACK);
				rbt_set_color(rbt_get_gp(node), RBT_RED);
				rbtree_left_rotate(t, rbt_get_gp(node));
			}
		}
	}

	rbt_set_color(t->rbt_root, RBT_BLACK);
}

void rbtree_insert(struct rbtree *t, struct rbtree_head *node)
{
	struct rbtree_head *prev = &t->rbt_nil;
	struct rbtree_head *n = t->rbt_root;

	while (!rbt_is_nil(t, n)) {
		prev = n;
		n = node->key < n->key ? n->left : n->right;
	}

	if (!rbt_is_nil(t, prev)) {
		rbt_set_p(node, prev);
		if (node->key < prev->key)
			prev->left = node;
		else
			prev->right = node;
	} else {
		rbt_set_p(node, &t->rbt_nil);
		t->rbt_root = node;
	}

	rbt_set_color(node, RBT_RED);	/* Color new node in red */
	node->left = &t->rbt_nil;
	node->right = &t->rbt_nil;

	__rbtree_insert_fixup(t, node);
}

static void __rbtree_delete_fixup(struct rbtree *t, struct rbtree_head *node)
{
	struct rbtree_head *sibling;

	while (node != t->rbt_root && rbt_is_black(node)) {
		if (node == rbt_get_p(node)->left) {
			sibling = rbt_get_p(node)->right;
			if (rbt_is_red(sibling)) {
				rbt_set_color(sibling, RBT_BLACK);
				rbt_set_color(rbt_get_p(node), RBT_RED);
				rbtree_left_rotate(t, rbt_get_p(node));
				sibling = rbt_get_p(node)->right;
			}
			if (rbt_is_black(sibling->left) && rbt_is_black(sibling->right)) {
				rbt_set_color(sibling, RBT_RED);
				node = rbt_get_p(node);
			} else {
				if (rbt_is_black(sibling->right)) {
					rbt_set_color(sibling->left, RBT_BLACK);
					rbt_set_color(sibling, RBT_RED);
					rbtree_right_rotate(t, sibling);
					sibling = rbt_get_p(node)->right;
				}
				rbt_copy_color(sibling, rbt_get_p(node));
				rbt_set_color(rbt_get_p(node), RBT_BLACK);
				rbt_set_color(sibling->right, RBT_BLACK);
				rbtree_left_rotate(t, rbt_get_p(node));
				node = t->rbt_root;
			}
		} else {
			sibling = rbt_get_p(node)->left;
			if (rbt_is_red(sibling)) {
				rbt_set_color(sibling, RBT_BLACK);
				rbt_set_color(rbt_get_p(node), RBT_RED);
				rbtree_right_rotate(t, rbt_get_p(node));
				sibling = rbt_get_p(node)->left;
			}
			if (rbt_is_black(sibling->left) && rbt_is_black(sibling->right)) {
				rbt_set_color(sibling, RBT_RED);
				node = rbt_get_p(node);
			} else {
				if (rbt_is_black(sibling->left)) {
					rbt_set_color(sibling->right, RBT_BLACK);
					rbt_set_color(sibling, RBT_RED);
					rbtree_left_rotate(t, sibling);
					sibling = rbt_get_p(node)->left;
				}
				rbt_copy_color(sibling, rbt_get_p(node));
				rbt_set_color(rbt_get_p(node), RBT_BLACK);
				rbt_set_color(sibling->left, RBT_BLACK);
				rbtree_right_rotate(t, rbt_get_p(node));
				node = t->rbt_root;
			}
		}
	}

	rbt_set_color(node, RBT_BLACK);
}

void rbtree_delete(struct rbtree *t, struct rbtree_head *node)
{
	struct rbtree_head *r;	/* Replacement node */
	struct rbtree_head *c;	/* Child node */
	int need_fixup = 0;

	if (node->left == &t->rbt_nil || node->right == &t->rbt_nil)
		r = node;
	else
		r = rbtree_successor(t, node);

	if (r->left != &t->rbt_nil)
		c = r->left;
	else
		c = r->right;

	rbt_set_p(c, rbt_get_p(r));

	if (rbt_get_p(r) == &t->rbt_nil) {
		t->rbt_root = c;
	} else {
		if (rbt_get_p(r)->left == r)
			rbt_get_p(r)->left = c;
		else
			rbt_get_p(r)->right = c;
	}

	need_fixup = rbt_is_black(r);

	if (r != node) {
		rbt_set_p(r, rbt_get_p(node));
		if (rbt_get_p(node) == &t->rbt_nil) {
			t->rbt_root = r;
		} else {
			if (rbt_get_p(node)->left == node)
				rbt_get_p(node)->left = r;
			else
				rbt_get_p(node)->right = r;
		}
		r->left = node->left;
		rbt_set_p(node->left, r);
		r->right = node->right;
		rbt_set_p(node->right, r);
		rbt_copy_color(r, node);
	}

	if (need_fixup)
		__rbtree_delete_fixup(t, c);
}

struct rbtree_head *rbtree_lookup(struct rbtree *t, uint64_t key)
{
	struct rbtree_head *n = t->rbt_root;

	while (!rbt_is_nil(t, n)) {
		if (n->key == key)
			return n;
		else if (n->key > key)
			n = n->left;
		else
			n = n->right;
	}

	return &t->rbt_nil;
}
