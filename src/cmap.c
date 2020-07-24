/**
 * Clusters map handling code
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "img.h"
#include "misc.h"
#include "sqlite.h"
#include "cmap.h"

static inline void cmap_block_detach(struct nhr_cb *cb)
{
	rbtree_delete(&nhr.cmap, &cb->tree);
}

static inline void cmap_block_insert(struct nhr_cb *cb)
{
	rbtree_insert(&nhr.cmap, &cb->tree);
}

static inline struct nhr_cb *cmap_block_clone(struct nhr_cb *cb)
{
	struct nhr_cb *new = malloc(sizeof(*new));

	return memcpy(new, cb, sizeof(*new));
}

/**
 * Find block, which contains specified cluster
 *
 * off - needle offset, clusters
 */
struct nhr_cb *cmap_find(const uint64_t off)
{
	struct rbtree *t = &nhr.cmap;
	struct nhr_cb *cb = rbtree_entry(t->rbt_root, struct nhr_cb, tree);

	while (!rbt_is_nil(t, &cb->tree)) {
		if (nhr_cb_end(cb) <= off) {
			cb = nhr_cb_right(cb);
		} else if (nhr_ob_off(cb) > off) {
			cb = nhr_cb_left(cb);
		} else {
			return cb;
		}
	}

	return NULL;
}

void cmap_block_mark(uint64_t off, uint64_t len, unsigned flags)
{
	const uint64_t end = off + len;
	uint64_t pos;
	struct nhr_cb *cb, *tmp;
	int cut_left, cut_right;

	assert(len);

	for (pos = off; pos < end;) {
		cb = cmap_find(pos);
		assert(cb);
		if ((cb->flags & flags) == flags) {
			pos = nhr_cb_end(cb);
			continue;
		}
		/* Cut left side of block */
		cut_left = nhr_cb_off(cb) < off;
		if (cut_left) {
			/**
			 * Actually cut right side of current block, create new
			 * block from cut clusters, insert it into the tree and
			 * then switch to new block.
			 */
			tmp = cmap_block_clone(cb);
			tmp->len = nhr_cb_end(cb) - off;
			nhr_cb_off(tmp) = off;
			cmap_block_insert(tmp);
			cb->len -= tmp->len;
			cb = tmp;
		}
		/* Cut right side of block */
		cut_right = nhr_cb_end(cb) > end;
		if (cut_right) {
			/* Just cutoff right side to new block */
			tmp = cmap_block_clone(cb);
			tmp->len = nhr_cb_end(cb) - end;
			nhr_cb_off(tmp) = end;
			cmap_block_insert(tmp);
			cb->len -= tmp->len;
		}
		cb->flags |= flags;
		/* Merge with left block */
		if (!cut_left && (tmp = nhr_cb_prev(&nhr.cmap, cb)) != NULL &&
		    tmp->flags == cb->flags) {
			/* Join with left block and switch to it */
			cmap_block_detach(cb);
			tmp->len += cb->len;
			free(cb);
			cb = tmp;
		}
		/* Merge with right block */
		if (!cut_right && (tmp = nhr_cb_next(&nhr.cmap, cb)) != NULL &&
		    tmp->flags == cb->flags) {
			/* Just join right block to current */
			cmap_block_detach(tmp);
			cb->len += tmp->len;
			free(tmp);
		}
		pos = nhr_cb_end(cb);
	}
}

void cmap_sqlite_clean(void)
{
	static const char *q_drop = "DROP TABLE IF EXISTS cmap";

	if (sqlite3_exec(nhr.db, q_drop, NULL, NULL, NULL) != SQLITE_OK)
		fprintf(stderr, "cmap: sqlite-err: could not drop table: %s\n",
			sqlite3_errmsg(nhr.db));
}

void cmap_sqlite_dump(void)
{
	static const char *q_create = "CREATE TABLE cmap ("
		"off UNSIGNED INT64,"
		"len UNSIGNED INT64,"
		"flags UNSIGNED)";
	static const char *q_insert = "INSERT INTO cmap"
		"(off, len, flags)"
		"VALUES (:off, :len, :flags)";
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	struct nhr_cb *cb;
	int res;

	res = sqlite3_exec(nhr.db, "BEGIN", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cmap: sqlite-err: could not begin transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		return;
	}

	res = sqlite3_exec(nhr.db, q_create, NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cmap: sqlite-err: could not create table: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cmap: sqlite-err: could not prepare insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	rbt_inorder_walk_entry(cb, &nhr.cmap, tree) {
		SQLITE_BIND(int64, "off", nhr_cb_off(cb));
		SQLITE_BIND(int64, "len", cb->len);
		SQLITE_BIND(int, "flags", cb->flags);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "cmap: sqlite-err: could not insert CB [0x%08"PRIX64":0x%08"PRIX64"]\n",
				nhr_cb_off(cb), nhr_cb_end(cb));
			goto exit_rollback;
		}
		sqlite3_reset(stmt);
	}

	res = sqlite3_exec(nhr.db, "COMMIT", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cmap: sqlite-err: could not commit transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	goto exit;

exit_err_bind:
	fprintf(stderr, "cmap: sqlite-err: could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));

exit_rollback:
	if (sqlite3_exec(nhr.db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
		fprintf(stderr, "cmap: sqlite-err: could not rollback transaction: %s\n",
			sqlite3_errmsg(nhr.db));

exit:
	sqlite3_finalize(stmt);
}

void cmap_init(const uint64_t cnum)
{
	struct nhr_cb *cb = calloc(1, sizeof(*cb));

	nhr_cb_off(cb) = 0;
	cb->len = cnum;

	rbtree_insert(&nhr.cmap, &cb->tree);
}
