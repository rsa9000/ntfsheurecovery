/**
 * Bad blocks (sectors) handling
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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "cmap.h"
#include "sqlite.h"
#include "cache.h"
#include "attr.h"
#include "bb.h"

struct nhr_bb *bb_find(off_t off)
{
	struct rbtree_head *node = rbtree_lookup(&nhr.bb_tree, off);

	return rbt_is_nil(&nhr.bb_tree, node) ? NULL : (struct nhr_bb *)node;
}

void bb_postproc(void)
{
	struct nhr_bb *bb;
	struct nhr_cb *cb = NULL;
	uint64_t cb_end = 0;

	rbt_inorder_walk_entry(bb, &nhr.bb_tree, tree) {
		if (bb->flags)		/* Process only unknown BBs */
			continue;
		if (nhr_bb_off(bb) >= cb_end) {
			cb = cmap_find(nhr_bb_off(bb) / nhr.vol.cls_sz);
			assert(cb);
			cb_end = nhr_cb_end(cb) * nhr.vol.cls_sz;
		}
		if (cb->flags & NHR_CB_F_FREE) {
			bb->flags |= NHR_BB_F_FREE;
		} else if (!cb->flags) {
			bb->flags |= NHR_BB_F_ORPH;
		}
	}
}

void bb_sqlite_clean(void)
{
	static const char *q_drop = "DROP TABLE IF EXISTS bb";

	if (sqlite3_exec(nhr.db, q_drop, NULL, NULL, NULL) != SQLITE_OK)
		fprintf(stderr, "bb: sqlite-err: could not drop table: %s\n",
			sqlite3_errmsg(nhr.db));
}

void bb_sqlite_dump(void)
{
	static const char *q_create = "CREATE TABLE bb ("
		"off UNSIGNED INT64,"
		"flags UNSIGNED,"
		"entnum UNSIGNED INT64,"
		"attr_type UNSIGNED,"
		"attr_id UNSIGNED,"
		"voff UNSIGNED INT64,"
		"entity_idx INT)";
	static const char *q_insert = "INSERT INTO bb"
		"(off, flags, entnum, attr_type, attr_id, voff, entity_idx)"
		"VALUES"
		"(:off, :flags, :entnum, :attr_type, :attr_id, :voff, :entity_idx)";
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	const struct nhr_attr_info *ainfo;
	struct nhr_bb *bb;
	int res, entity_idx;

	res = sqlite3_exec(nhr.db, "BEGIN", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "bb: sqlite-err: could not begin transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		return;
	}

	res = sqlite3_exec(nhr.db, q_create, NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "bb: sqlite-err: could not create table: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "bb: sqlite-err: could not prepare insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	rbt_inorder_walk_entry(bb, &nhr.bb_tree, tree) {
		ainfo = bb->attr_type ? attr_get_info(bb->attr_type) : NULL;
		SQLITE_BIND(int64, "off", nhr_bb_off(bb));
		SQLITE_BIND(int, "flags", bb->flags);
		if (bb->mfte) {
			SQLITE_BIND(int64, "entnum", nhr_mfte_num(bb->mfte));
		} else {
			SQLITE_BIND(null, "entnum");
		}
		SQLITE_BIND(int, "attr_type", bb->attr_type);
		SQLITE_BIND(int, "attr_id", bb->attr_id);
		SQLITE_BIND(int64, "voff", bb->voff);
		if (ainfo && ainfo->entity_idx && bb->entity)
			entity_idx = ainfo->entity_idx(bb->mfte->bmfte,
						       bb->entity);
		else
			entity_idx = ~0;
		SQLITE_BIND(int, "entity_idx", entity_idx);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "bb: sqlite-err: could not insert BB at 0x%08"PRIX64"\n",
				nhr_bb_off(bb));
			goto exit_rollback;
		}
		sqlite3_reset(stmt);
	}

	res = sqlite3_exec(nhr.db, "COMMIT", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "bb: sqlite-err: could not commit transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	goto exit;

exit_err_bind:
	fprintf(stderr, "bb: sqlite-err: could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));

exit_rollback:
	if (sqlite3_exec(nhr.db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
		fprintf(stderr, "bb: sqlite-err: could not rollback transaction: %s\n",
			sqlite3_errmsg(nhr.db));

exit:
	sqlite3_finalize(stmt);
}
