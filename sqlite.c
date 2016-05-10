/**
 * SQLite storage backend
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
#include <errno.h>
#include <sqlite3.h>

#include "ntfsheurecovery.h"
#include "sqlite.h"

static void sqlite_upd_hook(void *priv, int cause, const char *db_name,
			    const char *tbl_name, sqlite3_int64 rowid)
{
	uint64_t *last_rowid = priv;

	if (cause != SQLITE_INSERT)
		return;

	*last_rowid = rowid;
}

int sqlite_open(void)
{
	int res;

	res = sqlite3_open(nhr.db_file_name, &nhr.db);
	if (res != SQLITE_OK) {
		fprintf(stderr, "Could not open database: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_free;
	}

	sqlite3_update_hook(nhr.db, sqlite_upd_hook, &nhr.db_last_rowid);

	return 0;

exit_free:
	sqlite3_close(nhr.db);
	nhr.db = NULL;

	return -EINVAL;
}

void sqlite_close(void)
{
	sqlite3_close(nhr.db);
	nhr.db = NULL;
}

int sqlite_create_tables(const struct sqlite_tbl *tbls, int ntbls, int *err)
{
	char q[0x200];
	int i, res;

	for (i = 0; i < ntbls; ++i) {
		snprintf(q, sizeof(q), "CREATE TABLE %s (%s)", tbls[i].name,
			 tbls[i].fields);
		res = sqlite3_exec(nhr.db, q, NULL, NULL, NULL);
		if (res != SQLITE_OK) {
			if (err)
				*err = i;
			return res;
		}
	}

	return SQLITE_OK;
}

int sqlite_drop_tables(const struct sqlite_tbl *tbls, int ntbls, int *err)
{
	char q[0x100];
	int i, res;

	for (i = 0; i < ntbls; ++i) {
		snprintf(q, sizeof(q), "DROP TABLE IF EXISTS %s", tbls[i].name);
		res = sqlite3_exec(nhr.db, q, NULL, NULL, NULL);
		if (res != SQLITE_OK) {
			if (err)
				*err = i;
			return res;
		}
	}

	return SQLITE_OK;
}

int sqlite_create_indexes(const struct sqlite_idx *idxs, int nidxs, int *err)
{
	char q[0x100];
	int i, res;

	for (i = 0; i < nidxs; ++i) {
		snprintf(q, sizeof(q), "CREATE INDEX %s ON %s", idxs[i].name,
			 idxs[i].fields);
		res = sqlite3_exec(nhr.db, q, NULL, NULL, NULL);
		if (res != SQLITE_OK) {
			if (err)
				*err = i;
			return res;
		}
	}

	return SQLITE_OK;
}
