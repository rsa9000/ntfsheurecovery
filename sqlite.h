/**
 * SQLite storage backend interface
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

#ifndef _SQLITE_H_
#define _SQLITE_H_

struct sqlite_tbl {
	const char * const name;	/* Table name */
	const char * const desc;	/* Table description */
	const char * const fields;	/* Table fields list */
};

struct sqlite_idx {
	const char * const name;	/* Index name */
	const char * const desc;	/* Index description */
	const char * const fields;	/* Index fields list */
};

#define SQLITE_BIND(__type, __name, ...)				\
		do {							\
			int __num = sqlite3_bind_parameter_index(stmt,	\
								 ":" __name);\
			int __res = sqlite3_bind_##__type(stmt, __num,	\
							  ##__VA_ARGS__);\
			if (__res != SQLITE_OK) {			\
				errfield = __name;			\
				goto exit_err_bind;			\
			}						\
		} while (0);

int sqlite_open(void);
void sqlite_close(void);
int sqlite_create_tables(const struct sqlite_tbl *tbls, int n, int *err);
int sqlite_drop_tables(const struct sqlite_tbl *tbls, int n, int *err);
int sqlite_create_indexes(const struct sqlite_idx *idxs, int n, int *err);

#endif	/* _SQLITE_H_ */
