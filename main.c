/**
 * NTFS heuristic recovery utility
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <libgen.h>
#include <locale.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "img.h"
#include "ddrescue.h"
#include "attr.h"
#include "data.h"
#include "idx.h"
#include "hints.h"
#include "ntfsheurecovery.h"
#include "bb.h"
#include "cmap.h"
#include "vol.h"
#include "scan.h"
#include "cache.h"
#include "mft_aux.h"
#include "mft_analyze.h"
#include "mft_recover.h"
#include "objid.h"
#include "secure.h"
#include "idx_fetch.h"
#include "idx_i30.h"
#include "idx_secure.h"
#include "idx_recover.h"
#include "name.h"
#include "sqlite.h"
#include "secfile_dump.h"

struct nhr_state nhr;

static const char *version = "0.1 alpha";

static const struct sqlite_tbl main_tables[] = {
	{
		.name = "src",
		.desc = "info sources",
		.fields = "id INT,"
			"name CHAR,"
			"desc CHAR",
	}, {
		.name = "idx_types",
		.desc = "index types",
		.fields = "id INT,"
			"name CHAR NOT NULL,"
			"desc CHAR",
	}, {
		.name = "param",
		.desc = "main parameters",
		.fields = "name CHAR,"
			"val CHAR",
	}
};

#define main_ntables	(sizeof(main_tables)/sizeof(main_tables[0]))

static void main_sqlite_clean(void)
{
	int res, i;

	res = sqlite_drop_tables(main_tables, main_ntables, &i);
	if (res != SQLITE_OK)
		fprintf(stderr, "main: sqlite-err: could not drop %s table: %s\n",
			main_tables[i].desc, sqlite3_errmsg(nhr.db));
}

static int main_sqlite_dump_sources(void)
{
	static const char *q_insert = "INSERT INTO src (id, name, desc)"
		"VALUES (:id, :name, :desc)";
	static const struct {
		unsigned id;
		const char const *name;
		const char const *desc;
	} sources[] = {
		{NHR_SRC_NONE, "None", "No data"},
		{NHR_SRC_HEUR, "Heur", "Heuristic assumption"},
		{NHR_SRC_HINT, "Hint", "User's hint"},
		{NHR_SRC_FN, "FN", "$FILE_NAME attribute"},
		{NHR_SRC_STDINF, "StdInf", "$STANDARD_INFORMATION attribute"},
		{NHR_SRC_ALIST, "AList", "$ATTRIBUTE_LIST attribute"},
		{NHR_SRC_IDX_OBJID, "IdxObjId", "Object id index entry"},
		{NHR_SRC_I30, "I30", "$I30 index entry"},
		{NHR_SRC_ATTR, "Attr", "Attribute header"},
		{NHR_SRC_MFT, "MFT", "MFT entry header"},
	};
	static const int nsources = sizeof(sources)/sizeof(sources[0]);
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	int res, i;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "source:sqlite-err: could not prepare insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		return -1;
	}

	res = SQLITE_ERROR;
	for (i = 0; i < nsources; ++i) {
		SQLITE_BIND(int, "id", sources[i].id);
		SQLITE_BIND(text, "name", sources[i].name, -1, SQLITE_STATIC);
		SQLITE_BIND(text, "desc", sources[i].desc, -1, SQLITE_STATIC);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "source:sqlite-err: could non insert %u (%s) source info: %s\n",
				sources[i].id, sources[i].name,
				sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "source:sqlite-err: could not bind source '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int main_sqlite_dump_idx_info(const struct nhr_idx_info *info,
				     void *priv)
{
	struct sqlite3_stmt *stmt = priv;
	char const *errfield;

	SQLITE_BIND(int, "id", info->type);
	SQLITE_BIND(text16, "name", info->name, info->name_len * 2,
		    SQLITE_STATIC);
	SQLITE_BIND(text, "desc", info->desc, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "idxtypes:sqlite-err: could not insert %s index type: %s\n",
			info->desc, sqlite3_errmsg(nhr.db));
		return -1;
	}

	sqlite3_reset(stmt);

	return 0;

exit_err_bind:
	fprintf(stderr, "idxtypes:sqlite-err: could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	return -1;
}

static int main_sqlite_dump_idx_types(void)
{
	static const char *q_insert = "INSERT INTO idx_types (id, name, desc)"
		"VALUES (:id, :name, :desc)";
	struct sqlite3_stmt *stmt = NULL;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "idxtypes:sqlite-err: could not prepare insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		return -1;
	}

	res = idx_info_foreach_cb(main_sqlite_dump_idx_info, stmt);
	if (res)
		goto exit;

	res = SQLITE_OK;
exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int main_sqlite_dump_param(void)
{
	static const char *q_insert = "INSERT INTO param (name, val)"
		"VALUES (?1, ?2)";
	static const struct {
		const char const *name;
		unsigned sz;
		const void *data;
	} params[] = {
		{"version", 0, &version},
#define __PARAM(__name, __var)	{__name, sizeof(typeof(__var)), &(__var)}
		__PARAM("vol_sec_sz", nhr.vol.sec_sz),
		__PARAM("vol_cls_sz", nhr.vol.cls_sz),
		__PARAM("vol_sec_num", nhr.vol.sec_num),
		__PARAM("vol_cls_num", nhr.vol.cls_num),
		__PARAM("vol_mft_lcn", nhr.vol.mft_lcn),
		__PARAM("vol_mft_sz", nhr.vol.mft_sz),
		__PARAM("vol_mft_ent_sz", nhr.vol.mft_ent_sz),
		__PARAM("vol_idx_blk_sz", nhr.vol.idx_blk_sz),
#undef __PARAM
	};
	static const int nparams = sizeof(params)/sizeof(params[0]);
	struct sqlite3_stmt *stmt = NULL;
	int res, i;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "param: sqlite-err: could not prepare insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		return -1;
	}

	for (i = 0; i < nparams; ++i) {
		sqlite3_reset(stmt);
		res = sqlite3_bind_text(stmt, 1, params[i].name, -1,
					SQLITE_STATIC);
		if (res != SQLITE_OK) {
			fprintf(stderr, "params: sqlite-err: could not set param %s name: %s\n",
				params[i].name, sqlite3_errmsg(nhr.db));
			continue;
		}
		if (params[i].sz == 0) {
			res = sqlite3_bind_text(stmt, 2,
						*(char **)params[i].data, -1,
						SQLITE_STATIC);
		} else if (params[i].sz == 1) {
			res = sqlite3_bind_int(stmt, 2,
					       *(uint8_t *)params[i].data);
		} else if (params[i].sz == 4) {
			res = sqlite3_bind_int(stmt, 2,
					       *(uint32_t *)params[i].data);
		} else if (params[i].sz == 8) {
			res = sqlite3_bind_int64(stmt, 2,
						 *(uint64_t *)params[i].data);
		} else {
			assert(0);
		}
		if (res != SQLITE_OK) {
			fprintf(stderr, "params: sqlite-err: could not set param %s value: %s\n",
				params[i].name, sqlite3_errmsg(nhr.db));
			continue;
		}
		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "params: sqlite-err: could not store %s to DB: %s\n",
				params[i].name, sqlite3_errmsg(nhr.db));
		}
	}

	sqlite3_finalize(stmt);

	return 0;
}

static void main_sqlite_dump(void)
{
	int res, i;

	res = sqlite3_exec(nhr.db, "BEGIN", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "main:sqlite-err: could not begin transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		return;
	}

	res = sqlite_create_tables(main_tables, main_ntables, &i);
	if (res != SQLITE_OK) {
		fprintf(stderr, "main:sqlite-err: could not create %s table: %s\n",
			main_tables[i].desc, sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	res = main_sqlite_dump_sources();
	if (res)
		goto exit_rollback;

	res = main_sqlite_dump_idx_types();
	if (res)
		goto exit_rollback;

	res = main_sqlite_dump_param();
	if (res)
		goto exit_rollback;

	res = sqlite3_exec(nhr.db, "COMMIT", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "main:sqlite-err: could not commit transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	return;

exit_rollback:
	if (sqlite3_exec(nhr.db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
		fprintf(stderr, "main:sqlite-err: could not rollback transaction: %s\n",
			sqlite3_errmsg(nhr.db));
}

static void usage(const char *progname)
{
	printf(
		"NTFS heuristic recovery v%s\n"
		"\n"
		"Usage:\n"
		"  %s [-v] [-B <bbfile>[:<off>]] [-H <hintsfile>] [-D <dbfile>] [-O <outdir>] <fsfile>\n"
		"  %s -h\n"
		"\n"
		"Options:\n"
		"  <fsfile>             File, which contains filesystem. That should be either\n"
		"                       block device (e.g. /dev/sdX1) or image file (e.g. dump.img)\n"
		"  -B <bbfile>[:<off>]  Read <bbfile> and extract bad blocks list from it. Now only\n"
		"                       ddrescue log file supported. If <off> offset is specified, then\n"
		"                       it value would be substructed from each bad block offset\n"
		"  -H <hintsfile>       Hints file (see documentation)\n"
		"  -D <dbfile>          SQLite database file to store internal structures to\n"
		"  -O <outdir>          Store overlay fragments to <outdir> directory\n"
		"  -h                   Print this help and exit\n"
		"  -v                   Be verbose (use multiple times to greatly increase messages number)\n"
		"\n", version,
		progname, progname
	);
}

int main(int argc, char *argv[])
{
	const char *progname = basename(argv[0]);
	char *p, *ep;
	int opt;
	int res;

	memset(&nhr, 0x00, sizeof(nhr));
	nhr.fs_fd = -1;
	rbtree_init(&nhr.hints);
	rbtree_init(&nhr.bb_tree);
	rbtree_init(&nhr.img_overlay);
	rbtree_init(&nhr.cmap);
	cache_init();
	nhr.mft_bitmap = NULL;

	while ((opt = getopt(argc, argv, "D:H:B:O:hv")) != -1) {
		switch (opt) {
		case 'B':
			p = strrchr(optarg, ':');
			if (p) {
				errno = 0;
				nhr.bb_file_off = strtoull(p + 1, &ep, 0);
				if (errno || *ep != '\0') {
					fprintf(stderr, "%s: invalid bad block list offset\n",
						progname);
					exit(EXIT_FAILURE);
				}
				*p = '\0';
			}
			nhr.bb_file_name = optarg;
			break;
		case 'H':
			nhr.hints_file_name = optarg;
			break;
		case 'D':
			nhr.db_file_name = optarg;
			break;
		case 'O':
			nhr.out_dir = optarg;
			break;
		case 'h':
			usage(progname);
			return EXIT_SUCCESS;
		case 'v':
			nhr.verbose++;
			break;
		default:
			goto exit_err_opt;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "%s: no FS file specified\n", progname);
		goto exit_err_opt;
	}
	nhr.fs_file_name = argv[optind++];

	setlocale(LC_CTYPE, "");

	res = img_open();
	if (res) {
		fprintf(stderr, "Could not open image\n");
		return EXIT_FAILURE;
	}

	res = vol_open();
	if (res) {
		fprintf(stderr, "Could not open volume\n");
		return EXIT_FAILURE;
	}

	cmap_init(nhr.vol.cls_num);

	if (nhr.out_dir) {
		struct stat sb;

		if (stat(nhr.out_dir, &sb) == -1) {
			fprintf(stderr, "Could not stat output directory '%s': %s\n",
				nhr.out_dir, strerror(errno));
			return EXIT_FAILURE;
		}

		if (!S_ISDIR(sb.st_mode)) {
			fprintf(stderr, "Specified output path '%s' is not directory\n",
				nhr.out_dir);
			return EXIT_FAILURE;
		}
	}

	if (nhr.bb_file_name)
		ddrescue_log_parse(nhr.bb_file_name,
				   nhr.bb_file_off);

	if (rbtree_empty(&nhr.bb_tree) && nhr.verbose >= 1)
		printf("bb: no badblocks found, do you really need to recover something?\n");

	if (nhr.hints_file_name) {
		res = hints_file_parse(nhr.hints_file_name);
		if (res)
			return EXIT_FAILURE;
	}

	if (nhr.db_file_name) {
		res = sqlite_open();
		if (res) {
			fprintf(stderr, "Could not open SQlite storage in file: %s\n",
				nhr.db_file_name);
			return EXIT_FAILURE;
		}
	}

	res = mft_open();
	if (res) {
		fprintf(stderr, "Could not open MFT\n");
		return EXIT_FAILURE;
	}

	mft_bitmap_process();

	vol_bitmap_read();

	res = vol_upcase_read();
	if (res) {
		fprintf(stderr, "Could not read $UpCase\n");
		return EXIT_FAILURE;
	}

	mft_analyze_all();

#if 0	/* $LogFile content yet never helps to recover any structure :( */
	logfile_analyze();
#endif

	/**
	 * Initial analisys finished, now attempt to recover
	 * metadata.
	 */

	objid_analyze();

	secure_sds_recover();

	idx_i30_mft2ent();

	mft_hints2meta();

	cls_scan_orph();

	data_apply_hints();

	mft_gen_dosnames();

	idx_i30_cache2ent();

	idx_sec_sds2ent();

	idx_read_blocks();

	idx_recover_indexes();

	data_recover();

	data_verify_all();

	idx_verify_all();

	idx_recover_blocks();

	data_bb_ignore();

	name_verify_all();

	mft_attr_bind();

	mft_attr_recover();

	attr_verify_all();

	mft_recover_entries();

	if (nhr.db) {
		bb_postproc();

#if 0
		/* Uncomment if you need $Secure dump */
		secfile_dump();
#endif

		main_sqlite_clean();
		hints_sqlite_clean();
		cmap_sqlite_clean();
		bb_sqlite_clean();
		cache_sqlite_clean();

		main_sqlite_dump();
		hints_sqlite_dump();
		cmap_sqlite_dump();
		bb_sqlite_dump();
		cache_sqlite_dump();

		sqlite_close();
	}

	if (nhr.out_dir && img_overlay_export(nhr.out_dir) != 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;

exit_err_opt:
	fprintf(stderr, "Try '%s -h' for more information\n", progname);
	return EXIT_FAILURE;
}
