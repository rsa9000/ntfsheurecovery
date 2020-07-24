/**
 * NTFS entities cache
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
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "bb.h"
#include "cmask.h"
#include "idx.h"
#include "attr.h"
#include "mft_aux.h"
#include "misc.h"
#include "sqlite.h"
#include "cache.h"

static const struct sqlite_tbl cache_tables[] = {
	{
		.name = "mft_entries",
		.desc = "MFT entries",
		.fields = "num UNSIGNED INT64,"
			"f_cmn UNSIGNED,"
			"f_bad UNSIGNED,"
			"f_rec UNSIGNED,"
			"f_sum UNSIGNED,"
			"bb_map UNSIGNED,"
			"bb_rec UNSIGNED,"
			"parent UNSIGNED INT64,"
			"parent_src UNSIGNED,"
			"base UNSIGNED INT64,"
			"base_src UNSIGNED,"
			"seqno UNSIGNED,"
			"seqno_src UNSIGNED,"
			"t_create UNSIGNED INT64,"
			"t_create_src UNSIGNED,"
			"t_change UNSIGNED INT64,"
			"t_change_src UNSIGNED,"
			"t_mft UNSIGNED INT64,"
			"t_mft_src UNSIGNED,"
			"t_access UNSIGNED INT64,"
			"t_access_src UNSIGNED,"
			"fileflags UNSIGNED,"
			"fileflags_src UNSIGNED,"
			"sid UNSIGNED,"
			"sid_src UNSIGNED",
	}, {
		.name = "mft_entries_fn",
		.desc = "entries fn",
		.fields = "num INTEGER,"
			"attr_id UNSIGNED,"
			"src INTEGER,"
			"type UNSIGNED,"
			"len UNSIGNED,"
			"name TEXT,"
			"PRIMARY KEY(num, type)",
	}, {
		.name = "mft_entries_oid",
		.desc = "entries object id",
		.fields = "num INTEGER PRIMARY KEY,"
			"src UNSIGNED,"
			"obj_id TEXT,"
			"birth_vol_id TEXT,"
			"birth_obj_id TEXT,"
			"domain_id TEXT",
	}, {
		.name = "data",
		.desc = "data streams",
		.fields = "mft_entnum UNSIGNED INT64,"
			"pos UNSIGNED,"
			"name TEXT,"
			"flags UNSIGNED,"
			"sz_alloc UNSIGNED INT64,"
			"sz_alloc_src UNSIGNED,"
			"sz_used UNSIGNED INT64,"
			"sz_used_src UNSIGNED,"
			"sz_init UNSIGNED INT64,"
			"sz_init_src UNSIGNED,"
			"PRIMARY KEY(mft_entnum, pos)",
	}, {
		.name = "data_mp",
		.desc = "data clusters",
		.fields = "mft_entnum UNSIGNED INT64,"
			"pos UNSIGNED,"
			"vcn UNSIGNED INT64,"
			"lcn UNSIGNED INT64,"
			"clen UNSIGNED INT64,"
			"PRIMARY KEY(mft_entnum, pos, vcn)",
	}, {
		.name = "data_chunks",
		.desc = "data chunks",
		.fields = "mft_entnum UNSIGNED INT64,"
			"pos UNSINGED NOT NULL,"
			"voff UNSIGNED NOT NULL,"
			"len UNSIGNED NOT NULL,"
			"src UNSIGNED NOT NULL,"
			"PRIMARY KEY(mft_entnum, pos, voff)",
	}, {
		.name = "data_segments",
		.desc = "data stream segments",
		.fields = "mft_entnum UNSIGNED INT64,"
			"pos UNSIGNED NOT NULL,"
			"firstvcn UNSIGNED INT64 NOT NULL,"
			"firstvcn_src USIGNED NOT NULL,"
			"lastvcn UNSIGNED INT64 NOT NULL,"
			"lastvcn_src UNSIGNED NOT NULL,"
			"attr_entnum UNSIGNED INT64,"
			"attr_id UNSIGNED,"
			"PRIMARY KEY(mft_entnum, pos, firstvcn)",
	}, {
		.name = "mft_entries_attrs",
		.desc = "entries attribute list items",
		.fields = "num UNSIGNED INT64 NOT NULL,"
			"pos UNSIGNED NOT NULL,"
			"src UNSIGNED NOT NULL,"
			"type UNSIGNED NOT NULL,"
			"id UNSIGNED NOT NULL,"
			"name TEXT,"
			"entnum UNSIGNED INT64 NOT NULL,"
			"firstvcn UNSIGNED INT64 NOT NULL,"
			"entity_idx UNSIGNED NOT NULL,"
			"PRIMARY KEY(num, pos)",
	}, {
		.name = "idx_nodes",
		.desc = "index nodes",
		.fields = "mft_entnum UNSIGNED INT64,"
			"type INTEGER NOT NULL,"
			"vcn UNSIGNED INT64,"
			"lcn UNSIGNED INT64,"
			"parent UNSIGNED INT64,"
			"level INTEGER,"
			"flags UNSIGNED INTEGER,"
			"bb_map UNSIGNED,"
			"bb_rec UNSIGNED,"
			"PRIMARY KEY(mft_entnum, type, vcn)",
	}, {
		.name = "idx_entries",
		.desc = "generic index entries",
		.fields = "mft_entnum UNSIGNED INT64,"
			"type INTEGER NOT NULL,"
			"pos UNSIGNED NOT NULL,"
			"container UNSIGNED INT64,"
			"child UNSIGNED INT64,"
			"voff UNSIGNED NOT NULL,"
			"PRIMARY KEY (mft_entnum, type, pos)",
	}, {
		.name = "idx_entries_dir",
		.desc = "directory index entries",
		.fields = "mft_entnum UNSIGNED INT64,"
			"pos UNSIGNED NOT NULL,"
			"parent UNSIGNED INT64,"
			"t_create UNSIGNED INT64,"
			"t_change UNSIGNED INT64,"
			"t_mft UNSIGNED INT64,"
			"t_access UNSIGNED INT64,"
			"alloc_sz UNSIGNED INT64,"
			"used_sz UNSIGNED INT64,"
			"flags UNSIGNED,"
			"reparse UNSINGED,"
			"name_len UNSIGNED,"
			"name_type UNSIGNED,"
			"name TEXT,"
			"mref UNSIGNED INT64,"
			"PRIMARY KEY (mft_entnum, pos)",
	}, {
		.name = "idx_entries_sdh",
		.desc = "security descriptors hashes index",
		.fields = "mft_entnum UNSIGNED INT64,"
			"pos UNSIGNED NOT NULL,"
			"hash UNSIGNED NOT NULL,"
			"id UNSIGNED NOT NULL,"
			"voff UNSIGNED NOT NULL,"
			"len UNSIGNED NOT NULL,"
			"PRIMARY KEY (mft_entnum, pos)",
	}, {
		.name = "idx_entries_sii",
		.desc = "security descriptors id index",
		.fields = "mft_entnum UNSIGNED INT64,"
			"pos UNSIGNED NOT NULL,"
			"id UNSIGNED NOT NULL,"
			"hash UNSIGNED NOT NULL,"
			"voff UNSIGNED NOT NULL,"
			"len UNSIGNED NOT NULL,"
			"PRIMARY KEY (mft_entnum, pos)",
	}, {
		.name = "mft_entries_tree",
		.desc = "entries tree",
		.fields = "entry UNSIGNED INT64 NOT NULL,"
			"parent UNSIGNED INT64 NOT NULL,"
			"h UNSIGNED NOT NULL,"
			"PRIMARY KEY (parent, entry)",
	}
};

#define cache_ntables	(sizeof(cache_tables)/sizeof(cache_tables[0]))

static const struct sqlite_idx cache_indexes[] = {
	{
		.name = "mft_entries_fn_num",
		.desc = "entries fn",
		.fields = "mft_entries_fn (num)",
	}, {
		.name = "idx_entries_dir_key",
		.desc = "directory entries",
		.fields = "idx_entries_dir (mft_entnum, mref, name_type)",
	}, {
		.name = "idx_entries_sdh_key",
		.desc = "security descriptors hashes",
		.fields = "idx_entries_sdh (mft_entnum, hash, id)",
	}, {
		.name = "idx_entries_sii_key",
		.desc = "security descriptors ids",
		.fields = "idx_entries_sii (mft_entnum, id)",
	}
};

#define cache_nindexes	(sizeof(cache_indexes)/sizeof(cache_indexes[0]))

static int cache_mft_sqlite_dump_attrs(struct nhr_mft_entry *mfte)
{
	static const char *q_insert = "INSERT INTO mft_entries_attrs"
		"(num, pos, src, type, id, name, entnum, firstvcn, entity_idx)"
		"VALUES"
		"(:num, :pos, :src, :type, :id, :name, :entnum, :firstvcn,"
		":entity_idx)";
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	struct nhr_alist_item *ali;
	const struct nhr_attr_info *ainfo;
	unsigned pos, entity_idx;
	int res;

	if (list_empty(&mfte->alist))
		return 0;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:mft:sqlite: could not prepare MFT attributes insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "num", nhr_mfte_num(mfte));

	res = SQLITE_ERROR;
	pos = 0;
	list_for_each_entry(ali, &mfte->alist, list) {
		ainfo = attr_get_info(ali->type);
		SQLITE_BIND(int, "pos", pos++);
		SQLITE_BIND(int, "src", ali->src);
		SQLITE_BIND(int, "type", ali->type);
		SQLITE_BIND(int, "id", ali->id);
		if (ali->name_len) {
			SQLITE_BIND(text16, "name", ali->name,
				    ali->name_len * 2, SQLITE_STATIC);
		} else {
			SQLITE_BIND(null, "name");
		}
		SQLITE_BIND(int64, "entnum", nhr_mfte_num(ali->mfte));
		SQLITE_BIND(int64, "firstvcn", ali->firstvcn);
		if (ainfo && ainfo->entity_idx && ali->entity)
			entity_idx = ainfo->entity_idx(mfte, ali->entity);
		else
			entity_idx = ~0;
		SQLITE_BIND(int, "entity_idx", entity_idx);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "cache:mft:sqlite: could not insert MFT entry"
				"#%"PRIu64" attribute info: %s\n",
				nhr_mfte_num(mfte), sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:mft:sqlite: could not bind MFT attrs fn '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int cache_mft_sqlite_dump_fn(struct nhr_mft_entry *mfte)
{
	static const char *q_insert = "INSERT INTO mft_entries_fn"
		"(num, attr_id, src, type, len, name) VALUES"
		"(:num, :attr_id, :src, :type, :len, :name)";
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	unsigned i;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:mft:sqlite: could not prepare MFT fn insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "num", nhr_mfte_num(mfte));

	res = SQLITE_ERROR;
	for (i = 0; i < sizeof(mfte->names)/sizeof(mfte->names[0]); ++i) {
		if (mfte->names[i].src == NHR_SRC_NONE)
			continue;
		SQLITE_BIND(int, "attr_id", mfte->names[i].attr_id);
		SQLITE_BIND(int, "src", mfte->names[i].src);
		SQLITE_BIND(int, "type", i);
		SQLITE_BIND(int, "len", mfte->names[i].len);
		SQLITE_BIND(text16, "name", mfte->names[i].name,
			    mfte->names[i].len * 2, SQLITE_STATIC);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "cache:mft:sqlite: could not insert MFT entry"
				"#%"PRIu64" fn: %s\n",
				nhr_mfte_num(mfte),
				sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:mft:sqlite: could not bind MFT fn '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int cache_mft_sqlite_dump_oid(struct nhr_mft_entry *mfte)
{
	static const char *q_insert = "INSERT INTO mft_entries_oid"
		"(num, src, obj_id, birth_vol_id, birth_obj_id, domain_id)"
		"VALUES (:num, :src, :obj_id, :birth_vol_id, :birth_obj_id,"
		":domain_id)";
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	char guid_str[4][NTFS_GUID_STR_LEN + 1];
	int res;

	if (mfte->oid_src == NHR_SRC_NONE)
		return 0;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:mft:sqlite: could not prepare MFT OID insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "num", nhr_mfte_num(mfte));
	SQLITE_BIND(int, "src", mfte->oid_src);
	ntfs_guid2str_r(&mfte->oid->obj_id, guid_str[0]);
	SQLITE_BIND(text, "obj_id", guid_str[0], NTFS_GUID_STR_LEN,
		    SQLITE_STATIC);
	ntfs_guid2str_r(&mfte->oid->birth_vol_id, guid_str[1]);
	SQLITE_BIND(text, "birth_vol_id", guid_str[1], NTFS_GUID_STR_LEN,
		    SQLITE_STATIC);
	ntfs_guid2str_r(&mfte->oid->birth_obj_id, guid_str[2]);
	SQLITE_BIND(text, "birth_obj_id", guid_str[2], NTFS_GUID_STR_LEN,
		    SQLITE_STATIC);
	ntfs_guid2str_r(&mfte->oid->domain_id, guid_str[3]);
	SQLITE_BIND(text, "domain_id", guid_str[3], NTFS_GUID_STR_LEN,
		    SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "cache:mft:sqlite: could not insert MFT entry"
			"#%"PRIu64" OID: %s\n", nhr_mfte_num(mfte),
			sqlite3_errmsg(nhr.db));
		res = SQLITE_ERROR;
		goto exit;
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:mft:sqlite: could not bind MFT fn '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
	return 0;
}

static int cache_data_sqlite_dump_mp(const struct nhr_mft_entry *mfte,
				     unsigned pos)
{
	static const char *q_insert = "INSERT INTO data_mp"
		"(mft_entnum, pos, vcn, lcn, clen) VALUES"
		"(:mft_entnum, :pos, :vcn, :lcn, :clen)";
	struct sqlite3_stmt *stmt;
	const char *errfield;
	const struct ntfs_mp *mp;
	int res;

	if (!mfte->data[pos]->mpl)	/* No associated data */
		return 0;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:data:sqlite: could not prepare mp insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "mft_entnum", nhr_mfte_num(mfte));
	SQLITE_BIND(int, "pos", pos);

	for (mp = mfte->data[pos]->mpl; mp->clen; mp++) {
		SQLITE_BIND(int64, "vcn", mp->vcn);
		SQLITE_BIND(int64, "lcn", mp->lcn);
		SQLITE_BIND(int64, "clen", mp->clen);

		res = sqlite3_step(stmt);
		if (res != SQLITE_DONE) {
			fprintf(stderr, "cache:data[#%"PRIu64",%ls]:sqlite: could not insert mp 0x%08"PRIX64": %s\n",
				nhr_mfte_num(mfte),
				cache_data_name(mfte->data[pos]), mp->vcn,
				sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:data:sqlite: could not bind mp '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int cache_data_sqlite_dump_chunks(const struct nhr_mft_entry *mfte,
					 unsigned pos)
{
	static const char *q_insert = "INSERT INTO data_chunks"
		"(mft_entnum, pos, voff, len, src) VALUES"
		"(:mft_entnum, :pos, :voff, :len, :src)";
	struct sqlite3_stmt *stmt;
	const char *errfield;
	const struct nhr_data_chunk *chunk;
	int res;

	if (list_empty(&mfte->data[pos]->chunks))	/* No associated data */
		return 0;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:data:sqlite: could not prepare chunk insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "mft_entnum", nhr_mfte_num(mfte));
	SQLITE_BIND(int, "pos", pos);

	list_for_each_entry(chunk, &mfte->data[pos]->chunks, list) {
		SQLITE_BIND(int, "voff", chunk->voff);
		SQLITE_BIND(int, "len", chunk->len);
		SQLITE_BIND(int, "src", chunk->src);

		res = sqlite3_step(stmt);
		if (res != SQLITE_DONE) {
			fprintf(stderr, "cache:data[#%"PRIu64",%ls]:sqlite: could not insert chunk [0x%08X:0x%08X]: %s\n",
				nhr_mfte_num(mfte),
				cache_data_name(mfte->data[pos]), chunk->voff,
				chunk->voff + chunk->len - 1,
				sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:data:sqlite: could not bind chunk '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int cache_data_sqlite_dump_segments(const struct nhr_mft_entry *mfte,
					   unsigned pos)
{
	static const char *q_insert = "INSERT INTO data_segments"
		"(mft_entnum, pos, firstvcn, firstvcn_src, lastvcn,"
		"lastvcn_src, attr_entnum, attr_id) VALUES"
		"(:mft_entnum, :pos, :firstvcn, :firstvcn_src, :lastvcn,"
		":lastvcn_src, :attr_entnum, :attr_id)";
	struct sqlite3_stmt *stmt;
	const char *errfield;
	const struct nhr_str_segm *segm;
	int res;

	if (list_empty(&mfte->data[pos]->segments))	/* No segments */
		return 0;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:data:sqlite: could not prepare segments insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "mft_entnum", nhr_mfte_num(mfte));
	SQLITE_BIND(int, "pos", pos);

	list_for_each_entry(segm, &mfte->data[pos]->segments, list) {
		SQLITE_BIND(int64, "firstvcn", segm->firstvcn.val);
		SQLITE_BIND(int, "firstvcn_src", segm->firstvcn.src);
		SQLITE_BIND(int64, "lastvcn", segm->lastvcn.val);
		SQLITE_BIND(int, "lastvcn_src", segm->lastvcn.src);

		if (segm->ali) {
			SQLITE_BIND(int64, "attr_entnum", nhr_mfte_num(segm->ali->mfte));
			SQLITE_BIND(int, "attr_id", segm->ali->id);
		}

		res = sqlite3_step(stmt);
		if (res != SQLITE_DONE) {
			fprintf(stderr, "cache:data[#%"PRIu64",%ls]:sqlite: could not insert segment [0x%08"PRIX64":0x%08"PRIX64"]: %s\n",
				nhr_mfte_num(mfte),
				cache_data_name(mfte->data[pos]),
				segm->firstvcn.val, segm->lastvcn.val,
				sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:data:sqlite: could not bind segment '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int cache_data_sqlite_dump(const struct nhr_mft_entry *mfte)
{
	static const char *q_insert = "INSERT INTO data"
		"(mft_entnum, pos, name, flags, sz_alloc, sz_alloc_src,"
		"sz_used, sz_used_src, sz_init, sz_init_src) VALUES"
		"(:mft_entnum, :pos, :name, :flags, :sz_alloc, :sz_alloc_src,"
		":sz_used, :sz_used_src, :sz_init, :sz_init_src)";
	struct sqlite3_stmt *stmt;
	const char *errfield;
	unsigned i;
	const struct nhr_data *data;
	int res;

	if (!mfte->data_num)
		return 0;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:data:sqlite: could not prepare insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "mft_entnum", nhr_mfte_num(mfte));

	for (i = 0; i < mfte->data_num; ++i) {
		data = mfte->data[i];

		SQLITE_BIND(int, "pos", i);
		if (data->name_len) {
			SQLITE_BIND(text16, "name", data->name,
				    data->name_len * 2, SQLITE_STATIC);
		} else {
			SQLITE_BIND(null, "name");
		}
		SQLITE_BIND(int, "flags", data->flags);
		SQLITE_BIND(int64, "sz_alloc", data->sz_alloc.val);
		SQLITE_BIND(int, "sz_alloc_src", data->sz_alloc.src);
		SQLITE_BIND(int64, "sz_used", data->sz_used.val);
		SQLITE_BIND(int, "sz_used_src", data->sz_used.src);
		SQLITE_BIND(int64, "sz_init", data->sz_init.val);
		SQLITE_BIND(int, "sz_init_src", data->sz_init.src);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "cache:data[#%"PRIu64",%ls]:sqlite: could not insert row: %s\n",
				nhr_mfte_num(mfte), cache_data_name(data),
				sqlite3_errmsg(nhr.db));
			res = SQLITE_ERROR;
			goto exit;
		}
		sqlite3_reset(stmt);

		res = cache_data_sqlite_dump_mp(mfte, i);
		if (res) {
			res = SQLITE_ERROR;
			goto exit;
		}

		res = cache_data_sqlite_dump_chunks(mfte, i);
		if (res) {
			res = SQLITE_ERROR;
			goto exit;
		}

		res = cache_data_sqlite_dump_segments(mfte, i);
		if (res) {
			res = SQLITE_ERROR;
			goto exit;
		}
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:data:sqlite: could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int cache_idx_sqlite_dump_nodes(const struct nhr_mft_entry *mfte,
				       const struct nhr_idx *idx)
{
	static const char *q_insert = "INSERT INTO idx_nodes"
		"(mft_entnum, type, vcn, lcn, parent, level, flags, bb_map,"
		"bb_rec) "
		"VALUES "
		"(:mft_entnum, :type, :vcn, :lcn, :parent, :level, :flags,"
		":bb_map, :bb_rec)";
	struct nhr_idx_node *idxn;
	struct sqlite3_stmt *stmt;
	uint64_t parent_vcn;
	const char *errfield;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:idxn:sqlite: could not prepare idx node insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "mft_entnum", nhr_mfte_num(mfte));
	SQLITE_BIND(int, "type", idx->info->type);

	list_for_each_entry(idxn, &idx->nodes, list) {
		SQLITE_BIND(int64, "vcn", idxn->vcn);
		SQLITE_BIND(int64, "lcn", idxn->lcn);
		if (idxn->parent == NHR_IDXN_PTR_UNKN)
			parent_vcn = NHR_IDXN_VCN_UNKN;
		else if (idxn->parent == NHR_IDXN_PTR_NONE)
			parent_vcn = NHR_IDXN_VCN_NONE;
		else
			parent_vcn = idxn->parent->vcn;
		SQLITE_BIND(int64, "parent", parent_vcn);
		SQLITE_BIND(int, "level", idxn->lvl);
		SQLITE_BIND(int, "flags", idxn->flags);
		SQLITE_BIND(int, "bb_map", idxn->bb_map);
		SQLITE_BIND(int, "bb_rec", idxn->bb_rec);

		res = sqlite3_step(stmt);
		if (res != SQLITE_DONE) {
			fprintf(stderr, "cache:idxn:sqlite: could not insert index node: %s\n",
				sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}
	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:idxn:sqlite: could not bind node '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? 0 : -1;
}

static int cache_idx_sqlite_dump_entry_dir(const struct nhr_mft_entry *mfte,
					   const struct nhr_idx_entry *idxe,
					   unsigned pos)
{
	static const char *q_insert = "INSERT INTO idx_entries_dir"
		"(mft_entnum, pos, parent, t_create, t_change, t_mft, t_access,"
		"alloc_sz, used_sz, flags, reparse,"
		"name_len, name_type, name, mref)"
		"VALUES "
		"(:mft_entnum, :pos, :parent, :t_create, :t_change, :t_mft,"
		":t_access, :alloc_sz, :used_sz, :flags, :reparse, :name_len,"
		":name_type, :name, :mref)";
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	struct ntfs_attr_fname *fn = idxe->key;
	uint64_t mref = *(uint64_t *)idxe->data;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:idxe:dir:sqlite: could not prepare insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "mft_entnum", nhr_mfte_num(mfte));
	SQLITE_BIND(int, "pos", pos);
	SQLITE_BIND(int64, "parent", fn->parent);
	SQLITE_BIND(int64, "t_create", fn->time_create);
	SQLITE_BIND(int64, "t_change", fn->time_change);
	SQLITE_BIND(int64, "t_mft", fn->time_mft);
	SQLITE_BIND(int64, "t_access", fn->time_access);
	SQLITE_BIND(int64, "alloc_sz", fn->alloc_sz);
	SQLITE_BIND(int64, "used_sz", fn->used_sz);
	SQLITE_BIND(int, "flags", fn->flags);
	SQLITE_BIND(int, "reparse", fn->reparse_point);
	SQLITE_BIND(int, "name_len", fn->name_len);
	SQLITE_BIND(int, "name_type", fn->name_type);
	SQLITE_BIND(text16, "name", fn->name, fn->name_len * 2, SQLITE_STATIC);
	SQLITE_BIND(int64, "mref", mref);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "cache:idxe:dir:sqlite: could not insert entry: %s\n",
			sqlite3_errmsg(nhr.db));
		res = SQLITE_ERROR;
	}

	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:idxe:dir:sqlite: could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? 0 : -1;
}

static int cache_idx_sqlite_dump_entry_sdh(const struct nhr_mft_entry *mfte,
					   const struct nhr_idx_entry *idxe,
					   unsigned pos)
{
	static const char *q_insert = "INSERT INTO idx_entries_sdh"
		"(mft_entnum, pos, hash, id, voff, len)"
		"VALUES "
		"(:mft_entnum, :pos, :hash, :id, :voff, :len)";
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	struct ntfs_idx_sdh_key *sdh_key = idxe->key;
	struct ntfs_sec_desc_hdr *sdh = idxe->data;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:idxe:sdh:sqlite: could not prepare insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "mft_entnum", nhr_mfte_num(mfte));
	SQLITE_BIND(int, "pos", pos);
	SQLITE_BIND(int, "hash", sdh_key->hash);
	SQLITE_BIND(int, "id", sdh_key->id);
	SQLITE_BIND(int64, "voff", sdh->voff);
	SQLITE_BIND(int64, "len", sdh->len);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "cache:idxe:sdh:sqlite: could not insert entry: %s\n",
			sqlite3_errmsg(nhr.db));
		res = SQLITE_ERROR;
	}

	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:idxe:sdh:sqlite: could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? 0 : -1;
}

static int cache_idx_sqlite_dump_entry_sii(const struct nhr_mft_entry *mfte,
					   const struct nhr_idx_entry *idxe,
					   unsigned pos)
{
	static const char *q_insert = "INSERT INTO idx_entries_sii"
		"(mft_entnum, pos, id, hash, voff, len)"
		"VALUES "
		"(:mft_entnum, :pos, :id, :hash, :voff, :len)";
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	struct ntfs_idx_sii_key *sii_key = idxe->key;
	struct ntfs_sec_desc_hdr *sdh = idxe->data;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:idxe:sii:sqlite: could not prepare insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "mft_entnum", nhr_mfte_num(mfte));
	SQLITE_BIND(int, "pos", pos);
	SQLITE_BIND(int, "id", sii_key->id);
	SQLITE_BIND(int, "hash", sdh->hash);
	SQLITE_BIND(int64, "voff", sdh->voff);
	SQLITE_BIND(int64, "len", sdh->len);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "cache:idxe:sii:sqlite: could not insert entry: %s\n",
			sqlite3_errmsg(nhr.db));
		res = SQLITE_ERROR;
	}

	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:idxe:sii:sqlite: could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? 0 : -1;
}

static int cache_idx_sqlite_dump_entry(const struct nhr_mft_entry *mfte,
				       const struct nhr_idx *idx,
				       const struct nhr_idx_entry *idxe,
				       unsigned pos)
{
	switch (idx->info->type) {
	case NHR_IDX_T_DIR:
		return cache_idx_sqlite_dump_entry_dir(mfte, idxe, pos);
	case NHR_IDX_T_SDH:
		return cache_idx_sqlite_dump_entry_sdh(mfte, idxe, pos);
	case NHR_IDX_T_SII:
		return cache_idx_sqlite_dump_entry_sii(mfte, idxe, pos);
	}

	fprintf(stderr, "cache:idxe: don't know how to dump entry of type %d\n",
		idx->info->type);
	return 0;
}

static int cache_idx_sqlite_dump_entries(const struct nhr_mft_entry *mfte,
					 const struct nhr_idx *idx)
{
	static const char *q_insert = "INSERT INTO idx_entries"
		"(mft_entnum, type, pos, container, child, voff) VALUES"
		"(:mft_entnum, :type, :pos, :container, :child, :voff)";
	struct nhr_idx_entry *idxe;
	struct sqlite3_stmt *stmt;
	const char *errfield;
	uint64_t container_vcn, child_vcn;
	unsigned pos;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:idxe:sqlite: could not prepare idx entry insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int64, "mft_entnum", nhr_mfte_num(mfte));
	SQLITE_BIND(int, "type", idx->info->type);

	pos = 0;
	list_for_each_entry(idxe, &idx->entries, list) {
		SQLITE_BIND(int, "pos", pos);
		if (idxe->container == NHR_IDXN_PTR_UNKN)
			container_vcn = NHR_IDXN_VCN_UNKN;
		else if (idxe->container == NHR_IDXN_PTR_NONE)
			container_vcn = NHR_IDXN_VCN_NONE;
		else
			container_vcn = idxe->container->vcn;
		SQLITE_BIND(int64, "container", container_vcn);
		if (idxe->child == NHR_IDXN_PTR_UNKN)
			child_vcn = NHR_IDXN_VCN_UNKN;
		else if (idxe->child == NHR_IDXN_PTR_NONE)
			child_vcn = NHR_IDXN_VCN_NONE;
		else
			child_vcn = idxe->child->vcn;
		SQLITE_BIND(int64, "child", child_vcn);
		SQLITE_BIND(int, "voff", idxe->voff);

		if (idxe->key) {
			res = cache_idx_sqlite_dump_entry(mfte, idx, idxe, pos);
			if (res) {
				res = SQLITE_ERROR;
				goto exit;
			}
		}

		res = sqlite3_step(stmt);
		if (res != SQLITE_DONE) {
			fprintf(stderr, "cache:idxe:sqlite: could not insert index entry: %s\n",
				sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
		pos++;
	}
	res = SQLITE_OK;

	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:idxe:sqlite: could not bind entry '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? 0 : -1;
}

static int cache_idx_sqlite_dump(const struct nhr_mft_entry *mfte)
{
	unsigned i;
	int res;

	for (i = 0; i < mfte->idx_num; ++i) {
		res = cache_idx_sqlite_dump_nodes(mfte, mfte->idx[i]);
		if (res)
			return res;
		res = cache_idx_sqlite_dump_entries(mfte, mfte->idx[i]);
		if (res)
			return res;
	}

	return 0;
}

static int cache_mfte_sqlite_dump(void)
{
	static const char *q_insert = "INSERT INTO mft_entries"
		"(num, f_cmn, f_bad, f_rec, f_sum, bb_map, bb_rec, parent,"
		"parent_src, base, base_src, seqno, seqno_src, t_create,"
		"t_create_src, t_change, t_change_src, t_mft, t_mft_src,"
		"t_access, t_access_src, fileflags, fileflags_src, sid,"
		"sid_src) VALUES (:num, :f_cmn, :f_bad, :f_rec, :f_sum,"
		":bb_map, :bb_rec, :parent, :parent_src, :base, :base_src,"
		":seqno, :seqno_src, :t_create, :t_create_src, :t_change,"
		":t_change_src, :t_mft, :t_mft_src, :t_access, :t_access_src,"
		":fileflags, :fileflags_src, :sid, :sid_src)";
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	struct nhr_mft_entry *mfte;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:mft:sqlite: could not prepare MFT entry insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	res = SQLITE_ERROR;
	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		SQLITE_BIND(int64, "num", nhr_mfte_num(mfte));
		SQLITE_BIND(int, "f_cmn", mfte->f_cmn);
		SQLITE_BIND(int, "f_bad", mfte->f_bad);
		SQLITE_BIND(int, "f_rec", mfte->f_rec);
		SQLITE_BIND(int, "f_sum", mfte->f_sum);
		SQLITE_BIND(int, "bb_map", mfte->bb_map);
		SQLITE_BIND(int, "bb_rec", mfte->bb_rec);
		SQLITE_BIND(int64, "parent", mfte->parent.val);
		SQLITE_BIND(int, "parent_src", mfte->parent.src);
		if (mfte->base_src != NHR_SRC_NONE) {
			SQLITE_BIND(int64, "base", nhr_mfte_num(mfte->bmfte));
		} else {
			SQLITE_BIND(int64, "base", 0);
		}
		SQLITE_BIND(int, "base_src", mfte->base_src);
		SQLITE_BIND(int, "seqno", mfte->seqno.val);
		SQLITE_BIND(int, "seqno_src", mfte->seqno.src);
		SQLITE_BIND(int64, "t_create", mfte->time_create.val);
		SQLITE_BIND(int, "t_create_src", mfte->time_create.src);
		SQLITE_BIND(int64, "t_change", mfte->time_change.val);
		SQLITE_BIND(int, "t_change_src", mfte->time_change.src);
		SQLITE_BIND(int64, "t_mft", mfte->time_mft.val);
		SQLITE_BIND(int, "t_mft_src", mfte->time_mft.src);
		SQLITE_BIND(int64, "t_access", mfte->time_access.val);
		SQLITE_BIND(int, "t_access_src", mfte->time_access.src);
		SQLITE_BIND(int, "fileflags", mfte->fileflags.val);
		SQLITE_BIND(int, "fileflags_src", mfte->fileflags.src);
		SQLITE_BIND(int, "sid", mfte->sid.val);
		SQLITE_BIND(int, "sid_src", mfte->sid.src);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "cache:mft:sqlite: could not insert MFT entry #%"PRIu64": %s\n",
				nhr_mfte_num(mfte), sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
		res = cache_mft_sqlite_dump_attrs(mfte);
		if (res)
			goto exit;
		res = cache_mft_sqlite_dump_fn(mfte);
		if (res)
			goto exit;
		res = cache_mft_sqlite_dump_oid(mfte);
		if (res)
			goto exit;
		res = cache_data_sqlite_dump(mfte);
		if (res)
			goto exit;
		res = cache_idx_sqlite_dump(mfte);
		if (res)
			goto exit;
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "cache:mft:sqlite: could not bind MFT entry '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? 0 : -1;
}

/**
 * Create aux table to simplify children searching
 */
static int cache_mft_sqlite_build_tree(void)
{
	static const char *q_cpy_base = "INSERT INTO mft_entries_tree "
		"SELECT num, parent, 1 FROM mft_entries WHERE base = 0";
	static const char *q_cpy_ext = "INSERT INTO mft_entries_tree "
		"SELECT t1.num, t2.parent, 1 "
		"FROM mft_entries AS t1, mft_entries AS t2 "
		"WHERE t1.base <> 0 AND t1.base = t2.num";
	static const char *q_tpl = "INSERT INTO mft_entries_tree "
		"SELECT t1.entry, t2.parent, t1.h + t2.h "
		"FROM mft_entries_tree AS t1, mft_entries_tree AS t2 "
		"WHERE "
		"t1.parent = t2.entry AND t1.parent != t2.parent AND "
		"t1.parent <> 0 AND t1.h=%u AND t2.h = 1";
	char q_tier[0x200];
	unsigned h = 0;

	if (sqlite3_exec(nhr.db, q_cpy_base, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "cache:sqlite: could not do MFT tree initial base filling: %s\n",
			sqlite3_errmsg(nhr.db));
		return -1;
	}

	if (sqlite3_exec(nhr.db, q_cpy_ext, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "cache:sqlite: could not do MFT tree initial extent filling: %s\n",
			sqlite3_errmsg(nhr.db));
		return -1;
	}

	while (1) {
		assert(h < 100);
		snprintf(q_tier, sizeof(q_tier), q_tpl, ++h);
		if (sqlite3_exec(nhr.db, q_tier, NULL, NULL, NULL) != SQLITE_OK) {
			fprintf(stderr, "cache:sqlite: could not create MFT tree tier #%u: %s\n",
				h, sqlite3_errmsg(nhr.db));
			return -1;
		}
		if (sqlite3_changes(nhr.db) == 0)
			break;
	}

	return 0;
}

/** Refresh corruption summary flags */
static void cache_mfte_fsum_refresh(struct nhr_mft_entry *bmfte)
{
	unsigned f_sum = bmfte->f_bad & ~bmfte->f_rec;
	struct nhr_mft_entry *mfte;

	list_for_each_entry(mfte, &bmfte->ext, ext)
		f_sum |= mfte->f_bad & ~mfte->f_rec;

	bmfte->f_sum = f_sum;
}

/** Insert BB to MFT entry's list of BBs */
static void cache_mfte_bb_insert(struct nhr_mft_entry *mfte, struct nhr_bb *bb)
{
	struct nhr_bb *__bb;

	INIT_LIST_HEAD(&bb->list);	/* Reinit and use as flag */
	list_for_each_entry(__bb, &mfte->bb, list) {
		if (__bb->attr_type < bb->attr_type)
			continue;
		if (__bb->entity < bb->entity)
			continue;
		if (__bb->voff < bb->voff)
			continue;
		list_add_tail(&bb->list, &__bb->list);
		break;
	}
	if (list_empty(&bb->list))
		list_add_tail(&bb->list, &mfte->bb);
}

/** Update BB entity pointer */
static void cache_mfte_bb_rebind(const struct nhr_mft_entry *mfte, void *old,
				 void *new)
{
	struct nhr_bb *bb;

	list_for_each_entry(bb, &mfte->bb, list) {
		if (bb->entity == old)
			bb->entity = new;
	}
}

/**
 * Allocate new entry and add it to cache
 * entnum - entry number
 * return allocated entry or NULL
 */
struct nhr_mft_entry *cache_mfte_alloc(const uint64_t entnum)
{
	struct nhr_mft_entry *mfte = calloc(1, sizeof(*mfte));

	if (!mfte)
		return NULL;

	nhr_mfte_num(mfte) = entnum;
	INIT_LIST_HEAD(&mfte->bb);
	INIT_LIST_HEAD(&mfte->ext);
	INIT_LIST_HEAD(&mfte->alist);
	mfte->bmfte = mfte;

	rbtree_insert(&nhr.mft_cache, &mfte->tree);

	return mfte;
}

/**
 * Find cached MFT entry by its id
 *
 * entnum - entry number
 * return cached entry pointer or NULL if entry not found in cache
 */
struct nhr_mft_entry *cache_mfte_find(uint64_t entnum)
{
	struct rbtree_head *node = rbtree_lookup(&nhr.mft_cache, entnum);

	return rbt_is_nil(&nhr.mft_cache, node) ? NULL :
	       rbtree_entry(node, struct nhr_mft_entry, tree);
}

/** Set corruption type flag (see NHR_MFT_FB_xxx) */
void cache_mfte_fbad_set(struct nhr_mft_entry *mfte, unsigned flags)
{
	struct nhr_mft_entry *bmfte = mfte->bmfte;

	mfte->f_bad |= flags;
	mfte->f_rec &= ~flags;
	bmfte->f_sum |= flags;
}

/** Mark corruption recovered flag (see NHR_MFT_FB_xxx) */
void cache_mfte_frec_set(struct nhr_mft_entry *mfte, unsigned flags)
{
	struct nhr_mft_entry *bmfte = mfte->bmfte;

	mfte->f_rec |= flags;

	cache_mfte_fsum_refresh(bmfte);
}

/**
 * Set base entry
 */
void cache_mfte_base_set(struct nhr_mft_entry *mfte,
			 struct nhr_mft_entry *bmfte,
			 enum nhr_info_src src)
{
	int i;
	struct nhr_data *bdata, *data;
	struct nhr_idx *idx;
	struct nhr_bb *bb;

	if (src < mfte->base_src)	/* Nothing to update */
		return;

	if (mfte->base_src != NHR_SRC_NONE) {	/* If we already know our base */
		mfte->base_src = src;
		assert(mfte->bmfte == bmfte);
		return;
	}

	mfte->f_cmn |= NHR_MFT_FC_EXTENT;
	mfte->base_src = src;		/* Preferability checked above */

	assert(list_empty(&mfte->ext));
	mfte->bmfte = bmfte;
	list_add(&mfte->ext, &bmfte->ext);

	/* Merge ext data streams to base */
	for (i = 0; i < mfte->data_num; ++i) {
		data = mfte->data[i];
		bdata = cache_data_find(bmfte, data->name_len, data->name);
		if (!bdata)
			bdata = cache_data_alloc(bmfte, data->name_len,
						 data->name);
		__cache_data_merge(bdata, data);
		cache_mfte_bb_rebind(mfte, data, bdata);
		assert(list_empty(&mfte->alist));
	}
	if (mfte->data_num) {
		free(mfte->data);
		mfte->data_num = 0;
		mfte->data = NULL;
	}

	/* Merge indexes to base */
	for (i = 0; i < mfte->idx_num; ++i) {
		idx = mfte->idx[i];
		assert(cache_idx_find(bmfte, idx->info->type) == NULL);	/* Merge not yet supported */
		__cache_idx_insert(bmfte, idx);
	}
	if (mfte->idx_num) {
		free(mfte->idx);
		mfte->idx_num = 0;
		mfte->idx = NULL;
	}

	/* Move BBs from ext to base */
	while (!list_empty(&mfte->bb)) {
		bb = list_first_entry(&mfte->bb, typeof(*bb), list);
		list_del(&bb->list);
		cache_mfte_bb_insert(bmfte, bb);
	}

	/* Move summary to base entry */
	bmfte->f_sum |= mfte->f_sum;
	mfte->f_sum = 0;
}

/**
 * Update file flags
 *
 * Note: we have one nasty issue with fileflags from $STANDARD_INFORMATION,
 * they sometime miss indexes ($I30 and view) flags, so function has few
 * workarounds for such case.
 */
void cache_mfte_fileflags_upd(struct nhr_mft_entry *mfte, uint32_t fileflags,
			      enum nhr_info_src src)
{
	if (fileflags & NTFS_FILE_F_IDX_I30) {
		mfte->f_cmn |= NHR_MFT_FC_DIR;
		if (mfte->f_bad & NHR_MFT_FB_SELF &&
		    !cache_idx_find(mfte, NHR_IDX_T_DIR))
			cache_idx_alloc(mfte, NHR_IDX_T_DIR);
	} else if (fileflags & NTFS_FILE_F_IDX_VIEW) {
		mfte->f_cmn |= NHR_MFT_FC_IDX;
	} else if (src != NHR_SRC_STDINF) {
		mfte->f_cmn |= NHR_MFT_FC_FILE;
	}

	if (src <= mfte->fileflags.src) {
		if (mfte->fileflags.src == NHR_SRC_STDINF)
			mfte->fileflags.val |= fileflags & NTFS_FILE_F_IDX_M;
		return;
	}

	mfte->fileflags.src = src;
	if (src == NHR_SRC_STDINF)
		mfte->fileflags.val = fileflags | (mfte->fileflags.val &
						   NTFS_FILE_F_IDX_M);
	else
		mfte->fileflags.val = fileflags;
}

/**
 * Return entry name
 */
const wchar_t *cache_mfte_name(const struct nhr_mft_entry *mfte)
{
	const struct nhr_mfte_fn *fn = NULL;

	if (mfte->names[NTFS_FNAME_T_WIN32DOS].src != NHR_SRC_NONE)
		fn = &mfte->names[NTFS_FNAME_T_WIN32DOS];
	else if (mfte->names[NTFS_FNAME_T_WIN32].src != NHR_SRC_NONE)
		fn = &mfte->names[NTFS_FNAME_T_WIN32];
	else if (mfte->names[NTFS_FNAME_T_DOS].src != NHR_SRC_NONE)
		fn = &mfte->names[NTFS_FNAME_T_DOS];

	return fn ? name2wchar(fn->name, fn->len) : L"<none>";
}

/**
 * Add new badblock to MFT entry
 */
void cache_mfte_bb_add(struct nhr_mft_entry *mfte, struct nhr_bb *bb)
{
	unsigned f_bad;

	if (bb->mfte) {
		assert(bb->mfte == mfte);
		return;
	}

	switch (bb->attr_type) {
	case NTFS_ATTR_DATA:
		f_bad = NHR_MFT_FB_ADATA;
		mfte->bb_cnt_data++;
		break;
	case NTFS_ATTR_IALLOC:
		f_bad = NHR_MFT_FB_AIDX;
		mfte->bb_cnt_idx++;
		break;
	default:
		assert(0);
	}

	bb->mfte = mfte;

	cache_mfte_bb_insert(mfte->bmfte, bb);

	cache_mfte_fbad_set(mfte, f_bad);
}

/**
 * Mark BB as Ok (e.g. recovered, could be ignored, etc.)
 */
void cache_mfte_bb_ok(struct nhr_bb *bb)
{
	struct nhr_mft_entry *mfte = bb->mfte;

	assert(mfte);

	switch (bb->attr_type) {
	case NTFS_ATTR_DATA:
		assert(mfte->bb_cnt_data > 0);
		mfte->bb_cnt_data--;
		if (mfte->bb_cnt_data == 0)
			cache_mfte_frec_set(mfte, NHR_MFT_FB_ADATA);
		break;
	case NTFS_ATTR_IALLOC:
		assert(mfte->bb_cnt_idx > 0);
		mfte->bb_cnt_idx--;
		if (mfte->bb_cnt_idx == 0)
			cache_mfte_frec_set(mfte, NHR_MFT_FB_AIDX);
		break;
	default:
		assert(0);
	}
}

/**
 * Find first BB for particular entity
 */
struct nhr_bb *cache_mfte_bb_find(const struct nhr_mft_entry *mfte,
				  uint32_t attr_type, const void *entity)
{
	struct nhr_bb *bb;

	list_for_each_entry(bb, &mfte->bmfte->bb, list) {
		if (bb->attr_type == attr_type && bb->entity == entity)
			return bb;
	}

	return NULL;
}

/**
 * Find next BB for particular attribute
 */
struct nhr_bb *cache_mfte_bb_next(struct nhr_bb *bb)
{
	struct nhr_mft_entry *mfte = bb->mfte->bmfte;
	struct nhr_bb *__bb;

	do {
		__bb = list_next_entry(bb, list);
		if (&__bb->list == &mfte->bb)
			break;
		if (__bb->attr_type != bb->attr_type ||
		    __bb->entity != bb->entity)
			break;
		return __bb;
	} while (1);

	return NULL;
}

/**
 * Counter number of attributes of specified entry
 */
int cache_mfte_attrs_num(const struct nhr_mft_entry *mfte)
{
	struct nhr_alist_item *ali;
	int num = 0;

	list_for_each_entry(ali, &mfte->bmfte->alist, list)
		if (ali->mfte == mfte)
			num++;

	return num;
}

/**
 * Allocate new attribute list entry
 */
struct nhr_alist_item *cache_attr_alloc(struct nhr_mft_entry *mfte,
					uint32_t type, unsigned name_len,
					const uint8_t *name, uint64_t firstvcn)
{
	struct nhr_alist_item *__ali, *ali;
	unsigned len;
	int res;

	list_for_each_entry(__ali, &mfte->bmfte->alist, list) {
		if (type > __ali->type)
			continue;
		if (type < __ali->type)
			break;
		len = name_len > __ali->name_len ?
		      __ali->name_len : name_len;
		res = memcmp(name, __ali->name, 2 * len);
		if (res > 0)
			continue;
		if (res < 0)
			break;
		if (name_len > __ali->name_len)
			continue;
		if (name_len < __ali->name_len)
			break;
		if (firstvcn > __ali->firstvcn)
			continue;
		break;
	}

	ali = calloc(1, sizeof(*ali));
	ali->type = type;
	ali->name_len = name_len;
	ali->name = malloc(name_len * 2);
	memcpy(ali->name, name, name_len * 2);
	ali->mfte = mfte;
	ali->firstvcn = firstvcn;

	list_add_tail(&ali->list, &__ali->list);

	return ali;
}

/**
 * Search attribute by its type and id
 */
struct nhr_alist_item *cache_attr_find_id(const struct nhr_mft_entry *mfte,
					  uint32_t type, uint16_t id)
{
	struct nhr_alist_item *ali;

	list_for_each_entry(ali, &mfte->bmfte->alist, list) {
		if (mfte != ali->mfte)
			continue;
		if (type != ali->type)
			continue;
		if (id != ali->id)
			continue;
		return ali;
	}

	return NULL;
}

/**
 * Search attribute by its type and entity
 */
struct nhr_alist_item *cache_attr_find_entity(const struct nhr_mft_entry *mfte,
					      uint32_t type, const void *entity)
{
	struct nhr_alist_item *ali;

	list_for_each_entry(ali, &mfte->bmfte->alist, list) {
		if (type != ali->type)
			continue;
		if (entity != ali->entity)
			continue;
		return ali;
	}

	return NULL;
}

/**
 * Search first attribute in the named stream
 */
struct nhr_alist_item *cache_attr_str_find(const struct nhr_mft_entry *mfte,
					   uint32_t type, unsigned name_len,
					   const uint8_t *name)
{
	struct nhr_alist_item *ali;

	list_for_each_entry(ali, &mfte->bmfte->alist, list) {
		if (type > ali->type)
			continue;
		if (type < ali->type)
			break;
		if (name_len != ali->name_len)
			continue;
		if (memcmp(name, ali->name, name_len * 2) != 0)
			continue;
		return ali;
	}

	return NULL;
}

/**
 * Get next attribute from named stream
 */
struct nhr_alist_item *cache_attr_str_next(const struct nhr_mft_entry *mfte,
					   struct nhr_alist_item *ali)
{
	const struct nhr_mft_entry *bmfte = mfte->bmfte;
	struct nhr_alist_item *ali_next = list_next_entry(ali, list);

	if (&ali_next->list == &bmfte->alist)
		return NULL;
	if (ali->type != ali_next->type)
		return NULL;
	if (ali->name_len != ali_next->name_len)
		return NULL;
	if (memcmp(ali->name, ali_next->name, ali->name_len * 2) != 0)
		return NULL;

	return ali_next;
}

/**
 * Returns attribute name or '<default>' string if no name assigned
 */
const wchar_t *cache_attr_name(const struct nhr_alist_item *ali)
{
	return ali->name_len ? name2wchar(ali->name, ali->name_len) :
			       L"<default>";
}

/**
 * Find max attribute id
 */
int cache_alist_maxid(const struct nhr_mft_entry *mfte)
{
	const struct nhr_mft_entry *bmfte = mfte->bmfte;
	struct nhr_alist_item *ali;
	int max = 0;

	list_for_each_entry(ali, &bmfte->alist, list)
		if (ali->mfte == mfte && ali->id > max)
			max = ali->id;

	return max;
}

/** Merge info from src data into dst data and free src */
void __cache_data_merge(struct nhr_data *dst, struct nhr_data *src)
{
	struct nhr_str_segm *dsegm, *ssegm, *tmp;

	free(src->name);

	dst->flags |= src->flags;
	dst->flags &= ~NHR_DATA_F_VALID;

	NHR_FIELD_UPDATE(&dst->sz_alloc, src->sz_alloc.val, src->sz_alloc.src);
	NHR_FIELD_UPDATE(&dst->sz_used, src->sz_used.val, src->sz_used.src);
	NHR_FIELD_UPDATE(&dst->sz_init, src->sz_init.val, src->sz_init.src);

	if (src->mpl) {
		dst->mpl = ntfs_mpl_merge(dst->mpl, src->mpl);
		assert(dst->mpl);
		free(src->mpl);
	}
	if (src->digest && dst->digest) {
		assert(!memcmp(dst->digest, src->digest, 16));
		free(src->digest);
	} else if (src->digest && !dst->digest) {
		dst->digest = src->digest;
	}

	list_for_each_entry_safe(ssegm, tmp, &src->segments, list) {
		list_del(&ssegm->list);
		dsegm = cache_data_segm_find(dst, ssegm->firstvcn.val);
		if (!dsegm) {
			__cache_data_segm_insert(dst, ssegm);
		} else {
			NHR_FIELD_UPDATE(&dsegm->firstvcn, ssegm->firstvcn.val,
					 ssegm->firstvcn.src);
			NHR_FIELD_UPDATE(&dsegm->lastvcn, ssegm->lastvcn.val,
					 ssegm->lastvcn.src);
			if (!dsegm->ali)
				dsegm->ali = ssegm->ali;
			free(ssegm);
		}
	}

	free(src);
}

/**
 * Allocates new data stream
 */
struct nhr_data *cache_data_alloc(struct nhr_mft_entry *mfte, unsigned name_len,
				  const uint8_t *name)
{
	struct nhr_mft_entry *bmfte = mfte->bmfte;
	struct nhr_data *data = calloc(1, sizeof(*data));

	bmfte->data = realloc(bmfte->data,
			     (bmfte->data_num + 1) * sizeof(bmfte->data[0]));
	bmfte->data[bmfte->data_num] = data;
	bmfte->data_num++;

	data->name_len = name_len;
	data->name = malloc(name_len * 2);
	memcpy(data->name, name, name_len * 2);
	INIT_LIST_HEAD(&data->chunks);
	INIT_LIST_HEAD(&data->segments);

	return data;
}

/**
 * Find cached data stream by its name
 */
struct nhr_data *cache_data_find(const struct nhr_mft_entry *mfte,
				 unsigned name_len, const uint8_t *name)
{
	const struct nhr_mft_entry *bmfte = mfte->bmfte;
	unsigned i;

	for (i = 0; i < bmfte->data_num; ++i)
		if (bmfte->data[i]->name_len == name_len &&
		    memcmp(bmfte->data[i]->name, name, name_len * 2) == 0)
			return bmfte->data[i];

	return NULL;
}

/**
 * Get data stream index
 */
unsigned cache_data_idx(const struct nhr_mft_entry *mfte,
			const struct nhr_data *data)
{
	const struct nhr_mft_entry *bmfte = mfte->bmfte;
	unsigned i;

	for (i = 0; i < bmfte->data_num; ++i)
		if (bmfte->data[i] == data)
			return i;

	return -1;
}

const wchar_t *cache_data_name(const struct nhr_data *data)
{
	return data->name_len ? name2wchar(data->name, data->name_len) :
				L"<default>";
}

void __cache_data_segm_insert(struct nhr_data *data, struct nhr_str_segm *segm)
{
	struct nhr_str_segm *__segm;

	list_for_each_entry(__segm, &data->segments, list) {
		if (segm->firstvcn.val > __segm->firstvcn.val)
			continue;
		list_add_tail(&segm->list, &__segm->list);
		return;
	}

	list_add_tail(&segm->list, &data->segments);
}

struct nhr_str_segm *cache_data_segm_alloc(struct nhr_data *data,
					   uint64_t firstvcn)
{
	struct nhr_str_segm *segm = malloc(sizeof(*segm));

	segm->firstvcn.val = firstvcn;
	segm->firstvcn.src = NHR_SRC_NONE;
	segm->lastvcn.val = ~0ULL;
	segm->lastvcn.src = NHR_SRC_NONE;
	segm->ali = NULL;

	__cache_data_segm_insert(data, segm);

	return segm;
}

struct nhr_str_segm *cache_data_segm_find(const struct nhr_data *data,
					  uint64_t firstvcn)
{
	struct nhr_str_segm *segm;

	list_for_each_entry(segm, &data->segments, list) {
		if (segm->firstvcn.val == firstvcn)
			return segm;
	}

	return NULL;
}

/* Return first orphaned (without binded attribute) segment */
struct nhr_str_segm *cache_data_segm_orph(const struct nhr_data *data)
{
	struct nhr_str_segm *segm;

	list_for_each_entry(segm, &data->segments, list)
		if (!segm->ali)
			return segm;

	return NULL;
}

/**
 * Generate bad blocks mask for specified data stream
 * Returns allocated BB mask or NULL on error
 *
 * NB: caller should care about memory freeing
 * NB: if no BB exists within stream than mask contains only one valid element
 */
struct nhr_cmask_elem *cache_data_bb_gen_mask(const struct nhr_mft_entry *mfte,
					      const struct nhr_data *data)
{
	struct nhr_cmask_elem *mask = NULL;
	struct nhr_bb *bb;
	uint64_t voff = 0;

	if (data->sz_alloc.src == NHR_SRC_NONE)	/* Oops */
		return NULL;

	for (bb = cache_mfte_bb_find(mfte, NTFS_ATTR_DATA, data);
	     bb != NULL; bb = cache_mfte_bb_next(bb)) {
		if (bb->flags & (NHR_BB_F_IGNORE | NHR_BB_F_REC))
			continue;
		cmask_append(&mask, 1, bb->voff - voff);
		cmask_append(&mask, 0, nhr.vol.sec_sz);
		voff = bb->voff + nhr.vol.sec_sz;
	}

	cmask_append(&mask, 1, data->sz_alloc.val - voff);

	return mask;
}

int __cache_idx_insert(struct nhr_mft_entry *mfte, struct nhr_idx *idx)
{
	unsigned i;

	for (i = 0; i < mfte->idx_num; ++i) {
		assert(mfte->idx[i]->info != idx->info);
		if (mfte->idx[i]->info->type > idx->info->type)
			break;
	}

	mfte->idx = realloc(mfte->idx,
			    (mfte->idx_num + 1) * sizeof(mfte->idx[0]));
	memmove(&mfte->idx[i + 1], &mfte->idx[i],
		(mfte->idx_num - i) * sizeof(mfte->idx[0]));
	mfte->idx_num++;
	mfte->idx[i] = idx;

	return i;
}

struct nhr_idx *cache_idx_alloc(struct nhr_mft_entry *mfte, int type)
{
	const struct nhr_idx_info *info = idx_info_get(type);
	struct nhr_idx *idx;
	struct nhr_idx_node *idxn;
	struct nhr_idx_entry *idxe;

	assert(info);

	idx = malloc(sizeof(*idx));
	idx->root_buf = NULL;
	idx->root_buf_len = 0;
	idx->info = info;
	INIT_LIST_HEAD(&idx->nodes);
	INIT_LIST_HEAD(&idx->entries);

	idxn = calloc(1, sizeof(*idxn));
	idxn->vcn = NHR_IDXN_VCN_ROOT;
	idxn->flags = NHR_IDXN_F_INUSE;
	idxn->lvl = NHR_IDXN_LVL_UNKN;
	idxn->parent = NHR_IDXN_PTR_NONE;
	idx->root = idxn;
	list_add(&idxn->list, &idx->nodes);

	/**
	 * Create 'stream end marker' special entry. We use it to simplify
	 * and unify index root node handling. Logically this entry is parent
	 * of root node.
	 */
	idxe = calloc(1, sizeof(*idxe));
	idxe->container = NHR_IDXN_PTR_NONE;
	idxe->child = idx->root;
	idxe->voff = 0;
	idx->end = idxe;
	list_add_tail(&idxe->list, &idx->entries);

	__cache_idx_insert(mfte->bmfte, idx);

	return idx;
}

struct nhr_idx *cache_idx_find(const struct nhr_mft_entry *mfte, int type)
{
	const struct nhr_mft_entry *bmfte = mfte->bmfte;
	unsigned i;

	for (i = 0; i < bmfte->idx_num; ++i)
		if (bmfte->idx[i]->info->type == type)
			return bmfte->idx[i];

	return NULL;
}

/** Get position in indexes array of specified index */
int cache_idx_idx(const struct nhr_mft_entry *mfte, const struct nhr_idx *idx)
{
	const struct nhr_mft_entry *bmfte = mfte;
	unsigned i;

	for (i = 0; i < bmfte->idx_num; ++i)
		if (bmfte->idx[i] == idx)
			return i;

	return -1;
}

const wchar_t *cache_idx_name(const struct nhr_idx *idx)
{
	return name2wchar(idx->info->name, idx->info->name_len);
}

struct nhr_idx_node *cache_idxn_alloc(struct nhr_idx *idx, int64_t vcn)
{
	struct nhr_idx_node *idxn = calloc(1, sizeof(*idxn));
	struct nhr_idx_node *iidxn;

	idxn->vcn = vcn;
	idxn->lvl = NHR_IDXN_LVL_UNKN;

	list_for_each_entry(iidxn, &idx->nodes, list) {
		if (idxn->vcn < iidxn->vcn) {
			list_add_tail(&idxn->list, &iidxn->list);
			return idxn;
		}
	}
	list_add_tail(&idxn->list, &idx->nodes);
	return idxn;
}

struct nhr_idx_node *cache_idxn_find(const struct nhr_idx *idx, int64_t vcn)
{
	struct nhr_idx_node *idxn;

	list_for_each_entry(idxn, &idx->nodes, list) {
		if (idxn->vcn == vcn)
			return idxn;
		if (idxn->vcn > vcn)
			break;
	}

	return NULL;
}

/**
 * Search last (most right) child node of specified node
 *
 * In fact, this function searches node, which is child of end block entry
 *
 * Returns NONE if node not exists (true for leaf), UNKN if node could not be
 * detected, and node pointer if desired child node found.
 */
struct nhr_idx_node *cache_idxn_child_last(const struct nhr_idx *idx,
					   const struct nhr_idx_node *idxn)
{
	struct nhr_idx_entry *idxe;

	if (idxn->flags & NHR_IDXN_F_LEAF)
		return NHR_IDXN_PTR_NONE;
	if (idxn->last == NULL && idxn->vcn != NHR_IDXN_VCN_ROOT)
		return NHR_IDXN_PTR_UNKN;

	list_for_each_entry_reverse(idxe, &idx->entries, list) {
		if (!NHR_IDXN_PTR_VALID(idxe->container))
			continue;
		if (!NHR_IDXN_PTR_VALID(idxe->container->parent))
			continue;
		if (idxe->container->parent == idxn)
			return idxe->container;
	}

	return NHR_IDXN_PTR_UNKN;
}

/** Search last entry from specified node */
struct nhr_idx_entry *cache_idxn_entry_last(const struct nhr_idx *idx,
					    const struct nhr_idx_node *idxn)
{
	struct nhr_idx_entry *idxe, *res = NULL;

	list_for_each_entry(idxe, &idx->entries, list) {
		if (idxe->container == idxn)
			res = idxe;
	}

	return res;
}

/** Search node parent entry */
struct nhr_idx_entry *cache_idxn_parent(const struct nhr_idx *idx,
					const struct nhr_idx_node *idxn)
{
	struct nhr_idx_entry *idxe;

	if (idxn->parent == NHR_IDXN_PTR_UNKN)
		return NULL;

	list_for_each_entry(idxe, &idx->entries, list) {
		if (idxe->child == idxn)
			return idxe;
	}

	return NULL;
}

const char *cache_idxn_name(const struct nhr_idx_node *idxn)
{
	static char buf[4][0x10];
	static int buf_num = 0;

	if (idxn == NHR_IDXN_PTR_UNKN)
		return "<U>";
	else if (idxn == NHR_IDXN_PTR_NONE)
		return "<N>";
	else if (idxn->vcn == NHR_IDXN_VCN_ROOT)
		return "<R>";
	else if (idxn->vcn == NHR_IDXN_VCN_UNKN)
		return "<U>";

	buf_num = (buf_num + 1) % (sizeof(buf)/sizeof(buf[0]));
	snprintf(buf[buf_num], sizeof(buf[0]), "#%"PRIu64, idxn->vcn);

	return buf[buf_num];
}

struct nhr_idx_entry *cache_idxe_alloc(struct nhr_idx *idx, void *key)
{
	struct nhr_idx_entry *idxe = malloc(sizeof(*idxe));
	struct nhr_idx_entry *iidxe;
	unsigned data_sz = idx->info->data_sz ? idx->info->data_sz :
						sizeof(uint64_t);

	idxe->container = NHR_IDXN_PTR_UNKN;
	idxe->child = NHR_IDXN_PTR_UNKN;
	idxe->key = key;
	idxe->data = malloc(data_sz);
	idxe->voff = ~0;

	list_for_each_entry(iidxe, &idx->entries, list) {
		if (iidxe == idx->end)
			break;
		if (!iidxe->key)
			continue;
		if (idx->info->key_cmp(idxe->key, iidxe->key) < 0) {
			list_add_tail(&idxe->list, &iidxe->list);
			return idxe;
		}
	}
	list_add_tail(&idxe->list, &idx->end->list);	/* Before stream end */
	return idxe;
}

struct nhr_idx_entry *cache_idxe_find(const struct nhr_idx *idx,
				      const void *key)
{
	struct nhr_idx_entry *idxe;
	int res;

	list_for_each_entry(idxe, &idx->entries, list) {
		if (idxe == idx->end)
			break;
		if (!idxe->key)
			continue;
		res = idx->info->key_cmp(key, idxe->key);
		if (res == 0)
			return idxe;
		else if (res < 0)
			break;
	}

	return NULL;
}

int cache_idxe_pos_unkn(const struct nhr_idx *idx,
			const struct nhr_idx_entry *idxe)
{
	const struct nhr_idx_entry *__idxe;

	/* Search from stream end till list end */
	for (__idxe = list_next_entry(idx->end, list);
	     &__idxe->list != &idx->entries;
	     __idxe = list_next_entry(__idxe, list))
		if (idxe == __idxe)
			return 1;

	return 0;
}

void cache_idxe_container_set(struct nhr_idx_entry *idxe,
			      struct nhr_idx_node *idxn)
{
	idxe->container = idxn;
	if (!idxn->first || idxn->first->voff > idxe->voff)
		idxn->first = idxe;
	if (!idxn->last || idxn->last->voff < idxe->voff)
		idxn->last = idxe;
}

const wchar_t *cache_idxe_name(const struct nhr_idx *idx,
			       const struct nhr_idx_entry *idxe)
{
	return idxe->key ? idx->info->entry_name(idxe) : L"<end>";
}

void nhr_mft_eemap_add(uint64_t ext_entnum, uint64_t base_entnum)
{
	struct nhr_mft_eemap *ee;
	struct rbtree_head *node = rbtree_lookup(&nhr.mft_eemap, ext_entnum);

	if (!rbt_is_nil(&nhr.mft_eemap, node)) {
		ee = rbtree_entry(node, typeof(*ee), tree);
		assert(ee->base == base_entnum);
		return;
	}

	ee = malloc(sizeof(*ee));
	assert(ee);
	nhr_mftee_num(ee) = ext_entnum;
	ee->base = base_entnum;
	rbtree_insert(&nhr.mft_eemap, &ee->tree);
}

void cache_sqlite_clean(void)
{
	int res, i;

	res = sqlite_drop_tables(cache_tables, cache_ntables, &i);
	if (res != SQLITE_OK)
		fprintf(stderr, "cache:sqlite: could not drop %s table: %s\n",
			cache_tables[i].desc, sqlite3_errmsg(nhr.db));
}

void cache_sqlite_dump(void)
{
	int res, i;

	res = sqlite3_exec(nhr.db, "BEGIN", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:sqlite: could not begin transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		return;
	}

	res = sqlite_create_tables(cache_tables, cache_ntables, &i);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:sqlite: could not create %s table: %s\n",
			cache_tables[i].desc, sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	res = sqlite_create_indexes(cache_indexes, cache_nindexes, &i);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:sqlite: could not create %s index: %s\n",
			cache_indexes[i].desc, sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	res = cache_mfte_sqlite_dump();
	if (res)
		goto exit_rollback;

	res = cache_mft_sqlite_build_tree();
	if (res)
		goto exit_rollback;

	res = sqlite3_exec(nhr.db, "COMMIT", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "cache:sqlite: could not commit transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	return;

exit_rollback:
	if (sqlite3_exec(nhr.db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
		fprintf(stderr, "cache:sqlite: could not rollback transaction: %s\n",
			sqlite3_errmsg(nhr.db));
}

/**
 * Initialize cache
 *
 * Initialize internal structures
 */
void cache_init(void)
{
	rbtree_init(&nhr.mft_cache);
	rbtree_init(&nhr.mft_eemap);
}
