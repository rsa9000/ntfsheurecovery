/**
 * $Secure file dump
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
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sqlite3.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "bb.h"
#include "img.h"
#include "cache.h"
#include "cmask.h"
#include "ntfs.h"
#include "ntfs_dump.h"
#include "mft_aux.h"
#include "mft_analyze.h"
#include "sqlite.h"
#include "misc.h"
#include "secure.h"
#include "secfile_dump.h"

static const struct sqlite_tbl secdump_tables[] = {
	{
		.name = "sec_desc_hdr",
		.desc = "security descriptor headers",
		.fields = "id UNSIGNED,"
			"hash UNSIGNED,"
			"voff INTEGER PRIMARY KEY,"
			"len UNSIGNED NOT NULL",
	}, {
		.name = "sec_desc",
		.desc = "security descriptors",
		.fields = "id INTEGER PRIMARY KEY,"
			"flags UNSIGNED NOT NULL,"
			"owner TEXT,"
			"`group` TEXT,"
			"sacl UNSIGNED,"
			"dacl UNSIGNED",
	}, {
		.name = "sec_acl",
		.desc = "security access control lists (ACL)",
		.fields = "id INTEGER PRIMARY KEY,"
			"ace_num UNSIGNED NOT NULL",
	}, {
		.name = "sec_ace",
		.desc = "security acess control entries (ACE)",
		.fields = "acl UNSIGNED NOT NULL,"
			"pos UNSIGNED NOT NULL,"
			"type UNSIGNED NOT NULL,"
			"flags UNSIGNED NOT NULL,"
			"mask UNSIGNED NOT NULL,"
			"sid TEXT NOT NULL",
	}
};

#define secdump_ntables		(sizeof(secdump_tables) /	\
				 sizeof(secdump_tables[0]))

static const struct sqlite_idx secdump_indexes[] = {
	{
		.name = "sec_desc_hdr_id",
		.desc = "security descriptior headers",
		.fields = "sec_desc_hdr (id)",
	}
};

#define secdump_nindexes	(sizeof(secdump_indexes) /	\
				 sizeof(secdump_indexes[0]))

static int secfile_sds_sqlite_dump_prep(void)
{
	int res, i;

	if (sqlite3_exec(nhr.db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "sds:sqlite: could not begin transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		return -1;
	}

	res = sqlite_drop_tables(secdump_tables, secdump_ntables, &i);
	if (res != SQLITE_OK) {
		fprintf(stderr, "sds:sqlite: could not drop %s table: %s\n",
			secdump_tables[i].name, sqlite3_errmsg(nhr.db));
		return -1;
	}

	res = sqlite_create_tables(secdump_tables, secdump_ntables, &i);
	if (res != SQLITE_OK) {
		fprintf(stderr, "sds:sqlite: could not create %s table: %s\n",
			secdump_tables[i].name, sqlite3_errmsg(nhr.db));
		return -1;
	}

	res = sqlite_create_indexes(secdump_indexes, secdump_nindexes, &i);
	if (res != SQLITE_OK) {
		fprintf(stderr, "sds:sqlite: could not create %s index: %s\n",
			secdump_indexes[i].desc, sqlite3_errmsg(nhr.db));
		return -1;
	}

	return 0;
}

static void secfile_sds_sqlite_dump_fail(void)
{
	if (sqlite3_exec(nhr.db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
		fprintf(stderr, "sds:sqlite: could not rollback transaction\n");
}

static void secfile_sds_sqlite_dump_done(void)
{
	if (sqlite3_exec(nhr.db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
		fprintf(stderr, "sds:sqlite: could not commit transaction\n");
}

static int secfile_sds_sqlite_dump_aces(const struct ntfs_sec_acl *acl,
					const int aclid)
{
	const struct ntfs_sec_ace *ace;
	const struct ntfs_sec_ace_file *f_ace;
	static const char *q_insert = "INSERT INTO sec_ace (acl, pos, type, flags, mask, sid)"
		"VALUES (:acl, :pos, :type, :flags, :mask, :sid)";
	struct sqlite3_stmt *stmt;
	const char *errfield;
	int pos, res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "sds:sqlite: could not prepare ACE insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int, "acl", aclid);

	ace = NTFS_SEC_ACL_FIRST_ACE(acl);
	for (pos = 0; pos < acl->ace_num; ++pos, ace = NTFS_SEC_ACE_NEXT(ace)) {
		SQLITE_BIND(int, "pos", pos);
		SQLITE_BIND(int, "type", ace->type);
		SQLITE_BIND(int, "flags", ace->flags);

		switch (ace->type) {
		case NTFS_SEC_ACE_T_ALLOW:
		case NTFS_SEC_ACE_T_DENY:
		case NTFS_SEC_ACE_T_AUDIT:
		case NTFS_SEC_ACE_T_ALARM:
			f_ace = (struct ntfs_sec_ace_file *)ace;
			SQLITE_BIND(int, "mask", f_ace->mask);
			SQLITE_BIND(text, "sid", ntfs_sid2str(&f_ace->sid), -1, free);
			break;
		default:
			SQLITE_BIND(int, "mask", 0);
			SQLITE_BIND(text, "sid", "", 0, SQLITE_STATIC);
			fprintf(stderr, "sds:sqlite: unsupported ACE type\n");
			break;
		}

		res = sqlite3_step(stmt);
		if (res != SQLITE_DONE) {
			fprintf(stderr, "sds:sqlite: could not insert ACE: %s\n",
				sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "sds:sqlite could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? 0 : -1;
}

static int secfile_sds_sqlite_dump_acl(const struct ntfs_sec_acl *acl)
{
	static const char *q_insert = "INSERT INTO sec_acl (ace_num)"
		"VALUES (:ace_num)";
	struct sqlite3_stmt *stmt;
	const char *errfield;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "sds:sqlite: could not prepare ACL insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int, "ace_num", acl->ace_num);

	res = sqlite3_step(stmt);
	if (res != SQLITE_DONE) {
		fprintf(stderr, "sds:sqlite: could not insert ACL: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	res = secfile_sds_sqlite_dump_aces(acl, nhr.db_last_rowid) ? SQLITE_ERROR : SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "sds:sqlite could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? nhr.db_last_rowid : -1;
}

static int secfile_sds_sqlite_dump_desc(const struct ntfs_sec_desc *sd,
					unsigned sid)
{
	static const char *q_insert = "INSERT INTO sec_desc"
		"(id, flags, owner, `group`, sacl, dacl) VALUES"
		"(:id, :flags, :owner, :group, :sacl, :dacl)";
	struct sqlite3_stmt *stmt;
	const char *errfield;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "sds:sqlite: could not prepare descriptor insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	SQLITE_BIND(int, "id", sid);
	SQLITE_BIND(int, "flags", sd->flags);
	if (sd->owner_off)
		SQLITE_BIND(text, "owner", ntfs_sid2str((void *)sd + sd->owner_off), -1, free);
	if (sd->group_off)
		SQLITE_BIND(text, "group", ntfs_sid2str((void *)sd + sd->group_off), -1, free);
	if (sd->flags & NTFS_SEC_DESC_F_SACL && sd->sacl_off) {
		res = secfile_sds_sqlite_dump_acl((void *)sd + sd->sacl_off);
		if (res < 0) {
			res = SQLITE_ERROR;
			goto exit;
		}
		SQLITE_BIND(int, "sacl", res);
	}
	if (sd->flags & NTFS_SEC_DESC_F_DACL && sd->dacl_off) {
		res = secfile_sds_sqlite_dump_acl((void *)sd + sd->dacl_off);
		if (res < 0) {
			res = SQLITE_ERROR;
			goto exit;
		}
		SQLITE_BIND(int, "dacl", res);
	}

	res = sqlite3_step(stmt);
	if (res != SQLITE_DONE) {
		fprintf(stderr, "sds:sqlite: could not insert SDS descriptor: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "sds:sqlite could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? 0 : -1;
}

static int secfile_sds_sqlite_dump_desc_hdr(uint64_t voff,
					    const struct ntfs_sec_desc_hdr *sdh)
{
	static const char *q_insert = "INSERT INTO sec_desc_hdr"
		"(id, hash, voff, len) VALUES (:id, :hash, :voff, :len)";
	struct sqlite3_stmt *stmt;
	const char *errfield;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "sds:sqlite: could not prepare descriptor header insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	if (sdh->id) {
		SQLITE_BIND(int, "id", sdh->id);
		SQLITE_BIND(int, "hash", sdh->hash);
		SQLITE_BIND(int64, "voff", sdh->voff);
	} else {
		SQLITE_BIND(null, "id");
		SQLITE_BIND(null, "hash");
		SQLITE_BIND(int64, "voff", voff);
	}
	SQLITE_BIND(int, "len", sdh->len);

	res = sqlite3_step(stmt);
	if (res != SQLITE_DONE) {
		fprintf(stderr, "sds:sqlite: could not insert SDS descriptor header: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit;
	}

	if (sdh->id)
		res = secfile_sds_sqlite_dump_desc((void *)sdh->data, sdh->id);
	else
		res = SQLITE_OK;

	goto exit;

exit_err_bind:
	fprintf(stderr, "sds:sqlite could not bind '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res == SQLITE_OK ? 0 : -1;
}

static int secfile_sds_dump_item(uint64_t voff,
				 const struct ntfs_sec_desc_hdr *sdh,
				 void *priv)
{
	uint32_t hash;

	secfile_sds_sqlite_dump_desc_hdr(voff, sdh);

	hash = ntfs_sec_desc_hash(sdh->data, sdh->len - sizeof(*sdh));
	if (sdh->id != 0) {
		if (hash != sdh->hash)
			printf("sds:desc:hash checking fail (expect: 0x%08X)\n", hash);
		ntfs_dump_sec_desc_hdr("sds:desc:", sdh, 1);
	} else {
		ntfs_dump_sec_desc_hdr_short("sds:desc:", sdh);
	}

	return 0;
}

static void secfile_sds_dump(const struct ntfs_mp *mpl,
			     const struct nhr_cmask_elem *bb_mask,
			     const uint64_t sds_len)
{
	int res;

	if (secfile_sds_sqlite_dump_prep() != 0) {
		fprintf(stderr, "sds: could not prepare SQLite dump\n");
		return;
	}

	res = secure_sds_foreach_cb(mpl, bb_mask, sds_len,
				    secfile_sds_dump_item, NULL);
	if (res != 0) {
		secfile_sds_sqlite_dump_fail();
		return;
	}

	secfile_sds_sqlite_dump_done();
}

void secfile_dump(void)
{
	static const char sds_name[] = {'$', 0, 'S', 0, 'D', 0, 'S', 0};
	struct nhr_mft_entry *mfte, *bmfte;
	unsigned i;
	struct nhr_alist_item *ali;
	struct nhr_data *data = NULL;
	struct nhr_cmask_elem *sds_bb_mask;
	int res;

	bmfte = cache_mfte_find(NTFS_ENTNUM_SECURE);

	if (!bmfte) {	/* Ok, $Secure is not corrupted */
		bmfte = cache_mfte_alloc(NTFS_ENTNUM_SECURE);
		bmfte->f_cmn |= NHR_MFT_FC_BASE;
		bmfte->f_cmn |= NHR_MFT_FC_IDX;
	}

	res = mft_entry_attr2cache(bmfte);
	if (res) {
		fprintf(stderr, "secure:could not fetch $Secure file attributes\n");
		return;
	}
	list_for_each_entry(mfte, &bmfte->ext, ext) {
		res = mft_entry_attr2cache(mfte);
		if (res) {
			fprintf(stderr, "secure: could not fetch $Secure file attributes from extent entry\n");
			return;
		}
	}

	printf("Fetched attributes:\n");
	list_for_each_entry(ali, &bmfte->alist, list)
		printf("name = %9ls type = 0x%02X id = %2u entnum = #%-6"PRIu64" firstvcn = %"PRIu64"\n",
		       cache_attr_name(ali), ali->type, ali->id,
		       nhr_mfte_num(ali->mfte), ali->firstvcn);

	/* Fetch $SDS data information (mapping pairs, size) */
	res = mft_fetch_data_info(bmfte, sizeof(sds_name) / 2,
				  (uint8_t *)sds_name);
	assert(res == 0);

	for (i = 0; i < bmfte->data_num; ++i) {
		data = bmfte->data[i];
		if (data->name_len == 0)	/* Skip default data stream */
			continue;

		printf("%ls clusters: %"PRIu64" (%"PRIu64" bytes)\n",
		       cache_data_name(data), ntfs_mpl_vclen(data->mpl),
		       data->sz_used.val);
		if (data->name_len == 4 &&
		    memcmp(data->name, sds_name, sizeof(sds_name)) == 0) {
			sds_bb_mask = cache_data_bb_gen_mask(bmfte, data);
			assert(sds_bb_mask);
			secfile_sds_dump(data->mpl, sds_bb_mask, data->sz_used.val);
			cmask_free(sds_bb_mask);
			sds_bb_mask = NULL;
		}
	}

}
