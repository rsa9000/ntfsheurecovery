/**
 * Hints processing
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
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/stat.h>

#include "ntfsheurecovery.h"
#include "idx.h"
#include "attr.h"
#include "sqlite.h"
#include "misc.h"
#include "hints.h"

struct hints_parse_ctx {
	char *str;			/* Whole string */
	char *p;			/* Current position */
	char *e;			/* String end */
	void *data;
	unsigned data_sz;
	union {
		struct hint_cargs_data data;
		struct hint_cargs_idxn idxn;
		struct hint_cargs_attr attr;
	} cargs;
	union {
		struct hint_args_data_raw data_raw;
	} args;
};

struct hint_args {
	unsigned sz;
	const void *def;
	int argc_min;
	int argc_max;
	int (*parser)(int argc, char *argv[],
		      struct hints_parse_ctx *ctx);
	const char * (*dump)(const struct hint *h);
};

struct hint_info {
	const char const *name;
	const char const *tok;
	const struct hint_args args;
	int (*parser)(struct hints_parse_ctx *);
	const char * (*dump)(const struct hint *);
};

struct hint_class_info {
	const char const *name;
	const char const *tok;
	const struct hint_args cargs;
	const struct hint_info *hints;
	unsigned hints_num;
};

static const struct sqlite_tbl hints_tables[] = {
	{
		.name = "hints_classes",
		.desc = "hint classes info",
		.fields = "id INT,"
			"name CHAR NOT NULL",
	}, {
		.name = "hints_types",
		.desc = "hint types info",
		.fields = "class INT,"
			"id INT NOT NULL,"
			"name CHAR NOT NULL,"
			"PRIMARY KEY (class, id)"
	}, {
		.name = "hints",
		.desc = "hints items",
		.fields = "mft_entnum INT,"
			"class INT NOT NULL,"
			"type INT NOT NULL,"
			"cargs CHAR NOT NULL,"
			"args CHAR NOT NULL,"
			"val TEXT NOT NULL"
	}
};

#define hints_ntables	(sizeof(hints_tables)/sizeof(hints_tables[0]))

static int hints_parse_str(struct hints_parse_ctx *ctx)
{
	ctx->data_sz = ctx->e - ctx->p + 1;
	ctx->data = malloc(ctx->data_sz);
	memcpy(ctx->data, ctx->p, ctx->e - ctx->p);
	((char *)ctx->data)[ctx->e - ctx->p] = '\0';

	return 0;
}

static const char *hints_dump_str(const struct hint *h)
{
	return (char *)h->data;
}

static int hints_parse_u64(struct hints_parse_ctx *ctx)
{
	uint64_t tmp;
	char *endp;

	errno = 0;
	tmp = strtoull(ctx->p, &endp, 0);
	if (errno)
		return -errno;
	if (*endp != '\0')
		return -EINVAL;

	ctx->data_sz = sizeof(uint64_t);
	ctx->data = malloc(sizeof(uint64_t));
	memcpy(ctx->data, &tmp, sizeof(uint64_t));

	return 0;
}

static const char *hints_dump_u64(const struct hint *h)
{
	static char buf[24];
	uint64_t tmp;

	memcpy(&tmp, h->data, sizeof(uint64_t));
	snprintf(buf, sizeof(buf), "%"PRIu64, tmp);

	return buf;
}

static int hints_parse_u32(struct hints_parse_ctx *ctx)
{
	unsigned long tmp;
	char *endp;

	errno = 0;
	tmp = strtoul(ctx->p, &endp, 0);
	if (errno)
		return -errno;
	if (*endp != '\0')
		return -EINVAL;

	ctx->data_sz = sizeof(uint32_t);
	ctx->data = malloc(sizeof(uint32_t));
	memcpy(ctx->data, &tmp, sizeof(uint32_t));

	return 0;
}

static const char *hints_dump_x32(const struct hint *h)
{
	static char buf[16];
	uint32_t tmp;

	memcpy(&tmp, h->data, sizeof(uint32_t));
	snprintf(buf, sizeof(buf), "0x%08X", tmp);

	return buf;
}

static int hints_parse_u16(struct hints_parse_ctx *ctx)
{
	unsigned long tmp;
	uint16_t tmp16;
	char *endp;

	errno = 0;
	tmp = strtoul(ctx->p, &endp, 0);
	if (errno)
		return -errno;
	if (*endp != '\0')
		return -EINVAL;
	if (tmp > 0xFFFF)
		return -ERANGE;

	ctx->data_sz = sizeof(uint16_t);
	ctx->data = malloc(sizeof(uint16_t));
	tmp16 = tmp;
	memcpy(ctx->data, &tmp16, sizeof(uint16_t));

	return 0;
}

static const char *hints_dump_u16(const struct hint *h)
{
	static char buf[8];
	uint16_t tmp;

	memcpy(&tmp, h->data, sizeof(uint16_t));
	snprintf(buf, sizeof(buf), "%u", tmp);

	return buf;
}

static int hints_parse_cls(struct hints_parse_ctx *ctx)
{
	int i, num;
	void *data;
	struct ntfs_mp *mp;
	uint64_t vcn, lcn, clen;
	char *endp;

	for (i = 0, num = 0; ctx->p[i] != '\0'; ++i)
		if (ctx->p[i] == ',')
			num++;
	num += 2;	/* Last block + end element */

	ctx->data_sz = num * sizeof(*mp);
	data = malloc(ctx->data_sz);
	mp = data;

	endp = ctx->p - 1;
	errno = 0;
	vcn = 0;

	/**
	 * Item entry format MUST be one of the:
	 * LCN
	 * LCN:CLEN
	 * LCN(VCN)
	 * LCN(VCN):CLEN
	 *
	 * Generally item entry looks like: LCN[(VCN)][:CLEN]
	 */
	while (*endp != '\0') {
		lcn = strtoull(endp + 1, &endp, 0);
		if (errno)
			goto exit_inval;
		if (*endp == '\0' || *endp == ',') {
			clen = 1;
			goto finish_element;
		}
		if (*endp != ':' && *endp != '(')
			goto exit_inval;

		if (*endp == '(') {
			vcn = strtoull(endp + 1, &endp, 0);
			if (errno || *endp != ')')
				goto exit_inval;
			endp++;
			if (*endp == '\0' || *endp == ',') {
				clen = 1;
				goto finish_element;
			}
			if (*endp != ':')
				goto exit_inval;
		}

		clen = strtoull(endp + 1, &endp, 0);
		if (errno || (*endp != '\0' && *endp != ','))
			goto exit_inval;

finish_element:
		mp->vcn = vcn;
		mp->lcn = lcn;
		mp->clen = clen;
		vcn += clen;
		mp++;
	}

	mp->vcn = 0;
	mp->lcn = 0;
	mp->clen = 0;

	ctx->data = data;

	return 0;

exit_inval:
	free(data);

	return -EINVAL;
}

static const char *hints_dump_cls(const struct hint *h)
{
	static char buf[0x1000];
	char *p = buf, *e = buf + sizeof(buf);
	struct ntfs_mp *mp;
	uint64_t vcn = 0;

	for (mp = (void *)h->data; mp->clen; mp++) {
		if (mp->clen == 1) {
			if (vcn == mp->vcn)
				p += snprintf(p, e - p, "%"PRId64, mp->lcn);
			else
				p += snprintf(p, e - p, "%"PRId64"(%"PRIu64")",
					      mp->lcn, mp->vcn);
		} else {
			if (vcn == mp->vcn)
				p += snprintf(p, e - p, "%"PRId64":%"PRIu64,
					      mp->lcn, mp->clen);
			else
				p += snprintf(p, e - p,
					      "%"PRId64"(%"PRIu64"):%"PRIu64,
					      mp->lcn, mp->vcn, mp->clen);
		}
		if ((mp + 1)->clen)
			p += snprintf(p, e - p, ",");
		vcn = mp->vcn + mp->clen;
	}

	return buf;
}

static int hints_parse_digest(struct hints_parse_ctx *ctx)
{
	char *p = ctx->p;
	int i, res;
	uint8_t *digest = malloc(16);

	for (i = 0; i < 16; ++i, p += 2) {
		res = sscanf(p, "%2hhx", &digest[i]);
		if (res != 1) {
			free(digest);
			return -EINVAL;
		}
	}

	ctx->data_sz = 16;
	ctx->data = digest;

	return 0;
}

static char const *hints_dump_digest(const struct hint *h)
{
	return digest2str(h->data);
}

static int hints_parse_inputfile(struct hints_parse_ctx *ctx)
{
	struct hint_args_data_raw *ha = &ctx->args.data_raw;
	int fd = open(ctx->p, O_RDONLY);
	struct stat stat;
	ssize_t res;
	int __errno;

	if (fd == -1) {
		__errno = errno;
		fprintf(stderr, "hints: data: raw: could not open specified file\n");
		return -__errno;
	}

	if (fstat(fd, &stat)) {
		__errno = errno;
		fprintf(stderr, "hints: data: raw: could not get file metadata\n");
		goto exit_err;
	}

	if (ha->len == ~0) {
		ha->len = stat.st_size;
	} else if (ha->len + ha->foff > stat.st_size) {
		fprintf(stderr, "hints: data: raw: could read requested block [0x%08X:0x%08X] since file is too short (only 0x%08jX bytes)\n",
			ha->foff, ha->foff + ha->len - 1, stat.st_size);
		__errno = ENOSPC;
		goto exit_err;
	}

	ha->fnlen = strlen(ctx->p);
	ctx->data_sz = ha->len + ha->fnlen;
	ctx->data = malloc(ctx->data_sz);
	if (!ctx->data) {
		__errno = errno;
		goto exit_err;
	}

	res = read(fd, ctx->data, ha->len);
	if (res != ha->len) {
		__errno = errno;
		fprintf(stderr, "hints: data: raw: could not read from input file\n");
		goto exit_err;
	}

	close(fd);

	memcpy(ctx->data + ha->len, ctx->p, ha->fnlen);

	return 0;

exit_err:
	close(fd);
	free(ctx->data);
	ctx->data = NULL;
	ctx->data_sz = 0;

	return -__errno;
}

static char const *hints_dump_inputfile(const struct hint *h)
{
	static char buf[0x200];
	const struct hint_args_data_raw *ha = h->args;
	const char *filename = (char *)h->data + ha->len;

	snprintf(buf, sizeof(buf), "%.*s", ha->fnlen, filename);

	return buf;
}

static int hints_parse_nope(struct hints_parse_ctx *ctx)
{
	ctx->data_sz = 1;
	ctx->data = malloc(ctx->data_sz);
	return 0;
}

static char const *hints_dump_nope(const struct hint *h)
{
	return "";
}

static const struct hint_info hints_meta_info[] = {
	[HINT_META_PARENT] = {
		.name = "parent",
		.tok = "parent",
		.parser = hints_parse_u64,
		.dump = hints_dump_u64,
	},
	[HINT_META_ENTSEQNO] = {
		.name = "MFT entry seqno",
		.tok = "seqno",
		.parser = hints_parse_u16,
		.dump = hints_dump_u16,
	},
	[HINT_META_FILENAME] = {
		.name = "file name",
		.tok = "filename",
		.parser = hints_parse_str,
		.dump = hints_dump_str,
	},
	[HINT_META_TIME_CREATE] = {
		.name = "creation time",
		.tok = "time_create",
		.parser = hints_parse_u64,
		.dump = hints_dump_u64,
	},
	[HINT_META_TIME_CHANGE] = {
		.name = "change time",
		.tok = "time_change",
		.parser = hints_parse_u64,
		.dump = hints_dump_u64,
	},
	[HINT_META_TIME_MFT] = {
		.name = "MFT change time",
		.tok = "time_mft",
		.parser = hints_parse_u64,
		.dump = hints_dump_u64,
	},
	[HINT_META_TIME_ACCESS] = {
		.name = "access time",
		.tok = "time_access",
		.parser = hints_parse_u64,
		.dump = hints_dump_u64,
	},
	[HINT_META_FILEFLAGS] = {
		.name = "file flags",
		.tok = "fileflags",
		.parser = hints_parse_u32,
		.dump = hints_dump_x32,
	},
	[HINT_META_SID] = {
		.name = "Security ID",
		.tok = "sid",
		.parser = hints_parse_u32,
		.dump = hints_dump_x32,
	},
};

static const struct hint_info hints_idxn_info[] = {
	[HINT_IDXN_RESERVE] = {
		.name = "reserve",
		.tok = "reserve",
		.parser = hints_parse_u32,
		.dump = hints_dump_x32,
	},
};

static const struct hint_args_data_raw hints_data_raw_args_def = {
	.voff = 0,
	.len = ~0,
	.foff = 0,
};

static int hints_data_raw_args_parser(int argc, char *argv[],
				      struct hints_parse_ctx *ctx)
{
	struct hint_args_data_raw *ha = &ctx->args.data_raw;
	char *endp;

	errno = 0;

	ha->voff = strtoull(argv[0], &endp, 0);
	if (errno || *endp != '\0') {
		fprintf(stderr, "hints: data: raw: invalid virtual offset argument '%s' in: %s\n",
			argv[0], ctx->str);
		return -EINVAL;
	}

	if (argc > 1) {
		ha->len = strtoul(argv[1], &endp, 0);
		if (errno || *endp != '\0' || !ha->len) {
			fprintf(stderr, "hints: data: raw: invalid length argument '%s' in: %s\n",
				argv[1], ctx->str);
			return -EINVAL;
		}
	}

	if (argc > 2) {
		ha->foff = strtoul(argv[2], &endp, 0);
		if (errno || *endp != '\0') {
			fprintf(stderr, "hints: raw: invalid file offset argument '%s' in: %s\n",
				argv[2], ctx->str);
			return -EINVAL;
		}
	}

	return 0;
}

static const char *hints_data_raw_args_dump(const struct hint *h)
{
	static char buf[128];
	char *p = buf, *e = buf + sizeof(buf);
	const struct hint_args_data_raw *ha = h->args;

	p += snprintf(p, e - p, "0x%"PRIX64", 0x%X", ha->voff, ha->len);
	if (ha->foff)
		p += snprintf(p, e - p, ", 0x%X", ha->foff);

	return buf;
}

static const struct hint_info hints_data_info[] = {
	[HINT_DATA_SZ_ALLOC] = {
		.name = "allocated size",
		.tok = "sz_alloc",
		.parser = hints_parse_u64,
		.dump = hints_dump_u64,
	},
	[HINT_DATA_SZ_USED] = {
		.name = "used size",
		.tok = "sz_used",
		.parser = hints_parse_u64,
		.dump = hints_dump_u64,
	},
	[HINT_DATA_SZ_INIT] = {
		.name = "initialized size",
		.tok = "sz_init",
		.parser = hints_parse_u64,
		.dump = hints_dump_u64,
	},
	[HINT_DATA_DIGEST] = {
		.name = "digest",
		.tok = "digest",
		.parser = hints_parse_digest,
		.dump = hints_dump_digest,
	},
	[HINT_DATA_CLS] = {
		.name = "cls",
		.tok = "cls",
		.parser = hints_parse_cls,
		.dump = hints_dump_cls,
	},
	[HINT_DATA_RAW] = {
		.name = "raw",
		.tok = "raw",
		.args = {
			.sz = sizeof(struct hint_args_data_raw),
			.def = &hints_data_raw_args_def,
			.argc_max = 3,
			.parser = hints_data_raw_args_parser,
			.dump = hints_data_raw_args_dump,
		},
		.parser = hints_parse_inputfile,
		.dump = hints_dump_inputfile,
	},
	[HINT_DATA_BBIGN] = {
		.name = "ignore bb",
		.tok = "bbignore",
		.parser = hints_parse_nope,
		.dump = hints_dump_nope,
	},
};

static const struct hint_info hints_attr_info[] = {
	[HINT_ATTR_ID] = {
		.name = "attribute identity",
		.tok = "id",
		.parser = hints_parse_u16,
		.dump = hints_dump_u16,
	},
};

static int hints_idxn_cargs_parser(int argc, char *argv[],
				   struct hints_parse_ctx *ctx)
{
	int len;
	uint8_t idx_name[16 * 2];
	char *endp;

	len = strlen(argv[0]);
	if (len > sizeof(idx_name)/2) {
		fprintf(stderr, "hints: idxn: index name '%s' too long in: %s\n",
			argv[0], ctx->str);
		return -EINVAL;
	}

	str2utf16(argv[0], idx_name);

	ctx->cargs.idxn.idx_type = idx_detect_type(len, idx_name);
	if (ctx->cargs.idxn.idx_type == NHR_IDX_T_UNKN) {
		fprintf(stderr, "hints: idxn: invalid index '%s' in: %s\n",
			argv[0], ctx->str);
		return -EINVAL;
	}

	errno = 0;
	ctx->cargs.idxn.vcn = strtoull(argv[1], &endp, 0);
	if (errno || *endp != '\0') {
		fprintf(stderr, "hints: idxn: invalid index block VCN '%s' in: %s\n",
			argv[1], ctx->str);
		return -EINVAL;
	}

	return 0;
}

static const char *hints_idxn_cargs_dump(const struct hint *h)
{
	static char buf[32];
	const struct hint_cargs_idxn *hca = h->cargs;

	snprintf(buf, sizeof(buf), "%d, %"PRIu64, hca->idx_type, hca->vcn);

	return buf;
}

static const struct hint_cargs_data hints_data_cargs_def = {
	.name_len = 0,
};

static int hints_data_cargs_parser(int argc, char *argv[],
				   struct hints_parse_ctx *ctx)
{
	int len = strlen(argv[0]);

	if (len > sizeof(ctx->cargs.data.name)/2) {
		fprintf(stderr, "hints: data: stream name '%s' is too long in: %s\n",
			argv[0], ctx->str);
		return -EINVAL;
	}
	str2utf16(argv[0], ctx->cargs.data.name);
	ctx->cargs.data.name_len = len;

	return 0;
}

static const char *hints_data_cargs_dump(const struct hint *h)
{
	static char buf[32];
	const struct hint_cargs_data *hca = h->cargs;

	snprintf(buf, sizeof(buf), "%ls", name2wchar(hca->name, hca->name_len));

	return buf;
}

static int hints_attr_cargs_parser(int argc, char *argv[],
				   struct hints_parse_ctx *ctx)
{
	int len;
	char *endp;

	ctx->cargs.attr.type = attr_title2type(argv[0]);
	if (!ctx->cargs.attr.type) {
		fprintf(stderr, "hints: attr: unknown attribute type '%s' in: %s\n",
			argv[0], ctx->str);
		return -EINVAL;
	}

	len = strlen(argv[1]);
	if (len > sizeof(ctx->cargs.attr.name)/2) {
		fprintf(stderr, "hints: attr: attribute name '%s' too long in: %s\n",
			argv[1], ctx->str);
		return -EINVAL;
	}
	str2utf16(argv[1], ctx->cargs.attr.name);
	ctx->cargs.attr.name_len = len;

	if (argc < 3) {
		ctx->cargs.attr.sel = LONG_MAX;
	} else {
		errno = 0;
		ctx->cargs.attr.sel = strtol(argv[2], &endp, 0);
		if (errno || *endp != '\0') {
			fprintf(stderr, "hints: attr: invalid selector '%s' in: %s\n",
				argv[2], ctx->str);
			return -EINVAL;
		}
	}

	return 0;
}

static const char *hints_attr_cargs_dump(const struct hint *h)
{
	static char buf[128];
	char *p = buf, *e = buf + sizeof(buf);
	const struct hint_cargs_attr *hca = h->cargs;
	const struct nhr_attr_info *ai = attr_get_info(hca->type);

	p += snprintf(p, e - p, "%s, %ls", ai ? ai->title : "\"\"",
		      name2wchar(hca->name, hca->name_len));
	if (hca->sel != LONG_MAX)
		p += snprintf(p, e - p, ", %ld", hca->sel);

	return buf;
}

static const struct hint_class_info hints_classes_info[] = {
	[HINT_META] = {
		.name = "metadata",
		.tok = "meta",
		.hints = hints_meta_info,
		.hints_num = sizeof(hints_meta_info)/sizeof(hints_meta_info[0]),
	},
	[HINT_IDXN] = {
		.name = "index node",
		.tok = "idxn",
		.cargs = {
			.sz = sizeof(struct hint_cargs_idxn),
			.argc_min = 2,
			.argc_max = 2,
			.parser = hints_idxn_cargs_parser,
			.dump = hints_idxn_cargs_dump,
		},
		.hints = hints_idxn_info,
		.hints_num = sizeof(hints_idxn_info)/sizeof(hints_idxn_info[0]),
	},
	[HINT_DATA] = {
		.name = "data",
		.tok = "data",
		.cargs = {
			.sz = sizeof(struct hint_cargs_data),
			.def = &hints_data_cargs_def,
			.argc_min = 1,
			.argc_max = 1,
			.parser = hints_data_cargs_parser,
			.dump = hints_data_cargs_dump,
		},
		.hints = hints_data_info,
		.hints_num = sizeof(hints_data_info)/sizeof(hints_data_info[0]),
	},
	[HINT_ATTR] = {
		.name = "attribute",
		.tok = "attr",
		.cargs = {
			.sz = sizeof(struct hint_cargs_attr),
			.argc_min = 2,
			.argc_max = 3,
			.parser = hints_attr_cargs_parser,
			.dump = hints_attr_cargs_dump,
		},
		.hints = hints_attr_info,
		.hints_num = sizeof(hints_attr_info)/sizeof(hints_attr_info[0]),
	},
};

static int hints_sqlite_dump_types(const struct hint_class_info *cinf)
{
	static const char *q_insert = "INSERT INTO hints_types (class, id, name)"
		"VALUES (:class, :id, :name)";
	const struct hint_info *inf;
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	int res, i;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "hints: sqlite-err: could not prepare type info insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		return SQLITE_ERROR;
	}

	SQLITE_BIND(int, "class", cinf - hints_classes_info);

	res = SQLITE_ERROR;
	for (i = 0; i < cinf->hints_num; ++i) {
		inf = &cinf->hints[i];
		SQLITE_BIND(int, "id", i);
		SQLITE_BIND(text, "name", inf->name, -1, SQLITE_STATIC);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "hints: sqlite-err: could not insert %s::%s type info: %s\n",
				cinf->name, inf->name, sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "hints: sqlite-err: could not bind class info '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res;
}

static int hints_sqlite_dump_info(void)
{
	static const char *q_insert = "INSERT INTO hints_classes (id, name)"
		"VALUES (:id, :name)";
	const struct hint_class_info *cinf;
	const int n = sizeof(hints_classes_info) /
		      sizeof(hints_classes_info[0]);
	char const *errfield;
	struct sqlite3_stmt *stmt = NULL;
	int res, i;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "hints: sqlite-err: could not prepare class info insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		return -1;
	}

	for (i = 0; i < n; ++i) {
		cinf = &hints_classes_info[i];
		SQLITE_BIND(int, "id", i);
		SQLITE_BIND(text, "name", cinf->name, -1, SQLITE_STATIC);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "hints: sqlite-err: could non insert %s hint class info: %s\n",
				cinf->name, sqlite3_errmsg(nhr.db));
			res = SQLITE_ERROR;
			goto exit;
		}
		sqlite3_reset(stmt);

		res = hints_sqlite_dump_types(cinf);
		if (res != SQLITE_OK)
			goto exit;
	}

	goto exit;

exit_err_bind:
	fprintf(stderr, "hints: sqlite-err: could not bind class info '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int hints_sqlite_dump_hints(const struct hint_entry *he)
{
	static const char *q_insert = "INSERT INTO hints"
		"(mft_entnum, class, type, cargs, args, val) VALUES"
		"(:mft_entnum, :class, :type, :cargs, :args, :val)";
	const struct hint_class_info *cinf;
	const struct hint_info *inf;
	const struct hint *h;
	char const *errfield;
	char const *cargs, *args;
	struct sqlite3_stmt *stmt = NULL;
	int res;

	res = sqlite3_prepare_v2(nhr.db, q_insert, -1, &stmt, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "hints: sqlite-err: could not prepare hint insert statement: %s\n",
			sqlite3_errmsg(nhr.db));
		return -1;
	}

	SQLITE_BIND(int64, "mft_entnum", hint_entry_num(he));

	res = SQLITE_ERROR;
	list_for_each_entry(h, &he->hints, list) {
		cinf = &hints_classes_info[h->class];
		inf = &cinf->hints[h->type];
		SQLITE_BIND(int, "class", h->class);
		SQLITE_BIND(int, "type", h->type);
		cargs = cinf->cargs.dump ? cinf->cargs.dump(h) : "";
		SQLITE_BIND(text, "cargs", cargs, -1, SQLITE_STATIC);
		args = inf->args.dump ? inf->args.dump(h) : "";
		SQLITE_BIND(text, "args", args, -1, SQLITE_STATIC);
		SQLITE_BIND(text, "val", inf->dump(h), -1, SQLITE_STATIC);

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "hints: sqlite-err: could not insert %"PRIu64"::%s::%s hint: %s\n",
				hint_entry_num(he), cinf->name, inf->name,
				sqlite3_errmsg(nhr.db));
			goto exit;
		}
		sqlite3_reset(stmt);
	}

	res = SQLITE_OK;
	goto exit;

exit_err_bind:
	fprintf(stderr, "hints: sqlite-err: could not bind hint '%s' value: %s\n",
		errfield, sqlite3_errmsg(nhr.db));
	res = SQLITE_ERROR;

exit:
	sqlite3_finalize(stmt);

	return res != SQLITE_OK ? -1 : 0;
}

static int hints_sqlite_dump_entries(void)
{
	struct hint_entry *he;
	int res;

	rbt_inorder_walk_entry(he, &nhr.hints, tree) {
		res = hints_sqlite_dump_hints(he);
		if (res)
			return res;
	}

	return 0;
}

static const struct hint_class_info *hints_class_tok2info(const char *tok,
							  unsigned len)
{
	static const int n = sizeof(hints_classes_info) /
			     sizeof(hints_classes_info[0]);
	unsigned i;

	for (i = 0; i < n; ++i) {
		if (strncmp(tok, hints_classes_info[i].tok, len) != 0)
			continue;
		if (strlen(hints_classes_info[i].tok) != len)
			continue;
		return &hints_classes_info[i];
	}

	return NULL;
}

static const struct hint_info *hints_tok2info(const struct hint_class_info *cinf,
					      const char *tok, unsigned len)
{
	unsigned i;

	for (i = 0; i < cinf->hints_num; ++i) {
		if (strncmp(tok, cinf->hints[i].tok, len) != 0)
			continue;
		if (strlen(cinf->hints[i].tok) != len)
			continue;
		return &cinf->hints[i];
	}

	return NULL;
}

static void hints_hint_insert(struct hint_entry *he, struct hint *h)
{
	struct hint *__h;

	he->cmap |= 1 << h->class;

	list_for_each_entry(__h, &he->hints, list) {
		if (h->class > __h->class)
			continue;
		if (h->class == __h->class && h->type >= __h->type)
			continue;
		list_add_tail(&h->list, &__h->list);	/* Add before */
		return;
	}

	list_add_tail(&h->list, &he->hints);
}

static int hints_parse_args(const char *name, const struct hint_args *args,
			    struct hints_parse_ctx *ctx)
{
	int i, argc = 0, res = 0;
	char **argv = NULL;
	char *p;

	while ((p = strpbrk(ctx->p, ",)")) != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(argv[0]));
		argv[argc] = malloc(p - ctx->p + 1);
		strncpy(argv[argc], ctx->p, p - ctx->p);
		argv[argc][p - ctx->p] = '\0';
		argc++;
		ctx->p = p + 1;
		if (*p == ')')
			break;
	}
	if (!p || *p != ')') {
		fprintf(stderr, "hints: syntax error (invalid %s arguments) in: %s\n",
			name, ctx->str);
		res = -EINVAL;
	} else if (argc == 1 && argv[0][0] == '\0') {
		fprintf(stderr, "hints: syntax error: no %s arguments specified in: %s\n",
			name, ctx->str);
		res = -EINVAL;
	} else if (args->argc_min && argc < args->argc_min) {
		fprintf(stderr, "hints: not enough %s arguments (require at least %d args) in: %s\n",
			name, args->argc_min, ctx->str);
		res = -EINVAL;
	} else if (args->argc_max && argc > args->argc_max) {
		fprintf(stderr, "hints: too many %s arguments (require not more than %d args) in: %s\n",
			name, args->argc_max, ctx->str);
		res = -EINVAL;
	}
	if (res)
		goto exit;

	res = args->parser(argc, argv, ctx);

exit:
	for (i = 0; i < argc; ++i)
		free(argv[i]);
	free(argv);

	return res;
}

static int hints_str_parse(char *str)
{
	struct hints_parse_ctx _ctx, *ctx = &_ctx;
	uint64_t entnum;
	struct hint_entry *ent;
	struct hint *h;
	const struct hint_class_info *cinf;
	const struct hint_info *inf;
	const char *p;
	int res, n;

	memset(ctx, 0x00, sizeof(*ctx));
	ctx->str = str;
	ctx->p = str;
	ctx->e = str + strlen(str);

	if (ctx->e > ctx->p && ctx->e[-1] == '\n') {
		ctx->e[-1] = '\0';
		ctx->e--;
	}

	if (ctx->e == ctx->p)
		return 0;

	res = sscanf(ctx->p, "%"SCNu64"-%n", &entnum, &n);
	if (res != 1) {
		fprintf(stderr, "hints: unknown entry number in string: %s\n", ctx->str);
		return -EINVAL;
	}

	ctx->p += n;

	p = strpbrk(ctx->p, "-(");
	if (!p) {
		fprintf(stderr, "hints: syntax error (class missed) in: %s\n", ctx->str);
		return -EINVAL;
	}

	n = p - ctx->p;
	cinf = hints_class_tok2info(ctx->p, n);
	if (!cinf) {
		fprintf(stderr, "hints: unknown hint class '%.*s' in: %s\n", n,
			ctx->p, ctx->str);
		return -EINVAL;
	}

	ctx->p += n + 1;	/* Skip class token and delimiter */

	/* Apply default class arguments */
	if (cinf->cargs.def)
		memcpy(&ctx->cargs, cinf->cargs.def, cinf->cargs.sz);

	/* Handle possible class-wide arguments (metadata) */
	if (ctx->p[-1] == '(') {
		if (!cinf->cargs.parser) {
			fprintf(stderr, "hints: %s class does not accept argument in: %s\n",
				cinf->name, ctx->str);
			return -EINVAL;
		}
		res = hints_parse_args("class", &cinf->cargs, ctx);
		if (res)
			return res;
		if (ctx->p[0] != '-') {
			fprintf(stderr, "hints: syntax error (expect delimiter after class arguments) in: %s\n",
				ctx->str);
			return -EINVAL;
		}
		ctx->p++;
	} else {
		if (cinf->cargs.parser && !cinf->cargs.def) {
			fprintf(stderr, "hints: %s class require some arguemnts in: %s\n",
				cinf->name, ctx->str);
			return -EINVAL;
		}
	}

	p = strpbrk(ctx->p, " =(");
	if (!p) {
		fprintf(stderr, "hints: syntax error (hint value missed) in: %s\n",
			ctx->str);
		return -EINVAL;
	}

	n = p - ctx->p;
	inf = hints_tok2info(cinf, ctx->p, n);
	if (!inf) {
		fprintf(stderr, "hints: unknown %s '%.*s' hint type in: %s\n",
			cinf->name, n, ctx->p, ctx->str);
		return -EINVAL;
	}

	ctx->p += n;	/* Skip hint token */

	/* Apply default hint arguments */
	if (inf->args.def)
		memcpy(&ctx->args, inf->args.def, inf->args.sz);

	if (ctx->p[0] == '(') {
		if (!inf->args.parser) {
			fprintf(stderr, "hints: %s %s hint type does not accept argument in: %s\n",
				cinf->name, inf->name, ctx->str);
			return -EINVAL;
		}
		ctx->p++;	/* Skip leading '(' */
		res = hints_parse_args("hint", &inf->args, ctx);
		if (res)
			return res;
	} else {
		if (inf->args.parser && !inf->args.def) {
			fprintf(stderr, "hints: %s %s hint type require some arguments in: %s\n",
				cinf->name, inf->name, ctx->str);
			return -EINVAL;
		}
	}

	while (ctx->p != ctx->e && ctx->p[0] != '=')	/* Skip spaces */
		ctx->p++;
	if (ctx->p[0] != '=') {
		fprintf(stderr, "hints: syntax error (hint value missed) in: %s\n",
			ctx->str);
		return -EINVAL;
	}

	ctx->p++;	/* Skip '=' symbol */

	while (ctx->p != ctx->e && ctx->p[0] == ' ')	/* Skip spaces */
		ctx->p++;
	if (ctx->p == ctx->e) {
		fprintf(stderr, "hints: no value specified in: %s\n", ctx->str);
		return -EINVAL;
	}

	res = inf->parser(ctx);
	if (res || !ctx->data) {
		fprintf(stderr, "hints: %s %s hint parse error (err: %s): %s\n",
			cinf->name, inf->name, strerror(-res), ctx->str);
		return res;
	}

	h = malloc(sizeof(*h) + ctx->data_sz);
	h->class = cinf - hints_classes_info;
	h->type = inf - cinf->hints;
	memcpy(h->data, ctx->data, ctx->data_sz);
	free(ctx->data);

	if (cinf->cargs.sz) {
		h->cargs = malloc(cinf->cargs.sz);
		memcpy(h->cargs, &ctx->cargs, cinf->cargs.sz);
	}

	if (inf->args.sz) {
		h->args = malloc(inf->args.sz);
		memcpy(h->args, &ctx->args, inf->args.sz);
	}

	ent = hints_find_entry(entnum);
	if (!ent) {
		ent = malloc(sizeof(*ent));
		hint_entry_num(ent) = entnum;
		ent->cmap = 0;
		INIT_LIST_HEAD(&ent->hints);
		rbtree_insert(&nhr.hints, &ent->tree);
	}

	hints_hint_insert(ent, h);

	return 0;
}

int hints_file_parse(const char *hintsfile)
{
	FILE *fp = fopen(hintsfile, "r");
	char *buf;
	int res = 0;

	if (NULL == fp) {
		fprintf(stderr, "Could not open hints file '%s' for reading (err: %d): %s\n",
			hintsfile, errno, strerror(errno));
		return -errno;
	}

	buf = malloc(0x2000);

	while (fgets(buf, 0x2000, fp)) {
		if (buf[0] == '#')
			continue;
		res = hints_str_parse(buf);
		if (res)
			break;
	}

	free(buf);

	fclose(fp);

	return res;
}

struct hint_entry *hints_find_entry(uint64_t entnum)
{
	struct rbtree_head *node = rbtree_lookup(&nhr.hints, entnum);

	return rbt_is_nil(&nhr.hints, node) ? NULL : (struct hint_entry *)node;
}

struct hint *hints_find_hint_idxn(uint64_t entnum, int idx_type, int64_t vcn,
				  enum hint_idxn_types type)
{
	struct hint_entry *he = hints_find_entry(entnum);
	struct hint *h;
	struct hint_cargs_idxn *hca;

	if (!he || !(he->cmap & (1 << HINT_IDXN)))
		return NULL;

	list_for_each_entry(h, &he->hints, list) {
		if (h->class < HINT_IDXN)
			continue;
		if (h->class > HINT_IDXN)
			break;
		if (h->type != type)
			continue;
		hca = h->cargs;
		if (hca->idx_type == idx_type && hca->vcn == vcn)
			return h;
	}

	return NULL;
}

void hints_sqlite_clean(void)
{
	int res, i;

	res = sqlite_drop_tables(hints_tables, hints_ntables, &i);
	if (res != SQLITE_OK)
		fprintf(stderr, "hints: sqlite-err: could not drop %s table: %s\n",
			hints_tables[i].desc, sqlite3_errmsg(nhr.db));
}

void hints_sqlite_dump(void)
{
	int res, i;

	res = sqlite3_exec(nhr.db, "BEGIN", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "hints: sqlite-err: could not begin transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		return;
	}

	res = sqlite_create_tables(hints_tables, hints_ntables, &i);
	if (res != SQLITE_OK) {
		fprintf(stderr, "hints: sqlite-err: could not create %s table: %s\n",
			hints_tables[i].desc, sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	res = hints_sqlite_dump_info();
	if (res)
		goto exit_rollback;

	res = hints_sqlite_dump_entries();
	if (res)
		goto exit_rollback;

	res = sqlite3_exec(nhr.db, "COMMIT", NULL, NULL, NULL);
	if (res != SQLITE_OK) {
		fprintf(stderr, "hints: sqlite-err: could not commit transaction: %s\n",
			sqlite3_errmsg(nhr.db));
		goto exit_rollback;
	}

	return;

exit_rollback:
	if (sqlite3_exec(nhr.db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
		fprintf(stderr, "hints: sqlite-err: could not rollback transaction: %s\n",
			sqlite3_errmsg(nhr.db));
}
