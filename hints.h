/**
 * Hints processor interface
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

#ifndef _HINTS_H_
#define _HINTS_H_

#include "rbtree.h"
#include "list.h"

/**
 * MFT entry hints descriptor
 * NB: MFT entry number stored in the tree node key
 */
struct hint_entry {
	struct rbtree_head tree;
	unsigned cmap;			/* Class map (each bit indicate class presence) */
	struct list_head hints;		/* Hints list */
};

#define hint_entry_num(__h)	(__h)->tree.key

enum hint_class {
	HINT_META,	/* File metadata hints */
	HINT_IDXN,	/* Index nodes hints */
	HINT_DATA,	/* File data stream hints */
	HINT_ATTR,	/* Attributes metadata hints */
};

/**
 * Note: hint types order in following enums is meaningful since we order
 * hints internally by class and type. So if some code traverse hints list
 * sequently it found hints in the same order as in this enums.
 */

enum hint_meta_types {
	HINT_META_PARENT,
	HINT_META_ENTSEQNO,
	HINT_META_FILENAME,
	HINT_META_TIME_CREATE,
	HINT_META_TIME_CHANGE,
	HINT_META_TIME_MFT,
	HINT_META_TIME_ACCESS,
	HINT_META_FILEFLAGS,
	HINT_META_SID,
};

enum hint_idxn_types {
	HINT_IDXN_RESERVE,
};

enum hint_data_types {
	HINT_DATA_SZ_ALLOC,
	HINT_DATA_SZ_USED,
	HINT_DATA_SZ_INIT,
	HINT_DATA_DIGEST,
	HINT_DATA_CLS,
	HINT_DATA_RAW,
	HINT_DATA_BBIGN,
};

enum hint_attr_type {
	HINT_ATTR_ID,
};

struct hint {
	struct list_head list;		/* Link item MFT entry hints */
	enum hint_class class;		/* Hint class */
	unsigned type;			/* Hint type */
	void *cargs;			/* Hint class level arguments */
	void *args;			/* Hint type level arguments */
	uint8_t data[];			/* Hint data */
};

/* Hint arguments for data class */
struct hint_cargs_data {
	unsigned name_len;		/* Data stream name length */
	uint8_t name[32 * 2];		/* Data stream name (UTF16) */
};

/* Hint arguments for data raw hints */
struct hint_args_data_raw {
	uint64_t voff;			/* Virtual offset inside stream */
	uint32_t len;			/* Hint data length */
	uint32_t foff;			/* Offset inside input file */
	unsigned fnlen;			/* Input file name */
};

/* Hint arguments for index nodes class */
struct hint_cargs_idxn {
	int idx_type;			/* Index type */
	int64_t vcn;			/* Index block VCN */
};

/* Hint arguments for attributes class */
struct hint_cargs_attr {
	uint32_t type;			/* Attribute type */
	long sel;			/* Additional selector (e.g. name type for $FILE_NAME attr) */
	unsigned name_len;		/* Attribute name length */
	uint8_t name[32 * 2];		/* Attribute name (UTF16) */
};

/* Check whether entry have hints of specified class or no */
static inline int hints_have_class(const struct hint_entry *he, enum hint_class class)
{
	return he->cmap & (1 << class);
}

int hints_file_parse(const char *hintsfile);
struct hint_entry *hints_find_entry(uint64_t entnum);
struct hint *hints_find_hint_idxn(uint64_t entnum, int idx_type, int64_t vcn,
				  enum hint_idxn_types type);
void hints_sqlite_clean(void);
void hints_sqlite_dump(void);

#endif	/* _HINTS_H_ */
