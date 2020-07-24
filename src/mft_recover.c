/**
 * MFT recovery procedures
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
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "bb.h"
#include "img.h"
#include "misc.h"
#include "hints.h"
#include "cache.h"
#include "mft_aux.h"
#include "mft_cmp.h"
#include "attr.h"
#include "idx.h"
#include "ntfs_struct.h"
#include "mft_recover.h"

/**
 * Recover item MFT name using hints
 */
static void mft_hints2meta_name(struct nhr_mft_entry *mfte,
				const char *filename)
{
	struct nhr_mfte_fn *efn = ntfs_name_is_dos_compatible(filename) ?
				  &mfte->names[NTFS_FNAME_T_WIN32DOS] :
				  &mfte->names[NTFS_FNAME_T_WIN32];

	if (efn->src >= NHR_SRC_HINT)
		return;

	free(efn->name);
	efn->len = strlen(filename);
	efn->name = malloc(efn->len * 2);
	str2utf16(filename, efn->name);
	efn->src = NHR_SRC_HINT;
}

/**
 * Recover item MFT entry data using hints
 */
static void mft_hints2meta_mfte(struct nhr_mft_entry *mfte,
				struct hint_entry *he)
{
	struct hint *h;
	uint16_t val16;
	uint32_t val32;
	uint64_t val64;

	list_for_each_entry(h, &he->hints, list) {
		if (h->class < HINT_META)
			continue;
		if (h->class > HINT_META)
			break;
		switch (h->type) {
		case HINT_META_FILENAME:
			mft_hints2meta_name(mfte, (char *)h->data);
			mfte->f_cmn |= NHR_MFT_FC_BASE;
			break;
		case HINT_META_PARENT:
			memcpy(&val64, h->data, sizeof(val64));
			NHR_FIELD_UPDATE(&mfte->parent, val64, NHR_SRC_HINT);
			mfte->f_cmn |= NHR_MFT_FC_BASE;
			break;
		case HINT_META_ENTSEQNO:
			memcpy(&val16, h->data, sizeof(val16));
			NHR_FIELD_UPDATE(&mfte->seqno, val16, NHR_SRC_HINT);
			break;
		case HINT_META_TIME_CREATE:
			memcpy(&val64, h->data, sizeof(val64));
			NHR_FIELD_UPDATE(&mfte->time_create, val64,
					 NHR_SRC_HINT);
			break;
		case HINT_META_TIME_CHANGE:
			memcpy(&val64, h->data, sizeof(val64));
			NHR_FIELD_UPDATE(&mfte->time_change, val64,
					 NHR_SRC_HINT);
			break;
		case HINT_META_TIME_MFT:
			memcpy(&val64, h->data, sizeof(val64));
			NHR_FIELD_UPDATE(&mfte->time_mft, val64, NHR_SRC_HINT);
			break;
		case HINT_META_TIME_ACCESS:
			memcpy(&val64, h->data, sizeof(val64));
			NHR_FIELD_UPDATE(&mfte->time_access, val64,
					 NHR_SRC_HINT);
			break;
		case HINT_META_FILEFLAGS:
			memcpy(&val32, h->data, sizeof(val32));
			cache_mfte_fileflags_upd(mfte, val32, NHR_SRC_HINT);
			break;
		case HINT_META_SID:
			memcpy(&val32, h->data, sizeof(val32));
			NHR_FIELD_UPDATE(&mfte->sid, val32, NHR_SRC_HINT);
			break;
		}
	}
}

/**
 * Recover MFT entry metadata using hints
 */
void mft_hints2meta(void)
{
	struct hint_entry *he;
	struct nhr_mft_entry *mfte;

	rbt_inorder_walk_entry(he, &nhr.hints, tree) {
		if (!hints_have_class(he, HINT_META))
			continue;
		mfte = cache_mfte_find(hint_entry_num(he));
		if (!mfte)
			continue;

		mft_hints2meta_mfte(mfte, he);
	}
}

static int mft_gen_dosname(struct nhr_mft_entry *mfte,
			   struct nhr_mft_entry *pmfte)
{
	struct nhr_mfte_fn *efn;
	unsigned i;
	char winname[256];
	const char *dosname;
	uint8_t dosfn_buf[sizeof(struct ntfs_attr_fname) + 255 * sizeof(uint16_t)];
	struct ntfs_attr_fname *dosfn = (void *)dosfn_buf;
	struct nhr_idx *idx = cache_idx_find(pmfte, NHR_IDX_T_DIR);
	struct nhr_idx_entry *idxe;

	/* TODO: this is ugly :( all code should be reworked to use UTF8 or UTF16 */
	efn = &mfte->names[NTFS_FNAME_T_WIN32];
	for (i = 0; i < efn->len; ++i) {
		winname[i] = efn->name[2 * i];
	}
	winname[i] = '\0';

	if (nhr.verbose >= 3)
		printf("mft[#%"PRIu64"]: gen DOS name for %s\n", nhr_mfte_num(mfte), winname);

	/* This is simple method, which IMHO cover ~80% cases */
	memset(dosfn, 0x00, sizeof(*dosfn));
	for (i = 1; i < 10; ++i) {
		dosname = ntfs_make_dos_name(winname, i);
		dosfn->name_len = strlen(dosname);
		str2utf16(dosname, dosfn->name);
		if (!idx) {	/* Dirty hack, actually we should skip generation */
			idxe = NULL;
			break;
		}
		idxe = cache_idxe_find(idx, dosfn);
		if (!idxe)
			break;
		if (idxe->data)
			assert(NTFS_MREF_ENTNUM(*(uint64_t *)idxe->data) != nhr_mfte_num(mfte));
	}
	if (idxe) {
		if (nhr.verbose >= 1)
			printf("mft[#%"PRIu64"]: could not generate unique DOS name\n",
			       nhr_mfte_num(mfte));
		return -1;
	}

	efn = &mfte->names[NTFS_FNAME_T_DOS];
	efn->len = dosfn->name_len;
	efn->name = malloc(dosfn->name_len * 2);
	memcpy(efn->name, dosfn->name, dosfn->name_len * 2);
	efn->src = NHR_SRC_HEUR;

	return 0;
}

/**
 * Regenerate DOS names for entries, which miss it
 */
void mft_gen_dosnames(void)
{
	struct nhr_mft_entry *mfte, *pmfte;
	unsigned cnt_tot = 0, cnt_ok = 0;

	if (nhr.verbose >= 1)
		printf("mft: regenerate DOS names\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (mfte->names[NTFS_FNAME_T_WIN32].src == NHR_SRC_NONE)
			continue;
		if (mfte->names[NTFS_FNAME_T_DOS].src != NHR_SRC_NONE)
			continue;
		cnt_tot++;
		if (!NHR_FIELD_VALID(&mfte->parent)) {
			fprintf(stderr, "mft[#%"PRIu64"]: could not generate DOS name, since parent is unknown\n",
				nhr_mfte_num(mfte));
			continue;
		}
		pmfte = cache_mfte_find(mfte->parent.val);
		if (!pmfte) {
			fprintf(stderr, "mft[#%"PRIu64"]: could not generate DOS name, since no parent entry #%"PRIu64" found in cache\n",
				nhr_mfte_num(mfte), mfte->parent.val);
			continue;
		}
		if (mft_gen_dosname(mfte, pmfte) == 0)
			cnt_ok++;
	}

	if (nhr.verbose >= 1)
		printf("mft: processed %u entries, regenerate DOS names for %u of them\n",
		       cnt_tot, cnt_ok);
}

/** Bind attributes to entities of item MFT entry */
static int mft_attr_bind_mfte(struct nhr_mft_entry *mfte)
{
	struct nhr_alist_item *ali;
	const struct nhr_attr_info *ai;
	int res;

	list_for_each_entry(ali, &mfte->alist, list) {
		if (ali->entity)
			continue;
		ai = attr_get_info(ali->type);
		if (!ai) {
			if (nhr.verbose >= 3)
				printf("mft[#%"PRIu64"]: unknown attribute 0x%02X\n",
				       nhr_mfte_num(mfte), ali->type);
			continue;
		}
		if (ai->flags & NHR_ATTR_F_UNIQ)
			continue;
		res = ai->entity_bind(mfte, ali);
		if (res && nhr.verbose >= 3)
			printf("mft[#%"PRIu64"]: attribute 0x%02X %u %ls bind failure\n",
			       nhr_mfte_num(mfte), ali->type, ali->id,
			       cache_attr_name(ali));
	}

	return 0;
}

void mft_attr_bind(void)
{
	struct nhr_mft_entry *mfte;

	if (nhr.verbose >= 1)
		printf("mft: bind attributes\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(mfte->f_cmn & NHR_MFT_FC_BASE))
			continue;
		if (!mfte->f_sum)	/* Ignore valid (and recovered) entries */
			continue;
		mft_attr_bind_mfte(mfte);
	}

	if (nhr.verbose >= 1)
		printf("mft: attributes binding done\n");
}

/**
 * Regenerate attribute list for item base file MFT entry
 *
 * This function emulates MFT entry atttributes life: initial creation, deletion
 * and recreation in the same order as that happen with real MFT entry.
 */
static int mft_attr_recover_file_base(struct nhr_mft_entry *mfte)
{
	struct nhr_data *data = cache_data_find(mfte, 0, NULL);
	struct nhr_alist_item *ali;
	struct nhr_str_segm *segm;
	unsigned id = 0, i;

	assert(data);

	/* Add $STANDARD_INFO attribute */
	ali = cache_attr_alloc(mfte, NTFS_ATTR_STDINF, 0, NULL, 0);
	ali->src = NHR_SRC_HEUR;
	ali->id = id++;

	/**
	 * Add resident $DATA attribute
	 *
	 * We really create attribute here only if data stream is resident,
	 * otherwise just skip id and add attribute later.
	 */
	if (data->sz_alloc.val < nhr.vol.cls_sz) {
		ali = cache_attr_alloc(mfte, NTFS_ATTR_DATA, 0, NULL, 0);
		ali->src = NHR_SRC_HEUR;
		ali->id = id++;
		ali->entity = data;
	} else {
		id++;	/* Just skip id */
	}

	/* Add $FILE_NAME attribute(s) */
	for (i = 0; i < sizeof(mfte->names)/sizeof(mfte->names[0]); ++i) {
		if (mfte->names[i].src == NHR_SRC_NONE)
			continue;
		ali = cache_attr_alloc(mfte, NTFS_ATTR_FNAME, 0, NULL, 0);
		ali->src = NHR_SRC_HEUR;
		ali->id = id++;
		ali->entity = &mfte->names[i];
	}

	/* Add non-resident $DATA attribute */
	if (data->sz_alloc.val >= nhr.vol.cls_sz) {
		segm = cache_data_segm_orph(data);
		if (segm) {
			ali = cache_attr_alloc(mfte, NTFS_ATTR_DATA, 0, NULL, 0);
			ali->src = NHR_SRC_HEUR;
			ali->id = id++;
			ali->firstvcn = segm->firstvcn.val;
			ali->entity = data;
			segm->ali = ali;
		} else {
			id++;	/* Consume id in any case */
		}
	}

	/* Add $OBJECT_ID attribute */
	if (mfte->oid_src != NHR_SRC_NONE) {
		ali = cache_attr_alloc(mfte, NTFS_ATTR_OID, 0, NULL, 0);
		ali->src = NHR_SRC_HEUR;
		ali->id = id++;
	}

	/* Add $ATTRIBUTES_LIST attribute */
	if (!list_empty(&mfte->ext)) {
		ali = cache_attr_alloc(mfte, NTFS_ATTR_ALIST, 0, NULL, 0);
		ali->src = NHR_SRC_HEUR;
		ali->id = id++;
	}

	return 0;
}

/**
 * Regenerate attribute list for item base dir MFT entry
 */
static int mft_attr_recover_dir_base(struct nhr_mft_entry *mfte)
{
	const struct nhr_idx_info *iinfo = idx_info_get(NHR_IDX_T_DIR);
	struct nhr_idx *idx = cache_idx_find(mfte, NHR_IDX_T_DIR);
	struct nhr_alist_item *ali;
	unsigned id = 0, i;

	assert(idx && iinfo);

	/* Add $STANDARD_INFO attribute */
	ali = cache_attr_alloc(mfte, NTFS_ATTR_STDINF, 0, NULL, 0);
	ali->src = NHR_SRC_HEUR;
	ali->id = id++;

	/* Add $INDEX_ROOT attribute */
	ali = cache_attr_alloc(mfte, NTFS_ATTR_IROOT, iinfo->name_len,
			       iinfo->name, 0);
	ali->src = NHR_SRC_HEUR;
	ali->id = id++;
	ali->entity = idx;

	/* Add $FILE_NAME attribute(s) */
	for (i = 0; i < sizeof(mfte->names)/sizeof(mfte->names[0]); ++i) {
		if (mfte->names[i].src == NHR_SRC_NONE)
			continue;
		ali = cache_attr_alloc(mfte, NTFS_ATTR_FNAME, 0, NULL, 0);
		ali->src = NHR_SRC_HEUR;
		ali->id = id++;
		ali->entity = &mfte->names[i];
	}

	if (!(idx->root->flags & NHR_IDXN_F_LEAF)) {
		/* Add $INDEX_ALLOCATION attribute */
		ali = cache_attr_alloc(mfte, NTFS_ATTR_IALLOC, iinfo->name_len,
				       iinfo->name, 0);
		ali->src = NHR_SRC_HEUR;
		ali->id = id++;
		ali->entity = idx;

		/* Add $BITMAP attribute */
		ali = cache_attr_alloc(mfte, NTFS_ATTR_BITMAP, iinfo->name_len,
				       iinfo->name, 0);
		ali->src = NHR_SRC_HEUR;
		ali->id = id++;
		ali->entity = idx;

		/* Emulate $INDEX_ROOT recreation */
		list_for_each_entry(ali, &mfte->alist, list) {
			if (ali->type == NTFS_ATTR_IROOT) {
				ali->id = id++;
				break;
			}
		}
	}

	/* Add $OBJECT_ID attribute */
	if (mfte->oid_src != NHR_SRC_NONE) {
		ali = cache_attr_alloc(mfte, NTFS_ATTR_OID, 0, NULL, 0);
		ali->src = NHR_SRC_HEUR;
		ali->id = id++;
	}

	return 0;
}

/* Apply attribute hints */
static void mft_attr_apply_hints(struct nhr_mft_entry *mfte)
{
	struct nhr_mft_entry *bmfte = mfte->bmfte;
	struct hint_entry *he = hints_find_entry(nhr_mfte_num(mfte));
	struct hint *h;
	struct hint_cargs_attr *hca;
	struct nhr_alist_item *ali, *__ali;
	long sel;
	uint16_t val16;

	if (!he || !hints_have_class(he, HINT_ATTR))
		return;

	list_for_each_entry(h, &he->hints, list) {
		/* Select hints class */
		if (h->class < HINT_ATTR)
			continue;
		if (h->class > HINT_ATTR)
			break;
		/* Search referenced attribute */
		hca = h->cargs;
		ali = NULL;
		list_for_each_entry(__ali, &bmfte->alist, list) {
			if (__ali->type < hca->type)
				continue;
			if (__ali->type > hca->type)
				break;
			if (__ali->mfte != mfte)
				continue;
			if (__ali->name_len != hca->name_len)
				continue;
			if (memcmp(__ali->name, hca->name, hca->name_len) != 0)
				continue;
			/* Hack for $FILE_NAME attribute selection */
			if (hca->type == NTFS_ATTR_FNAME && hca->sel != LONG_MAX) {
				sel = __ali->entity - (void *)&bmfte->names[0];
				sel/= sizeof(bmfte->names[0]);
				if (sel != hca->sel)
					continue;
			}
			ali = __ali;
			break;
		}
		if (!ali)
			continue;
		/* Apply hint */
		switch (h->type) {
		case HINT_ATTR_ID:
			memcpy(&val16, h->data, sizeof(val16));
			ali->id = val16;
			break;
		}
	}
}

/**
 * Regenerate attributes list
 */
void mft_attr_recover(void)
{
	struct nhr_mft_entry *mfte;
	struct nhr_data *data;
	struct nhr_idx *idx;
	unsigned cnt_tot = 0, cnt_try = 0, cnt_ok = 0;
	int res;

	if (nhr.verbose >= 1)
		printf("mft: regenerate attributes list\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(nhr_mfte_bflags(mfte) & NHR_MFT_FB_SELF))	/* Ignore anything other than broken MFT entries */
			continue;
		if (mfte->f_cmn & NHR_MFT_FC_FREE)
			continue;
		if (!(mfte->f_cmn & NHR_MFT_FC_BASE))	/* Ignore anything other than base entries */
			continue;
		cnt_tot++;
		if (cache_mfte_attrs_num(mfte))		/* Ignore entries, which have attrs */
			continue;
		if (mfte->f_cmn & NHR_MFT_FC_FILE) {
			/* Get default data stream */
			data = cache_data_find(mfte, 0, NULL);
			if (!data)
				continue;
			if (!(data->flags & NHR_DATA_F_VALID))
				continue;
		} else if (mfte->f_cmn & NHR_MFT_FC_DIR) {
			/* Get default ($I30) index */
			idx = cache_idx_find(mfte, NHR_IDX_T_DIR);
			if (!idx)
				continue;
			if (!(idx->flags & NHR_IDX_F_VALID))
				continue;
		} else {
			continue;
		}
		cnt_try++;

		if (mfte->f_cmn & NHR_MFT_FC_FILE)
			res = mft_attr_recover_file_base(mfte);
		else if (mfte->f_cmn & NHR_MFT_FC_DIR)
			res = mft_attr_recover_dir_base(mfte);
		else
			res = EINVAL;

		if (!res) {
			mft_attr_apply_hints(mfte);
			cnt_ok++;
		}
	}

	if (nhr.verbose >= 1)
		printf("mft: checked %u broken entries: %u of %u matched entries are regenerated\n",
		       cnt_tot, cnt_ok, cnt_try);
}

/**
 * Create overlay from data generated during MFT entry rebuild
 */
static void mft_recover_create_overlay(struct nhr_mft_entry *mfte,
				       off_t ent_off, const uint8_t *rec_buf)
{
	const unsigned mft_ent_ssz = nhr.vol.mft_ent_sz / nhr.vol.sec_sz;
	unsigned i, voff;
	struct nhr_bb *bb;
	struct nhr_ob *ob;

	for (i = 0; i < mft_ent_ssz; ++i) {
		if (!(mfte->bb_map & (1 << i)))
			continue;
		voff = i * nhr.vol.sec_sz;
		bb = bb_find(ent_off + voff);
		assert(bb);

		ob = img_overlay_alloc(nhr.vol.sec_sz);
		nhr_ob_off(ob) = nhr_bb_off(bb);
		memcpy(ob->buf, rec_buf + voff, nhr.vol.sec_sz);
		img_overlay_add(ob);

		bb->flags |= NHR_BB_F_REC;
		mfte->bb_rec |= 1 << i;
		cache_mfte_bb_ok(bb);
	}
}

/**
 * Build MFT entry as we image it
 */
static int mft_recover_build_entry(const struct nhr_mft_entry *mfte,
				   uint64_t lsn, uint16_t usn, void *buf)
{
	const struct nhr_mft_entry *bmfte = mfte->bmfte;
	const struct nhr_alist_item *ali;
	const struct nhr_attr_info *ai;
	int size = nhr.vol.mft_ent_sz;
	struct ntfs_mft_entry *ent = buf;
	struct ntfs_mft_entry_ext *ente = buf;
	struct ntfs_attr_hdr *attr;
	struct ntfs_usa *usa;
	uint16_t *usa_ptr;
	unsigned i;
	int res;

	/**
	 * MFT entry layout:
	 *  - entry header
	 *  - USA (update sequence array)
	 *  - attribute 1
	 *  - attribute 2
	 *  ...
	 *  - attribute N (the END attribute)
	 */

	/* MFT entry header */
	memcpy(ent->r.magic, "FILE", 4);
	ent->r.usa_off = NTFS_ALIGN(sizeof(*ent));
	ent->r.usa_len = nhr.vol.mft_ent_sz / nhr.vol.sec_sz + 1;
	ent->lsn = lsn;
	ent->seqno = mfte->seqno.val;
	for (i = 0; i < sizeof(mfte->names)/sizeof(mfte->names[0]); ++i)
		if (mfte->names[i].src != NHR_SRC_NONE)
			ent->linksno++;
	ent->attr_off = NTFS_ALIGN(ent->r.usa_off + ntfs_usa_blen(&ent->r));
	ent->flags |= NTFS_MFT_ENTRY_F_INUSE;
	if (mfte->f_cmn & NHR_MFT_FC_DIR)
		ent->flags |= NTFS_MFT_ENTRY_F_DIR;
	ent->allocated_sz = nhr.vol.mft_ent_sz;
	if (mfte->f_cmn & NHR_MFT_FC_EXTENT) {
		ent->base = NTFS_MREF_MAKE(bmfte->seqno.val,
					   nhr_mfte_num(bmfte));
	} else {
		ent->base = 0;
	}
	ent->attr_next_id = cache_alist_maxid(mfte) + 1;
	ente->entnumlo = nhr_mfte_num(mfte) & 0xffffffff;

	/* Reconstruct attributes */
	attr = buf + ent->attr_off;
	size -= ent->attr_off;
	list_for_each_entry(ali, &bmfte->alist, list) {
		if (ali->mfte != mfte)
			continue;

		ai = attr_get_info(ali->type);
		assert(ai);
		assert(ai->recover_data);

		if (size < NTFS_ATTR_HDR_COMMON_LEN)
			goto err_nofreespace;

		attr->type = ali->type;
		attr->nonresident = 0;
		attr->size = 0;
		attr->name_len = ali->name_len;
		attr->name_off = 0;
		attr->flags = 0;
		attr->id = ali->id;

		if (ai->recover_hdr) {
			res = ai->recover_hdr(mfte, ali, attr);
			if (res < 0) {
				fprintf(stderr, "mft[#%"PRIu64"]: attribute 0x%02X pre-build failed\n",
					nhr_mfte_num(mfte), attr->type);
				return res;
			}
		}

		if (attr->nonresident) {
			if (size < NTFS_ATTR_HDR_NONRESIDENT_LEN)
				goto err_nofreespace;
			attr->mp_off = NTFS_ALIGN(NTFS_ATTR_HDR_NONRESIDENT_LEN);
			if (!(attr->flags & NTFS_ATTR_F_COMP) ||
			    attr->firstvcn != 0)
				attr->mp_off-= sizeof(attr->comp_sz);
			if (attr->name_len) {
				attr->name_off = attr->mp_off;
				attr->mp_off+= NTFS_ALIGN(attr->name_len * 2);
			}
			size -= attr->mp_off;
			if (size < 0)
				goto err_nofreespace;
		} else {
			if (size < NTFS_ATTR_HDR_RESIDENT_LEN)
				goto err_nofreespace;
			attr->data_off = NTFS_ALIGN(NTFS_ATTR_HDR_RESIDENT_LEN);
			if (attr->name_len) {
				attr->name_off = attr->data_off;
				attr->data_off+= NTFS_ALIGN(attr->name_len * 2);
			}
			size -= attr->data_off;
			if (size < 0)
				goto err_nofreespace;
		}

		memcpy(NTFS_ATTR_NAME(attr), ali->name, ali->name_len * 2);

		res = ai->recover_data(mfte, ali, attr, size);
		if (res < 0) {
			fprintf(stderr, "mft[#%"PRIu64"]: could not recover 0x%02X attribute\n",
				nhr_mfte_num(mfte), ali->type);
			return res;
		}

		if (attr->nonresident) {
			attr->size = NTFS_ALIGN(attr->mp_off + res);
		} else {
			attr->data_sz = res;
			attr->size = NTFS_ALIGN(attr->data_off + res);
		}

		size -= NTFS_ALIGN(res);
		attr = (void *)attr + attr->size;
	}

	if (size < NTFS_ATTR_HDR_MIN_LEN)
		goto err_nofreespace;

	/* Write END attribute */
	attr->type = NTFS_ATTR_END;
	attr->size = 0x11477982;	/* Some magic size value */
	attr = (void *)attr + NTFS_ATTR_HDR_MIN_LEN;

	/* Calculate final attribute length */
	ent->used_sz = (void *)attr - buf;

	/* Reconstruct USA */
	usa = ntfs_usa_ptr(&ent->r);
	usa->usn = usn;
	for (i = 0; i < nhr.vol.mft_ent_sz/nhr.vol.sec_sz; ++i) {
		usa_ptr = buf + (i + 1) * nhr.vol.sec_sz - sizeof(uint16_t);
		usa->sec[i] = *usa_ptr;
		*usa_ptr = usa->usn;
	}

	return 0;

err_nofreespace:
	printf("mft[#%"PRIu64"]: no space left for MFT entry content writing\n",
	       nhr_mfte_num(mfte));

	return -1;
}

/**
 * Recover item MFT entry
 */
static int mft_recover_entry(struct nhr_mft_entry *mfte)
{
	const unsigned mft_ent_ssz = nhr.vol.mft_ent_sz / nhr.vol.sec_sz;
	const unsigned bb_map_mask = ~(~0 << mft_ent_ssz);
	uint8_t buf_rec[nhr.vol.mft_ent_sz];
	uint8_t buf_img[nhr.vol.mft_ent_sz];
	const struct ntfs_mft_entry *ent = (void *)buf_img;
	off_t ent_off;
	uint64_t lsn;
	uint16_t usn;
	int i, res;

	if (mft_entry_read(nhr_mfte_num(mfte), buf_img, &ent_off) != 0)
		return -1;

	/* Attempt to fetch some non-critical data */
	if ((mfte->bb_map & bb_map_mask) == bb_map_mask) {
		lsn = 1;
		usn = 0xCDAB;
	} else if (mfte->bb_map & 1) {
		lsn = 1;
		usn = 0xCDAB;
		for (i = 0; i < mft_ent_ssz; ++i) {
			if (mfte->bb_map & (1 << i))
				continue;
			usn = *(uint16_t *)(buf_img + (i + 1) * nhr.vol.sec_sz - sizeof(uint16_t));
			break;
		}
	} else {
		lsn = ent->lsn;
		usn = *(uint16_t *)(buf_img + ent->r.usa_off);
	}

	/* Rebuild MFT entry */
	memset(buf_rec, 0x00, sizeof(buf_rec));
	res = mft_recover_build_entry(mfte, lsn, usn, buf_rec);
	if (res)
		return -1;

	/* Verify rebuilded entry against valid on disk data */
	if (mft_entry_cmp(buf_img, buf_rec, mfte->bb_map)) {
		if (nhr.verbose >= 2) {
			printf("mft[#%"PRIu64"]: compare with on disk data failed\n",
			       nhr_mfte_num(mfte));
			printf("mft[#%"PRIu64"]: on disk data hexdump:\n",
			       nhr_mfte_num(mfte));
			hexdump(buf_img, sizeof(buf_img));
			printf("mft[#%"PRIu64"]: recovery buffer data:\n",
			       nhr_mfte_num(mfte));
			hexdump(buf_rec, sizeof(buf_rec));
		}
		return -1;
	}

	mft_recover_create_overlay(mfte, ent_off, buf_rec);

	return 0;
}

/** Checks whether attributes Ok for MFT entry regeneration or no */
static int mft_recover_check_attrs(const struct nhr_mft_entry *mfte)
{
	const struct nhr_mft_entry *bmfte = mfte->bmfte;
	const struct nhr_alist_item *ali;
	const struct nhr_attr_info *ai;
	unsigned cnt = 0;

	/* Check each attribute recoverability */
	list_for_each_entry(ali, &mfte->bmfte->alist, list) {
		if (ali->mfte != mfte)
			continue;
		cnt++;
		ai = attr_get_info(ali->type);
		if (ai->recover_prerequisite(bmfte, ali) != 0) {
			if (nhr.verbose >= 3)
				printf("mft[#%"PRIu64"]: attribute 0x%02X could not be recovered\n",
				       nhr_mfte_num(mfte), ali->type);
			return -1;
		}
	}

	if (cnt == 0) {
		if (nhr.verbose >= 3)
			printf("mft[#%"PRIu64"]: entry does not have assigned attributes\n",
			       nhr_mfte_num(mfte));
		return -1;
	}

	return 0;
}

void mft_recover_entries(void)
{
	struct nhr_mft_entry *mfte;
	unsigned cnt_tot = 0, cnt_ok = 0;
	int res;

	if (nhr.verbose >= 1)
		printf("mft: recover corrupted entries\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(nhr_mfte_bflags(mfte) & NHR_MFT_FB_SELF))	/* Ignore anything other than broken MFT entries */
			continue;
		if (mfte->f_cmn & NHR_MFT_FC_FREE)		/* Ignore free entries */
			continue;
		cnt_tot++;
		if ((mfte->f_cmn & NHR_MFT_FC_FDI_MASK) == 0) {
			if (nhr.verbose >= 2)
				printf("mft[#%"PRIu64"]: entry type (file/dir/idx) is unknown, skip it\n",
				       nhr_mfte_num(mfte));
			continue;
		}
		if (mfte->f_cmn & NHR_MFT_FC_IDX) {
			if (nhr.verbose >= 2)
				printf("mft[#%"PRIu64"]: view index entries regeneration not yet supported\n",
				       nhr_mfte_num(mfte));
			continue;
		}
		if ((mfte->f_cmn & NHR_MFT_FC_BASEEXT_MASK) == 0) {
			if (nhr.verbose >= 2)
				printf("mft[#%"PRIu64"]: entry type (base/ext) is unknown, skip it\n",
				       nhr_mfte_num(mfte));
			continue;
		}
		if (!mfte->bmfte->names_valid) {
			if (nhr.verbose >= 2)
				printf("mft[#%"PRIu64"]: filenames set invalid\n",
				       nhr_mfte_num(mfte));
			continue;
		}
		if (mfte->f_cmn & NHR_MFT_FC_FILE &&
		    cache_data_find(mfte, 0, NULL) == NULL) {
			if (nhr.verbose >= 2)
				printf("mft[#%"PRIu64"]: default data stream missed\n",
				       nhr_mfte_num(mfte));
			continue;
		}
		if (mfte->f_cmn & NHR_MFT_FC_DIR &&
		    cache_idx_find(mfte, NHR_IDX_T_DIR) == NULL) {
			if (nhr.verbose >= 2)
				printf("mft[#%"PRIu64"]: directory index ($I30) missed\n",
				       nhr_mfte_num(mfte));
			continue;
		}
		if (!NHR_FIELD_VALID(&mfte->seqno)) {
			if (nhr.verbose >= 2)
				printf("mft[#%"PRIu64"]: seqno is unknown, skip entry\n",
				       nhr_mfte_num(mfte));
			continue;
		}
		if (!mfte->bmfte->alist_valid) {
			if (nhr.verbose >= 2)
				printf("mft[#%"PRIu64"]: attributes list is not valid, skip entry\n",
				       nhr_mfte_num(mfte));
			continue;
		}
		res = mft_recover_check_attrs(mfte);
		if (res) {
			if (nhr.verbose >= 2)
				printf("mft[#%"PRIu64"]: attributes check failed, skip entry\n",
				       nhr_mfte_num(mfte));
			continue;
		}

		res = mft_recover_entry(mfte);
		if (!res) {
			cnt_ok++;
			cache_mfte_frec_set(mfte, NHR_MFT_FB_SELF);
		}
	}

	if (nhr.verbose >= 1)
		printf("mft: processed %u entries, %u of them are recovered\n",
		       cnt_tot, cnt_ok);
}
