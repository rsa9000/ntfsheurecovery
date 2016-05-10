/**
 * $Secure file indexes operations
 *
 * Copyright (c) 2016, Sergey Ryazanov <ryazanov.s.a@gmail.com>
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
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ntfsheurecovery.h"
#include "cache.h"
#include "secure.h"
#include "cmask.h"
#include "ntfs_struct.h"
#include "idx_secure.h"

int idx_sdh_key_cmp(const void *k1, const void *k2)
{
	const struct ntfs_idx_sdh_key *key1 = k1;
	const struct ntfs_idx_sdh_key *key2 = k2;

	if (key1->hash < key2->hash)
		return -1;
	if (key1->hash > key2->hash)
		return 1;
	if (key1->id < key2->id)
		return -1;
	if (key1->id > key2->id)
		return 1;

	return 0;
}

const wchar_t *idx_sdh_entry_name(const struct nhr_idx_entry *idxe)
{
#define NAME_BUF_LEN	24
	static wchar_t buf[NAME_BUF_LEN];
	const struct ntfs_idx_sdh_key *ksdh = idxe->key;

	swprintf(buf, NAME_BUF_LEN, L"0x%08X:%u", ksdh->hash, ksdh->id);

	return buf;
#undef NAME_BUF_LEN
}

int idx_sdh_entry_validate(const struct ntfs_idx_entry_hdr *ieh)
{
	struct ntfs_idx_sdh_key *ksdh = (void *)ieh->key;
	struct ntfs_sec_desc_hdr *sdh = ntfs_idx_entry_data(ieh);

	/* Verify key & data consistency */
	if (ksdh->hash != sdh->hash || ksdh->id != sdh->id || !sdh->id)
		return 0;

	return 1;
}

/** Search cached index entry using corrupted index entry */
struct nhr_idx_entry *idx_sdh_cache_idxe_find(const struct nhr_idx *idx,
					      const struct ntfs_idx_entry_hdr *ieh,
					      unsigned len)
{
	struct ntfs_idx_sdh_key *ksdh = (void *)ieh->key;

	if (sizeof(*ieh) + sizeof(*ksdh) > len)	/* Is key corrupted? */
		return NULL;

	return cache_idxe_find(idx, ksdh);
}

int idx_sii_key_cmp(const void *k1, const void *k2)
{
	const struct ntfs_idx_sii_key *key1 = k1;
	const struct ntfs_idx_sii_key *key2 = k2;

	if (key1->id < key2->id)
		return -1;
	if (key1->id > key2->id)
		return 1;

	return 0;
}

const wchar_t *idx_sii_entry_name(const struct nhr_idx_entry *idxe)
{
#define NAME_BUF_LEN	16
	static wchar_t buf[NAME_BUF_LEN];
	const struct ntfs_idx_sii_key *ksii = idxe->key;

	swprintf(buf, NAME_BUF_LEN, L"%u", ksii->id);

	return buf;
#undef NAME_BUF_LEN
}

int idx_sii_entry_validate(const struct ntfs_idx_entry_hdr *ieh)
{
	struct ntfs_idx_sii_key *ksii = (void *)ieh->key;
	struct ntfs_sec_desc_hdr *sdh = ntfs_idx_entry_data(ieh);

	/* Verify key & data consistency */
	if (ksii->id != sdh->id || !sdh->id)
		return 0;

	return 1;
}

/** Search cached index entry using corrupted index entry */
struct nhr_idx_entry *idx_sii_cache_idxe_find(const struct nhr_idx *idx,
					      const struct ntfs_idx_entry_hdr *ieh,
					      unsigned len)
{
	struct ntfs_idx_sii_key *ksii = (void *)ieh->key;

	if (sizeof(*ieh) + sizeof(*ksii) > len)	/* Is key corrupted? */
		return NULL;

	return cache_idxe_find(idx, ksii);
}

uint64_t idx_sec_blk_mfte_detect(const struct ntfs_idx_rec_hdr *irh)
{
	return NTFS_ENTNUM_SECURE;	/* Always belongs to $Secure file */
}

struct idx_sec_sds2ent_ctx {
	struct nhr_idx *idx_sdh;
	struct nhr_idx *idx_sii;
	int cnt_desc;
};

/** Callback, which invoked for each security descriptor */
static int idx_sec_sds2ent_cb(uint64_t voff,
			      const struct ntfs_sec_desc_hdr *sdh,
			      void *priv)
{
	struct idx_sec_sds2ent_ctx *ctx = priv;

	if (sdh->id == 0)	/* Ignore empty regions */
		return 0;

	ctx->cnt_desc++;

	if (ctx->idx_sdh) {
		struct ntfs_idx_sdh_key *sdh_key = malloc(sizeof(*sdh_key));
		struct nhr_idx_entry *idxe;

		sdh_key->hash = sdh->hash;
		sdh_key->id = sdh->id;

		idxe = cache_idxe_alloc(ctx->idx_sdh, sdh_key);
		memcpy(idxe->data, sdh, sizeof(*sdh));
	}

	if (ctx->idx_sii) {
		struct ntfs_idx_sii_key *sii_key = malloc(sizeof(*sii_key));
		struct nhr_idx_entry *idxe;

		sii_key->id = sdh->id;

		idxe = cache_idxe_alloc(ctx->idx_sii, sii_key);
		memcpy(idxe->data, sdh, sizeof(*sdh));
	}

	return 0;
}

/** Process $SDS stream and generates $SDH and $SII indexes entries */
void idx_sec_sds2ent(void)
{
	static const uint8_t sds_name[] = {'$', 0, 'S', 0, 'D', 0, 'S', 0};
	struct idx_sec_sds2ent_ctx ctx;
	struct nhr_mft_entry *mfte = cache_mfte_find(NTFS_ENTNUM_SECURE);
	struct nhr_data *sds_data;
	struct nhr_cmask_elem *sds_bbmask;

	if (!mfte)	/* Entry looks Ok, so nothing to recover */
		return;

	if (nhr.verbose >= 1)
		printf("idx:sec: fill $Secure indexes from $SDS data\n");

	sds_data = cache_data_find(mfte, sizeof(sds_name)/2, sds_name);
	if (!sds_data) {
		fprintf(stderr, "idx:sec: could not find $SDS data stream\n");
		return;
	}

	if (!sds_data->mpl || sds_data->sz_used.src == NHR_SRC_NONE) {
		fprintf(stderr, "idx:sec: $SDS stream invalid\n");
		return;
	}

	sds_bbmask = cache_data_bb_gen_mask(mfte, sds_data);
	assert(sds_bbmask);

	if ((!sds_bbmask->valid || !sds_bbmask->end) && nhr.verbose >= 2)
		printf("idx:sec: $SDS stream data corrupted, index incompletness is possible\n");

	memset(&ctx, 0x00, sizeof(ctx));

	ctx.idx_sdh = cache_idx_find(mfte, NHR_IDX_T_SDH);
	ctx.idx_sii = cache_idx_find(mfte, NHR_IDX_T_SII);

	secure_sds_foreach_cb(sds_data->mpl, sds_bbmask, sds_data->sz_used.val,
			      idx_sec_sds2ent_cb, &ctx);

	cmask_free(sds_bbmask);

	if (nhr.verbose >= 1)
		printf("idx:sec: processed %d security descriptors\n",
		       ctx.cnt_desc);
}
