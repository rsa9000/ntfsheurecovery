/**
 * NTFS library interface and declarations
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

#ifndef _NTFS_H_
#define _NTFS_H_

#include <time.h>

#include "ntfs_struct.h"

/* Generic NTFS volume information */
struct ntfs_volume {
	unsigned sec_sz;	/* Sector size, bytes */
	unsigned cls_ssz;	/* Cluster size, sectors */
	unsigned cls_sz;	/* Cluster size, bytes */
	uint64_t sec_num;	/* Sectors number */
	uint64_t cls_num;	/* Clusters number */
	uint64_t mft_lcn;	/* MFT first cluster */
	uint64_t mft_sz;	/* Total MFT size, bytes */
	unsigned mft_ent_sz;	/* MFT entry size, bytes */
	unsigned idx_blk_sz;	/* Index record size, bytes */
	unsigned idx_blk_csz;	/* Index record size, clusters */
	unsigned com_blk_sz;	/* Compression block size */
};

#define NTFS_MP_NEXT(__mph)						\
		((struct ntfs_mp_hdr *)((void *)(__mph) +		\
					sizeof(struct ntfs_mp_hdr) +	\
					(__mph)->mp_len_sz +		\
					(__mph)->mp_off_sz))

/* No LCN mark (special value) */
#define NTFS_LCN_NONE		(-1LLU)

/**
 * Non-resident attribute in memory mapping pair descriptor
 */
struct ntfs_mp {
	uint64_t vcn;		/* MP virtual cluster number */
	uint64_t lcn;		/* MP logical (no disk) cluster number */
	uint64_t clen;		/* MP length, in clusters */
};

/**
 * Entry's attributes index
 */
struct ntfs_attr_idx {
	const struct ntfs_attr_hdr **a;	/* Pointers to attributes */
	unsigned num;			/* Number of attributes in index */
	unsigned size;			/* Array size */
};

/**
 * Some fields store size in encoded form:
 * field = size >= sizeof(cluster) ? size / sizeof(cluster) : -log2(sz)
 * so if you need take size in bytes back, than you should do:
 * size = field > 0 ? field * sizeof(cluster) : 2 ^ -field;
 */
static inline unsigned ntfs_sz_decode(int sz, unsigned cluster_sz)
{
	return sz > 0 ? sz * cluster_sz : 1 << -sz;
}

/**
 * Convert NTFS timestamp to UNIX timestamp
 */
static inline time_t ntfs_time2ts(const uint64_t time)
{
	return time / NTFS_TICKS_PER_SEC - 11644488000;
}

int ntfs_mpl_has_unmapped(const struct ntfs_mp *mpl);
int ntfs_mpl_has_gap(const struct ntfs_mp *mpl);
uint64_t ntfs_mpl_vclen(const struct ntfs_mp *mpl);
uint64_t ntfs_mpl_lclen(const struct ntfs_mp *mpl);
unsigned ntfs_mpl_len(const struct ntfs_mp *mpl);
struct ntfs_mp *ntfs_mpl_merge(struct ntfs_mp *dst, const struct ntfs_mp *src);
struct ntfs_mp *ntfs_mpl_extr(struct ntfs_mp *src, uint64_t firstvcn,
			      uint64_t lastvcn);
struct ntfs_mp *ntfs_mpl_find(struct ntfs_mp *mpl, unsigned mpl_sz,
			      uint64_t vcn);
uint64_t ntfs_mpl_voff2off(struct ntfs_mp *mpl, unsigned cls_sz, uint64_t voff);
int ntfs_mpl_pack(const struct ntfs_mp *mpl, void *buf);
int ntfs_mpl_packed_len(const struct ntfs_mp *mpl);
struct ntfs_mp *ntfs_attr_mp_unpack(const struct ntfs_attr_hdr *attr);
int ntfs_attr_mp_len(const struct ntfs_attr_hdr *attr);
int ntfs_mft_aidx_get(const struct ntfs_mft_entry *ent,
		      struct ntfs_attr_idx *aidx);
void ntfs_mft_aidx_clean(struct ntfs_attr_idx *aidx);

/* Returns USA length in bytes */
static inline int ntfs_usa_blen(const struct ntfs_record *r)
{
	return r->usa_len * sizeof(uint16_t);
}

/* Return pointer to USA */
static inline struct ntfs_usa *ntfs_usa_ptr(struct ntfs_record *r)
{
	return (void *)r + r->usa_off;
}

int ntfs_usa_apply(void *buf, size_t buf_sz, unsigned sec_sz);

char *ntfs_guid2str_r(const struct ntfs_guid *guid,
		      char buf[NTFS_GUID_STR_LEN + 1]);
const char *ntfs_guid2str(const struct ntfs_guid *guid);
int ntfs_name_is_dos_compatible(const char *name);
const char *ntfs_make_dos_name(const char *name, int idx);
int ntfs_name_cmp(const uint16_t *n1, unsigned n1_len,
		  const uint16_t *n2, unsigned n2_len,
		  const uint16_t *upcase, unsigned upcase_sz);
char *ntfs_sid2str(const struct ntfs_sec_sid *sid);
uint32_t ntfs_sec_desc_hash(const void *buf, int len);

#endif
