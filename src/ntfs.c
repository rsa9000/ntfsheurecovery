/**
 * NTFS handling library
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
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "ntfs.h"
#include "ntfs_struct.h"

/**
 * Checks whether list contains unmapped clusters
 */
int ntfs_mpl_has_unmapped(const struct ntfs_mp *mpl)
{
	for (; mpl->clen; ++mpl)
		if (mpl->lcn == NTFS_LCN_NONE)
			return 1;

	return 0;
}

/**
 * Checks whether list contains gaps
 */
int ntfs_mpl_has_gap(const struct ntfs_mp *mpl)
{
	uint64_t next_vcn = 0;

	for (; mpl->clen; ++mpl) {
		if (mpl->vcn != next_vcn)
			return 1;
		else
			next_vcn += mpl->clen;
	}

	return 0;
}

/**
 * Count total virtual clusters number in the mapping pair list
 * mpl - mapping pair list
 * Returns virtual data length (in clusters)
 */
uint64_t ntfs_mpl_vclen(const struct ntfs_mp *mpl)
{
	uint64_t sz;

	for (sz = 0; mpl->clen; ++mpl)
		sz += mpl->clen;

	return sz;
}

/**
 * Count total logical (real) clusters number in the mapping pairs list
 */
uint64_t ntfs_mpl_lclen(const struct ntfs_mp *mpl)
{
	uint64_t sz = 0;

	for (; mpl->clen; ++mpl)
		if (mpl->lcn != NTFS_LCN_NONE)
			sz += mpl->clen;

	return sz;
}

/**
 * Count number pairs in list (except end marker)
 * mpl - mapping pairs list
 * Returns pairs number
 */
unsigned ntfs_mpl_len(const struct ntfs_mp *mpl)
{
	unsigned len;

	if (!mpl)
		return 0;

	for (len = 0; mpl->clen; ++len, ++mpl);

	return len;
}

/**
 * Merge src mp list to dst
 * dst - destination list (will be reallocated)
 * src - source list
 * Return merged list or NULL if fail
 */
struct ntfs_mp *ntfs_mpl_merge(struct ntfs_mp *dst, const struct ntfs_mp *src)
{
	const unsigned dst_len = ntfs_mpl_len(dst);
	const unsigned src_len = ntfs_mpl_len(src);
	const unsigned res_len = dst_len + src_len;
	const size_t res_sz = sizeof(struct ntfs_mp) * (res_len + 1);
	unsigned dst_pos, src_pos, res_pos;
	uint64_t vcn_next;
	struct ntfs_mp *res;

	/* Handle simple cases */
	if (!dst || dst[0].clen == 0) {	/* Empty destination case */
		dst = realloc(dst, res_sz);
		memcpy(dst, src, res_sz);
		return dst;
	}
	if (src[0].clen == 0)		/* Empty source case */
		return dst;

	/* Check whether merge is possibile or not */
	dst_pos = 0;
	src_pos = 0;
	vcn_next = dst[0].vcn < src[0].vcn ? dst[0].vcn : src[0].vcn;
	for (res_pos = 0; res_pos < res_len; ++res_pos) {
		if (dst[dst_pos].clen && dst[dst_pos].vcn < vcn_next)
			return NULL;
		if (src[src_pos].clen && src[src_pos].vcn < vcn_next)
			return NULL;
		if (dst[dst_pos].vcn == src[src_pos].vcn)
			return NULL;
		if (dst[dst_pos].clen && (!src[src_pos].clen ||
					  dst[dst_pos].vcn < src[src_pos].vcn)) {
			vcn_next = dst[dst_pos].vcn + dst[dst_pos].clen;
			if (++dst_pos > dst_len)
				break;
		} else {

			vcn_next = src[src_pos].vcn + src[src_pos].clen;
			if (++src_pos > src_len)
				break;
		}
	}
	if (dst_pos != dst_len || src_pos != src_len)
		return NULL;

	/* Merge lists */
	res = malloc(res_sz);
	dst_pos = 0;
	src_pos = 0;
	for (res_pos = 0; res_pos < res_len; ++res_pos) {
		if (dst[dst_pos].clen == 0)
			memcpy(&res[res_pos], &src[src_pos++], sizeof(res[0]));
		else if (src[src_pos].clen == 0)
			memcpy(&res[res_pos], &dst[dst_pos++], sizeof(res[0]));
		else if (src[src_pos].vcn < dst[dst_pos].vcn)
			memcpy(&res[res_pos], &src[src_pos++], sizeof(res[0]));
		else
			memcpy(&res[res_pos], &dst[dst_pos++], sizeof(res[0]));
	}

	res[res_pos].vcn = 0;
	res[res_pos].lcn = 0;
	res[res_pos].clen = 0;

	/* Free original destination */
	free(dst);

	return res;
}

/**
 * Create a partial copy of mapping pairs list
 * mpl - mapping pairs list
 * firstvcn - first required vcn of sublist
 * lastvcn - last required vcn of sublist
 * Returns sublist in allocated memory or NULL
 */
struct ntfs_mp *ntfs_mpl_extr(struct ntfs_mp *mpl, uint64_t firstvcn,
			      uint64_t lastvcn)
{
	unsigned len = ntfs_mpl_len(mpl);
	struct ntfs_mp *s = ntfs_mpl_find(mpl, len, firstvcn);
	struct ntfs_mp *e = ntfs_mpl_find(mpl, len, lastvcn);
	struct ntfs_mp *res;

	if (!s || !e || s->vcn != firstvcn || e->vcn + e->clen - 1 != lastvcn)
		return NULL;

	len = e - s + 1;	/* Since they are just pointers to src mpl elements */
	res = malloc((len + 1) * sizeof(res[0]));
	memcpy(res, s, len * sizeof(res[0]));
	res[len].vcn = 0;
	res[len].lcn = 0;
	res[len].clen = 0;

	return res;
}

/**
 * Find mapping pair, which contains specified VCN
 * mpl - mapping pairs list (actually array)
 * mpl_sz - list size (in pairs)
 * vcn - needle cluster
 */
struct ntfs_mp *ntfs_mpl_find(struct ntfs_mp *mpl, unsigned mpl_sz,
			      uint64_t vcn)
{
	int l = 0, r = mpl_sz - 1, m;

	while (l <= r) {	/* Binary search */
		m = (l + r) / 2;
		if (vcn < mpl[m].vcn)
			r = m - 1;
		else if (vcn >= (mpl[m].vcn + mpl[m].clen))
			l = m + 1;
		else
			return mpl + m;
	}

	return NULL;
}

/**
 * Convert virtual offset to disk offset
 * Returns disk offset or 0xFF...FF if smth go wrong
 */
uint64_t ntfs_mpl_voff2off(struct ntfs_mp *mpl, unsigned cls_sz, uint64_t voff)
{
	unsigned mpl_len = ntfs_mpl_len(mpl);
	uint64_t vcn;
	struct ntfs_mp *mp;

	if (!mpl_len)
		return ~0ULL;

	vcn = voff / cls_sz;
	mp = ntfs_mpl_find(mpl, mpl_len, vcn);
	if (!mp)
		return ~0ULL;

	return (mp->lcn + vcn - mp->vcn) * cls_sz + voff % cls_sz;
}

/**
 * Pack mapping pairs list back to on disk format
 */
int ntfs_mpl_pack(const struct ntfs_mp *mpl, void *buf)
{
	const struct ntfs_mp *mp;
	void *p = buf;
	struct ntfs_mp_hdr *mph;
	uint64_t lcn = 0;
	int64_t off;

	for (mp = mpl; mp->clen; mp++) {
		mph = p;
		p += sizeof(*mph);
		if (mp->clen < (1LLU << 7))
			mph->mp_len_sz = 1;
		else if (mp->clen < (1LLU << 15))
			mph->mp_len_sz = 2;
		else if (mp->clen < (1LLU << 23))
			mph->mp_len_sz = 3;
		else if (mp->clen < (1ULL << 31))
			mph->mp_len_sz = 4;
		else
			assert(0);
		memcpy(p, &mp->clen, mph->mp_len_sz);
		p += mph->mp_len_sz;

		if (mp->lcn == NTFS_LCN_NONE) {
			mph->mp_off_sz = 0;
			continue;
		}

		off = mp->lcn - lcn;

		if (off > 0) {
			if (off < (1LLU << 7))
				mph->mp_off_sz = 1;
			else if (off < (1LLU << 15))
				mph->mp_off_sz = 2;
			else if (off < (1LLU << 23))
				mph->mp_off_sz = 3;
			else if (off < (1LLU << 31))
				mph->mp_off_sz = 4;
			else
				assert(0);
		} else {
			if (off >= (~0LLU << 7))
				mph->mp_off_sz = 1;
			else if (off >= (~0LLU << 15))
				mph->mp_off_sz = 2;
			else if (off >= (~0LLU << 23))
				mph->mp_off_sz = 3;
			else if (off >= (~0LLU << 31))
				mph->mp_off_sz = 4;
			else
				assert(0);
		}
		memcpy(p, &off, mph->mp_off_sz);
		p += mph->mp_off_sz;

		lcn = mp->lcn;
	}

	/* Add end marker */
	mph = p;
	p += sizeof(*mph);
	mph->mp_len_sz = 0;
	mph->mp_off_sz = 0;

	return p - buf;
}

int ntfs_mpl_packed_len(const struct ntfs_mp *mpl)
{
	const struct ntfs_mp *mp;
	int len = 0;
	uint64_t lcn = 0;
	int64_t off;

	for (mp = mpl; mp->clen; mp++) {
		len += sizeof(struct ntfs_mp_hdr);
		if (mp->clen < (1LLU << 7))
			len += 1;
		else if (mp->clen < (1LLU << 15))
			len += 2;
		else if (mp->clen < (1LLU << 23))
			len += 3;
		else if (mp->clen < (1ULL << 31))
			len += 4;
		else
			assert(0);

		if (mp->lcn == NTFS_LCN_NONE)
			continue;

		off = mp->lcn - lcn;

		if (off > 0) {
			if (off < (1LLU << 7))
				len += 1;
			else if (off < (1LLU << 15))
				len += 2;
			else if (off < (1LLU << 23))
				len += 3;
			else if (off < (1LLU << 31))
				len += 4;
			else
				assert(0);
		} else {
			if (off >= (~0LLU << 7))
				len += 1;
			else if (off >= (~0LLU << 15))
				len += 2;
			else if (off >= (~0LLU << 23))
				len += 3;
			else if (off >= (~0LLU << 31))
				len += 4;
			else
				assert(0);
		}
		lcn = mp->lcn;
	}

	/* Add end marker */
	len += sizeof(struct ntfs_mp_hdr);

	return len;
}

struct ntfs_mp *ntfs_attr_mp_unpack(const struct ntfs_attr_hdr *attr)
{
	const struct ntfs_mp_hdr *mph = (void *)attr + attr->mp_off;
	const struct ntfs_mp_hdr *end = (void *)attr + attr->size;
	uint32_t mp_len;
	int32_t mp_off;
	int64_t lcn = 0;
	uint64_t vcn = attr->firstvcn;
	struct ntfs_mp *mp_buf, *mp;
	unsigned mp_buf_sz = 2;	/* Most attr contains only 1 mapping pair */

	mp_buf = malloc(mp_buf_sz * sizeof(*mp));
	mp = mp_buf;

	while (mph < end && mph->mp_len_sz) {
		if ((mp - mp_buf) + 1 == mp_buf_sz) {
			mp_buf_sz += 16;
			mp_buf = realloc(mp_buf, mp_buf_sz * sizeof(*mp));
			mp = mp_buf + mp_buf_sz - 16 - 1;
		}
		assert(mph->mp_len_sz <= 4);
		mp_len = *(uint32_t *)((void *)mph + sizeof(*mph));
		mp_len &= (uint32_t)-1 >> ((4 - mph->mp_len_sz) * 8);
		mp->vcn = vcn;
		mp->clen = mp_len;
		assert(mph->mp_off_sz <= 4);
		if (mph->mp_off_sz > 0) {
			mp_off = *(int32_t *)((void *)mph + sizeof(*mph) +
					      mph->mp_len_sz);
			if (mph->mp_off_sz == 4) {
				/* Nothing to do, use value as is */
			} else if (mp_off & (1 << (mph->mp_off_sz * 8 - 1))) {
				mp_off |= (uint32_t)-1 << (mph->mp_off_sz * 8);
			} else {
				mp_off &= (uint32_t)-1 >> ((4 - mph->mp_off_sz) * 8);
			}
			lcn += mp_off;
			mp->lcn = lcn;
		} else {
			mp->lcn = NTFS_LCN_NONE;
		}
		mp++;
		vcn += mp_len;
		mph = NTFS_MP_NEXT(mph);
	}

	/* Set end marker */
	mp->vcn = 0;
	mp->lcn = 0;
	mp->clen = 0;

	return mp_buf;
}

/**
 * Returns actual length of mapping pairs run list
 */
int ntfs_attr_mp_len(const struct ntfs_attr_hdr *attr)
{
	const struct ntfs_mp_hdr *mph = (void *)attr + attr->mp_off;
	const struct ntfs_mp_hdr *end = (void *)attr + attr->size;

	while (mph < end && mph->mp_len_sz)
		mph = NTFS_MP_NEXT(mph);

	return (void *)mph - NTFS_ATTR_MPL(attr) + sizeof(*mph);
}

/**
 * Extract attribute index (array of pointers) from MFT entry
 * ent - MFT entry for processing
 * aidx_bufp - pointer to index buffer pointer (could be reallocated)
 * aidx_lenp - pointer to index buffer length
 * Returns extracted index length or -1 on error
 */
int ntfs_mft_aidx_get(const struct ntfs_mft_entry *ent,
		      struct ntfs_attr_idx *aidx)
{
	struct ntfs_attr_hdr *attr = (void *)ent + ent->attr_off;
	const void * const end = (void *)ent + ent->used_sz;
	const struct ntfs_attr_hdr **aidx_buf = aidx->a;
	unsigned aidx_pos = 0, aidx_len = aidx->size;

	if (!aidx_len) {
		aidx_len = 8;
		aidx_buf = malloc(sizeof(void *) * aidx_len);
		if (!aidx_buf)
			return -1;
	}

	while (1) {
		if ((end - (void *)attr) < NTFS_ATTR_HDR_MIN_LEN) {
			errno = EINVAL;
			goto error;
		}
		if (attr->type == NTFS_ATTR_END)
			break;
		if ((aidx_pos + 1) == aidx_len) {
			aidx_len += 4;
			aidx_buf = realloc(aidx_buf, sizeof(void *) * aidx_len);
		}
		aidx_buf[aidx_pos++] = attr;
		attr = (void *)attr + attr->size;
	}

	aidx_buf[aidx_pos] = NULL;

	aidx->a = aidx_buf;
	aidx->size = aidx_len;
	aidx->num = aidx_pos;

	return 0;

error:
	/**
	 * If buffer initially was not allocated then free our buffer
	 * else return possibly reallocated buffer via passed pointer.
	 */
	if (!aidx->a) {
		free(aidx_buf);
	} else {
		aidx->a = aidx_buf;
		aidx->size = aidx_len;
	}

	return -1;
}

/**
 * Cleanup attributes index
 */
void ntfs_mft_aidx_clean(struct ntfs_attr_idx *aidx)
{
	free(aidx->a);
	aidx->a = NULL;
	aidx->size = 0;
	aidx->num = 0;
}

int ntfs_usa_apply(void *buf, size_t buf_sz, unsigned sec_sz)
{
	struct ntfs_record *rh = buf;
	struct ntfs_usa *usa = ntfs_usa_ptr(rh);
	uint16_t *p;
	unsigned num = buf_sz / sec_sz;
	unsigned i;

	if (rh->usa_len != num + 1) {
		errno = EINVAL;
		return -1;
	}

	p = buf + sec_sz - sizeof(*p);
	for (i = 0; i < num; ++i) {
		if (usa->usn != *p) {
			errno = EINVAL;
			return -2;
		}
		p += sec_sz / sizeof(*p);
	}

	p = buf + sec_sz - sizeof(*p);
	for (i = 0; i < num; ++i) {
		*p = usa->sec[i];
		p += sec_sz / sizeof(*p);
	}

	return 0;
}

char *ntfs_guid2str_r(const struct ntfs_guid *guid,
		      char buf[NTFS_GUID_STR_LEN + 1])
{
	snprintf(buf, NTFS_GUID_STR_LEN + 1,
		 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 guid->p1, guid->p2, guid->p3, guid->p4[0], guid->p4[1],
		 guid->p5[0], guid->p5[1], guid->p5[2], guid->p5[3],
		 guid->p5[4], guid->p5[5]);

	return buf;
}

const char *ntfs_guid2str(const struct ntfs_guid *guid)
{
	static char buf[NTFS_GUID_STR_LEN + 1];

	return ntfs_guid2str_r(guid, buf);
}

static const char ntfs_name_inv_chars[] = ".\"/\\[]:;=, ";

int ntfs_name_is_dos_compatible(const char *name)
{
	const char *fin = name + strlen(name);
	const char *ext = strrchr(name, '.');
	const char *pos;

	if (!ext)
		ext = fin;
	if (ext - name > 8)	/* Name length should be <= 8 */
		return 0;
	if (ext == name)	/* Name length should be > 0 */
		return 0;
	if (fin - ext - 1 > 3)	/* Ext length should be <= 3 */
		return 0;
	pos = strpbrk(name, ntfs_name_inv_chars);
	if (pos && pos != ext)
		return 0;
	if (strchr(name, '+'))
		return 0;

	return 1;
}

const char *ntfs_make_dos_name(const char *name, int idx)
{
	static char out[8 + 1 + 3 + 1];	/* 8.3 format */
	const char *fin = name + strlen(name);
	const char *ext = strrchr(name, '.');
	unsigned i, j, k;

	if (idx < 1 || idx > 9)
		idx = 1;

	if (name == ext) {	/* If name have form '.ext' */
		ext = fin;
		name++;
	} else if (!ext) {
		ext = fin;
	}

	for (i = 0, j = 0; name[i] != '\0' && name + i < ext && j < 6; ++i) {
		if (name[i] == '+' || name[i] == '[' || name[i] == ']')
			out[j++] = '_';
		else if (strchr(ntfs_name_inv_chars, name[i]))
			continue;
		else
			out[j++] = toupper(name[i]);
	}
	out[j++] = '~';
	out[j++] = '0' + idx;

	if (ext != fin) {
		out[j++] = '.';
		for (i = ext - name, k = 0; name[i] != '\0' && k < 3; ++i) {
			if (name[i] == '+')
				out[j + k++] = '_';
			else if (strchr(ntfs_name_inv_chars, name[i]))
				continue;
			else
				out[j + k++] = toupper(name[i]);
		}
	} else {
		k = 0;
	}
	out[j + k] = '\0';

	return out;
}

int ntfs_name_cmp(const uint16_t *n1, unsigned n1_len,
		  const uint16_t *n2, unsigned n2_len,
		  const uint16_t *upcase, unsigned upcase_sz)
{
	uint16_t a, b;
	const unsigned len = n1_len < n2_len ? n1_len : n2_len;
	unsigned i;

	for (i = 0; i < len; ++i) {
		a = n1[i];
		b = n2[i];
		if (a < upcase_sz && b < upcase_sz) {
			a = upcase[a];
			b = upcase[b];
		}
		if (a != b)
			return a < b ? -1 : 1;
	}

	if (n1_len != n2_len)
		return n1_len > n2_len ? 1 : -1;

	return 0;
}

static inline uint32_t ntfs_rol3(uint32_t val)
{
	return (val << 3) | (val >> (32 - 3));
}

uint32_t ntfs_sec_desc_hash(const void *buf, int len)
{
	const uint32_t *p = buf;
	const uint32_t *e = p + len / sizeof(uint32_t);
	uint32_t hash = 0;

	for (; p < e; ++p)
		hash = *p + ntfs_rol3(hash);

	return hash;
}

char *ntfs_sid2str(const struct ntfs_sec_sid *sid)
{
	unsigned len, i;
	char *buf, *p, *e;

	assert(sid->rev == 1);

	len = 4;	/* "S-1-" prefix */
	if (sid->authority[0] || sid->authority[1])
		len += 14;		/* Hex format: 0xXXXXXXXXXXXX */
	else
		len += 10;		/* Dec format: D...D (up to 10 digs) */
	len += (1 + 10) * sid->subauth_num;	/* -D...D (up to 10 digs) */
	len += 1;	/* Leading null-byte */

	buf = malloc(len);
	p = buf;
	e = buf + len;

	p += snprintf(p, e - p, "S-1-");

	if (sid->authority[0] || sid->authority[1])
		p += snprintf(p, e - p, "0x%02X%02X%02X%02X%02X%02X",
			      sid->authority[0], sid->authority[1],
			      sid->authority[2], sid->authority[3],
			      sid->authority[4], sid->authority[5]);
	else
		p += snprintf(p, e - p, "%u", (uint32_t)sid->authority[2] +
			      (uint32_t)sid->authority[3] +
			      (uint32_t)sid->authority[4] +
			      (uint32_t)sid->authority[5]);

	for (i = 0; i < sid->subauth_num; ++i)
		p += snprintf(p, e - p, "-%u", sid->subauth[i]);

	return buf;
}
