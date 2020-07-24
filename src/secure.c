/**
 * NTFS $Secure file related functions
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
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "bb.h"
#include "cmask.h"
#include "img.h"
#include "cache.h"
#include "mft_analyze.h"
#include "secure.h"

/**
 * Due to the fact that NTFS stores item security descriptor twice parsing
 * and recovering appropriate data stream ($SDS - security descriptors stream)
 * could be a bit puzzled task.
 *
 * As said above, each security descriptor stored twice: at its main location
 * and its copy is stored after 0x40000 (256KB). Once NTFS fill item 256KB
 * region it reach region, which contains mirrored descriptors. In such case
 * NTFS skip whole mirroring region and starts writing new descriptor in next
 * 256KB region. Since descriptor could not cross 256KB boundary (if descriptor
 * does not fit fully into left space, then NTFS store it in the next region)
 * we could call this regions a blocks. So the $SDS stream is the sequence of
 * two interlaced sets of blocks (main and mirror). It should be noted that
 * NTFS initially allocates full main block + one cluster for mirror block and
 * then allocates new clusters for mirror block when it need to store new
 * data. So last mirror block is never fully allocated!
 *
 *  |<-------------- Attribute allocated space ------------>|
 *  |<------------ Attribute used space ------------------>||
 *  |                                                      ||
 *  .----------.----------.----------.     .----------.----------.
 *  |   Main   |  Mirror  |   Main   |     |   Main   |  Mirror  |
 *  | block #1 | block #1 | block #2 | ... | block #N | block #N |
 *  '----------'----------'----------'     '----------'----------'
 *  |                                           |     |    |     |
 *  '-------------------.-----------------------'--.--'--.-'--.--'
 *                      |                          |     |    |
 *                      '----------------.---------|-----'    |
 *                                  Space in use   |          |
 *                                                 |          |
 *                                           Allocated    Non allocated
 *                                           free space     free space
 */

/**
 * This function attempts to recover BB of $SDS (security descriptors stream)
 * attribute (ignore, which could be ignored and copy from mirror, which could
 * be copied).
 */
void secure_sds_recover(void)
{
	static const uint8_t sds_name[] = {'$', 0, 'S', 0, 'D', 0, 'S', 0};
	const unsigned sds_name_len = sizeof(sds_name) / 2;
	struct nhr_mft_entry *mfte, *bmfte;
	const struct nhr_data *data;
	unsigned sds_mpl_len;
	uint64_t voff2, off2;
	struct nhr_bb *bb1, *bb2;
	const struct ntfs_mp *mp1, *mp2;
	struct nhr_ob *ob;
	int res, bb2_ok;
	int cnt_tot = 0, cnt_ok = 0, cnt_ign = 0;

	bmfte = cache_mfte_find(NTFS_ENTNUM_SECURE);
	if (!bmfte)
		return;

	if (nhr.verbose >= 1)
		printf("secure:sds: recover data\n");

	/* Load attributes */
	res = mft_entry_attr2cache(bmfte);
	if (res) {
		fprintf(stderr, "secure:sds: could not fetch attributes\n");
		return;
	}
	list_for_each_entry(mfte, &bmfte->ext, ext) {
		res = mft_entry_attr2cache(mfte);
		if (res) {
			fprintf(stderr, "secure:sds: could not fetch attributes from extent entry\n");
			return;
		}
	}

	/* Load $SDS stream info */
	res = mft_fetch_data_info(bmfte, sds_name_len, sds_name);
	if (res) {
		fprintf(stderr, "secure:sds: could not fetch $SDS data info\n");
		return;
	}

	data = cache_data_find(bmfte, sds_name_len, sds_name);
	assert(data);

	if (!NHR_FIELD_VALID(&data->sz_used) ||
	    !NHR_FIELD_VALID(&data->sz_alloc) || !data->mpl ||
	    data->sz_alloc.val != ntfs_mpl_lclen(data->mpl) * nhr.vol.cls_sz) {
		fprintf(stderr, "secure:sds: $SDS data info not fully loaded\n");
		return;
	}

	sds_mpl_len = ntfs_mpl_len(data->mpl);
	for (bb1 = cache_mfte_bb_find(bmfte, NTFS_ATTR_DATA, data);
	     bb1 != NULL;
	     bb1 = cache_mfte_bb_next(bb1)) {
		if (bb1->flags & (NHR_BB_F_IGNORE | NHR_BB_F_REC))
			continue;
		cnt_tot++;
		if (nhr.verbose >= 3)
			printf("secure:sds: got BB at 0x%08"PRIX64" (#%"PRIu64", 0x%02X, %u)\n",
			       bb1->voff, nhr_mfte_num(bb1->mfte),
			       bb1->attr_type, bb1->attr_id);
		mp1 = ntfs_mpl_find(data->mpl, sds_mpl_len, bb1->voff / nhr.vol.cls_sz);
		if (nhr.verbose >= 3)
			printf("secure:sds:   which is belongs to mapping pair 0x%08"PRIX64"<->0x%08"PRIX64" (%"PRIu64" clusters)\n",
			       mp1->vcn, mp1->lcn, mp1->clen);
		if (bb1->voff / NTFS_SEC_SDS_BLK_SZ % 2) {
			voff2 = bb1->voff - NTFS_SEC_SDS_BLK_SZ;
		} else {
			voff2 = bb1->voff + NTFS_SEC_SDS_BLK_SZ;
		}
		if (nhr.verbose >= 3)
			printf("secure:sds:   search mirror sector at 0x%08"PRIX64" (%s)\n",
			       voff2,
			       bb1->voff < voff2 ? "forward" : "reverse");
		mp2 = ntfs_mpl_find(data->mpl, sds_mpl_len, voff2 / nhr.vol.cls_sz);
		if (bb1->voff < voff2 && voff2 > data->sz_used.val) {
			if (nhr.verbose >= 3) {
				printf("secure:sds:   which is fall into unused area\n");
			}
			bb1->flags |= NHR_BB_F_IGNORE;
			cache_mfte_bb_ok(bb1);
			cnt_ign++;
			continue;
		}
		if (nhr.verbose >= 3)
			printf("secure:sds:   which is belongs to mapping pair 0x%08"PRIX64"<->0x%08"PRIX64" (%"PRIu64" clusters)\n",
			       mp2->vcn, mp2->lcn, mp2->clen);
		off2 = mp2->lcn * nhr.vol.cls_sz + (voff2 - mp2->vcn * nhr.vol.cls_sz);
		bb2 = bb_find(off2);
		bb2_ok = !bb2 || !!(bb2->flags & (NHR_BB_F_IGNORE | NHR_BB_F_REC));
		if (nhr.verbose >= 3)
			printf("secure:sds:   mirror sector is %s\n",
			       bb2_ok ? "Ok" : "corrupted too");
		if (!bb2_ok)
			continue;
		ob = img_overlay_alloc(nhr.vol.sec_sz);
		nhr_ob_off(ob) = nhr_bb_off(bb1);
		img_read_sectors(off2, ob->buf, 1);
		img_overlay_add(ob);
		bb1->flags |= NHR_BB_F_REC;
		cache_mfte_bb_ok(bb1);
		cnt_ok++;
	}

	if (nhr.verbose >= 1)
		printf("secure:sds: processed %d BBs (%d of them recovered and %d marked as ignorable)\n",
		       cnt_tot, cnt_ok, cnt_ign);
}

/**
 * Parse $Secure file $SDS data stream and invoke callback function for each
 * detected security descriptor
 */
int secure_sds_foreach_cb(const struct ntfs_mp *mpl,
			  const struct nhr_cmask_elem *bb_mask,
			  const uint64_t sds_len,
			  secure_sds_cb_t cb, void *cb_priv)
{
	const uint64_t voff_end = (sds_len / NTFS_SEC_SDS_BLK_SZ / 2) * 2 *
				  NTFS_SEC_SDS_BLK_SZ + sds_len % NTFS_SEC_SDS_BLK_SZ;
	const struct ntfs_mp *mp = mpl;
	uint64_t voff = 0, lcn = mp->lcn - 1;
	uint8_t buf[nhr.vol.cls_sz * 2];
	void *p = buf + sizeof(buf);		/* Position */
	void * const e = buf + sizeof(buf);	/* End */
	struct ntfs_sec_desc_hdr *sdh;
	unsigned __len;
	const struct nhr_cmask_elem *me = bb_mask;
	uint32_t last_sid = 256;
	int res = 0, needmore = 1, parser = 1;
	int __n = 2000000;

	assert(mp->vcn == 0);

	do {
#if 0
		fprintf(stderr, "voff = 0x%08"PRIX64" pos = 0x%04zX left = 0x%04zX needmore = %d lcn = 0x%08"PRIX64" parser = %d\n",
			voff, p - (void *)buf, e - p, needmore, lcn, parser);
#endif
		if (needmore) {
			if (e - p > nhr.vol.cls_sz) {
				fprintf(stderr, "sds: buffer is too small for descriptor at 0x%08"PRIX64"\n",
					voff);
				break;
			}
			memcpy(p - nhr.vol.cls_sz, p, e - p);
			++lcn;
			if (lcn - mp->lcn >= mp->clen) {
				mp++;
				lcn = mp->lcn;
			}
			assert(mp->lcn);
#if 0
			fprintf(stderr, "sds: read from 0x%08"PRIX64"\n",
				lcn * nhr.vol.cls_sz);
#endif
			img_read_cluster(lcn, buf + nhr.vol.cls_sz);
			img_overlay_apply(lcn * nhr.vol.cls_sz, buf + nhr.vol.cls_sz,
					  nhr.vol.cls_sz);
			p -= nhr.vol.cls_sz;
			needmore = 0;
		}

		if (sizeof(*sdh) > e - p) {
			needmore = 1;
			continue;
		}

		if (parser) {
			assert(me->valid);

			if (voff + sizeof(*sdh) > me->off + me->len) {
				parser = 0;
				p += sizeof(*sdh);
				voff += sizeof(*sdh);
				me++;
				continue;
			}

			sdh = p;
			if (sdh->len > e - p) {
				needmore = 1;
				continue;
			}

			__len = (sdh->len + NTFS_SEC_SDS_ALIGNTO - 1) & ~(NTFS_SEC_SDS_ALIGNTO - 1);

			if (voff + sdh->len > me->off + me->len) {
				parser = 0;
				p += __len;
				voff += __len;
				while (voff > (me->off + me->len))
					me++;
				continue;
			}

			if (sdh->len == 0 && sdh->hash == 0 && sdh->id == 0) {
				assert(NTFS_SEC_SDS_BLK_SZ - (voff % NTFS_SEC_SDS_BLK_SZ) < nhr.vol.cls_sz);

				/* Calc position of next block */
				voff = ((voff / NTFS_SEC_SDS_BLK_SZ) + 2) * NTFS_SEC_SDS_BLK_SZ;
				/* "Fast forward" stream to new position */
				while ((voff / nhr.vol.cls_sz) > (mp->vcn + (lcn - mp->lcn))) {
					++lcn;
					if (lcn - mp->lcn >= mp->clen) {
						mp++;
						lcn = mp->lcn;
					}
				}
				/* "Fast forward" bb mask to new position */
				while (voff > (me->off + me->len))
					me++;
				if (!me->valid)
					parser = 0;
#if 0
				fprintf(stderr,
					"voff = 0x%08"PRIX64" (LCN = 0x%08"PRIX64", Pos = 0x%02"PRIX64", MP->VCN = 0x%08"PRIX64", MP->LCN = 0x%08"PRIX64", MP->CLEN = 0x%02"PRIX64")\n",
					voff, lcn, lcn - mp->lcn, mp->vcn, mp->lcn, mp->clen);
#endif
				/* Reconfigure pointers and so on */
				lcn--;					/* Point to cluster immediatly before targeted */
				p = buf + sizeof(buf);			/* Trigger reading */
				continue;
			}

			if (sdh->len < sizeof(*sdh)) {
				fprintf(stderr, "sds: descriptor at 0x%08"PRIX64" is too short: 0x%08X bytes\n",
					voff, sdh->len);
				break;
			}

			last_sid = sdh->id;
			res = cb(voff, sdh, cb_priv);
			if (res)
				break;

			p += __len;
			voff += __len;
		} else {
			/* Do we still (again) inside corrupted area? */
			if (!me->valid) {
				if (e - p > me->off + me->len - voff) {
					p += me->off + me->len - voff;
					voff = me->off + me->len;
					me++;
				} else {
					voff += e - p;
					p = e;
				}
				continue;
			}

			if (voff + sizeof(*sdh) > me->off + me->len) {
				p += sizeof(*sdh);
				voff += sizeof(*sdh);
				me++;
				continue;
			}

			sdh = p;

			/* Do some simple checks */
			if (sdh->voff != voff || sdh->id <= last_sid) {
				p += NTFS_SEC_SDS_ALIGNTO;
				voff += NTFS_SEC_SDS_ALIGNTO;
				continue;
			}

			if (sdh->len > e - p) {
				needmore = 1;
				continue;
			}

			if (voff + sdh->len > me->off + me->len) {
				p += NTFS_SEC_SDS_ALIGNTO;
				voff += NTFS_SEC_SDS_ALIGNTO;
				continue;
			}

			if (sdh->hash != ntfs_sec_desc_hash(sdh->data, sdh->len - sizeof(*sdh))) {
				p += NTFS_SEC_SDS_ALIGNTO;
				voff += NTFS_SEC_SDS_ALIGNTO;
				continue;
			}

			parser = 1;	/* We in sync with stream */
		}
	} while (voff < voff_end && --__n > 0);

	return 0;
}
