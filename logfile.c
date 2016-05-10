/**
 * NTFS $LogFile analysis code
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
#include <assert.h>
#include <inttypes.h>

#include "ntfs_struct.h"
#include "ntfs_dump.h"

#include "ntfsheurecovery.h"
#include "img.h"
#include "cmap.h"
#include "cache.h"
#include "mft_aux.h"

struct logfile_analyze_ctx {
	uint64_t off;		/* Logfile on disk offset, octets */
	unsigned len;		/* Logfile length, octets */
	unsigned last_pg_voff;	/* Last page virtual offset LSN */
	uint64_t last_lsn;	/* Last logfile LSN */
};

/**
 * Read $LogFile page from disk and preprocess it
 * off - on disk page offset
 * buf - buffer for readed page
 * magic - magic signature (4 octets)
 */
static int logfile_read_page(uint64_t off, void *buf, const char *magic)
{
	int res;

	res = img_read_sectors(off, buf, NTFS_LOG_PG_SZ/nhr.vol.sec_sz);
	if (res) {
		fprintf(stderr, "log[0x%"PRIX64"]: could not read page\n", off);
		return res;
	}

	if (memcmp(buf, magic, 4) != 0) {
		fprintf(stderr, "log[0x%"PRIX64"]: invalid magic %s expects \"%4s\"\n",
			off, mft_rec_magic_dump(buf), magic);
		return -EINVAL;
	}

	res = ntfs_usa_apply(buf, NTFS_LOG_PG_SZ, nhr.vol.sec_sz);
	if (res) {
		fprintf(stderr, "log[0x%"PRIX64"]: page integrity error\n",
			off);
		return -errno;
	}

	return 0;
}

static inline int logfile_read_rst_page(uint64_t off, void *buf)
{
	return logfile_read_page(off, buf, "RSTR");
}

static inline int logfile_read_rec_page(uint64_t off, void *buf)
{
	return logfile_read_page(off, buf, "RCRD");
}

static int logfile_analyze_rst_item(int pg_num, struct logfile_analyze_ctx *lctx)
{
	uint8_t buf[NTFS_LOG_PG_SZ];
	int res;

	res = logfile_read_rst_page(lctx->off + NTFS_LOG_PG_SZ * pg_num, buf);
	if (res)
		return res;

	return 0;
}

static int logfile_analyze_rst(struct logfile_analyze_ctx *lctx)
{
	int res;

	res = logfile_analyze_rst_item(NTFS_LOG_PGNUM_RST1, lctx);
	if (res)
		return res;

	res = logfile_analyze_rst_item(NTFS_LOG_PGNUM_RST2, lctx);
	if (res)
		return res;

	return 0;
}

static void logfile_analyze_buf_item(uint64_t off,
				     struct logfile_analyze_ctx *lctx)
{
	uint8_t buf[NTFS_LOG_PG_SZ];
	struct ntfs_log_rec_pg_hdr *recph = (void *)buf;

	if (logfile_read_rec_page(off, buf))
		return;

	lctx->last_pg_voff = recph->file_offset;
	lctx->last_lsn = recph->last_end_lsn;
}

/**
 * Analyze buffer space (1st and 2nd pages of logging area)
 */
static int logfile_analyze_buf(struct logfile_analyze_ctx *lctx)
{
	logfile_analyze_buf_item(lctx->off + NTFS_LOG_PG_SZ *
				 NTFS_LOG_PGNUM_BUF1, lctx);

	if (!lctx->last_lsn) {
		logfile_analyze_buf_item(lctx->off + NTFS_LOG_PG_SZ *
					 NTFS_LOG_PGNUM_BUF2, lctx);
		if (!lctx->last_lsn)
			return -ENOENT;
	}

	if (nhr.verbose >= 1) {
		printf("log: last record LSN: 0x%"PRIX64"\n", lctx->last_lsn);
		printf("log: last record page virt offset: 0x%08X (%u)\n",
		       lctx->last_pg_voff, lctx->last_pg_voff);
	}

	return 0;
}

static void logfile_analyze_rec_item(struct ntfs_log_rec_cmn_hdr *crec,
				     struct logfile_analyze_ctx *lctx)
{
	struct ntfs_log_rec_hdr *rec = (void *)crec->data;
	struct nhr_cb *cb;
	uint64_t ent_voff;
	struct nhr_mft_entry *mfte;

	if (rec->lcn_num) {
		cb = cmap_find(rec->tgt_lcn);
		assert(cb);
		if (!cb->flags) {
			printf("log: rec: LSN: 0x%08"PRIX64" modifies orphaned clusters block [0x%08"PRIX64":0x%08"PRIX64"]\n",
			       crec->this_lsn, nhr_cb_off(cb), nhr_cb_end(cb));
		}
	}

	switch (rec->redo_op) {
	case NTFS_LOG_OP_INITFILERECSEG:
	case NTFS_LOG_OP_DEALLOCFILERECSEG:
	case NTFS_LOG_OP_CREATEATTR:
	case NTFS_LOG_OP_DELETEATTR:
	case NTFS_LOG_OP_UPDRESIDENT:
	case NTFS_LOG_OP_UPDMP:
	case NTFS_LOG_OP_SETNEWATTRSZS:
	case NTFS_LOG_OP_ADDIDXROOT:
	case NTFS_LOG_OP_DELIDXROOT:
	case NTFS_LOG_OP_SETIDXROOT:
	case NTFS_LOG_OP_UPDFNROOT:
		ent_voff = rec->tgt_vcn * nhr.vol.cls_sz + rec->cls_boff *
			   NTFS_LOG_BLK_SZ;
		break;
	case NTFS_LOG_OP_NOOP:
	case NTFS_LOG_OP_UPDNONRESIDENT:
	case NTFS_LOG_OP_ADDIDXALLOC:
	case NTFS_LOG_OP_DELIDXALLOC:
	case NTFS_LOG_OP_WREOFIDX:
	case NTFS_LOG_OP_SETIDXALLOC:
	case NTFS_LOG_OP_UPDFNALLOC:
	case NTFS_LOG_OP_BMSETBITS:
	case NTFS_LOG_OP_BMCLRBITS:
	case NTFS_LOG_OP_FORGETTRANSACTION:
	case NTFS_LOG_OP_OPENNONRESATTR:
	case NTFS_LOG_OP_OPENATTRTBLDUMP:
	case NTFS_LOG_OP_ATTRNAMESDUMP:
	case NTFS_LOG_OP_DIRTYPGTBLDUMP:
	case NTFS_LOG_OP_TRANSACTIONTBLDUMP:
		ent_voff = 0;	/* Ignore */
		break;
	default:
		ntfs_dump_logfile_rec_cmn("log: rec: ", crec, 1);
		printf("Unknown redo operation type: 0x%02X\n", rec->redo_op);
		abort();
	}

	if (ent_voff) {
		mfte = cache_mfte_find(ent_voff / nhr.vol.mft_ent_sz);
		if (mfte) {
			printf("log: rec: LSN: 0x%"PRIX64" RedoOp: 0x%02X modifies MFT entry #%"PRIu64"\n",
			       crec->this_lsn, rec->redo_op,
			       nhr_mfte_num(mfte));
		}
	}
}

static void logfile_analyze_rec(struct logfile_analyze_ctx *lctx)
{
	uint8_t *buf, *p, *e;
	size_t buf_sz;
	struct ntfs_log_rec_pg_hdr *recph;
	struct ntfs_log_rec_cmn_hdr *reccmn;
	uint64_t pg_off;
	const uint64_t pg_off_end = lctx->off + lctx->len;
	const uint64_t pg_off_last = lctx->off + lctx->last_pg_voff;
	const uint64_t pg_off_first = pg_off_last + NTFS_LOG_PG_SZ;
	const unsigned pg_ssz = NTFS_LOG_PG_SZ / nhr.vol.sec_sz;
	const unsigned pg_data_off = NTFS_ALIGN(sizeof(*recph) + (pg_ssz + 1) *
						sizeof(uint16_t));
	int res, done = 0;

	buf_sz = 4 * NTFS_LOG_PG_SZ;
	buf = malloc(buf_sz);
	recph = (void *)buf;

	/* Search first page with known record header */
	pg_off = pg_off_first;
	do {
		res = logfile_read_rec_page(pg_off, buf);
		assert(res == 0);
		if (recph->last_end_lsn)
			break;
		pg_off += NTFS_LOG_PG_SZ;
		if (pg_off == pg_off_end)
			pg_off = lctx->off + NTFS_LOG_PG_SZ * NTFS_LOG_PGNUM_LOGSTART;
	} while (pg_off != pg_off_last);

	if (pg_off == pg_off_last) {
		fprintf(stderr, "log: log begining is not found\n");
		free(buf);
		return;
	}

	p = (void *)recph + recph->rec_off;
	e = (void *)buf + NTFS_LOG_PG_SZ;
	while (1) {
		while (1) {
			reccmn = (void *)p;

			/* If there are no space for header */
			if ((e - p) < sizeof(*reccmn)) {
				/* Skip current page */
				p = buf;
				e = buf;
				break;
			}
			/* Is record fully loaded to buffer */
			if ((e - p) < sizeof(*reccmn) + reccmn->data_sz)
				break;

			logfile_analyze_rec_item(reccmn, lctx);

			if (reccmn->this_lsn == lctx->last_lsn) {
				done = 1;
				break;
			}

			p += sizeof(*reccmn) + reccmn->data_sz;
		}
		if (done)
			break;

		/* Attempt to free buffer tail if have some headroom */
		if (buf_sz - (e - buf) < NTFS_LOG_PG_SZ && p != buf) {
			memmove(buf, p, e - p);
			e -= p - buf;
			p = buf;
		}

		/* Enlarge buffer if it still too small */
		if (buf_sz - (e - buf) < NTFS_LOG_PG_SZ) {
			unsigned __buf_pos = p - buf;
			unsigned __buf_end = e - buf;

			buf_sz += NTFS_LOG_PG_SZ;
			assert(buf_sz <= 8 * NTFS_LOG_PG_SZ);
			buf = realloc(buf, buf_sz);
			assert(buf);
			p = buf + __buf_pos;
			e = buf + __buf_end;
		}

		/* Select next page for reading */
		pg_off += NTFS_LOG_PG_SZ;
		if (pg_off == pg_off_end)		/* Logging area end reached */
			pg_off = lctx->off + NTFS_LOG_PG_SZ * NTFS_LOG_PGNUM_LOGSTART;

		res = logfile_read_rec_page(pg_off, e);
		assert(res == 0);

		/* Remove page header */
		memmove(e, e + pg_data_off, NTFS_LOG_PG_SZ - pg_data_off);
		e += NTFS_LOG_PG_SZ - pg_data_off;
	}

	free(buf);
}

void logfile_analyze(void)
{
	struct logfile_analyze_ctx lctx;
	uint8_t ent_buf[nhr.vol.mft_ent_sz];
	struct ntfs_mft_entry *ent = (void *)ent_buf;
	struct ntfs_attr_idx aidx;
	const struct ntfs_attr_hdr *attr;
	unsigned i;
	struct ntfs_mp *mpl = NULL;
	int res;

	memset(&lctx, 0x00, sizeof(lctx));
	memset(&aidx, 0x00, sizeof(aidx));

	res = mft_entry_read_and_preprocess(NTFS_ENTNUM_LOGFILE, ent, 0);
	if (res) {
		fprintf(stderr, "logfile: could not read $LogFile MFT entry\n");
		return;
	}

	ntfs_mft_aidx_get(ent, &aidx);
	for (i = 0; i < aidx.num; ++i) {
		attr = aidx.a[i];
		if (attr->type != NTFS_ATTR_DATA || attr->name_len)
			continue;
		mpl = ntfs_attr_mp_unpack(attr);
		break;
	}
	assert(mpl);
	assert(ntfs_mpl_len(mpl) == 1);
	ntfs_mft_aidx_clean(&aidx);

	lctx.off = mpl->lcn * nhr.vol.cls_sz;
	lctx.len = mpl->clen * nhr.vol.cls_sz;

	res = logfile_analyze_rst(&lctx);
	if (res)
		return;

	res = logfile_analyze_buf(&lctx);
	if (res)
		return;

	logfile_analyze_rec(&lctx);
}
