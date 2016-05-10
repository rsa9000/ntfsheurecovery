/**
 * Image I/O functions
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
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include <sys/stat.h>

#include "ntfsheurecovery.h"
#include "misc.h"
#include "md5.h"
#include "img.h"

int img_open(void)
{
	int fd;
	struct stat stat;

	fd = open(nhr.fs_file_name, O_RDONLY);
	if (-1 == fd) {
		fprintf(stderr, "img: could not open '%s' file for reading (err: %d): %s\n",
			nhr.fs_file_name, errno, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &stat)) {
		fprintf(stderr, "img: could not obtain image file data (err: %d): %s\n",
			errno, strerror(errno));
		close(fd);
		return -errno;
	}

	if (nhr.verbose >= 1)
		printf("img: total image size: %s\n", int2sz(stat.st_size));

	nhr.fs_file_sz = stat.st_size;
	nhr.fs_fd = fd;

	return 0;
}

/**
 * Read several sectors from image (disk)
 * off - sector offset, bytes
 * buf - buffer for readed data
 * num - number of sectors, what should be readed
 * Returns zero or negative error code
 */
int img_read_sectors(off_t off, void *buf, size_t num)
{
	const size_t count = num * nhr.vol.sec_sz;
	ssize_t readed;

	if (lseek(nhr.fs_fd, off, SEEK_SET) == -1) {
		fprintf(stderr, "img: could not seek to offset %ju\n", off);
		return -EIO;
	}

	readed = read(nhr.fs_fd, buf, count);
	if (readed != count) {
		fprintf(stderr, "img: could not read %zu sector(s) from %ju\n",
			num, off);
		return -EIO;
	}

	return 0;
}

void img_fetch_mp_data(const struct ntfs_mp *mpl, void *buf)
{
	for (; mpl->clen; ++mpl) {
		assert(mpl->lcn != NTFS_LCN_NONE);
		img_read_clusters(mpl->lcn, buf, mpl->clen);
		buf += mpl->clen * nhr.vol.cls_sz;
	}
}

void img_make_digest(const struct ntfs_mp *mpl, size_t len, uint8_t *digest)
{
	struct md5_ctx ctx;
	uint8_t buf[nhr.vol.cls_sz];
	unsigned i, l;

	if (len == 0)
		len = ntfs_mpl_vclen(mpl) * nhr.vol.cls_sz;

	md5_init(&ctx);

	for (; mpl->clen && len > 0; ++mpl) {
		assert(mpl->lcn != NTFS_LCN_NONE);
		for (i = 0; i < mpl->clen && len > 0; ++i) {
			img_read_clusters(mpl->lcn + i, buf, 1);
			l = len > sizeof(buf) ? sizeof(buf) : len;
			md5_update(&ctx, buf, l);
			len -= l;
		}
	}

	md5_finish(&ctx, digest);
}

/**
 * Apply overlay to specified region
 *
 * off - region on disk offset, bytes
 * buf - buffer, which data should be updated
 * len - buffer length
 */
void img_overlay_apply(uint64_t off, void *buf, size_t len)
{
	const uint64_t end = off + len;
	struct rbtree *t = &nhr.img_overlay;
	struct nhr_ob *ob = rbtree_entry(t->rbt_root, struct nhr_ob, tree);
	struct nhr_ob *ob_last = rbtree_entry(&t->rbt_nil, struct nhr_ob, tree);
	int __buf_off, __ob_off, __len;

	/* Search suitable overlay block with minimal address */
	while (!rbt_is_nil(t, &ob->tree)) {
		if (nhr_ob_end(ob) <= off) {
			ob = nhr_ob_right(ob);
		} else if (nhr_ob_off(ob) >= end) {
			ob = nhr_ob_left(ob);
		} else {
			ob_last = ob;
			if (nhr_ob_off(ob) > off)
				ob = nhr_ob_left(ob);
			else
				break;
		}
	}

	ob = ob_last;

	while (!rbt_is_nil(t, &ob->tree)) {
		if (nhr_ob_off(ob) >= end)
			break;

		__len = ob->len;
		__buf_off = nhr_ob_off(ob) - off;
		if (__buf_off < 0) {	/* If overlay block begins before the buffer */
			__len += __buf_off;
			__ob_off = -__buf_off;
			__buf_off = 0;
		} else {
			__ob_off = 0;
		}
		if (nhr_ob_end(ob) > end)	/* If overlay block ends after the buffer */
			__len -= end - nhr_ob_end(ob);

		memcpy(buf + __buf_off, ob->buf + __ob_off, __len);

		ob = nhr_ob_next(t, ob);
	}
}

struct nhr_ob *img_overlay_alloc(size_t buf_sz)
{
	struct nhr_ob *ob = calloc(1, sizeof(*ob));

	if (!ob)
		return NULL;

	ob->buf = malloc(buf_sz);
	if (!ob->buf) {
		free(ob);
		return NULL;
	}

	ob->len = buf_sz;

	return ob;
}

void img_overlay_add(struct nhr_ob *ob)
{
	rbtree_insert(&nhr.img_overlay, &ob->tree);
}

int img_overlay_export(const char *outdir)
{
	size_t dirname_len = strlen(outdir);
	char opath[dirname_len + 64];
	struct nhr_ob *ob;
	int fd, res;

	strncpy(opath, outdir, dirname_len);
	if (outdir[dirname_len - 1] != '/') {
		opath[dirname_len] = '/';
		dirname_len++;
	}

	rbt_inorder_walk_entry(ob, &nhr.img_overlay, tree) {
		snprintf(opath + dirname_len, sizeof(opath) - dirname_len,
			 "overlay-0x%010"PRIX64"-0x%04X.bin",
			 ob->tree.key, ob->len);

		fd = open(opath, O_WRONLY | O_CREAT | O_EXCL,
			  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (fd == -1) {
			fprintf(stderr, "img: could not create '%s' file for overlay export: %s\n",
				opath, strerror(errno));
			return -1;
		}

		res = write(fd, ob->buf, ob->len);
		if (res != ob->len) {
			fprintf(stderr, "fd = %d, ob->len = %d, res = %d\n", fd, ob->len, res);
			fprintf(stderr, "img: could not write overlay block to '%s': %s\n",
				opath, strerror(errno));
			close(fd);
			return -1;
		}

		close(fd);
	}

	return 0;
}
