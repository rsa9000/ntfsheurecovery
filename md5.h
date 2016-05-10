/**
 * MD5 hashing interface
 *
 * Copyright (c) 2012, 2015, Sergey Ryazanov <ryazanov.s.a@gmail.com>
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

#ifndef _MD5_H_
#define _MD5_H_

#include <stdint.h>

#define MD5_BLOCK_SZ	64	/* block size (512 bit) */
#define MD5_DIGEST_SZ	16	/* digest size (128 bit) */

/* execution context */
struct md5_ctx {
	uint32_t a, b, c, d;		/* state (ABCD) */
	uint32_t lh, ll;		/* bit lengh high and low */
	uint8_t buf[MD5_BLOCK_SZ];	/* buffer */
	unsigned buf_n;			/* buffered data len */
};

void md5_init(struct md5_ctx *ctx);
void md5_update(struct md5_ctx *ctx, const uint8_t *in, const uint32_t len);
void md5_finish(struct md5_ctx *ctx, uint8_t digest[MD5_DIGEST_SZ]);

/** Perform full hashing sequence at single call */
static inline void md5(const uint8_t *buf, const unsigned len,
		       uint8_t digest[MD5_DIGEST_SZ])
{
	struct md5_ctx ctx;

	md5_init(&ctx);
	md5_update(&ctx, buf, len);
	md5_finish(&ctx, digest);
}

#endif	/* _MD5_H_ */
