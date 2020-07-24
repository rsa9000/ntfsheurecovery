/**
 * MD5 hashing realization
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

#include <string.h>
#include <stdint.h>

#include "md5.h"

/* Encode input words into output bytes */
static inline void md5_encode(uint8_t *out, const uint32_t *in,
			      const unsigned len)
{
	unsigned i, j;

	for (i = 0, j = 0; j < len; ++i, j += 4) {
		out[j + 0] = (in[i] >> 0) & 0xff;
		out[j + 1] = (in[i] >> 8) & 0xff;
		out[j + 2] = (in[i] >> 16) & 0xff;
		out[j + 3] = (in[i] >> 24) & 0xff;
	}
}

/* MD5 basic transformation */
static void md5_block_proc(struct md5_ctx *ctx,
			   const uint8_t block[MD5_BLOCK_SZ])
{
	uint32_t a = ctx->a, b = ctx->b, c = ctx->c, d = ctx->d;
	uint32_t x[MD5_BLOCK_SZ / 4];
	unsigned ii, jj;

#define MD5_S11 7
#define MD5_S12 12
#define MD5_S13 17
#define MD5_S14 22
#define MD5_S21 5
#define MD5_S22 9
#define MD5_S23 14
#define MD5_S24 20
#define MD5_S31 4
#define MD5_S32 11
#define MD5_S33 16
#define MD5_S34 23
#define MD5_S41 6
#define MD5_S42 10
#define MD5_S43 15
#define MD5_S44 21

	/* Basic MD5 round functions */
	uint32_t f(const uint32_t x, const uint32_t y, const uint32_t z)
	{
		return ((x & y) | (~x & z));
	}
	uint32_t g(const uint32_t x, const uint32_t y, const uint32_t z)
	{
		return ((x & z) | (y & ~z));
	}
	uint32_t h(const uint32_t x, const uint32_t y, const uint32_t z)
	{
		return (x ^ y ^ z);
	}
	uint32_t i(const uint32_t x, const uint32_t y, const uint32_t z)
	{
		return ((y) ^ ((x) | (~z)));
	}
	/* Rotate left */
	inline uint32_t rl(const uint32_t x, const uint32_t n)
	{
		return (((x) << (n)) | ((x) >> (32-(n))));
	}
	/* Process item */
	uint32_t calc_item(
		const uint32_t a, const uint32_t b, const uint32_t c,
		const uint32_t d, const uint32_t x, const uint32_t s,
		const uint32_t ac, uint32_t (*f)(uint32_t, uint32_t, uint32_t)
	)
	{
		return b + rl(a + f(b, c, d) + x + ac, s);
	}

	/* Prepare input block */
	for (ii = 0, jj = 0; jj < MD5_BLOCK_SZ; ++ii, jj += 4) {
		x[ii] = ((uint32_t)block[jj + 0]) << 0;
		x[ii]|= ((uint32_t)block[jj + 1]) << 8;
		x[ii]|= ((uint32_t)block[jj + 2]) << 16;
		x[ii]|= ((uint32_t)block[jj + 3]) << 24;
	}

	/* Round 1 */
	a = calc_item(a, b, c, d, x[ 0], MD5_S11, 0xd76aa478, f); /* 1 */
	d = calc_item(d, a, b, c, x[ 1], MD5_S12, 0xe8c7b756, f); /* 2 */
	c = calc_item(c, d, a, b, x[ 2], MD5_S13, 0x242070db, f); /* 3 */
	b = calc_item(b, c, d, a, x[ 3], MD5_S14, 0xc1bdceee, f); /* 4 */
	a = calc_item(a, b, c, d, x[ 4], MD5_S11, 0xf57c0faf, f); /* 5 */
	d = calc_item(d, a, b, c, x[ 5], MD5_S12, 0x4787c62a, f); /* 6 */
	c = calc_item(c, d, a, b, x[ 6], MD5_S13, 0xa8304613, f); /* 7 */
	b = calc_item(b, c, d, a, x[ 7], MD5_S14, 0xfd469501, f); /* 8 */
	a = calc_item(a, b, c, d, x[ 8], MD5_S11, 0x698098d8, f); /* 9 */
	d = calc_item(d, a, b, c, x[ 9], MD5_S12, 0x8b44f7af, f); /* 10 */
	c = calc_item(c, d, a, b, x[10], MD5_S13, 0xffff5bb1, f); /* 11 */
	b = calc_item(b, c, d, a, x[11], MD5_S14, 0x895cd7be, f); /* 12 */
	a = calc_item(a, b, c, d, x[12], MD5_S11, 0x6b901122, f); /* 13 */
	d = calc_item(d, a, b, c, x[13], MD5_S12, 0xfd987193, f); /* 14 */
	c = calc_item(c, d, a, b, x[14], MD5_S13, 0xa679438e, f); /* 15 */
	b = calc_item(b, c, d, a, x[15], MD5_S14, 0x49b40821, f); /* 16 */

	/* Round 2 */
	a = calc_item(a, b, c, d, x[ 1], MD5_S21, 0xf61e2562, g); /* 17 */
	d = calc_item(d, a, b, c, x[ 6], MD5_S22, 0xc040b340, g); /* 18 */
	c = calc_item(c, d, a, b, x[11], MD5_S23, 0x265e5a51, g); /* 19 */
	b = calc_item(b, c, d, a, x[ 0], MD5_S24, 0xe9b6c7aa, g); /* 20 */
	a = calc_item(a, b, c, d, x[ 5], MD5_S21, 0xd62f105d, g); /* 21 */
	d = calc_item(d, a, b, c, x[10], MD5_S22,  0x2441453, g); /* 22 */
	c = calc_item(c, d, a, b, x[15], MD5_S23, 0xd8a1e681, g); /* 23 */
	b = calc_item(b, c, d, a, x[ 4], MD5_S24, 0xe7d3fbc8, g); /* 24 */
	a = calc_item(a, b, c, d, x[ 9], MD5_S21, 0x21e1cde6, g); /* 25 */
	d = calc_item(d, a, b, c, x[14], MD5_S22, 0xc33707d6, g); /* 26 */
	c = calc_item(c, d, a, b, x[ 3], MD5_S23, 0xf4d50d87, g); /* 27 */
	b = calc_item(b, c, d, a, x[ 8], MD5_S24, 0x455a14ed, g); /* 28 */
	a = calc_item(a, b, c, d, x[13], MD5_S21, 0xa9e3e905, g); /* 29 */
	d = calc_item(d, a, b, c, x[ 2], MD5_S22, 0xfcefa3f8, g); /* 30 */
	c = calc_item(c, d, a, b, x[ 7], MD5_S23, 0x676f02d9, g); /* 31 */
	b = calc_item(b, c, d, a, x[12], MD5_S24, 0x8d2a4c8a, g); /* 32 */

	/* Round 3 */
	a = calc_item(a, b, c, d, x[ 5], MD5_S31, 0xfffa3942, h); /* 33 */
	d = calc_item(d, a, b, c, x[ 8], MD5_S32, 0x8771f681, h); /* 34 */
	c = calc_item(c, d, a, b, x[11], MD5_S33, 0x6d9d6122, h); /* 35 */
	b = calc_item(b, c, d, a, x[14], MD5_S34, 0xfde5380c, h); /* 36 */
	a = calc_item(a, b, c, d, x[ 1], MD5_S31, 0xa4beea44, h); /* 37 */
	d = calc_item(d, a, b, c, x[ 4], MD5_S32, 0x4bdecfa9, h); /* 38 */
	c = calc_item(c, d, a, b, x[ 7], MD5_S33, 0xf6bb4b60, h); /* 39 */
	b = calc_item(b, c, d, a, x[10], MD5_S34, 0xbebfbc70, h); /* 40 */
	a = calc_item(a, b, c, d, x[13], MD5_S31, 0x289b7ec6, h); /* 41 */
	d = calc_item(d, a, b, c, x[ 0], MD5_S32, 0xeaa127fa, h); /* 42 */
	c = calc_item(c, d, a, b, x[ 3], MD5_S33, 0xd4ef3085, h); /* 43 */
	b = calc_item(b, c, d, a, x[ 6], MD5_S34,  0x4881d05, h); /* 44 */
	a = calc_item(a, b, c, d, x[ 9], MD5_S31, 0xd9d4d039, h); /* 45 */
	d = calc_item(d, a, b, c, x[12], MD5_S32, 0xe6db99e5, h); /* 46 */
	c = calc_item(c, d, a, b, x[15], MD5_S33, 0x1fa27cf8, h); /* 47 */
	b = calc_item(b, c, d, a, x[ 2], MD5_S34, 0xc4ac5665, h); /* 48 */

	/* Round 4 */
	a = calc_item(a, b, c, d, x[ 0], MD5_S41, 0xf4292244, i); /* 49 */
	d = calc_item(d, a, b, c, x[ 7], MD5_S42, 0x432aff97, i); /* 50 */
	c = calc_item(c, d, a, b, x[14], MD5_S43, 0xab9423a7, i); /* 51 */
	b = calc_item(b, c, d, a, x[ 5], MD5_S44, 0xfc93a039, i); /* 52 */
	a = calc_item(a, b, c, d, x[12], MD5_S41, 0x655b59c3, i); /* 53 */
	d = calc_item(d, a, b, c, x[ 3], MD5_S42, 0x8f0ccc92, i); /* 54 */
	c = calc_item(c, d, a, b, x[10], MD5_S43, 0xffeff47d, i); /* 55 */
	b = calc_item(b, c, d, a, x[ 1], MD5_S44, 0x85845dd1, i); /* 56 */
	a = calc_item(a, b, c, d, x[ 8], MD5_S41, 0x6fa87e4f, i); /* 57 */
	d = calc_item(d, a, b, c, x[15], MD5_S42, 0xfe2ce6e0, i); /* 58 */
	c = calc_item(c, d, a, b, x[ 6], MD5_S43, 0xa3014314, i); /* 59 */
	b = calc_item(b, c, d, a, x[13], MD5_S44, 0x4e0811a1, i); /* 60 */
	a = calc_item(a, b, c, d, x[ 4], MD5_S41, 0xf7537e82, i); /* 61 */
	d = calc_item(d, a, b, c, x[11], MD5_S42, 0xbd3af235, i); /* 62 */
	c = calc_item(c, d, a, b, x[ 2], MD5_S43, 0x2ad7d2bb, i); /* 63 */
	b = calc_item(b, c, d, a, x[ 9], MD5_S44, 0xeb86d391, i); /* 64 */

	/* Accumulate result */
	ctx->a += a;
	ctx->b += b;
	ctx->c += c;
	ctx->d += d;

	memset(x, 0x00, sizeof(x));	/* Zeroes sensitive data */

#undef MD5_S11
#undef MD5_S12
#undef MD5_S13
#undef MD5_S14
#undef MD5_S21
#undef MD5_S22
#undef MD5_S23
#undef MD5_S24
#undef MD5_S31
#undef MD5_S32
#undef MD5_S33
#undef MD5_S34
#undef MD5_S41
#undef MD5_S42
#undef MD5_S43
#undef MD5_S44
}

void md5_init(struct md5_ctx *ctx)
{
	ctx->lh = ctx->ll = 0;
	ctx->buf_n = 0;

	/* Load magic initialization constants. */
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;
}

void md5_update(struct md5_ctx *ctx, const uint8_t *in, const uint32_t len)
{
	unsigned i;			/* Input offset */
	unsigned b = ctx->buf_n;	/* Buffer offset */

	/* Update length */
	if ((ctx->ll += (len << 3)) < (len << 3))
		++(ctx->lh);
	ctx->lh += (len >> 29);

	/* Fill buffer */
	for (i = 0; b < sizeof(ctx->buf) && i < len; ++b, ++i)
		*(ctx->buf + b) = *(in + i);

	if (sizeof(ctx->buf) == b) {
		b = 0;
		md5_block_proc(ctx, ctx->buf);
		for (; (i + MD5_BLOCK_SZ - 1) < len; i += MD5_BLOCK_SZ)
			md5_block_proc(ctx, in + i);
	}

	/* Buffer remaining input */
	for (; i < len; ++i, ++b)
		*(ctx->buf + b) = *(in + i);
	ctx->buf_n = b;
}

void md5_finish(struct md5_ctx *ctx, uint8_t digest[MD5_DIGEST_SZ])
{
	uint8_t bits[8];
	unsigned b = ctx->buf_n;

	/* Save number of bits */
	md5_encode(bits + 0, &ctx->ll, 4);
	md5_encode(bits + 4, &ctx->lh, 4);

	/* Pad to 448 bit */
	ctx->buf[b++] = 0x80;		/* There are always space for one */
	if (b > (MD5_BLOCK_SZ - 8)) {
		memset(ctx->buf + b, 0x00, MD5_BLOCK_SZ - b);
		b = 0;
		md5_block_proc(ctx, ctx->buf);
	}
	memset(ctx->buf + b, 0x00, MD5_BLOCK_SZ - 8 - b);

	/* Put lenth data */
	memcpy(ctx->buf + (MD5_BLOCK_SZ - 8), bits, 8);

	/* Process last block */
	md5_block_proc(ctx, ctx->buf);

	md5_encode(digest + 0, &ctx->a, 4);	/* store A to digest */
	md5_encode(digest + 4, &ctx->b, 4);	/* store B to digest */
	md5_encode(digest + 8, &ctx->c, 4);	/* store C to digest */
	md5_encode(digest +12, &ctx->d, 4);	/* store D to digest */

	memset(ctx, 0x00, sizeof(*ctx));	/* Zeroes sensitive data */
}
