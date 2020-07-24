/**
 * Compressed NTFS data unpacker utility
 *
 * Copyright (c) 2015, Sergey Ryazanov <ryazanov.s.a@gmail.com>
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
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#ifndef DEBUG
#define DEBUG	0
#endif

#define BLK_COMP	0x8000
#define BLK_LEN_M	0x0fff

#define DEF_BLK_SZ	0x1000	/* Default compression block size, bytes */
#define DEF_CLS_SZ	0x1000	/* Default cluster size, bytes */
#define DEF_UNIT_SZ	0x0010	/* Default compression unit size, clusters */

static int unpack(FILE *fi, FILE *fo, int cls_sz, int blk_sz)
{
	uint8_t obuf[blk_sz];	/* Uncompressed data cache */
	unsigned left = 0;	/* How many octets we expect to process */
	unsigned ipos = 0;	/* Absolute position in the input stream */
	unsigned opos = 0;	/* Ouput position, relative to block start */
	unsigned tokn = 0;	/* Token # */
	int _c;
	uint8_t c = 0;
	uint16_t bhdr = 0;	/* Block header */
	uint8_t thdr = 0;	/* Tokens header */
	uint16_t phdr = 0;	/* Phrase header */
	enum {
		BLK_HDR_READ1 = 0x00 | 0x80,
		BLK_HDR_READ2 = 0x01 | 0x80,
		TOK_HDR_READ  = 0x03 | 0x80,
		TOK_NEXT      = 0x04,
		TOK_SYM_READ  = 0x05 | 0x80,
		TOK_PHR_READ1 = 0x06 | 0x80,
		TOK_PHR_READ2 = 0x07 | 0x80,
		GARBAGE       = 0x08 | 0x80,	/* Skip trailing garbage */
	} s = BLK_HDR_READ1;

	for (ipos = -1; ;) {
		/* Read input octet */
		if (s & 0x80) {
			ipos++;
			_c = fgetc(fi);
			if (EOF == _c)
				break;
			c = _c;
			left--;
		}

		switch (s) {
		case BLK_HDR_READ1:
			bhdr = c;
			s = BLK_HDR_READ2;
			break;
		case BLK_HDR_READ2:
			bhdr |= (uint16_t)c << 8;
#if DEBUG != 0
			fprintf(stderr, "%04X(%04X):%04X:Block header: %04X (len: %u, comp: %c)\n",
				ipos - 1, 0, 0,
				bhdr, bhdr & BLK_LEN_M, bhdr & BLK_COMP ? 'y' : 'n');
#endif
			if (bhdr == 0) {	/* End of compression unit */
				s = GARBAGE;
				break;
			}
			left = (bhdr & BLK_LEN_M) + 1;
			if (bhdr & BLK_COMP) {
				s = TOK_HDR_READ;
			} else {
				assert(0);
			}
			opos = 0;
			break;
		case TOK_HDR_READ:
			thdr = c;
#if DEBUG != 0
			fprintf(stderr, "%04X(%04X):%04X:    Token header: %02X\n",
				ipos, left, opos, thdr);
#endif
			tokn = 0;
			s = TOK_NEXT;
			/* Fall throught */
		case TOK_NEXT:
			if (left == 0) {
				s = BLK_HDR_READ1;
			} else if (opos == blk_sz) {
				assert(0);
			} else if (tokn == 8) {
				s = TOK_HDR_READ;
			} else if (thdr & (1 << tokn++)) {
				s = TOK_PHR_READ1;
			} else {
				s = TOK_SYM_READ;
			}
			break;
		case TOK_SYM_READ:
			assert(opos <= blk_sz);
			obuf[opos++] = c;
			fputc(c, fo);
			s = TOK_NEXT;
			break;
		case TOK_PHR_READ1:
			phdr = c;
			s = TOK_PHR_READ2;
			break;
		case TOK_PHR_READ2:
			phdr |= (uint16_t)c << 8;
			do {
				unsigned sh = 0;
				unsigned i;
				unsigned ret;	/* How far we should go back */
				unsigned len;	/* How many data should be copied */
				unsigned end;	/* Next char after last copy source char */

				/*
				 * Length of offset and length fields inside
				 * phrase header depends on amount of already
				 * uncompressed part of block.
				 */
				for (i = opos - 1; i >= 0x10; i >>= 1)
					sh++;

				ret = (phdr >> (12 - sh)) + 1;
				len = (phdr & (0xfff >> sh)) + 3;
				end = opos - ret + len;
#if DEBUG != 0
				fprintf(stderr, "%04X(%04X):%04X:        Phrase token: %04X (sh: %u, ret: %4u, len: %4u, from: %04X:%04X to: %04X:%04X)\n",
					ipos - 1, left, opos,
					phdr, sh, ret, len, opos - ret, end - 1, opos, opos + len - 1);
#endif
				assert(ret <= opos);
				assert(end <= blk_sz);
				assert(opos + len <= blk_sz);

				for (i = opos - ret; i < end; ++i) {
					obuf[opos++] = obuf[i];
					fputc(obuf[i], fo);
				}

				s = TOK_NEXT;
			} while (0);
			break;
		case GARBAGE:
			if (ipos % cls_sz == cls_sz - 1) {
#if DEBUG != 0
				fprintf(stderr, "%04X(%04X):%04X:End of cluster reached, start new block read\n",
					ipos, 0, 0);
#endif
				s = BLK_HDR_READ1;
			}
			break;	/* Just continue reading */
		}
	}

	if (s != GARBAGE && s != BLK_HDR_READ1) {
		fprintf(stderr, "Error: unexpected stream end\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	unsigned blk_sz = DEF_BLK_SZ;
	unsigned cls_sz = DEF_CLS_SZ;

	/*
	 * TODO: make parameters and input/output configurable via command line
	 * options
	 */

	return unpack(stdin, stdout, cls_sz, blk_sz) ? EXIT_FAILURE:
						       EXIT_SUCCESS;
}
