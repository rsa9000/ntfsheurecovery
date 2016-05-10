/**
 * Misc code
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
#include <ctype.h>
#include <wchar.h>
#include <assert.h>
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "misc.h"

const char *bin2hex(const uint8_t *buf, const size_t len)
{
#define BIN2HEX_BUF_SZ	0x100
	static char _buf[3 * BIN2HEX_BUF_SZ + 1];
	char *p;
	unsigned i;

	p = _buf;
	for (i = 0; i < len && i < BIN2HEX_BUF_SZ; ++i)
		p += snprintf(p, 4, " %02X", buf[i]);

	if (len == 0)
		_buf[1] = '\0';

	return _buf + 1;
#undef BIN2HEX_BUF_SZ
}

void hexdump(const uint8_t *buf, const size_t len)
{
	unsigned i, j;

	for (i = 0; i < len; i += 16) {
		printf("%08x ", i);
		for (j = 0; j < 16; ++j) {
			if (j == 8)
				putchar(' ');
			if (i + j < len)
				printf(" %02x", buf[i + j]);
			else
				printf("   ");
		}
		printf("  |");
		for (j = 0; j < 16 && i + j < len; ++j)
			putchar(isprint(buf[i + j]) ? buf[i + j] : '.');
		puts("|");
	}
	printf("%08x\n", i);
}

/**
 * Convert Unicode (UTF-16) name to wchar_t
 * name - buffer with name
 * len - name length in Unicode chars
 *
 * NB: use self realization instead of iconv to be able constify
 * arguments.
 */
const wchar_t *name2wchar(const void *name, const size_t len)
{
	static wchar_t buf[0x100];
#if WCHAR_MAX <= 0xffff
	assert(len <= 255);
	memcpy(buf, name, len * 2);
#elif WCHAR_MAX <= 0xffffffff
	unsigned i;
	assert(len <= 255);

	for (i = 0; i < len; ++i)
		buf[i] = ((uint16_t *)name)[i];
#endif
	buf[len] = L'\0';

	return buf;
}

void str2utf16(const char *in, void *out)
{
	const char *i = in;
	uint16_t *o = out;

	for (; *i != '\0'; ++i, ++o)
		*o = *i;
}

const char *int2sz(const uint64_t sz)
{
	static char buf[0x10];

	if (sz < 1024) {
		snprintf(buf, sizeof(buf), "%"PRIu64" B", sz);
	} else if (sz < (1024 * 1024)) {
		snprintf(buf, sizeof(buf), "%"PRIu64" KB", sz / 1024);
	} else if (sz < (1024 * 1024 * 1024)) {
		snprintf(buf, sizeof(buf), "%"PRIu64" MB", sz / (1024 * 1024));
	} else {
		snprintf(buf, sizeof(buf), "%"PRIu64" GB", sz / (1024 * 1024 * 1024));
	}

	return buf;
}

const char *digest2str(const uint8_t *digest)
{
	static char buf[16 * 2 + 1];
	unsigned i;

	for (i = 0; i < 16; ++i)
		snprintf(buf + 2 * i, sizeof(buf) - 2 * i, "%02x", digest[i]);

	return buf;
}
