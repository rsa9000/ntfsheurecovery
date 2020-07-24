/**
 * ddrescue log parser
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "rbtree.h"
#include "ntfsheurecovery.h"
#include "bb.h"

int ddrescue_log_parse(const char *logfile, uint64_t offset)
{
	FILE *fp = fopen(logfile, "r");
	char buf[0x100];
	int ret = 0;
	char status;
	uint64_t pos, len;
	struct nhr_bb *bb;

	if (NULL == fp) {
		fprintf(stderr, "Could not open ddrescue log file '%s' for reading (err: %d): %s\n",
			logfile, errno, strerror(errno));
		return -errno;
	}

	/* Search "ddrescue" signature */
	ret = -ENOENT;
	while (fgets(buf, sizeof(buf), fp)) {
		if (buf[0] != '#')
			break;
		if (strstr(buf, "ddrescue") != NULL) {
			ret = 0;
			break;
		}
	}

	if (ret != 0) {
		fprintf(stderr, "No \"ddrescue\" word found, looks like this is not valid log file\n");
		goto exit;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		if (buf[0] == '#')
			continue;
		if (sscanf(buf, "0x%"PRIx64"  0x%"PRIx64"  %c\n", &pos, &len, &status) != 3)
			continue;
		if (status != '-' && status != '\\' && status != '*')
			continue;
		if (pos < offset)
			continue;
		pos -= offset;
		len += pos;	/* Move to next normal offset */

		for (; pos < len; pos += nhr.vol.sec_sz) {
			bb = calloc(1, sizeof(*bb));
			nhr_bb_off(bb) = pos;
			rbtree_insert(&nhr.bb_tree, &bb->tree);
		}
	}

exit:
	fclose(fp);

	return ret;
}
