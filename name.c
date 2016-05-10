/**
 * Filenames handling functions
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
#include <inttypes.h>

#include "ntfsheurecovery.h"
#include "cache.h"
#include "misc.h"
#include "name.h"

/** Verify filenames set of item file (MFT entry) */
static int name_verify_mfte(const struct nhr_mft_entry *mfte)
{
	const struct nhr_mfte_fn *fn;

	if (mfte->names[NTFS_FNAME_T_POSIX].src != NHR_SRC_NONE) {
		if (nhr.verbose >= 3) {
			fn = &mfte->names[NTFS_FNAME_T_POSIX];
			printf("name[#%"PRIu64"]: got unexpected POSIX name %ls\n",
			       nhr_mfte_num(mfte),
			       name2wchar(fn->name, fn->len));
		}
		return -1;
	} else if (mfte->names[NTFS_FNAME_T_WIN32DOS].src != NHR_SRC_NONE) {
		if (mfte->names[NTFS_FNAME_T_WIN32].src != NHR_SRC_NONE) {
			if (nhr.verbose >= 3) {
				fn = &mfte->names[NTFS_FNAME_T_WIN32];
				printf("name[#%"PRIu64"]: got odd WIN32 name %ls\n",
				       nhr_mfte_num(mfte),
				       name2wchar(fn->name, fn->len));
			}
			return -1;
		}
		if (mfte->names[NTFS_FNAME_T_DOS].src != NHR_SRC_NONE) {
			if (nhr.verbose >= 3) {
				fn = &mfte->names[NTFS_FNAME_T_DOS];
				printf("name[#%"PRIu64"]: got odd DOS name %ls\n",
				       nhr_mfte_num(mfte),
				       name2wchar(fn->name, fn->len));
			}
			return -1;
		}
	} else if (mfte->names[NTFS_FNAME_T_WIN32].src != NHR_SRC_NONE) {
		if (mfte->names[NTFS_FNAME_T_DOS].src == NHR_SRC_NONE) {
			if (nhr.verbose >= 3) {
				fn = &mfte->names[NTFS_FNAME_T_WIN32];
				printf("name[#%"PRIu64"]: no corresponding DOS name for WIN32 name %ls\n",
				       nhr_mfte_num(mfte),
				       name2wchar(fn->name, fn->len));
			}
			return -1;
		}
	} else if (mfte->names[NTFS_FNAME_T_DOS].src != NHR_SRC_NONE) {
		if (nhr.verbose >= 3) {
			fn = &mfte->names[NTFS_FNAME_T_DOS];
			printf("name[#%"PRIu64"]: no corresponding WIN32 name for DOS name %ls\n",
			       nhr_mfte_num(mfte),
			       name2wchar(fn->name, fn->len));
		}
		return -1;
	} else {
		if (nhr.verbose >= 3)
			printf("name[#%"PRIu64"]: no filename\n",
			       nhr_mfte_num(mfte));
		return -1;
	}

	return 0;
}

void name_verify_all(void)
{
	struct nhr_mft_entry *mfte;
	unsigned cnt_tot = 0, cnt_ok = 0;
	int res;

	if (nhr.verbose >= 1)
		printf("name: verify filenames\n");

	rbt_inorder_walk_entry(mfte, &nhr.mft_cache, tree) {
		if (!(mfte->f_cmn & NHR_MFT_FC_BASE))	/* Only base entries */
			continue;
		if (!(mfte->f_sum & NHR_MFT_FB_SELF))	/* Only corrupted */
			continue;
		cnt_tot++;
		res = name_verify_mfte(mfte);
		if (!res) {
			cnt_ok++;
			mfte->names_valid = 1;
		}
	}

	if (nhr.verbose >= 1)
		printf("name: checked %u MFT entries, %u of them is valid\n",
		       cnt_tot, cnt_ok);
}
