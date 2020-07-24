/**
 * MFT analysis code interface
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

#ifndef _MFT_ANALYZE_H_
#define _MFT_ANALYZE_H_

void mft_analyze_fname_parse(const void *buf, const unsigned len,
			     enum nhr_info_src src,
			     struct nhr_mft_entry *mfte);
void mft_analyze_i30_node_parse(const void *buf, size_t len);
void mft_analyze_all(void);
int mft_entry_attr2cache(struct nhr_mft_entry *mfte);
int mft_fetch_data_info(struct nhr_mft_entry *bmfte, unsigned name_len,
			const uint8_t *name);

#endif	/* _MFT_ANALYZE_H_ */
