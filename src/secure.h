/**
 * NTFS $Secure file related functions interface
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

#ifndef _SECURE_H_
#define _SECURE_H_

typedef int (* secure_sds_cb_t)(uint64_t voff,
				const struct ntfs_sec_desc_hdr *sdh,
				void *priv);

void secure_sds_recover(void);
int secure_sds_foreach_cb(const struct ntfs_mp *mpl,
			  const struct nhr_cmask_elem *bb_mask,
			  const uint64_t sds_len,
			  secure_sds_cb_t cb, void *cb_priv);

#endif	/* _SECURE_H_ */
