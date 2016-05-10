/**
 * MFT entry attributes handling interface
 *
 * Copyright (c) 2016, Sergey Ryazanov <ryazanov.s.a@gmail.com>
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

#ifndef _ATTR_H_
#define _ATTR_H_

#include "cache.h"

#define NHR_ATTR_F_UNIQ		0x01	/* Attribute should be unique */
#define NHR_ATTR_F_RESIDENT	0x02	/* Attribute should be resident */
#define NHR_ATTR_F_MANDATORY	0x04	/* Attribute is mandatory */

/**
 * Attribute info
 */
struct nhr_attr_info {
	unsigned type;		/* Attribute type */
	const char *title;	/* Attribute title */
	unsigned flags;		/* Attribute flags, see NHR_ATTR_F_xxx */
	int (*entity_bind)(struct nhr_mft_entry *mfte,
			   struct nhr_alist_item *ali);
	int (*entity_idx)(const struct nhr_mft_entry *mfte,
			  const void *entity);
	int (*entity_check)(const struct nhr_mft_entry *mfte,
			    const struct nhr_alist_item *ali);
	int (*recover_prerequisite)(const struct nhr_mft_entry *mfte,
				    const struct nhr_alist_item *ali);
	int (*recover_hdr)(const struct nhr_mft_entry *mfte,
			   const struct nhr_alist_item *ali,
			   struct ntfs_attr_hdr *attr);
	int (*recover_data)(const struct nhr_mft_entry *mfte,
			    const struct nhr_alist_item *ali,
			    struct ntfs_attr_hdr *attr, int size);
};

const struct nhr_attr_info *attr_get_info(unsigned type);
uint16_t attr_title2type(const char *title);
void attr_verify_all(void);

#endif	/* _ATTR_H_ */
