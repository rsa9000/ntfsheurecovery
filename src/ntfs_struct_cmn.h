/**
 * On-disk NTFS common structures
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

#ifndef _NTFS_STRUCT_CMN_H_
#define _NTFS_STRUCT_CMN_H_

/**
 * Common header for many NTFS on disk structure
 *
 * USA is Update Sequence Array - the technic of multisector structures
 * integrity validation.
 */
struct ntfs_record {
/* 00 */char magic[4];
/* 04 */uint16_t usa_off;	/* Array position offset */
/* 06 */uint16_t usa_len;	/* Array length (in elements) */
} __attribute__((packed));

/**
 * Update Sequence Array
 *
 * USA always have USN as first element, so define this structure to facilitate
 * handling
 */
struct ntfs_usa {
/* 00 */uint16_t usn;	/* Update sequnce number */
/* 02 */uint16_t sec[];	/* Per-sector replaced data */
} __attribute__((packed));

/**
 * GUID is the Microsoft's reinvention of UUID
 *
 * First tree parts are stored in little endian form,
 * two last parts stored as-is.
 */
struct ntfs_guid {
/* 00 */uint32_t p1;
/* 04 */uint16_t p2;
/* 06 */uint16_t p3;
/* 08 */uint8_t p4[2];
/* 0A */uint8_t p5[6];
} __attribute__((packed));

/* NB: does not include trailing zero */
#define NTFS_GUID_STR_LEN	36

/* Ticks per second (for timestamp fields) */
#define NTFS_TICKS_PER_SEC		10000000LLU

#endif	/* _NTFS_STRUCT_CMN_H_ */
