/**
 * On-disk NTFS misc structures
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

#ifndef _NTFS_STRUCT_MISC_H_
#define _NTFS_STRUCT_MISC_H_

/**
 * Total structure size should be 512 octets.
 */
struct ntfs_boot {
/* 00 */uint8_t jump[3];	/* Jump instruction */
/* 03 */uint8_t oemname[8];	/* OEM name: "NTFS    " */
/* 0B */uint16_t bytes_per_sect;/* Bytes per sector */
/* 0D */uint8_t sect_per_clust;	/* Sectors per cluster */
/* 0E */uint16_t reserved_sect;	/* Should be zero */
/* 10 */uint8_t reserved1[5];	/* Should be zero */
/* 15 */uint8_t media_type;	/* Disk descriptor */
/* 16 */uint8_t reserved2[2];	/* Should be zero */
/* 18 */uint8_t reserved3[8];	/* Not checked */
/* 20 */uint8_t reserved4[4];	/* Should be zero */
/* 24 */uint8_t reserved5[4];	/* Not checked */
/* 28 */uint64_t sectors_num;	/* Total sectors number */
/* 30 */uint64_t mft_offset;	/* MFT first cluster offset */
/* 38 */uint64_t mftmirr_offset;/* MFT mirror offset */
/* 40 */int8_t mft_entry_size;	/* Item MFT entry size */
/* 41 */uint8_t reserved6[3];	/* Not used */
/* 44 */int8_t idx_record_size;	/* Item index record size */
/* 45 */uint8_t reserved7[3];	/* Not used */
/* 48 */uint64_t serial;	/* Volume serial number */
/* 50 */uint8_t reserved8[4];	/* Not used */
/* 54 */uint8_t bootcode[426];
/*1FE */uint16_t magic;		/* 0xAA55 magic */
} __attribute__((packed));

#endif	/* _NTFS_STRUCT_MISC_H_ */
