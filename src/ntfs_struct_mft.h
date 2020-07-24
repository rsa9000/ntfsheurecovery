/**
 * On-disk NTFS MFT structures
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

#ifndef _NTFS_STRUCT_MFT_H_
#define _NTFS_STRUCT_MFT_H_

/**
 * MFT entries numbers reserved for system (FS) files
 */
enum ntfs_entnum_system {
	NTFS_ENTNUM_MFT = 0,	/* $MFT - main file table */
	NTFS_ENTNUM_MFTMIRR = 1,/* $MFTMirr - MFT first entries mirror */
	NTFS_ENTNUM_LOGFILE = 2,/* $LogFile - FS operations log */
	NTFS_ENTNUM_VOLUME = 3,	/* $Volume - volume description */
	NTFS_ENTNUM_ATTRDEF = 4,/* $AttrDef - attributes info */
	NTFS_ENTNUM_ROOT = 5,	/* . - FS root */
	NTFS_ENTNUM_BITMAP = 6,	/* $Bitmap - clusters allocation bitmap */
	NTFS_ENTNUM_BOOT = 7,	/* $Boot - bootsector */
	NTFS_ENTNUM_BADCLUS = 8,/* $BadClus - bad clusters */
	NTFS_ENTNUM_SECURE = 9,	/* $Secure - security descriptors */
	NTFS_ENTNUM_UPCASE = 10,/* $UpCase - Unicode uppercase table */
	NTFS_ENTNUM_EXTEND = 11,/* $Extend - directory for other sys files */
				/* Reserved (unused) entry numbers */
	NTFS_ENTNUM_USER = 16,	/* First user's entry number */
};

#define NTFS_MFT_ENTRY_F_INUSE	0x0001	/* Entry is in use */
#define NTFS_MFT_ENTRY_F_DIR	0x0002	/* Entry is directory ($I30 index) */
#define NTFS_MFT_ENTRY_F_EXTEND	0x0004	/* Entry is from $Extend dir */
#define NTFS_MFT_ENTRY_F_VIEW	0x0008	/* Entry contains non $I30 index */

struct ntfs_mft_entry {
/* 00 */struct ntfs_record r;	/* Should contains "FILE" magic signature */
/* 08 */uint64_t lsn;
/* 10 */uint16_t seqno;
/* 12 */uint16_t linksno;
/* 14 */uint16_t attr_off;
/* 16 */uint16_t flags;
/* 18 */uint32_t used_sz;
/* 1C */uint32_t allocated_sz;
/* 20 */uint64_t base;		/* Includes base entry seqno and number */
/* 28 */uint16_t attr_next_id;
} __attribute__((packed));

/**
 * Extended MFT header
 *
 * MS NTFS driver uses space after main header to store low part of MFT entry
 * number.
 *
 * Missing this info is not critical from chkdsk point of view and I don't know
 * which version of the driver really write it and which is not so utility only
 * write it during MFT entry regeneration and never read or check this field.
 */
struct ntfs_mft_entry_ext {
/* 00 */struct ntfs_mft_entry cmn;
/* 2A */uint16_t __padding;
/* 2C */uint32_t entnumlo;	/* Low 32-bits of MFT entry number */
} __attribute__((packed));

#define NTFS_MREF_SEQNO_M		0xFFFFULL
#define NTFS_MREF_SEQNO_S		48
#define NTFS_MREF_ENTNUM_M		0x0000FFFFFFFFFFFFULL
#define NTFS_MREF_SEQNO(__val)		\
		(((__val) >> NTFS_MREF_SEQNO_S) & NTFS_MREF_SEQNO_M)
#define NTFS_MREF_ENTNUM(__val)		\
		((__val) & NTFS_MREF_ENTNUM_M)
#define NTFS_MREF_MAKE(__seqno, __entnum)\
		(((uint64_t)((__seqno) & NTFS_MREF_SEQNO_M)) << NTFS_MREF_SEQNO_S | \
		 ((__entnum) & NTFS_MREF_ENTNUM_M))

/** Mapping pair header */
struct ntfs_mp_hdr {
	uint8_t mp_len_sz:4;
	uint8_t mp_off_sz:4;
} __attribute__((packed));

#define NTFS_ATTR_STDINF	0x00000010	/* $STANDARD_INFORMATION */
#define NTFS_ATTR_ALIST		0x00000020	/* $ATTRIBUTE_LIST */
#define NTFS_ATTR_FNAME		0x00000030	/* $FILE_NAME */
#define NTFS_ATTR_OID		0x00000040	/* $OBJECT_ID */
#define NTFS_ATTR_SDESC		0x00000050	/* $SECURITY_DESCRIPTOR */
#define NTFS_ATTR_VNAME		0x00000060	/* $VOLUME_NAME */
#define NTFS_ATTR_VINFO		0x00000070	/* $VOLUME_INFORMATION */
#define NTFS_ATTR_DATA		0x00000080	/* $DATA */
#define NTFS_ATTR_IROOT		0x00000090	/* $INDEX_ROOT */
#define NTFS_ATTR_IALLOC	0x000000a0	/* $INDEX_ALLOCATION */
#define NTFS_ATTR_BITMAP	0x000000b0	/* $BITMAP */
#define NTFS_ATTR_RPOINT	0x000000c0	/* $REPARSE_POINT */
#define NTFS_ATTR_LUS		0x00000100	/* $LOGGED_UTILITY_STREAM */
#define NTFS_ATTR_END		0xffffffff

#define NTFS_ATTR_F_COMP	0x0001	/* Compressed */
#define NTFS_ATTR_F_ENC		0x4000	/* Encrypted */
#define NTFS_ATTR_F_SPAR	0x8000	/* Sparse */

#define NTFS_ATTR_RF_IDX	0x0001	/* Attribute is in index */

struct ntfs_attr_hdr {
/* 00 */uint32_t type;
/* 04 */uint32_t size;
	int __min_hdr_end[0];	/* End of minimal header marker */
/* 08 */uint8_t nonresident;
/* 09 */uint8_t name_len;
/* 0A */uint16_t name_off;
/* 0C */uint16_t flags;
/* 0E */uint16_t id;
	int __cmn_hdr_end[0];	/* End of common header marker */
	union {
		struct {
/* 10 */		uint32_t data_sz;
/* 14 */		uint16_t data_off;
/* 16 */		uint8_t rflags;		/* Resident flags */
/* 17 */		uint8_t __padding;
/* 18 */		int __resident_hdr_end[0];/* End of resident hdr marker */
		} __attribute__((packed));
		struct {
/* 10 */		uint64_t firstvcn;
/* 18 */		uint64_t lastvcn;
/* 20 */		uint16_t mp_off;	/* Mapping pair off */
/* 22 */		uint16_t cblk_sz;	/* Comp block size */
/* 24 */		uint8_t reserved[4];
/* 28 */		uint64_t alloc_sz;	/* Virtual allocated space (match
						   allocated disk space for
						   non-compressed streams) */
/* 30 */		uint64_t used_sz;	/* EndOfFile marker position */
/* 38 */		uint64_t init_sz;	/* Initialized aka valid data size */
/* 40 */		uint64_t comp_sz;	/* Compressed size (actual ammount of
						   allocated disk space). Exists only
						   if compressed flag is set and
						   if firstvcn == 0 */
/* 48 */		int __nonresident_hdr_end[0];/* End of non-resident hdr marker */
		} __attribute__((packed));
	} __attribute__((packed));
} __attribute__((packed));

#define NTFS_ATTR_HDR_MIN_LEN	\
		__builtin_offsetof(struct ntfs_attr_hdr, __min_hdr_end)
#define NTFS_ATTR_HDR_COMMON_LEN	\
		__builtin_offsetof(struct ntfs_attr_hdr, __cmn_hdr_end)
#define NTFS_ATTR_HDR_RESIDENT_LEN	\
		__builtin_offsetof(struct ntfs_attr_hdr, __resident_hdr_end)
#define NTFS_ATTR_HDR_NONRESIDENT_LEN	\
		__builtin_offsetof(struct ntfs_attr_hdr, __nonresident_hdr_end)
#define NTFS_ATTR_NAME(__attr)		((void *)(__attr) + (__attr)->name_off)
#define NTFS_ATTR_RDATA(__attr)		\
		((void *)__attr + (__attr)->data_off)
#define NTFS_ATTR_MPL(__attr)		\
		((void *)__attr + (__attr)->mp_off)

#define NTFS_FILE_F_READONLY	0x0001		/* Readonly file */
#define NTFS_FILE_F_HIDDEN	0x0002		/* File hidden */
#define NTFS_FILE_F_SYSTEM	0x0004		/* System file */
#define NTFS_FILE_F_ARCHIVE	0x0020		/* Archive file */
#define NTFS_FILE_F_DEVICE	0x0040		/* Device file */
#define NTFS_FILE_F_NORMAL	0x0080		/* Normal (regular) file */
#define NTFS_FILE_F_TMP		0x0100		/* Temporary file */
#define NTFS_FILE_F_SPARSE	0x0200		/* Sparse file */
#define NTFS_FILE_F_RPOINT	0x0400		/* Reparse point */
#define NTFS_FILE_F_COMP	0x0800		/* Compressed file */
#define NTFS_FILE_F_OFFLINE	0x1000		/* Offline? */
#define NTFS_FILE_F_NOIDX	0x2000		/* File content not indexed */
#define NTFS_FILE_F_ENC		0x4000		/* Encrypted file */
#define NTFS_FILE_F_IDX_I30	0x10000000	/* Entry contains directory ($I30) index */
#define NTFS_FILE_F_IDX_VIEW	0x20000000	/* Entry contains view index */
#define NTFS_FILE_F_IDX_M	(NTFS_FILE_F_IDX_I30 | NTFS_FILE_F_IDX_VIEW)

struct ntfs_attr_stdinf {
/* 00 */uint64_t time_create;	/* File creation time */
/* 08 */uint64_t time_change;	/* File modification time */
/* 10 */uint64_t time_mft;	/* MFT modification time */
/* 18 */uint64_t time_access;	/* File access time */
/* 20 */uint32_t flags;		/* File flags */
/* 24 */uint32_t ver_max;	/* Maximum allowed version */
/* 28 */uint32_t ver_num;	/* File version number */
/* 2C */uint32_t class_id;
/* 30 */uint32_t owner_id;
/* 34 */uint32_t security_id;
/* 38 */uint64_t quotta;
/* 40 */uint64_t usn;		/* Update sequence number */
};

struct ntfs_attr_alist_item {
/* 00 */uint32_t type;		/* Attribute type */
/* 04 */uint16_t size;		/* Item size */
/* 06 */uint8_t name_len;	/* Attribute name length */
/* 07 */uint8_t name_off;	/* Attribute name offset */
/* 08 */uint64_t firstvcn;	/* First VCN */
/* 10 */uint64_t mref;		/* MFT entry, which contains this attr */
/* 18 */uint16_t id;		/* Attribute instance */
} __attribute__((packed));

#define NTFS_ATTR_ALI_NAME(__ali)	((void *)(__ali) + (__ali)->name_off)

#define NTFS_FNAME_T_POSIX	0		/* Posix file name */
#define NTFS_FNAME_T_WIN32	1		/* Win32 file name */
#define NTFS_FNAME_T_DOS	2		/* DOS file name */
#define NTFS_FNAME_T_WIN32DOS	3		/* Name suitable for Win32 & DOS */
#define NTFS_FNAME_T_MAX	3		/* Maximum possible name type value */

struct ntfs_attr_fname {
/* 00 */uint64_t parent;	/* Parent directory entry */
/* 08 */uint64_t time_create;	/* File creation time */
/* 10 */uint64_t time_change;	/* File modification time */
/* 18 */uint64_t time_mft;	/* MFT modification time */
/* 20 */uint64_t time_access;	/* File access time */
/* 28 */uint64_t alloc_sz;	/* File allocated size */
/* 30 */uint64_t used_sz;	/* File real size */
/* 38 */uint32_t flags;		/* File flags */
/* 3C */uint32_t reparse_point;	/* Reparse point */
/* 40 */uint8_t name_len;	/* Filename length */
/* 41 */uint8_t name_type;	/* Filename type */
/* 42 */uint8_t name[];		/* File name array */
} __attribute__((packed));

#define NTFS_ATTR_FNAME_LEN(__fn)	(sizeof(*(__fn)) + (__fn)->name_len * 2)

struct ntfs_attr_oid {
/* 00 */struct ntfs_guid obj_id;
	int __min_len[0];
/* 10 */struct ntfs_guid birth_obj_id;
/* 20 */struct ntfs_guid birth_vol_id;
/* 30 */struct ntfs_guid domain_id;
} __attribute__((packed));

#define NTFS_ATTR_OID_MIN_LEN	\
		__builtin_offsetof(struct ntfs_attr_oid, __min_len)

struct ntfs_attr_iroot {
/* 00 */uint32_t idx_attr;	/* Which attribute is indexed */
/* 04 */uint32_t idx_sort;	/* Sorting rule */
/* 08 */uint32_t idx_blk_sz;	/* Index block size, bytes */
/* 0C */int8_t idx_blk_csz;	/* Index block size, clusters */
/* 0D */uint8_t reserved[3];	/* Alignment */
/* 10 */uint8_t data[];
} __attribute__((packed));

#endif	/* _NTFS_STRUCT_MFT_H_ */
