/**
 * On-disk NTFS $Secure structures
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

#ifndef _NTFS_STRUCT_SEC_H_
#define _NTFS_STRUCT_SEC_H_

#define NTFS_SEC_SDS_BLK_SZ		0x40000	/* 256KB $SDS mirror block sz */
#define NTFS_SEC_SDS_ALIGNTO		0x10	/* Entries alignment in $SDS */

/** Security identitifier (of user or group) */
struct ntfs_sec_sid {
/* 00 */uint8_t rev;		/* Revision */
/* 01 */uint8_t subauth_num;	/* Sub-authorities number */
/* 02 */uint8_t authority[6];	/* 48 bit long authority identifier in big-endian form */
/* 08 */uint32_t subauth[];	/* Sub-authorities array */
} __attribute__((packed));

#define NTFS_SEC_ACE_T_ALLOW	0x00	/* Access Allow */
#define NTFS_SEC_ACE_T_DENY	0x01	/* Access Deny */
#define NTFS_SEC_ACE_T_AUDIT	0x02	/* System Audit */
#define NTFS_SEC_ACE_T_ALARM	0x03	/* System Alarm */

#define NTFS_SEC_ACE_F_INH_OBJ		0x01	/* Object inherit ACE */
#define NTFS_SEC_ACE_F_INH_CONT		0x02	/* Container inherit ACE */
#define NTFS_SEC_ACE_F_INH_NOPROP	0x04	/* No propagete inherit ACE */
#define NTFS_SEC_ACE_F_INH_ONLY		0x08	/* Inherit only ACE */
#define NTFS_SEC_ACE_F_INHERITED	0x10	/* Inherited ACE */
#define NTFS_SEC_ACE_F_SUCCESSFUL	0x40	/* Audit successful access */
#define NTFS_SEC_ACE_F_FAILED		0x80	/* Audit failed access */

/** Access control entry (ACE) header */
struct ntfs_sec_ace {
/* 00 */uint8_t type;		/* ACE type, see NTFS_SEC_ACE_T_xxx */
/* 01 */uint8_t flags;		/* ACE flags, see NTFS_SEC_ACE_F_xxx */
/* 02 */uint16_t size;		/* ACE size */
/* 04 */uint8_t data[];		/* ACE data */
};

#define NTFS_SEC_ACE_NEXT(__ace)		\
		((struct ntfs_sec_ace *)((void *)__ace + (__ace)->size))

#define NTFS_SEC_ACE_M_READ_DATA	0x00000001	/* Read data (file) */
#define NTFS_SEC_ACE_M_LIST_DIR		0x00000001	/* List content (dir) */
#define NTFS_SEC_ACE_M_WRITE_DATA	0x00000002	/* Write data (file) */
#define NTFS_SEC_ACE_M_ADD_FILE		0x00000002	/* Add file (dir) */
#define NTFS_SEC_ACE_M_APPEND_DATA	0x00000004	/* Append data (file) */
#define NTFS_SEC_ACE_M_ADD_SUBDIR	0x00000004	/* Add subdir (dir) */
#define NTFS_SEC_ACE_M_READ_EA		0x00000008	/* Read ext attr (file & dir) */
#define NTFS_SEC_ACE_M_WRITE_EA		0x00000010	/* Write ext attr (file & dir) */
#define NTFS_SEC_ACE_M_EXECUTE		0x00000020	/* Execute (file) */
#define NTFS_SEC_ACE_M_TRAVERSE		0x00000020	/* Traverse (dir) */
#define NTFS_SEC_ACE_M_DELETE_CHILD	0x00000040	/* Delete child (dir) */
#define NTFS_SEC_ACE_M_READ_ATTR	0x00000080	/* Read attributes (file & dir) */
#define NTFS_SEC_ACE_M_WRITE_ATTR	0x00000100	/* Write attributes (file & dir) */

/** File ACE */
struct ntfs_sec_ace_file {
/* 00 */struct ntfs_sec_ace hdr;	/* ACE common header */
/* 04 */uint32_t mask;			/* Access mask, see NTFS_SEC_ACE_M_xxx */
/* 08 */struct ntfs_sec_sid sid;	/* SID */
};

#define NTFS_SEC_ACE_OBJ_F_TYPE		0x00000001	/* Object type present */
#define NTFS_SEC_ACE_OBJ_F_INH_TYPE	0x00000002	/* Inherited type present */

/** Object ACE */
struct ntfs_sec_ace_obj {
/* 00 */struct ntfs_sec_ace hdr;	/* ACE common header */
/* 04 */uint32_t mask;			/* Access mask, see NTFS_SEC_ACE_M_xxx */
/* 08 */uint32_t flags;			/* Object flags, see NTFS_SEC_ACE_OBJ_F_xxx */
/* 0C */struct ntfs_guid type;		/* Object type */
/* 1C */struct ntfs_guid inh_type;	/* Object inherited type */
/* 2C */struct ntfs_sec_sid sid;	/* SID */
};

/** Access control list (ACL) header */
struct ntfs_sec_acl {
/* 00 */uint8_t rev;		/* Revision */
/* 01 */uint8_t __pad1;
/* 02 */uint16_t size;		/* Allocated space */
/* 04 */uint16_t ace_num;	/* ACE(s) number */
/* 06 */uint16_t __pad2;
/* 08 */uint8_t data[];		/* ACE(s) area */
} __attribute__((packed));

#define NTFS_SEC_ACL_FIRST_ACE(__acl)		\
		((struct ntfs_sec_ace *)(__acl)->data)

#define NTFS_SEC_DESC_F_OWNER_DEF	0x0001	/* Owner is set by-default */
#define NTFS_SEC_DESC_F_GROUP_DEF	0x0002	/* Group is set by-default */
#define NTFS_SEC_DESC_F_DACL		0x0004	/* DACL is present */
#define NTFS_SEC_DESC_F_DACL_DEF	0x0008	/* DACL is set by-default */
#define NTFS_SEC_DESC_F_SACL		0x0010	/* SACL is present */
#define NTFS_SEC_DESC_F_SACL_DEF	0x0020	/* SACL is set by-default */
#define NTFS_SEC_DESC_F_DACL_NEED_INH	0x0100	/* DACL needs to be inherited */
#define NTFS_SEC_DESC_F_SACL_NEED_INH	0x0200	/* SACL needs to be inherited */
#define NTFS_SEC_DESC_F_DACL_INHERITED	0x0400	/* DACL is inherited */
#define NTFS_SEC_DESC_F_SACL_INHERITED	0x0800	/* SACL is inherited */
#define NTFS_SEC_DESC_F_DACL_PROTECTED	0x1000	/* DACL is protected */
#define NTFS_SEC_DESC_F_SACL_PROTECTED	0x2000	/* SACL is protected */

/** Security descriptor */
struct ntfs_sec_desc {
/* 00 */uint8_t rev;		/* Descriptor format revision */
/* 01 */uint8_t __pad;
/* 02 */uint16_t flags;		/* See NTFS_SEC_DESC_F_xxx */
/* 04 */uint32_t owner_off;	/* Offset to owner SID */
/* 08 */uint32_t group_off;	/* Offset to group SID */
/* 0C */uint32_t sacl_off;	/* Offset to System ACL */
/* 10 */uint32_t dacl_off;	/* Offset to Discretionary ACL */
} __attribute__((packed));

/** Security descriptor header */
struct ntfs_sec_desc_hdr {
/* 00 */uint32_t hash;		/* Descriptor hash */
/* 04 */uint32_t id;		/* Descriptor id */
/* 08 */uint64_t voff;		/* Descriptor offset inside $SDS data stream */
/* 10 */uint32_t len;		/* Descriptor length */
/* 14 */uint8_t data[];		/* Descriptor themself */
} __attribute__((packed));

#endif	/* _NTFS_STRUCT_SEC_H_ */
