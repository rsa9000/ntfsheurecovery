/**
 * On-disk NTFS data structures
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

#ifndef _NTFS_STRUCT_H_
#define _NTFS_STRUCT_H_

/**
 * Since there are no full official documentation, following descriptions
 * is the compilation from several sources:
 * - Brian Carrier File System Forensic Analysis
 * - How NTFS works: Local File Systems (https://technet.microsoft.com/en-us/library/cc781134(v=ws.10).aspx)
 * - NTFS-3G header files
 * - documentation from https://flatcap.org/linux-ntfs/ntfs/index.html
 * - documentation from http://ntfs.com/ntfs.htm
 * - OpenNT headers files (http://www.opennt.net/projects/opennt/repository/show/trunk/base/fs/ntfs)
 */

#include <stdint.h>

/* Most of the NTFS on disk structures should be aligned */
#define NTFS_ALIGNTO	8
#define NTFS_ALIGN(__v)	((__v + NTFS_ALIGNTO - 1) & ~(NTFS_ALIGNTO - 1))

#include "ntfs_struct_cmn.h"
#include "ntfs_struct_sec.h"
#include "ntfs_struct_mft.h"
#include "ntfs_struct_idx.h"
#include "ntfs_struct_log.h"
#include "ntfs_struct_misc.h"

#endif	/* _NTFS_STRUCT_H_ */
