/**
 * NTFS struct dump routines interface
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

#ifndef _NTFS_DUMP_H_
#define _NTFS_DUMP_H_

const char *ntfs_time2str(const uint64_t time);
void ntfs_dump_logfile_rec(const char *ident,
			   struct ntfs_log_rec_hdr *rec, int deep);
void ntfs_dump_logfile_rec_short(const char *ident,
				 struct ntfs_log_rec_hdr *rec);
void ntfs_dump_logfile_rec_cmn(const char *ident,
			       struct ntfs_log_rec_cmn_hdr *rec,
			       int deep);
void ntfs_dump_logfile_rec_cmn_short(const char *ident,
				     struct ntfs_log_rec_cmn_hdr *rec);
void ntfs_dump_logfile_rec_page(const char *ident,
				struct ntfs_log_rec_pg_hdr *rpg);
void ntfs_dump_logfile_rec_page_short(const char *ident,
				      struct ntfs_log_rec_pg_hdr *rpg);
void ntfs_dump_logfile_client(const char *ident, struct ntfs_log_client *lc);
void ntfs_dump_logfile_rst(const char *ident, struct ntfs_log_rst *rst,
			   int deep);
void ntfs_dump_logfile_rst_page(const char *ident,
				struct ntfs_log_rst_pg_hdr *rpg, int deep);
void ntfs_dump_sec_ace_file(const char *ident,
			    const struct ntfs_sec_ace_file *ace);
void ntfs_dump_sec_ace(const char *ident, const struct ntfs_sec_ace *ace,
		       int deep);
void ntfs_dump_sec_acl(const char *ident, const struct ntfs_sec_acl *acl,
		       int deep);
void ntfs_dump_sec_desc(const char *ident, const struct ntfs_sec_desc *sd,
			int deep);
void ntfs_dump_sec_desc_hdr(const char *ident,
			    const struct ntfs_sec_desc_hdr *sdh, int deep);
void ntfs_dump_sec_desc_hdr_short(const char *ident,
				  const struct ntfs_sec_desc_hdr *sdh);

#endif	/* _NTFS_DUMP_H_ */
