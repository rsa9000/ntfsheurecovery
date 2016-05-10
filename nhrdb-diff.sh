#!/bin/sh

DEF_LDB=ntfsheurecovery-old.db
DEF_RDB=ntfsheurecovery.db

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery DB diff

Usage:
  $APPNAME -h
  $APPNAME [-l <left DB>] [-r <right DB>]

Options:
  -l <left DB>  Specify left database file for comparison (def: $DEF_LDB)
  -r <right DB> Specify right database file for comparison (def: $DEF_RDB)
  -h            Print this help
"
}

while getopts "hl:r:" OPT; do
	case "$OPT" in
	h)
		usage
		exit 0
		;;
	l) LDB="$OPTARG";;
	r) RDB="$OPTARG";;
	*) exit 1;;
	esac
done

[ -z "$LDB" ] && LDB=$DEF_LDB;
[ -z "$RDB" ] && RDB=$DEF_RDB;

if [ \! -f "$LDB" ]; then
	echo "No left database file $LDB" >&2
	exit 1;
fi

if [ \! -f "$RDB" ]; then
	echo "No right database file $RDB" >&2
	exit 1;
fi

case "$(uname -s)" in
	Linux )
		RE_WS="\<"
		RE_WE="\>"
		;;
	*BSD )
		RE_WS="[[:<:]]"
		RE_WE="[[:>:]]"
		;;
esac

Q_ATTACH="ATTACH DATABASE '$LDB' AS ldb;
ATTACH DATABASE '$RDB' AS rdb;"

TABLES="src idx_types param hints_classes hints_types hints cmap bb mft_entries mft_entries_fn mft_entries_oid data data_mp data_chunks data_segments mft_entries_attrs mft_entries_tree idx_nodes idx_entries idx_entries_dir idx_entries_sdh idx_entries_sii"

F_CMN_src="id"
F_DIFF_src="name desc"
F_SORT_src="id"

F_CMN_idx_types="id"
F_DIFF_idx_types="name desc"
F_SORT_idx_types="id"

F_CMN_param="name"
F_DIFF_param="val"
F_SORT_param="name"

F_CMN_hints_classes="id"
F_DIFF_hints_classes="name"
F_SORT_hints_classes="id"

F_CMN_hints_types="class id"
F_DIFF_hints_types="name"
F_SORT_hints_types="class id"

F_CMN_hints="mft_entnum class type cargs args"
F_DIFF_hints="val"
F_SORT_hints="mft_entnum class type"

F_CMN_cmap="off len"
F_DIFF_cmap="flags"
F_SORT_cmap="off"

F_CMN_bb="off"
F_DIFF_bb="flags entnum attr_type attr_id voff entity_idx"
F_SORT_bb="off"

F_CMN_mft_entries="num"
F_DIFF_mft_entries="f_cmn f_bad f_rec f_sum bb_map bb_rec parent parent_src base base_src seqno seqno_src t_create t_create_src t_change t_change_src t_mft t_mft_src t_access t_access_src fileflags fileflags_src sid sid_src"
F_SORT_mft_entries="num"

F_CMN_mft_entries_fn="num type"
F_DIFF_mft_entries_fn="attr_id src len name"
F_SORT_mft_entries_fn="num"

F_CMN_mft_entries_oid="num"
F_DIFF_mft_entries_oid="src obj_id birth_vol_id birth_obj_id domain_id"
F_SORT_mft_entries_oid="num"

F_CMN_data="mft_entnum pos"
F_DIFF_data="name flags sz_alloc sz_alloc_src sz_used sz_used_src sz_init sz_init_src"
F_SORT_data="mft_entnum pos"

F_CMN_data_mp="mft_entnum pos vcn"
F_DIFF_data_mp="lcn clen"
F_SORT_data_mp="mft_entnum pos"

F_CMN_data_chunks="mft_entnum pos voff"
F_DIFF_data_chunks="len src"
F_SORT_data_chunks="mft_entnum pos"

F_CMN_data_segments="mft_entnum pos firstvcn"
F_DIFF_data_segments="firstvcn_src lastvcn lastvcn_src attr_entnum attr_id"
F_SORT_data_segments="mft_entnum pos firstvcn"

F_CMN_mft_entries_attrs="num pos"
F_DIFF_mft_entries_attrs="src type id name entnum firstvcn entity_idx"
F_SORT_mft_entries_attrs="num pos"

F_CMN_mft_entries_tree="entry parent h"
F_DIFF_mft_entries_tree=""
F_SORT_mft_entries_tree="entry"

F_CMN_idx_nodes="mft_entnum type vcn"
F_DIFF_idx_nodes="lcn parent level flags bb_map bb_rec"
F_SORT_idx_nodes="mft_entnum type vcn"

F_CMN_idx_entries="mft_entnum type pos"
F_DIFF_idx_entries="container child voff"
F_SORT_idx_entries="mft_entnum type pos"

F_CMN_idx_entries_dir="mft_entnum mref name_type"
F_DIFF_idx_entries_dir="pos parent t_create t_change t_mft t_access alloc_sz used_sz flags reparse name_len name"
F_SORT_idx_entries_dir="mft_entnum"

F_CMN_idx_entries_sdh="mft_entnum hash id"
F_DIFF_idx_entries_sdh="pos voff len"
F_SORT_idx_entries_sdh="mft_entnum hash id"

F_CMN_idx_entries_sii="mft_entnum id"
F_DIFF_idx_entries_sii="hash pos voff len"
F_SORT_idx_entries_sii="mft_entnum id"

for TBL in $TABLES; do
	eval F_CMN='$F_CMN_'$TBL
	eval F_DIFF='$F_DIFF_'$TBL
	eval F_SORT='$F_SORT_'$TBL

	F_CMN1=$(echo "$F_CMN" | awk '{ print $1 }')
	F_L_CMN=$(echo "$F_CMN" | sed -re "s/($RE_WS[a-z0-9_]+$RE_WE)/, l.\1 AS \1/g;s/^, //")
	F_R_CMN=$(echo "$F_CMN" | sed -re "s/($RE_WS[a-z0-9_]+$RE_WE)/, r.\1 AS \1/g;s/^, //")

	if [ -n "$F_DIFF" ]; then
		F_L_DIFF=$(echo " $F_DIFF" | sed -re "s/($RE_WS[a-z0-9_]+$RE_WE)/l.\1/g;s/[[:space:]]+/, /g")
		F_R_DIFF=$(echo " $F_DIFF" | sed -re "s/($RE_WS[a-z0-9_]+$RE_WE)/r.\1/g;s/[[:space:]]+/, /g")
		W_DIFF=$(echo "$F_DIFF" | sed -re "s/($RE_WS[a-z0-9_]+$RE_WE)/(l.\1 IS NULL AND r.\1 NOT NULL OR l.\1 NOT NULL AND r.\1 IS NULL OR l.\1<>r.\1)/g;s/[)][[:space:]]+[(]/) OR (/g")
	else
		F_L_DIFF=
		F_R_DIFF=
		W_DIFF="1 = 0"
	fi

	F_SORT=$(echo "$F_SORT" | sed -re "s/[[:space:]]+/,/g")

	J=$(echo "$F_CMN" | sed -re "s/($RE_WS[a-z0-9_]+$RE_WE)/l.\1=r.\1/g;s/[[:space:]]+/ AND /g")

	Q_DEL="SELECT 'del' as op, $F_L_CMN $F_L_DIFF $F_R_DIFF FROM ldb.$TBL AS l LEFT  JOIN rdb.$TBL AS r ON $J WHERE r.$F_CMN1 IS NULL"
	Q_ADD="SELECT 'add' as op, $F_R_CMN $F_L_DIFF $F_R_DIFF FROM rdb.$TBL AS r LEFT  JOIN ldb.$TBL AS l ON $J WHERE l.$F_CMN1 IS NULL"
	Q_CHR="SELECT 'chr' as op, $F_L_CMN $F_L_DIFF $F_R_DIFF FROM ldb.$TBL AS l INNER JOIN rdb.$TBL AS r ON $J WHERE $W_DIFF"

	Q="${Q_ATTACH}
SELECT * FROM (
  ${Q_DEL}
  UNION ALL
  ${Q_ADD}
  UNION ALL
  ${Q_CHR}
) ORDER BY $F_SORT;"

	NCMN=$(echo $(echo $F_CMN | wc -w))
	NDIFF=$(echo $(echo $F_DIFF | wc -w))

	echo "$Q" | sqlite3 -header | awk -v TBL=$TBL -v NCMN=$NCMN -v NDIFF=$NDIFF -F '|' '
BEGIN {
	ltot = 0
	rtot = 0
	ls = 1 + NCMN + 1
	rs = ls + NDIFF
}
NR == 1 {
	HDR=$2
	for (i = 3; i <= NCMN + 1; ++i)
		HDR=sprintf("%s\t%s", HDR, $i);
	for (i = ls; i <= rs - 1; ++i)
		HDR=sprintf("%s\t%s", HDR, $i);
}
NR == 2 {
	printf "--- a/tbl_%s\n", TBL
	printf "+++ b/tbl_%s\n", TBL
}
NR > 1 {
	l = $1 != "add" ? 1 : 0;
	r = $1 != "del" ? 1 : 0;
	if (NR % 10 == 2) {
		l +=1
		r +=1
	}
	printf "@@ -%u,%u +%u,%u @@\n", ltot, l, rtot, r
	if (NR % 10 == 2)
		printf "  %s\n", HDR
	if ($1 != "add") {
		printf "- %s", $2;
		for (i = 3; i <= NCMN + 1; ++i)
			printf "\t%s", $i
		for (i = ls; i <= rs - 1; ++i)
			printf "\t%s", $i
		printf "\n"
	}
	if ($1 != "del") {
		printf "+ %s", $2;
		for (i = 3; i <= NCMN + 1; ++i)
			printf "\t%s", $i
		for (i = rs; i <= NF; ++i)
			printf "\t%s", $i
		printf "\n"
	}
	ltot += l
	rtot += r
}
'

done
