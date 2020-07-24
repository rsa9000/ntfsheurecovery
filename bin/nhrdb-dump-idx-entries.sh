#!/bin/sh

DB=ntfsheurecovery.db
MFT_ENTNUM=
IDX_TYPE=
PRINT_POS=0

IDX_TYPE_MIN=0
IDX_TYPE_MAX=2

Q_IDX0_TBL="idx_entries_dir"
Q_IDX0_KEY="(t2.mref & $((0xffffffffffff)))||':'||t2.name"
Q_IDX1_TBL="idx_entries_sdh"
Q_IDX1_KEY="printf('%08X', t2.hash & $((0xffffffff)))||':'||t2.id"
Q_IDX2_TBL="idx_entries_sii"
Q_IDX2_KEY="t2.id"

usage() {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery DB index entries dump

Usage:
  $APPNAME -h
  $APPNAME [-D <database>] [-i <mft ent#>] [-t <idx type>] [-p]

Options:
  -D <database> Use <database> file as data source (def: $DB)
  -i <mft ent#> Dump only indexes of specified MFT entry
  -t <idx type> Dump only specified index type, see below
  -p            Print position of each index entry
  -h            Print this help

Index types is:
  0 - directory files index (aka \$I30)
"
}

while getopts "hD:i:t:p" OPT; do
	case "$OPT" in
	h)
		usage
		exit 0
		;;
	D) DB="$OPTARG";;
	i) MFT_ENTNUM=$OPTARG;;
	t) IDX_TYPE=$OPTARG;;
	p) PRINT_POS=1;;
	*) exit 1;;
	esac
done

if [ -n "$MFT_ENTNUM" ]; then
	# Nice pure POSIX check
	# http://stackoverflow.com/questions/309745/check-that-a-variable-is-a-number-in-unix-shell
	case $MFT_ENTNUM in
		(*[!0-9]*|'') echo "Invalid MFT entry number: $MFT_ENTNUM" >&2; exit 1;;
	esac

	Q_MFT_ENTNUM="t1.mft_entnum = $MFT_ENTNUM"
else
	Q_MFT_ENTNUM="1 = 1"
fi

if [ -n "$IDX_TYPE" ]; then
	case $IDX_TYPE in
		(*[!0-9]*|'') echo "Invalid index type: $IDX_TYPE" >&2; exit 1;;
	esac

	if [ $IDX_TYPE -lt $IDX_TYPE_MIN -o $IDX_TYPE -gt $IDX_TYPE_MAX ]; then
		echo "Unknown index type: $IDX_TYPE" >&2
		exit 1;
	fi
fi

if [ \! -f "$DB" ]; then
	echo "No database file $DB" >&2
	exit 1;
fi

Q=
for I in $(seq $IDX_TYPE_MIN $IDX_TYPE_MAX); do
	[ -n "$IDX_TYPE" ] && [ $I -ne "$IDX_TYPE" ] && continue

	eval Q_IDX_TBL='$Q_IDX'$I'_TBL'
	eval Q_IDX_KEY='$Q_IDX'$I'_KEY'

	Q_ITEM=$(cat <<EOL
SELECT
  t1.mft_entnum,
  t1.type,
  t1.pos,
  CASE t1.container
    WHEN -1 THEN '<R>'
    WHEN -2 THEN '<U>'
    WHEN -3 THEN '<N>'
    ELSE '#'||t1.container
  END AS container,
  CASE t1.child
    WHEN -1 THEN '<R>'
    WHEN -2 THEN '<U>'
    WHEN -3 THEN '<N>'
    ELSE '#'||t1.child
  END AS child,
  CASE t1.voff
    WHEN -1 THEN '<U>'
    ELSE t1.voff
  END AS voff,
  ifnull($Q_IDX_KEY, '<end>') as key
FROM
  idx_entries as t1
LEFT JOIN
  $Q_IDX_TBL as t2
ON
  t1.mft_entnum = t2.mft_entnum AND t1.pos = t2.pos
WHERE
  $Q_MFT_ENTNUM AND t1.type = $I
EOL
)

	[ -z "$Q" ] && Q="$Q_ITEM" || Q="$Q UNION ALL $Q_ITEM"
done

Q="SELECT * FROM ($Q) ORDER BY mft_entnum, type, pos"

sqlite3 $DB "$Q" | awk -v PRINT_POS=$PRINT_POS -F '|' '
{
	if (PRINT_POS)
		printf "#%u type:%u  pos:%4u  node:%-4s  child:%-4s  voff:%4s  key:%s\n", $1, $2, $3, $4, $5, $6, $7, $8;
	else
		printf "#%u type:%u  node:%-4s  child:%-4s  voff:%4s  key:%s\n", $1, $2, $4, $5, $6, $7, $8;
}
'
