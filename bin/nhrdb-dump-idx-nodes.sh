#!/bin/sh

DB=ntfsheurecovery.db
MFT_ENTNUM=
IDX_TYPE=

IDX_TYPE_MIN=0
IDX_TYPE_MAX=2

usage() {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery DB index nodes dump

Usage:
  $APPNAME -h
  $APPNAME [-D <database>] [-i <mft ent#>] [-t <idx type>]

Options:
  -D <database> Use <database> file as data source (def: $DB)
  -i <mft ent#> Dump only indexes of specified MFT entry
  -t <idx type> Dump only specified index type, see below
  -h            Print this help

Index types is:
  0 - directory files index (aka \$I30)
"
}

while getopts "hD:i:t:" OPT; do
	case "$OPT" in
	h)
		usage
		exit 0
		;;
	D) DB="$OPTARG";;
	i) MFT_ENTNUM=$OPTARG;;
	t) IDX_TYPE=$OPTARG;;
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
  t1.vcn as vcn_int,
  CASE t1.vcn
    WHEN -1 THEN '<R>'
    ELSE '#'||t1.vcn
  END AS vcn,
  lcn,
  CASE t1.parent
    WHEN -1 THEN '<R>'
    WHEN -2 THEN '<U>'
    WHEN -3 THEN '<N>'
    ELSE '#'||t1.parent
  END AS parent,
  case t1.level
    WHEN -1 THEN '-'
    ELSE t1.level
  END AS level,
  t1.flags,
  t1.bb_map, t1.bb_rec
FROM
  idx_nodes as t1
WHERE
  $Q_MFT_ENTNUM AND t1.type = $I
EOL
)

	[ -z "$Q" ] && Q="$Q_ITEM" || Q="$Q UNION ALL $Q_ITEM"
done

Q="SELECT * FROM ($Q) ORDER BY mft_entnum, type, vcn_int"

sqlite3 $DB "$Q" | awk -F '|' '
{
	printf "#%u type:%u  vcn:%-4s  lcn:0x%08X  parent:%-4s  level:%4s  flags:0x%02X  BB:0x%02X(0x%02X)\n", $1, $2, $4, $5, $6, $7, $8, $9, $10;
}
'
