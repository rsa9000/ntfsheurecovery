#!/bin/sh

DB=ntfsheurecovery.db
INODES=0

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery DB full patch constructor

Usage:
  $APPNAME -h
  $APPNAME [-i] [-D <database>] <MFT entry #>

Options:
  <MFT entry #> Number of MFT entry, which path should be reconstructed
  -D <database> Use <database> file as data source (def: $DB)
  -i            Print inodes (MFT entry number) for each path elements
  -h            Print this help
"
}

while getopts "hD:i" OPT; do
	case "$OPT" in
	h)
		usage
		exit 0
		;;
	D) DB="$OPTARG";;
	i) INODES=1;;
	*) exit 1;;
	esac
done

shift $(($OPTIND - 1))

if [ -z "$1" ]; then
	echo "MFT entry number not specified" >&2
	exit 1;
fi

if [ \! -f "$DB" ]; then
	echo "No database file $DB" >&2
	exit 1;
fi

NUM=$1
PARENT=0
FPATH=
while true; do
	Q="SELECT t1.parent, t2.name FROM mft_entries as t1, mft_entries_fn as t2 WHERE t1.num = t2.num AND t1.num = $NUM LIMIT 1"
	L=$(sqlite3 "$DB" "$Q")
	[ -z "$L" ] && break
	PARENT=$(echo "$L" | sed -e "s/|.*$//")
	NAME=$(echo "$L" | sed -e "s/^.*|//")
	[ $INODES -eq 1 ] && FPATH="($NUM)$FPATH"
	FPATH="/$NAME$FPATH"
	[ "$PARENT" -eq 5 -o "$PARENT" -eq 0 ] && break
	NUM=$PARENT
done

[ $PARENT -ne 5 ] && FPATH="???$FPATH"

echo $FPATH
