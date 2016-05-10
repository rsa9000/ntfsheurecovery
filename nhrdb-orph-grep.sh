#!/bin/sh

DB=ntfsheurecovery.db
IMG=
GREP_OPT=
PATTERN=

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery orphaned clusters full text search

This script analyses DB clusters map, search specified pattern in each
cluster and print number of pattern occurance per cluster.

Usage:
  $APPNAME -h
  $APPNAME [-D <database>] [-P] <img> <pattern>

Options:
  <img>         Partition image file (or device)
  <pattern>     Search pattern, which will be passed as-is to grep(1)
  -D <database> Use <database> file as data source (def: $DB)
  -P            Threat <pattern> as perl regular expression (useful for binary search)
  -h            Print this help
"
}

while getopts "hD:P" OPT; do
	case "$OPT" in
	h)
		usage
		exit 0
		;;
	D) DB="$OPTARG";;
	P) GREP_OPT="$GREP_OPT -P";;
	*) exit 1;;
	esac
done

shift $(($OPTIND - 1))

if [ -z "$1" ]; then
	echo "No partition image specified" >&2
	exit 1
else
	IMG=$1
fi

if [ -z "$2" ]; then
	echo "No search pattern specified" >&2
	exit 1
else
	PATTERN="$2"
fi

if [ \! -e "$IMG" ]; then
	echo "No such file $IMG" >&2
	exit 1
fi

if [ \! -f "$DB" ]; then
	echo "No database file $DB" >&2
	exit 1;
fi

Q="SELECT * FROM param"
PARAMS=$(sqlite3 $DB "$Q")
VOL_CLS_SZ=$(echo "$PARAMS" | awk -F '|' '$1 ~ /^vol_cls_sz$/ { print $2 }')

Q="SELECT off, len FROM cmap WHERE flags = 0"
sqlite3 $DB "$Q" | while read R; do
	F=$(echo "$R" | awk -F '|' '{ print $1 }')
	N=$(echo "$R" | awk -F '|' '{print $2}')
	L=$(($F + $N - 1))
	for I in $(seq $F $L); do
		NUM=$(dd if=$IMG bs=$VOL_CLS_SZ count=1 skip=$I 2>/dev/null | grep -ac $GREP_OPT "$PATTERN")
		[ $NUM -eq 0 ] && continue
		echo $I: $NUM
	done
done
