#!/bin/sh

DB=ntfsheurecovery.db
IMG=

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery orphaned clusters digest generator

This script analyses DB clusters map and generates digest for each orphaned
cluster.

Usage:
  $APPNAME -h
  $APPNAME [-D <database>] <img>

Options:
  <img>         Partition image file (or device)
  -D <database> Use <database> file as data source (def: $DB)
  -h            Print this help
"
}

while getopts "hD:" OPT; do
	case "$OPT" in
	h)
		usage
		exit 0
		;;
	D) DB="$OPTARG";;
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
		MD5=$(dd if=$IMG bs=$VOL_CLS_SZ count=1 skip=$I 2>/dev/null | md5sum | sed -e "s/  -$//")
		echo $I: $MD5
	done
done
