#!/bin/sh

DB=ntfsheurecovery.db
OFF=0
LEN=
IMG=

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery orphaned clusters partial digest generator

This script analyses DB clusters map and generates digest for specified part
of each orphaned cluster.

Usage:
  $APPNAME -h
  $APPNAME [-D <database>] [-o <off>] [-l <len>] <img>

Options:
  <img>         Partition image file (or device)
  -o <off>      Start digest generation at <off> bytes offset
  -l <len>      Generate digest only for <len> bytes
  -D <database> Use <database> file as data source (def: $DB)
  -h            Print this help
"
}

while getopts "hD:o:l:" OPT; do
	case "$OPT" in
	h)
		usage
		exit 0
		;;
	D) DB="$OPTARG";;
	o) OFF="$OPTARG";;
	l) LEN="$OPTARG";;
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

if [ $OFF -ge $VOL_CLS_SZ ]; then
	echo "Offset $OFF is greater than cluster size $VOL_CLS_SZ"
	exit 1
fi

if [ -z "$LEN" ]; then
	LEN=$(($VOL_CLS_SZ - $OFF))
elif [ $(($OFF + $LEN)) -gt $VOL_CLS_SZ ]; then
	echo "Specified region is greater than cluster size"
	exit 1
fi

Q="SELECT off, len FROM cmap WHERE flags = 0"
sqlite3 $DB "$Q" | while read R; do
	F=$(echo "$R" | awk -F '|' '{ print $1 }')
	N=$(echo "$R" | awk -F '|' '{print $2}')
	L=$(($F + $N - 1))
	for I in $(seq $F $L); do
		MD5=$(dd if=$IMG bs=$VOL_CLS_SZ count=1 skip=$I 2>/dev/null | dd bs=1 skip=$OFF count=$LEN 2>/dev/null | md5sum | sed -e "s/  -$//")
		echo $I: $MD5
	done
done
