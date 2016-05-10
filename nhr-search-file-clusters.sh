#!/bin/sh

DIG=orph-clusters.dig
CLS_SZ=4096
IMG=

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery file clusters detector

Find file clusters within orphaned clusters list by its digest.

Usage:
  $APPNAME -h
  $APPNAME [-D <digfile>] [-C <clssz>] [-i <img>] <needle>

Options:
  <needle>      Needle file, which clusters should be detected
  -D <digfile>  Use <digfile> as cluster digests source (def: $DIG)
  -C <clssz>    Assume, that cluster is <clssz> bytes (def: $CLS_SZ)
  -i <img>      Use <img> file as filesystem image, when search not fully
                filled last file cluster
  -h            Print this help
"
}

while getopts "hD:C:i:" OPT; do
	case "$OPT" in
	h)
		usage
		exit 0
		;;
	D) DIG="$OPTARG";;
	C) CLS_SZ="$OPTARG";;
	i) IMG="$OPTARG";;
	*) exit 1;;
	esac
done

shift $(($OPTIND - 1))

if [ -z "$1" ]; then
	echo "Needle file is not specified" >&2
	exit 1
else
	FILE="$1"
fi

if [ \! -f "$FILE" ]; then
	echo "Needle file does not exits: $FILE" >&2
	exit 1
fi

if [ \! -f "$DIG" ]; then
	echo "Clusters digest file does not exits: $DIG" >&2
	exit 1
fi

if [ -n "$IMG" -a \! -e "$IMG" ]; then
	echo "Specified image file not exists: $IMG" >&2
	exit 1
fi

case "$(uname -s)" in
	Linux )
		MD5CMD="md5sum"
		FILE_SIZE=$(stat -c "%s" "$FILE");;
	*BSD )
		MD5CMD="md5 -r"
		FILE_SIZE=$(stat -f "%z" "$FILE");;
esac

if [ -z "$FILE_SIZE" ]; then
	echo "Could not detects needle file size"
	exit 1
fi

MD5=$($MD5CMD "$FILE" | sed -e "s/ .*$//")
echo "File digest: $MD5"

if [ $(($FILE_SIZE % $CLS_SZ)) -ne 0 -a -z "$IMG" ]; then
	OFF=$((($FILE_SIZE / $CLS_SZ) * $CLS_SZ))
	LEN=$(($FILE_SIZE - $OFF))
	MD5=$(dd if="$FILE" bs=1 count=$LEN skip=$OFF 2>/dev/null | $MD5CMD | sed -e "s/  [-]$//")
	echo "Warn: file size is not multiple of cluster size, last cluster ($LEN bytes, digest: $MD5) will not be detected"
fi

if [ $FILE_SIZE -lt $CLS_SZ ]; then
	echo "Warn: file size ($FILE_SIZE) is less then cluster size. Exiting"
	exit
fi

CLS_LIST=
LAST_CLS=0
for I in $(seq 0 $(($FILE_SIZE / $CLS_SZ - 1))); do
	MD5=$(dd if="$FILE" bs=$CLS_SZ count=1 skip=$I 2>/dev/null | $MD5CMD | sed -e "s/  [-]$//")
	CLS="$(grep "$MD5" "$DIG" | sed -nre 's/^([0-9]+)[:] .*$/\1/p')"
	NUM=$(echo "$CLS" | grep -v '^$' | wc -l)
	if [ $NUM -gt 1 ]; then
		echo Warn: digest $MD5 for file cluster $I was find $NUM times in clusters: $CLS
		echo "$CLS" | grep -q "\<$(($LAST_CLS + 1))\>" && {
			CLS=$(($LAST_CLS + 1))
		} || {
			CLS=$(echo "$CLS" | head -n1)
		}
	elif [ $NUM -eq 0 ]; then
		echo Warn: digest $MD5 for file cluster $I was not found
		CLS=XXX
	fi
	[ "$CLS" != "XXX" ] && LAST_CLS=$CLS || LAST_CLS=$(($LAST_CLS + 1))
	CLS_LIST="$CLS_LIST $CLS"
done

if [ $(($FILE_SIZE % $CLS_SZ)) -ne 0 -a -n "$IMG" ]; then
	OFF=$((($FILE_SIZE / $CLS_SZ) * $CLS_SZ))
	LEN=$(($FILE_SIZE - $OFF))
	FILE_MD5=$(dd if="$FILE" bs=1 count=$LEN skip=$OFF 2>/dev/null | $MD5CMD | sed -e "s/  [-]$//")
	CLS=$(($LAST_CLS + 1))
	CLS_MD5=$(dd if="$IMG" bs=$CLS_SZ count=1 skip=$CLS 2>/dev/null | dd bs=1 count=$LEN 2>/dev/null | $MD5CMD | sed -e "s/  [-]$//")
	if [ "$FILE_MD5" != "$CLS_MD5" ]; then
		echo "Warn: digest $FILE_MD5 for last file cluster $(($I + 1)) (used $LEN bytes) was not found"
		CLS_LIST="$CLS_LIST XXX"
	else
		CLS_LIST="$CLS_LIST $CLS"
	fi
fi

BLK_VSTART=0
BLK_LSTART=$(echo $CLS_LIST | sed -re "s/^(XXX|[0-9]+).*$/\1/")
BLK_LEN=0
LCN_BLK=
VCN=1
for LCN in $(echo $CLS_LIST | sed -re "s/^(XXX|[0-9]+)//"); do
	if [ "$LCN" == "XXX" ]; then
		if [ "$BLK_LSTART" != "XXX" ]; then
			LCN_BLK=$BLK_LSTART
			[ $BLK_LEN -gt 0 ] && LCN_BLK=$LCN_BLK-$(($BLK_LSTART + $BLK_LEN))
		fi
	else
		if [ "$BLK_LSTART" == "XXX" ]; then
			LCN_BLK=XXX
			[ $BLK_LEN -gt 0 ] && LCN_BLK=$LCN_BLK-XXX
		elif [ $LCN -ne $(($BLK_LSTART + $BLK_LEN + 1)) ]; then
			LCN_BLK=$BLK_LSTART
			[ $BLK_LEN -gt 0 ] && LCN_BLK=$LCN_BLK-$(($BLK_LSTART + $BLK_LEN))
		fi
	fi

	if [ -n "$LCN_BLK" ]; then
		VCN_BLK=$BLK_VSTART
		[ $BLK_LEN -gt 0 ] && VCN_BLK=$VCN_BLK-$(($BLK_VSTART + $BLK_LEN))
		VCN_STREAM=${VCN_STREAM}${VCN_BLK},
		LCN_STREAM=${LCN_STREAM}${LCN_BLK},
		LCN_BLK=
		BLK_VSTART=$VCN
		BLK_LSTART=$LCN
		BLK_LEN=0
	else
		BLK_LEN=$(($BLK_LEN + 1))
	fi

	VCN=$(($VCN + 1))
done

VCN_STREAM=$VCN_STREAM$BLK_VSTART
[ $BLK_LEN -gt 0 ] && VCN_STREAM=$VCN_STREAM-$(($BLK_VSTART + $BLK_LEN))

if [ "$BLK_LSTART" == "XXX" ]; then
	LCN_STREAM=$LCN_STREAM$BLK_LSTART
	[ $BLK_LEN -gt 0 ] && LCN_STREAM=$LCN_STREAM-XXX
else
	LCN_STREAM=$LCN_STREAM$BLK_LSTART
	[ $BLK_LEN -gt 0 ] && LCN_STREAM=$LCN_STREAM-$(($BLK_LSTART + $BLK_LEN))
fi

echo "VCN: $VCN_STREAM"
echo "LCN: $LCN_STREAM"
