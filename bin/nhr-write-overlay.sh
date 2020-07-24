#!/bin/sh

OVERLAY_DIR=overlay
IMG_OFF=0
IMG=

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery overlay writing script

Take generated files with overlay data and apply them to specified
filesystem image file. Overlay files selected from specified directory
by following template: overlay-<off,hex>-<len,hex>.bin

Usage:
  $APPNAME -h
  $APPNAME [-o <imgoff>] [-O <overlaydir>] <image>

Options:
  <image>          Filesystem image, to which the overlay is applied
  -O <overlaydir>  Directory, which contains generated overlay files
                   (def: $OVERLAY_DIR)
  -o <imgoff>      Base offset for output image, bytes
  -h               Print this help
"
}

while getopts "hO:o:" OPT; do
	case "$OPT" in
	h)
		usage
		exit 0
		;;
	O) OVERLAY_DIR="$OPTARG";;
	o) IMG_OFF=$((0 + $OPTARG));;
	*) exit 1;;
	esac
done

shift $(($OPTIND - 1))

if [ -z "$1" ]; then
	echo "Filesystem image file is not specified" >&2
	exit 1
else
	IMG="$1"
fi

if [ \! -e "$IMG" ]; then
	echo "Filesystem image file does not exists: $IMG" >&2
	exit 1
fi

if [ \! -d "$OVERLAY_DIR" ]; then
	echo "Overlay directory does not exists: $OVERLAY_DIR" >&2
	exit 1
fi

for F in $(ls $OVERLAY_DIR/overlay-0x*-0x*.bin 2>/dev/null); do
	OFF=$(echo "$F" | sed -rne 's/^.*\/overlay-(0x[0-9A-Fa-f]+)-(0x[0-9A-Fa-f]+).bin$/\1/p')
	LEN=$(echo "$F" | sed -rne 's/^.*\/overlay-(0x[0-9A-Fa-f]+)-(0x[0-9A-Fa-f]+).bin$/\2/p')
	[ -z "$OFF" -o -z "$LEN" ] && continue
	dd if="$F" of="$IMG" bs=1 seek=$(($IMG_OFF + $OFF)) count=$(($LEN)) conv=notrunc 2> /dev/null
	if [ $? -ne 0 ]; then
		echo "Could not apply $OFF:$LEN overlay block" >&2
		exit 1
	fi
done
