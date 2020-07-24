#!/bin/sh

DB=ntfsheurecovery.db

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery DB MFT entry number to offset converter

Usage:
  $APPNAME -h
  $APPNAME [-D <database>] <MFT entry #>

Options:
  <MFT entry #> Number of MFT entry, which offset should be calculated
  -D <database> Use <database> file as data source (def: $DB)
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
	*) exit 1;;
	esac
done

shift $(($OPTIND - 1))

if [ -z "$1" ]; then
	usage
	exit 0
fi

if [ \! -f "$DB" ]; then
	echo "No database file $DB" >&2
	exit 1
fi

Q="SELECT * FROM param WHERE name = 'vol_sec_sz' OR name = 'vol_cls_sz' OR name = 'vol_mft_ent_sz'"
PARAMS=$(sqlite3 $DB "$Q")
VOL_SEC_SZ=$(echo "$PARAMS" | awk -F '|' '$1 ~ /^vol_sec_sz$/ { print $2 }')
VOL_CLS_SZ=$(echo "$PARAMS" | awk -F '|' '$1 ~ /^vol_cls_sz$/ { print $2 }')
VOL_ENT_SZ=$(echo "$PARAMS" | awk -F '|' '$1 ~ /^vol_mft_ent_sz$/ { print $2 }')

if [ -z "$VOL_SEC_SZ" -o -z "$VOL_CLS_SZ" -o -z "$VOL_ENT_SZ" ]; then
	echo "Could not load all partition parameters from DB" >&2
	exit 1
fi

ENT_NUM=$(($1 + 0))
ENT_VOFF_B=$(($ENT_NUM * $VOL_ENT_SZ))
ENT_VOFF_S=$(($ENT_VOFF_B / $VOL_SEC_SZ))
ENT_VOFF_C=$(($ENT_VOFF_B / $VOL_CLS_SZ))

printf "Entry number = 0x%X\n" "$ENT_NUM"
printf "Virtual offset, bytes = 0x%X\n" "$ENT_VOFF_B"
printf "Virtual offset, sect  = 0x%X\n" "$ENT_VOFF_S"
printf "Virtual offset, clust = 0x%X\n" "$ENT_VOFF_C"

Q="SELECT lcn, vcn FROM data_mp WHERE mft_entnum = 0 AND vcn <= $ENT_VOFF_C AND vcn + clen > $ENT_VOFF_C"
MP_DATA=$(sqlite3 $DB "$Q")
if [ -z "$MP_DATA" ]; then
	echo "Could not translate VCN to LCN (virtual cluster to disk)" >&2
	exit 1
fi

MP_LCN=$(echo "$MP_DATA" | awk -F '|' '{print $1}')
MP_VCN=$(echo "$MP_DATA" | awk -F '|' '{print $2}')

ENT_OFF_C=$(($MP_LCN + ($ENT_VOFF_C - $MP_VCN)))
ENT_OFF_S=$(($ENT_OFF_C * ($VOL_CLS_SZ / $VOL_SEC_SZ) + $ENT_VOFF_S % ($VOL_CLS_SZ / $VOL_SEC_SZ)))

printf "Logical offset, clust = 0x%X\n" "$ENT_OFF_C"
printf "Logical offset, sect  = 0x%X\n" "$ENT_OFF_S"
