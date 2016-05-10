#!/bin/sh

DB=ntfsheurecovery.db

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery DB statistics

Usage:
  $APPNAME -h
  $APPNAME [-D <database>]

Options:
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

if [ \! -f "$DB" ]; then
	echo "No database file $DB" >&2
	exit 1;
fi

Q="SELECT * FROM param"
PARAMS=$(sqlite3 $DB "$Q")
VOL_SEC_SZ=$(echo "$PARAMS" | awk -F '|' '$1 ~ /^vol_sec_sz$/ { print $2 }')
VOL_CLS_SZ=$(echo "$PARAMS" | awk -F '|' '$1 ~ /^vol_cls_sz$/ { print $2 }')
VOL_MFT_ENT_SZ=$(echo "$PARAMS" | awk -F '|' '$1 ~ /^vol_mft_ent_sz$/ { print $2 }')


Q="SELECT flags, COUNT(*) as cnt, SUM(LEN) as len FROM cmap GROUP BY flags"
sqlite3 -header $DB "$Q" | awk -F "|" -v VOL_CLS_SZ=$VOL_CLS_SZ '
function human(sz) {
	if (sz < 1024)
		return sz " B"
	else if (sz < (1024 * 1024))
		return int(sz / 1024) " KB"
	else if (sz < (1024 * 1024 * 1024))
		return int(sz / (1024 * 1024)) " MB"
	else
		return int(sz / (1024 * 1024 * 1024)) " GB"
}
BEGIN {
	printf "cmap:stat:start\n"
	T_BL=0
	T_CL=0
	F_BL=0
	F_CL=0
	A_BL=0
	A_CL=0
	O_BL=0
	O_CL=0
}
NR == 1 {
	# Read column names from header
	for (i = 1; i <= NF; ++i)
		FNAMES[i] = $i
}
NR > 1 {
	for (i = 1; i <= NF; ++i)
		CB[FNAMES[i]] = $i

	if (CB["flags"] == 0) {
		O_BL=CB["cnt"]
		O_CL=CB["len"]
	} else if (CB["flags"] == 1) {
		F_BL=CB["cnt"]
		F_CL=CB["len"]
	} else if (CB["flags"] == 2) {
		A_BL=CB["cnt"]
		A_CL=CB["len"]
	} else {
		printf "cmap:stat: unknown flags combination: 0x%08X\n", CB["flags"]
	}
	T_BL += CB["cnt"]
	T_CL += CB["len"]
}
END {
	printf "cmap:stat:  total = %6u blocks, %10u clusters, %7s\n", T_BL, T_CL, human(T_CL * VOL_CLS_SZ)
	printf "cmap:stat:   free = %6u blocks, %10u clusters, %7s\n", F_BL, F_CL, human(F_CL * VOL_CLS_SZ)
	printf "cmap:stat:  alloc = %6u blocks, %10u clusters, %7s\n", A_BL, A_CL, human(A_CL * VOL_CLS_SZ)
	printf "cmap:stat: orphan = %6u blocks, %10u clusters, %7s\n", O_BL, O_CL, human(O_CL * VOL_CLS_SZ)
	printf "cmap:stat:end\n"

}
'

Q=$(cat <<EOL
SELECT
  entnum,
  (flags & 1) == 1 as f_auto,
  (flags & 2) == 2 as f_free,
  (flags & 4) == 4 as f_orph,
  (flags & 8) == 8 as f_ignore,
  (flags & 16) == 16 as f_rec,
  (flags & ~1) as f_known,
  attr_type
FROM
  bb
EOL
)
sqlite3 -header $DB "$Q" | awk -F '|' '
BEGIN {
	printf "bb:stat:start\n"
	CNT_TOT=0
	CNT_AUTO=0
	CNT_FREE=0
	CNT_IGNORE=0
	CNT_ORPH=0
	CNT_UNKN=0
	TCNT_TOT=0;	TCNT[0, TCNT_TOT]=0;	TCNT[1, TCNT_TOT]=0;
	TCNT_MFT=1;	TCNT[0, TCNT_MFT]=0;	TCNT[1, TCNT_MFT]=0;
	TCNT_MFTB=2;	TCNT[0, TCNT_MFTB]=0;	TCNT[1, TCNT_MFTB]=0;
	TCNT_DATA=3;	TCNT[0, TCNT_DATA]=0;	TCNT[1, TCNT_DATA]=0;
	TCNT_IDX=4;	TCNT[0, TCNT_IDX]=0;	TCNT[1, TCNT_IDX]=0;
	TCNT_SYS=5;	TCNT[0, TCNT_SYS]=0;	TCNT[1, TCNT_SYS]=0;
	TCNT_USER=6;	TCNT[0, TCNT_USER]=0;	TCNT[1, TCNT_USER]=0;

	NTFS_ENTNUM_MFT=0
	NTFS_ATTR_DATA=128
	NTFS_ATTR_IALLOC=160
	NTFS_ATTR_BITMAP=176
}
NR == 1 {
	# Read column names from header
	for (i = 1; i <= NF; ++i)
		FNAMES[i] = $i
}
NR > 1 {
	for (i = 1; i <= NF; ++i)
		BB[FNAMES[i]] = $i

	CNT_TOT++
	if (BB["f_free"]) {
		CNT_FREE++
		next
	}
	if (BB["f_auto"])
		CNT_AUTO++
	if (BB["f_ignore"]) {
		CNT_IGNORE++
		next
	}
	if (BB["f_orph"]) {
		CNT_ORPH++
		next
	}
	if (!BB["f_known"] && BB["entnum"] == "") {
		CNT_UNKN++
		next
	}
	REC_STATUS = BB["f_rec"] ? 0 : 1
	TCNT[REC_STATUS, TCNT_TOT]++
	if (BB["entnum"] == NTFS_ENTNUM_MFT && BB["attr_type"] == NTFS_ATTR_DATA)
		TCNT[REC_STATUS, TCNT_MFT]++
	if (BB["entnum"] == NTFS_ENTNUM_MFT && BB["attr_type"] == NTFS_ATTR_BITMAP)
		TCNT[REC_STATUS, TCNT_MFTB]++
	if (BB["attr_type"] == NTFS_ATTR_DATA)
		TCNT[REC_STATUS, TCNT_DATA]++
	if (BB["attr_type"] == NTFS_ATTR_IALLOC)
		TCNT[REC_STATUS, TCNT_IDX]++
	if (BB["attr_type"] == NTFS_ATTR_IALLOC ||
	    (BB["attr_type"] == NTFS_ATTR_DATA && BB["entnum"] <= 24))
		TCNT[REC_STATUS, TCNT_SYS]++
	if (BB["attr_type"] == NTFS_ATTR_DATA && BB["entnum"] > 24)
		TCNT[REC_STATUS, TCNT_USER]++
}
END {
	printf "bb:stat:   total = %u\n", CNT_TOT
	printf "bb:stat:    auto = %u\n", CNT_AUTO
	printf "bb:stat:    free = %u\n", CNT_FREE
	printf "bb:stat:  ignore = %u\n", CNT_IGNORE
	printf "bb:stat:  orphan = %u\n", CNT_ORPH
	printf "bb:stat: unknown = %u\n", CNT_UNKN
	printf "bb:stat: corrupt (recovered/unrecovered/total):\n"
	printf "bb:stat:      total = %7u %7u %7u\n", TCNT[0, TCNT_TOT], TCNT[1, TCNT_TOT], TCNT[0, TCNT_TOT] + TCNT[1, TCNT_TOT]
	printf "bb:stat:        MFT = %7u %7u %7u\n", TCNT[0, TCNT_MFT], TCNT[1, TCNT_MFT], TCNT[0, TCNT_MFT] + TCNT[1, TCNT_MFT]
	printf "bb:stat: MFT bitmap = %7u %7u %7u\n", TCNT[0, TCNT_MFTB], TCNT[1, TCNT_MFTB], TCNT[0, TCNT_MFTB] + TCNT[1, TCNT_MFTB]
	printf "bb:stat:       data = %7u %7u %7u\n", TCNT[0, TCNT_DATA], TCNT[1, TCNT_DATA], TCNT[0, TCNT_DATA] + TCNT[1, TCNT_DATA]
	printf "bb:stat:      index = %7u %7u %7u\n", TCNT[0, TCNT_IDX], TCNT[1, TCNT_IDX], TCNT[0, TCNT_IDX] + TCNT[1, TCNT_IDX]
	printf "bb:stat:     system = %7u %7u %7u\n", TCNT[0, TCNT_SYS], TCNT[1, TCNT_SYS], TCNT[0, TCNT_SYS] + TCNT[1, TCNT_SYS]
	printf "bb:stat:       user = %7u %7u %7u\n", TCNT[0, TCNT_USER], TCNT[1, TCNT_USER], TCNT[0, TCNT_USER] + TCNT[1, TCNT_USER]
	printf "bb:stat:end\n"
}
'

Q=$(cat <<EOF
SELECT
  base,
  parent,
  f_cmn,
  (f_cmn & 1) == 1 as fc_free,
  (f_cmn & 2) == 2 as fc_file,
  (f_cmn & 4) == 4 as fc_dir,
  (f_cmn & 8) == 8 as fc_idx,
  (f_cmn & 16) == 16 as fc_base,
  (f_cmn & 32) == 32 as fc_extent,
  (f_cmn & 64) == 64 as fc_integ,
  f_bad,
  (f_bad & 1) == 1 as fb_self,
  (f_bad & 2) == 2 as fb_aidx,
  (f_bad & 4) == 4 as fb_adata,
  f_rec,
  (f_rec & 1) == 1 as fr_self,
  (f_rec & 2) == 2 as fr_aidx,
  (f_rec & 4) == 4 as fr_adata,
  bb_map
FROM
  mft_entries
EOF
)
sqlite3 -header $DB "$Q" | awk -F '|' -v VOL_SEC_SZ=$VOL_SEC_SZ -v VOL_MFT_ENT_SZ=$VOL_MFT_ENT_SZ '
BEGIN {
	printf "cache:mft:stat:start\n"

	# Common counters
	CNT_TOT=0
	CNT_FREE=0
	CNT_VALID=0
	CNT_BAD=0
	CNT_ORPH=0
	CNT_REC_FULL=0
	CNT_REC_PART=0
	CNT_REC_NONE=0

	# Per corruption type counters
	TCNTC_SELF=0;		TCNTC[0, TCNTC_SELF]=0;		TCNTC[1, TCNTC_SELF]=0;
	TCNTC_SELF_INTEG=1;	TCNTC[0, TCNTC_SELF_INTEG]=0;	TCNTC[1, TCNTC_SELF_INTEG]=0;
	TCNTC_SELF_FULL=2;	TCNTC[0, TCNTC_SELF_FULL]=0;	TCNTC[1, TCNTC_SELF_FULL]=0;
	TCNTC_SELF_PART=3;	TCNTC[0, TCNTC_SELF_PART]=0;	TCNTC[1, TCNTC_SELF_PART]=0;
	TCNTC_SELF_INIT=4;	TCNTC[0, TCNTC_SELF_PART]=0;	TCNTC[1, TCNTC_SELF_INIT]=0;
	TCNTC_DATA=5;		TCNTC[0, TCNTC_DATA]=0;		TCNTC[1, TCNTC_DATA]=0;
	TCNTC_IDX=6;		TCNTC[0, TCNTC_IDX]=0;		TCNTC[1, TCNTC_IDX]=0;
	TCNTC_MIN=0;
	TCNTC_MAX=6;

	# Per entry type couters
	TCNTE_FILE=0;	TCNTE[0, TCNTE_FILE]=0;		TCNTE[1, TCNTE_FILE]=0;		TCNTE[2, TCNTE_FILE]=0;
	TCNTE_DIR=1;	TCNTE[0, TCNTE_DIR]=0;		TCNTE[1, TCNTE_DIR]=0;		TCNTE[2, TCNTE_DIR]=0;
	TCNTE_IDX=2;	TCNTE[0, TCNTE_IDX]=0;		TCNTE[1, TCNTE_IDX]=0;		TCNTE[2, TCNTE_IDX]=0;
	TCNTE_FD_UNKN=3;TCNTE[0, TCNTE_FD_UNKN]=0;	TCNTE[1, TCNTE_FD_UNKN]=0;	TCNTE[2, TCNTE_FD_UNKN]=0;
	TCNTE_BASE=4;	TCNTE[0, TCNTE_BASE]=0;		TCNTE[1, TCNTE_BASE]=0;		TCNTE[2, TCNTE_BASE]=0;
	TCNTE_EXTENT=5;	TCNTE[0, TCNTE_EXTENT]=0;	TCNTE[1, TCNTE_EXTENT]=0;	TCNTE[2, TCNTE_EXTENT]=0;
	TCNTE_BE_UNKN=6;TCNTE[0, TCNTE_BE_UNKN]=0;	TCNTE[1, TCNTE_BE_UNKN]=0;	TCNTE[2, TCNTE_BE_UNKN]=0;
	TCNTE_MIN=0;
	TCNTE_MAX=6;

	# Emulate left shift
	BB_MAP_MASK=0
	for (I = 0; I < VOL_MFT_ENT_SZ / VOL_SEC_SZ; ++I)
		BB_MAP_MASK = BB_MAP_MASK * 2 + 1
}
NR == 1 {
	# Read column names from header
	for (i = 1; i <= NF; ++i)
		FNAMES[i] = $i
}
NR > 1 {
	for (i = 1; i <= NF; ++i)
		MFTE[FNAMES[i]] = $i

	CNT_TOT++

	if (MFTE["fc_free"]) {
		CNT_FREE++
		next
	}

	if (MFTE["f_bad"]) {
		CNT_BAD++
		if (MFTE["f_bad"] == MFTE["f_rec"]) {
			CNT_REC_FULL++
			REC_STATUS=0
		} else if (MFTE["f_rec"]) {
			CNT_REC_PART++
			REC_STATUS=1
		} else {
			CNT_REC_NONE++
			REC_STATUS=1
		}
	} else {
		CNT_VALID++
		REC_STATUS=2
	}

	if (MFTE["fb_self"]) {
		SREC_STATUS = MFTE["fr_self"] ? 0 : 1;
		TCNTC[SREC_STATUS, TCNTC_SELF]++
		if (MFTE["fc_integ"]) {
			TCNTC[SREC_STATUS, TCNTC_SELF_INTEG]++
		} else if (MFTE["bb_map"] == BB_MAP_MASK) {
			TCNTC[SREC_STATUS, TCNTC_SELF_FULL]++
		} else {
			TCNTC[SREC_STATUS, TCNTC_SELF_PART]++
			if (MFTE["bb_map"] % 2 == 1)
				TCNTC[SREC_STATUS, TCNTC_SELF_INIT]++
		}
		if (MFTE["base"]==0 && MFTE["parent"]==0)
			CNT_ORPH++
	}
	if (MFTE["fb_adata"])
		TCNTC[MFTE["fr_adata"] ? 0 : 1, TCNTC_DATA]++
	if (MFTE["fb_aidx"])
		TCNTC[MFTE["fr_aidx"] ? 0 : 1, TCNTC_IDX]++

	if (MFTE["fc_file"])
		TCNTE[REC_STATUS, TCNTE_FILE]++
	if (MFTE["fc_dir"])
		TCNTE[REC_STATUS, TCNTE_DIR]++
	if (MFTE["fc_idx"])
		TCNTE[REC_STATUS, TCNTE_IDX]++
	if (!MFTE["fc_file"] && !MFTE["fc_dir"] && !MFTE["fc_idx"])
		TCNTE[REC_STATUS, TCNTE_FD_UNKN]++
	if (MFTE["fc_base"])
		TCNTE[REC_STATUS, TCNTE_BASE]++
	if (MFTE["fc_extent"])
		TCNTE[REC_STATUS, TCNTE_EXTENT]++
	if (!MFTE["fc_base"] && !MFTE["fc_extent"])
		TCNTE[REC_STATUS, TCNTE_BE_UNKN]++
}
END {
	for (I = TCNTC_MIN; I <= TCNTC_MAX; ++I)
		TCNTC[2, I] = TCNTC[0, I] + TCNTC[1, I]
	for (I = TCNTE_MIN; I <= TCNTE_MAX; ++I)
		TCNTE[3, I] = TCNTE[0, I] + TCNTE[1, I] + TCNTE[2, I];

	printf "cache:mft:stat:     total = %u\n", CNT_TOT
	printf "cache:mft:stat:      free = %u\n", CNT_FREE
	printf "cache:mft:stat:     valid = %u\n", CNT_VALID
	printf "cache:mft:stat: corrupted = %u\n", CNT_BAD
	printf "cache:mft:stat:  orphaned = %u\n", CNT_ORPH
	printf "cache:mft:stat:  rec-full = %u\n", CNT_REC_FULL
	printf "cache:mft:stat:  rec-part = %u\n", CNT_REC_PART
	printf "cache:mft:stat:  rec-none = %u\n", CNT_REC_NONE
	printf "cache:mft:stat: corrupt (recovered/unrecovered/total):\n"
	printf "cache:mft:stat:   +-self     = %4u  %4u  %4u\n", TCNTC[0, TCNTC_SELF], TCNTC[1, TCNTC_SELF], TCNTC[2, TCNTC_SELF]
	printf "cache:mft:stat:   | +-integ  = %4u  %4u  %4u\n", TCNTC[0, TCNTC_SELF_INTEG], TCNTC[1, TCNTC_SELF_INTEG], TCNTC[2, TCNTC_SELF_INTEG]
	printf "cache:mft:stat:   | +-full   = %4u  %4u  %4u\n", TCNTC[0, TCNTC_SELF_FULL], TCNTC[1, TCNTC_SELF_FULL], TCNTC[2, TCNTC_SELF_FULL]
	printf "cache:mft:stat:   | `-part   = %4u  %4u  %4u\n", TCNTC[0, TCNTC_SELF_PART], TCNTC[1, TCNTC_SELF_PART], TCNTC[2, TCNTC_SELF_PART]
	printf "cache:mft:stat:   |   `-init = %4u  %4u  %4u\n", TCNTC[0, TCNTC_SELF_INIT], TCNTC[1, TCNTC_SELF_INIT], TCNTC[2, TCNTC_SELF_INIT]
	printf "cache:mft:stat:   +-data     = %4u  %4u  %4u\n", TCNTC[0, TCNTC_DATA], TCNTC[1, TCNTC_DATA], TCNTC[2, TCNTC_DATA]
	printf "cache:mft:stat:   `-index    = %4u  %4u  %4u\n", TCNTC[0, TCNTC_IDX], TCNTC[1, TCNTC_IDX], TCNTC[2, TCNTC_IDX]
	printf "cache:mft:stat: type (recovered/unrecovered/valid/total):\n"
	printf "cache:mft:stat:   +-file     = %4u  %4u  %4u  %4u\n", TCNTE[0, TCNTE_FILE], TCNTE[1, TCNTE_FILE], TCNTE[2, TCNTE_FILE], TCNTE[3, TCNTE_FILE]
	printf "cache:mft:stat:   +-dir      = %4u  %4u  %4u  %4u\n", TCNTE[0, TCNTE_DIR], TCNTE[1, TCNTE_DIR], TCNTE[2, TCNTE_DIR], TCNTE[3, TCNTE_DIR]
	printf "cache:mft:stat:   +-idx      = %4u  %4u  %4u  %4u\n", TCNTE[0, TCNTE_IDX], TCNTE[1, TCNTE_IDX], TCNTE[2, TCNTE_IDX], TCNTE[3, TCNTE_IDX]
	printf "cache:mft:stat:   +-unknown  = %4u  %4u  %4u  %4u\n", TCNTE[0, TCNTE_FD_UNKN], TCNTE[1, TCNTE_FD_UNKN], TCNTE[2, TCNTE_FD_UNKN], TCNTE[3, TCNTE_FD_UNKN]
	printf "cache:mft:stat:   +-base     = %4u  %4u  %4u  %4u\n", TCNTE[0, TCNTE_BASE], TCNTE[1, TCNTE_BASE], TCNTE[2, TCNTE_BASE], TCNTE[3, TCNTE_BASE]
	printf "cache:mft:stat:   +-extent   = %4u  %4u  %4u  %4u\n", TCNTE[0, TCNTE_EXTENT], TCNTE[1, TCNTE_EXTENT], TCNTE[2, TCNTE_EXTENT], TCNTE[3, TCNTE_EXTENT]
	printf "cache:mft:stat:   `-unknown  = %4u  %4u  %4u  %4u\n", TCNTE[0, TCNTE_BE_UNKN], TCNTE[1, TCNTE_BE_UNKN], TCNTE[2, TCNTE_BE_UNKN], TCNTE[3, TCNTE_BE_UNKN]
	printf "cache:mft:stat:end\n"
}
'
