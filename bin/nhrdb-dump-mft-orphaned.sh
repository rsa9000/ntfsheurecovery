#!/bin/sh

DB=ntfsheurecovery.db

usage () {
	APPNAME=$(basename "$0")
	echo "ntfsheurecovery DB orphaned MFT entries dump

Usage:
  $APPNAME -h
  $APPNAME [-D <database>]

Options:
  -D <database> Use <database> file as data source (def: $DB)
  -h            Print this help
"
}

while getopts "hD:P:" OPT; do
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

Q=$(cat <<EOL
/* Create names sorting rule */
CREATE TEMP TABLE name_pref (type INT, pref INT);
INSERT INTO name_pref VALUES (0, 10), (1, 40), (2, 20), (3, 30);
/* Create transient table, which contains only prefered names */
CREATE TEMP TABLE mft_entries_fn_pref AS SELECT
  t1.num,
  t1.type
FROM
  mft_entries_fn as t1,
  name_pref as t2,
  (SELECT
     t1.num, MAX(t2.pref) AS pref
   FROM
     mft_entries_fn AS t1,
     name_pref AS t2
   WHERE
     t1.type = t2.type
   GROUP BY t1.num) as t3
WHERE
  t1.type = t2.type AND t1.num = t3.num AND t2.pref = t3.pref;
/* Do main query */
SELECT
  t1.num,
  CASE WHEN t1.base <> 0 THEN 'b' ELSE 'p' END,
  CASE WHEN t1.base <> 0 THEN t1.base ELSE t1.parent END,
  t1.f_cmn, t1.f_bad, t1.f_rec, t1.f_sum, t3.src,
  t2.type, ifnull(t3.name, '<none>')
FROM
    mft_entries_tree AS t01
  LEFT JOIN
    mft_entries_tree AS t02
  ON
    t01.entry = t02.entry AND t02.parent = 5
  LEFT JOIN
    mft_entries AS t1
  ON
    t01.entry = t1.num
  LEFT JOIN
    mft_entries_fn_pref AS t2
  ON
    t1.num = t2.num
  LEFT JOIN
    mft_entries_fn AS t3
  ON
    t1.num = t3.num AND t2.type = t3.type
WHERE
  t01.h = 1 AND t02.entry IS NULL
ORDER BY
  t1.num
EOL
)

echo "Entry   Parent/    Flags              Name"
echo "Number  Base       cmn/bad/rec/sum Type/Source  Name"

sqlite3 $DB "$Q" | awk -F "|" '
{
	printf "#%-6u (%c)#%-6u %02X/%02X/%02X/%02X        %u/%u       %s\n",
	       $1, $2, $3, $4, $5, $6, $7, $9, $8, $10;
}
'
