ntfsheurecovery: NT File System (NTFS) recovery tool
====================================================

Features
--------

ntfsheurecovery is tool for the filesystem recovery process automation.

Key features of htfsheurecovery is:

  * bad blocks (corrupted sectors) awareness
  * filesystem recovery instead of data fetching
  * detailed metadata corruption reporting
  * iterative and controllable behavior
  * uses the standard and widespread DB engine (sqlite) to keep state
    information, which facilitates precise analysis and development of
    auxiliary software
  * read only work mode (only user decides what and when should be written
    back to image)

ntfsheurecovery is the acronym of "NTFS heuristic recovery", which means
that the main goal is to make filesystem consistent again, possibly by
price of ignoring the fact of losing some metadata. Actually NTFS
duplicates a lot of info, so losing of metadata is not so terrible.

NTFS stores almost the same info in different places in different forms
with different degree of staleness. So ntfsheurecovery tracks the metadata
themselves, tracks the source of these data and makes efforts to use the
best one.

The following OS(s) are tested/supported:

 * FreeBSD
 * GNU/Linux

Note: tested only against filesystems produced by WinXP NTFS driver
(ver. 3.1) and disk sector size of 512 bytes with 4kb clusters.

Build
-----

Build requirements:

 * gcc
 * gmake (GNU make)
 * pkg-config
 * sqlite (version 3)

To build ntfsheurecovery from sources, just run the following command:

    make

After build process finished you will get two binaries:

  * ntfsheurecoveryand
  * untfspk

If you would like to install this software to your system then you could
manually copy output binaries and aux scripts to /usr/local/bin/ or
somewhere else by your choice.

Usage
-----

This software actually is a package of main program and a set of utilities
around it:

  * ntfsheurecovery - base program, which does the main analysis and
    recovery work
  * untfspk - extracts content of compressed sectors
  * nhrdb-stat.sh - analyzes state database and prints quick statistics
  * nhrdb-diff.sh - compares two databases and prints differences in the
    "diff -u" format
  * nhrdb-dump-mft.sh - prints full MFT cache from state database
  * nhrdb-dump-mft-unrecovered.sh - prints unrecovered MFT entries from
    state database
  * nhrdb-dump-mft-orphaned.sh - prints orphaned MFT entries from state
    database
  * nhrdb-dump-idx-nodes.sh - prints cached index nodes from state database
  * nhrdb-dump-idx-entries.sh - prints cached index entries from state
    database
  * nhrdb-get-full-path.sh - checks state database and prints the full path
    of specified file
  * nhrdb-mft-entry2offset.sh - finds the partition offset of specified MFT
    entry
  * nhrdb-orph-digest.sh - calculates the md5 digest of each orphaned
    partition sector
  * nhrdb-orph-ftype.sh - detects content type of each orphaned partition
    sector with help of file(1) utility
  * nhrdb-orph-grep.sh - runs grep(1) for each orphaned sector
  * nhr-search-file-clusters.sh - uses digests of orphaned sectors (see
    description of nhrdb-orph-digest.sh) to reconstruct set of sectors,
    which allocated for specified file (used to recover MFT entry of file
    with known content)
  * nhr-write-overlay.sh - writes the created overlay back to the
    partition image

ntfsheurecovery works in iterative manner, which means that you possibly
need to run it several times and modify recovery hints between runs to
tweak the recovery process.

Typical workflow looks like:

  1. Take the image of partition with corrupted filesystem. Use some
     software, which not only fetches data from corrupted disk, but also
     keeps map of corrupted disk sectors. Now ntfsheurecovery supports
     only ddrescue logs:

    ddrescue /dev/sdb1 disk.img disk.log

  2. Create empty hints file:

    touch hints.txt

  3. Run ntfsheurecovery to do the initial analysis (use ntfsheurecovery -h
     to known meaning of each option):

    ntfsheurecovery -B disk.log -H hints.txt -D ntfsheurecovery.db disk.img

  4. Investigate the recovery results with help of nhrdb-dump-xxx scripts

  5. If you satisfied by recovery results then go to the step 10,
     otherwise go to the next step

  6. Create a copy of latest state database to be able to compare with the
     next iteration (to be able use of nhrdb-diff.sh script):

    cp ntfsheurecovery.db ntfsheurecovery-old.db

  7. Edit hints.txt to tweak recovery process (see example hints file)

  8. Run ntfsheurecovery again:

    ntfsheurecovery -B disk.log -H hints.txt -D ntfsheurecovery.db disk.img

  9. Go to the step 4

  10. Create directory for overlay data:

    mkdir overlay

  11. Run ntfsheurecovery in overlay generation mode:

    ntfsheurecovery -B disk.log -H hints.txt -O overlay disk.img

  12. Create backup copy of partition image:

    cp disk.img disk.img.orig

  13. Write overlay data to the image:

    nhr-write-overlay.sh -O overlay disk.img

  14. Check image integrity by mounting it:

    mount -t ntfs -o loop disk.img /mnt/

  15. Write image to new healthy disk if you need this

TODO
----

 * add support for machines with big-endian arch (now LE only)
 * verify and fix terminology
 * make recovery a bit more iterative instead of recover or fail approach
 * add careful internal and filesystem errors handling
 * make $Secure dump controllable by command line option instead of #ifdef
   inside source code

License
-------

This project is licensed under the terms of the ISC license. See
the LICENSE file for license rights and limitations.
