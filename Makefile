#
# Copyright (c) 2015-2016, Sergey Ryazanov <ryazanov.s.a@gmail.com>
#

TGT_REC=ntfsheurecovery

SRC_REC=attr.c \
	bb.c \
	cache.c \
	cmap.c \
	cmask.c \
	data.c \
	ddrescue.c \
	hints.c \
	idx.c \
	idx_i30.c \
	idx_aux.c \
	idx_cmp.c \
	idx_fetch.c \
	idx_recover.c \
	idx_secure.c \
	img.c \
	logfile.c \
	main.c \
	md5.c \
	mft_analyze.c \
	mft_aux.c \
	mft_cmp.c \
	mft_recover.c \
	misc.c \
	name.c \
	ntfs.c \
	ntfs_dump.c \
	objid.c \
	rbtree.c \
	scan.c \
	secfile_dump.c \
	secure.c \
	sqlite.c \
	vol.c
OBJ_REC=$(SRC_REC:%.c=%.o)

TGT_UPK=untfspk
SRC_UPK=untfspk.c
OBJ_UPK=$(SRC_UPK:%.c=%.o)

DEPDIR=.dep

CFLAGS += -O2 -D_FILE_OFFSET_BITS=64 -DANOTHER_BRICK_IN_THE -Wall -g
DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$*.Td

CFLAGS += $(shell pkg-config --cflags sqlite3)
LDFLAGS_REC += $(shell pkg-config --libs sqlite3)

.PHONY: all clean

all: $(DEPDIR) $(TGT_REC) $(TGT_UPK)

$(TGT_REC): $(OBJ_REC)
	$(CC) $(LDFLAGS_REC) -o $@ $(OBJ_REC)

$(TGT_UPK): $(OBJ_UPK)
	$(CC) -o $@ $(OBJ_UPK)

%.o: %.c
	$(CC) $(DEPFLAGS) $(CFLAGS) -o $@ -c $<
	@mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d

$(DEPDIR):
	mkdir -p $(DEPDIR)

clean:
	rm -rf $(DEPDIR)
	rm -rf $(TGT_REC)
	rm -rf $(OBJ_REC)
	rm -rf $(TGT_UPK)
	rm -rf $(OBJ_UPK)

$(DEPDIR)/%.d:;

-include $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRC_REC)))
-include $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRC_UPK)))
