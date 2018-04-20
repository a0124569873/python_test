S?=$(CURDIR)
O ?= $(CURDIR)

VPATH= $(S) $(S)/../common

LIB= libcmgr-fp-vswitch.so

prefix = /usr/local
exec_prefix = $(prefix)
libcmgr-dir = $(exec_prefix)/lib/cmgr
includedir = $(prefix)/include

# If we cannot find the common dir in the top folder,
# we need fp-ovs devel to be installed
ifeq ($(wildcard $(S)/../common),)
fpovs-dir = $(prefix)/fp-ovs
else
fpovs-dir = $(S)/../common
endif

all: $(LIB)

SRCS := fpvs-cmgr.c fpvs-parse-flow.c

OBJS := $(SRCS:%.c=%.o)

CFLAGS += -fPIC
CFLAGS += -D__KERNEL__
CFLAGS += -I$(S)
CFLAGS += -I$(fpovs-dir)

# Last chance to find libnl3 headers in native mode
libnl-cflags ?= $(shell pkg-config --silence-errors --cflags libnl-3.0)
CFLAGS += $(libnl-cflags)

CFLAGS += -I$(S)/../openvswitch

ifeq ($(NOSTRIP),yes)
LIBINSTALL=$(LIB)
else
LIBINSTALL=$(LIB).stripped

$(LIB).stripped: $(LIB)
	$(STRIP) --strip-unneeded -o $@ $<
endif

$(LIB): $(OBJS)
	$(CC) -shared $(OBJS) $(EXTRA_LDFLAGS) -o $@ -lrt

%.o:%.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

install install-devel install-target: $(DESTDIR)/$(libcmgr-dir)/$(LIB)

$(DESTDIR)/$(libcmgr-dir)/$(LIB): $(LIB)
	install -D $< $@

clean:
	rm -f  $(LIB) $(OBJS)
