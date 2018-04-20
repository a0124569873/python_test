# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

VPATH= $(S) $(S)/../common

LIB= libdpif-fp.so

prefix = /usr/local
exec_prefix = $(prefix)
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
fpovs-dir = $(prefix)/fp-ovs

all: $(LIB)

SRCS := dpif-fp.c fpvs-common.c fpvs-parse-flow.c

OBJS = $(SRCS:%.c=%.o)

include $(DIST_FP)/mcore_common.mk

CFLAGS += -O3 -Wextra -Wall
CFLAGS += -Werror
CFLAGS += -Wstrict-prototypes
CFLAGS += -Wno-unused-parameter
# for openvswitch headers
CFLAGS += -Wno-undef -Wno-sign-compare
CFLAGS += -g
CFLAGS += $(FPNSDK_CFLAGS)
CFLAGS += $(MCORE_COMMON_CFLAGS)

CFLAGS += -fPIC -fno-stack-protector
CFLAGS += -I$(S)
CFLAGS += -I$(S)/../common

# Last chance to find libnl3 headers in native mode
libnl-cflags ?= $(shell pkg-config --silence-errors --cflags libnl-3.0)
CFLAGS += $(libnl-cflags)

include $(S)/../common/fp-vswitch-cflags.mk

CFLAGS += -I$(S)/../openvswitch/

ifeq ($(NOSTRIP),yes)
LIBINSTALL=$(LIB)
else
LIBINSTALL=$(LIB).stripped

$(LIB).stripped: $(LIB)
	$(STRIP) --strip-unneeded -o $@ $<
endif

CFLAGS_dpif-fp.o += $(MCORE_CFLAGS_FP_VSWITCH)
CFLAGS_fpvs-common.o += $(MCORE_CFLAGS_FP_VSWITCH)

$(LIB): $(OBJS)
	$(CC) -shared $^ $(EXTRA_LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS_$@) -o $@ -c $<

install install-target: $(DESTDIR)/$(libdir)/$(LIB)

install install-devel: $(DESTDIR)/$(libdir)/$(LIB)
	$(Q)install -D $(S)/dpif-fp.h $(DESTDIR)$(fpovs-dir)/dpif-fp.h

$(DESTDIR)/$(libdir)/$(LIB): $(LIB)
	install -D $< $@

clean:
	rm -f  $(LIB) $(OBJS)
