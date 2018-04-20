# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

VPATH= $(S) $(S)/../common

LIB= libfpm-fp-vswitch.so

prefix = /usr/local
exec_prefix = $(prefix)
libfpm-dir = $(exec_prefix)/lib/fpm
includedir = $(prefix)/include
fpovs-dir = $(prefix)/fp-ovs

all: $(LIB)

SRCS := fpm-fpvswitch.c
SRCS += fpvs-common.c
SRCS += fp-vswitch.c

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

CFLAGS += -fPIC
CFLAGS += -I$(DIST_FP)/fpm
CFLAGS += -I$(DIST_FP)/libnetfpc
CFLAGS += -I$(S)
CFLAGS += -I$(S)/../common

include $(S)/../common/fp-vswitch-cflags.mk

CFLAGS += -I$(S)/../openvswitch

CFLAGS_fpm-fpvswitch.o += $(MCORE_CFLAGS_FP_VSWITCH)
CFLAGS_fpvs-common.o += $(MCORE_CFLAGS_FP_VSWITCH)

ifeq ($(NOSTRIP),yes)
LIBINSTALL=$(LIB)
else
LIBINSTALL=$(LIB).stripped

$(LIB).stripped: $(LIB)
	$(STRIP) --strip-unneeded -o $@ $<
endif

$(LIB): $(OBJS)
	$(CC) -shared $^ $(EXTRA_LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(CFLAGS_$@) -o $@ -c $<

install install-target: $(DESTDIR)/$(libfpm-dir)/$(LIB)

install install-devel: $(DESTDIR)/$(libfpm-dir)/$(LIB)
	$(Q)install -D $(S)/../common/fpvs-cp.h $(DESTDIR)$(fpovs-dir)/fpvs-cp.h

$(DESTDIR)/$(libfpm-dir)/$(LIB): $(LIB)
	install -D $< $@

clean:
	rm -f  $(LIB) $(OBJS)
