# Copyright 2013 6WIND S.A.

S?=$($(DIST_BLADE_IPSEC)/tools/sa-migrate)
STRIP?=strip

VPATH = $(S)

PROG:= sa-migrate
SRCS:= sa-migrate.c

prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin

CFLAGS+= -O2 -Wall -Werror
CFLAGS+= -g
CFLAGS+= -I$(S)/../../common

# We expect /usr/include/linux matches the kernel.
# User of custom kernel may have run 'make headers_install',
# leaving sanitized headers into /lib/modules/<ver>/build/usr/include
# Add this path to include directory.
# Give a chance too for cross compilation giving KERNEL_BUILDROOT,
# add KERNEL_BUILDROOT/usr/include.
ifneq ($(INCKERN),)
CFLAGS+= $(INCKERN)
else
ifneq ($(KERNEL_BUILDROOT),)
CFLAGS+= -I$(KERNEL_BUILDROOT)/usr/include
else
CFLAGS+= -I/lib/modules/$(linuxversion)/build/usr/include
endif
endif

# libnl
# Last chance to find libnl3 headers in native mode
libnl-cflags ?= $(shell pkg-config --silence-errors --cflags libnl-3.0)
CFLAGS += $(libnl-cflags)
LDFLAGS += $(libnl-ldflags)

LDADD+= -lnl-3 -lnl-genl-3

OBJS:=$(SRCS:%.c=%.o)

ifeq ($(NOSTRIP), yes)
PROGINSTALL=$(PROG)
else
PROGINSTALL=$(PROG).stripped

$(PROG).stripped: $(PROG)
	$(STRIP) --strip-all -o $@ $<

endif

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS) $(LDADD)

%.o:%.c
	$(CC) $(CFLAGS) $(CFLAGS_$(@)) $(EXTRA_CFLAGS) -o $@ -c $<


install install-target: $(DESTDIR)/$(bindir)/$(PROG)

$(DESTDIR)/$(bindir)/$(PROG): $(PROGINSTALL)
	install -D $< $@

clean:
	@rm -f $(OBJS) $(PROG) $(PROG).stripped

install-devel:;
