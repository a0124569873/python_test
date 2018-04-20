# Copyright 2014 6WIND S.A.

VPATH = $(S)

prefix = /usr/local
bindir = $(prefix)/bin
libdir = $(prefix)/lib
includedir = $(prefix)/include

CFLAGS	+= -I$(TOP_S)/tools/libnetgraph -I$(TOP_S)/sys/
LDFLAGS_LIBNETGRAPH ?= -L$(TOP_O)/tools/libnetgraph
LDFLAGS += $(LDFLAGS_LIBNETGRAPH)
LDADD  += -lnetgraph

OBJS = $(SRCS:%.c=%.o)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDADD) $(LDLIBS)

%.o:%.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

clean:
	rm -f $(PROG) $(OBJS)

$(DESTDIR)/$(bindir)/$(PROG): $(PROG)
	install -D $< $@

install install-target: $(DESTDIR)/$(bindir)/$(PROG)

install-devel:;

pkg-src:;
