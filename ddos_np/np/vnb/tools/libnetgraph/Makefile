S?=$(CURDIR)

VPATH= $(S)

LIB= libnetgraph.so
AR?=ar
RANLIB?=ranlib

prefix = /usr/local
exec_prefix = $(prefix)
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include

all: $(LIB)

INCVNB	:= -I$(S)/../../sys/

SRCS	 = sock.c msg.c debug.c

CFLAGS	+= -D__linux__
CFLAGS	+= $(INCVNB)

# compat snagpear
CFLAGS	+= -Wall -Wextra
CFLAGS	+= -Wundef
CFLAGS	+= -Wno-unused-parameter -Wstrict-prototypes
CFLAGS	+= -std=gnu99
CFLAGS	+= -I$(S)

OBJS = $(SRCS:%.c=%.o)

$(LIB): $(OBJS)
	$(CC) -shared $(OBJS) -o $(LIB)

%.o:%.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -fPIC -o $@ -c $<

install install-devel: $(DESTDIR)/$(libdir)/$(LIB) \
	$(DESTDIR)/$(includedir)/netgraph.h \
	$(DESTDIR)/$(includedir)/libnetgraph/internal.h

$(DESTDIR)/$(libdir)/$(LIB): $(LIB)
	install -D $< $@

$(DESTDIR)/$(includedir)/netgraph.h: $(S)/netgraph.h
	install -D $< $@

$(DESTDIR)/$(includedir)/libnetgraph/internal.h: $(S)/internal.h
	install -D $< $@

install-target: $(DESTDIR)/$(libdir)/$(LIB)

clean:
	rm -f  $(LIB) $(OBJS)

pkg-src:;
