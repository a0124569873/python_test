S?=$(CURDIR)

VPATH= $(S)

LIB= libifuid.a
AR?=ar
RANLIB?=ranlib

prefix = /usr/local
exec_prefix = $(prefix)
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include

all: $(LIB)

SRCS:= ifuid_compute.c
OBJS:= ifuid_compute.o

# compat snagpear
CFLAGS += -Wall -Wextra -Werror
CFLAGS += -Wundef
CFLAGS += -Wno-unused-parameter -Wstrict-prototypes
CFLAGS += -std=gnu99
CFLAGS += -I$(S)
CFLAGS += -fPIC

$(LIB): $(OBJS)
	$(AR) cru $(LIB) $(OBJS)
	$(RANLIB) $(LIB)

%.o:%.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

install install-devel: $(DESTDIR)/$(libdir)/$(LIB) $(DESTDIR)/$(includedir)/ifuid.h

$(DESTDIR)/$(libdir)/$(LIB): $(LIB)
	install -D $< $@

$(DESTDIR)/$(includedir)/ifuid.h: $(S)/ifuid.h
	install -D $< $@

install-target:;

clean:
	rm -f  $(LIB) $(OBJS)
