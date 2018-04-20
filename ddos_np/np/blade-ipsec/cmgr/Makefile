S?=$(CURDIR)

VPATH= $(S)

LIB= libcmgr-blade-ipsec.so

prefix = /usr/local
exec_prefix = $(prefix)
libcmgr-dir = $(exec_prefix)/lib/cmgr
includedir = $(prefix)/include

all: $(LIB)

SRCS:= blade-ipsec-cmgr.c

OBJS = $(SRCS:%.c=%.o)

CFLAGS += -Wall -Werror -fPIC
CFLAGS += -I$(S) -I$(S)/../common

# Last chance to find libnl3 headers in native mode
libnl-cflags ?= $(shell pkg-config --silence-errors --cflags libnl-3.0)
CFLAGS += $(libnl-cflags)

ifeq ($(NOSTRIP), yes)
LIBINSTALL=$(LIB)
else
LIBINSTALL=$(LIB).stripped

$(LIB).stripped: $(LIB)
	$(STRIP) --strip-unneeded -o $@ $<

endif

$(LIB): $(OBJS)
	$(CC) -shared $(OBJS) $(EXTRA_LDFLAGS) -o $@

%.o:%.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

install install-devel install-target: $(DESTDIR)/$(libcmgr-dir)/$(LIB)

$(DESTDIR)/$(libcmgr-dir)/$(LIB): $(LIB)
	install -D $< $@

clean:
	rm -f  $(LIB) $(OBJS)
