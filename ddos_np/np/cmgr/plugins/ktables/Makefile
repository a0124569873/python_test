S?=$(CURDIR)
ifeq ("$(origin V)", "command line")
Q =
P = @ true
else
Q = @
P = @ echo
endif

VPATH= $(S)

LIB= libcmgr-ktables.so

prefix = /usr/local
exec_prefix = $(prefix)
libcmgr-dir = $(exec_prefix)/lib/cmgr
includedir = $(prefix)/include

all: $(LIB)

SRCS:= ktables-cmgr.c

OBJS = $(SRCS:%.c=%.o)

CFLAGS += -Wall -Werror -fPIC
CFLAGS += -I$(S) -I$(DIST_KTABLES)/module

# Last chance to find libnl3 headers in native mode
libnl-cflags ?= $(shell pkg-config --silence-errors --cflags libnl-3.0)
CFLAGS += $(libnl-cflags)

ifeq ($(NOSTRIP), yes)
LIBINSTALL=$(LIB)
else
LIBINSTALL=$(LIB).stripped

$(LIB).stripped: $(LIB)
	$P '  STRIP $(notdir $@)'
	$Q $(STRIP) --strip-unneeded -o $@ $<

endif

$(LIB): $(OBJS)
	$P '  LD $(notdir $@)'
	$Q $(CC) -shared $(OBJS) $(EXTRA_LDFLAGS) -o $@

%.o:%.c
	$P '  CC $(notdir $@)'
	$Q $(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

install install-devel install-target: $(DESTDIR)/$(libcmgr-dir)/$(LIB)

$(DESTDIR)/$(libcmgr-dir)/$(LIB): $(LIB)
	$P '  INSTALL $(notdir $@)'
	$Q install -D $< $@

clean:
	$Q rm -f  $(LIB) $(OBJS)
