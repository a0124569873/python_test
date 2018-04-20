S?=$($(DIST_IFUID)/ifname2ifuid
STRIP?=strip

VPATH = $(S)

PROG:= ifname2ifuid
SRCS:= ifname2ifuid.c

prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin

CFLAGS+= -O2 -Wall -Werror
CFLAGS+= -g
CFLAGS+= -I$(S)/../libifuid

LDFLAGS+= -L../libifuid
LDADD+= -lifuid

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

prog_clean:
		@rm -f $(OBJS) $(PROG) $(PROG).stripped

install install-target: $(DESTDIR)/$(bindir)/$(PROG)

$(DESTDIR)/$(bindir)/$(PROG): $(PROGINSTALL)
	install -D $< $@

clean: prog_clean

install-devel:;
