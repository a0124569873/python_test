ifeq ($(PROGX),)
PROGRAM = $(PROG)
else
PROGRAM = $(PROGX)
endif

override EXTRA_CFLAGS += $(EXTRA_CFLAGS_$(PROGRAM))
override EXTRA_LDFLAGS += $(EXTRA_LDFLAGS_$(PROGRAM))

include $(FPNSDK_DIR)/mk/gcc.mk

OBJS = $(patsubst %.cpp,%.o,$(patsubst %.c,%.o,$(SRCS:%.cc=%.o)))


#include any gcc bug workaround
CFLAGS+= $(GCC_CFLAGS_WORKAROUND_BUG)

all: $(PROGRAM)

$(PROG): $(OBJS)
	$(P) '  PROG $(notdir $@)'
	$(Q)$(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS) $(LDADD) $(LDLIBS)

$(PROGX): $(OBJS)
	$(P) '  PROGX $(notdir $@)'
	$(Q)$(CXX) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS) $(LDADD) $(LDLIBS)

# C language compilation
.c.o:
	$(call cc_rule,$@,$<)

# C++ language compilation
.cpp.o .cc.o:
	$(call cpp_rule,$@,$<)

clean:
	$(P) '  CLEAN $(PROGRAM)'
	$(Q)rm -f $(PROGRAM) $(PROGRAM).stripped $(OBJS)

ifeq ($(NOSTRIP),yes)
PROG_INSTALL=$(PROGRAM)
else
PROG_INSTALL=$(PROGRAM).stripped

$(PROGRAM).stripped: $(PROGRAM)
	$(P) '  STRIP $(PROGRAM)'
	$(Q)$(STRIP) --strip-all -o $@ $<

endif

# Old compat with PREFIX_BINDIR
ifneq ($(PREFIX_BINDIR),)
bindir = $(PREFIX_BINDIR)
else
prefix = /usr/local
bindir = $(prefix)/bin
PREFIX_BINDIR = $(bindir)/
endif

install-target install: $(DESTDIR)/$(bindir)/$(PROGRAM)

$(DESTDIR)/$(bindir)/$(PROGRAM): $(PROG_INSTALL)
	$(P) '  INSTALL-PROG $(PROGRAM)'
	$(Q)install -D $< $@

install-devel:;
