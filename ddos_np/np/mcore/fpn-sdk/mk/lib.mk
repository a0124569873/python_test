BASELIB:=$(basename $(notdir $(LIB)))
override EXTRA_CFLAGS += $(EXTRA_CFLAGS_$(BASELIB))
override EXTRA_LDFLAGS += $(EXTRA_LDFLAGS_$(BASELIB))

include $(FPNSDK_DIR)/mk/gcc.mk

Q?=
P?=@echo

OBJS?= $(patsubst %.cpp,%.o,$(SRCS:%.c=%.o))

#include any gcc bug workaround
CFLAGS+= $(GCC_CFLAGS_WORKAROUND_BUG)

# Assume -fPIC even for non shared lib because many build 
# of libX.so are made from libX.a, and w/o -fPIC gcc (>=4.3.3)
# will complain.
#
CFLAGS+= -fPIC
CXXFLAGS+= -fPIC

LIST?=$(LIB)

all: ${LIST}

# C language compilation
.c.o:
	$(call cc_rule,$@,$<)

# C++ language compilation
.cpp.o:
	$(call cpp_rule,$@,$<)

clean:
	$(P) '  CLEAN   $(BASELIB)'
	$(Q)rm -f $(BASELIB).a $(BASELIB).so* $(LIB).stripped $(OBJS)

ifeq ($(NOSTRIP), yes)
LIBINSTALL=$(LIB)
else
LIBINSTALL=$(LIB).stripped

$(LIB).stripped: $(LIB)
	$(P) '  STRIP $(LIB)'
	$(Q)$(STRIP) --strip-unneeded -o $@ $<

endif

# Old compat with PREFIX_LIBDIR
ifneq ($(PREFIX_LIBDIR),)
libdir?= $(PREFIX_LIBDIR)
else
prefix?= /usr/local
libdir?= $(prefix)/lib
endif

$(DESTDIR)/$(libdir)/$(LIB): $(LIBINSTALL)
	$(P) '  INSTALL-LIB  $(LIB)'
	$(Q)install -D $< $@

install install-devel: $(DESTDIR)/$(libdir)/$(LIB)

ifeq ($(SHARED_LIB), yes)

$(LIB): $(OBJS)
	$(P) '  LIB     $(notdir $@)'
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(LDFLAGS) -shared $(OBJS) -o $@

install-target: $(DESTDIR)/$(libdir)/$(LIB)

else

AR?=ar
RANLIB?=ranlib
# It is a static library (archive file)
$(LIB): $(OBJS)
	$(P) '  AR      $(notdir $@)'
	$(Q)mkdir -p $(dir $@)
	$(Q)$(AR) cru $(LIB) $(OBJS)
	$(P) '  RANLIB  $(notdir $@)'
	$(Q)$(RANLIB) $(LIB)

install-target:
	@true

endif
