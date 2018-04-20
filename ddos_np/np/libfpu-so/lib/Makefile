LIB := libfpu-so.so

prefix = /usr/local
exec_prefix = $(prefix)
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
bindir = $(prefix)/bin

ifeq ($(FP_DIR),)
$(error FP_DIR is not defined)
endif
ifeq ($(FPNSDK_DIR),)
$(error FPNSDK_DIR is not defined)
endif

ifeq ($(CC),)
CC = gcc
endif

VPATH = $(S)

# Set default fastpath build directory
FP_BIN ?= $(FP_DIR)

LUA = 0

include $(FPNSDK_DIR)/fpn-arch.mk

CFLAGS += -W -Wall -Werror -fvisibility=protected -fPIC -fms-extensions
CFLAGS += -O2 -g -std=c99

CFLAGS += -I$(FP_DIR)/fp-modules/fpu-rpc
CFLAGS += -I$(FP_DIR)/fp-modules/fpu-rpc/lib
CFLAGS += -I$(FP_DIR)/fastpath/include
CFLAGS += $(FPNSDK_CFLAGS)

ifeq ($(LUA),1)
CFLAGS += -DHAVE_LUA
endif

LDFLAGS += -shared
LDFLAGS += -L$(FP_BIN)/fp-modules/fpu-rpc/lib
LDFLAGS += $(FPNSDK_LDFLAGS)

ifeq ($(LUA),1)
LDLIBS += -llua
endif
LDLIBS += -lfpu-rpc
LDLIBS += -lfpn-shmem
LDLIBS += -ldl -lrt

SRCS := fpu-so-glibc.c
SRCS += fpu-so-rpc.c
SRCS += fpu-so-init.c

OBJS := $(SRCS:%.c=%.o)
DEPS := $(SRCS:%.c=%.d)

all: $(LIB)

$(LIB): $(OBJS)
	$(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) -Wp,-MD,$(@:%.o=%.d) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS) $(DEPS) $(LIB)

install install-target install-devel: $(DESTDIR)/$(libdir)/$(LIB)

$(DESTDIR)/$(libdir)/$(LIB): $(LIB)
	install -D $< $@

-include $(DEPS)

.PHONY: all clean install-target install-devel install
