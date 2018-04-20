PROG = sds-ifd

VPATH = $(S)

SRCS  = sdsifd_main.c sdsifd_fp.c sdsifd_cp.c sdsifd_pkt.c sdsifd_nl.c sdsifd_conf.c

CFLAGS += -DHAVE_GCC_FUNCTION

CFLAGS   += -Wextra -Wall -Wno-unused-parameter
CFLAGS   += -Werror

CFLAGS   += $(libevent-cflags)
CFLAGS   += $(libconsole-cflags)
CFLAGS   += $(libstream-cflags)
CFLAGS   += $(libif-cflags)
CFLAGS   += $(libifevent-cflags)
CFLAGS   += $(libnl-cflags)

LDFLAGS  += $(libevent-ldflags)
LDFLAGS  += $(libconsole-ldflags)
LDFLAGS  += $(libstream-ldflags)
LDFLAGS  += $(libif-ldflags)
LDFLAGS  += $(libifevent-ldflags)
LDFLAGS  += $(libnl-ldflags)

LDADD   += -levent
LDADD   += -lconsole
LDADD   += -lstream
LDADD   += -lif
LDADD   += -lifevent
LDADD   += -lnl-3 -lnl-route-3

ifeq ($(CONFIG_HA6W_SUPPORT), y)
CFLAGS += $(ha-cflags)
LDFLAGS += $(ha-ldflags)
LDLIBS += -l6whas -lxml2 -lxt -lm
endif

include $(FPNSDK_DIR)/mk/prog.mk
