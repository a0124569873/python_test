PROG = fpmonitord

VPATH = $(S)

include $(DIST_FP)/mcore_common.mk

CFLAGS += $(FPNSDK_CFLAGS)
CFLAGS += $(MCORE_COMMON_CFLAGS)

CFLAGS += -Wextra -Wall -Werror -Wno-unused-parameter
# use a low optimization level to avoid issues with inlining (on x86_64)
CFLAGS += -O0

SRCS = fpmonitord.c netlink.c

CFLAGS   += $(libevent-cflags)
CFLAGS   += $(libnl-cflags)

LDFLAGS  += $(libevent-ldflags)
LDFLAGS  += $(libnl-ldflags)

LDADD+= -levent -lnl-3 -lnl-route-3
#
# high availability required
CFLAGS   += $(ha-cflags)
LDFLAGS  += $(ha-ldflags)
LDADD    += -l6whas
LDADD    += -lxt -lxml2 -lm

include $(FPNSDK_DIR)/mk/prog.mk

SCRIPT_FILES:=$(addprefix $(S)/,start_fpmonitord.sh)

include $(FPNSDK_DIR)/mk/scripts.mk
