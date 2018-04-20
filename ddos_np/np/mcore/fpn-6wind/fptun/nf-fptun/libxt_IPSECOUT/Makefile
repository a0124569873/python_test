LIB = xtables/libxt_IPSECOUT.so
SHARED_LIB=yes

VPATH= $(S)

SRCS = libxt_IPSECOUT.c

CFLAGS += -I$(DIST_FP)/fptun/nf-fptun/

# iptables requires /lib/xtables
prefix:=

include $(FPNSDK_DIR)/mk/lib.mk
