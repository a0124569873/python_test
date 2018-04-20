# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

HDRS_MPLS := ng_mpls_common.h ng_mpls_ether.h ng_mpls_ilm2nhlfe.h ng_mpls_nhlfe.h ng_mpls_oam.h
SRCS_MPLS := ng_mpls_ether.c ng_mpls_ilm2nhlfe.c ng_mpls_nhlfe.c ng_mpls_oam.c

HDRS = $(addprefix $(S)/netgraph/, $(HDRS_MPLS))
SRCS = $(addprefix $(S)/netgraph/, $(SRCS_MPLS))

VNB_MODS := vnb_mpls

include $(TOP_S)/kbuild.mk

ifneq ($(DIST_VNB),) # snapgear
ifeq (${CONFIG_PORTS_KTABLES}, y)
EXTRA_CFLAGS += -DHAVE_KTABLES
EXTRA_CFLAGS += -I${DIST_KTABLES}/module
EXTRA_CFLAGS += -I${ROOTDIR}/ports/ktables/config
endif
endif

ifneq ($(KERNELRELEASE),)
obj-m  += $(addsuffix .o,$(VNB_MODS))
vnb_mpls-objs = $(patsubst %.c,%.o,$(SRCS_MPLS))
endif

-include $(TOP_S)/module.mk
