# Copyright 2014 6WIND S.A.

S?=$(CURDIR)

prefix ?= /usr/local
includedir = $(prefix)/include
LACP_SRCDIR = $(TOP_S)/tools/lacp

DIST_KCOMPAT?=$(KCOMPAT_DIR)
KCOMPAT_BINDIR?=$(KCOMPAT_DIR)
VRF_BINDIR?=$(VRF_DIR)
DIST_VRF?=$(VRF_DIR)

# inside kbuild.mk, we include vnb.config: sets all $(CONFIG_VNB_*) options
include $(TOP_S)/kbuild.mk

ifeq ($(USE_VRF_NETNS),y)
EXTRA_CFLAGS += -I$(DIST_VRF)/vrf-module/ -DUSE_VRF_NETNS
endif

# kernel shared_mem_t
EXTRA_CFLAGS += -include $(FPNSDK_BIN)/config/fpnsdk_config.h
EXTRA_CFLAGS += -include $(FP_BUILDROOT)/config/fp_config.h
EXTRA_CFLAGS += -I$(DIST_FP)/common
EXTRA_CFLAGS += -I$(FPNSDK_DIR)
EXTRA_CFLAGS += -I$(DIST_FP)/fastpath/include
EXTRA_CFLAGS += -I$(DIST_FP)/fptun
EXTRA_CFLAGS += -I$(DIST_FP)/fp-modules/filter/common
EXTRA_CFLAGS += -I$(DIST_FP)/fp-modules/veda_ddos/common
EXTRA_CFLAGS += -I$(DIST_FP)/fp-modules/tunnel/common
EXTRA_CFLAGS += -I$(DIST_FP)/fp-modules/mcast/common
EXTRA_CFLAGS += -I$(DIST_FP)/fp-modules/ip/common

#
EXTRA_CFLAGS += -I$(DIST_KCOMPAT)/kcompat-module/
EXTRA_CFLAGS += -I$(TOP_S)/sys/netgraph/nglib
EXTRA_CFLAGS += -I$(TOP_S)/tools/lacp

# for kmap_skb.h inclusion
EXTRA_CFLAGS += -I$(TOP_S)/sys/netgraph

ifeq ($(DIST_VNB),)
# in case compiling outside snapgear (no DIST_VNB)
EXTRA_CFLAGS += -I$(includedir)/netgraph
EXTRA_CFLAGS += -I$(includedir)/netgraph/nglib


endif



ifeq (${CONFIG_PORTS_KTABLES}, y)
EXTRA_CFLAGS += -DHAVE_KTABLES
EXTRA_CFLAGS += -I${DIST_KTABLES}/module
EXTRA_CFLAGS += -I${ROOTDIR}/ports/ktables/config
KBUILD_EXTRA_SYMBOLS+= $(ROOTDIR)/ports/ktables/module/Module.symvers
endif

ifeq ($(wildcard $(KCOMPAT_BINDIR)/kcompat-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers),)
KBUILD_EXTRA_SYMBOLS += $(KCOMPAT_BINDIR)/kcompat-module/Module.symvers
else # dkms case
KBUILD_EXTRA_SYMBOLS += $(KCOMPAT_BINDIR)/kcompat-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers
endif

ifeq ($(wildcard $(VRF_BINDIR)/vrf-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers),)
KBUILD_EXTRA_SYMBOLS += $(VRF_BINDIR)/vrf-module/Module.symvers
else # dkms case
KBUILD_EXTRA_SYMBOLS += $(VRF_BINDIR)/vrf-module/$(KERNELRELEASE)/$(KERNELARCH)/Module.symvers
endif



srcs		= ng_base.c ng_parse.c ng_parse.h ng_proc.c ng_proc.h ng_qsort.c

srcs_socket	= ng_socket_linux.c ng_socket.h
srcs_ether	= ng_ether_linux.c ng_ether.h
srcs_iface	= ng_iface_linux.c ng_iface.h
srcs_eiface	= ng_eiface_linux.c ng_eiface.h
srcs_ksocket	= ng_ksocket_linux.c ng_ksocket.h

srcs_tee	= ng_tee.c ng_tee.h
srcs_one2many	= ng_one2many.c ng_one2many.h
srcs_div	= ng_div.c ng_div.h
srcs_split	= ng_split.c ng_split.h
srcs_mux	= ng_mux.c ng_mux.h
#srcs_ddos  =  ng_ddos.c ng_ddos.h
srcs_gen	= ng_gen.c ng_gen.h

CORE_SRCS	= srcs srcs_socket srcs_ether srcs_iface srcs_eiface srcs_ksocket \
		srcs_tee srcs_one2many srcs_div srcs_split srcs_mux  srcs_gen

ifeq ($(CONFIG_VNB_NODE_NFFEC), y)
	srcs_nffec = ng_nffec.c ng_nffec.h
	CORE_SRCS += srcs_nffec
endif

# Only Snapgear should declare DIST_VNB, so testing this variable helps
# to build all VNB modules from that makefile
ifneq ($(DIST_VNB),)
srcs_raw	= ng_raw.c ng_raw.h
srcs_vrrp_mux	= ng_vrrp_mux.c ng_vrrp_mux.h
srcs_filter	= ng_filter.c ng_filter.h
srcs_pae	= ng_pae.c ng_pae.h
srcs_osi	= ng_osi_eth.c ng_osi_tun.c ng_osi.h ng_osi_eth.h ng_osi_tun.h
lacp_srcs	= ieee8023_tlv.c ieee8023ad_marker.c
srcs_ethgrp	= ng_ethgrp.c ng_ethgrp.h $(lacp_srcs)
srcs_pptpgre	= ng_pptpgre.c ng_pptpgre.h
srcs_echo	= ng_echo.c ng_echo.h
srcs_cisco	= ng_cisco.c ng_cisco.h
srcs_vjc	= ng_vjc.c ng_vjc.h
srcs_pppchdlcdetect	= ng_pppchdlcdetect.c ng_pppchdlcdetect.h
srcs_ether_rmon	= ng_ether_rmon.c ng_ether_rmon.h
srcs_tcpmss	= ng_tcpmss.c ng_tcpmss.h

BLD_SRC-$(CONFIG_VNB_NODE_RAW) += srcs_raw
BLD_SRC-$(CONFIG_VNB_NODE_VRRP_MUX) += srcs_vrrp_mux
BLD_SRC-$(CONFIG_VNB_NODE_FILTER) += srcs_filter
BLD_SRC-$(CONFIG_VNB_NODE_PAE) += srcs_pae
BLD_SRC-$(CONFIG_VNB_NODE_OSI) += srcs_osi
BLD_SRC-$(CONFIG_VNB_NODE_PPTPGRE) += srcs_pptpgre
BLD_SRC-$(CONFIG_VNB_NODE_ECHO) += srcs_echo
BLD_SRC-$(CONFIG_VNB_NODE_CISCO) += srcs_cisco
BLD_SRC-$(CONFIG_VNB_NODE_VJC) += srcs_vjc
BLD_SRC-$(CONFIG_VNB_NODE_PPPCHDLCDETECT) += srcs_pppchdlcdetect
BLD_SRC-$(CONFIG_VNB_NODE_ETHER_RMON) += srcs_ether_rmon
BLD_SRC-$(CONFIG_VNB_NODE_TCPMSS) += srcs_tcpmss
endif

BUILD_SRCS_LIST = $(CORE_SRCS) $(BLD_SRC-y)

# Contruct vnb_<module> name from BUILD_SRCS_LIST list. Module name for srcsxxx will be vnbxxx
VNB_MODS = $(patsubst srcs%, vnb%, $(foreach src,$(BUILD_SRCS_LIST),$(src)))

ifneq ($(KERNELRELEASE),)
obj-m  += $(addsuffix .o,$(VNB_MODS))
# prepare matching variables for each module. It will expand as something like
#   vnb_ethgrp = ng_ethgrp.o
#   vnb = ng_base.o ng_parse.o ng_proc.o ng_qsort.o
$(foreach module,$(BUILD_SRCS_LIST),\
	$(eval $(patsubst srcs%, vnb%, $(addsuffix -objs, $(module))) = \
		$(patsubst %.c, %.o, $(filter %.c, $($(module))))))
endif

SRCS := $(addprefix $(S)/,$(foreach src,$(BUILD_SRCS_LIST),$($(src))))
SRCS += $(addprefix $(LACP_SRCDIR)/,$(LACP_SRCS))

# for cache manager (via ng_netlink.h) and MPD
SHARED_HDRS = \
		alignment.h netgraph.h queue.h ng_message.h ng_hash_name.h nfmark.h ng_mppc.h \
		vnblinux.h vnb_in.h vnb_in6.h vnb_ip.h vnb_ip6.h vnb_tcp.h vnb_udp.h vnb_ether.h \
		$(filter %.h, $(srcs) $(srcs_socket) $(srcs_iface) $(srcs_ether) \
			$(srcs_ksocket) $(srcs_socket) $(srcs_tee) $(srcs_eiface))

HDRS += $(addprefix $(S)/,$(SHARED_HDRS))

# defines $(DKMSDIR)/ subdirectory where to store source files
MODULE_SRC_DIR := sys/netgraph
-include $(TOP_S)/module.mk

install install-devel: $(DESTDIR)/$(prefix)/modules/vnb/base-module/Module.symvers

$(DESTDIR)/$(prefix)/modules/vnb/base-module/Module.symvers: $(O)/Module.symvers
	install -D -m 644 $< $@

DKMS_DEPS= nglib/ip6_sprintf.h nglib/inet_pton.c
NGLIB_HDRS = $(addprefix $(S)/,$(DKMS_DEPS))

install-nglib: $(NGLIB_HDRS)
	$(MAKE) HDRS_SUBDIR=netgraph/nglib HDRS="$(NGLIB_HDRS)" install-headers

ifeq ($(PKG_DKMS),y)
install install-target: install-nglib
else
install install-devel: install-nglib
endif
