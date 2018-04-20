S?=$(CURDIR)
O?=$(CURDIR)

-include $(S)/.pkg-conf
export $(filter PKG_%,$(.VARIABLES))

export FP_DOT_CONFIG=$(O)/config/fp.config
export FP_CONFIG_H=$(O)/config/fp_config.h

MCONFIG_TITLE=fp
MCONFIG_NAME=$(FP_DOT_CONFIG)
MCONFIG_HEADER=$(FP_CONFIG_H)
MCONFIG_PATH=$(S)

# If not set, MCONF_BINDIR default to /usr/local/mconf-tools, unless
# user has specified the source directory.
MCONF_BINDIR?=$(if $(DIST_MCONF_TOOLS),$(DIST_MCONF_TOOLS),/usr/local/mconf-tools)
include $(MCONF_BINDIR)/template.mk

# Nothing else to do at configuration step.
# This allows to configure even if fpn-sdk is not built.
ifeq ($(filter config %config,$(MAKECMDGOALS)),)

DIST_FP=$(S)
export DIST_FP

DIST_VNB?=$(DIST_FP)/../vnb
export DIST_VNB
VNB_BINDIR?=/usr/local/vnb
export VNB_BINDIR

ifeq ($(CONFIG_MCORE_BUILTIN_VSWITCH),y)
export DIST_FP_VSWITCH?=$(DIST_FP)/../fp-ovs
endif

export FP_BUILDROOT=$(O)
FPNSDK_DIR?=/usr/local/fpn-sdk
export FPNSDK_DIR

# for sub components looking for $IFUID_DIR/ifuid-module
IFUID_DIR?=/usr/local/modules/ifuid
export IFUID_DIR

export USE_VRF_NETNS ?= y

ifeq ($(USE_VRF_NETNS),y)
# for sub components looking for $VRF_DIR/vrf-module
VRF_DIR?=/usr/local/modules/vrf
export VRF_DIR
endif

$(if $(FPNSDK_DIR),,$(error FPNSDK_DIR not defined))

-include $(FPNSDK_DIR)/mk/verbose.mk
-include $(FPNSDK_DIR)/fpn-arch.mk
-include $(FP_DOT_CONFIG)

SUBDIR-y =
SUBDIR-$(CONFIG_MCORE_FASTPATH) += libnetfpc libfp_shm
SUBDIR-$(CONFIG_MCORE_FASTPATH) += fp-modules
SUBDIR-$(CONFIG_MCORE_FASTPATH) += fastpath
SUBDIR-$(CONFIG_MCORE_FPDEBUG) += fpdebug
SUBDIR-$(CONFIG_MCORE_FPM) += fpm
SUBDIR-$(CONFIG_MCORE_SDSIFD) += distrib-tools/sds-ifd
SUBDIR-$(CONFIG_MCORE_RFPVI) += distrib-tools/rfpvi
SUBDIR-$(CONFIG_MCORE_FPTUN) += fptun
ifeq ($(CONFIG_MCORE_IPSEC),y)
SUBDIR-$(CONFIG_MCORE_FPTUN) += fptun/nf-fptun
SUBDIR-$(CONFIG_MCORE_FPTUN) += fptun/nf-fptun/libxt_IPSECOUT
endif
SUBDIR-$(CONFIG_MCORE_FPS) += fps
SUBDIR-$(CONFIG_MCORE_HITFLAGS_SYNC) += hitflagsd
SUBDIR-$(CONFIG_MCORE_FPMONITORD) += fpmonitord
SUBDIR-$(CONFIG_MCORE_EMBEDDED_SCRIPTS) += embedded-scripts
ifeq ($(CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY),y)
SUBDIR-$(CONFIG_MCORE_FP_PLUGINS) += fp-plugins
endif

SUBDIR:=$(SUBDIR-y)

ifeq ($(PKG_DKMS),y)
DKMS_NAME := fastpath
PKG_VERSION ?= unknown
export DKMSDIR ?= $(DESTDIR)/usr/src/$(DKMS_NAME)-$(PKG_VERSION)

DKMS_DEPS=\
 mcore_common.mk \
 common/fp-rfps-proto.h \
 common/fp-hitflags.h \
 common/fp-blade.h

install install-target:
	$(Q)if find $(DKMSDIR)/*.dkms.conf 1>/dev/null 2>&1; then \
		install -D -m 644 $(S)/Makefile.dkms $(DKMSDIR)/Makefile && \
		printf 'PACKAGE_NAME="$(DKMS_NAME)"\n'\
	'PACKAGE_VERSION="$(PKG_VERSION)"\n'\
	'AUTOINSTALL="yes"\n'\
	'BUILD_DEPENDS[0]="ifuid"\n'\
	'MAKE[0]="make KERNEL_SRC=$${kernel_source_dir}'\
	' USE_VRF_NETNS=$(USE_VRF_NETNS)'\
	' KERNELARCH=$$arch modules"\n'\
	'CLEAN=":"\n' > $(DKMSDIR)/dkms.conf && \
		idx=0 && \
		for i in $$(ls $(DKMSDIR)/*.dkms.conf 2>/dev/null); do \
			sed "s/\[INDEX\]/[$$idx]/g" $$i >> $(DKMSDIR)/dkms.conf || exit 1; \
			idx=$$(( $$idx + 1 )); \
		done && \
		rm -f $(DKMSDIR)/*.dkms.conf && \
		for FILE in $(DKMS_DEPS); do \
			if [ -f $(DIST_FP)/$$FILE ]; then \
				install -D -m 644 $(DIST_FP)/$$FILE $(DKMSDIR)/$$FILE; \
			fi; \
		done && \
		rm -f $(DKMSDIR)/*.post_build.sh; \
	fi
endif

-include $(FPNSDK_DIR)/mk/subdir.mk

$(SUBDIR): $(MCONFIG_HEADER)

fpdebug: libnetfpc libfp_shm

fp-modules: libnetfpc libfp_shm

fpm: libnetfpc libfp_shm fp-modules

fptun/nf-fptun: distrib-tools/rfpvi

fps: fptun

# Empty rules for deps
$(SUBDIR-):

prefix ?= /usr/local/fp

MCORE_DEVEL_FILES :=

MCORE_DEVEL_FILES += $(DIST_FP)/mcore_common.mk
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/mcore.mk

MCORE_DEVEL_FILES += $(DIST_FP)/common/fp.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-blade.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-hlist.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-seqlock.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-if.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-jhash.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-rfps-conf.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-socket-portset.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-socket-stat.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-stats-defs.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-tc-var.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-track-debug.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-var.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-log.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-syslog.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-packet.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-exceptions.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/net/fp-socket.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/net/fp-ethernet.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/netinet/fp-in.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/netinet/fp-in6.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/netinet/fp-ip.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/netinet/fp-ip6.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/netinet/fp-udp.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/netinet/fp-sctp.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/netinet/fp-tcp.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/netinet/fp-icmp.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-bsd-compat.h
MCORE_DEVEL_FILES += $(DIST_FP)/fpdebug/fpdebug.h
MCORE_DEVEL_FILES += $(DIST_FP)/fpdebug/fpdebug-priv.h
MCORE_DEVEL_FILES += $(DIST_FP)/fpm/fpm_common.h
MCORE_DEVEL_FILES += $(DIST_FP)/fptun/fptun.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/ip/common/fp-addr-list.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/fp-anti-ddos.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/ddos_gc.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/ddos_hash.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/flow_define.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/black_white.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/syn_flood_define.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/udp_flood_define.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/server_node_define.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/ddos_log.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/cJSON.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/ip_mac.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/filter/common/fp-netfilter.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/filter6/common/fp-netfilter6.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/ipsec/common/fp-ipsec.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/ipsec/common/fp-sad.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/ipsec/common/fp-spd.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/ipsec/common/filter/filter.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/ipsec6/common/fp-ipsec6.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/ipsec6/common/fp-sad6.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/ipsec6/common/fp-spd6.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/tunnel/common/fp-tunnels-var.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-module.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-stats.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/include/netinet/fp-icmp6.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-main-process.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-ether.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-hook.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-mbuf-priv.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-mbuf-mtag.h
MCORE_DEVEL_FILES += $(DIST_FP)/fpdebug/fpdebug-stats.h
MCORE_DEVEL_FILES += $(DIST_FP)/fpdebug/fpdebug-ifnet.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/svti/common/fp-svti.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/svti/common/fp-svti6.h
MCORE_DEVEL_FILES += $(DIST_FP)/common/fp-hitflags.h
MCORE_DEVEL_FILES += $(DIST_FP)/fastpath/fp-netfpc.h
MCORE_DEVEL_FILES += $(DIST_FP)/libnetfpc/netfpc.h
MCORE_DEVEL_FILES += $(DIST_FP)/libnetfpc/netfpc_var.h

ifeq ($(CONFIG_MCORE_VXLAN),y)
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/vxlan/common/fp-vxlan-var.h
endif

ifeq ($(CONFIG_MCORE_BRIDGE),y)
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/bridge/common/fp-bridge-var.h
endif

ifeq ($(CONFIG_MCORE_EBTABLES),y)
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/filter-bridge/common/fp-ebtables-var.h
endif

ifeq ($(CONFIG_MCORE_LAG),y)
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/lag/common/fp-bonding-var.h
endif

ifeq ($(CONFIG_MCORE_GRE),y)
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/gre/common/fp-gre-var.h
endif

ifneq ($(CONFIG_MCORE_MULTICAST4)$(CONFIG_MCORE_MULTICAST6),)
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/mcast/common/fp-mroute.h
endif

ifeq ($(CONFIG_MCORE_SOCKET),y)
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-so.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/sys/socket.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/sys/socketvar.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/sys/protosw.h
endif

ifeq ($(CONFIG_MCORE_ARCH_DPDK)$(CONFIG_MCORE_SW_SCHED),yy)
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/egress-qos/dataplane/fpn-sw-sched.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/filter/dataplane/fp-nf-tables.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/filter/common/fp-nfct.h
endif

MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/dataplane/general_function.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/dataplane/server_flow_deal.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/dataplane/syn_flood_deal.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/dataplane/udp_flood_deal.h
MCORE_DEVEL_FILES += $(DIST_FP)/fp-modules/veda_ddos/dataplane/server_ip_port_deal.h

install install-target: $(DESTDIR)$(prefix)/config/fp_config.h $(DESTDIR)$(prefix)/config/fp.config

install install-devel: .install-devel

.install-devel:
	$Q for i in $(patsubst $(DIST_FP)/%,%,$(MCORE_DEVEL_FILES)); do \
	  if [ -f $(DIST_FP)/$$i ]; then \
	    install -D $(DIST_FP)/$$i $(DESTDIR)$(prefix)/$$i; \
	  fi; \
	done

$(DESTDIR)$(prefix)/%: $(CURDIR)/%
	$(Q)install -D $< $@

$(DESTDIR)$(prefix)/config/fp_config.h: $(FP_BUILDROOT)/config/fp_config.h
	$(Q)install -D -m 644 $< $@

$(DESTDIR)$(prefix)/config/fp.config: $(FP_BUILDROOT)/config/fp.config
	$(Q)install -D -m 644 $< $@
endif
