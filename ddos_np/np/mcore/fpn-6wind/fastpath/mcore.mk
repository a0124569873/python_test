#
# Define sources and paths for 6WIND fastpath
#

#### CFLAGS

MCORE_CFLAGS += -I$(DIST_FP)/fastpath
MCORE_CFLAGS += -I$(DIST_FP)/libnetfpc
MCORE_CFLAGS += -I$(DIST_FP)/fpdebug
MCORE_CFLAGS += -D__FastPath__

ifeq ($(CONFIG_MCORE_VNB),y)
MCORE_CFLAGS += -I$(DIST_VNB)/sys -I$(DIST_FP)/fp-modules/vnb/dataplane
MCORE_CFLAGS += -I$(DIST_VNB)/etherbridge -I$(DIST_VNB)/gre
MCORE_CFLAGS += -I$(DIST_VNB)/lag -I$(DIST_VNB)/mpls -I$(DIST_VNB)/vlan
MCORE_CFLAGS += -I$(DIST_VNB)/ppp -I$(DIST_VNB)/l2tp -I$(DIST_VNB)/pppoe
MCORE_CFLAGS += -I$(DIST_VNB)/gtpu
MCORE_CFLAGS += -I$(DIST_VNB)/sys/netgraph/nglib
MCORE_CFLAGS += -I$(DIST_VNB)/tools/lacp
VNB_BINDIR?=$(ROOTDIR)/ports/vnb
MCORE_CFLAGS += -I$(VNB_BINDIR)/config/
MCORE_CFLAGS += -D_KERNEL
ifeq ($(CONFIG_MCORE_KTABLES), y)
MCORE_CFLAGS += -I$(DIST_KTABLES)/module
MCORE_CFLAGS += -I$(ROOTDIR)/ports/ktables/config
endif
endif

ifeq ($(CONFIG_MCORE_TC),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/tc/common
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/tc/dataplane
endif

ifeq ($(CONFIG_MCORE_TC_ERL),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/tc-erl/dataplane
endif

MCORE_CFLAGS += $(MCORE_COMMON_CFLAGS)

#### Sources

MCORE_FILES += $(DIST_FP)/fastpath/fp-init.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-shared.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-bsd-compat.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-main-process.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-ether.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-packet.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-module.c

ifeq ($(CONFIG_MCORE_IP),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/ip/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/ip/dataplane/fp-ip.c
MCORE_FILES += $(DIST_FP)/fp-modules/ip/dataplane/fp-fragment.c
ifeq ($(CONFIG_MCORE_IP_REASS),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/reass/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/reass/dataplane/fp-reass.c
endif
ifeq ($(CONFIG_MCORE_IPV6_REASS),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/reass6/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/reass6/dataplane/fp-reass6.c
endif
endif # CONFIG_MCORE_IP
ifeq ($(CONFIG_MCORE_ARP_REPLY),y)
MCORE_FILES += $(DIST_FP)/fp-modules/ip/dataplane/fp-arp.c
endif
ifeq ($(CONFIG_MCORE_TCP_MSS),y)
MCORE_FILES += $(DIST_FP)/fp-modules/ip/dataplane/fp-tcp-mss.c
endif

ifeq ($(CONFIG_MCORE_MULTICAST4),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/mcast/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/mcast/dataplane/fp-mcast.c
endif
ifeq ($(CONFIG_MCORE_IPV6),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/ip6/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/ip6/dataplane/fp-ip6.c
ifeq ($(CONFIG_MCORE_MULTICAST6),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/mcast6/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/mcast6/dataplane/fp-mcast6.c
endif
endif
MCORE_FILES += $(DIST_FP)/fastpath/fp-fptun.c
ifeq ($(CONFIG_MCORE_MULTIBLADE),y)
MCORE_FILES += $(DIST_FP)/fastpath/fp-fpib.c
endif
MCORE_FILES += $(DIST_FP)/fastpath/fp-exceptions.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-mbuf-mtag.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-netfpc.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-test-fpn0.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-syslog.c
MCORE_FILES += $(DIST_FP)/fastpath/fp-eqos.c
MCORE_FILES += $(DIST_FP)/common/fp-if.c

ifeq ($(CONFIG_MCORE_EMBEDDED_FPDEBUG), y)

MCORE_CFLAGS += $(libifuid-cflags)
MCORE_LDLAGS += $(libifuid-ldflags) -lifuid

MCORE_FILES += $(DIST_FP)/fpdebug/fpdebug.c
MCORE_FILES += $(DIST_FP)/fpdebug/cli-cmd/fp-cli-commands.c
MCORE_FILES += $(DIST_FP)/fpdebug/b64/b64.c
MCORE_FILES += $(DIST_FP)/fpdebug/fpdebug-stats.c
MCORE_FILES += $(DIST_FP)/fpdebug/fp-autoconf-if.c

MCORE_FILES += $(DIST_FP)/fpdebug/licence/fp-licence.c
MCORE_FILES += $(DIST_FP)/fpdebug/licence/fp-hd-no.c
MCORE_FILES += $(DIST_FP)/fpdebug/licence/fp-net-macs.c
MCORE_FILES += $(DIST_FP)/fpdebug/licence/fp-cpu-model.c
MCORE_FILES += $(DIST_FP)/fpdebug/md5/md5.c
MCORE_FILES += $(DIST_FP)/fpdebug/licence/fp-licence-decode.c
MCORE_FILES += $(DIST_FP)/fpdebug/licence/fp-serial-no.c
MCORE_CFLAGS += -I$(FP_BUILDROOT)/config


ifeq ($(CONFIG_MCORE_VNB),y)
MCORE_FILES += $(DIST_FP)/fpdebug/fpd-vnb.c
endif
ifeq ($(CONFIG_MCORE_ARCH_DPDK),y)
MCORE_FILES += $(DIST_FP)/fpdebug/fpd-dpdk-vf.c
MCORE_FILES += $(DIST_FP)/fpdebug/fpd-dpdk-rss.c
MCORE_FILES += $(DIST_FP)/fpdebug/fpd-dpdk-link-flowctrl.c
MCORE_FILES += $(DIST_FP)/fpdebug/fpd-dpdk-fdir.c
endif
ifeq ($(CONFIG_MCORE_IP),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/ip/common
MCORE_FILES += $(DIST_FP)/fp-modules/ip/common/fp-l3.c
MCORE_FILES += $(DIST_FP)/fp-modules/ip/common/fp-addr-list.c
endif
ifeq ($(CONFIG_MCORE_TAP_CIRCULAR_BUFFER),y)
MCORE_FILES += $(DIST_FP)/fp-modules/tap/common/fp-bpf.c
endif
ifeq ($(CONFIG_MCORE_IPSEC), y)
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/common/fp-ipsec.c
ifeq ($(CONFIG_MCORE_IPSEC_SVTI), y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/svti/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/svti/common/fp-svti.c
ifeq ($(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA), y)
MCORE_FILES += $(DIST_FP)/fp-modules/svti/dataplane/fp-svti-lookup.c
endif
endif
endif
ifeq ($(CONFIG_MCORE_IPSEC_IPV6), y)
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec6/common/fp-ipsec6.c
ifeq ($(CONFIG_MCORE_IPSEC_SVTI), y)
MCORE_FILES += $(DIST_FP)/fp-modules/svti/common/fp-svti6.c
endif
endif
ifeq ($(CONFIG_MCORE_VXLAN), y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/vxlan/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/vxlan/common/fp-vxlan-config.c
MCORE_FILES += $(DIST_FP)/fp-modules/vxlan/dataplane/fp-vxlan.c
endif
ifeq ($(CONFIG_MCORE_VLAN), y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/vlan/common
MCORE_FILES += $(DIST_FP)/fp-modules/vlan/common/fp-vlan-config.c
MCORE_FILES += $(DIST_FP)/fp-modules/vlan/dataplane/fp-vlan.c
endif
ifeq ($(CONFIG_MCORE_MACVLAN), y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/macvlan/common
MCORE_FILES += $(DIST_FP)/fp-modules/macvlan/common/fp-macvlan-config.c
MCORE_FILES += $(DIST_FP)/fp-modules/macvlan/dataplane/fp-macvlan.c
endif
ifeq ($(CONFIG_MCORE_BRIDGE), y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/bridge/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/bridge/common/fp-bridge-config.c
MCORE_FILES += $(DIST_FP)/fp-modules/bridge/dataplane/fp-bridge.c
endif
ifeq ($(CONFIG_MCORE_LAG), y)
MCORE_FILES += $(DIST_FP)/fp-modules/lag/common/fp-bonding-config.c
MCORE_FILES += $(DIST_FP)/fp-modules/lag/dataplane/fp-bonding.c
endif
ifeq ($(CONFIG_MCORE_GRE), y)
MCORE_FILES += $(DIST_FP)/fp-modules/gre/common/fp-gre-config.c
MCORE_FILES += $(DIST_FP)/fp-modules/gre/dataplane/fp-gre.c
endif
MCORE_FILES += $(DIST_FP)/common/fp.c
MCORE_FILES += $(DIST_FP)/common/fp-blade.c
ifeq ($(CONFIG_MCORE_EBTABLES), y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/filter-bridge/common
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/filter-bridge/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/filter-bridge/common/fp-ebtables-config.c
MCORE_FILES += $(DIST_FP)/fp-modules/filter-bridge/dataplane/fp-ebtables.c
endif
ifeq ($(CONFIG_MCORE_NETFILTER), y)
MCORE_FILES += $(DIST_FP)/fp-modules/filter/common/fp-netfilter.c
endif
MCORE_FILES += $(DIST_FP)/common/fp-rfps-conf.c
endif

# json
MCORE_FILES += $(DIST_FP)/fp-modules/veda_ddos/common/cJSON.c

ifeq ($(CONFIG_MCORE_TC),y)
MCORE_FILES += $(DIST_FP)/fp-modules/tc/common/fpn-tc.c
MCORE_FILES += $(DIST_FP)/fp-modules/tc/dataplane/fp-tc.c
MCORE_FILES += $(DIST_FP)/fp-modules/tc/cli/fpd-tc.c
ifeq ($(CONFIG_MCORE_TC_ERL),y)
MCORE_FILES += $(DIST_FP)/fp-modules/tc-erl/dataplane/fp-tc-erl.c
endif
endif

ifeq ($(CONFIG_MCORE_IPSEC),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/ipsec/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/dataplane/fp-ipsec-common.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/dataplane/fp-ipsec-lookup.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/dataplane/fp-ipsec-input.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/dataplane/fp-ipsec-output.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/dataplane/fp-ipsec-replay.c
ifeq ($(CONFIG_MCORE_IPSEC_TRIE),y)
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/common/filter/pool.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/common/filter/egt-pc/egt-pc.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/common/filter/classif/classifier.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/common/filter/classif/binary_tree.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/common/filter/rfc/rfc.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec/common/filter/rfc/dheap.c
endif
endif

ifeq ($(CONFIG_MCORE_IPSEC_IPV6),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/ipsec6/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec6/dataplane/fp-ipsec6-lookup.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec6/dataplane/fp-ipsec6-input.c
MCORE_FILES += $(DIST_FP)/fp-modules/ipsec6/dataplane/fp-ipsec6-output.c
endif

ifeq ($(CONFIG_MCORE_NETFILTER),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/filter/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/filter/dataplane/fp-nf-tables.c
MCORE_FILES += $(DIST_FP)/fp-modules/filter/dataplane/fp-nf-physdev.c
ifeq ($(CONFIG_MCORE_NETFILTER_NAT),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/nat/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/nat/dataplane/fp-nf-nat.c
endif
ifeq ($(CONFIG_MCORE_NETFILTER_CACHE),y)
MCORE_FILES += $(DIST_FP)/fp-modules/filter/dataplane/fp-nf-cache.c
endif
endif

MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/veda_ddos/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/veda_ddos/dataplane/server_flow_deal.c
MCORE_FILES += $(DIST_FP)/fp-modules/veda_ddos/dataplane/server_config.c
MCORE_FILES += $(DIST_FP)/fp-modules/veda_ddos/dataplane/ddos_log.c
MCORE_FILES += $(DIST_FP)/fp-modules/veda_ddos/fp-anti-ddos-main-loop.c
MCORE_FILES += $(DIST_FP)/fp-modules/veda_ddos/fp-anti-ddos.c

ifeq ($(CONFIG_MCORE_NETFILTER_IPV6),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/filter6/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/filter6/dataplane/fp-nf6-tables.c
ifeq ($(CONFIG_MCORE_NETFILTER_IPV6_CACHE),y)
MCORE_FILES += $(DIST_FP)/fp-modules/filter6/dataplane/fp-nf6-cache.c
endif
endif

ifneq ($(FASTPATH_PLUGIN),y)
ifeq ($(CONFIG_MCORE_VNB),y)
# Include VNB config file
include $(VNB_BINDIR)/config/vnb.config

# Core VNB files
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_base.c
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_parse.c
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_qsort.c

# Stack nodes
MCORE_FILES += $(DIST_FP)/fp-modules/vnb/dataplane/fp-ng_ether.c
MCORE_FILES += $(DIST_FP)/fp-modules/vnb/dataplane/fp-ng_socket.c
MCORE_FILES += $(DIST_FP)/fp-modules/vnb/dataplane/fp-ng_iface.c
MCORE_FILES += $(DIST_FP)/fp-modules/vnb/dataplane/fp-ng_eiface.c
MCORE_FILES += $(DIST_FP)/fp-modules/vnb/dataplane/fp-ng_ksocket.c

# Liaison nodes
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_tee.c
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_div.c
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_split.c
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_one2many.c
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_mux.c


# other nodes
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_ddos.c

ifeq ($(CONFIG_VNB_NODE_ETHGRP),y)
MCORE_FILES += $(DIST_VNB)/lag/netgraph/ng_ethgrp.c
MCORE_FILES += $(DIST_VNB)/lag/netgraph/ieee8023_tlv.c
MCORE_FILES += $(DIST_VNB)/lag/netgraph/ieee8023ad_marker.c
endif
ifeq ($(CONFIG_VNB_NODE_ETF),y)
MCORE_FILES += $(DIST_VNB)/etherbridge/netgraph/ng_etf.c
endif
ifeq ($(CONFIG_VNB_NODE_GRE),y)
MCORE_FILES += $(DIST_VNB)/gre/netgraph/ng_gre.c
endif
ifeq ($(CONFIG_VNB_NODE_VLAN),y)
MCORE_FILES += $(DIST_VNB)/vlan/netgraph/ng_vlan.c
MCORE_CFLAGS += -I$(DIST_VNB)/vlan
endif
ifeq ($(CONFIG_VNB_NODE_BRIDGE),y)
MCORE_FILES += $(DIST_VNB)/etherbridge/netgraph/ng_bridge.c
endif
ifeq ($(CONFIG_VNB_NODE_VRRP_MUX),y)
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_vrrp_mux.c
endif
ifeq ($(CONFIG_VNB_NODE_MPLS),y)
MCORE_FILES += $(DIST_VNB)/mpls/netgraph/ng_mpls_ilm2nhlfe.c
MCORE_FILES += $(DIST_VNB)/mpls/netgraph/ng_mpls_nhlfe.c
MCORE_FILES += $(DIST_VNB)/mpls/netgraph/ng_mpls_ether.c
MCORE_FILES += $(DIST_VNB)/mpls/netgraph/ng_mpls_oam.c
endif
ifeq ($(CONFIG_VNB_NODE_NFFEC),y)
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_nffec.c
endif
ifeq ($(CONFIG_VNB_NODE_ETHERBRIDGE),y)
MCORE_FILES += $(DIST_VNB)/etherbridge/netgraph/ng_etherbridge.c
endif
ifeq ($(CONFIG_VNB_NODE_GEN),y)
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_gen.c
endif
ifeq ($(CONFIG_VNB_NODE_GTPU),y)
MCORE_FILES += $(DIST_VNB)/gtpu/netgraph/ng_gtpu_pktq.c
MCORE_FILES += $(DIST_VNB)/gtpu/netgraph/ng_gtpu.c
endif
ifeq ($(CONFIG_VNB_NODE_PPPCHDLCDETECT),y)
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_pppchdlcdetect.c
endif
ifeq ($(CONFIG_VNB_NODE_CISCO),y)
MCORE_FILES += $(DIST_VNB)/sys/netgraph/ng_cisco.c
endif
ifeq ($(CONFIG_VNB_NODE_PPP),y)
MCORE_FILES += $(DIST_VNB)/ppp/netgraph/ng_ppp.c
endif
ifeq ($(CONFIG_VNB_NODE_PPPOE),y)
MCORE_FILES += $(DIST_VNB)/pppoe/netgraph/ng_pppoe.c
endif
ifeq ($(CONFIG_VNB_NODE_L2TP),y)
MCORE_FILES += $(DIST_VNB)/l2tp/netgraph/ng_l2tp.c
endif
endif
endif

ifneq ($(CONFIG_MCORE_XIN4)$(CONFIG_MCORE_XIN6),)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/tunnel/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/tunnel/dataplane/fp-tunnels.c
endif

ifeq ($(CONFIG_MCORE_TAP),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/tap/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/tap/dataplane/fp-tap.c
endif

ifeq ($(CONFIG_MCORE_TAP_BPF),y)
MCORE_FILES += $(DIST_FP)/fp-modules/tap/dataplane/fp-bpf_filter.c
endif

ifeq ($(CONFIG_MCORE_TRAFFIC_GEN),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/traffic-gen/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/traffic-gen/dataplane/fp-traffic-gen.c
MCORE_FILES += $(DIST_FP)/fp-modules/traffic-gen/dataplane/fp-traffic-gen-tx.c
MCORE_FILES += $(DIST_FP)/fp-modules/traffic-gen/dataplane/fp-traffic-gen-rx.c
MCORE_FILES += $(DIST_FP)/fp-modules/traffic-gen/dataplane/fp-tg-latency.c
ifeq ($(CONFIG_MCORE_TRAFFIC_GEN_SCTP),y)
MCORE_FILES += $(DIST_FP)/fp-modules/traffic-gen/dataplane/fp-tg-sctp.c
endif
ifeq ($(CONFIG_MCORE_TRAFFIC_GEN_TCP),y)
MCORE_FILES += $(DIST_FP)/fp-modules/traffic-gen/dataplane/fp-tg-tcp.c
endif
endif

ifeq ($(CONFIG_MCORE_SOCKET),y)
ifeq ($(CONFIG_MCORE_EMBEDDED_FPDEBUG),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/tcp-udp/cli
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/cli/fpd-socket.c
endif
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/tcp-udp/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-so.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/kern/subr_hash.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/kern/uipc_socket2.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/net/if.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/kern/uipc_socket.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/kern/uipc_domain.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/in_proto.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/in_pcb.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/udp_usrreq.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/ip_icmp.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/tcp_input.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/tcp_output.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/tcp_subr.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/tcp_usrreq.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/tcp_timer.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/tcp_congctl.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netinet/tcp_sack.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netstat/inet.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp/dataplane/fp-bsd/netconfig/netconfig.c
ifeq ($(CONFIG_MCORE_SOCKET_INET6),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/tcp-udp6/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp6/dataplane/fp-bsd/netinet6/in6_pcb.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp6/dataplane/fp-bsd/netinet6/in6_proto.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp6/dataplane/fp-bsd/netinet6/in6_src.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp6/dataplane/fp-bsd/net/if6.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp6/dataplane/fp-bsd/netinet6/icmp6.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp6/dataplane/fp-bsd/netinet6/udp6_usrreq.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp6/dataplane/fp-bsd/netinet6/udp6_output.c
MCORE_FILES += $(DIST_FP)/fp-modules/tcp-udp6/dataplane/fp-bsd/netstat/inet6.c
endif
ifneq ($(CONFIG_MCORE_FP_PLUGINS)$(CONFIG_MCORE_ARCH_HAS_SHARED_LIBRARY),yy)
ifeq ($(CONFIG_MCORE_EMBEDDED_FPDEBUG),y)
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/udp-server/fpd-so-udp-server.c
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/tcp-server/fpd-so-tcp-server.c
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/tcp-client/fpd-so-tcp-client.c
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/tcp-proxy/fpd-so-tcp-proxy.c
ifeq ($(CONFIG_MCORE_TCP_SENDER),y)
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/http-client/fpd-so-http-client.c
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/tcp-sender/fpd-so-tcp-sender.c
endif
endif
MCORE_CFLAGS += -I$(DIST_FP)/fp-plugins/so-apps
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/udp-server/fp-so-udp-server.c
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/tcp-server/fp-so-tcp-server.c
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/tcp-client/fp-so-tcp-client.c
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/tcp-proxy/fp-so-tcp-proxy.c
ifeq ($(CONFIG_MCORE_TCP_SENDER),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-plugins/so-apps/tcp-sender
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/tcp-sender/fp-so-tcp-sender.c
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/tcp-sender/fp-so-tcpclient-sessions.c
MCORE_FILES += $(DIST_FP)/fp-plugins/so-apps/http-client/fp-so-http-client.c
endif
endif
endif

ifeq ($(CONFIG_MCORE_DEBUG_PROBE),y)
MCORE_FILES += $(DIST_FP)/fastpath/fp-probe.c
endif

ifeq ($(CONFIG_MCORE_L2SWITCH),y)
MCORE_FILES += $(DIST_FP)/fastpath/fp-l2switch.c
endif

ifeq ($(CONFIG_MCORE_FPU_RPC),y)
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/fpu-rpc
MCORE_CFLAGS += -I$(DIST_FP)/fp-modules/fpu-rpc/dataplane
MCORE_FILES += $(DIST_FP)/fp-modules/fpu-rpc/dataplane/fpu-rpc.c
MCORE_FILES += $(DIST_FP)/fp-modules/fpu-rpc/dataplane/fpu-rpc-mgr.c
endif

ifeq ($(CONFIG_MCORE_ARCH_DPDK)$(CONFIG_MCORE_SW_SCHED),yy)
MCORE_FILES += $(DIST_FP)/fp-modules/egress-qos/dataplane/fpn-sw-sched.c
endif

ifeq ($(CONFIG_MCORE_BUILTIN_VSWITCH),y)
include $(DIST_FP_VSWITCH)/fp/fp-vswitch.mk
endif

# Same, but without the full path
MCORE_SRCS = $(notdir $(MCORE_FILES))

# List of all dirs where we can find sources
MCORE_SRCPATH = $(sort $(dir $(MCORE_FILES)))
