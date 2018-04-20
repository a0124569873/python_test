#!/bin/sh -e
#
# Copyright 6WIND, 2014, All rights reserved.

# any failure on this script is considered fatal

FASTPATH_DIR=${FASTPATH_DIR:-/var/run/fast-path}

# Save in /var/run/fast-path/fp-sync the shell command
# to restore current sysctl value, and set it to the new
# requested value
# $1 : sysctl name
# $2 : new value
sysctl_set () {
	local value=$(sysctl $1 | tr -d ' ' | cut -d '=' -f 2)
	if [ "$value" -ne "$2" ] ; then
		echo "sysctl -w "$(sysctl $1 | tr -d ' ') >> ${FASTPATH_DIR}/fp-sync
		sysctl -w $1=$2
	fi
}

# Set up a sysctl value on all interfaces (including default, 
# to automatically configure any interface that will come up later)
# but without using .all. sysctl since .all. does not allow
# to know which value were really changed, preventing us to be
# able to restore previous state on service stop
# $1 : family in 'ipv4 ipv6'
# $2 : variable
# $3 : value
sysctl_set_all_interfaces () {
	for intf in $(ls /proc/sys/net/$1/conf); do
		if [ "$intf" != "all" ]; then
			sysctl_set net.$1.conf.$intf.$2 $3
		fi
	done
}

start () {
	if [ -f ${FASTPATH_DIR}/fp-sync ]; then
		echo "Linux Synchronization is already running. Use stop or restart commands only."
		exit 1
	fi

	# first kcompat to provide kernel adapation layer
	modprobe $MODPROBE_PARAMS kcompat

	# VR0 must be initialized as soon as possible. Keep that line on top of the script.
	if [ -x "$(command -v vrf.sh)" ]; then vrf.sh start; fi
	# VNB registers a handler for VNB2VNB exceptions ("ng_recv_exception").
	# VNB therefore MUST be started before loading fptun module, which looks for the handler's existence.
	if [ -x "$(command -v vnb.sh)" ]; then vnb.sh start; fi

	modprobe $MODPROBE_PARAMS ifuid

	# launch nf_conntrack before fptun to access
	# nf_ct_timeout_lookup function
	modprobe nf_conntrack
	# launch nf_conntrack_netlink to have netlink notifications
	# before starting cache manager
	modprobe nf_conntrack_netlink
	modprobe $MODPROBE_PARAMS fptun
	#add fpn0, lo to fptun interface white list
	if [ -f /proc/net/fptun/add_iface_to_whitelist ]; then
		echo "fpn0" > /proc/net/fptun/add_iface_to_whitelist
		echo "lo" > /proc/net/fptun/add_iface_to_whitelist
	fi

	if modprobe $MODPROBE_PARAMS --dry-run nf-fptun 2>/dev/null; then
		# force insertion of ip[6]_tables modules
		echo "modprobing ip[6]_tables"
		modprobe ip_tables
		modprobe ip6_tables

		echo "modprobing nf-fptun"
		modprobe $MODPROBE_PARAMS nf-fptun
	fi

	if modprobe $MODPROBE_PARAMS -n blade-ipsec 2>/dev/null; then
		echo "modprobing blade-ipsec"
		modprobe $MODPROBE_PARAMS blade-ipsec
		# ipsec output delegation
		sysctl_set blade-ipsec.default_fp 1
	fi

	echo "Enabling IPv4 forwarding"
	sysctl_set_all_interfaces ipv4 forwarding 1

	echo "Enabling IPv6 forwarding"
	sysctl_set_all_interfaces ipv6 disable_ipv6 0
	# net.ipv6.conf.all.forwarding has a special behaviour, since
	# IPv6 forwarding can not be set on a per interface basis, the
	# forwarding is driven by value in conf.all.forwarding. This value
	# is propagated on all interfaces, including default.
	sysctl_set net.ipv6.conf.all.forwarding 1

	echo "Set the socket read max size to 8MB"
	sysctl_set net.core.rmem_max 8388608

	# This script MUST be called even if there is no vrf support, it initializes
	# the vrf0 aka netns 'init_net' which always exists.
	linux-fp-sync-vrf.sh

	fpm.sh start

	cmgr.sh start

	fps.sh start

	hitflags.sh start
}

stop () {
	# Disable exit on error
	set +e

	hitflags.sh stop

	fps.sh stop

	cmgr.sh stop

	fpm.sh stop

	echo "Reset parameters to their original value"
	if [ -f ${FASTPATH_DIR}/fp-sync ]; then
		. ${FASTPATH_DIR}/fp-sync
		rm -rf ${FASTPATH_DIR}/fp-sync
	fi

	# Remove fptun iptables
	if lsmod | grep -q "\<nf_fptun\>"; then
		echo "Cleaning iptables' fptun"
		iptables -F -t fptun
		ip6tables -F -t fptun
	fi

	echo "Removing sync modules"
	modprobe -r -q $MODPROBE_PARAMS blade_ipsec nf_fptun fptun
	modprobe -r -q $MODPROBE_PARAMS ifuid

	if [ -x "$(command -v vnb.sh)" ]; then vnb.sh stop; fi
	if [ -x "$(command -v vrf.sh)" ]; then vrf.sh stop; fi

	modprobe -r -q $MODPROBE_PARAMS kcompat

	# Re-enable exit on error
	set -e
}

restart () {
        stop
        start
}

status () {
	if [ "$1" = "complete" ]; then
		check_mod kcompat ifuid fptun nf_fptun blade_ipsec

		disp_ctl blade-ipsec.default_fp
		for intf in $(ls /proc/sys/net/ipv4/conf); do
			disp_ctl net.ipv4.conf.$intf.forwarding
		done
		for intf in $(ls /proc/sys/net/ipv6/conf); do
			disp_ctl net.ipv6.conf.$intf.disable_ipv6
		done
		disp_ctl net.ipv6.conf.all.forwarding net.core.rmem_max
	fi

	if [ -x "$(command -v vrf.sh)" ]; then vrf.sh status $*; fi
	if [ -x "$(command -v vnb.sh)" ]; then vnb.sh status $*; fi

	fpm.sh status $*
	cmgr.sh status $*
	fps.sh status $* 
	hitflags.sh status $*
}

# if not set, define TOOLBOX_DIR as /usr/local/lib
TOOLBOX_DIR=${TOOLBOX_DIR:-/usr/local/lib}

if [ -f "${TOOLBOX_DIR}/fp-toolbox.sh" ]; then
	. ${TOOLBOX_DIR}/fp-toolbox.sh
else
	echo "$0: can't find ${TOOLBOX_DIR}/fp-toolbox.sh. Quitting."
	exit 1
fi

# if not set, define XTABLES_LIBDIR to standard location for iptable extensions
export XTABLES_LIBDIR=${XTABLES_LIBDIR:=/usr/local/lib/xtables:/lib/xtables:/lib64/xtables}

script_init $0 "Linux Synchronization"

script_parse_args $@
