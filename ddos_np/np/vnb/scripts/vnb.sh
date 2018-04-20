#!/bin/sh -e
#
# Copyright 6WIND, 2014, All rights reserved.
#

VNB_MODULES="vnb_ether vnb_iface vnb_eiface vnb_ksocket vnb_socket vnb_split vnb_div \
             vnb_tee vnb_one2many vnb_mux vnb_vlan vnb_lag vnb_gre vnb_etherbridge vnb_gen \
             vnb_bridge vnb_etf vnb_mpls vnb_nffec vnb_ppp vnb_pppoe vnb_l2tp vnb_gtpu"

# Reverse list of words, to unload modules in load reverse order
reverse () {
	if [ $# -gt 0 ]; then
		local first=$1
		shift
		echo $(reverse $@) $first
	fi
}

# Parse environment variables for known values and put them in the right field.
parse_envvar () {
	add_option_if_exist "VNB_OPTIONS" "MODULES" ""
}

start () {
	parse_envvar

	# Unload any previously loaded rose protocol
	rose_active=$(lsmod | grep rose | wc -l)
	if [ "$rose_active" -ge 1 ]; then
		echo "ROSE network protocol module loaded. Unloading first"
		modprobe -r rose ax25
	fi

	modprobe $MODPROBE_PARAMS vnb-linux
	modprobe $MODPROBE_PARAMS vnb

	# check each known modules for activation
 	for module in $VNB_MODULES; do
		if modprobe $MODPROBE_PARAMS -n $module 2>/dev/null; then
			modprobe $MODPROBE_PARAMS $module
		fi
 	done
}

stop () {
	# Disable exit on error
	set +e

	vnb_socket_active=$(lsmod | grep vnb_socket | wc -l)
	if [ "$vnb_socket_active" -ge 1 ]; then
		nodes=$(ngctl list | grep -v ngctl | grep -v "total nodes" | sed 's/.*Name: \(.*\).Type:.*/\1/')

		for node in $nodes; do
			ngctl shutdown ${node}:
		done
	fi

	for module in $(reverse $VNB_MODULES); do
		if modprobe -r -q $MODPROBE_PARAMS -n $module; then
			modprobe -r -q $MODPROBE_PARAMS $module
		fi
 	done

	modprobe -r -q $MODPROBE_PARAMS vnb
	modprobe -r -q $MODPROBE_PARAMS vnb_linux

	# Re-enable exit on error
	set -e

	return $OK
}

restart () {
	stop
	start
}

status () {
	if [ "$1" = "complete" ]; then
		check_mod vnb vnb_linux
		check_mod $VNB_MODULES
	fi
}

# if not set, define TOOLBOX_DIR as /usr/local/lib
TOOLBOX_DIR=${TOOLBOX_DIR:-/usr/local/lib}

if [ -f "${TOOLBOX_DIR}/fp-toolbox.sh" ]; then
	. ${TOOLBOX_DIR}/fp-toolbox.sh
else
	echo "$0: can't find ${TOOLBOX_DIR}/fp-toolbox.sh. Quitting."
	exit 1
fi

script_init $0 "Virtual Networking Blocks"

script_parse_args $@
