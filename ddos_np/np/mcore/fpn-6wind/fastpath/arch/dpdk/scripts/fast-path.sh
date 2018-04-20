#!/bin/sh -e
#
# Copyright 6WIND, 2014, All rights reserved.

# if not set, define TOOLBOX_DIR as /usr/local/lib
TOOLBOX_DIR=${TOOLBOX_DIR:-/usr/local/lib}
FASTPATH_DIR=${FASTPATH_DIR:-/var/run/fast-path}

[ -f "${TOOLBOX_DIR}/fp-toolbox.sh" ] && . ${TOOLBOX_DIR}/fp-toolbox.sh
[ $? -ne 0 ] &&	echo "$0: can't find ${TOOLBOX_DIR}/fp-toolbox.sh. Quitting." && exit 2

SELF_DIR=$(dirname $(readlink -e $0))
. $SELF_DIR/check-sys-conf.sh
. $SELF_DIR/check-fp-conf.sh

script_init $0 "Fast Path"

# if unset in conf file, then set default values
: ${HUGEPAGES_DIR:=/mnt/huge}
: ${NB_HUGEPAGES:=256}

# won't be overwritten in the config file
prog="fp-rte"
CMD=$(command -v $prog)

# Translate a netdev name into a PCI device
translate_netdev() {
	SYSFS=/sys
	: ${1:?interface name required}
	{
		# Print physical device path for interface $1.
		cd "${SYSFS}/class/net/${1}/device" &&
			pwd -P
	} | {
		# Strip path name, keep bus address.
		read -r path &&
			addr="${path##*/}"
		# Return if bus address is empty.
		[ -n "${addr}" ] ||
			return
		case "${addr}" in
		virtio*)
			# Virtio device, find out its PCI bus address.
			# Extract index number (%u from virtio%u).
			idx=${addr#virtio}
			i=0
			# For each PCI device managed by the virtio-pci module,
			# sorted by their inode number (the order they are
			# created in matches their virtio index number):
			ls -1id "${SYSFS}/bus/pci/drivers/virtio-pci/"*:*:*.* |
			sort -n |
			while read -r inode path
			do
				[ "${i}" = "${idx}" ] || {
					i=$(($i + 1))
					continue
				}
				# Found device matching index idx, extract and
				# print PCI bus address.
				addr="${path##*/}"
				[ -n "${addr}" ] &&
					printf '%s\n' "${addr}"
				return
			done
			# Did not find anything.
			;;
		*:*:*.*)
			# Standard PCI bus address, print directly.
			printf '%s\n' "${addr}"
			return
			;;
		*)
			# Unknown.
			;;
		esac
	}
} 2> /dev/null # Redirect all errors to /dev/null.

# Write pci blacklist by parsing EAL_OPTIONS
get_pci_blacklist() {
	local blist short long arg
	while [ -n "${1:-}" ] && [ "$1" != '--' ]; do
		short=$(printf %.2s $1) # first 2 chars of $1
		long=$(printf %.15s $1) # first 15 chars of $1
		arg=${1}
		shift
		if [ "${arg}" = "-b" ]; then
			arg=${1}
		elif [ "${short}" = "-b" ]; then
			arg=${arg#${short}} # remove "-b" prefix
		elif [ "${arg}" = "--pci-blacklist" ]; then
			arg=${1}
		elif [ "${long}" = "--pci-blacklist" ]; then
			arg=${arg#${long}} # remove "--pci-blacklist" prefix
		else
			continue
		fi
		arg=${arg%%,*} # remove everything after comma in argument
		case $arg in
		????:*)
			;;
		*)
			# prepend with default PCI domain if missing
			arg="0000:$arg"
			;;
		esac
		blist="$blist ${arg}"  # append arg to list
	done
	echo $blist
}

# Write pci whitelist by parsing EAL_OPTIONS
get_pci_whitelist() {
	local wlist short long arg
	while [ -n "${1:-}" ] && [ "$1" != '--' ]; do
		short=$(printf %.2s $1) # first 2 chars of $1
		long=$(printf %.15s $1) # first 15 chars of $1
		arg=${1}
		shift
		if [ "${arg}" = "-w" ]; then
			arg=${1}
		elif [ "${short}" = "-w" ]; then
			arg=${arg#${short}} # remove "-w" prefix
		elif [ "${arg}" = "--pci-whitelist" ]; then
			arg=${1}
		elif [ "${long}" = "--pci-whitelist" ]; then
			arg=${arg#${long}} # remove "--pci-whitelist" prefix
		else
			continue
		fi
		arg=${arg%%,*} # remove everything after comma in argument
		case $arg in
		????:*)
			;;
		*)
			# prepend with default PCI domain if missing
			arg="0000:$arg"
			;;
		esac
		wlist="$wlist ${arg}"  # append arg to list
	done
	echo $wlist
}

# Find pci devices handled by igb_uio, then bind them if not in blacklist
UNBOUND='unbound'
bind_igb_uio_devices() {
	local blacklist whitelist modname=igb_uio alias file pcidev module
	local driver use_igb_uio vendor device netdev
	blacklist=$(get_pci_blacklist $EAL_OPTIONS)
	whitelist=$(get_pci_whitelist $EAL_OPTIONS)

	[ "${whitelist}" != "" ] && [ "${blacklist}" != "" ] && \
		echo "cannot use both whitelist and blacklist" && \
		return 1

	for alias in $(igbuio_modalias); do
		for file in $(grep -l ${alias%%sv*}sv /sys/bus/pci/devices/*/modalias); do
			pcidev=$(cd -P ${file%%/modalias} && echo ${PWD##*/})

			# Blacklisted or not in whitelist, give back device to
			# correct module
			use_igb_uio=1
			[ "${whitelist}" = "" ] && [ "${blacklist%%$pcidev*}" != "$blacklist" ] && use_igb_uio=0
			[ "${whitelist}" != "" ] && [ "${whitelist%%$pcidev*}" = "$whitelist" ] && use_igb_uio=0
			if [ ${use_igb_uio} = 0 ]; then

				if [ -f ${FASTPATH_DIR}/bound/$pcidev/module ]; then
					module=$(cat ${FASTPATH_DIR}/bound/$pcidev/module)
					driver=$(cat ${FASTPATH_DIR}/bound/$pcidev/driver)
					echo $pcidev > /sys/bus/pci/devices/$pcidev/driver/unbind
					echo $pcidev > /sys/module/$module/drivers/pci\:$driver/bind
					rm -rf ${FASTPATH_DIR}/bound/$pcidev
				fi
			else
				if [ -d /sys/bus/pci/devices/$pcidev/driver ] && [ -d /sys/bus/pci/devices/$pcidev/driver/module ]; then
					module=$(cd -P /sys/bus/pci/devices/$pcidev/driver/module && echo ${PWD##*/})
					driver=$(cd -P /sys/bus/pci/devices/$pcidev/driver && echo ${PWD##*/})
				else
					module=$UNBOUND
					driver=$UNBOUND
				fi

				# Already bound to igb_uio, nothing to do
				[ "$module" = "$modname" ] && continue

				# Save netdev
				netdev=""
				if [ -d /sys/bus/pci/devices/$pcidev/net ]; then
					netdev=$(ls /sys/bus/pci/devices/$pcidev/net)
				fi
				vendor=$(cat /sys/bus/pci/devices/$pcidev/vendor)
				device=$(cat /sys/bus/pci/devices/$pcidev/device)

				# Unbind from previous module, and bind to igb_uio
				echo $vendor $device > /sys/module/$modname/drivers/pci\:$modname/new_id
				if [ $module != $UNBOUND ]; then
					echo $pcidev > /sys/bus/pci/devices/$pcidev/driver/unbind
					echo $pcidev > /sys/module/$modname/drivers/pci\:$modname/bind
				fi
				echo $vendor $device > /sys/module/$modname/drivers/pci\:$modname/remove_id

				# Store unbound module for rebinding
				mkdir -p ${FASTPATH_DIR}/bound/$pcidev
				echo $module > ${FASTPATH_DIR}/bound/$pcidev/module
				echo $driver > ${FASTPATH_DIR}/bound/$pcidev/driver
				[ -n "$netdev" ] && echo $netdev > ${FASTPATH_DIR}/bound/$pcidev/netdev
			fi
		done
	done
}

# Unbind previously bound devices
unbind_igb_uio_devices() {
	local pcidev module driver
	for bound in ${FASTPATH_DIR}/bound/*; do
		[ ! -d $bound ] && continue

		pcidev=${bound##*/}
		module=$(cat ${bound}/module)
		driver=$(cat ${bound}/driver)

		echo $pcidev > /sys/bus/pci/devices/$pcidev/driver/unbind
		if [ "$driver" != $UNBOUND ] || [ "$module" != $UNBOUND ]; then
			echo $pcidev > /sys/module/$module/drivers/pci\:$driver/bind
		fi
		rm -rf $bound
	done
}

# Parse environment variables for known values and put them in the right field.
parse_envvar () {
	for intf in ${IGNORE_NETDEV:-}; do
		pci_dev=$(translate_netdev $intf)
		if [ -z "$pci_dev" ]; then
			echo "WARNING: could not find netdev '"$intf"', skipping it"
		else
			echo "blacklist $pci_dev for netdev '"$intf"'"
			EAL_OPTIONS="$EAL_OPTIONS -b $pci_dev"
		fi
	done

	add_option_if_exist "EAL_OPTIONS" "HUGEPAGES_DIR" "--huge-dir="
	add_option_if_exist "EAL_OPTIONS" "NB_MEM_CHANNELS" "-n "
	add_option_if_exist "EAL_OPTIONS" "FP_MASK" "-c "
	add_option_if_exist "EAL_OPTIONS" "FP_MEMORY" "-m "

	add_option_if_exist "FPNSDK_OPTIONS" "CORE_PORT_MAPPING" "-t "
	add_option_if_exist "FPNSDK_OPTIONS" "EXC_LCOREID" "-x "
	add_option_if_exist "FPNSDK_OPTIONS" "DPVI_MASK" "-e "
	add_option_if_exist "FPNSDK_OPTIONS" "NB_MBUF" "--nb-mbuf "
}

prepare_hugepages () {
	local entry node nb_nodes nb_pages hugepages_size hugepages_list

	# Hugepages already setup, just exit
	[ -f ${FASTPATH_DIR}/umount_hugepages ] && return

	# Mount hugepages access point if not done
	HUGEPAGES_MOUNTED=$(mount -t hugetlbfs | grep ${HUGEPAGES_DIR}) || true
	if [ -z "$HUGEPAGES_MOUNTED" ]; then
		mkdir -p ${HUGEPAGES_DIR}
		mount -t hugetlbfs nodev ${HUGEPAGES_DIR}
		echo "umount ${HUGEPAGES_DIR} || true" >> ${FASTPATH_DIR}/umount_hugepages
	fi

	# Get list of hugepages per numa node
	hugepages_list=$(echo $NB_HUGEPAGES | cut -d ',' -f 1- --output-delimiter=' ')

	# If this is a comma separated list, manage per node allocation
	nb_nodes=$(echo $hugepages_list | wc -w)
	if [ $nb_nodes -gt 1 ]; then
		tmpl='echo /sys/devices/system/node/node${node}/hugepages/hugepages-2048kB/nr_hugepages'
		MODE="${nb_nodes} nodes allocation"
	else
		tmpl='echo /proc/sys/vm/nr_hugepages'
		MODE="Global allocation"
	fi

	echo "# $MODE" >> ${FASTPATH_DIR}/umount_hugepages

	node=0
	for nb_pages in $hugepages_list; do
		# Get sysentry name
		entry=$(eval $tmpl)

		# Put the nb of hugepages required by fast-path in the node pool
		CURRENT_HUGEPAGES=$(cat $entry)
		SET_HUGEPAGES=$(($CURRENT_HUGEPAGES + $nb_pages))
		echo $SET_HUGEPAGES > $entry || true

		# Check the amount of allocated pages
		NEW_HUGEPAGES=$(cat $entry)
		if [ "$NEW_HUGEPAGES" -ne "$SET_HUGEPAGES" ]; then
			hugepages_size=$(cat /proc/meminfo | awk '/Hugepagesize/ { print $2" "$3 }')
			echo "WARNING: Can not allocate $nb_pages hugepages"
			echo "         $(( $NEW_HUGEPAGES - $CURRENT_HUGEPAGES )) pages of size $hugepages_size were allocated"
			nb_pages=$(( $NEW_HUGEPAGES - $CURRENT_HUGEPAGES ))
		fi

		# Prepare unset script
		echo 'echo $(( $(cat '"$entry"') - '"$nb_pages"' )) > '"$entry" >> ${FASTPATH_DIR}/umount_hugepages

		# Parse next node
		node=$((node+1))
	done
}

# Remove hugepages set by latest fastpath start
clean_hugepages () {
	# Unmount hugepages done by the script
	if [ -f ${FASTPATH_DIR}/umount_hugepages ]; then
		. ${FASTPATH_DIR}/umount_hugepages
		rm -rf ${FASTPATH_DIR}/umount_hugepages
	fi
}

check_hugepages () {
	local entry node nb_nodes nb_pages hugepages_size hugepages_list

	# umount_hugepages should be present
	[ ! -f ${FASTPATH_DIR}/umount_hugepages ] && return

	# Get list of hugepages per numa node
	hugepages_list=$(echo $NB_HUGEPAGES | cut -d ',' -f 1- --output-delimiter=' ')

	# If this is a comma separated list, manage per node allocation
	nb_nodes=$(echo $hugepages_list | wc -w)
	if [ $nb_nodes -gt 1 ]; then
		tmpl='echo /sys/devices/system/node/node${node}/hugepages/hugepages-2048kB/nr_hugepages'
		MODE="${nb_nodes} nodes allocation"
	else
		tmpl='echo /proc/sys/vm/nr_hugepages'
		MODE="Global allocation"
	fi

	# If allocation method changed, completely redo the hugepages allocation
	if [ $(grep -c "$MODE" ${FASTPATH_DIR}/umount_hugepages) -eq 0 ]; then
		echo "Hugepages allocation method changed, completely reallocate hugepages"
		clean_hugepages
		prepare_hugepages
		return
	fi

	node=0
	for nb_pages in $hugepages_list; do
		# Get sysentry name
		entry=$(eval $tmpl)

		# Compute new number of hugepages
		CURRENT_HUGEPAGES=$(cat $entry)
		INITIAL_HUGEPAGES=$(eval $(sed -n "s~\(.*\) . ${entry}~\1~p" ${FASTPATH_DIR}/umount_hugepages))
		SET_HUGEPAGES=$(( $INITIAL_HUGEPAGES + $nb_pages ))

		# Increment now node as next operation can return immediately
		node=$((node+1))

		# Huge pages allocation did not change, return
		[ $SET_HUGEPAGES = $CURRENT_HUGEPAGES ] && continue

		# Set new hugepage pool size
		echo $SET_HUGEPAGES > $entry || true

		# Check the amount of allocated pages
		NEW_HUGEPAGES=$(cat $entry)
		if [ "$NEW_HUGEPAGES" -ne "$SET_HUGEPAGES" ]; then
			hugepages_size=$(cat /proc/meminfo | awk '/Hugepagesize/ { print $2" "$3 }')
			echo "WARNING: Can not allocate $nb_pages hugepages"
			echo "         $(( $NEW_HUGEPAGES - $INITIAL_HUGEPAGES )) pages of size $hugepages_size were allocated"
			nb_pages=$(( $NEW_HUGEPAGES - $INITIAL_HUGEPAGES ))
		fi

		# Update unmount script
		sed "s~- [0-9]* \(.. .\) ${entry}~- $nb_pages \1 ${entry}~" -i ${FASTPATH_DIR}/umount_hugepages
	done
}

# Start fastpath
start_fp () {
	local loop=0
	local fp_cmdline

	# Check program presence
	if [ ! -x $CMD ]; then
		echo "$0: can't find $prog at \"$CMD\""
		return $ERR_INSTALL
	fi

	# Do not wait DPVI entry in FPVI TAP mode
	if [ -f /proc/sys/dpvi/running_fastpath ]; then
		# Wait if dpvi cleanup is not complete
		pid=$(cat /proc/sys/dpvi/running_fastpath 2> /dev/null) || echo 1
		while [ $pid -ne 0 -a $loop -ne 10 ]; do
			sleep 1

			pid=$(cat /proc/sys/dpvi/running_fastpath 2> /dev/null) || echo 1
			loop=$(( $loop + 1 ))
		done

		if [ "$loop" -eq 10 ]; then
			return $ERR_RUN
		fi
	fi

	fp_cmdline="${CMD} ${EAL_OPTIONS} -- ${FPNSDK_OPTIONS} -- ${FP_OPTIONS}"

	# Start fastpath with computed options
	echo "$fp_cmdline"
	# WARNING: we need this || so that shell won't stop upon fp_cmdline
	# failure (see man 1p set, -e option)
	$fp_cmdline || RETVAL=1
	if [ $RETVAL -eq 1 ]; then
		echo "$0: error starting ${CMD}."
		return $RETVAL
	fi
}

# Stop fastpath
stop_fp () {
	kill_proc $CMD
}

# Start DPVI
start_dpvi () {
	# Insert DPVI module if needed
	if modprobe ${MODPROBE_PARAMS} -n dpvi-perf 2>/dev/null; then
		modprobe ${MODPROBE_PARAMS} dpvi-perf ${DPVI_OPTIONS}

		# Start fpn0
		ip link set fpn0 up
	fi

	# /tmp/fp-nf-rules will be used by user to remove possible restrictive
	# rules automatically set by default on each interfaces on some systems
	echo "iptables -I INPUT -i fpn0 -j ACCEPT" > /tmp/fp-nf-rules
	echo "iptables -I OUTPUT -o fpn0 -j ACCEPT" >> /tmp/fp-nf-rules
	echo "ip6tables -I INPUT -i fpn0 -j ACCEPT" >> /tmp/fp-nf-rules
	echo "ip6tables -I OUTPUT -o fpn0 -j ACCEPT" >> /tmp/fp-nf-rules
}

# Stop DPVI
stop_dpvi () {
	# Stop fpn0
	ip link set fpn0 down 2>/dev/null

	# Remove DPVI
	rmmod dpvi_perf
}

# Install modules
init () {
	# Create fastpath run directory
	mkdir -p ${FASTPATH_DIR}

	# will also load uio
	modprobe -n -q uio && modprobe uio
	if modprobe -n -q ${MODPROBE_PARAMS} igb_uio; then
		modprobe ${MODPROBE_PARAMS} igb_uio

		# bind devices to igb_uio
		bind_igb_uio_devices
	fi

	# If running on xlp
	modprobe -q -n nae && modprobe nae
	modprobe -q -n dpdk-dm && modprobe dpdk-dm

	# Create huge pages
	prepare_hugepages

	# Insert shared mem module
	modprobe ${MODPROBE_PARAMS} fpn_shmem_linux
}

# Remove installed modules
finalize () {
	# Delete pending shared mems and associated nodes
	local shared
	for shared in $(cat /proc/sys/fpn_shmem/list_shm | tail -n +3 | cut -d ' ' -f 1); do
		rm -f /dev/$shared
		echo $shared > /proc/sys/fpn_shmem/del_shm
	done

	# Remove shared mem module
	modprobe -r -q ${MODPROBE_PARAMS} fpn_shmem_linux

	# Clean hugepages
	clean_hugepages

	# unbind devices from igb_uio
	unbind_igb_uio_devices

	# Remove uio modules
	modprobe -r -q ${MODPROBE_PARAMS} igb_uio
	modprobe -r -q uio
}

check () {
	check_hugepages $NB_HUGEPAGES $FP_MEMORY || true
	check_lo_ipv6 || true
	check_fpmem $FP_MEMORY $NB_MBUF || true
}

start () {
	PRESENT=$(pidof $prog) || true
	if [ -n "${PRESENT}" ] ; then
		echo "$prog process is already running (pid $PRESENT). Use stop or restart commands only."
		exit $ERR_RUN
	fi

	init
	check
	start_dpvi && start_fp

	# Try to clean up if start failed
	if [ "$?" -ne 0 ]; then
		stop
		exit 1
	fi
}

stop () {
	# Disable exit on error
	set +e

	local status
	status=$(linux-fp-sync.sh status 2>&1 | grep " ok ") || true
	if [ -n "$status" ]; then
		echo "WARNING: fast path synchronization is running. It will be stopped first."
		linux-fp-sync.sh stop
	fi

	stop_fp
	stop_dpvi
	finalize

	# Re-enable exit on error
	set -e
}

restart () {
	local mode status
	if [ "$1" = "graceful" ]; then
		mode="graceful"
	else
		status=$(linux-fp-sync.sh status 2>&1 | grep " ok ") || true
		if [ -n "$status" ]; then
			echo "WARNING: fast path synchronization is running. Using graceful restart mode."
			echo "         To completely restart fast path, first manually stop linux synchro."
			mode="graceful"
		fi
	fi
	if [ "$mode" = "graceful" ]; then
		# Stop current instance of the fastpath
		stop_fp

		# Check hugepages allocation
		check_hugepages

		# Start new fastpath instance
		start_fp
	else
		stop
		start
	fi
}

status () {
	check_proc $prog
	if [ "$1" = "complete" ]; then
		check_mod fpn_shmem_linux dpvi_perf
		ip link show fpn0 | head -n 1 | sed 's/.*<\(.*\)>.*/fpn0 status : \1/' || true
	fi
}

config () {
	PRESENT=$(pidof $prog) || true
	if [ -n "${PRESENT}" ] ; then
		echo "$prog process is already running (pid $PRESENT). Use stop before configuring."
		exit $ERR_RUN
	fi

	fp_configline="fp-conf-tool $@"

	# Configure fastpath with provided arguments
	$fp_configline
}

parse_envvar

script_parse_args $@
