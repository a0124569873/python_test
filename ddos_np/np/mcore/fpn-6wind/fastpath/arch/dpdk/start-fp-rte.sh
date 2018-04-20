#!/bin/sh
#
# Copyright 6WIND, 2010, All rights reserved.
#
# This script will start userland Fast Path if present on the filesystem and
# a fp_mask parameter with a -m option is found on the kernel command-line.
#
# fp_mask=-m(0xCOREMASK|all) fp_opts=-qNUM
#
# You are forced to specify either -m0xCOREMASK or -mall. This mask tells
# the userland Fast Path which cores it is supposed to use.

ULFP='/usr/local/6bin/fp-rte'

. /usr/local/6WINDGate/etc/env
. libcmdline.sh

FP_MASK=`cmdline fp_mask`
FP_OPTS=`cmdline fp_opts`
DPVI_MASK=`cmdline dpvi_mask`
FP_PLUGINS=`cmdline fp_plugins`

NCPU=`grep '^processor' /proc/cpuinfo | wc -l`

# check if userland fastpath binary exists
if [ ! -x "${ULFP}" ]; then
	echo "$0: cannot find ${ULFP}"
	exit 1
fi

# options given to fp-rte
fp_mask=''
#nb_mbuf=16384
nb_mbuf=262144

e_arg=''
exc_lcore=''
rxq_shared_arg=''
txq_shared_arg=''
fdir_conf=''

# Parse the kernel command line for the following memory-oriented options:
# "-Sx=N"  to reserve N megabytes of huge pages in the memory of socket N
# "-MCH=N" to set the number of memory channels to N (default value is 3)
CMDLINE=`cat /proc/cmdline`
FP_MEM=0
MEM_CH=4
for opt in $CMDLINE; do
    case "$opt" in
	-S*)
	    SCKTMB=${opt##*=};
	    FP_MEM=$(($FP_MEM + $SCKTMB))
	    if [ -z "${MEM0}" ]; then
	    	MEM0=$SCKTMB
	    else
	    	MEM1=$SCKTMB
	    fi	    
	    ;;

	-MCH=*)
	    MEM_CH=${opt##*=};
	    ;;
    esac
done
if [ -z "${SCKTMB}" ]; then
	if [[ -n `cat /proc/cmdline | grep default_hugepagesz=1G` ]]; then
    	FP_MEM=4096
	else	
    	FP_MEM=256
    fi
fi

echo "Socket 0 mem: $MEM0 MB, Socket 1 mem: $MEM1 MB."
#
# parse fp_mask= argument
# -m option is mandatory, it contains the CPU mask to be used for FP
#
for opt in "${FP_MASK}"; do
	case "${opt}" in
		-m*)
			fp_mask="${opt#-m}"
			;;
	esac
done
if [ -z "${fp_mask}" ]; then
	echo "$0: fp_mask is not specified, fastpath not started"
	exit 1
fi

if [ "${fp_mask}" = 'all' ]; then
	fp_mask = "0-$((${NCPU}-1))"
fi

#
# translate a netdev name into a PCI device
#
translate_netdev ()
{
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
		# Return nonzero status.
		! :
	}
} 2> /dev/null # Redirect all errors to /dev/null.

#
# find pci devices handled by igb_uio, then bind them if not in blacklist
#
bind_igb_uio_devices_blist() {
	local blacklist modname=igb_uio alias file pcidev
	local vendor device
	blacklist="$@"

	for alias in $(igbuio_modalias); do
		for file in $(grep -l ${alias%%sv*}sv /sys/bus/pci/devices/*/modalias); do
			pcidev=$(cd -P ${file%%/modalias} && echo ${PWD##*/})
			[ "${blacklist%%$pcidev*}" != "$blacklist" ] && continue

			vendor=$(cat /sys/bus/pci/devices/$pcidev/vendor)
			device=$(cat /sys/bus/pci/devices/$pcidev/device)

			echo $vendor $device > /sys/module/$modname/drivers/pci\:$modname/new_id
			echo $pcidev > ${file%%/modalias}/driver/unbind
			echo $pcidev > /sys/module/$modname/drivers/pci\:$modname/bind
			echo $vendor $device > /sys/module/$modname/drivers/pci\:$modname/remove_id
		done
	done
}

#
# find pci devices handled by igb_uio, then bind them if in whitelist
#
bind_igb_uio_devices_wlist() {
	local blacklist modname=igb_uio alias file pcidev
	local vendor device
	whitelist="$@"

	for alias in $(igbuio_modalias); do
		for file in $(grep -l ${alias%%sv*}sv /sys/bus/pci/devices/*/modalias); do
			pcidev=$(cd -P ${file%%/modalias} && echo ${PWD##*/})
			[ "${whitelist%%$pcidev*}" = "$whitelist" ] && continue

			vendor=$(cat /sys/bus/pci/devices/$pcidev/vendor)
			device=$(cat /sys/bus/pci/devices/$pcidev/device)

			echo $vendor $device > /sys/module/$modname/drivers/pci\:$modname/new_id
			echo $pcidev > ${file%%/modalias}/driver/unbind
			echo $pcidev > /sys/module/$modname/drivers/pci\:$modname/bind
			echo $vendor $device > /sys/module/$modname/drivers/pci\:$modname/remove_id
		done
	done
}

#
# parse fp_opts= argument
# -q (or --pmd-82576-q) option is not mandatory, it contains the
#    number of 1GB ports per lcore (default is 8)
# -Q (or --pmd-82599-q) option is not mandatory, it contains the
#    number of 10GB ports per lcore (default is 1)
# --nb-mbuf is not mandatory, it can specify the number of mbuf to
#    add in pool (default is 16384).
# --nb-sockets is not mandatory, it can specify the number of sockets
#    allocated by the tcp/udp stack
# -t provide full lcore/port mapping. Argument format is:
#    LCORE1=PORT1:PORT2/LCORE2=PORT3:PORT4/LCORE3=PORT5:PORT6
#    example: c0=0:1:2:3/c1=4:5:6:7
# -T provide full lcore/crypto_device mapping. Argument format is:
#    LCORE1=DEVICE1:FARM1:ENGINE1/LCORE2=DEVICE2:FARM2:ENGINE2/...
#    example: c0=0:0:0/c1=0:0:1
# -b blacklist a PCI device by providing its complete bus address
#    such as "0000:03:00.0". Blacklisted devices aren't managed by
#    fp-rte. Valid PCI bus addresses are listed at start.
#    For instance, starting with 5 available devices:
#
#    # fp-rte -b 0000:03:00.0 -b 0000:04:00.0 -b 0000:0b:00.0 \
#      -c 0xff -m 256 --huge-dir=/var/tmp/mnt/huge -n 3 -- \
#      -t c0=0/c1=0/c2=0/c3=0/c4=1/c5=1/c6=1/c7=1 \
#      --nb-mbuf=16384 -- --nb-sockets=10000
#
#    Bus  Device        ID         Port#  RXQ  RXD/Q  TXQ  TXD/Q  Excl  Driver name
#    PCI  0000:03:00.0  15ad:07b0  -1     0    128    8    512    1     rte_vmxnet3_pmd
#    PCI  0000:04:00.0  15ad:07b0  -1     0    128    8    512    1     rte_vmxnet3_pmd
#    PCI  0000:0b:00.0  15ad:07b0  -1     0    128    8    512    1     rte_vmxnet3_pmd
#    PCI  0000:13:00.0  15ad:07b0  0      4    128    8    512    0     rte_vmxnet3_pmd
#    PCI  0000:1b:00.0  15ad:07b0  1      4    128    8    512    0     rte_vmxnet3_pmd
#
#    The first three devices are blacklisted, fp-rte only "sees" the two last
#    ports.
#
# -w whitelist a PCI device by providing its complete bus address
#    such as "0000:03:00.0". If a whitelist is provided, only whitelisted
#    devices will be managed by fp-rte. It is not possible to use both
#    blacklist and whitelist at the same time.

solib_arg=""
eal_opt=""
for opt in `foreach_comma "${FP_OPTS}"`; do
	case "${opt}" in
		-a*)
			ad_arg="-a ${opt#-a=}"
			;;
		-p*)
			echo "WARNING: -p option is deprecated, skipping it"
			;;
		-q*)
			q1_num="${opt#-q}"
			q1_arg="-q ${q1_num}"
			;;
		-x*)
			exc_lcore="${opt#-x}"
			;;
		--pmd-82576-q*)
			q1_num="${opt#--pmd-82576-q=}"
			q1_arg="-q ${q1_num}"
			;;
		-Q*)
			q10_num="${opt#-Q}"
			q10_arg="-Q ${q10_num}"
			;;
		--pmd-82599-q*)
			q10_num="${opt#--pmd-82599-q=}"
			q10_arg="-Q ${q10_num}"
			;;
		--nb-mbuf*)
			nb_mbuf="${opt#--nb-mbuf=}"
			;;
		--nb-sockets*)
			nb_sockets="--nb-sockets=${opt#--nb-sockets=}"
			;;
		-t*)
			t_arg="-t ${opt#-t}"
			;;
		-T*)
			crypto_arg="-T ${opt#-T}"
			;;
		-l*)
			l_arg="-l ${opt#-l}"
			;;
		--nb-rxd*)
			nb_rxd_num="${opt#--nb-rxd=}"
			nb_rxd_arg="--nb-rxd="${nb_rxd_num}
			;;
		--nb-txd*)
			nb_txd_num="${opt#--nb-txd=}"
			nb_txd_arg="--nb-txd="${nb_txd_num}
			;;
		--igb-rxp*)
			igb_rxp_num="${opt#--igb-rxp=}"
			igb_rxp_arg="--igb-rxp="${igb_rxp_num}
			;;
		--igb-rxh*)
			igb_rxh_num="${opt#--igb-rxh=}"
			igb_rxh_arg="--igb-rxh="${igb_rxh_num}
			;;
		--igb-rxw*)
			igb_rxw_num="${opt#--igb-rxw=}"
			igb_rxw_arg="--igb-rxw="${igb_rxw_num}
			;;
		--igb-txp*)
			igb_txp_num="${opt#--igb-txp=}"
			igb_txp_arg="--igb-txp="${igb_txp_num}
			;;
		--igb-txh*)
			igb_txh_num="${opt#--igb-txh=}"
			igb_txh_arg="--igb-txh="${igb_txh_num}
			;;
		--igb-txw*)
			igb_txw_num="${opt#--igb-txw=}"
			igb_txw_arg="--igb-txw="${igb_txw_num}
			;;
		-d*)
			solib_arg=$solib_arg" -d ${opt#-d}"
			;;
		-b*)
			pci_id="${opt#-b}"
			case "${pci_id}" in
			????:*)
				;;
			*)
				# prepend with default PCI domain if missing
				pci_id="0000:${pci_id}"
				;;
			esac
			b_list="${b_list} ${pci_id}"
			;;
		-w*)
			pci_id="${opt#-w}"
			case "${pci_id}" in
			????:*)
				;;
			*)
				# prepend with default PCI domain if missing
				pci_id="0000:${pci_id}"
				;;
			esac
			w_list="${w_list} ${pci_id}"
			;;
		--ignore-netdev=*)
			pci_dev=$(translate_netdev ${opt#--ignore-netdev=})
			if [ -z "$pci_dev" ]; then
				echo "WARNING: could not find netdev '"${opt#--ignore-netdev=}"', skipping it"
			else
				echo "blacklist $pci_dev for netdev '"${opt#--ignore-netdev=}"'"
				b_list="${b_list} ${pci_dev}"
			fi
			;;
		--eal=*)
			eal_opt="$eal_opt ${opt#--eal=}"
			;;
		--vmware)
			eal_opt="$eal_opt --vmware-tsc-map"
			;;
		--rxq-shared*)
			rxq_shared_arg="${opt}"
			;;
		--txq-shared*)
			txq_shared_arg="${opt}"
			;;
		--fdir-conf=*)
			fdir_conf="$fdir_conf "${opt}
			;;
	esac
done

# Linux dpvi threads listening to exception packets
if [ -n "${DPVI_MASK}" ]; then
	e_arg="-e "${DPVI_MASK}
fi
# Linux lcore exception packets
if [ -n "${exc_lcore}" ]; then
	x_arg="-x "${exc_lcore}
fi

PLUGIN_ARGS=
for opt in `foreach_comma "${FP_PLUGINS}"`; do
	case "${opt}" in
		-p*)
			plugin="${opt#-p}"
			PLUGIN_ARGS="$PLUGIN_ARGS -p $plugin"
			;;
		-e*)
			env="${opt#-e}"
			# Malformed option, we want a =
			[ "$env" != "${env##*=}" ] || continue
			export $env
			;;
	esac
done

#
# automatically bind devices to igb_uio if any
#
if [ ! -z "${w_list}" -a ! -z "${b_list}" ]; then
	echo "$0: cannot use both whitelist and blacklist, fastpath not started"
	exit 1
fi
for opt in $w_list; do
	w_arg="$w_arg -w $opt"
done
for opt in $b_list; do
	b_arg="$b_arg -b $opt"
done
if [ ! -z "${w_list}" ]; then
	bind_igb_uio_devices_wlist $w_list
else
	bind_igb_uio_devices_blist $b_list
fi


fp_mask=`convert_mask ${fp_mask}`

#
# start the fastpath
#
fp_eal_opts="--create-uio-dev"
fp_eal_opts="$fp_eal_opts --no-hpet"
fp_eal_opts="$fp_eal_opts ${w_arg}"
fp_eal_opts="$fp_eal_opts ${b_arg}"
fp_eal_opts="$fp_eal_opts -c ${fp_mask}"

if [ -z "${MEM0}" ]; then
	fp_eal_opts="$fp_eal_opts -m ${FP_MEM}"
else
	fp_eal_opts="$fp_eal_opts --socket-mem $MEM0,$MEM1"
fi	  

fp_eal_opts="$fp_eal_opts --huge-dir=/var/tmp/mnt/huge"
fp_eal_opts="$fp_eal_opts -n ${MEM_CH}"
fp_eal_opts="$fp_eal_opts ${solib_arg}"
fp_eal_opts="$fp_eal_opts ${eal_opt}"
fp_eal_opts="$fp_eal_opts ${EAL_EXTRA_OPTS}"

fp_fpnsdk_opts="${crypto_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${q1_arg} "
fp_fpnsdk_opts="$fp_fpnsdk_opts ${q10_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${ad_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${t_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts --nb-mbuf=${nb_mbuf}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${l_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${e_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${x_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${nb_rxd_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${nb_txd_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${igb_rxp_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${igb_rxh_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${igb_rxw_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${igb_txp_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${igb_txh_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${igb_txw_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${rxq_shared_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${txq_shared_arg}"
fp_fpnsdk_opts="$fp_fpnsdk_opts ${fdir_conf}"

fp_fp_opts="$PLUGIN_ARGS"
fp_fp_opts="$fp_fp_opts $nb_sockets"

fp_cmdline="${ULFP}"
fp_cmdline="$fp_cmdline $fp_eal_opts --"
fp_cmdline="$fp_cmdline $fp_fpnsdk_opts --"
fp_cmdline="$fp_cmdline $fp_fp_opts"

echo "Starting userland Fast Path on cpumask ${fp_mask}."
echo "$fp_cmdline"
$fp_cmdline

if [ $? -ne 0 ]; then
	echo "$0: error starting ${ULFP}"
	exit 1
fi

echo "$0: ${ULFP} started successfully"
exit 0
