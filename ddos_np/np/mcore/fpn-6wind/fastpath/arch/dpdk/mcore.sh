#!/bin/sh

MODPATH=/lib/modules/`uname -r`

if [ -f /var/tmp/shells/mcore.env ]; then
	. /var/tmp/shells/mcore.env
fi
if [ -f /usr/local/6WINDGate/etc/scripts/mcore-nf-gen-rules.sh ]; then
	. /usr/local/6WINDGate/etc/scripts/mcore-nf-gen-rules.sh
else
	function fp_nf_rules_add_iface() { echo ""; }
fi

if [ "$STARTFP" = "no" ]; then
	echo "fast path startup aborted"
	exit 0
fi

. libcmdline.sh
FP_MASK=`cmdline fp_mask`
FP_OPTS=`cmdline fp_opts`

if [ -z "${FP_MASK}" ]; then
	echo "fp_mask= command line argument missing, running as ADS"
	exit 0
fi

# function that set reservation size of huge page according to NUMA feature
# is supported or not
function set_hugepage_reserved_size {
	if [ -e $NODEPATH/node$SCKT/hugepages/hugepages-2048kB/nr_hugepages ]; then
	    # NUMA is supported
	    echo $1 > $NODEPATH/node$SCKT/hugepages/hugepages-2048kB/nr_hugepages
	else
	    echo $1 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
	fi
}

configure_librte_pmd_mlx4 ()
{
	local sys_verbs=/sys/class/infiniband_verbs
	local dev_infiniband=/dev/infiniband
	local dir
	local wait=10

	modprobe mlx4_core log_num_mgm_entry_size=-1 &&
	modprobe mlx4_en &&
	modprobe mlx4_ib &&
	modprobe ib_uverbs &&
	mkdir -p "$dev_infiniband" ||
	return
	# A delay is sometimes necessary for uverbs devices to appear.
	while [ $wait -gt 0 ]
	do
		for dir in "${sys_verbs}/uverbs"*
		do
			# Stop here if a directory is found.
			[ -d "$dir" ] &&
			break 2
		done
		# Wait until something appears.
		printf 'Waiting for uverbs devices (%d)...\n' "$wait"
		sleep 1
		wait=$(($wait - 1))
	done
	! [ $wait -eq 0 ] ||
	return
	for dir in "${sys_verbs}/uverbs"*
	do
		local IFS=:
		local uverbs="${dir##*/}"

		[ -e "${dev_infiniband}/${uverbs}" ] &&
		continue
		read -r major minor < "${dir}/dev" &&
		mknod "${dev_infiniband}/${uverbs}" c "${major}" "${minor}" &&
		printf 'Created %s/%s.\n' "${dev_infiniband}" "${uverbs}" ||
		return
	done
}

configure_librte_pmd_oce ()
{
	local ethtool file MAJOR MINOR DEVNAME

	# Load kernel modules and create device nodes.
	modprobe -a be2net surf_hub surf_provider dpdk_surf &&
	for file in /sys/devices/virtual/dpdk_oce_surf/*/uevent
	do
		[ -e "$file" ] ||
		break
		unset MAJOR MINOR DEVNAME
		eval `sed -rn '/^(MAJOR|MINOR|DEVNAME)=/p' "$file"` &&
		mknod -m 0600 "/dev/${DEVNAME}" c "${MAJOR}" "${MINOR}"
	done
	# Pick the right ethtool command.
	command -v ethtool 2> /dev/null 1>&2 &&
	ethtool=ethtool ||
	ethtool=ethtool-2
	# Disable flow control (pause frames) by default and lower the
	# number of kernel RX queues for each interface.
	# Optional but useful for performance.
	for file in /sys/module/be2net/drivers/*/*/net/*
	do
		[ -e "$file" ] ||
		break
		file="${file##*/}"
		"${ethtool}" -L "$file" combined 1
		"${ethtool}" -A "$file" autoneg off rx off tx off
	done
}

if [ "$BLADEROLE" = fp -o "$BLADEROLE" = coloc ];then

	# FPN/FPM shared memory
	if [ -f $MODPATH/drivers/net/fpn_shmem_linux.ko ]; then
		mount -t tmpfs none /dev/shm
		insmod $MODPATH/drivers/net/fpn_shmem_linux.ko
	fi

	# prepare huge pages
	mkdir /mnt/huge
	mount -t hugetlbfs nodev /var/tmp/mnt/huge

	# Parse the kernel command line for option "-Sx=N" which
	# reserves N megabytes of huge pages in the memory of socket N
	NODEPATH=/sys/devices/system/node
	CMDLINE=`cat /proc/cmdline`
	for opt in $CMDLINE; do
	    case "$opt" in
		-S*)
		    NBMB=${opt##*=}; NBHP=$(($NBMB / 2))
		    SCKT=${opt:2}; SCKT=${SCKT%%=*};
		    echo "Use $NBMB MB ($NBHP 2 MB huge pages) of socket $SCKT"
		    set_hugepage_reserved_size $NBHP
	    esac
	done
	if [ -z "${NBHP}" ]; then
	    echo "Default memory conf: 128 x 2MB huge pages of socket 0"
	    set_hugepage_reserved_size 128
	fi

	# create /dev/hpet device
	DEVID=`cat /sys/class/misc/hpet/dev`
	if [ -n "$DEVID" ]; then
		MAJOR="${DEVID%:*}"
		MINOR="${DEVID##*:}"

		if [ \( "$MAJOR" -gt 0 \) -a \( "$MINOR" -gt 0 \) ]; then
			rm -f /dev/hpet
			mknod /dev/hpet c $MAJOR $MINOR
		fi
	fi

	# Parse fp_opt options for active crypto engine
	crypto_nitrox=0
	crypto_quickassist=0
	for opt in `foreach_comma "${FP_OPTS}"`; do
		case "${opt}" in
		-d*librte_crypto_nitrox.so)
			crypto_nitrox=1
			;;
		-d*librte_crypto_quickassist.so)
			crypto_quickassist=1
			;;
		esac
	done

	# Try to load Nitrox driver if crypto_nitrox==1
	if [ "$crypto_nitrox" = "1" ]; then
		modprobe pkp_drv ssl=0
		csp1_init ssl=0
	fi

	# Try to load Quickassist driver if crypto_quickassist==1
	if [ "$crypto_quickassist" = "1" ]; then
		# enable hotplug to load quickassist firmware
		if [ -f /proc/sys/kernel/hotplug ]; then
			echo /sbin/hotplug.sh > /proc/sys/kernel/hotplug
		fi

		insmod $MODPATH/drivers/crypto/icp_qa_al.ko

		# Do uDev job
		QAT_TYPES="./ dh895xcc!"
		QAT_CLASSES="icp_adf_ctl icp_dev_csr icp_dev_ring icp_dev_mem icp_dev_processes"
		for QAT_TYPE in ${QAT_TYPES} ; do
			mkdir -p /dev/${QAT_TYPE%!*}
			for QAT_CLASS in ${QAT_CLASSES} ; do
				for QAT_DEVICE in `ls /sys/class/${QAT_TYPE}${QAT_CLASS} 2>&-` ; do
					DEVID=`cat /sys/class/${QAT_TYPE}${QAT_CLASS}/${QAT_DEVICE}/dev`
					MAJOR="${DEVID%:*}"
					MINOR="${DEVID##*:}"
					mknod /dev/${QAT_DEVICE/\!/\/} c $MAJOR $MINOR
				done
			done
		done

		# Get Fast Path core mask from command line
		for opt in `foreach_comma "${FP_MASK}"`; do
			case "${opt}" in
			-m*)
				fp_mask=${opt#-m}
				;;
			esac
		done

		# Parse fp_opt option to read mask of devices
		cac_mask=0
		coc_mask=0
		for opt in `foreach_comma "${FP_OPTS}"`; do
			case "${opt}" in
			--cavecreek=*)
				cac_mask=${opt#--cavecreek=}
				;;

			--coletocreek=*)
				coc_mask=${opt#--coletocreek=}
				;;
			esac
		done

		# Parse fp_opt to recover -T option content
		affinity_list=""
		for opt in `foreach_comma "${FP_OPTS}"`; do
			case "${opt}" in
			-Tquickassist:*)
				affinity_list=${opt#-Tquickassist:}
				;;
			esac
		done

		# Generate automatically configuration files
		if [ -f /usr/local/6WINDGate/etc/scripts/cavecreek.sh ]; then
			. /usr/local/6WINDGate/etc/scripts/cavecreek.sh ${fp_mask} ${cac_mask} ${affinity_list}
		fi
		if [ -f /usr/local/6WINDGate/etc/scripts/coletocreek.sh ]; then
			. /usr/local/6WINDGate/etc/scripts/coletocreek.sh ${fp_mask} ${coc_mask} ${affinity_list}
		fi

		# This binary will initialize the devices
		/usr/local/6bin/adf_ctl

		# firmware is loaded, re-disable hotplug.sh to speedup interface creation
		if [ -f /proc/sys/kernel/hotplug ]; then
			echo "" > /proc/sys/kernel/hotplug
		fi
	fi

	# load uio module
	if [ -f ${MODPATH}/kernel/drivers/uio/uio.ko ]; then
		insmod ${MODPATH}/kernel/drivers/uio/uio.ko
	fi

	# load igb_uio module
	if [ -f ${MODPATH}/drivers/net/igb_uio.ko ]; then
		insmod ${MODPATH}/drivers/net/igb_uio.ko
	fi

	# load librte_pmd_mlx4 modules
	if [ -f /lib*/librte_pmd_mlx4.so ]; then
		configure_librte_pmd_mlx4
	fi

	# load librte_pmd_oce modules
	if [ -f /lib*/librte_pmd_oce.so ]; then
		configure_librte_pmd_oce
	fi

	# load dpdk_mem module
	if [ -f ${MODPATH}/drivers/net/dpdk_mem.ko ]; then
		insmod ${MODPATH}/drivers/net/dpdk_mem.ko
		DEVID=`cat /sys/class/misc/dpdk_mem/dev`
		MAJOR="${DEVID%:*}"
		MINOR="${DEVID##*:}"
		mknod /dev/dpdk_mem c $MAJOR $MINOR
	fi
	# load dpdk_pci module
	if [ -f ${MODPATH}/drivers/net/dpdk_pci.ko ]; then
		insmod ${MODPATH}/drivers/net/dpdk_pci.ko
		DEVID=`cat /sys/class/misc/dpdk_pci/dev`
		MAJOR="${DEVID%:*}"
		MINOR="${DEVID##*:}"
		mknod /dev/dpdk_pci c $MAJOR $MINOR
	fi

	# Start DPVI module.
	if [ -f $MODPATH/drivers/net/dpvi-perf.ko ]; then

		# Start DPVI module. It will create a virtual fpn0 interface
		insmod $MODPATH/drivers/net/dpvi-perf.ko 

		# Create dpvi-perf node
		DEVID=`cat /sys/class/misc/dpvi-perf/dev`
		MAJOR="${DEVID%:*}"
		MINOR="${DEVID##*:}"
		mknod /dev/dpvi-perf c $MAJOR $MINOR

		# VNB communication
		ip link set fpn0 arp off
		fp_nf_rules_add_iface fpn0
		ifconfig fpn0 up
	fi

	# launch fastpath, it will daemonize when init is finished
	start-fp-rte.sh
	if [ $? -ne 0 ]; then
		echo "Skipping fastpath modules because of previous errors"
		exit 1
	fi

	# load OCF driver if it exists
	if [ -f $MODPATH/drivers/crypto/ocf.ko ]; then
		insmod $MODPATH/drivers/crypto/ocf.ko
		# Load cryptodev driver if present
		if [ -f $MODPATH/drivers/crypto/cryptodev.ko ]; then
			insmod $MODPATH/drivers/crypto/cryptodev.ko
			DEVID=`cat /sys/class/misc/crypto/dev`
			MAJOR="${DEVID%:*}"
			MINOR="${DEVID##*:}"
			mknod /dev/crypto c $MAJOR $MINOR
		fi
		# Load cryptosoft driver if present
		if [ -f $MODPATH/drivers/crypto/cryptosoft.ko ]; then
			insmod $MODPATH/drivers/crypto/cryptosoft.ko
		fi
	fi

	# it may take time to have fp_shared ready for mmap
	wait_fpshared.sh
fi
