#!/bin/sh

if [ -f /var/tmp/shells/mcore.env ]; then
	. /var/tmp/shells/mcore.env
fi

if [ "$STARTFP" = "no" ]; then
	echo "fast path daemons startup aborted"
	exit 0
fi

# Increase default values of IPv6 stack to have enough
# IPv6 entries allocated by NETFPC socket.
case $BLADEROLE in
	"coloc"|"fp")
		echo 32768 > /proc/sys/net/ipv6/route/max_size
		echo 8192 > /proc/sys/net/ipv6/route/gc_thresh
		;;
esac

MODPATH=/lib/modules/`uname -r`
# fptun module need to be loaded before FPS
case $BLADEROLE in
	"coloc"|"cp")
		modprobe blade
		modprobe blade-ipsec
		modprobe ifuid

		if [ -f $MODPATH/drivers/net/fptun.ko ]; then
			if [ "x$MULTIBLADE" = "xN" -a "$BLADEROLE" = coloc ]; then
				insmod $MODPATH/drivers/net/fptun.ko
			else
				insmod $MODPATH/drivers/net/fptun.ko bladeid="$BLADEID"
			fi
		fi

		if [ "$BLADEROLE" = coloc ]; then
			#add fpn0, lo to fptun interface white list
			if [ -f /proc/net/fptun/add_iface_to_whitelist ]; then
				echo "fpn0" > /proc/net/fptun/add_iface_to_whitelist
				echo "lo" > /proc/net/fptun/add_iface_to_whitelist

				#add fpib interface to white list if BLADEFPIB_IFNAME is not empty
				if [ ! -z $BLADEFPIB_IFNAME ]; then
					echo $BLADEFPIB_IFNAME > /proc/net/fptun/add_iface_to_whitelist
				fi
			fi
		else
			if [ ! -z $BLADEPEER_IFNAME ]; then
				#add to fptun interface white list
				if [ -f /proc/net/fptun/add_iface_to_whitelist ]; then
					echo $BLADEPEER_IFNAME > /proc/net/fptun/add_iface_to_whitelist
				fi
			fi
		fi

		;;
esac

#
# In case of 1CPxFP, the coloc CP must gather statistics from other fast path.
# Its own statistics are sent by its own fast path side. So the FPS must behave
# as CP aggregator.
#
case $DISTMODE in
	"1cpxfp"|"1cpxfp-ha")
		if [ $BLADEROLE = "coloc" ]; then
			FPS_BLADEROLE="cp";
		else
			FPS_BLADEROLE=$BLADEROLE;
		fi
		;;
	*)
		FPS_BLADEROLE=$BLADEROLE;
		;;
esac

# FPS module must be loaded before RFPVI
case $FPS_BLADEROLE in
	"coloc")
		if [ -f $MODPATH/drivers/net/fps.ko ]; then
			insmod $MODPATH/drivers/net/fps.ko max_blade_id=1
		fi
		;;
	"cp")
		if [ -f $MODPATH/drivers/net/fps.ko ]; then
			insmod $MODPATH/drivers/net/fps.ko
		fi
		;;
	"fp")
		;;
esac

# FPVI
case $DISTMODE in
	"1cpxfp"|"1cpxfp-ha")
		mcore_start_${DISTMODE}.sh
		;;
	"1cp1fp")
		mcore_start_1cp1fp.sh
		;;
	*)
		echo "Invalid distmode $DISTMODE"
		;;
esac
