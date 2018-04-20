#!/bin/bash
#
# SDS startup script
#
# Parameters are read form Linux kernel command line
# They are overriden by the script arguments, if any
#

if [ $# -gt 0 ]; then
	CMDLINE="$@"
else
	CMDLINE=$(cat /proc/cmdline)
	# Extract paramater from FDT if present (XLP)
	if [ -x /usr/local/6bin/fdt-tools ]; then
		CMDLINE=$(echo $CMDLINE ; fdt-tools)
	fi
fi

extract_var ()
{
	echo $CMDLINE | tr ' ' '\n' | sed -n 's/^'"$1"'=\(.*\)$/\1/p'
}

is_integer ()
{
	test "$1" -a -z $(echo "$1"|tr -d '[0-9]')
}

check_bladeid ()
{
	if ! is_integer "$1"; then
		echo "Malformed bladeid $1"
		exit
	fi

	if [ "$1" -le 0 -o "$1" -ge 16 ]; then
		echo "Invalid bladeid $1 (valid range 1..15)"
		exit
	fi
}

check_mac ()
{
	# hexadecimal byte regular expression
	local XB='[0-9a-fA-F]\{1,2\}'

	if ! echo "$1" | grep -q "^$XB:$XB:$XB:$XB:$XB:$XB$"; then
		echo "Invalid mac address $1"
		exit
	fi
}

DISTMODE=$(extract_var distmode)
BLADEID=$(extract_var bladeid)
FPIB=$(extract_var fpib)
BLADEROLE=$(extract_var bladerole)
STARTFP=$(extract_var startfp)

if [ -z $STARTFP ]; then
	STARTFP="yes"
fi

if [ -z $DISTMODE ]; then
	DISTMODE="1cp1fp"
fi

if [ -z $BLADEROLE ]; then
	BLADEROLE="coloc"
fi

if [ -z $BLADEID ]; then
	MULTIBLADE=N
	BLADEID=1
else
	MULTIBLADE=Y
	check_bladeid "$BLADEID"
	BLADEFPIB_IFNAME=$(extract_var bladefpib)
	BLADECPIB=$(extract_var bladecpib)
	BLADECPIB_IFNAME=$(echo "$BLADECPIB" | cut -d, -f1)
	BLADECPIB_IP=$(echo "$BLADECPIB" | cut -d, -f2)
fi

rm -f /var/tmp/shells/mcore.env

case "$BLADEROLE" in
	cp)
		echo "Starting SDS in distributed dual-NPU mode"
		echo "Starting blade $BLADEID Control Plane"
		BLADEPEER=$(extract_var bladepeer)
		BLADEPEER_IFNAME=$(echo "$BLADEPEER" | cut -d, -f1)
		BLADEPEER_MAC=$(echo "$BLADEPEER" | cut -d, -f2)
		BLADEMODE=$(extract_var blademode)
		if [ ! -z $BLADEPEER_MAC ] ; then
			check_mac "$BLADEPEER_MAC"
		fi
		echo "FP ifname=$BLADEPEER_IFNAME mac=$BLADEPEER_MAC"
		(echo "MULTIBLADE=$MULTIBLADE"
		 echo "DISTMODE=$DISTMODE"
		 echo "BLADEFPIB_IFNAME=$BLADEFPIB_IFNAME"
		 echo "BLADEID=$BLADEID"
		 echo "DUALNPU=Y"
		 echo "BLADEROLE=$BLADEROLE"
		 echo "BLADEMODE=$BLADEMODE"
		 echo "BLADEPEER_IFNAME=$BLADEPEER_IFNAME"
		 echo "BLADEPEER_MAC=$BLADEPEER_MAC"
		 echo "LIBHAO_LOCAL_ADDR=$BLADECPIB_IP"
		 echo "LIBHAO_IF=$BLADECPIB_IFNAME"
		 echo "STARTFP=$STARTFP") > /var/tmp/shells/mcore.env
		;;
	fp)
		echo "Starting SDS in distributed mode dual-NPU mode"
		echo "Starting blade $BLADEID Fast Path"
		BLADEPEER=$(extract_var bladepeer)
		BLADEPEER_IFNAME=$(echo "$BLADEPEER" | cut -d, -f1)
		BLADEPEER_MAC=$(echo "$BLADEPEER" | cut -d, -f2)
		BLADEMODE=$(extract_var blademode)
		CPBLADEID=$(echo "$BLADEPEER" | cut -d, -f3)
		HFBLADEID=$(extract_var hfbladeid)
		if [ ! -z $BLADEPEER_MAC ] ; then
			check_mac "$BLADEPEER_MAC"
		fi
		echo "CP ifname=$BLADEPEER_IFNAME mac=$BLADEPEER_MAC"
		(echo "MULTIBLADE=$MULTIBLADE"
		 echo "DISTMODE=$DISTMODE"
		 echo "BLADEID=$BLADEID"
		 echo "FPIB=$FPIB"
		 echo "CPBLADEID=$CPBLADEID"
		 echo "HFBLADEID=$HFBLADEID"
		 echo "DUALNPU=Y"
		 echo "BLADEROLE=$BLADEROLE"
		 echo "BLADEMODE=$BLADEMODE"
		 echo "BLADEPEER_IFNAME=$BLADEPEER_IFNAME"
		 echo "BLADEPEER_MAC=$BLADEPEER_MAC"
		 echo "STARTFP=$STARTFP") > /var/tmp/shells/mcore.env
		;;
	coloc)
		BLADEMODE=$(extract_var blademode)
		HFBLADEID=$(extract_var hfbladeid)
		echo "Starting SDS in co-localized mode"
		echo "Starting blade $BLADEID co-localized Control Plane and Fast Path"
		(echo "MULTIBLADE=$MULTIBLADE"
		 echo "BLADEFPIB_IFNAME=$BLADEFPIB_IFNAME"
		 echo "DISTMODE=$DISTMODE"
		 echo "BLADEID=$BLADEID"
		 echo "DUALNPU=N"
		 echo "BLADEROLE=$BLADEROLE"
		 echo "BLADEMODE=$BLADEMODE"
		 echo "HFBLADEID=$HFBLADEID"
		 echo "BLADEPEER_IFNAME=fpn0"
		 echo "BLADEPEER_MAC=00:00:00:00:00:00"
		 echo "LIBHAO_LOCAL_ADDR=$BLADECPIB_IP"
		 echo "LIBHAO_IF=$BLADECPIB_IFNAME"
		 echo "STARTFP=$STARTFP") > /var/tmp/shells/mcore.env
		;;
	*)
		echo "Invalid bladerole $BLADEROLE"
		;;
esac

