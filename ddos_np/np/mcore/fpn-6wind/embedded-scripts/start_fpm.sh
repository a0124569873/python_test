#!/bin/sh
#
# Copyright (c) 2011 6WIND, All rights reserved.
#

if [ -f /var/tmp/shells/mcore.env ]; then
	. /var/tmp/shells/mcore.env
fi

BIN_PATH=/usr/local/6bin
SCR_PATH=/usr/local/6WINDGate/etc/scripts/

CMD=fpmd

STORE="$@"

if [ -f ${SCR_PATH}/rc_daemon.subr ]; then
	. ${SCR_PATH}/rc_daemon.subr

	CMD_LINE=`set_prefix ${CMD}`
fi

# if DUALNPU set to Y,
#   BLADEID must be defined
#   BLADEPEER_IFNAME must be defined
#   BLADEPEER_MAC must be defined
# if DISTMODE set to 1cpxfp or 1cpxfp-ha
#   FPIB must be defined

if [ -x $BIN_PATH/${CMD} ]; then
	FPM_OPTS=
	FP_MAPPING="/usr/admin/etc/fpmapping"
	if [ ! -f $FP_MAPPING ]; then
		FP_MAPPING="/var/tmp/shells/fpmapping"
	fi
	if [ -f $FP_MAPPING ]; then
		FPM_OPTS="$FPM_OPTS -f $FP_MAPPING"
	fi
	if [ "$MULTIBLADE" = "Y" -o "$BLADEROLE" = cp ]; then
		FPM_OPTS="$FPM_OPTS -B $BLADEID"
	fi
	if [ -n "$CPBLADEID" ];then
		FPM_OPTS="$FPM_OPTS -C $CPBLADEID"
	fi
	if [ "$DUALNPU" = "Y" ];then
		if [ "$DISTMODE" = "1cpxfp" -o "$DISTMODE" = "1cpxfp-ha" ]; then
			FPM_OPTS="$FPM_OPTS -P $BLADEPEER_IFNAME -M $BLADEPEER_MAC"
			FPM_OPTS="$FPM_OPTS -t 169.254.$BLADEID.128:8888"
			FPM_OPTS="$FPM_OPTS -r 169.254.$BLADEID.$CPBLADEID"
		else
			FPM_OPTS="$FPM_OPTS -P $BLADEPEER_IFNAME -M $BLADEPEER_MAC"
			FPM_OPTS="$FPM_OPTS -t 169.254.66.2:8888"
		fi
	fi

	CMD_LINE="${CMD_LINE} ${BIN_PATH}/${CMD} $FPM_OPTS ${STORE}"
	${CMD_LINE}

	# wait for fpmd to be scheduled up to its "select" loop
	sleep 2
fi
