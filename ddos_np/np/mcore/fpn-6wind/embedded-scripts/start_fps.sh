#!/bin/sh
#
# Copyright (c) 2013 6WIND, All rights reserved.
#

if [ -f /var/tmp/shells/mcore.env ]; then
	. /var/tmp/shells/mcore.env
fi

BIN_PATH=/usr/local/6bin
SCR_PATH=/usr/local/6WINDGate/etc/scripts/

CMD=fpsd

STORE="$@"

if [ -f ${SCR_PATH}/rc_daemon.subr ]; then
	. ${SCR_PATH}/rc_daemon.subr

	CMD_LINE=`set_prefix ${CMD}`
fi

# if DUALNPU set to Y,
#   BLADEID must be defined
#   BLADEPEER_IFNAME must be defined
#   BLADEPEER_MAC must be defined

if [ -x $BIN_PATH/${CMD} ]; then
	FPS_OPTS=
	if [ "$DUALNPU" = "Y" ];then
		# 1cpxfp or 1cpxfp-ha: tell peer ifname and mac address
		FPS_OPTS="$FPS_OPTS -i $BLADEPEER_IFNAME -m $BLADEPEER_MAC"
	fi

	CMD_LINE="${CMD_LINE} ${BIN_PATH}/${CMD} $FPS_OPTS ${STORE}"
	${CMD_LINE}
fi
