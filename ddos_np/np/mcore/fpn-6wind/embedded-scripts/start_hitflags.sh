#!/bin/sh
#
# Copyright (c) 2014 6WIND, All rights reserved.
#

if [ -f /var/tmp/shells/mcore.env ]; then
	. /var/tmp/shells/mcore.env
fi

BIN_PATH=/usr/local/6bin
SCR_PATH=/usr/local/6WINDGate/etc/scripts/

CMD=hitflagsd

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
	HITFLAGS_OPTS=
	if [ "$DUALNPU" = "Y" ];then
		# 1cpxfp or 1cpxfp-ha: tell peer ifname and mac address
		HITFLAGS_OPTS="$HITFLAGS_OPTS -i $BLADEPEER_IFNAME -m $BLADEPEER_MAC"
	fi

	CMD_LINE="${CMD_LINE} ${BIN_PATH}/${CMD} $HITFLAGS_OPTS ${STORE}"
	${CMD_LINE}
fi
