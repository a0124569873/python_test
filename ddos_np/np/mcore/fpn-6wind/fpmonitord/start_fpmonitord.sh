#!/bin/sh
#
# Copyright (c) 2011 6WIND, All rights reserved.
#

BIN_PATH=/usr/local/6bin
SCR_PATH=/usr/local/6WINDGate/etc/scripts/

CMD=fpmonitord

if [ -f ${SCR_PATH}/rc_daemon.subr ]; then
	. ${SCR_PATH}/rc_daemon.subr

	CMD_LINE=`set_prefix ${CMD}`
fi

if [ -x ${BIN_PATH}/${CMD} ]; then

	CMD_LINE="${CMD_LINE} ${BIN_PATH}/${CMD} $@"
	${CMD_LINE}

	# wait for fpmonitord to be scheduled up to its "select" loop
	sleep 2
fi
