#!/bin/sh
#
# Copyright (c) 2012 6WIND, All rights reserved.
#

# this script is used to start daemons for NON-HA mode

BIN_PATH=/usr/local/6bin

# start a daemon sds-XXX
start_daemon()
{
	daemon=$1
	shift

	if [ -x $BIN_PATH/$daemon ]; then
		CMD_LINE="$BIN_PATH/$daemon $*"
	else
		echo "Cannot find daemon $daemon"
		exit 1
	fi

	${CMD_LINE}
}

# currently, we only support sds-ifd.
# if we need to support more in the future, we can add them here.
case $1 in
	"sds-ifd")
		if [ -f /usr/admin/etc/sds-ifd.conf ]; then
			IFD_CONF=/usr/admin/etc/sds-ifd.conf
		else
			IFD_CONF=/var/tmp/shells/sds-ifd.conf
		fi
		start_daemon sds-ifd -c ${IFD_CONF} -Z /tmp/.health
	;;
esac
