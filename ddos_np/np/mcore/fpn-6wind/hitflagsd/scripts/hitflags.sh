#!/bin/sh
#
# Copyright 6WIND, 2014, All rights reserved.
#

# Parse environment variables for known values and put them in the right field.
parse_envvar () {
	add_option_if_exist "HITFLAGSD_OPTIONS" "HA" "-Z "
}

start () {
	parse_envvar

	if [ ! -x "${CMD}" ]; then
		echo "$0: can't find $prog at \"$CMD\""
		return $ERR_INSTALL
	fi

	echo "${CMD} ${HITFLAGSD_OPTIONS}"
	${CMD} ${HITFLAGSD_OPTIONS} || RETVAL=$?
	if [ $RETVAL -ne 0 ]; then
		echo "$0: error starting ${CMD}."
		return $RETVAL
	fi
}

stop () {
	# Disable exit on error
	set +e

	kill_proc ${CMD}

	# Re-enable exit on error
	set -e
}

restart () {
	stop
	start
}

status () {
	check_proc $prog
}

config () {
	# nothing to do
	echo > /dev/null
}


# if not set, define TOOLBOX_DIR as /usr/local/lib
TOOLBOX_DIR=${TOOLBOX_DIR:-/usr/local/lib}

if [ -f "${TOOLBOX_DIR}/fp-toolbox.sh" ]; then
	. ${TOOLBOX_DIR}/fp-toolbox.sh
else
	echo "$0: can't find ${TOOLBOX_DIR}/fp-toolbox.sh. Quitting."
	exit 1
fi

script_init $0 "Hitflags daemon"

prog="hitflagsd"
CMD=$(command -v $prog)

script_parse_args $@
