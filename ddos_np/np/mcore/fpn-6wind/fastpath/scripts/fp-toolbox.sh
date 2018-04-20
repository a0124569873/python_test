#!/bin/sh -e
#
# Copyright 6WIND, 2014, All rights reserved.
#

# Setup display variables
TPUT=`which tput || true`
if [ -x "$TPUT" ]; then
	BLACK=$(tput op || true)
	RED=$(tput setaf 1 || true)
	GREEN=$(tput setaf 2 || true)
	YELLOW=$(tput setaf 3 || true)
	BLUE=$(tput setaf 6 || true)
	BOLD=$(tput bold || true)
	NORMAL=$(tput sgr0 || true)
fi

# kill_proc proc_name
#
# Kill a running program, given its name "proc_name".
kill_proc() {
	PRESENT=$(pidof $@) || true
	if [ -z "${PRESENT}" ] ; then
		echo Process $@ not found
	else
		echo Try to gently kill process $@
		for pid in ${PRESENT} ; do
			kill $pid
		done
		sleep 1
		PRESENT=$(pidof $@) || true
		for pid in ${PRESENT} ; do
			echo Forcefully kill process $@ with pid $pid
			kill -9 $pid
		done
	fi
}


# add_option_if_exist ARRAY_NAME ENVVAR_NAME [PREFIX]
#
# evaluates to ARRAY_NAME="OLD_ARRAY_VALUE PREFIX ENVVAR_VALUE" if ENVVAR_VALUE is set
add_option_if_exist () {
	eval "envval=\$$2"
	if [ -n "$envval" ]; then
		eval "$1=\"\$$1 ${3}${envval}\""
	fi
}


# add_empty_option_if_exist ARRAY_NAME ENVVAR_NAME PREFIX
#
# evaluates to ARRAY_NAME="OLD_ARRAY_VALUE PREFIX" if ENVVAR_VALUE is set
add_empty_option_if_exist () {
	eval "envval=\$$2"
	if [ -n "$envval" ]; then
		eval "$1=\"\$$1 ${3}\""
	fi
}


# check_mod module
#
# Check module presence
check_mod() {
	while [ -n "$1" ] ; do
		PRESENT=$(lsmod | grep -w ^$1) || true
		if [ -n "${PRESENT}" ] ; then
			echo "[${GREEN} ok ${BLACK}] Module $1 present"
		else
			echo "[${RED}${BOLD}fail${NORMAL}${BLACK}] Module $1 not present"
		fi
		shift
	done
}


# check_proc proc
#
# Check process presence
check_proc() {
	while [ -n "$1" ] ; do
		PRESENT=$(pidof $1) || true
		if [ -n "${PRESENT}" ] ; then
			echo "[${GREEN} ok ${BLACK}] Process $1 running"
		else
			echo "[${RED}${BOLD}fail${NORMAL}${BLACK}] Process $1 not running"
		fi
		shift
	done
}


# disp_ctl variable
#
# display sysctl variable value
disp_ctl() {
	while [ -n "$1" ] ; do
		VALUE=$(sysctl -b $1) || true
		echo "[${BLUE}info${BLACK}] $1=$VALUE"
		shift
	done
}


#################### Init framework ####################
## Define your own start, stop, status and restart    ##
## functions.                                         ##
## They will be called given the script's arguments.  ##
########################################################

# error codes are based on Linux Standard Base Core specifications
# http://refspecs.linux-foundation.org/LSB_3.2.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html

OK=0
ERR_UNSPEC=1     # generic or unspecified error (current practice)
ERR_INVAL=2	 # invalid or excess argument(s)
ERR_NOSYS=3	 # unimplemented feature (for example, "reload")
ERR_ACCES=4	 # user had insufficient privilege
ERR_INSTALL=5	 # program is not installed
ERR_CONF=6	 # program is not configured
ERR_RUN=7	 # program is not running

usage () {
	echo "Usage: $0 {start|stop|restart|status|config [complete]}"
}

# CONF_ROOTDIR defines the default location for all config files
# It is only set to /usr/local/etc if not already set
: ${CONF_ROOTDIR:=/usr/local/etc}

# $1: script location as first argument
#     the script must match <script_name>.sh and its conf file <script_name>.env
# $2: script label i.e. "Fast Path"
script_init () {
	local script_name conf_name cf_envvar CONF_FILE
	script_name=$(basename $1)
	conf_name=${script_name%.sh}.env
	# turn '-' into '_' in cf_envvar, otherwise it won't be a valid variable name.
	cf_envvar=CONF_FILE_$(echo ${script_name%.sh} | tr '-' '_')

	# check if the CONF_FILE_script_name configuration file is specified
	CONF_FILE=$(eval echo \$\{$cf_envvar\})
	if [ -z ${CONF_FILE} ]; then
		# set CONF_FILE as the default
		CONF_FILE=${CONF_ROOTDIR}/${conf_name}
	fi

	if [ -f $CONF_FILE ]; then
		. $CONF_FILE
	else
		echo "Warning: $CONF_FILE configuration file not found for $script_name."
	fi

	RETVAL=0
	LAYER_STR=$2
}

# requires a previous script_init
# $?: pass all the arguments to the script
script_parse_args () {
	local command=$1
	shift

	case "$command" in
	start)
		echo "Starting ${LAYER_STR}..."
		start $*
		echo "${LAYER_STR} successfully started"
		;;
	stop)
		echo "Stopping ${LAYER_STR}..."
		stop $*
		echo "${LAYER_STR} successfully stopped"
		;;
	restart)
		echo "Restarting ${LAYER_STR}..."
		restart $*
		echo "${LAYER_STR} successfully restarted"
		;;
	status)
		echo "${LAYER_STR} status..."
		status $*
		;;
	config)
		echo "Configuring ${LAYER_STR}..."
		config $*
		;;
	*)
		usage
		RETVAL=$ERR_INVAL
		;;

	esac

	exit $RETVAL
}
