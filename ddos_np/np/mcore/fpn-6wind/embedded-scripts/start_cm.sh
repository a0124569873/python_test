#!/bin/sh
#
# Copyright (c) 2011 6WIND, All rights reserved.
#

if [ -f /var/tmp/shells/mcore.env ]; then
	. /var/tmp/shells/mcore.env
fi

FP_PATH=/usr/local/6bin
SCR_PATH=/usr/local/6WINDGate/etc/scripts/

CMD=cmgrd

if [ -f ${SCR_PATH}/rc_daemon.subr ]; then
	. ${SCR_PATH}/rc_daemon.subr

	CMD_LINE=`set_prefix ${CMD}`
fi

if [ -x $FP_PATH/${CMD} ]; then
	CM_OPTS=
	case $DISTMODE in
	"1cpxfp"|"1cpxfp-ha")
		OPTION_I=`echo $@ | grep -e '\-I'`
		if [ -z "$OPTION_I" ]; then
			echo "Option -I <instance-id> is missing, cmgrd is not started!"
			exit 1
		fi
		CM_INSTANCEID=`echo $@ | sed 's/.*-I[ ]*//' | cut -d " " -f 1`

		if [ "$BLADEROLE" = "coloc" -a "$CM_INSTANCEID" = "$BLADEID" ]; then
			CM_OPTS="$CM_OPTS -B $BLADEFPIB_IFNAME"
		else
			while read LINE ; do
				FPBLADEID=$(echo "$LINE" | cut -d" " -f1)
				FPIB=$(echo "$LINE" | cut -d" " -f2)
				CPIF=$(echo "$LINE" | cut -d" " -f4)

				if [ "$CM_INSTANCEID" != "$FPBLADEID" ]; then
					continue
				fi

				if [ "$HA" = "Y" -a "$CPIF" = "detached" ]; then
					# Do not start cmgrd
					exit 0
				fi
				CM_OPTS="$CM_OPTS -t 169.254.$FPBLADEID.128:8888 -B $FPIB"
				break
			done < /usr/admin/etc/1cpxfp.conf
		fi
		;;
	*)
		if [ -f /lib/modules/`uname -r`/net/openvswitch.ko ]; then
			CM_OPTS="$CM_OPTS -L"
		fi
		if [ "$DUALNPU" = "Y" ];then
			CM_OPTS="$CM_OPTS -t 169.254.66.2:8888"
		fi
		if [ "$MULTIBLADE" = "Y" -a "$BLADEFPIB_IFNAME" != "" ]; then
			CM_OPTS="$CM_OPTS -B $BLADEFPIB_IFNAME"
		fi
		;;
	esac

	CMD_LINE="$CMD_LINE $FP_PATH/${CMD} $CM_OPTS $@"
	# start cmgrd with a high priority
	nice -n 0 $CMD_LINE

	# wait for fpmd to be scheduled up to its "select" loop
	sleep 2
fi
