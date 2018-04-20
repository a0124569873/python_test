#!/bin/sh

if [ -f /var/tmp/shells/mcore.env ]; then
	. /var/tmp/shells/mcore.env
fi
if [ -f /usr/local/6WINDGate/etc/scripts/mcore-nf-gen-rules.sh ]; then
	. /usr/local/6WINDGate/etc/scripts/mcore-nf-gen-rules.sh
else
	function fp_nf_rules_add_iface() { echo ""; }
fi

MODPATH=/lib/modules/`uname -r`

case $BLADEROLE in
	cp|coloc)
		# Sample boot command parameters:
		#   dual-NPU mode, Control Plane:
		#     bladerole=cp bladepeer=cpeth1,00:11:22:33:44:55
		#   dual-NPU mode, Control Plane, HA:
		#     bladeid=${BLADEID} bladerole=cp bladepeer=mpuchancp${BLADEID},52:54:00:0b:12:01 \
		#     bladefpib=fpib${BLADEID} bladecpib=cpib${BLADEID},169.254.99.${BLADEID}
		#   single-NPU mode, HA:
		#     bladeid=${BLADEID} bladerole=coloc bladefpib=fpib${BLADEID} bladecpib=cpib${BLADEID},169.254.99.${BLADEID}

		if [ "$MULTIBLADE" = "Y" ]; then
			prepare_hao.sh
		fi

		# BLADEID MUST be set before loading RFPVI
		if [ "$MULTIBLADE" = "Y" -o "$BLADEROLE" = cp ]; then
			if [ -f /proc/sys/6WINDGate/blade_id ]; then
				echo $BLADEID > /proc/sys/6WINDGate/blade_id
			fi
		fi

		fp_nf_rules_add_iface $BLADEPEER_IFNAME
		ip link set $BLADEPEER_IFNAME up
		if [ -f $MODPATH/drivers/net/rfpvi.ko ]; then
			insmod $MODPATH/drivers/net/rfpvi.ko phys_ifname=$BLADEPEER_IFNAME phys_mac=$BLADEPEER_MAC blade_id=$BLADEID
		fi

		# Distributed mode
		# address to talk to the control plane
		if [ "$BLADEROLE" = cp ]; then
			ip addr add 169.254.66.1/24 dev $BLADEPEER_IFNAME
		fi

		# configure IPsec SA/SP default fp output blade
		if [ -f /proc/sys/blade-ipsec/default_fp ]; then
			echo $BLADEID > /proc/sys/blade-ipsec/default_fp
		fi
		insmod $MODPATH/net/netfilter/nf-fptun.ko
		iptables -t fptun -I POSTROUTING 1 -m policy --dir out --pol ipsec -j IPSECOUT
		ip6tables -t fptun -I POSTROUTING 1 -m policy --dir out --pol ipsec -j IPSECOUT
		if [ "$BLADEROLE" = coloc ]; then
			fpcmd set-ipsec-output-blade $BLADEID
			fpcmd set-ipsec6-output-blade $BLADEID
		fi

		if [ "$BLADEROLE" = cp ]; then
			HAO_IFD_TEMPLATE_NAME=hao-ifd.cp.template
			SDS_IFD_TEMPLATE_NAME=sds-ifd.cp.template
		else
			HAO_IFD_TEMPLATE_NAME=hao-ifd.coloc.template
			SDS_IFD_TEMPLATE_NAME=sds-ifd.coloc.template
		fi

		if [ "$MULTIBLADE" = "Y" -o "$BLADEROLE" = cp ]; then
			HAO_IFD_CONF=/var/tmp/shells/hao-ifd.conf
			SDS_IFD_CONF=/var/tmp/shells/sds-ifd.conf

			if [ -f /usr/admin/etc/$HAO_IFD_TEMPLATE_NAME ]; then
				HAO_IFD_TEMPLATE_FILE=/usr/admin/etc/$HAO_IFD_TEMPLATE_NAME
			else
				HAO_IFD_TEMPLATE_FILE=/usr/local/6WINDGate/etc/scripts/$HAO_IFD_TEMPLATE_NAME
			fi
			cp $HAO_IFD_TEMPLATE_FILE $HAO_IFD_CONF

			if [ -f /usr/admin/etc/$SDS_IFD_TEMPLATE_NAME ]; then
				SDS_IFD_TEMPLATE_FILE=/usr/admin/etc/$SDS_IFD_TEMPLATE_NAME
			else
				SDS_IFD_TEMPLATE_FILE=/usr/local/6WINDGate/etc/scripts/$SDS_IFD_TEMPLATE_NAME
			fi
			cp $SDS_IFD_TEMPLATE_FILE $SDS_IFD_CONF

			sed -i s,'$BLADEID',"$BLADEID", $HAO_IFD_CONF
			sed -i s,'$BLADEID',"$BLADEID", $SDS_IFD_CONF

			if [ ! -z "${BLADEFPIB_IFNAME}" ]; then
				cat << --END >> $HAO_IFD_CONF

interface ${BLADEFPIB_IFNAME}
	fpib
--END
				# needed for colocalized, no sds-ifd
				# to put fpib up
				ip link set ${BLADEFPIB_IFNAME} up
			fi
		fi

		if [ "$DONTSTART_DAEMONS" != "Y" ]; then

			if [ "$MULTIBLADE" = "Y" ]; then
				launch_hao_daemons.sh
			fi

			# launch fpm only in co-localized mode
			if [ "$BLADEROLE" = coloc ]; then
				start_fpm.sh -Z /tmp/.health
				start_fps.sh -Z /tmp/.health
				start_hitflags.sh -Z /tmp/.health

				if [ -x /usr/local/6bin/fpu-rpc-mgrd ]; then
					/usr/local/6bin/fpu-rpc-mgrd &
				fi
			else
				start_sds_daemon.sh "sds-ifd"
			fi

			if [ "$BLADEROLE" = coloc -a -f $MODPATH/drivers/net/fpm-nfct.ko ]; then
				# disable netlink conntrack listening if colocalized
				# and fpm-nfct.ko is present
				start_cm.sh -K -Z /tmp/.health
				insmod $MODPATH/drivers/net/fpm-nfct.ko
			else
				start_cm.sh -Z /tmp/.health
			fi

			if [ -x /usr/local/6bin/6whasctld ]; then
				/usr/local/6bin/6whasctld
			fi
		fi
	;;
	fp)
		# Sample boot command parameters:
		#   dual-NPU mode, fast path:
		#     bladerole=fp bladepeer=ether1_1,00:11:22:33:44:66
		#   dual-NPU mode, fast path, HA:
		#     bladeid=${BLADEID} bladerole=fp bladepeer=mpuchanfp${BLADEID},52:54:00:0a:12:01

		# BLADEID MUST be set before loading RFPVI
		if [ -f /proc/sys/6WINDGate/blade_id ]; then
			echo $BLADEID > /proc/sys/6WINDGate/blade_id
		fi

		fp_nf_rules_add_iface $BLADEPEER_IFNAME
		ip link set $BLADEPEER_IFNAME up

		# address to talk to the control plane
		ip addr add 169.254.66.2/24 dev $BLADEPEER_IFNAME

		IFD_TEMPLATE_NAME=sds-ifd.fp.template
		IFD_CONF=/var/tmp/shells/sds-ifd.conf

		if [ -f /usr/admin/etc/$IFD_TEMPLATE_NAME ]; then
			IFD_TEMPLATE_FILE=/usr/admin/etc/$IFD_TEMPLATE_NAME
		else
			IFD_TEMPLATE_FILE=/usr/local/6WINDGate/etc/scripts/$IFD_TEMPLATE_NAME
		fi
		cp $IFD_TEMPLATE_FILE $IFD_CONF

		sed -i s,'$BLADEID',"$BLADEID", $IFD_CONF
		if [ ! -z "${FPIB}" ]; then
			cat << --END >> $IFD_CONF

interface ${FPIB}
	fpib
--END
		fi

		fpcmd set-ipsec-output-blade $BLADEID
		fpcmd set-ipsec6-output-blade $BLADEID

		if [ "$DONTSTART_DAEMONS" != "Y" ]; then
			start_sds_daemon.sh "sds-ifd"
			start_fpm.sh -Z /tmp/.health
			start_fps.sh -Z /tmp/.health
			start_hitflags.sh -Z /tmp/.health
		fi
	;;
esac
