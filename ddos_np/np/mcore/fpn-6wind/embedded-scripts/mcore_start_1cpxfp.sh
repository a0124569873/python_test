#!/bin/sh

#Note: this script is only a template that should be customized

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
		#   bladeid=${CPBLADEID} bladerole=cp distmode=1cpxfp
		#   bladeid=${CPBLADEID} bladerole=coloc distmode=1cpxfp

		if [ "$HA" = "Y" ]; then
			prepare_hao.sh
		fi

		# BLADEID MUST be set before loading RFPVI
		if [ -f /proc/sys/6WINDGate/blade_id ]; then
			echo $BLADEID > /proc/sys/6WINDGate/blade_id
		fi

		if [ -f $MODPATH/drivers/net/rfpvi.ko ]; then
			if [ $BLADEROLE = "coloc" ]; then
				insmod $MODPATH/drivers/net/rfpvi.ko phys_ifname=fpn0 phys_mac=00:00:00:00:00:00 blade_id=$BLADEID
			else
				insmod $MODPATH/drivers/net/rfpvi.ko blade_id=$BLADEID
			fi
		fi

		if [ -f /usr/admin/etc/1cpxfp.conf ]; then
			cat /usr/admin/etc/1cpxfp.conf | while read LINE ; do
				FPBLADEID=$(echo "$LINE" | cut -d" " -f1)
				FPIB=$(echo "$LINE" | cut -d" " -f2)
				FPIB_MAC=$(echo "$LINE" | cut -d" " -f3)
				CPIF=$(echo "$LINE" | cut -d" " -f4)
				CPIF_PEER_MAC=$(echo "$LINE" | cut -d" " -f5)

				if [ "$FPBLADEID" = "#" ]; then
					continue
				fi

				if [ "$BLADEROLE" = "cp" -o "$BLADEID" != "$FPBLADEID" ]; then
					if [ ! -z $CPIF ]; then
						# add CPIF to fptun interface white list
						if [ -f /proc/net/fptun/add_iface_to_whitelist ]; then
							echo $CPIF > /proc/net/fptun/add_iface_to_whitelist
						fi
						if [ "$HA" = "Y" ]; then
							if [ "$CPIF" != "detached" ]; then
								fp_nf_rules_add_iface $CPIF
								ip link set $CPIF up
								echo $FPBLADEID $CPIF $CPIF_PEER_MAC > /proc/sys/rfpvi/add_blade
							fi
						else
							fp_nf_rules_add_iface $CPIF
							ip link set $CPIF up
							echo $FPBLADEID $CPIF $CPIF_PEER_MAC > /proc/sys/rfpvi/add_blade
						fi
					fi

					if [ "$CPIF" != "detached" ]; then
						# address to talk to the fast path
						ip addr add 169.254.$FPBLADEID.$BLADEID/24 dev $CPIF
					fi

					if [ "$DONTSTART_DAEMONS" != "Y" ]; then
						start_cm.sh -Z /tmp/.health -I $FPBLADEID
					fi
				else
					echo "BLADEFPIB_IFNAME=$FPIB" >> /var/tmp/shells/mcore.env
					#add fpib interface to white list
					if [ ! -z $FPIB ]; then
						if [ -f /proc/net/fptun/add_iface_to_whitelist ]; then
							echo $FPIB > /proc/net/fptun/add_iface_to_whitelist
						fi
					fi
					ip link set $FPIB up
					start_fpm.sh -Z /tmp/.health
					start_fps.sh -Z /tmp/.health
					start_hitflags.sh -Z /tmp/.health
					start_cm.sh -Z /tmp/.health -I $BLADEID
				fi

                               if [ "$HA" = "Y" ]; then
                                       cat << --END >> /var/tmp/shells/sync-ifd-fpib.conf

interface ${FPIB}
       fpib
--END
                               fi
				# 1cpxfp does not support blade
				# creation via sds-ifd. Do it manually
				if [ "$HA" != "Y" ]; then
					echo $FPBLADEID $FPIB_MAC > /proc/sys/blade/add_fp
				fi
			done
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

		if [ $BLADEROLE == "coloc" ]; then
			HAO_IFD_TEMPLATE_NAME=hao-ifd.coloc.template
			SDS_IFD_TEMPLATE_NAME=sds-ifd.coloc.template
		else
			HAO_IFD_TEMPLATE_NAME=hao-ifd.cp.template
			SDS_IFD_TEMPLATE_NAME=sds-ifd.cp.template
		fi

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

		if [ -f /var/tmp/shells/sync-ifd-fpib.conf ]; then
			cat /var/tmp/shells/sync-ifd-fpib.conf >> $HAO_IFD_CONF
		fi

		if [ "$DONTSTART_DAEMONS" != "Y" ]; then
			if [ "$HA" = "Y" ]; then
				launch_hao_daemons.sh
			fi
			start_sds_daemon.sh "sds-ifd"
		fi

	;;
	fp)
		# Sample boot command parameters:
		#   bladeid=$FPBLADEID bladerole=fp distmode=1cpxfp bladepeer=ether${FPBLADEID}_0,00:01:02:03:04:00,$CPBLADEID fpib=ether${FPBLADEID}_1

		# BLADEID MUST be set before loading RFPVI
		if [ -f /proc/sys/6WINDGate/blade_id ]; then
			echo $BLADEID > /proc/sys/6WINDGate/blade_id
		fi

		fp_nf_rules_add_iface $BLADEPEER_IFNAME
		ip link set $BLADEPEER_IFNAME up

		# address to talk to the control plane
		ip addr add 169.254.$BLADEID.128/24 dev $BLADEPEER_IFNAME

		IFD_TEMPLATE_NAME=sds-ifd.fp.template
		IFD_CONF=/var/tmp/shells/sds-ifd.conf

		if [ -f /usr/admin/etc/$IFD_TEMPLATE_NAME ]; then
			IFD_TEMPLATE_FILE=/usr/admin/etc/$IFD_TEMPLATE_NAME
		else
			IFD_TEMPLATE_FILE=/usr/local/6WINDGate/etc/scripts/$IFD_TEMPLATE_NAME
		fi	
		cp $IFD_TEMPLATE_FILE $IFD_CONF

		sed -i s,'$BLADEID',"$BLADEID", $IFD_CONF
		sed -i s,'169.254.66.1',"169.254.$BLADEID.$CPBLADEID", $IFD_CONF
		if [ ! -z "${FPIB}" ]; then
			cat << --END >> /var/tmp/shells/sds-ifd.conf

interface ${FPIB}
	fpib
--END
		fi

		fpcmd set-ipsec-output-blade $CPBLADEID
		fpcmd set-ipsec6-output-blade $CPBLADEID

		if [ "$DONTSTART_DAEMONS" != "Y" ]; then
			start_sds_daemon.sh "sds-ifd"
			start_fpm.sh -Z /tmp/.health
			start_fps.sh -Z /tmp/.health
			start_hitflags.sh -Z /tmp/.health
		fi
	;;
	*)
		echo "Bladerole [$BLADEROLE] is unknown"
		exit 1
	;;
esac
