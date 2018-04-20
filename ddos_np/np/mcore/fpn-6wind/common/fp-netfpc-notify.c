/*
 * Copyright 2014 6WIND S.A.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "fp.h"
#include "netfpc.h"
#include "net/fp-ethernet.h"

#ifndef __FastPath__
/* comes from fpn-6wind/fpdebug/fpdebug.c fpn-6wind/fpm/main_fpm.c */
extern int s_nfpc;

int netfpc_notify_mtu(fp_ifnet_t *ifp, uint32_t mtu)
{
	struct netfpc_mtu_msg mtu_msg = {
		.ifuid = ifp->if_ifuid,
	};

	if (ifp->if_port == FP_IFNET_VIRTUAL_PORT)
		return EXIT_SUCCESS;

	/* notify the FP and wait for the ack */
	mtu_msg.mtu = htonl(mtu);

	if (s_nfpc >= 0) {
		if (netfpc_send(s_nfpc, &mtu_msg, sizeof(mtu_msg), 0,
				NETFPC_MSGTYPE_SET_MTU) < 0) {
			fp_log_common(LOG_ERR,
				      "add:fail to send notification if#0x%x:%s\n",
				      ntohl(ifp->if_ifuid), strerror(errno));
			return EXIT_FAILURE;
		}
		if (netfpc_recv(s_nfpc, &mtu_msg, sizeof(mtu_msg), 0, NULL) < 0) {
			fp_log_common(LOG_ERR,
				      "add:fail to receive notification if#0x%x:%s\n",
				      ntohl(ifp->if_ifuid), strerror(errno));
			return EXIT_FAILURE;
		}

		if (mtu_msg.error) {
			int err = ntohl(mtu_msg.error);
			fp_log_common(LOG_ERR,
				      "add:cannot set mtu in FP if#0x%x: [%d]\n",
				      ntohl(ifp->if_ifuid), err);
			return EXIT_FAILURE;
		}

	}
	return EXIT_SUCCESS;
}

int netfpc_notify_mac(fp_ifnet_t *ifp, const uint8_t *mac)
{
	struct netfpc_mac_msg mac_msg = {
		.ifuid = ifp->if_ifuid,
	};

	if (mac == NULL)
		return EXIT_SUCCESS;

	if (ifp->if_port == FP_IFNET_VIRTUAL_PORT)
		return EXIT_SUCCESS;

	/* notify the FP and wait for the ack */
	memcpy(mac_msg.mac, mac, FP_ETHER_ADDR_LEN);

	if (s_nfpc >= 0) {
		if (netfpc_send(s_nfpc, &mac_msg, sizeof(mac_msg), 0,
				NETFPC_MSGTYPE_SET_MAC) < 0) {
			fp_log_common(LOG_ERR,
				      "add:fail to send notification if#0x%x:%s\n",
				      ntohl(ifp->if_ifuid), strerror(errno));
			return EXIT_FAILURE;
		}
		if (netfpc_recv(s_nfpc, &mac_msg, sizeof(mac_msg), 0, NULL) < 0) {
			fp_log_common(LOG_ERR,
				      "add:fail to receive notification if#0x%x:%s\n",
				      ntohl(ifp->if_ifuid), strerror(errno));
			return EXIT_FAILURE;
		}

		if (mac_msg.error) {
			int err = ntohl(mac_msg.error);

			fp_log_common(LOG_ERR,
				      "add:cannot set mac in FP if#0x%x: [%d]\n",
				      ntohl(ifp->if_ifuid), err);
			return EXIT_FAILURE;
		}

	}
	return EXIT_SUCCESS;
}

int netfpc_notify_flags(fp_ifnet_t *ifp, const uint32_t flags)
{
	struct netfpc_flags_msg flags_msg  = {
		.ifuid = ifp->if_ifuid,
	};

	if (ifp->if_port == FP_IFNET_VIRTUAL_PORT)
		return EXIT_SUCCESS;

	/* notify the FP and wait for the ack */
	flags_msg.flags = htonl(flags);

	if (s_nfpc >= 0) {
		if (netfpc_send(s_nfpc, &flags_msg, sizeof(flags_msg), 0,
				NETFPC_MSGTYPE_SET_FLAGS) < 0) {
			fp_log_common(LOG_ERR,
				      "add:fail to send notification if#0x%x:%s\n",
				      ntohl(ifp->if_ifuid), strerror(errno));
			return EXIT_FAILURE;
		}
		if (netfpc_recv(s_nfpc, &flags_msg, sizeof(flags_msg), 0, NULL) < 0) {
			fp_log_common(LOG_ERR,
				      "add:fail to receive notification if#0x%x:%s\n",
				      ntohl(ifp->if_ifuid), strerror(errno));
			return EXIT_FAILURE;
		}

		if (flags_msg.error) {
			int err = ntohl(flags_msg.error);
			fp_log_common(LOG_ERR,
				      "add:cannot set flags in FP if#0x%x: [%d]\n",
				      ntohl(ifp->if_ifuid), err);
			return EXIT_FAILURE;
		}

	}
	return EXIT_SUCCESS;
}

int fp_interface_add(uint16_t vrfid, const char *name,
		     const uint8_t *mac, uint32_t mtu, uint32_t ifuid,
		     uint32_t vnb_nodeid, uint8_t port, uint8_t type,
		     int graceful_restart_in_progress)
{
	int ret;
	int nfpc_err = 0;
	struct netfpc_if_msg if_msg  = {
		.ifuid = ifuid,
	};

	ret = fp_addifnet(vrfid, name, mac, mtu, ifuid, port, type);
	if (ret != FP_ADDIFNET_SUCCESS) {
		if (graceful_restart_in_progress)
			if (ret == FP_ADDIFNET_EXIST)
				goto vnb;
		fp_log_common(LOG_ERR, "fp_addifnet() fail");
		return ret;
	}
	if (port != FP_IFNET_VIRTUAL_PORT) {
		fp_ifnet_t *ifp = fp_ifuid2ifnet(ifuid);

		nfpc_err = netfpc_notify_mtu(ifp, mtu);
		nfpc_err += netfpc_notify_mac(ifp, mac);
		if (ifp != NULL)
			nfpc_err += netfpc_notify_flags(ifp,
			                                ifp->if_flags & IFF_CP_MASK);
	}

vnb:
	/* notify the FP and wait for the ack */
	if_msg.vnb_nodeid = htonl(vnb_nodeid);

	if (s_nfpc >= 0) {
		if (netfpc_send(s_nfpc, &if_msg, sizeof(if_msg), 0,
				NETFPC_MSGTYPE_NEWIF) < 0) {
			fp_log_common(LOG_ERR,
				      "add:fail to send notification if#0x%08x:%s\n",
				      ntohl(ifuid), strerror(errno));
			return FP_ADDIFNET_ERROR;
		}
		if (netfpc_recv(s_nfpc, &if_msg, sizeof(if_msg), 0, NULL) < 0) {
			fp_log_common(LOG_ERR,
				      "add:fail to receive notification if#0x%08x:%s\n",
				      ntohl(ifuid), strerror(errno));
			return FP_ADDIFNET_ERROR;
		}

		if (if_msg.error) {
			int err = ntohl(if_msg.error);

			fp_log_common(LOG_ERR,
				      "add:cannot add in FP if#0x%08x:%s [%d]\n",
				      ntohl(ifuid), strerror(err), err);
			return FP_ADDIFNET_ERROR;
		}

	}

	if (nfpc_err < 0)
		return FP_ADDIFNET_ERROR;

	return ret;
}

int fp_interface_del(uint32_t ifuid, uint8_t vnb_keep_node,
		     int graceful_restart_in_progress)
{
	fp_ifnet_t *ifp;
	struct netfpc_if_msg if_msg = {
		.ifuid = ifuid,
	};

	if ((ifp = fp_ifuid2ifnet(ifuid)) == NULL)
		return -1;

	/* notify the FP and wait for the ack */
	if_msg.vnb_keep_node = vnb_keep_node;
	if (s_nfpc >= 0) {
		if (netfpc_send(s_nfpc, &if_msg, sizeof(if_msg), 0,
				NETFPC_MSGTYPE_DELIF) < 0) {
			fp_log_common(LOG_ERR,
				      "del:fail to send notification if#0x%08x:%s\n",
				      ntohl(ifuid), strerror(errno));
			return -1;
		}
		if (netfpc_recv(s_nfpc, &if_msg, sizeof(if_msg), 0, NULL) < 0) {
			fp_log_common(LOG_ERR,
				      "del:fail to receive notification if#0x%08x:%s\n",
				      ntohl(ifuid), strerror(errno));
			return -1;
		}

		/* During VNB GR, ethernet interface detach will return ENOENT error due
		 * to 2 namesapce design in FP. The interface which should be deleted
		 * will remain if return -1 here on this error. Because it is not a fatal
		 * error, bypass it in order to correctly delete the interface */
		if (if_msg.error &&
		    (graceful_restart_in_progress && ntohl(if_msg.error) != ENOENT)) {
			int err = ntohl(if_msg.error);

			fp_log_common(LOG_ERR,
				      "add:cannot del in FP if#0x%08x:%s [%d]\n",
				      ntohl(ifuid), strerror(err), err);
			return -1;
		}
	}
	return fp_delifnet(ifuid);
}

#endif /* __FastPath__ */
