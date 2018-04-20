/*
 * Copyright 2013 6WIND, All rights reserved.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

#include "fp.h"
#include "fp-if.h"
#include "fp-vswitch.h"
#include "fpvs-common.h"

#include "shmem/fpn-shmem.h"
#include "linux/openvswitch.h"

static int fpvs_detach_ifp(fp_ifnet_t *ifp, fp_vswitch_port_t *port, uint32_t type)
{
	port->ifp_index = FPVS_INVALID_IF_IDX;

	switch (type) {
	case OVS_VPORT_TYPE_NETDEV:
		fp_ifnet_ops_unregister(ifp, RX_DEV_OPS);
		break;

	case OVS_VPORT_TYPE_INTERNAL:
		fp_ifnet_ops_unregister(ifp, TX_DEV_OPS);
		break;

	default:
		break;
	}

	return 0;
}

static int fpvs_attach_ifp(fp_ifnet_t *ifp, fp_vswitch_port_t *port, uint32_t ovsport,
			   uint32_t type)
{
	unsigned long index;

	if (!ifp)
		return -1;

	index = (unsigned long)(ifp - fp_shared->ifnet.table);
	port->ifp_index = index;

	switch (type) {
	case OVS_VPORT_TYPE_NETDEV:
		if (fp_ifnet_ops_register(ifp, RX_DEV_OPS,
					  fpvs_shared->mod_uid,
					  (void *)(uintptr_t)ovsport)) {
			syslog(LOG_ERR, "%s: failed, %s rx_dev_ops is busy\n",
			       __func__, ifp->if_name);
			return -1;
		}
		break;

	case OVS_VPORT_TYPE_INTERNAL:
		if (fp_ifnet_ops_register(ifp, TX_DEV_OPS,
					  fpvs_shared->mod_uid,
					  (void *)(uintptr_t)ovsport)) {
			syslog(LOG_ERR, "%s: failed, %s tx_dev_ops is busy\n",
			       __func__, ifp->if_name);
			return -1;
		}
		break;

	default:
		break;
	}

	return 0;
}

static int fpvs_tunnel_create(uint32_t type, uint32_t ovsport,
			      uint16_t tun_dstport, fp_vswitch_port_t *port)
{
	switch (type) {
	case OVS_VPORT_TYPE_VXLAN:
#ifdef CONFIG_MCORE_VXLAN
		port->priv = (void *)(uintptr_t)fp_vxlan_fpvs_port_create(ovsport, tun_dstport);
		if (port->priv == NULL) {
			syslog(LOG_ERR, "[FPVS]: failed to register vxlan vport\n");
			return -1;
		}
		break;
#endif
	case OVS_VPORT_TYPE_GRE:
#ifdef CONFIG_MCORE_GRE
		fp_gretap_fpvs_create(ovsport);
		break;
#endif
	case OVS_VPORT_TYPE_GRE64:
	case OVS_VPORT_TYPE_LISP:
	default:
		syslog(LOG_ERR, "[FPVS]: %s: type %u tunnel is not available\n",
		       __func__,type);
		return -1;
	}

	return 0;
}

/* return the ovsport that was attached to the tunnel dstport, or 0 on error */
static uint32_t fpvs_tunnel_delete(uint32_t type, uint16_t tun_dstport)
{
	uint32_t port = 0;
	switch (type) {
	case OVS_VPORT_TYPE_VXLAN:
#ifdef CONFIG_MCORE_VXLAN
		port = fp_vxlan_fpvs_port_delete(tun_dstport);
		break;
#endif
	case OVS_VPORT_TYPE_GRE:
#ifdef CONFIG_MCORE_GRE
		fp_gretap_fpvs_delete();
		break;
#endif
	case OVS_VPORT_TYPE_GRE64:
	case OVS_VPORT_TYPE_LISP:
	default:
		syslog(LOG_ERR, "[FPVS]: %s: type %u tunnel is not available\n",
		       __func__, type);
	}

	return port;
}

static inline int fpvs_vport_is_tunnel(uint32_t type) {
	return type == OVS_VPORT_TYPE_VXLAN || type == OVS_VPORT_TYPE_LISP ||
	       type == OVS_VPORT_TYPE_GRE   || type == OVS_VPORT_TYPE_GRE64;
}

int fpvs_set_ovsport(const char* ifname, uint32_t ovsport, uint32_t type,
		     uint16_t tun_dstport, uint32_t graceful_in_progress)
{
	fp_ifnet_t *ifp = NULL;
	fp_vswitch_port_t *port;

	if (ovsport > FPVS_MAX_OVS_PORTS && ovsport != FPVS_INVALID_PORT) {
		return -1;
	}

	if (!fpvs_vport_is_tunnel(type))
		ifp = fp_getifnetbyname(ifname);

	if (ovsport == FPVS_INVALID_PORT) {
		uint64_t oldport;

		if (fpvs_vport_is_tunnel(type)) {
			oldport = fpvs_tunnel_delete(type, tun_dstport);
			if (oldport == 0)
				return -1;
		} else if (!ifp) {
			/*
			 * XXX: we could make a slow lookup by looking
			 * into the ovsport table if we find the right
			 * port.
			 */
			return -1;
		} else {
			oldport = (uintptr_t)fp_ifnet_ops_get_data(ifp, RX_DEV_OPS);
		}

		port = fpvs_get_port(oldport);
		memset(&(port->ifp_name), 0, FP_IFNAMSIZ);
		port->type = OVS_VPORT_TYPE_UNSPEC;
		port->priv = NULL;
		if (ifp)
			fpvs_detach_ifp(ifp, port, type);
		return 0;
	}

	port = fpvs_get_port(ovsport);
	if (graceful_in_progress) {
		fp_ifnet_t *old_ifp = NULL;
		/* Graceful restart: Delete the old entry before creating the
		 * new one if entries are different
		 * Be careful for some types comparison is not possible:
		 * a valid comparison must be based on the mac address for
		 * OVS_VPORT_TYPE_INTERNAL and tunnel info for OVS_VPORT_TYPE_GRE
		 * For theses types old entry is always deleted.
		 */
		if ((type != OVS_VPORT_TYPE_INTERNAL) &&
		    (type != OVS_VPORT_TYPE_GRE) &&
		    (type == port->type) &&
		    (!strcmp(ifname, port->ifp_name))) {
			if (type == OVS_VPORT_TYPE_VXLAN) {
				if (tun_dstport == (uint16_t)(uintptr_t)port->priv)
					return 0;
			} else
				return 0;
		}
		syslog(LOG_INFO, "[FPVS]: %s: graceful restart delete an old vport (type %u, name %s)\n",
		       __func__, port->type, port->ifp_name);

		if (!fpvs_vport_is_tunnel(port->type)) {
			old_ifp = fp_getifnetbyname(port->ifp_name);
			if (old_ifp)
				fpvs_detach_ifp(old_ifp, port, port->type);
		} else
			fpvs_tunnel_delete(type, tun_dstport);
	}

	port->type = type;
	memcpy(&(port->ifp_name), ifname, FP_IFNAMSIZ);

	if (fpvs_vport_is_tunnel(type)) {
	    if (fpvs_tunnel_create(type, ovsport, tun_dstport, port) == -1)
		return -1;
	} else if (fpvs_attach_ifp(ifp, port, ovsport, type) == -1) {
		return -1;
	}

	return 0;
}
