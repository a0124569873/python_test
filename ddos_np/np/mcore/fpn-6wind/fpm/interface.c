/*
 * Copyright (c) 2006 6WIND
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <syslog.h>
#include <sys/types.h>
#include <inttypes.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <ctype.h>
#include <sys/queue.h>

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fpm_vrf.h"
#include "fp.h"
#ifdef CONFIG_MCORE_VXLAN
#include "net/fp-ethernet.h" /* for FP_NMAC */
#endif

#ifdef CONFIG_MCORE_IPSEC_SVTI
#ifndef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA

static int fpm_interface_svti_add(const struct cp_iface_create *req);

#else /* !CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */

static int fpm_interface_svti_tunnel_add(const uint8_t *request,
                                         const struct cp_hdr *hdr);
static int fpm_interface_svti_tunnel_del(const uint8_t *request,
                                         const struct cp_hdr *hdr);

#endif /* !CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */
#endif /* CONFIG_MCORE_IPSEC_SVTI */

static int fpm_add_sys_loopback(uint16_t vrfid, const char* name,
                uint32_t mtu, uint32_t ifuid)
{
	fp_interface_add(vrfid, name, NULL, mtu, ifuid, 0,
			 FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_LOOP,
			 fpm_graceful_restart_in_progress);

#ifdef CONFIG_MCORE_IP
	fp_ipv4_default_rules(vrfid, ifuid, 0);
#endif
#ifdef CONFIG_MCORE_IPV6
	fp_ipv6_default_rules(vrfid, ifuid, 0);
#endif

	return 0;
}

static int fpm_interface_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_create *req =
		(const struct cp_iface_create *)request;
	int port;
	fp_ifnet_t *ifp;
	uint32_t vrfid = ntohl(req->cpiface_vrfid) & FP_VRFID_MASK;

	if (vrfid >= FP_MAX_VR) {
		if (ntohl(req->cpiface_type) == CM_IFTYPE_LOOP)
			syslog(LOG_ERR, "fail to add loopback interface in vr %u (vrfid > FP_MAX_VR (%u))",
			       ntohl(req->cpiface_vrfid) & FP_VRFID_MASK, FP_MAX_VR);
		return EXIT_FAILURE;
	}

	switch(ntohl(req->cpiface_type)) {
	case CM_IFTYPE_ETH: {
		uint8_t type = FP_IFTYPE_ETHER;

		if (ntohl(req->cpiface_maclen) != ETHER_ADDR_LEN) {
			syslog(LOG_ERR, "ERROR %s: invalid MAC address length for %s (%d)\n",
			       __func__, req->cpiface_ifname, req->cpiface_maclen);
			return EXIT_FAILURE;
		}

		if (ntohl(req->cpiface_subtype) == CM_IFSUBTYPE_NGEIFACE) {
			port = FP_IFNET_VIRTUAL_PORT;
			type = FP_IFTYPE_EIFACE;
		}
		else if (ntohl(req->cpiface_subtype) == CM_IFSUBTYPE_XVRF) {
			port = FP_IFNET_VIRTUAL_PORT;
			type = FP_IFTYPE_XVRF;
		}
		else if (ntohl(req->cpiface_subtype) == CM_IFSUBTYPE_VETH) {
			port = FP_IFNET_VIRTUAL_PORT;
			type = FP_IFTYPE_VETH;
		}
		else if (ntohl(req->cpiface_subtype) == CM_IFSUBTYPE_BRIDGE) {
			port = FP_IFNET_VIRTUAL_PORT;
			type = FP_IFTYPE_BRIDGE;
		}
		else if ((port = fpn_name2port(req->cpiface_ifname))<0)
			port = FP_IFNET_VIRTUAL_PORT;

		if (f_verbose)
			syslog(LOG_DEBUG, "adding %s ifuid=0x%08x bound to port %d\n",
			       req->cpiface_ifname, ntohl(req->cpiface_ifuid), port);

		fp_interface_add(ntohl(req->cpiface_vrfid) & FP_VRFID_MASK,
				 req->cpiface_ifname, req->cpiface_mac,
				 ntohl(req->cpiface_mtu),
				 req->cpiface_ifuid,
				 ntohl(req->cpiface_vnb_nodeid),
				 port, type,
				 fpm_graceful_restart_in_progress);
		ifp = fp_ifuid2ifnet(req->cpiface_ifuid);
		if (!ifp) {
			syslog(LOG_ERR, "ERROR %s: bad insertion for %s\n",
			       __func__, req->cpiface_ifname);
			return EXIT_FAILURE;
		}
		/* All virtual ethernet devices */
		if (type != FP_IFTYPE_ETHER) {
			ifp->if_flags |= IFF_FP_LOCAL_OUT;
#ifdef CONFIG_MCORE_VRF
			if (type == FP_IFTYPE_XVRF)
				fp_shared->fp_xvrf[vrfid] = ifp -
				              &fp_shared->ifnet.table[0];
#endif
#ifdef CONFIG_MCORE_BRIDGE
			if (type == FP_IFTYPE_BRIDGE &&
			    fp_bridge_iface_add(ifp) < 0) {
				syslog(LOG_ERR,
				       "%s: fp_bridge_iface_add() fails for %s\n",
				       __func__, req->cpiface_ifname);
				return EXIT_FAILURE;
			}
#endif
		}
		break;
	}
	case CM_IFTYPE_LOCAL:
		if (f_verbose)
			syslog(LOG_DEBUG, "adding %s ifuid=0x%08x bound to port %d\n",
			       req->cpiface_ifname, ntohl(req->cpiface_ifuid),
			       FP_IFNET_VIRTUAL_PORT);
		fp_interface_add(ntohl(req->cpiface_vrfid) & FP_VRFID_MASK,
				 req->cpiface_ifname, NULL,
				 ntohl(req->cpiface_mtu),
				 req->cpiface_ifuid,
				 ntohl(req->cpiface_vnb_nodeid),
				 FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_LOCAL,
				 fpm_graceful_restart_in_progress);

		break;
#if defined(CONFIG_MCORE_IPSEC_SVTI) && !defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
	case CM_IFTYPE_SVTI:
		if (f_verbose)
			syslog(LOG_DEBUG, "adding svti %s ifuid=0x%08x bound to port %d\n",
			       req->cpiface_ifname, ntohl(req->cpiface_ifuid),
			       FP_IFNET_VIRTUAL_PORT);
		fpm_interface_svti_add(req);

		break;
#endif /* CONFIG_MCORE_IPSEC_SVTI && !CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */
	case CM_IFTYPE_LOOP:
		if (f_verbose)
			syslog(LOG_DEBUG, "adding loopback %s ifuid=0x%08x bound to port %d\n",
			       req->cpiface_ifname, ntohl(req->cpiface_ifuid),
			       FP_IFNET_VIRTUAL_PORT);
		fpm_add_sys_loopback(ntohl(req->cpiface_vrfid) & FP_VRFID_MASK,
				     req->cpiface_ifname, ntohl(req->cpiface_mtu),
				     req->cpiface_ifuid);
		break;

	default:
		syslog(LOG_ERR, "ERROR %s: type %d (%s) not implemented\n",
		       __func__, req->cpiface_type, req->cpiface_ifname);
		return EXIT_FAILURE;
	}

	if (f_coloc_1cp1fp && fp_shared) {
		fp_setifnet_bladeinfo(req->cpiface_ifuid, fp_shared->fp_blade_id);
	}

	return EXIT_SUCCESS;
}

static void fpm_interface_del_extra(fp_ifnet_t *ifp)
{
	switch (ifp->if_type) {
	case FP_IFTYPE_ETHER:
	case FP_IFTYPE_EIFACE:
	case FP_IFTYPE_LOCAL:
	case FP_IFTYPE_VETH:
		break;
	case FP_IFTYPE_LOOP:
#ifdef CONFIG_MCORE_IP
		fp_ipv4_default_rules(ifp->if_vrfid, ifp->if_ifuid, 1);
#endif
#ifdef CONFIG_MCORE_IPV6
		fp_ipv6_default_rules(ifp->if_vrfid, ifp->if_ifuid, 1);
#endif
		break;
#ifdef CONFIG_MCORE_VRF
	case FP_IFTYPE_XVRF:
		fp_shared->fp_xvrf[ifp->if_vrfid] = 0;
		break;
#endif
#ifdef CONFIG_MCORE_BRIDGE
	case FP_IFTYPE_BRIDGE:
		fp_bridge_iface_del(ifp->if_ifuid);
		break;
#endif
#ifdef CONFIG_MCORE_IPSEC_SVTI
	case FP_IFTYPE_SVTI:
#ifdef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
		fp_delifnet_svtiinfo(ifp->if_ifuid);
#else
		fp_svti_del(ifp->if_ifuid);
#endif
		break;
#endif
#ifdef CONFIG_MCORE_VXLAN
	case FP_IFTYPE_VXLAN:
		/* Note that fdb is flushed by this function. */
		fp_delifnet_vxlaninfo(ifp->if_ifuid);
		break;
#endif
	default:
		syslog(LOG_ERR, "%s: unexpected interface type: %u\n",
		       __func__, ifp->if_type);
		break;
	}
}

static int fpm_interface_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_create *req =
		(const struct cp_iface_create *)request;
	fp_ifnet_t *ifp;

	/* hdr may be NULL when calling from fpm_interface_revert() */

	ifp = fp_ifuid2ifnet(req->cpiface_ifuid);
	if (ifp == NULL) {
		syslog(LOG_ERR, "%s: interface not found (ifuid: 0x%08x)\n",
		       __func__, ntohl(req->cpiface_ifuid));
		return EXIT_FAILURE;
	}

	if (f_verbose)
		syslog(LOG_DEBUG, "Deleting interface %s ifuid=0x%08x\n",
		       req->cpiface_ifname, ntohl(req->cpiface_ifuid));

	fpm_interface_del_extra(ifp);
	fp_interface_del(req->cpiface_ifuid,
			 req->cpiface_vnb_keep_node,
			 fpm_graceful_restart_in_progress);
	return EXIT_SUCCESS;
}

static int fpm_interface_master(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_master *req = (const struct cp_iface_master *)request;

	if (f_verbose) {
		syslog (LOG_DEBUG, "%s: slave_ifuid: 0x%"PRIx32" master_ifuid: 0x%"PRIx32"\n",
			__func__, ntohl(req->cpiface_ifuid), ntohl(req->cpiface_master_ifuid));
	}

	return fp_setifnet_master(req->cpiface_ifuid, req->cpiface_master_ifuid);
}

static int fpm_interface_mtu(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_mtu *req = (const struct cp_iface_mtu *)request;
	uint32_t ifuid = req->cpiface_ifuid;

#ifdef CONFIG_MCORE_MULTIBLADE
	if (fpm_auto_threshold && ifuid == fpm_fpib_ifuid)
		fp_set_fpib_ifuid(ifuid, fpm_auto_threshold);
#endif

	return fp_setifnet_mtu(ifuid, ntohl(req->cpiface_mtu));
}

static int fpm_interface_mac(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_mac *req = (const struct cp_iface_mac *)request;
	uint32_t ifuid = req->cpiface_ifuid;

	return fp_setifnet_mac(ifuid, req->cpiface_mac);
}

static int fpm_interface_state(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_iface_state *req =
		(const struct cp_iface_state *)request;
	uint32_t ifuid = req->cpiface_ifuid;
	uint16_t flags;

	flags = ntohl(req->cpiface_state) & IFF_CP_MASK;
	/* Setup new flags in shared mem */
	return fp_setifnet_flags(ifuid, flags);
}

static int fpm_interface_bladeinfo(const uint8_t *request,
                                   const struct cp_hdr *hdr)
{
	const struct cp_iface_bladeinfo *req =
		(const struct cp_iface_bladeinfo *)request;
	uint8_t blade_id;

	/* if interface is defined on all blades, declare it to FP as on ours */
	blade_id = req->cpiface_blade_id;
	if (blade_id == CM_BLADE_ALL)
		blade_id = fp_shared->fp_blade_id;

#ifdef CONFIG_MCORE_MULTIBLADE
#ifdef CONFIG_MCORE_1CP_XFP
	if (blade_id == CM_BLADE_CP)
		blade_id = fp_shared->cp_blade_id;
#else
	/* in 1cp1fp-ha mode, cp_blade_id = fp_blade_id */
	if (blade_id == CM_BLADE_CP)
		blade_id = fp_shared->fp_blade_id;
#endif
#else
	/* in 1cp1fp mode, default value is 1 */
	if (blade_id == CM_BLADE_CP)
		blade_id = 1;
#endif

	fp_setifnet_bladeinfo(req->cpiface_ifuid, blade_id);

	return EXIT_SUCCESS;
}

static int fpm_interface_veth_peer(const uint8_t *request,
				   const struct cp_hdr *hdr)
{
	const struct cp_iface_veth_peer *req =
		(const struct cp_iface_veth_peer *)request;

	if (f_verbose) {
		syslog(LOG_DEBUG,
		       "%s: ifuid: 0x%"PRIx32" peer_ifuid: 0x%"PRIx32"\n",
		       __func__, ntohl(req->cpveth_ifuid),
		       ntohl(req->cpveth_peer_ifuid));
	}

	return fp_setifnet_veth_peer(req->cpveth_ifuid, req->cpveth_peer_ifuid);
}

#ifdef CONFIG_MCORE_IPSEC_SVTI
#ifndef CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA
int fpm_interface_svti_add(const struct cp_iface_create *req)
{
	uint32_t ifuid = req->cpiface_ifuid;
	int rc;

	rc = fp_interface_add(ntohl(req->cpiface_vrfid) & FP_VRFID_MASK,
			      req->cpiface_ifname, NULL,
			      ntohl(req->cpiface_mtu), ifuid, 0,
			      FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_SVTI,
			      fpm_graceful_restart_in_progress);

	if (likely(rc == FP_ADDIFNET_SUCCESS)) {
		fp_svti_add(ifuid);
		return EXIT_SUCCESS;
	} else if (rc == FP_ADDIFNET_EXIST)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}
#else /* !CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */
int fpm_interface_svti_tunnel_add(const uint8_t *request,
                                         const struct cp_hdr *hdr)
{
	const struct cp_svti *req = (const struct cp_svti *)request;
	uint32_t ifuid = req->cpsvti_ifuid;
	int rc;

	if (f_verbose)
		syslog(LOG_DEBUG, "adding svti %s ifuid=0x%08x port=%d\n"
		       "\tvrfid=%"PRIu32" mtu=%"PRIu32"\n"
		       "\tlocal="FP_NIPQUAD_FMT" remote="FP_NIPQUAD_FMT" link-vrfid=%"PRIu32"\n",
		       req->cpsvti_ifname, ntohl(ifuid), FP_IFNET_VIRTUAL_PORT,
		       ntohl(req->cpsvti_vrfid), ntohl(req->cpsvti_mtu),
		       FP_NIPQUAD(req->cpsvti_local.s_addr),
		       FP_NIPQUAD(req->cpsvti_remote.s_addr),
		       ntohl(req->cpsvti_linkvrfid));

	if ((ntohl(req->cpsvti_vrfid) & FP_VRFID_MASK) >= FP_MAX_VR ||
	    (ntohl(req->cpsvti_linkvrfid) & FP_VRFID_MASK) >= FP_MAX_VR)
		return EXIT_FAILURE;

	rc = fp_interface_add(ntohl(req->cpsvti_vrfid) & FP_VRFID_MASK,
			      req->cpsvti_ifname, NULL, ntohl(req->cpsvti_mtu),
			      ifuid, 0, FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_SVTI,
			      fpm_graceful_restart_in_progress);

	if (likely(rc == FP_ADDIFNET_SUCCESS)) {
		fp_addifnet_svtiinfo(ifuid,
				     ntohl(req->cpsvti_linkvrfid) & FP_VRFID_MASK,
				     (struct fp_in_addr *)&req->cpsvti_local.s_addr,
				     (struct fp_in_addr *)&req->cpsvti_remote.s_addr);

		if (f_coloc_1cp1fp && fp_shared) {
			fp_setifnet_bladeinfo(ifuid, fp_shared->fp_blade_id);
		}

		return EXIT_SUCCESS;
	} else if (rc == FP_ADDIFNET_EXIST)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}

int fpm_interface_svti_tunnel_del(const uint8_t *request,
                                         const struct cp_hdr *hdr)
{
	const struct cp_svti *req = (const struct cp_svti *)request;
	uint32_t ifuid = req->cpsvti_ifuid;

	if (f_verbose)
		syslog(LOG_DEBUG, "removing svti %s ifuid=0x%08x bound to port %d\n",
		       req->cpsvti_ifname, ntohl(req->cpsvti_ifuid), FP_IFNET_VIRTUAL_PORT);

	fp_delifnet_svtiinfo(ifuid);
	fp_interface_del(ifuid, 0, fpm_graceful_restart_in_progress);
	return EXIT_SUCCESS;
}
#endif /* !CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */
#endif /* CONFIG_MCORE_IPSEC_SVTI */

#ifdef CONFIG_MCORE_VXLAN
int fpm_interface_vxlan_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_vxlan *req = (struct cp_vxlan *)request;
	int rc;

	if (f_verbose)
		syslog(LOG_DEBUG, "adding vxlan %s ifuid=0x%08x"
		       " vrfid=%"PRIu32" mtu=%"PRIu32" vni=%"PRIu32
		       " dstport=%"PRIu16" srcminport=%"PRIu16
		       " srcmaxport=%"PRIu16" ttl=%"PRIu8" tos=%"PRIu8"\n",
		       req->cpvxlan_ifname, ntohl(req->cpvxlan_ifuid),
		       ntohl(req->cpvxlan_vrfid), ntohl(req->cpvxlan_mtu),
		       ntohl(req->cpvxlan_vni), ntohs(req->cpvxlan_dstport),
		       ntohs(req->cpvxlan_srcminport),
		       ntohs(req->cpvxlan_srcmaxport), req->cpvxlan_ttl,
		       req->cpvxlan_tos);

	if ((ntohl(req->cpvxlan_vrfid) & FP_VRFID_MASK) >= FP_MAX_VR)
		return EXIT_FAILURE;

	if (ntohl(req->cpvxlan_maclen) != ETHER_ADDR_LEN) {
		syslog(LOG_ERR, "ERROR %s: invalid MAC address length for %s (%d)\n",
		       __func__, req->cpvxlan_ifname, req->cpvxlan_maclen);
		return EXIT_FAILURE;
	}

	rc = fp_interface_add(ntohl(req->cpvxlan_vrfid) & FP_VRFID_MASK,
			      req->cpvxlan_ifname, req->cpvxlan_mac,
			      ntohl(req->cpvxlan_mtu), req->cpvxlan_ifuid,
			      ntohl(req->cpvxlan_vnb_nodeid),
			      FP_IFNET_VIRTUAL_PORT, FP_IFTYPE_VXLAN,
			      fpm_graceful_restart_in_progress);

	if (likely(rc == FP_ADDIFNET_SUCCESS)) {
		uint8_t flags = 0;

		if (req->cpvxlan_flags & FPM_VXLAN_IFACE_F_LEARN)
			flags |= FP_VXLAN_IFACE_F_LEARN;

		if (fp_addifnet_vxlaninfo(req->cpvxlan_ifuid,
					  ntohl(req->cpvxlan_vni),
					  req->cpvxlan_linkifuid,
					  req->cpvxlan_dstport,
					  req->cpvxlan_srcminport,
					  req->cpvxlan_srcmaxport,
					  req->cpvxlan_ttl, req->cpvxlan_tos,
					  req->cpvxlan_gwfamily,
					  &req->cpvxlan_gw,
					  req->cpvxlan_saddrfamily,
					  &req->cpvxlan_saddr, flags) < 0)
			return EXIT_FAILURE;

		if (f_coloc_1cp1fp && fp_shared)
			fp_setifnet_bladeinfo(req->cpvxlan_ifuid,
					      fp_shared->fp_blade_id);

		return EXIT_SUCCESS;
	} if (rc == FP_ADDIFNET_EXIST) {
		/* changelink is not supported at kernel level */
		return EXIT_SUCCESS;
	} else
		return EXIT_FAILURE;
}

int fpm_interface_vxlan_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	const struct cp_vxlan *req = (const struct cp_vxlan *)request;

	if (f_verbose)
		syslog(LOG_DEBUG, "removing vxlan %s ifuid=0x%08x\n",
		       req->cpvxlan_ifname, ntohl(req->cpvxlan_ifuid));

	fp_delifnet_vxlaninfo(req->cpvxlan_ifuid);
	fp_interface_del(req->cpvxlan_ifuid, 0,
			 fpm_graceful_restart_in_progress);
	return EXIT_SUCCESS;
}

int fpm_vxlan_fdb_add(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_vxlan_fdb *req = (struct cp_vxlan_fdb *)request;
	uint32_t vni = ntohl(req->fdb_vni);
	uint16_t dstport;
	fp_vxlan_iface_t *vxiface;
	fp_ifnet_t *ifp;

	if (f_verbose) {
		if (req->fdb_family == AF_INET)
			syslog(LOG_DEBUG, "%s: ifuid=0x%08x vni=%" PRIu32
			       " output_ifuid=0x%08x dstport=%" PRIu16 " daddr="
			       FP_NIPQUAD_FMT " " FP_NMAC_FMT "\n", __func__,
			       ntohl(req->fdb_ifuid), vni,
			       ntohl(req->fdb_output_ifuid),
			       ntohs(req->fdb_dst_port),
			       FP_NIPQUAD(req->fdb_addr.addr4),
			       FP_NMAC(req->fdb_mac));
		else if (req->fdb_family == AF_INET6)
			syslog(LOG_DEBUG, "%s: ifuid=0x%08x vni=%" PRIu32
			       " output_ifuid=0x%08x dstport=%" PRIu16 " daddr="
			       FP_NIP6_FMT " " FP_NMAC_FMT "\n", __func__,
			       ntohl(req->fdb_ifuid), vni,
			       ntohl(req->fdb_output_ifuid),
			       ntohs(req->fdb_dst_port),
			       NIP6(req->fdb_addr.addr6),
			       FP_NMAC(req->fdb_mac));
		else
			syslog(LOG_DEBUG, "%s: unknown address family (%u)\n",
			       __func__, req->fdb_family);
	}

	ifp = fp_ifuid2ifnet(req->fdb_ifuid);
	if (ifp == NULL) {
		/* Probably an fdb entry for an interface that the fast path
		 * doesn't manage, just skip it.
		 */
		return 0;
	}
	if (ifp->sub_table_index == 0) {
		syslog(LOG_ERR,
		       "%s: sub_table_index is not defined for ifuid 0x%08x\n",
		       __func__, ntohl(req->fdb_ifuid));
		return -1;
	}
	vxiface = &fp_shared->vxlan_iface[ifp->sub_table_index];
	vni = vni ? : vxiface->vni;
	dstport = req->fdb_dst_port ? : vxiface->dstport;

	return fp_vxlan_fdb_remote_add(vxiface, req->fdb_mac, vni, dstport,
				       req->fdb_output_ifuid, req->fdb_family,
				       &req->fdb_addr);
}

int fpm_vxlan_fdb_del(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_vxlan_fdb *req = (struct cp_vxlan_fdb *)request;
	uint32_t vni = ntohl(req->fdb_vni);
	uint16_t dstport;
	fp_vxlan_iface_t *vxiface;
	fp_ifnet_t *ifp;

	if (f_verbose) {
		if (req->fdb_family == AF_INET)
		/*NETHFMT*/
			syslog(LOG_DEBUG, "%s: ifuid=0x%08x vni=%" PRIu32
			       " output_ifuid=0x%08x dstport=%" PRIu16 " daddr="
			       FP_NIPQUAD_FMT " " FP_NMAC_FMT "\n", __func__,
			       ntohl(req->fdb_ifuid), vni,
			       ntohl(req->fdb_output_ifuid),
			       ntohs(req->fdb_dst_port),
			       FP_NIPQUAD(req->fdb_addr.addr4),
			       FP_NMAC(req->fdb_mac));
		else if (req->fdb_family == AF_INET6)
			syslog(LOG_DEBUG, "%s: ifuid=0x%08x vni=%" PRIu32
			       " output_ifuid=0x%08x dstport=%" PRIu16 " daddr="
			       FP_NIP6_FMT " " FP_NMAC_FMT "\n", __func__,
			       ntohl(req->fdb_ifuid), vni,
			       ntohl(req->fdb_output_ifuid),
			       ntohs(req->fdb_dst_port),
			       NIP6(req->fdb_addr.addr6),
			       FP_NMAC(req->fdb_mac));
		else
			syslog(LOG_DEBUG, "%s: unknown address family (%u)\n",
			       __func__, req->fdb_family);
	}

	ifp = fp_ifuid2ifnet(req->fdb_ifuid);
	if (ifp == NULL) {
		/* Probably an fdb entry for an interface that the fast path
		 * doesn't manage, just skip it.
		 */
		return 0;
	}
	if (ifp->sub_table_index == 0) {
		syslog(LOG_ERR,
		       "%s: sub_table_index is not defined for ifuid 0x%08x\n",
		       __func__, ntohl(req->fdb_ifuid));
		return -1;
	}
	vxiface = &fp_shared->vxlan_iface[ifp->sub_table_index];
	vni = vni ? : vxiface->vni;
	dstport = req->fdb_dst_port ? : vxiface->dstport;

	return fp_vxlan_fdb_remote_del(vxiface, req->fdb_mac, vni, dstport,
				       req->fdb_output_ifuid, req->fdb_family,
				       &req->fdb_addr);
}
#endif /* CONFIG_MCORE_VXLAN */

static fpm_interface_del_event_t del_evt_hdlr[FP_IFTYPE_MAX + 1];

int fpm_interface_register_del_event(uint8_t type,
				     fpm_interface_del_event_t handler)
{
	if (type > FP_IFTYPE_MAX) {
		syslog(LOG_ERR, "%s: type (%d) > FP_IFTYPE_MAX (%u)\n",
		       __func__, type, FP_IFTYPE_MAX);
		return -EINVAL;
	}

	if (del_evt_hdlr[type]) {
		syslog(LOG_ERR, "%s: type (%d) is already registered\n",
		       __func__, type);
		return -EEXIST;
	}

	del_evt_hdlr[type] = handler;
	return 0;
}

static void fpm_interface_vrf_del(uint16_t vrfid)
{
	fp_ifnet_t *ifp;
	uint32_t i;

	for (i = 1; i < FP_MAX_IFNET; i++) {
		ifp = &fp_shared->ifnet.table[i];

		if (ifp->if_ifuid == 0 ||
		    ifp->if_vrfid != vrfid)
			continue;

		switch (ifp->if_type) {
		case FP_IFTYPE_ETHER:
		case FP_IFTYPE_EIFACE:
		case FP_IFTYPE_LOCAL:
		case FP_IFTYPE_VETH:
		case FP_IFTYPE_LOOP:
		case FP_IFTYPE_XVRF:
		case FP_IFTYPE_BRIDGE:
		case FP_IFTYPE_SVTI:
		case FP_IFTYPE_VXLAN:
			fpm_interface_del_extra(ifp);
			break;
		default:
			if (del_evt_hdlr[ifp->if_type])
				del_evt_hdlr[ifp->if_type](ifp->if_ifuid);
			break;
		}

		/* vnb_keep_node is set to 1 because vnb nodes are all managed
		 * in vrf0 and thus we should receive a message to delete this
		 * node!
		 */
		fp_interface_del(ifp->if_ifuid, 1,
				 fpm_graceful_restart_in_progress);
	}
}

#if defined(CONFIG_MCORE_IPSEC_SVTI) && defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
static int fpm_svti_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_svti *if1 = cmd1->data;
	struct cp_svti *if2 = cmd2->data;

	if ((if1->cpsvti_ifuid == if2->cpsvti_ifuid) &&
	    (!strcmp(if1->cpsvti_ifname, if2->cpsvti_ifname))) {
		return 0;
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_svti_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_SVTI_DELETE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_svti_display(const fpm_cmd_t *fpm_cmd,
                             char *buffer, int len)
{
	struct cp_svti *data = fpm_cmd->data;

	snprintf(buffer, len, "CMD_SVTI - %s(0x%08x)\n",
	   data->cpsvti_ifname, ntohl(data->cpsvti_ifuid));
}

static fpm_cmd_t *fpm_svti_graceful(int gr_type, uint32_t cmd,
                                    const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_SVTI, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_svti));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_SVTI;
	fpm_cmd->comp    = fpm_svti_comp;
	fpm_cmd->revert  = fpm_svti_revert;
	fpm_cmd->display = fpm_svti_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}
#endif

#if defined(CONFIG_MCORE_VXLAN)
static int fpm_vxlan_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_vxlan *if1 = cmd1->data;
	struct cp_vxlan *if2 = cmd2->data;

	if ((if1->cpvxlan_ifuid == if2->cpvxlan_ifuid) &&
	    (!strcmp(if1->cpvxlan_ifname, if2->cpvxlan_ifname))) {
		return 0;
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_vxlan_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_VXLAN_DELETE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_vxlan_display(const fpm_cmd_t *fpm_cmd, char *buffer, int len)
{
	struct cp_vxlan *data = fpm_cmd->data;

	snprintf(buffer, len, "CMD_VXLAN - %s(dst port: 0x%08x)\n",
	   data->cpvxlan_ifname, ntohs(data->cpvxlan_dstport));
}

static fpm_cmd_t *fpm_vxlan_graceful(int gr_type, uint32_t cmd, const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_INTERFACE, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_vxlan));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_INTERFACE;
	fpm_cmd->comp    = fpm_vxlan_comp;
	fpm_cmd->revert  = fpm_vxlan_revert;
	fpm_cmd->display = fpm_vxlan_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}
#endif

static int fpm_interface_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_iface_create *if1 = cmd1->data;
	struct cp_iface_create *if2 = cmd2->data;

	if ((if1->cpiface_ifuid == if2->cpiface_ifuid) &&
	    (!strcmp(if1->cpiface_ifname, if2->cpiface_ifname))) {
		return 0;
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_interface_revert(const fpm_cmd_t *fpm_cmd)
{
	return fpm_interface_del(fpm_cmd->data, NULL);
}

static void fpm_interface_display(const fpm_cmd_t *fpm_cmd,
                                  char *buffer, int len)
{
	struct cp_iface_create *data = fpm_cmd->data;

	snprintf(buffer, len, "CMD_IF - %s(0x%08x)\n",
	   data->cpiface_ifname, ntohl(data->cpiface_ifuid));
}

static fpm_cmd_t *fpm_interface_graceful(int gr_type, uint32_t cmd,
                                         const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_INTERFACE, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_iface_create));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_INTERFACE;
	fpm_cmd->comp    = fpm_interface_comp;
	fpm_cmd->revert  = fpm_interface_revert;
	fpm_cmd->display = fpm_interface_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

static struct fpm_vrf_handler vrf_hdlr = {
	.name = "interface",
	.del = fpm_interface_vrf_del,
};

static int fpm_interface_shared_cmd(int gr_type, enum list_type list)
{
	int if_idx;
	int ret = 0;

	for (if_idx=0 ; if_idx<FP_MAX_IFNET ; if_idx++) {
		fp_ifnet_t *ifp;

		ifp = &fp_shared->ifnet.table[if_idx];

		/* If interface is not valid, continue */
		if (ifp->if_ifuid == 0) 
			continue;

		/* Add requests for interfaces types managed by CMD_IF_CREATE */
		if (ifp->if_type == FP_IFTYPE_ETHER ||
		    ifp->if_type ==  FP_IFTYPE_EIFACE ||
		    ifp->if_type ==  FP_IFTYPE_LOCAL ||
		    ifp->if_type ==  FP_IFTYPE_VETH ||
		    ifp->if_type ==  FP_IFTYPE_LOOP ||
		    ifp->if_type ==  FP_IFTYPE_XVRF ||
#if defined (CONFIG_MCORE_IPSEC_SVTI) && !defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
		    ifp->if_type ==  FP_IFTYPE_SVTI ||
#endif
		    ifp->if_type ==  FP_IFTYPE_BRIDGE) {
			struct cp_iface_create req;

			/* If graceful is not needed for this type, continue */
			if (!fpm_cmd_match_gr_type(FPM_CMD_INTERFACE, gr_type))
				continue;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			req.cpiface_ifuid = ifp->if_ifuid;
			strcpy(req.cpiface_ifname, ifp->if_name);
		
			ret |= fpm_cmd_create_and_enqueue(list, CMD_IF_CREATE, &req);
		}

#if defined (CONFIG_MCORE_IPSEC_SVTI) && defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
		if (ifp->if_type == FP_IFTYPE_SVTI) {
			struct cp_svti req;

			/* If graceful is not needed for this type, continue */
			if (!fpm_cmd_match_gr_type(FPM_CMD_SVTI, gr_type))
				continue;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			strcpy(req.cpsvti_ifname, ifp->if_name);
			req.cpsvti_ifuid = ifp->if_ifuid;

			ret |= fpm_cmd_create_and_enqueue(list, CMD_SVTI_CREATE, &req);
		}
#endif /* CONFIG_MCORE_IPSEC_SVTI && CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA */

#if defined (CONFIG_MCORE_VXLAN)
		if (ifp->if_type == FP_IFTYPE_VXLAN) {
			struct cp_vxlan req;

			/* If graceful is not needed for this type, continue */
			if (!fpm_cmd_match_gr_type(FPM_CMD_INTERFACE, gr_type))
				continue;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			strcpy(req.cpvxlan_ifname, ifp->if_name);
			req.cpvxlan_ifuid = ifp->if_ifuid;

			ret |= fpm_cmd_create_and_enqueue(list, CMD_VXLAN_CREATE, &req);
		}
#endif
	}

	return ret;
}

static void fpm_interface_init(__attribute__((unused)) int graceful)
{
	fpm_vrf_register(&vrf_hdlr);

	fpm_register_msg(CMD_IF_CREATE, fpm_interface_add, fpm_interface_graceful);
	fpm_register_msg(CMD_IF_DELETE, fpm_interface_del, NULL);
	fpm_register_msg(CMD_IF_MASTER, fpm_interface_master, NULL);
	fpm_register_msg(CMD_IF_MTU, fpm_interface_mtu, NULL);
	fpm_register_msg(CMD_IF_MAC, fpm_interface_mac, NULL);
	fpm_register_msg(CMD_IF_STATE_UPDATE, fpm_interface_state, NULL);

	fpm_register_msg(CMD_IF_BLADEINFO, fpm_interface_bladeinfo, NULL);
	fpm_register_msg(CMD_IF_VETH_PEER, fpm_interface_veth_peer, NULL);

#if defined(CONFIG_MCORE_IPSEC_SVTI) && defined(CONFIG_MCORE_IPSEC_SVTI_GLOBAL_SA)
	fpm_register_msg(CMD_SVTI_CREATE, fpm_interface_svti_tunnel_add, fpm_svti_graceful);
	fpm_register_msg(CMD_SVTI_DELETE, fpm_interface_svti_tunnel_del, NULL);
#endif

#if defined(CONFIG_MCORE_VXLAN)
	fpm_register_msg(CMD_VXLAN_CREATE, fpm_interface_vxlan_add, fpm_vxlan_graceful);
	fpm_register_msg(CMD_VXLAN_DELETE, fpm_interface_vxlan_del, NULL);
	fpm_register_msg(CMD_VXLAN_FDB_ADD, fpm_vxlan_fdb_add, NULL);
	fpm_register_msg(CMD_VXLAN_FDB_DEL, fpm_vxlan_fdb_del, NULL);
#endif
}

static struct fpm_mod fpm_interface_mod = {
	.name = "interface",
	.init = fpm_interface_init,
	.shared_cmd = fpm_interface_shared_cmd,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_interface_mod);
}
