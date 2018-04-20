/*
 * Copyright 2011-2013 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <netgraph.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_gtpu.h>
#include <netgraph/ng_nffec.h>
#include <netgraph/ng_ksocket.h>
#include <netgraph/ng_iface.h>

#define GTPU_SUCCESS	EXIT_SUCCESS
#define GTPU_FAILURE	EXIT_FAILURE

/* pre-defined constant UDP ports */
#define GTPU_SERVER_PORT	2152
#define GTPU_CLIENT_PORT	62152
/* max number of supported ksockets per GTP-U node (actually, only 4 are needed)*/
#define GTPU_MAX_KSOCKS		10

#define GTPU_CSOCK_CHECK \
	if (vnb_csock == -1) \
		return(GTPU_FAILURE);

/* sockets for communication with the ng_gtpu VNB node */
static int vnb_csock = -1; /* VNB Control socket */
static int vnb_dsock = -1; /* VNB Data socket */

static char *gtp_ifname = "gtp0";

/*
 * Creation of the control and data sockets
 */
static int
gtpu_vnb_init(void)
{
	char name[NG_NODELEN + 1];


	/* Format arguments */
	memset(&name, 0, sizeof(name));
	snprintf(name, sizeof(name), "gtpu%d", getpid());

	/* Send message */
	if (NgMkSockNode(name, &vnb_csock, &vnb_dsock) < 0) {
		warn("%s: unable to get a VNB socket", __func__);
		vnb_csock = -1;
		vnb_dsock = -1;
		return GTPU_FAILURE;
	}

	return GTPU_SUCCESS;
}

/*
 * Creation of an "un-connected", named VNB node
 */
static int
gtpu_addnode(const char * type, const char * ourhook, const char * peerhook)
{
	struct ngm_mkpeer mkp;
	char path_for_name[NG_PATHLEN + 1];
	struct ngm_name name;

	GTPU_CSOCK_CHECK;

	/* Format arguments */
	memset(&mkp, 0, sizeof(mkp));
	snprintf(mkp.type, sizeof(mkp.type), "%s", type);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s", ourhook);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%s", peerhook);

	/* Send message */
	if (NgSendMsg(vnb_csock, ".", NGM_GENERIC_COOKIE,
		NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		warn("%s: send msg NGM_MKPEER %s", __func__, type);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&path_for_name, 0, sizeof(path_for_name));
	sprintf(path_for_name,".:%s", ourhook);
	memset(&name, 0, sizeof(name));
	snprintf(name.name, sizeof(name.name), "%s", ourhook);

	/* Send message */
	if (NgSendMsg(vnb_csock, path_for_name, NGM_GENERIC_COOKIE,
		NGM_NAME, &name, sizeof(name)) < 0) {
		warn("%s: send msg NGM_NAME %s", __func__, name.name);
		return(GTPU_FAILURE);
	}
	return(GTPU_SUCCESS);
}

/*
 * Creation of the constant infrastructure, needed for all GTP-U configurations
 */
static int
gtpu_create_infra(int af)
{
	struct ngm_mkpeer mkp;
	char path_for_name[NG_PATHLEN + 1];
	struct ngm_name name;

	GTPU_CSOCK_CHECK;

	/* Add "root" node : dev_null */
	if (gtpu_addnode(NG_IFACE_NODE_TYPE, "dev_null", NG_IFACE_HOOK_INET) < 0) {
		warn("%s: gtpu_addnode", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&mkp, 0, sizeof(mkp));
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_GTPU_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s", NG_IFACE_HOOK_ALLIP);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%s", NG_GTPU_HOOK_NOMATCH);

	/* Send message */
	if (NgSendMsg(vnb_csock, "dev_null:", NGM_GENERIC_COOKIE,
		NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		warn("%s: send msg NGM_MKPEER gtpu", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&path_for_name, 0, sizeof(path_for_name));
	sprintf(path_for_name,"dev_null:%s", NG_IFACE_HOOK_ALLIP);
	memset(&name, 0, sizeof(name));
	snprintf(name.name, sizeof(name.name), "%s", "test_gtpu");

	/* Send message */
	if (NgSendMsg(vnb_csock, path_for_name, NGM_GENERIC_COOKIE,
		NGM_NAME, &name, sizeof(name)) < 0) {
		warn("%s: send msg NGM_NAME test_gtpu", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&mkp, 0, sizeof(mkp));
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_KSOCKET_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s", NG_GTPU_HOOK_LOWER_RX);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%s/%s",
		 af == AF_INET ? "inet" : "inet6", "dgram/udp");

	/* Send message */
	if (NgSendMsg(vnb_csock, "test_gtpu:", NGM_GENERIC_COOKIE,
		NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		warn("%s: send msg NGM_MKPEER ksocket", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&path_for_name, 0, sizeof(path_for_name));
	sprintf(path_for_name,"test_gtpu:%s", NG_GTPU_HOOK_LOWER_RX);
	memset(&name, 0, sizeof(name));
	snprintf(name.name, sizeof(name.name), "%s", "test_udp_rx");

	/* Send message */
	if (NgSendMsg(vnb_csock, path_for_name, NGM_GENERIC_COOKIE,
		NGM_NAME, &name, sizeof(name)) < 0) {
		warn("%s: send msg NGM_NAME test_udp_rx", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	if (af == AF_INET) {
		struct sockaddr_in laddr = {
			.sin_family = af,
			.sin_addr.s_addr = INADDR_ANY,
			.sin_port = htons(GTPU_SERVER_PORT)
		};

		/* Send message */
		if (NgSendMsg(vnb_csock, "test_udp_rx:", NGM_KSOCKET_COOKIE, NGM_KSOCKET_BIND,
			      &laddr, sizeof(laddr)) == -1) {
			warn("%s: failed to bind ksocket", __func__);
			return(GTPU_FAILURE);
		}
	} else /* AF_INET6 */ {
		struct sockaddr_in6 laddr = {
			.sin6_family = af,
			.sin6_addr = IN6ADDR_ANY_INIT,
			.sin6_port = htons(GTPU_SERVER_PORT)
		};

		/* Send message */
		if (NgSendMsg(vnb_csock, "test_udp_rx:", NGM_KSOCKET_COOKIE, NGM_KSOCKET_BIND,
			      &laddr, sizeof(laddr)) == -1) {
			warn("%s: failed to bind ksocket", __func__);
			return(GTPU_FAILURE);
		}
	}

	return(GTPU_SUCCESS);
}

/*
 * Creation of the specific infrastructure needed for the NFFEC configuration
 */
static int
gtpu_plug_nfm_infra(const in_addr_t loc_tun_addr, const in_addr_t rem_tun_addr)
{
	struct ngm_mkpeer mkp;
	char path_for_name[NG_PATHLEN + 1];
	char ifname[NG_IFACE_IFACE_NAME_MAX];
	struct ngm_name name;
	struct ng_nffec_mode sfc;
	int fd;
	struct ifreq ifr;
	struct sockaddr_in sin;

	GTPU_CSOCK_CHECK;

	/* Format arguments */
	memset(&mkp, 0, sizeof(mkp));
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_IFACE_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s", gtp_ifname);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%s", NG_IFACE_HOOK_INET);

	/* Send message */
	if (NgSendMsg(vnb_csock, ".", NGM_GENERIC_COOKIE,
		NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		warn("%s: send msg NGM_MKPEER iface", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(path_for_name, 0, sizeof(path_for_name));
	sprintf(path_for_name,".:%s", gtp_ifname);
	memset(ifname, 0, sizeof(ifname));
	strcpy(ifname, gtp_ifname);

	/* Send message */
	if (NgSendMsg(vnb_csock, path_for_name, NGM_IFACE_COOKIE, NGM_IFACE_SET_IFNAME,
		ifname, NG_IFACE_IFACE_NAME_MAX) == -1) {
		warn("%s: failed to set ifname", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&mkp, 0, sizeof(mkp));
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_NFFEC_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s", NG_IFACE_HOOK_ALLIP);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%s", NG_NFFEC_HOOK_MUX);

	/* Send message */
	memset(&path_for_name, 0, sizeof(path_for_name));
	sprintf(path_for_name,"%s:", gtp_ifname);
	if (NgSendMsg(vnb_csock, path_for_name, NGM_GENERIC_COOKIE,
		NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		warn("%s: send msg NGM_MKPEER nffec", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&path_for_name, 0, sizeof(path_for_name));
	sprintf(path_for_name,"%s:%s", gtp_ifname, NG_IFACE_HOOK_ALLIP);
	memset(&name, 0, sizeof(name));
	snprintf(name.name, sizeof(name.name), "%s", "nfm_nod_00");

	/* Send message */
	if (NgSendMsg(vnb_csock, path_for_name, NGM_GENERIC_COOKIE,
		NGM_NAME, &name, sizeof(name)) < 0) {
		warn("%s: send msg NGM_NAME nfm_nod_00", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&sfc, 0, sizeof(sfc));
	sfc.sfcEnable = NG_NFFEC_SFC_ENABLE;

	/* Send message */
	if (NgSendMsg(vnb_csock, "nfm_nod_00:", NGM_NFFEC_COOKIE,
		NGM_NFFEC_SET_MODE, &sfc, sizeof(sfc)) < 0) {
		warn("%s: send msg NGM_NFFEC_SET_MODE nfm_nod_00", __func__);
		return(GTPU_FAILURE);
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		warn("%s: cannot create socket", __func__);
		errno = ENOMEM;
		return(GTPU_FAILURE);
	}
	/* Format arguments */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, gtp_ifname, IFNAMSIZ-1);
	/* Send message */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		warn("%s: cannot get I/F flags", __func__);
		return(GTPU_FAILURE);
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	/* Send message */
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		warn("%s: cannot set I/F flags", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = loc_tun_addr;
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	/* Send message */
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
		warn("%s: cannot set local I/F addr", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = rem_tun_addr;
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	/* Send message */
	if (ioctl(fd, SIOCSIFDSTADDR, &ifr) < 0) {
		warn("%s: cannot set remote I/F addr", __func__);
		return(GTPU_FAILURE);
	}

	return(GTPU_SUCCESS);
}

/*
 * Creation of one ksocket (Tx) : bind + connect
 */
static int
gtpu_create_1_ksock(int af, const char *loc_gsn, const char *rem_gsn, const int index)
{
	struct ngm_mkpeer mkp;
	char path_for_name[NG_PATHLEN + 1];
	struct ngm_name name;

	GTPU_CSOCK_CHECK;

	/* Format arguments */
	memset(&mkp, 0, sizeof(mkp));
	snprintf(mkp.type, sizeof(mkp.type), "%s", NG_KSOCKET_NODE_TYPE);
	snprintf(mkp.ourhook, sizeof(mkp.ourhook), "%s%d", NG_GTPU_HOOK_LOWER_PREFIX, index);
	snprintf(mkp.peerhook, sizeof(mkp.peerhook), "%s/%s",
		 af == AF_INET ? "inet" : "inet6", "dgram/udp");

	/* Send message */
	if (NgSendMsg(vnb_csock, "test_gtpu:", NGM_GENERIC_COOKIE,
		NGM_MKPEER, &mkp, sizeof(mkp)) < 0) {
		warn("%s: send msg NGM_MKPEER ksocket", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&path_for_name, 0, sizeof(path_for_name));
	sprintf(path_for_name,"test_gtpu:%s%d", NG_GTPU_HOOK_LOWER_PREFIX, index);
	memset(&name, 0, sizeof(name));
	snprintf(name.name, sizeof(name.name), "%s%d", "gtp_udp_tx", index);

	/* Send message */
	if (NgSendMsg(vnb_csock, path_for_name, NGM_GENERIC_COOKIE,
		NGM_NAME, &name, sizeof(name)) < 0) {
		warn("%s: send msg NGM_NAME lower", __func__);
		return(GTPU_FAILURE);
	}

	/* Format arguments */
	memset(&path_for_name, 0, sizeof(path_for_name));
	sprintf(path_for_name,"gtp_udp_tx%d:", index);
	if (af == AF_INET) {
		struct sockaddr_in addr = {.sin_family = af};

		addr.sin_port = htons(GTPU_CLIENT_PORT);

		if (inet_pton(af, loc_gsn, (void *)&addr.sin_addr) <= 0) {
			warn("%s: wrong local address given: %s", __func__, loc_gsn);
			return (GTPU_FAILURE);
		}

		/* Send message for local gsn */
		if (NgSendMsg(vnb_csock, path_for_name, NGM_KSOCKET_COOKIE, NGM_KSOCKET_BIND,
			      &addr, sizeof(addr)) == -1) {
			warn("%s: failed to bind ksocket: %s", __func__, path_for_name);
			return(GTPU_FAILURE);
		}

		/* reuse addr for the remote */
		addr.sin_port = htons(GTPU_SERVER_PORT);

		memset(&addr.sin_addr, 0, sizeof(addr.sin_addr));
		if (inet_pton(af, rem_gsn, (void *)&addr.sin_addr) <= 0) {
			warn("%s: wrong remote address given: %s", __func__, rem_gsn);
			return (GTPU_FAILURE);
		}

		/* Send message for remote gsn */
		if (NgSendMsg(vnb_csock, path_for_name, NGM_KSOCKET_COOKIE, NGM_KSOCKET_CONNECT,
			      &addr, sizeof(addr)) == -1) {
			warn("%s: failed to connect ksocket: %s", __func__, path_for_name);
			return(GTPU_FAILURE);
		}
	} else /* IF_INET6 */ {
		struct sockaddr_in6 addr = {.sin6_family = af};

		addr.sin6_port = htons(GTPU_CLIENT_PORT);

		if (inet_pton(af, loc_gsn, (void *)&addr.sin6_addr) <= 0) {
			warn("%s: wrong local address given: %s", __func__, loc_gsn);
			return (GTPU_FAILURE);
		}

		/* Send message for local gsn */
		if (NgSendMsg(vnb_csock, path_for_name, NGM_KSOCKET_COOKIE, NGM_KSOCKET_BIND,
			      &addr, sizeof(addr)) == -1) {
			warn("%s: failed to bind ksocket: %s", __func__, path_for_name);
			return(GTPU_FAILURE);
		}

		/* reuse addr for the remote */
		addr.sin6_port = htons(GTPU_SERVER_PORT);

		memset(&addr.sin6_addr, 0, sizeof(addr.sin6_addr));
		if (inet_pton(af, rem_gsn, (void *)&addr.sin6_addr) <= 0) {
			warn("%s: wrong remote address given: %s", __func__, rem_gsn);
			return (GTPU_FAILURE);
		}

		/* Send message for remote gsn */
		if (NgSendMsg(vnb_csock, path_for_name, NGM_KSOCKET_COOKIE, NGM_KSOCKET_CONNECT,
			      &addr, sizeof(addr)) == -1) {
			warn("%s: failed to connect ksocket: %s", __func__, path_for_name);
			return(GTPU_FAILURE);
		}
	}

	return(GTPU_SUCCESS);
}

/*
 * Creation and configuration of the tunnels in an NFFEC configuration
 * (Simple Flow Classifier)
 */
static int
gtpu_create_nfm_tunnels(const int start, const int nb_tunnels,
						const int ksock_index, const int offset)
{
	int i, teid_tx, teid_rx;
	struct ngm_connect ngc;
	struct ng_gtpu_pdp_context npdp;

	GTPU_CSOCK_CHECK;

	for (i=start+1; i<=(start+nb_tunnels); i++) {
		teid_tx = i + offset;
		teid_rx = i + offset;

		/* Format arguments */
		memset(&ngc, 0, sizeof(ngc));
		snprintf(ngc.path, sizeof(ngc.path), "%s", "nfm_nod_00:");
		snprintf(ngc.ourhook, sizeof(ngc.ourhook), "%s%d", NG_GTPU_HOOK_UPPER_PREFIX, i);
		snprintf(ngc.peerhook, sizeof(ngc.peerhook), "%s0x%04x", NG_NFFEC_HOOK_LINK_PREFIX, i);

		/* Send message */
		if (NgSendMsg(vnb_csock, "test_gtpu:", NGM_GENERIC_COOKIE,
			NGM_CONNECT, &ngc, sizeof(ngc)) < 0) {
			warn("%s: send msg NGM_CONNECT nfm_nod_00:%s", __func__, ngc.peerhook);
			return(GTPU_FAILURE);
		}

		/* Format arguments */
		memset(&npdp, 0, sizeof(npdp));
		snprintf(npdp.lower, sizeof(npdp.lower), "%s%d", NG_GTPU_HOOK_LOWER_PREFIX, ksock_index);
		snprintf(npdp.upper, sizeof(npdp.upper), "%s%d", NG_GTPU_HOOK_UPPER_PREFIX, i);
		npdp.teid_tx = teid_tx;
		npdp.teid_rx = teid_rx;
		npdp.flags_tx = 0x30;
		npdp.tos = 0;

		/* Send message */
		if (NgSendMsg(vnb_csock, "test_gtpu:", NGM_GTPU_COOKIE,
			NGM_GTPU_ADDPDP_CTXT, &npdp, sizeof(npdp)) < 0) {
			warn("%s: send msg NGM_GTPU_ADDPDP_CTXT: %s", __func__, npdp.upper);
			return(GTPU_FAILURE);
		}

	}

	return(GTPU_SUCCESS);
}

/*
 * Creation and configuration of the tunnels in a relay configuration
 * (direct upper-to-upper connection)
 */
static int
gtpu_create_relay_tunnels(const int start, const int nb_tunnels, const int ksock_left,
						  const int ksock_right, const int offset)
{
	int i, teid_left_tx, teid_left_rx, teid_right_tx, teid_right_rx;
	struct ngm_connect ngc;
	struct ng_gtpu_pdp_context npdp;

	fprintf(stderr, "%s: entering\n", __func__);
	fprintf(stderr, "start %d nb_tunnels %d ksock l %d r %d offset %d\n",
			start, nb_tunnels, ksock_left, ksock_right, offset);

	GTPU_CSOCK_CHECK;

	for (i=start+1; i<=(start+nb_tunnels); i++) {
		teid_left_tx = i;
		teid_left_rx = i;
		teid_right_tx = i + offset;
		teid_right_rx = i + offset;

		/* Format arguments */
		memset(&ngc, 0, sizeof(ngc));
		snprintf(ngc.path, sizeof(ngc.path), "%s", "test_gtpu:");
		snprintf(ngc.ourhook, sizeof(ngc.ourhook), "%s%d", NG_GTPU_HOOK_UPPER_PREFIX, i);
		snprintf(ngc.peerhook, sizeof(ngc.peerhook), "%s%d", NG_GTPU_HOOK_UPPER_PREFIX, i + offset);

		/* Send message */
		if (NgSendMsg(vnb_csock, "test_gtpu:", NGM_GENERIC_COOKIE,
			NGM_CONNECT, &ngc, sizeof(ngc)) < 0) {
			warn("%s: send msg NGM_CONNECT test_gtpu:%s", __func__, ngc.peerhook);
			return(GTPU_FAILURE);
		}

		/* Format arguments */
		memset(&npdp, 0, sizeof(npdp));
		snprintf(npdp.lower, sizeof(npdp.lower), "%s%d", NG_GTPU_HOOK_LOWER_PREFIX, ksock_left);
		snprintf(npdp.upper, sizeof(npdp.upper), "%s%d", NG_GTPU_HOOK_UPPER_PREFIX, i);
		npdp.teid_tx = teid_left_tx;
		npdp.teid_rx = teid_left_rx;
		npdp.flags_tx = 0x30;
		npdp.tos = 0;

		/* Send message */
		if (NgSendMsg(vnb_csock, "test_gtpu:", NGM_GTPU_COOKIE,
			NGM_GTPU_ADDPDP_CTXT, &npdp, sizeof(npdp)) < 0) {
			warn("%s: send msg NGM_GTPU_ADDPDP_CTXT: %s", __func__, npdp.upper);
			return(GTPU_FAILURE);
		}

		/* Format arguments */
		memset(&npdp, 0, sizeof(npdp));
		snprintf(npdp.lower, sizeof(npdp.lower), "%s%d", NG_GTPU_HOOK_LOWER_PREFIX, ksock_right);
		snprintf(npdp.upper, sizeof(npdp.upper), "%s%d", NG_GTPU_HOOK_UPPER_PREFIX, i + offset);
		npdp.teid_tx = teid_right_tx;
		npdp.teid_rx = teid_right_rx;
		npdp.flags_tx = 0x30;
		npdp.tos = 0;

		/* Send message */
		if (NgSendMsg(vnb_csock, "test_gtpu:", NGM_GTPU_COOKIE,
			NGM_GTPU_ADDPDP_CTXT, &npdp, sizeof(npdp)) < 0) {
			warn("%s: send msg NGM_GTPU_ADDPDP_CTXT: %s", __func__, npdp.upper);
			return(GTPU_FAILURE);
		}

	}

	return(GTPU_SUCCESS);
}

static void
gtpuctl_usage(const char *path)
{
	const char *cmd;

	cmd = strrchr(path, '/');
	if (!cmd)
		cmd = path;
	else
		cmd++;
	(void) fprintf(stderr, "usage: %s", cmd);
	(void) fprintf(stderr, "[-h] [-l IP addr for local iface] [-r IP addr for remote iface]\n");
	(void) fprintf(stderr, "       {[-6] [-L IP addr for local ksock] [-R IP addr for remote ksock]}\n");
	(void) fprintf(stderr, "       [-t number of tunnels per ksocket (deprecated)]\n");
	(void) fprintf(stderr, "       [-o (TEID offset)]\n");
	(void) fprintf(stderr, "       [-p (PDN GW mode)] [-s (Serving GW mode)]\n");
	(void) fprintf(stderr, "       [-n gtp_ifname]\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "example: (PDN-left, PDN-right and Serving-GW)\n");
	(void) fprintf(stderr, "gtpuctl -p -l 1.2.3.4 -r 1.2.3.5 -L 10.123.1.1 -R 10.123.1.4\n");
	(void) fprintf(stderr, "gtpuctl -p -l 1.2.3.5 -r 1.2.3.4 -L 10.125.1.2 -R 10.125.1.4 -o 4097\n");
	(void) fprintf(stderr, "gtpuctl -s -L 10.123.1.4 -R 10.123.1.1 -L 10.125.1.4 -R 10.125.1.2 -o 4097\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "example: (PDN-left with two ksocks)\n");
	(void) fprintf(stderr, "gtpuctl -L 10.123.1.1 -R 10.123.1.4 -L 10.223.1.1 -R 10.223.1.4\n");

	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	int ch;
	char * loc_tun = "1.2.3.4";
	char * rem_tun = "1.2.3.5";
	char * loc_gsn[GTPU_MAX_KSOCKS] = {"10.1.1.1"};
	char * rem_gsn[GTPU_MAX_KSOCKS] = {"10.1.1.2"};
	int nb_L_ksocks = 0;
	int nb_R_ksocks = 0;
	int nb_tuns = NFFEC_HASHTABLE_SIZE;
	int i, j, p_flag, s_flag, start;
	int right_offset = 0;
	int af = AF_INET;

	p_flag = s_flag = 0;

	/* get options */
	while ((ch = getopt(argc, argv, "h6l:L:o:pr:R:st:n:")) != -1) {
		switch (ch) {
		/* Help message */
		case 'h':
			gtpuctl_usage(argv[0]);
			break;
		/* Enable IPv6 addresses */
		case '6':
			af = AF_INET6;
			break;
		/* set the name of the gtp iface */
		case 'n':
			gtp_ifname = optarg;
			break;
		/* IP address for the local endpoint of the iface */
		case 'l':
			loc_tun = optarg;
			break;
		/* Local IP address for one Tx ksocket */
		case 'L':
			loc_gsn[nb_L_ksocks] = optarg;
			nb_L_ksocks++;
			if (nb_L_ksocks == GTPU_MAX_KSOCKS) {
				fprintf(stderr, "Too many ksocks.\n");
				exit(EX_USAGE);
			}
			break;
		/*
		 * offset :
		 * - difference between TEID of the tunnels and the upper index in right PDN GW
		 * - difference between TEID of the "left" and "right" connected tunnels in serving GSN
		 */
		case 'o':
			right_offset = atoi(optarg);
			break;
		/* selection of Pdn GSN mode */
		case 'p':
			p_flag++;
			break;
		/* IP address for the remote endpoint of the iface */
		case 'r':
			rem_tun = optarg;
			break;
		/* Remote IP address for one Tx ksocket */
		case 'R':
			rem_gsn[nb_R_ksocks] = optarg;
			nb_R_ksocks++;
			if (nb_R_ksocks == GTPU_MAX_KSOCKS) {
				fprintf(stderr, "Too many ksocks.\n");
				exit(EX_USAGE);
			}
			break;
		/* selection of Serving GSN mode */
		case 's':
			s_flag++;
			break;
		/* deprecated: number of per ksocket tunnels */
		/* this value is intimately associated with the nffec hashtable order */
		case 't':
			/* -t silently ignored */
			break;

		default:
			fprintf(stderr, "Unknown option.\n");
			gtpuctl_usage(argv[0]);
		}
	}

	/* checks for the input parameters */
	if ((p_flag + s_flag) != 1) {
		fprintf(stderr, "Must define PDN GW or Serving GW.\n");
		exit(EX_USAGE);
	}
	if (nb_L_ksocks != nb_R_ksocks) {
		fprintf(stderr, "Unbalanced ksock parameters.\n");
		exit(EX_USAGE);
	}
	if (s_flag && (nb_L_ksocks%2 != 0)) {
		fprintf(stderr, "Serving GW: the number of ksocks must be even.\n");
		exit(EX_USAGE);
	}
	if (s_flag && (right_offset == 0)) {
		fprintf(stderr, "Serving GW: right_offset must not be null.\n");
		exit(EX_USAGE);
	}
	/* use the default parameter */
	if (nb_L_ksocks == 0)
		nb_L_ksocks = 1;

	if (gtpu_vnb_init() < 0)
		exit(EXIT_FAILURE);

	/* creation of the constant infrastructure */
	if (gtpu_create_infra(af) < 0)
		exit(EXIT_FAILURE);

	start = 0;
	if (p_flag) {
		/* configuration for a PDN GSN : with NFFEC (Simple Flow Classifier) */
		if (gtpu_plug_nfm_infra(inet_addr(loc_tun), inet_addr(rem_tun)) < 0)
			exit(EXIT_FAILURE);

		/* for each defined ksocket */
		for (i=0 ; i< nb_L_ksocks ; i++) {
			/* create the expected ksocket */
			gtpu_create_1_ksock(af, loc_gsn[i], rem_gsn[i], i);
			/* create the tunnels travelling the this ksocket */
			gtpu_create_nfm_tunnels(start, nb_tuns, i, right_offset);
			/* prepare for the next set of tunnels */
			start += nb_tuns;
		}
	} else {
		/* configuration for a Serving GSN : with direct upper-to-upper connection */
		for (i=0 ; i< nb_L_ksocks ; ) {
			/* create the "left" ksocket */
			gtpu_create_1_ksock(af, loc_gsn[i], rem_gsn[i], i);
			j = i+1;
			/* create the "right" ksocket */
			gtpu_create_1_ksock(af, loc_gsn[j], rem_gsn[j], j);
			/* and connect the tunnels from left to right */
			gtpu_create_relay_tunnels(start, nb_tuns, i, j, right_offset);
			/* prepare for the next set of tunnels */
			start += nb_tuns;
			i += 2;
		}
	}

	return EXIT_SUCCESS;
}
