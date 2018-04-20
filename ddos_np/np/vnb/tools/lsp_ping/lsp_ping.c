/*
 * Copyright 2011 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <event.h>
#include <signal.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netgraph.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <in_cksum.h>
#include <netgraph/ng_message.h>
#include <netgraph/ng_socket.h>
#include <netgraph/ng_nffec.h>

#include <netgraph/ng_mpls_oam.h>

/* maximum IP packet length */
#define BUFLEN 1500
/* simulated payload length (see LSP specific structure length) */
#define DATALEN 150

/* use a sendmsg : needed for ancillary data */
struct msghdr m = {0};
struct cmsghdr *cm;
struct iovec iov[2];
u_char cmsgbuf[256];

static int vnb_nffec_csock = -1; /* VNB Control socket */
static int vnb_nffec_dsock = -1; /* VNB Data socket */

static int vnb_oam_lsp_csock = -1;/* VNB Control socket */
static int vnb_oam_lsp_dsock = -1;/* VNB Data socket */
static int vnb_oam_bfd_csock = -1;/* VNB Control socket */
static int vnb_oam_bfd_dsock = -1;/* VNB Data socket */

static struct event oam_lsp_dsock_evt;
static void notify_lsp_ping_oam_lsp(int fd, short event, void *param);
static struct event oam_bfd_dsock_evt;
static void notify_lsp_ping_oam_bfd(int fd, short event, void *param);

static int
lsp_ping_nffec_init(char *nffec_name)
{
	int err;
	char name[NG_NODELEN + 1];

	snprintf(name, sizeof(name), "%s_%d", nffec_name, getpid());
	err = NgMkSockNode(name, &vnb_nffec_csock, &vnb_nffec_dsock);
	if (err < 0) {
		fprintf(stderr, "unable to get a VNB socket(nffec): %s\n",
		      strerror(errno));
		vnb_nffec_csock = -1;
		vnb_nffec_dsock = -1;
		return err;
	}
	return err;
}

/*
 * in the VNB graph, connect the lspping data hook from nodename
 * to the lsp_ping dsock data socket
 */
static int
lsp_ping_nffec_connect(char *nffec_name)
{
	struct ngm_connect ngc;
	int err = 0;

	/* be careful when sending the connect message, at this
	 * time the node may node exist */
	if (vnb_nffec_csock == -1) {
		fprintf(stderr, "node %s does not exist\n",
		      nffec_name);
		return -1;
	}

	snprintf(ngc.path, sizeof(ngc.path), "%s:", nffec_name);
	snprintf(ngc.ourhook, sizeof(ngc.ourhook), "%s", nffec_name);
	snprintf(ngc.peerhook, sizeof(ngc.peerhook), "%s%d",
			NG_NFFEC_HOOK_LOWER_IN_PREFIX, 0);
	err = NgSendMsg(vnb_nffec_csock, ".", NGM_GENERIC_COOKIE,
			NGM_CONNECT, &ngc, sizeof(ngc));
	if (err < 0) {
		fprintf(stderr, "unable to connect to node %s (err %d): %s\n",
		      nffec_name, err, strerror(errno));
		return -1;
	}

	return 0;
}


static int
lsp_ping_oam_lsp_init(char *oam_name)
{
	int err;
	char name[NG_NODELEN + 1];

	snprintf(name, sizeof(name), "%s_lsp_%d", oam_name, getpid());
	err = NgMkSockNode(name, &vnb_oam_lsp_csock, &vnb_oam_lsp_dsock);
	if (err < 0) {
		fprintf(stderr, "unable to get a VNB socket(oam_lsp): %s\n",
		      strerror(errno));
		vnb_oam_lsp_csock = -1;
		vnb_oam_lsp_dsock = -1;
		return err;
	}
	event_set(&oam_lsp_dsock_evt, vnb_oam_lsp_dsock,
		  EV_READ | EV_PERSIST, (void *) notify_lsp_ping_oam_lsp, NULL);
	event_add(&oam_lsp_dsock_evt, NULL);
	return err;
}

/*
 * in the VNB graph, connect the lspping data hook from nodename
 * to the lsp_ping dsock data socket
 */
static int
lsp_ping_oam_lsp_connect(char *oam_name)
{
	struct ngm_connect ngc;
	int err = 0;

	/* be careful when sending the connect message, at this
	 * time the node may node exist */
	if (vnb_oam_lsp_csock == -1) {
		fprintf(stderr, "node %s does not exist\n",
		      oam_name);
		return -1;
	}

	snprintf(ngc.path, sizeof(ngc.path), "%s:", oam_name);
	snprintf(ngc.ourhook, sizeof(ngc.ourhook), "%s_lsp", oam_name);
	snprintf(ngc.peerhook, sizeof(ngc.peerhook), NG_MPLS_OAM_HOOK_UPPER_LSP);
	err = NgSendMsg(vnb_oam_lsp_csock, ".", NGM_GENERIC_COOKIE,
			NGM_CONNECT, &ngc, sizeof(ngc));
	if (err < 0) {
		fprintf(stderr, "unable to connect to node %s (err %d): %s(lsp)\n",
		      oam_name, err, strerror(errno));
		return -1;
	}

	return 0;
}

/* derived from vnb/tools/snoop/notify.c */
static u_int8_t buf_lsp_ping_oam_lsp_read[2048];
/*
 * libevent callback for
 * lsp_ping_oam_lsp notifications socket receive
 */
static void
notify_lsp_ping_oam_lsp(int fd, short event, void *param)
{
	int len;

	fprintf(stderr, "%s: Entering\n", __func__);
	len = NgRecvData(fd, buf_lsp_ping_oam_lsp_read, sizeof(buf_lsp_ping_oam_lsp_read), NULL);
	/* check error conditions */
	if (len < 0) {
		fprintf(stderr, "NgRecvData: (oam_lsp) %s\n", strerror(errno));
		return;
	}

	fprintf(stderr, "%s: recv len = %d - incoming I/F = %s\n",
			__func__, len, buf_lsp_ping_oam_lsp_read);
}

static int
lsp_ping_oam_bfd_init(char *oam_name)
{
	int err;
	char name[NG_NODELEN + 1];

	snprintf(name, sizeof(name), "%s_bfd_%d", oam_name, getpid());
	err = NgMkSockNode(name, &vnb_oam_bfd_csock, &vnb_oam_bfd_dsock);
	if (err < 0) {
		fprintf(stderr, "unable to get a VNB socket(oam_bfd): %s\n",
		      strerror(errno));
		vnb_oam_bfd_csock = -1;
		vnb_oam_bfd_dsock = -1;
		return err;
	}
	event_set(&oam_bfd_dsock_evt, vnb_oam_bfd_dsock,
		  EV_READ | EV_PERSIST, (void *) notify_lsp_ping_oam_bfd, NULL);
	event_add(&oam_bfd_dsock_evt, NULL);
	return err;
}

/*
 * in the VNB graph, connect the lspping data hook from nodename
 * to the lsp_ping dsock data socket
 */
static int
lsp_ping_oam_bfd_connect(char *oam_name)
{
	struct ngm_connect ngc;
	int err = 0;

	/* be careful when sending the connect message, at this
	 * time the node may node exist */
	if (vnb_oam_bfd_csock == -1) {
		fprintf(stderr, "node %s does not exist\n",
		      oam_name);
		return -1;
	}

	snprintf(ngc.path, sizeof(ngc.path), "%s:", oam_name);
	snprintf(ngc.ourhook, sizeof(ngc.ourhook), "%s_bfd", oam_name);
	snprintf(ngc.peerhook, sizeof(ngc.peerhook), NG_MPLS_OAM_HOOK_UPPER_BFD);
	err = NgSendMsg(vnb_oam_bfd_csock, ".", NGM_GENERIC_COOKIE,
			NGM_CONNECT, &ngc, sizeof(ngc));
	if (err < 0) {
		fprintf(stderr, "unable to connect to node %s (err %d): %s(bfd)\n",
		      oam_name, err, strerror(errno));
		return -1;
	}

	return 0;
}

/* derived from vnb/tools/snoop/notify.c */
static u_int8_t buf_lsp_ping_oam_bfd_read[2048];
/*
 * libevent callback for
 * lsp_ping_oam_bfd notifications socket receive
 */
static void
notify_lsp_ping_oam_bfd(int fd, short event, void *param)
{
	int len;

	fprintf(stderr, "%s: Entering\n", __func__);
	len = NgRecvData(fd, buf_lsp_ping_oam_bfd_read, sizeof(buf_lsp_ping_oam_bfd_read), NULL);
	/* check error conditions */
	if (len < 0) {
		fprintf(stderr, "NgRecvData: (oam_bfd) %s\n", strerror(errno));
		return;
	}

	fprintf(stderr, "%s: recv len = %d - incoming I/F = %s\n",
			__func__, len, buf_lsp_ping_oam_bfd_read);
}

/* placeholder for prog termination actions */
static void
terminate(__attribute__ ((unused))int sock,
	  __attribute__ ((unused))short event,
	  __attribute__ ((unused))void *arg)
{
	fprintf(stderr, "exiting ...\n");
	exit(EXIT_SUCCESS);
}

static void
lsp_ping_usage(const char *cmd)
{
	(void) fprintf(stderr, "usage: %s", cmd);
	(void) fprintf(stderr, " [-a] [-E] [-h] [-b] [-S IP addr for original source] \n"\
		       "[-t TTL bs (default 255)] [-T TTL no bs (default 255)] \n"\
		       "[-x EXP bs (default 0)] [-X EXP no bs (default 0)] [-l TTL]\n"\
		       "[-r remote addr (default 10.10.10.1)] [-p UDP port]\n");

	exit(EX_USAGE);
}

int
main(int argc, char **argv)
{
	uint8_t *buf;
	uint8_t exp_bs = 0, exp_nobs = 0, ttl_bs = 255, ttl_nobs = 255, ip_ttl = 255;
	int ch, err;
	int ra_flag=0, ler_recv_flag=0;
	int bfd_flag = 0; /* BFD support instead of LSP Ping support */
	char * loc_addr = "10.22.1.2";
	/* Note: the destination address should be *random* from 127/8 */
	char * rem_addr = "10.10.10.1";
	struct in_addr loc_in_addr, rem_in_addr;
	struct sockaddr_ng sg;
	struct iphdr *ip;
	struct udphdr *udp;
	uint16_t udp_port = 0;
	char * mpls_nffec_name = "nffec_0";
	char * mpls_oam_name = "mpls_oam_0";
	struct meta_header *meta_hdr;
	mpls_oam_meta_t *lsp_meta;
	uint32_t *mark;
	struct event evt_sigterm, evt_sigint;

	const char *progname;

	progname = strrchr(argv[0], '/');
	if (!progname)
		progname = argv[0];
	else
		progname++;

	/* future option: -s(lsr, recv) */
	/* also get mpls_nffec_name from command line */
	while ((ch = getopt(argc, argv, "aEhbS:t:T:x:X:l:p:r:")) != -1) {
		switch (ch) {
		/* force Router Alert */
		case 'a':
			ra_flag=1;
			break;
		/* LER receive mode */
		case 'E':
			ler_recv_flag=1;
			break;
		/* Help message */
		case 'h':
			lsp_ping_usage(argv[0]);
			break;
		/* IP address for original source */
		case 'S':
			loc_addr = optarg;
			break;
		/* listen and generate BFD packets instead of LSP Ping*/
		case 'b':
			bfd_flag = 1;
			break;
		/* Force MPLS TTL BS */
		case 't':
			ttl_bs = atoi(optarg);
			break;
		/* Force MPLS TTL NO BS */
		case 'T':
			ttl_nobs = atoi(optarg);
			break;
		/* Force MPLS EXP BS */
		case 'x':
			exp_bs = atoi(optarg);
			break;
		/* Force MPLS EXP NO BS */
		case 'X':
			exp_nobs = atoi(optarg);
			break;
		/* Force IP TTL */
		case 'l':
			ip_ttl = atoi(optarg);
			break;
		/* Force IP destination */
		case 'r':
			rem_addr = optarg;
			break;
		/* Force UDP ports source and dest */
		case 'p':
			udp_port = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			lsp_ping_usage(progname);
		}
	}
	/* if (E_flag + s_flag) > 1 => usage */


	if (ler_recv_flag) {

		event_init();

		/* listen on socket for LSP : daemon mode */
		/* create VNB data socket */
		err = lsp_ping_oam_lsp_init(mpls_oam_name);
		/* connect to VNB graph */
		err = lsp_ping_oam_lsp_connect(mpls_oam_name);
		/* listen on socket for BFD : daemon mode */
		/* create VNB data socket */
		err = lsp_ping_oam_bfd_init(mpls_oam_name);
		/* connect to VNB graph */
		err = lsp_ping_oam_bfd_connect(mpls_oam_name);

		/* register signal handlers. */
		signal_set(&evt_sigterm, SIGTERM, terminate, (void *)SIGTERM);
		signal_add(&evt_sigterm, NULL);
		signal_set(&evt_sigint, SIGINT, terminate, (void *)SIGINT);
		signal_add(&evt_sigint, NULL);

		signal(SIGPIPE, SIG_IGN); /* may happen on admin sock */

		/* create reception event */
		event_dispatch(); /* infinite loop */

	} else {
		if (!udp_port) {
			if (bfd_flag)
				udp_port = BFD_PORT;
			else
				udp_port = LSP_PING_PORT;
		}

		fprintf(stderr, "Sending %s packets with:\n"\
			"IP src: %s, IP dst: %s, IP ttl: %d, UDP src: %d, UDP dst: %d\n"\
			"MPLS: RA %s, TTL bs: %d, TTL nobs: %d, EXP bs: %d, EXP nobs: %d\n",
			bfd_flag ? "BFD" : "LSP PING",
			loc_addr, rem_addr, ip_ttl, udp_port, udp_port,
			ra_flag ? "set" : "", ttl_bs, ttl_nobs, exp_bs, exp_nobs);

		buf = calloc(BUFLEN, sizeof(uint8_t));
		if (buf == NULL) {
			fprintf(stderr, "Malloc (buf).\n");
			exit(EXIT_FAILURE);
		}

		/* create VNB data socket */
		err = lsp_ping_nffec_init(mpls_nffec_name);
		/* connect to VNB graph */
		err = lsp_ping_nffec_connect(mpls_nffec_name);

		/* send LSP ping : client mode */
		/* create & prepare IP packet */
		memset((char *) &loc_in_addr, 0, sizeof(loc_in_addr));
		if (inet_aton(loc_addr, &loc_in_addr)==0) {
			fprintf(stderr, "inet_aton() failed\n");
			exit(EXIT_FAILURE);
		}
		memset((char *) &rem_in_addr, 0, sizeof(rem_in_addr));
		if (inet_aton(rem_addr, &rem_in_addr)==0) {
			fprintf(stderr, "inet_aton() failed\n");
			exit(EXIT_FAILURE);
		}

		/* Create IPv4 header */
		ip = (struct iphdr *)buf;
		ip->version = IPVERSION;
		/* the header size increases if the Router Alert Option is added */
		ip->ihl = 0x5; /* Size is 20 bytes */
		ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + DATALEN);
		ip->frag_off = 0; /* Don't fragment flag */
		ip->ttl = ip_ttl;
		ip->protocol = IPPROTO_UDP;
		ip->check = 0;
		ip->saddr = loc_in_addr.s_addr;
		ip->daddr = rem_in_addr.s_addr;
		/* compute IP checksum here */
		ip->check = in_cksum((u_short *)ip, ip->ihl*sizeof(uint32_t));
		/* create UDP header */
		udp = (struct udphdr *) ((u_int32_t *) ip + ip->ihl);
		udp->source = htons(udp_port);
		udp->dest =   htons(udp_port);

		udp->len =    htons(DATALEN);
		/* next, LSP payload (not done here) */

		/* add meta */
		memset(cmsgbuf, 0, sizeof(cmsgbuf)); /* ancillary data buffer */
		m.msg_control = (caddr_t)cmsgbuf;
		m.msg_controllen = CMSG_SPACE(sizeof(struct meta_header) +
					      sizeof(mpls_oam_meta_t));
		m.msg_controllen += CMSG_SPACE(sizeof(uint32_t));

		/* ancillary data for mpls_oam meta data */
		cm = CMSG_FIRSTHDR(&m);
		if (cm == NULL) {
			fprintf(stderr, "NULL cm\n");
			exit(EXIT_FAILURE);
		}
		cm->cmsg_len = CMSG_LEN(sizeof(struct meta_header) +
					sizeof(mpls_oam_meta_t));
		cm->cmsg_level = SOL_NETGRAPH;
		cm->cmsg_type = NG_OPT_METADATA;

		meta_hdr = (struct meta_header *)CMSG_DATA(cm);
		meta_hdr->len = sizeof(mpls_oam_meta_t);

		lsp_meta = (mpls_oam_meta_t *)meta_hdr->options;
		memset(lsp_meta, 0, sizeof(mpls_oam_meta_t));
		lsp_meta->hdr.cookie   = NGM_MPLS_OAM_COOKIE;
		lsp_meta->hdr.type     = NGM_MPLS_OAM_LSP_INFO;
		lsp_meta->hdr.len      = sizeof(mpls_oam_meta_t);
		lsp_meta->oam.exp      = (exp_bs & 0x7) << 4 | (exp_nobs & 0x7);
		lsp_meta->oam.ttl_bs   = ttl_bs;
		lsp_meta->oam.ttl_nobs = ttl_nobs;
		lsp_meta->oam.ra       = ra_flag;
		fprintf(stderr, "meta data: exp: %u, ttl_bs: %u, ttl_nobs: %u, ra: %u\n",
			lsp_meta->oam.exp, lsp_meta->oam.ttl_bs, lsp_meta->oam.ttl_nobs,
			lsp_meta->oam.ra);

		/* option to set the skb->mark */
		cm = CMSG_NXTHDR(&m, cm);
		if (cm == NULL) {
			fprintf(stderr, "NULL cm\n");
			exit(EXIT_FAILURE);
		}
		cm->cmsg_len = CMSG_LEN(sizeof(uint32_t));
		cm->cmsg_level = SOL_NETGRAPH;
		cm->cmsg_type = NG_OPT_MARK;

		mark = (uint32_t *)CMSG_DATA(cm);
		*mark = 31;
		fprintf(stderr, "skb->mark : %u\n", *mark);

		/* code derived from NgSendData with added ancillary data */
		sg.sg_family = AF_NETGRAPH;
		snprintf(sg.sg_data, NG_HOOKLEN + 1, "%s", mpls_nffec_name);
		sg.sg_len = strlen(sg.sg_data) + 3;

		m.msg_name = (caddr_t)&sg;
		m.msg_namelen = sizeof (struct sockaddr_ng);
		iov[0].iov_base = (caddr_t)buf;
		iov[0].iov_len = ntohs(ip->tot_len);
		m.msg_iov = iov;
		m.msg_iovlen = 1;

		if ((err = sendmsg (vnb_nffec_dsock, &m, 0)) < 0) {
			fprintf(stderr, "send data error for node %s:%s%d (%d - %s)\n",
					mpls_nffec_name, NG_NFFEC_HOOK_LOWER_IN_PREFIX, 0, err, strerror(errno));
			exit(EXIT_FAILURE);
		} else
			fprintf(stderr, "packet for %s is sent\n", mpls_nffec_name);

	}

	exit(EXIT_SUCCESS);
}
