/*
 * Copyright 6WIND 2011 All rights reserved.
 */

#include <sys/errno.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <paths.h>

#include <event.h>
#include <signal.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netlink/msg.h>
#include "netlink.h"

#include <hasupport.h>
struct has_ctx * fpmonitord_has = NULL;
static struct event evt_fpmonitor_fd;
static struct event evt_recv_fpmonit;

static struct timeval tm_fpmonitor;
static struct timeval tm_recv_fpmonit;
static struct event evt_fpmonitor;
static struct in_addr fpn0_src_addr;
static struct in_addr fp_dst_addr;
static int fpmonitor_fd;
static uint16_t nseq;
static int checkperiod;
static int fpn0_configured;

static struct event evt_sigterm;
static struct event evt_sigint;

static void icmp_format(void * buf, int buf_len);
static void fpmonitor_send(int fd, short event, void *data);
static int setup_fpn0();
static void init_fpn0();
static u_short in_cksum(uint16_t *addr, int len);

#define INADDR_DEF_FPN0	((in_addr_t) 0xa9fefe01) /* Inet 169.254.254.1 */
#define INADDR_DEF_FP	((in_addr_t) 0xa9fefe02) /* Inet 169.254.254.2 */
#define INADDR_DEF_MASK	((in_addr_t) 0xffffff00) /* Inet 255.255.255.0 */
#define ICMP_BUFLEN		64

/*
 * Format a "echo request" packet
 */
static void
icmp_format(void * buf, int buf_len)
{
 	struct iphdr* ip;
 	struct icmphdr* icmp;

	ip = (struct iphdr*) buf;
	icmp = (struct icmphdr*) (buf + sizeof(struct iphdr));

	memset(buf, 0, buf_len);
	/*
	 * fill the IP header
	 */
	ip->ihl      = 5;
	ip->version  = 4;
	ip->tos      = 0;
	ip->tot_len  = sizeof(struct iphdr) + sizeof(struct icmphdr);
	ip->id       = htons(random());
	ip->ttl      = 255;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr    = fpn0_src_addr.s_addr;
	ip->daddr    = fp_dst_addr.s_addr;

	/*
	* fill the ICMP header
	* (add ip checksum for both IP and ICMP)
	*/
	icmp->type             = ICMP_ECHO;
	icmp->code             = 0;
	icmp->un.echo.id       = 0;
	icmp->un.echo.sequence = htons(nseq);
	icmp->checksum         = 0;

	icmp->checksum         = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));
 	ip->check              = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

	nseq++;
	return;
}

/*
 * Send a "echo request" packet over fpn0
 */
static void
fpmonitor_send(int fd, short event, void *data)
{
	char buf[ICMP_BUFLEN];
	struct sockaddr_in dst_addr;
	socklen_t socklen = sizeof(dst_addr);

	syslog(LOG_DEBUG, "%s(): send echo request nseq : %d\n", __FUNCTION__, nseq);

	icmp_format((void *)buf, ICMP_BUFLEN);
	dst_addr.sin_addr.s_addr = fp_dst_addr.s_addr;
	dst_addr.sin_family = AF_INET;
	if (sendto(fpmonitor_fd, (void*)buf, ICMP_BUFLEN, 0,
	               (struct sockaddr *)&dst_addr, socklen) ==-1) {
		syslog(LOG_ERR, "Sendto Failure : %s\n",
			strerror(errno));
	}

	evtimer_add (&evt_fpmonitor, &tm_fpmonitor);
}

/*
 * Process a "echo reply" packet from fpn0
 */
static void
fpmonitor_recv(int fd, short event, void *data)
{
	char buf[ICMP_BUFLEN];
	int error;
 	struct iphdr* ip;
 	struct icmphdr* icmp;

	if ((error = recv(fd, (void *)buf, ICMP_BUFLEN, 0)) < 0) {
		if (errno != EINTR) {
			syslog(LOG_ERR, "recv : %s\n", strerror(errno));
			return;
		}
	}

	/*
	* parse the ICMP header
	*/
	ip = (struct iphdr*) buf;
	icmp = (struct icmphdr*) (buf + sizeof(struct iphdr));

	/*
	 * simple initial checks :
	 * only process ECHO REPLY from the FP
	 */
	if (icmp->type != ICMP_ECHOREPLY)
		return;
	if (ip->saddr != fp_dst_addr.s_addr)
		return;

	syslog(LOG_DEBUG, "%s(): receive echo reply from fp\n", __FUNCTION__);
	syslog(LOG_DEBUG, "src %08x dst %08x \n", htonl(ip->saddr), htonl(ip->daddr));

	/* reset "critical" timer */
	evtimer_del (&evt_recv_fpmonit);
	evtimer_add (&evt_recv_fpmonit, &tm_recv_fpmonit);
}

/*
 * Timeout on receive for a "echo request" packet over fpn0
 */
static void
fpmonitor_alarm(int fd, short event, void *data)
{
	syslog(LOG_DEBUG, "%s(): timeout\n", __FUNCTION__);

	/* set critical state for the daemon */
	if (fpmonitord_has != NULL)
#ifdef NOTYET
		/* NB : we cannot (yet) restart the fastpath */
		has_critical_state (fpmonitord_has);
#else
		fpmonitord_has->healthState = HA6W_HEALTH_DEGRADED;
#endif
}

/*
 * Setup fpn0
 * get initial IP address (if already set)
 * if set => compute dest address : X.Y.Z.2
 * if none => set 169.254.254.1/24 compute dest address : 169.254.254.2
 * create raw socket (ping v4) => fpmonitor_fd
 */
static int
setup_fpn0()
{
	int fd, ret;
	struct ifreq ifr;
	char * interface = "fpn0";
	in_addr_t fpn0_in_addr, fp_in_addr;
	int optval;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* get an IPv4 address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* for fpn0 interface */
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

	ret = ioctl(fd, SIOCGIFADDR, &ifr);

	if (ret < 0) {
		syslog(LOG_DEBUG, "No IP address on '%s'\n", interface);

		/* Set IPv4 address */
		ifr.ifr_addr.sa_family = AF_INET;
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr =
			 htonl(INADDR_DEF_FPN0);
		ret = ioctl(fd, SIOCSIFADDR, &ifr);

		if (ret < 0) {
			syslog(LOG_ERR, "Could not set IP address on '%s' : %s\n",
			            interface, strerror(errno));
			close(fd);
			return (-1);
		}

		/* Set IPv4 netmask */
		ifr.ifr_netmask.sa_family = AF_INET;
		((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr =
			htonl(INADDR_DEF_MASK);
		ret = ioctl(fd, SIOCSIFNETMASK, &ifr);

		if (ret < 0) {
			syslog(LOG_ERR, "Could not set IP netmask on '%s' : %s\n",
			            interface, strerror(errno));
			close(fd);
			return (-1);
		}

		/* Store Src and Dst IPv4 addresses */
		fpn0_src_addr.s_addr = htonl(INADDR_DEF_FPN0);
		fp_dst_addr.s_addr = htonl(INADDR_DEF_FP);
	} else {
		syslog(LOG_DEBUG, "IP address already set on '%s' : %s\n", interface,
		             inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

		fpn0_in_addr = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
		/* derive new IP addr from existing fpn0 addr */
		fp_in_addr = (fpn0_in_addr & INADDR_DEF_MASK) | 0x02;
		/* check new IP addr */
		if (fpn0_in_addr == fp_in_addr) {
			syslog(LOG_ERR, "Bad existing IP addr on '%s'\n", interface);
			close(fd);
			return (-1);
		}
		/* Store Src and Dst IPv4 addresses */
		fpn0_src_addr.s_addr = htonl(fpn0_in_addr);
		fp_dst_addr.s_addr = htonl(fp_in_addr);
	}

	/* display result */
	syslog(LOG_DEBUG, "IP addr for %s is %s\n", interface,
		inet_ntoa(fpn0_src_addr));
	syslog(LOG_DEBUG, "IP addr for FP is %s\n",
		inet_ntoa(fp_dst_addr));

	close(fd);

	fpmonitor_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fpmonitor_fd < 0) {
		syslog(LOG_ERR, "Error : cannot create RAW socket : %s\n",
			strerror(errno));
		close(fd);
		return -1;
	}
	setsockopt(fpmonitor_fd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));
	return (0);
}

/*
 * Callback function used to finalize fpn0 configuration
 * after fpn0 has been detected via netlink.
 */
static void
init_fpn0()
{
	int ret;

	syslog(LOG_DEBUG, "%s: entering\n", __FUNCTION__);

	/* check multiple calls */
	if (fpn0_configured != 0)
		return;
	fpn0_configured = 1;

	nseq = random();

	/*
	 * Setup fpn0 interface after it has been created.
	 */
	ret = setup_fpn0();
	if (ret < 0) {
		syslog(LOG_ERR, "%s(): could not setup fpn0\n", __FUNCTION__);
		exit(EXIT_FAILURE);
	}

	/*
	 * Event to handle ping_fd socket
	 */
	event_set(&evt_fpmonitor_fd, fpmonitor_fd, EV_READ | EV_PERSIST, fpmonitor_recv, 0);
	if (event_add(&evt_fpmonitor_fd, NULL)) {
		syslog(LOG_ERR, "%s(): ping_fd socket", __FUNCTION__);
		exit(EXIT_FAILURE);
	}

	/*
	 * FPmonitor check
	 */
	tm_fpmonitor.tv_sec  = checkperiod;
	tm_fpmonitor.tv_usec = 0;
	evtimer_set (&evt_fpmonitor, fpmonitor_send, NULL);
	if (evtimer_add (&evt_fpmonitor, &tm_fpmonitor)) {
		syslog(LOG_ERR, "%s(): evt_fpmonitor", __FUNCTION__);
		exit(EXIT_FAILURE);
	}

	tm_recv_fpmonit.tv_sec  = 3*checkperiod;
	tm_recv_fpmonit.tv_usec = 0;
	evtimer_set (&evt_recv_fpmonit, fpmonitor_alarm, NULL);
	if (evtimer_add (&evt_recv_fpmonit, &tm_recv_fpmonit)) {
		syslog(LOG_ERR, "%s(): evt_recv_fpmonit", __FUNCTION__);
		exit(EXIT_FAILURE);
	}
}

/*
 * in_cksum -- (derived from FreeBSD ping.c)
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
static u_short
in_cksum(uint16_t *addr, int len)
{
	int nleft, sum;
	uint16_t *w;
	union {
		uint16_t	us;
		u_char	uc[2];
	} last;
	uint16_t answer;

	nleft = len;
	sum = 0;
	w = addr;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		last.uc[0] = *(u_char *)w;
		last.uc[1] = 0;
		sum += last.us;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

static void 
terminate(__attribute__ ((unused))int sock,
	  __attribute__ ((unused))short event,
	  __attribute__ ((unused))void *arg)
{
	syslog(LOG_ERR, "terminating ...\n");
	fpmonitord_netlink_close();
	exit(EXIT_SUCCESS);
}

/*
 * Usage
 */
static void
fpmonitord_usage(const char *path)
{
	const char *cmd;

	cmd = strrchr(path, '/');
	if (!cmd)
		cmd = path;
	else
		cmd++;
	fprintf(stderr, "%s [-tZ]\n", cmd);
	fprintf(stderr, "%s",
	   	 "            -t (time)   seconds between polling\n"
	   	 "            -Z (name)   server socket\n\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int fd;
	int ch;
	char *has_srvname = NULL;
	int rc;
	struct event has_event;

	checkperiod = 1;
	fpn0_configured = 0;

#define NL_SOCKET_BUFSIZE 8*BUFSIZ
	nlmsg_set_default_size(NL_SOCKET_BUFSIZE);

	/* get options */
	while ((ch = getopt(argc, argv, "t:Z:")) != -1) {
		switch (ch) {

		case 't':
			checkperiod = strtol(optarg, NULL, 0);
			if (checkperiod <= 0) {
				fprintf(stderr, "Invalid -t parameter, should be > 0!");
				fpmonitord_usage(argv[0]);
			}
			break;
			/* High Availability srvname */
		case 'Z':
			has_srvname = optarg;
			break;

		default:
			fprintf(stderr, "Unknown option.\n");
			fpmonitord_usage(argv[0]);
		}
	}

	/* Open syslog */
	openlog("fpmonitord", LOG_NDELAY|LOG_PID, LOG_DAEMON);

	/* event init */
	event_init();

	/* revoke stdin/stdout/stderr */
	if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			(void)close (fd);
	}

	/* daemonize */
	if (daemon(1, 1) < 0) {
		fprintf(stderr, "%s error: %s\n", argv[0], strerror(errno));
		exit(EXIT_FAILURE);
	}
	/* Init high availability support */
	rc = has_init(HA6W_COMP_FPMONITORD, &fpmonitord_has, has_srvname,
		      argc,argv, 0, NULL);
	if (rc == HA6W_RESULT_ERROR) {
		syslog(LOG_ERR, "%s(): Can not initialize High Availability"
		      " support\n", __FUNCTION__);
	} else {
		event_set (&has_event, fpmonitord_has->sock, EV_READ | EV_PERSIST, 
			   has_handler_event, fpmonitord_has);
		if (event_add (&has_event, NULL)) {
			syslog(LOG_INFO, "%s(): HA-event error\n", __FUNCTION__);
			has_exit(fpmonitord_has);
		}
		syslog(LOG_INFO, "%s(): HA support event_add has_event\n",
		      __FUNCTION__);
	}


	/* Netlink : used to check for fpn0 */
	if (fpmonitord_netlink_init(&init_fpn0) < 0) {
		syslog(LOG_ERR, "%s could not init netlink\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	/* initial analysis of existing net connections */
	if (fpmonitord_netlink_dump() < 0) {
		syslog(LOG_ERR, "%s could not dump netlink\n", argv[0]);
		exit(EXIT_FAILURE);
	}


	/* register signal handlers. */
	signal_set(&evt_sigterm, SIGTERM, terminate, (void *)SIGTERM);
	signal_add(&evt_sigterm, NULL);
	signal_set(&evt_sigint, SIGINT, terminate, (void *)SIGINT);
	signal_add(&evt_sigint, NULL);

	signal(SIGPIPE, SIG_IGN); /* may happen on admin sock */

	/* libevent infinite loop */
	event_dispatch();
	perror("dispatch");

	closelog();
	exit(EXIT_SUCCESS);
}
