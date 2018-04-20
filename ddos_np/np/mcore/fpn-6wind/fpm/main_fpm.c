/*
 * Copyright (c) 2004, 2006 6WIND
 */

/*
 * Unix server for CM.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> 
#include <fcntl.h>
#include <stdarg.h>
#include <event.h>
#include <stdio.h>
#include <syslog.h>
#include <err.h>
#include <arpa/inet.h>

#include <glob.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/ethernet.h>	
#include <net/if.h>	/* IFNAMSIZ */
#include <netinet/tcp.h>
#include <netinet/fp-in.h>	/* in_addr, in6_addr */
#include <sys/un.h>	/* in_addr, in6_addr */
#include <getopt.h>

#include "fpm_plugin.h"
#include "fpm_common.h"
#include "sockmisc.h"
#include "fpm-netlink.h"

#include "fp.h"
#include "fpn-port.h"
#include "libfp_shm.h"

#define FPM_PLUGIN_DEF_PATTERN "/usr/local/lib/fpm/*.so"
#define FPM_PLUGIN_ENV_PATTERN "FPM_PLUGINS"

#define ACK_SIZE_LIMIT 64
#define ACK_TRIGGER_AUTO 256

shared_mem_t *fp_shared;
port_mem_t *fpn_port_shmem;

#define FPC_API_MAJOR  14
#define FPC_API_MINOR  0

#ifdef HA_SUPPORT
#include <6whasapi.h>
#include <hasupport.h>
struct has_ctx * myhas = NULL;
struct event has_event;
#endif

struct event_base *fpm_event_base;

#define FPM_DEFAULT_RECVSOCKBUFSIZ   524288
u_int32_t fpm_recvsockbufsiz = FPM_DEFAULT_RECVSOCKBUFSIZ;
#define FPM_DEFAULT_SOCKBUFSIZ	131070
int fpm_sockbufsiz = FPM_DEFAULT_SOCKBUFSIZ;

int fpm_graceful_restart = 1;
u_int32_t fpm_graceful_restart_in_progress = 0;
struct event event_graceful_restart;

int f_verbose = 0;

int s_nfpc = -1;
int fpm_wipe_vnb_nodes = 0;

uint32_t fpm_fpib_ifuid = 0;
int fpm_auto_threshold = 1;

int f_coloc_1cp1fp = 1;
int f_colocalized = 1;

struct in_addr peer_addr;

/* table to store mapping of interface name and port number */
static char filename_mapping[256];
static char *file_mapping;
typedef struct fpm_if_table {
	uint32_t count;
	uint8_t ready;
	struct table {
		char ifname[80];
		uint32_t port;
	} table[64];
} fpm_if_table_t;

static fpm_if_table_t interface_mapping;

/*
 * Default file names, acces names ...
 */
static char  pidfilename[256] = "/var/run/fpm.pid";
static char *progname;

#ifndef CM_VERSION
#define CM_VERSION "Unknown"
#endif

static int               sock_conn;
static struct event      event_conn;

/*
 * UNIX socket server variables
 */
static char             *srv_path = DEFAULT_CM_PATH;

static int wait_sec = 0;
static u_int8_t *__fpm_recv_buf;

static int sock_cli = -1;
static struct event      event_recv;
static struct event      event_sigterm;

struct fpm_mod_list fpm_mod_list = STAILQ_HEAD_INITIALIZER(fpm_mod_list);

static void
show_usage (int retval)
{
	int indent = strlen(progname);

	fprintf (stderr,
		 "usage:\n"
		 "%s [-FhlTvvW] [-p pidfile]\n"
		"%*s [-f port_map] [ -g vnb_ifname ]\n"
		"%*s [-w wait_seconds]\n"
		"%*s [[-s sockname] [-t tcpaddr:port [-r remoteaddr]]] [-b sockbufsiz]\n"
		"%*s [--spd-hash-min-preflen|-x local:remote]\n"
		"%*s [--spd6-hash-min-preflen|-X local:remote]\n",
		progname, indent, "", indent, "", indent, "", indent, "", indent, "");
	fprintf (stderr,
		"%*s [-B blade_id ] [-P CPportname] [-M CPportmac]\n",
		indent, "");
	fprintf (stderr, "    -f interface name-to-port mapping file\n");
	fprintf (stderr, "    -t CM/FPM tcp socket: address and port to listen to\n");
	fprintf (stderr, "       examples: 1.2.3.4:1234 fe80::1%%eth1:1234 3ffe::1:1234\n");
	fprintf (stderr, "                 0.0.0.0:1234 :::1234\n");
	fprintf (stderr, "    -r for tcp socket: authorized remote address (A.B.C.D)\n");
	fprintf (stderr, "    -g vnb_ifname (name of interface used for VNB configuration messages\n");
	fprintf (stderr, "    -B blade_id (1 to %d)\n", FP_BLADEID_MAX);
	fprintf (stderr, "    -P CPportname name of port used to communicate with Control Plane\n");
#ifdef CONFIG_MCORE_1CP_XFP
	fprintf (stderr, "    -C blade_id of CP (1 to %d)\n", FP_BLADEID_MAX);
#endif
	fprintf (stderr, "    -M CPportmac mac address of Control Plane\n");
	fprintf (stderr, "    -T disable automatic calculation of FPTUN size warning thresholds\n");
	fprintf(stderr, "     -x\n");
	fprintf(stderr, "     --spd-hash-min-preflen IPv4 SPD hash lookup minimum prefix lengths (0-32)\n");
	fprintf(stderr, "     -X\n");
	fprintf(stderr, "     --spd6-hash-min-preflen IPv6 SPD hash lookup minimum prefix lengths (0-128)\n");
	fprintf (stderr, "    -l to disable graceful restart\n");

	exit(retval);
}

#ifndef MIN
#define MIN(a,b) ((b) > (a) ? (a) : (b))
#endif

/*
 * Parse a string in the format local:remote
 * where local and remote are prefix lengths
 *
 * if local or remote is greater than max, then it is set to max
 * string: input string
 * local:  pointer on local prefix length
 * remote: pointer on remote prefix length
 * max:    maximum prefix length
 *
 * Return value:
 *    0: OK
 *   -1: bad format
 */
static int
fpm_parse_spd_hash_preflen(
		const char *string,
		uint8_t *local,
		uint8_t *remote,
		uint8_t max)
{
	unsigned long word1, word2;
	char *end;

	word1 = strtoul(string, &end, 0);
	if (*end != ':')
		return 1;

	word2 = strtoul(end+1, &end, 0);
	if (*end != 0)
		return 1;

	*local = (uint8_t)MIN(word1, max);
	*remote = (uint8_t)MIN(word2, max);

	return 0;
}

static void
fpm_get (int fd, short event, void *data)
{
	static u_int8_t *__fpm_recv_largebuf = NULL;
	static u_int32_t expected_len = 0;
	static u_int32_t offset = 0;
	struct cp_hdr *hdr;
	u_int8_t *req;
	int       lg;

	if (wait_sec) {
		if (f_verbose)
			syslog(LOG_INFO, "waiting %d seconds before reading socket\n", wait_sec);
		sleep(wait_sec);
	}

	if (__fpm_recv_largebuf)
		lg = recv(fd, __fpm_recv_largebuf + offset, expected_len - offset, 0);
	else
		lg = recv(fd, __fpm_recv_buf + offset, fpm_recvsockbufsiz - offset, 0);
	if (lg <= 0) {
		syslog(LOG_NOTICE, "Connection with Cache Manager is lost\n");
		event_del (&event_recv);
		sock_cli = -1;
		offset = 0;
		if (__fpm_recv_largebuf) {
			free(__fpm_recv_largebuf);
			__fpm_recv_largebuf = NULL;
		}
		return;
	}

	lg += offset;
	offset = 0;
	while (lg) {
		if (__fpm_recv_largebuf)
			hdr = (struct cp_hdr *)(__fpm_recv_largebuf);
		else
			hdr = (struct cp_hdr *)(__fpm_recv_buf + offset);
		if (lg >= (int)sizeof(struct cp_hdr))
			expected_len = ntohl(hdr->cphdr_length) + sizeof(struct cp_hdr);
		if (lg < (int)sizeof(struct cp_hdr) ||
		    lg < (int)expected_len) {
			if (lg >= (int)sizeof(struct cp_hdr) &&
			    expected_len > fpm_recvsockbufsiz &&
			    __fpm_recv_largebuf == NULL) {
				__fpm_recv_largebuf = (u_int8_t *)malloc(expected_len);
				memcpy(__fpm_recv_largebuf, __fpm_recv_buf + offset, lg);
				offset = lg;
				return;
			}
			goto out;
		}

		req = (u_int8_t *)(hdr + 1);

		if (fpm_dispatch(hdr, req) != EXIT_SUCCESS) {
			syslog(LOG_ERR, "Failed to process command 0x%x with cookie %u\n",
				ntohl(hdr->cphdr_type), ntohl(hdr->cphdr_cookie));
		}

		if (ntohl(hdr->cphdr_type) == CMD_RESET) {
			struct cp_reset *rst;

			rst = (struct cp_reset *)(hdr + 1);
			if (ntohs(rst->cp_reset_major) != FPC_API_MAJOR) {
				syslog(LOG_CRIT, "***  FPC API major release mismatch ***\n");
				syslog(LOG_CRIT, "***    Real FPM should STOP here    ***\n");
				syslog(LOG_CRIT, "***      recv(%d) != expected(%d)   ***\n",
				       ntohs(rst->cp_reset_major), FPC_API_MAJOR);
			}
			if (ntohs(rst->cp_reset_minor) != FPC_API_MINOR) {
				syslog(LOG_CRIT, "---  FPC API minor release mismatch ---\n");
				syslog(LOG_CRIT, "---      recv(%d) != expected(%d)   ---\n",
				       ntohs(rst->cp_reset_major), FPC_API_MINOR);
			}
		}

		if (__fpm_recv_largebuf) {
			free(__fpm_recv_largebuf);
			__fpm_recv_largebuf = NULL;
			offset = 0;
			return;
		}

		offset += expected_len;
		lg -= expected_len;
	}

out:
	if (lg && offset)
		memmove(__fpm_recv_buf, __fpm_recv_buf + offset, lg);
	offset = lg;
}

static void
exit_cb(int fd, short what, void *arg)
{
	syslog(LOG_NOTICE, "Caught SIGTERM, exiting fpmd\n");
	exit(0);
}

static void
fpm_accept (int fd, short event, void *data)
{
	struct sockaddr_in   remote;
	socklen_t            remote_len = sizeof(remote);
	int                  sock;
	struct sockaddr      *sa;

	if ((sock = accept (fd, (struct sockaddr *)&remote, &remote_len)) < 0) {
		syslog(LOG_NOTICE, "accept: %s\n", strerror(errno));
		return;
	}

	sa = (struct sockaddr *)&remote;

	if ((sa->sa_family == AF_INET) || (sa->sa_family == AF_INET6)) {
		char buf[INET_ADDRSTRLEN];

		inet_ntop(sa->sa_family, (const void*)&remote.sin_addr,
			  buf, remote_len);

		if (f_verbose)
			syslog(LOG_INFO, "CM connects from %s:%u", buf,
			       htons(remote.sin_port));

		/* connections are filtered if needed */
		if ((peer_addr.s_addr != 0) &&
		    (peer_addr.s_addr != remote.sin_addr.s_addr)) {
			if (f_verbose)
				syslog(LOG_INFO, "connection refused: bad peer address");
			close(sock);
			return;
		}
	} else
		if (f_verbose)
			syslog(LOG_INFO, "CM connects\n");

	setsock(sock, O_NONBLOCK, fpm_sockbufsiz, "CMstub client");

	/*
	 * If we 'ever' want to have several FPM, this would
	 * need some work here, with dyn alloc, linked list ...
	 */
	/*fpm = &FPM_CTX;*/

	/*
	 * context completion init
	 */
	if (sock_cli >= 0) {
		syslog(LOG_NOTICE, "New connection established, replace connection\n");
		event_del(&event_recv);
		close(sock_cli);
	}
	sock_cli = sock;

	/* Graceful restart only - go to graceful restart mode for FPM_GRACETIME seconds */
	if (fpm_graceful_restart) {
		struct timeval tv;

		if (fpm_graceful_restart_in_progress) {
			evtimer_del(&event_graceful_restart);
			fpm_graceful_timer_abort();
		}

		if (s_nfpc >= 0)
			netfpc_send(s_nfpc, NULL, 0, 0, NETFPC_MSGTYPE_GR_START);

		tv.tv_sec = FPM_GRACETIME;
		tv.tv_usec = 0;

		/* graceful restart for all protocols */
		fpm_graceful_restart_in_progress = CM_GR_TYPE_ALL;

		fpm_shared_mem_to_cmd(CM_GR_TYPE_ALL);

		evtimer_set(&event_graceful_restart, fpm_graceful_timer_end, NULL);
		evtimer_add(&event_graceful_restart, &tv);
	}

	/*
	 * Now we DO have a registered Client, it is time
	 * to set up events for this sock :
	 *  - receive event 
	 *  - send event, so that no sending will ever be blocking
	 */
	event_set (&event_recv, sock_cli,
			EV_READ | EV_PERSIST,
			fpm_get, /*fpm*/NULL);
	if (event_add (&event_recv, NULL))
		perror("event_add event_recv");

	return;
}

void fpm_restart (void) {
	/* Prevent endless loop: if we are already in complete GR process, */
	/* just issue a warning */
	if (fpm_graceful_restart_in_progress == CM_GR_TYPE_ALL) {
		syslog(LOG_ERR, "Cannot restart fastpath, graceful restart in progress\n");
		return;
	}

	/* force graceful restart mode */
	fpm_graceful_restart = 1;

	/* And close connection with cache manager, this will trigger a new gr phase */
	if (sock_cli >= 0) {
		syslog(LOG_WARNING, "Close uplink connection\n");
		event_del(&event_recv);
		close(sock_cli);
		sock_cli = -1;
	}
}

/* time between keepalives (secs) */
#define	FPM_KEEPALIVE_INTERVAL	1

/* time before sending the first keepalive (secs) */
#define	FPM_KEEP_IDLE		1

/* the number of NACK before considering the connection dead */
#define	FPM_KEEP_CNT		5
 
/*
 * FPM server socket connection
 */
static int fpm_socket(struct sockaddr *sa)
{
	int fd;
	int on;
	int val;
	struct linger linger;

	fd = newsock(sa->sa_family, SOCK_STREAM, 0, 0, fpm_sockbufsiz,
			"FPM connection");
	if (fd < 0) {
		perror("cannot open socket");
		return -1;
	}

	/* set reuse addr option, to avoid bind error when re-starting */
	on = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		perror("setsockopt SO_REUSEADDR");
		goto error;
	}

	if ((sa->sa_family == AF_INET) || (sa->sa_family == AF_INET6)) {
		/* immediately send a TCP RST when closing socket */
		linger.l_onoff  = 1;
		linger.l_linger = 0;

		if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0) {
			perror("setsockopt SO_LINGER");
			goto error;
		}

		/* Enable tcp keepalive */
		on = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {
			syslog(LOG_ERR, "Cannot set keepalive tcp option: %s\n",
			       strerror(errno));
			goto error;
		}

		/* the interval between the last data packet sent
		 * (simple ACKs are not considered data) and the first
		 * keepalive probe; after the connection is marked to
		 * need keepalive, this counter is not used any
		 * further  */
		val = FPM_KEEP_IDLE;
		if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0) {
			syslog(LOG_ERR, "Cannot set TCP_KEEPIDLE option: %s\n",
			       strerror(errno));
			goto error;
		}

		/* the interval between subsequential keepalive
		 * probes, regardless of what the connection has
		 * exchanged in the meantime  */
		val = FPM_KEEPALIVE_INTERVAL;
		if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0) {
			syslog(LOG_ERR, "Cannot set TCP_KEEPINTVL: %s\n",
			       strerror(errno));
			goto error;
		}

		/* the number of unacknowledged probes to send before
		 * considering the connection dead and notifying the
		 * application layer  */
		val = FPM_KEEP_CNT;
		if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0) {
			syslog(LOG_ERR, "Cannot set TCP_KEEPCNT option: %s\n",
			       strerror(errno));
			goto error;
		}
	}

	if (bind(fd, sa, sockaddr_len(sa)) < 0) {
		perror("cannot bind socket");
		goto error;
	}

	if (listen (fd, 1)) {
		perror("listen");
		goto error;
	}

	event_set (&event_conn, fd,
			EV_READ | EV_PERSIST,
			fpm_accept, NULL);
	event_add (&event_conn, NULL);

	sock_conn = fd;

	return 0;

error:
	close(fd);

	return -1;
}

static int mapping_init(char *mapping)
{
	char buf[256];
	FILE *fp;
	uint32_t count;

	memset(&interface_mapping, 0, sizeof(interface_mapping));

	if (mapping == NULL)
		return -1;

	fp = fopen(mapping, "r");

	if (!fp) {
		syslog(LOG_ERR, "Unable to open %s\n", mapping);
		return -1;
	}

	/* mark the table ready to use, user may require an empty mapping */
	interface_mapping.ready = 1;
	count = 0;
	while (fgets(buf, sizeof(buf), fp)) {
		char text[80];
		uint32_t value;
#if defined(CONFIG_MCORE_FPVI_TAP)
		uint32_t idx_value;
		char * ret_p;
#endif

		memset(text, 0, sizeof(text));
		value = 0;
#if defined(CONFIG_MCORE_FPVI_TAP)
		sscanf(buf, "%d%d", &idx_value, &value);
		ret_p = if_indextoname(idx_value, text);
		if (ret_p == NULL) {
			syslog(LOG_ERR, "No valid if name for idx %d\n", idx_value);
			return -1;
		}
#else
		sscanf(buf, "%s%d", text, &value);
#endif
		strncpy(interface_mapping.table[count].ifname, text, 80);
		interface_mapping.table[count].port = value;
		count++;
	}
	fclose(fp);

	interface_mapping.count = count;
	if (f_verbose) {
		syslog(LOG_DEBUG, "%d interfaces:\n", interface_mapping.count);
		for (count = 0; count < interface_mapping.count; count++)
			syslog(LOG_DEBUG, "\t%s - port %d\n",
			       interface_mapping.table[count].ifname,
			       interface_mapping.table[count].port);
	}

	return 0;
}

/* 
 * return -1 if file has not been read
 * otherwise return 0 and set found port or -1 in port.
 */
int fpm_ifname2port_from_file(const char *ifname, int *port)
{
	uint32_t count;

	*port = -1;
	if (interface_mapping.ready == 0)
		return -1;

	for (count = 0; count < interface_mapping.count; count++)
		if (!strncmp(ifname, interface_mapping.table[count].ifname, 
				strlen(interface_mapping.table[count].ifname) + 1)) {
			*port = (int)interface_mapping.table[count].port;
			break;
		}
	return 0;
}

int ll_addr_a2n(uint8_t *lladdr, int len, const char *arg0)
{
	int i;
	int ret = -1;
	char *arg; /* copy of xx:xx:xx:xx:xx:xx string */
	char *cp;  /* pointer on current byte */
	char *cn;  /* pointer on next byte */

	arg = strdup(arg0);

	if (arg == NULL)
		return -1;

	cp = arg;

	for (i=0; i<len; i++) {
		int temp;
		cn = strchr(cp, ':');
		if (cn)
			*cn++ = 0;
		if (sscanf(cp, "%x", &temp) != 1) {
			syslog(LOG_ERR, "\"%s\" is invalid lladdr.\n", arg);
			goto end;
		}
		if (temp < 0 || temp > 255) {
			syslog(LOG_ERR, "\"%s\" is invalid lladdr.\n", arg);
			goto end;
		}
		lladdr[i] = (uint8_t)temp;
		if (!cn)
			break;
		cp = cn;
	}

	ret = i+1;

end:
	free(arg);
	return ret;
}

#ifdef HA_SUPPORT
void fpm_ha_check_request(void)
{
	static unsigned int i = 0;

	/* do it every 16th call */
	if (((i++) & 0xf) == 0)
		has_check_request(myhas);
}
#endif

struct fpm_mod_entry *fpm_mod_find(char *name)
{
	struct fpm_mod_entry *entry;

	STAILQ_FOREACH(entry, &fpm_mod_list, next) {
		if (!strcmp(entry->mod->name, name))
			break;
	}

	return entry;
}

int fpm_mod_register(struct fpm_mod *mod)
{
	struct fpm_mod_entry *entry = NULL;

	if (!mod || !mod->name) {
		syslog(LOG_ERR, "fpm_mod_register: wrong argument\n");
		return -1;
	}

	if (fpm_mod_find(mod->name)) {
		syslog(LOG_ERR, "%s module already registered\n", mod->name);
		return -1;
	}

	entry = malloc(sizeof(*entry));
	if (!entry) {
		syslog(LOG_ERR, "could not allocate %s module\n", mod->name);
		return -1;
	}

	entry->mod = mod;
	STAILQ_INSERT_TAIL(&fpm_mod_list, entry, next);

	syslog(LOG_INFO, "%s module registered\n", mod->name);
	return 0;
}

/*
 * Load all .so files that match the plugin pattern.
 * Pattern can be overriden by the FPM_PLUGINS environment variable.
 */
static void
load_plugins(void)
{
	char *pattern;
	glob_t gl;
	unsigned int i;

	for (i=0; i<FP_MAX_PLUGINS; i++)
		memset(fp_shared->fpmplugins[i], 0, FP_PLUGINSNAME_MAXLEN);

	/* Set plugin location */
	if (!(pattern = getenv(FPM_PLUGIN_ENV_PATTERN)))
		pattern = FPM_PLUGIN_DEF_PATTERN;

	/* Load plugins */
	if (!glob(pattern, 0, NULL, &gl)) {

		for (i = 0; i < gl.gl_pathc; i++) {
			if (!dlopen(gl.gl_pathv[i], RTLD_NOW|RTLD_GLOBAL))
				fprintf(stderr, "cannot load %s: %s\n",
				        gl.gl_pathv[i], dlerror());

			if (i<FP_MAX_PLUGINS)
				memcpy(fp_shared->fpmplugins[i], gl.gl_pathv[i],
				       FP_PLUGINSNAME_MAXLEN - 1);
			else
				syslog(LOG_WARNING,
				       "%s plugin not stored for fpcmd show-loaded-plugins\n",
				       gl.gl_pathv[i]);
		}
		globfree(&gl);
	}
}

static int
fpm_reset(const uint8_t *request, const struct cp_hdr *hdr)
{
	// fp_init() - not tested.
	return 0;
}

char *vnb_name = NULL;

uint8_t spd_hash_loc_plen = 0;
uint8_t spd_hash_rem_plen = 0;
uint8_t spd6_hash_loc_plen = 0;
uint8_t spd6_hash_rem_plen = 0;

int
main(int ac, char *av[])
{
	int ch;
	int f_foreground = 0;
	struct sockaddr_generic srv_sockaddr_storage;
	typedef union {
		struct sockaddr s;
		struct sockaddr_generic sgen;
	} sockaddr_union_t;
	struct sockaddr *srv_sockaddr =
		&(((sockaddr_union_t*)&srv_sockaddr_storage)->s);
	int srv_family = AF_UNIX;
	uint8_t fpm_blade_id = 1;
	char   *fpm_cp_portname = NULL;
	uint8_t fpm_cp_portmac[6] = { 0,0,0,0,0,0 };
	uint8_t cp_blade_id = 0; /* Initialize it just to avoid a warning */
	int cp_blade_id_is_set = 0;
#ifdef HA_SUPPORT
	int rc;
	struct event has_event;
	char *has_srvname = NULL;
#endif

	int opt_idx = -1;
	const struct option long_options[] = {
		/* --spd-hash-min-preflen LOCAL:REMOTE */
		{"spd-hash-min-preflen", 1, NULL, 'x'},
		/* --spd6-hash-min-preflen LOCAL:REMOTE */
		{"spd6-hash-min-preflen", 1, NULL, 'X'},
		/* --help */
		{"help", 0, NULL, 'h'},
		{0, 0, 0, 0}
	};
	const char optstring[] = "b:B:C:f:FM:g:hlp:P:r:s:t:Tvw:Wx:X:Z:";

	progname = strrchr(av[0], '/');
	if (progname)
		progname++;
	else
		progname = av[0];

	memset(&peer_addr, 0, sizeof(peer_addr));

	/*
	 * set stdout and stderr line buffered, so that user can read messages
	 * as soon as line is complete
	 */

	/* With FPVI TAP, default is to try /tmp/fpmapping */
#ifdef CONFIG_MCORE_FPVI_TAP
	file_mapping = "/tmp/fpmapping";
#else
	file_mapping = NULL;
#endif
	while ((ch = getopt_long(ac, av , optstring, long_options, &opt_idx)) != EOF) {
		switch(ch) {
			case 'b':
				fpm_sockbufsiz = strtol(optarg, NULL, 0);
				break;
			case 'B':
				f_coloc_1cp1fp = 0;
				fpm_blade_id = (uint8_t)strtoul(optarg, NULL, 0);
				if ((fpm_blade_id == 0) || (fpm_blade_id > FP_BLADEID_MAX)) {
					fprintf(stderr, "blade_id out of range (1-%d)\n",
							FP_BLADEID_MAX);
					show_usage(1);
				}
				break;
#ifdef CONFIG_MCORE_1CP_XFP
			case 'C':
				cp_blade_id = (uint8_t)strtoul(optarg, NULL, 0);
				if ((cp_blade_id == 0) || (cp_blade_id > FP_BLADEID_MAX)) {
					fprintf(stderr, "cp_blade_id out of range (1-%d)\n",
							FP_BLADEID_MAX);
					show_usage(1);
				}
				cp_blade_id_is_set = 1;
				break;
#endif
			case 'f':
				strncpy(filename_mapping, optarg, sizeof(filename_mapping));
				file_mapping = filename_mapping;
				break;
			case 'F':
				f_foreground = 1;
				break;
			case 'g':
				vnb_name = optarg;
				break;
			case 'h':
				show_usage(0);
				break;
			case 'l':
				fpm_graceful_restart = 0;
				break;
			case 'M':
				if (ll_addr_a2n(fpm_cp_portmac, 6, optarg) != 6) {
					fprintf(stderr, "-M: invalid mac address\n");
					show_usage(1);
				}
				break;
			case 'p':
				strncpy(pidfilename, optarg, sizeof(pidfilename));
				break;
			case 'P':
				f_colocalized = 0;
				fpm_cp_portname = optarg;
				break;
			case 's':
				srv_path = optarg;
				break;
			case 'r':
				if (inet_pton(AF_INET, optarg, &peer_addr) <= 0) {
					fprintf(stderr, "invalid format for option -r\n");
					show_usage(1);
				}
				break;
			case 't':
				if (set_sockaddr_tcp(srv_sockaddr, SGENLEN, optarg)) {
					fprintf(stderr, "invalid format for option -t\n");
					show_usage(1);
				}
				srv_family = srv_sockaddr->sa_family;
				break;
			case 'T':
				fpm_auto_threshold = 0;
				break;
			case 'v':
				f_verbose++;
				break;
			case 'w':
				wait_sec = strtol(optarg, NULL, 0);
				break;
			case 'W':
				fpm_wipe_vnb_nodes = 1;
				break;
			case 'x':
				if (fpm_parse_spd_hash_preflen(optarg,
						&spd_hash_loc_plen,
						&spd_hash_rem_plen,
						32) == 0)
					printf("spd_hash_loc_plen=%u "
						"spd_hash_rem_plen=%u\n",
						spd_hash_loc_plen,
						spd_hash_rem_plen);
				else
					show_usage(1);
				break;
			case 'X':
				if (fpm_parse_spd_hash_preflen(optarg,
						&spd6_hash_loc_plen,
						&spd6_hash_rem_plen,
						128) == 0)
					printf("spd6_hash_loc_plen=%u "
						"spd6_hash_rem_plen=%u\n",
						spd6_hash_loc_plen,
						spd6_hash_rem_plen);
				else
					show_usage(1);

				break;
			case 'Z':
#ifdef HA_SUPPORT
				has_srvname = optarg;
#endif /* HA_SUPPORT */
				break;
			default:
				fprintf(stderr, "Wrong option: -%c\n", ch);
				show_usage(1);
				break;
		}
	}

	/*
	 * Map shared memory
	 */
	fp_shared = get_fp_shared();
	if (fp_shared == NULL) {
		syslog(LOG_ERR, "FPM: Initialization failure, cannot get fp_shared\n");
		exit(1);
	}

	/* Load fpm plugin libraries */
	load_plugins();

	if (!cp_blade_id_is_set)
		cp_blade_id = fpm_blade_id;

	openlog ("fpmd", LOG_NDELAY | LOG_PID | (f_verbose > 1 ? LOG_PERROR : 0), LOG_DAEMON);
	syslog(LOG_INFO, "%s: FPM starting\n", __FUNCTION__);

	/* no need to check for fpn_port_shmem, some arch have none */
	fpn_port_shmem = fpn_port_mmap();

	__fpm_recv_buf = (u_int8_t *)malloc(fpm_recvsockbufsiz);
	if (__fpm_recv_buf == NULL) {
		syslog(LOG_ERR, "FPM: Initialization failure, cannot allocate fpm_recv_buf\n");
		exit(1);
	}

	mapping_init(file_mapping);
	/*
	 * Internal basic inits 
	 */
	fpm_event_base = event_init();
	event_priority_init(2);

	/* register an event to properly exit fpmd */
	event_set(&event_sigterm, SIGTERM, EV_SIGNAL | EV_PERSIST, exit_cb, NULL);
	event_add(&event_sigterm, NULL);

#ifdef HA_SUPPORT
 	rc = has_init(HA6W_COMP_FPM, &myhas, has_srvname, ac, av,
	              HAS_NOAUTO_READY, NULL);
	if (rc == HA6W_RESULT_ERROR) {
		perror("Can not init High Availability support");
	}
	else {
		event_set (&has_event, myhas->sock, EV_READ | EV_PERSIST,
		           has_handler_event, myhas);
		if (event_add (&has_event, NULL)) {
			has_exit(myhas);
			perror("HA support event_add has_event");
		}
	}
#endif

	s_nfpc = netfpc_open(vnb_name);

	/* Cold start mode: */
	/* Initialize the shared memory */
	if (!fpm_graceful_restart)
		fp_init();
	
	/* Graceful restart mode: */
	/* - Initialize shared memory only if it was not already done */
	else if (!(fp_shared->conf.s.magic == FP_SHARED_MAGIC32))
		fp_init();
	/* - Else enter graceful restart mode forever. When the CM connects,
	 *   the graceful restart timer will be started. */
	else {
#ifdef CONFIG_MCORE_IP
		fpm_monitor_incomplete_nh_entries();
#endif
		fpm_graceful_restart_in_progress = CM_GR_TYPE_ALL;
	}

	/* Initialize local blade */
	fp_set_blade_id(fpm_blade_id, cp_blade_id);
	if (fpm_cp_portname) {
		uint32_t mtu = 1280;
		struct ifreq ifr;
		int fd;

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd >= 0) {
			memset(&ifr, 0, sizeof(struct ifreq));
			strcpy(ifr.ifr_name, fpm_cp_portname);
			if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
				mtu = ifr.ifr_mtu;
			else
				syslog(LOG_ERR, "Could not read MTU on %s (%s)\n",
				       fpm_cp_portname, strerror(errno));
			if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
			    	memcpy(fp_shared->fp_if_mac, ifr.ifr_hwaddr.sa_data, 6);
			else
			    	syslog(LOG_ERR, "Could not read MAC address on %s (%s)\n",
				       fpm_cp_portname, strerror(errno));
			close(fd);		
		}
		fp_set_cp_info(fpn_name2port(fpm_cp_portname), fpm_cp_portmac,
				mtu, fpm_auto_threshold);
	} else {
		/* Assume COLOC case. Store fpn0 mac address to be able
		 * to use FPTUN from FP to SP.
		 */
		uint32_t mtu = 1280;
		struct ifreq ifr;
		int fd;

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd >= 0) {
			char *fpn0 = vnb_name ? : "fpn0";
		
			memset(&ifr, 0, sizeof(struct ifreq));
			strcpy(ifr.ifr_name, fpn0);
			if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
				memcpy(fpm_cp_portmac, ifr.ifr_hwaddr.sa_data, 6);
			else
				syslog(LOG_ERR, "Could not read MAC on %s (%s)\n",
				       fpn0, strerror(errno));
			if (ioctl(fd, SIOCGIFMTU, &ifr) == 0)
				mtu = ifr.ifr_mtu;
			else
				syslog(LOG_ERR, "Could not read MTU on %s (%s)\n",
				       fpn0, strerror(errno));
			close(fd);		
		}
		fp_set_cp_info(IF_PORT_COLOC, fpm_cp_portmac, mtu, 0);
	}

	if (f_verbose)
		syslog(LOG_DEBUG, "magic = %x\n", fp_shared->conf.w32.magic);

	/*
	 * Open server socket
	 */
	if (srv_family == AF_UNIX) {
		if (set_sockaddr_unix(srv_sockaddr, SGENLEN, srv_path)) {
			syslog(LOG_ERR, "invalid socket path %s\n", srv_path);
			show_usage(1);
		}
		unlink(srv_path);
	}

	if (fpm_socket(srv_sockaddr) < 0)
		return -1;

#ifdef HA_SUPPORT
	/*
	 * All init done, we can answer READY
	 */
	myhas->ready = 1;
	has_ready(myhas);
#endif

	fpm_register_msg(CMD_RESET, fpm_reset, NULL);

	struct fpm_mod_entry *entry;

	/* Call plugin init hooks
	 */
	STAILQ_FOREACH(entry, &fpm_mod_list, next) {
		if (entry->mod->init)
			entry->mod->init(fpm_graceful_restart);
	}

	/* Watch netlink */
	fpm_netlink_init(fpm_event_base);

	/*
	 * Daemon stuff :
	 *  - detach terminal
	 *  - keep current working directory
	 *  - keep std outputs opened
	 */
	if (!f_foreground) {
		FILE *fp;
		if (daemon(1, 1) < 0)
			err(1, "daemon");
		if ((fp = fopen(pidfilename, "w")) != NULL) {
			fprintf(fp, "%d\n", (int) getpid());
			fclose(fp);
		}
	}

	/*
	 * Infinite loop
	 */
	event_dispatch();

#ifdef HA_SUPPORT
	has_exit(myhas);
	if (rc != HA6W_RESULT_ERROR)
		event_del(&has_event);
#endif

	/* Close netlink */
	fpm_netlink_close();
	syslog(LOG_INFO, "%s: FPM stopped\n", __FUNCTION__);

	return 0;
}
