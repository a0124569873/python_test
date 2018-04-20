/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *                   MAIN for the Cache Manager (CM)
 * $Id: main.c,v 1.45 2010-10-21 14:56:21 dichtel Exp $
 ***************************************************************
 */

#include <sys/types.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <event.h>
#include <stdio.h>
#include <syslog.h>

#include <glob.h>
#include <dlfcn.h>

#include <sys/un.h>

#include <net/if.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ip.h>
#include <linux/if_tunnel.h>
#include <netlink/msg.h>

#include "fpc.h"
#include "cm_pub.h"
#include "cm_priv.h"
#include "cm_admin.h"
#include "cm_sock.h"
#include "sockmisc.h"

#include "libconsole.h"

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
#include "libvrf.h"
#endif

#define CM_PLUGIN_DEF_PATTERN "/usr/local/lib/cmgr/*.so"
#define CM_PLUGIN_ENV_PATTERN "CMGR_PLUGINS"

int cm_sockbufsiz = CM_DEFAULT_SOCKBUFSIZ;
int cm_nl_sockbufsiz = CM_DEFAULT_SOCKBUFSIZ;
int cm_debug_level = 0;
int cm_skip_level = 0;
int cm_disable_nl_ovs_flow = 0;
#ifdef CONFIG_PORTS_CACHEMGR_DEF_NFCT_DISABLE
int cm_disable_nl_nfct = 1;
#else
int cm_disable_nl_nfct = 0;
#endif

struct event_base *cm_event_base;

#ifdef CONFIG_CACHEMGR_EBTABLES

#ifndef CONFIG_CACHEMGR_EBTABLES_UPDATE_TIME
#define CM_EBT_UPDATE_TIME 1
#else
#define CM_EBT_UPDATE_TIME CONFIG_CACHEMGR_EBTABLES_UPDATE_TIME
#endif

/* how often (in seconds) should we synchronize ebtables */
struct timeval tv_ebt_timer = { .tv_sec = CM_EBT_UPDATE_TIME, .tv_usec = 0};
struct event *ev_ebt_timer;

#endif


static struct sockaddr_generic srv_sockaddr_storage;
struct sockaddr *srv_sockaddr = (struct sockaddr *)&srv_sockaddr_storage;
int srv_family = AF_UNIX;

/*
 * Default file names, access names ...
 */
static char  pidfilename[256] = DEFAULT_CM_PIDFILE;
static char *progname;

#ifdef CONFIG_HA6W_SUPPORT
#include <6whasapi.h>
#include <hasupport.h>
struct has_ctx *cmg_has = NULL;
#endif

/* Default is to notify only pattern like 'tcpdump' is running */
int cm_bpf_notify = CM_BPF_PATTERN_ONLY;

/* selective BPF filters patterns of running apps */
static const char *bpf_patterns[] = {
	"tcpdump", "ethereal", "wireshark", "tshark" };

int bpf_match_pattern(const char *name)
{
	int i;

	for (i = 0; i < sizeof(bpf_patterns)/sizeof(char *); i++)
		if (strstr(name, bpf_patterns[i]))
			return 1;

	return 0;
}

#define _GET_CONF(x) case CM_##x: return(#x)

const char *_cm_get_config(int config_var)
{
	switch (config_var) {

#ifdef CONFIG_CACHEMGR_MULTIBLADE
		_GET_CONF(CONFIG_CACHEMGR_MULTIBLADE);
#endif
#ifdef CONFIG_PORTS_CACHEMGR_DEF_NFCT_DISABLE
		_GET_CONF(CONFIG_PORTS_CACHEMGR_DEF_NFCT_DISABLE);
#endif
#ifdef CONFIG_CACHEMGR_DIAG
		_GET_CONF(CONFIG_CACHEMGR_DIAG);
#endif
#ifdef CONFIG_CACHEMGR_NF_UID
		_GET_CONF(CONFIG_CACHEMGR_NF_UID);
#endif
#ifdef CONFIG_CACHEMGR_NF_LSN
		_GET_CONF(CONFIG_CACHEMGR_NF_LSN);
#endif
#ifdef CONFIG_CACHEMGR_AUDIT
		_GET_CONF(CONFIG_CACHEMGR_AUDIT);
#endif
#ifdef CONFIG_CACHEMGR_NF_DEV
		_GET_CONF(CONFIG_CACHEMGR_NF_DEV);
#endif
#ifdef CONFIG_PORTS_CACHEMGR_NF_RULE_NAT
		_GET_CONF(CONFIG_PORTS_CACHEMGR_NF_RULE_NAT);
#endif
#ifdef CONFIG_HA6W_SUPPORT
		_GET_CONF(CONFIG_HA6W_SUPPORT);
#endif
#ifdef RTM_GETNETCONF
		_GET_CONF(RTM_GETNETCONF);
#endif
#ifdef IFLA_IPTUN_MAX
		_GET_CONF(IFLA_IPTUN_MAX);
#endif
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
		_GET_CONF(CONFIG_PORTS_CACHEMGR_NETNS);
#endif
#ifdef CONFIG_CACHEMGR_VXLAN
		_GET_CONF(CONFIG_CACHEMGR_VXLAN);
#endif
#ifdef CONFIG_CACHEMGR_VLAN
		_GET_CONF(CONFIG_CACHEMGR_VLAN);
#endif
#ifdef CONFIG_CACHEMGR_BRIDGE
		_GET_CONF(CONFIG_CACHEMGR_BRIDGE);
#endif
#ifdef CONFIG_CACHEMGR_BONDING
		_GET_CONF(CONFIG_CACHEMGR_BONDING);
#endif
#ifdef CONFIG_CACHEMGR_GRE
		_GET_CONF(CONFIG_CACHEMGR_GRE);
#endif
#ifdef CONFIG_CACHEMGR_MACVLAN
		_GET_CONF(CONFIG_CACHEMGR_MACVLAN);
#endif
#ifdef CONFIG_CACHEMGR_EBTABLES
		_GET_CONF(CONFIG_CACHEMGR_EBTABLES);
#endif
	default:
		break;
	};

	return NULL;
}

static void cm_display_conf(void(*display)(int, const char *, ...), int i)
{
	unsigned int j;

	for (j = 0; j < __CM_CONFIG_MAX; j++)
		if (_cm_get_config(j))
			display(i, "%s\n", _cm_get_config(j));
}

/* console */
static void command_show_pid(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	command_printf(s, "Daemon pid: %d.\n", getpid());
}

static void command_show_netlink(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	cm_dump_netlink_stats(s);
}

static void command_show_queue(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	fpm_dump_queue(s);
#ifdef USE_QUEUE_ALLOC
	command_printf(s, "%s: address=%p\n", __func__, &qa_mem);
	command_printf(s, "\tcurrent=%p\n", qa_mem.current);
	command_printf(s, "\tchk_count=%d\n", qa_mem.chk_count);
	command_printf(s, "\tchk_total_count=%d\n", qa_mem.chk_total_count);
	command_printf(s, "\tobj_count=%d\n", qa_mem.obj_count);
	command_printf(s, "\tobj_total_count=%d\n", qa_mem.obj_total_count);
	command_printf(s, "\tobj_malloc_count=%d\n", qa_mem.obj_malloc_count);
	command_printf(s, "\tobj_ignored_free=%d\n", qa_mem.obj_ignored_free);
	command_printf(s, "\tnext_free=%p\n", qa_mem.next_free);
#endif
}

static void command_show_conf(int s, __attribute__ ((unused))char *dummy,
			      __attribute__ ((unused))void *evt)
{
	cm_display_conf(command_printf, s);
}

static void cm_display_modules(void(*display)(int, const char *, ...), int i)
{
	unsigned int j;

	for (j = CM_REGISTERED_FIRST; (j <= CM_REGISTERED_LAST); ++j)
		if (nlsock_hooks[j].name != NULL)
			display(i, "%s\n", (const char*)nlsock_hooks[j].name);
}

static void command_show_modules(int s, __attribute__ ((unused))char *dummy,
                                 __attribute__ ((unused))void *evt)
{
	cm_display_modules(command_printf, s);
}

static void command_show_interfaces(int s, __attribute__ ((unused))char *dummy,
				    __attribute__ ((unused))void *evt)
{
	cm_display_interfaces(command_printf, s);
}

static struct command_table show_command_table[] = {
	{ "pid",   command_show_pid, "show pid", NULL },
	{ "netlink",   command_show_netlink, "show netlink packets", NULL },
	{ "queue",   command_show_queue, "show queued msg", NULL },
	{ "conf",   command_show_conf, "show conf variables", NULL },
	{ "modules", command_show_modules, "show registered modules", NULL },
	{ "interfaces", command_show_interfaces, "show registered interfaces", NULL },
	{ NULL, NULL, NULL, NULL }
};

static struct command_table command_table[] = {
	{ "show", NULL, "show statistics", show_command_table },
	{ NULL, NULL, NULL, NULL }
};

/*
 * Signal management
 *    - SIGUSR1 : dump of all tables
 *    - ...
 */
static struct event sigusr1;
static struct event sigterm;
static struct event sigpipe;
static void
cm_sig (int fd, short event, void *__data)
{
	int data = (uintptr_t)__data;
	if ((int)data == SIGPIPE) /* Ignore the SIGPIPE */
		return;
	if ((int)data == SIGUSR1)
		fpm_dump();
	else if ((int)data == SIGTERM) {
		/* TBD some cleaning */
		syslog(LOG_INFO, "SIGTERM received: exiting\n");
#ifdef CONFIG_HA6W_SUPPORT
		has_exit(cmg_has);
#endif
		exit (1);
	}
}

/*
 * Load all .so files that match the plugin pattern.
 * Pattern can be overriden by the CMGR_PLUGINS environment variable.
 */
static void
load_plugins(void)
{
	char *pattern;
	glob_t gl;

	/* Set plugin location */
	if (!(pattern = getenv(CM_PLUGIN_ENV_PATTERN)))
		pattern = CM_PLUGIN_DEF_PATTERN;

	/* Load plugins */
	if (!glob(pattern, 0, NULL, &gl)) {
		unsigned int i;

		for (i = 0; i < gl.gl_pathc; i++)
			if (!dlopen(gl.gl_pathv[i], RTLD_NOW|RTLD_GLOBAL))
				fprintf(stderr, "cannot load %s: %s\n",
				        gl.gl_pathv[i], dlerror());
		globfree(&gl);
	}
}

static void
show_usage (int retval)
{
	int prognamesiz = strlen(progname);
	int i;

	fprintf (stderr,
	         "%s [-FKvhno] [-p pidfile] [-d debuglevel] [-a avoiddebug] \\\n"
		 "%*s [[-s sockname] [-t tcpaddr:port]] \\\n"
		 "%*s [-b sockbufsiz] [-l nlsockbufsiz] "
		 "[-B fpib_ifname]\n"
#ifdef CONFIG_HA6W_SUPPORT
		 "[-Z srvname] [-I instanceid] "
#endif
		 "[-D cm_bpf_notify]",
			progname, prognamesiz, "", prognamesiz, "");
	fprintf (stderr, "    -F foreground mode\n"
	"    -K           disable netlink conntrack listening\n"
	"    -L           disable netlink ovs flow listening\n"
	"    -v (verbose) copy logs to std output\n"
	"    -h (help)    show this help message\n"
	"    -d (debug)   debug level\n"
	"    -a (avoid)   skip some traces\n"
	"    -s (socket)  CM/FPM unix socket path\n"
	"    -t (tcp)     CM/FPM tcp socket IPv4/v6 address and port\n"
	"                 examples: 1.2.3.4:1234 fe80::1%%eth1:1234 3ffe::1:1234\n"
	"    -r (retry)   retry to connect to FPM up to retry times\n"
	"    -n (natpt)   inhibates NAT-PT message toward FPM\n"
	"    -b (size)    socket buffer size (default %d)\n"
	"    -l (size)    netlink socket buffer size (default %d)\n"
	"    -B (blade)   FPIB parameters (fast path inter-blade com)\n"
	"    -D (val)     val = %u : disable all BPF synchronization\n"
	"                 val = %u : use list of patterns to select BPF to synchronize\n"
	"                 val = %u : enable all BPF synchronization\n"
	"    -o           display conf variables and exit\n"
#ifdef CONFIG_HA6W_SUPPORT
	"    -Z (srvname) activate High-Availability\n"
	"    -I (instance-id)   instance id, used by lib6whas\n"
#endif
	, cm_sockbufsiz, cm_nl_sockbufsiz,
	CM_BPF_NEVER, CM_BPF_PATTERN_ONLY, CM_BPF_ALWAYS);

	fprintf(stderr, "List of patterns used to select BPF to synchronize:\n");
	for (i = 0; i < sizeof(bpf_patterns)/sizeof(char *); i++)
		fprintf(stderr, "\t- %s\n", bpf_patterns[i]);


	exit(retval);
}

#ifdef USE_QUEUE_ALLOC
qa_mem_t qa_mem;
#endif

int fpm_ignore = 0;

int
main(int ac, char *av[])
{
	int f_foreground = 0;
	int verbose = 0;
	int ch;
#ifdef CONFIG_HA6W_SUPPORT
	int rc;
	struct event *has_event = NULL;
	char *has_srvname = NULL;
	struct has_ext_param ext_param;
#endif
	char prompt[16];
	char name[16];
	char command_sockpath[64];

	progname = strrchr(av[0], '/');
	if (progname)
		progname++;
	else
		progname = av[0];

	snprintf(prompt, sizeof(prompt), "%s> ", progname);
#ifdef CONFIG_HA6W_SUPPORT
	memset(&ext_param, 0, sizeof(struct has_ext_param));
#endif
	nlmsg_set_default_size(BUFSIZ);

	/*
	 * set stdout and stderr line buffered, so that user can read messages
	 * as soon as line is complete
	 */
	while ((ch = getopt(ac, av, "hFKLva:d:p:s:b:l:t:Z:B:I:iD:o")) != -1) {
		switch(ch) {
		case 'a':
			cm_skip_level = strtol(optarg, NULL, 0);
			break;
		case 'd':
			cm_debug_level = strtol(optarg, NULL, 0);
			break;
		case 'F':
			f_foreground = 1;
			break;
		case 'i':
			fpm_ignore = 1;
			break;
		case 'p':
 			strncpy(pidfilename, optarg, sizeof(pidfilename)-1);
			break;
		case 'v':
			verbose = 1;
			break;
		case 's':
			srv_path = optarg;
			break;
		case 't':
			if (set_sockaddr_tcp(srv_sockaddr, SGENLEN, optarg)) {
				fprintf(stderr, "%s: parameters for option -t are invalid\n", progname);
				show_usage(1);
			}
			srv_family = srv_sockaddr->sa_family;
			break;
		case 'b':
			cm_sockbufsiz = strtol(optarg, NULL, 0);
			break;
		case 'l':
			cm_nl_sockbufsiz = strtol(optarg, NULL, 0);
			break;
		case 'h':
			show_usage(0);
			break;
		case 'Z':
#ifdef CONFIG_HA6W_SUPPORT
			has_srvname = optarg;
#endif /* CONFIG_HA6W_SUPPORT */
			break;
		case 'B':
#ifdef CONFIG_CACHEMGR_MULTIBLADE
			f_multiblade = 1;
			memset(&cm_fpib, 0, sizeof(cm_fpib));
			strncpy(cm_fpib.ifname, optarg, CM_IFNAMSIZE);
			printf("multiblade mode. FPIB interface %s\n", cm_fpib.ifname);
#else
			printf("CONFIG_CACHEMGR_MULTIBLADE is disabled. ignore -B option\n");
#endif
			break;
		case 'K':
			printf("Disable netlink conntrack listening\n");
			cm_disable_nl_nfct = 1;
			break;
		case 'L':
			printf("Disable netlink ovs flow listening\n");
			cm_disable_nl_ovs_flow = 1;
			break;
		case 'I':
#ifdef CONFIG_HA6W_SUPPORT
			ext_param.has_ext_instanceId = strtoul(optarg, NULL, 0);
#else
			/* Silently ignore this option: it is always set by start_cm.sh script */
#endif
			break;
		case 'D':
			cm_bpf_notify = strtol(optarg, NULL, 0);
			if (cm_bpf_notify != CM_BPF_NEVER &&
				cm_bpf_notify != CM_BPF_PATTERN_ONLY &&
				cm_bpf_notify != CM_BPF_ALWAYS) {
				fprintf(stderr, "Invalid -D value\n");
				show_usage(1);
			}
			if (cm_bpf_notify == CM_BPF_NEVER)
				printf("Disable BPF filters synchronization\n");
			else if (cm_bpf_notify == CM_BPF_ALWAYS)
				printf("Synchronize all BPF filters\n");

			break;
		case 'o':
			cm_display_conf(command_printf, STDOUT_FILENO);
			return 0;
		default:
			show_usage(1);
			break;
		}
    }

	if (srv_family == AF_UNIX) {
		if (set_sockaddr_unix(srv_sockaddr, SGENLEN, srv_path)) {
			fprintf(stderr, "%s: failed to set address for unix socket, the socket path: %s\n",
					__FUNCTION__, srv_path);
			show_usage(1);
		}
	}

#ifdef CONFIG_HA6W_SUPPORT
	if (ext_param.has_ext_instanceId)
		snprintf(name, sizeof(name), "%s%d", progname, ext_param.has_ext_instanceId);
	else
#endif
		snprintf(name, sizeof(name), "%s", progname);
	openlog (name, LOG_NDELAY | LOG_PID | (verbose ? LOG_PERROR : 0), LOG_DAEMON);
	syslog (LOG_INFO, "%s starting\n", progname);

	cm_display_conf(syslog, LOG_INFO);

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

#ifdef USE_QUEUE_ALLOC
	/* must be done before fpm_init() */
	/* second parameter for qa_init is chunk_size */
	qa_init(&qa_mem, 0);
#endif

	/*
	 * Internal basic inits
	 */
	cm_event_base = event_init();

	/*
	 * Now add the various Sigs, and timers
	 */
	signal_set (&sigusr1, SIGUSR1, cm_sig, (void *)SIGUSR1);
	signal_add (&sigusr1, NULL);
	signal_set (&sigterm, SIGTERM, cm_sig, (void *)SIGTERM);
	signal_add (&sigterm, NULL);
	signal_set (&sigpipe, SIGPIPE, cm_sig, (void *)SIGPIPE);
	signal_add (&sigpipe, NULL);

#ifdef CONFIG_HA6W_SUPPORT
	rc = has_init(HA6W_COMP_CM, &cmg_has, has_srvname, ac, av,
		      HAS_NOAUTO_READY, &ext_param);
	if (rc == HA6W_RESULT_ERROR) {
		syslog(LOG_ERR, "Can not initialize High Availability support\n");
	} else {
		has_event = event_new (cm_event_base, cmg_has->sock, EV_READ | EV_PERSIST,
				       has_handler_event, cmg_has);
		if (event_add (has_event, NULL)) {
			has_exit(cmg_has);
			syslog(LOG_ERR, "HA support event_add has_event");
		}
	}
#endif

	if (f_foreground) {
		/* libconsole init, must be done after event_init */
		command_stdin_init(prompt, command_table,
				sizeof(command_table) / sizeof(struct command_table));
	}

	snprintf(command_sockpath, sizeof(command_sockpath), "/tmp/.%s", name);
	if (command_init(prompt, command_table,
			sizeof(command_table) / sizeof(struct command_table),
			0, command_sockpath) == NULL) {
		syslog(LOG_ERR, "Unable to open user interface\n");
		exit(-1);
	}

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	if (libvrf_init() < 0) {
		syslog(LOG_ERR, "Could not init libvrf\n");
		exit(-1);
	}
#endif

	/* Load cmgr plugin libraries */
	load_plugins();

	/*
	 * CM/FPM init
	 */
	fpm_init(0);

#ifdef CONFIG_CACHEMGR_EBTABLES
	ev_ebt_timer = evtimer_new(cm_event_base, cm_ebtc_update_timer, NULL);
	evtimer_add(ev_ebt_timer, &tv_ebt_timer);
#endif

#ifdef CONFIG_HA6W_SUPPORT
	/*
	 * All init done, we can answer READY
	 */
	cmg_has->ready = 1;
	has_ready(cmg_has);
#endif

	/*
	 * Infinite loop
	 */
	event_dispatch();
#ifdef CONFIG_HA6W_SUPPORT
	has_exit(cmg_has);
	if (rc != HA6W_RESULT_ERROR)
		if (has_event)
			event_free(has_event);
#endif
	syslog (LOG_INFO, "%s stopped\n", progname);

	return 0;
}
