/*
 * Copyright 2008 6WIND, All rights reserved.
 */
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <netdb.h>
#include <event.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <err.h>
#include <net/if.h>
#include <signal.h>

#ifdef HA_SUPPORT
#include <hasupport.h>
struct has_ctx * myhas = NULL;
#endif

#include "syslogargs.h"

/* libhao includes */
#include "libconsole.h"
#include "hao_peer.h"
#include "hao_disc.h"
#include "hao_console.h"

/* librib includes */
#include "zebra.h"
#include "prefix.h"
#include "zclient.h"
#include "thread.h"

#include "haorouted_main.h"
#include "haorouted_zebra.h"
#include "haorouted_protocol.h"

static const char *myaddr = NULL;
static uint16_t myport = 9004;
static uint8_t my_peer_id  = 0;

static const char *groupaddr = "225.0.0.1";
static uint16_t groupport = 9005;

int routed_loglevel = LOG_INFO;
static char *progname;

static struct event hao_routed_signal_intr;
static struct event hao_routed_signal_term;

/* console */
static void command_show_pid(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	command_printf(s, "Daemon pid: %d.\n", getpid());
}

static void command_show_stats(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	return;
}

static void command_show_log(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	command_printf(s, "Daemon log level: %s.\n", syslog_level2name(routed_loglevel));
	return;
}

static struct command_table routed_show_command_table[] = {
	{ "stats", command_show_stats, "show daemon stats", NULL },
	{ "pid",   command_show_pid, "show daemon pid", NULL },
	{ "log",   command_show_log, "show daemon log", NULL},
	{ NULL, NULL, NULL, NULL }
};

static struct command_table show_command_table[] = {
	{ "daemon", NULL, "show daemon", routed_show_command_table },
	{ "hao", NULL, "show libhao statistics", hao_show_command_table },
	{ NULL, NULL, NULL, NULL }
};

static void command_set_log(int s, char *loglevel, __attribute__ ((unused))void *evt)
{
	int level = syslog_name2level(loglevel);
	if (level < 0) {
		command_printf(s, "Error: invalid log level %s.\n", loglevel);
		return;
	}
	routed_loglevel = level;
	command_printf(s, "Set daemon log level to %s.\n", loglevel);
	return;
}

static struct command_table routed_set_command_table[] = {
	{ "log",   command_set_log, "set daemon log", NULL },
	{ NULL, NULL, NULL, NULL }
};

static struct command_table set_command_table[] = {
	{ "hao", NULL, "set libhao parameters", hao_set_command_table },
	{ "daemon", NULL, "set daemon parameters", routed_set_command_table },
	{ NULL, NULL, NULL, NULL }
};

static struct command_table command_table[] = {
	{ "show", NULL, "show statistics", show_command_table },
	{ "set" , NULL, "set parameters",  set_command_table },
	{ NULL, NULL, NULL, NULL }
};

/* libhao peer_connected callback */
void hao_routed_peer_connected(uint8_t peer_id,
			__attribute__((unused)) uint16_t version,
			__attribute__((unused)) uint16_t flags)
{
	ROUTED_LOG(LOG_DEBUG, "%s(): peer_id %d\n", __FUNCTION__, peer_id);

	hao_routed_zebra_redistribute();
}

/* libhao peer_disconnected callback */
void hao_routed_peer_disconnected(uint8_t peer_id, int do_gr)
{
	ROUTED_LOG(LOG_DEBUG, "%s(): peer_id %d\n", __FUNCTION__, peer_id);

	hao_routed_peer_zebra_restart();
}

/* Signal handling function */
static void hao_routed_signal_handle(int signal, short unused, void *arg)
{
	ROUTED_LOG(LOG_WARNING, "%s: received signal %d\n", __FUNCTION__, signal);

	switch (signal) {
		case SIGINT:
		case SIGTERM:
			exit(0);
			break;

		default:
			break;
	}
}

/* Generic function to add signals */
static int hao_routed_event_signal(struct event *ev, int signal,
                void (*signal_handle)(int, short, void *))
{
	signal_set(ev, signal, hao_routed_signal_handle, ev);
	signal_add(ev, NULL);
	return 0;
}

/* Libevent init and signal registration */
int hao_routed_event_init(void (*signal_handle)(int, short, void *))
{
	event_init();

	hao_routed_event_signal(&hao_routed_signal_intr, SIGINT, signal_handle);
	hao_routed_event_signal(&hao_routed_signal_term, SIGTERM, signal_handle);

	ROUTED_LOG(LOG_INFO, "%s(): signal handler registered\n", __FUNCTION__);
	return 0;
}

void usage(void)
{
	fprintf(stderr, "usage: %s [-i ifname] [-A ipv4_ifname_addr] [-B my_blade_id] [-P tcp_port] [-D debugoption=level] [-F] [-Z]\n", progname);
	fprintf(stderr, "\n"
		"   -h           help\n"
		"   -D routed_loglevel=level   maximum level of log messages sent to syslog\n"
		);
#ifdef HA_SUPPORT
	has_usage();
#endif
	hao_usage();

	exit(1);
}

int
main(int argc, char **argv)
{
	int opt;
	int fg = 0;
	char *p = argv[0];
	char **argvopt = argv;
	struct sockaddr_in sin;
	struct sockaddr_in group;
	char groupifname[IFNAMSIZ];
	char *has_srvname = NULL;
	hao_callback_table_t callbacks = {
		.peer_connected = hao_routed_peer_connected,
		.peer_disconnected = hao_routed_peer_disconnected,
		.object_recv = hao_routed_protocol_recv_cb
	};
#ifdef HA_SUPPORT
	int rc;
	struct event has_event;
#endif
	char prompt[16];
	char path[16];
	int verbose = 0;
	int level;

	while ((p = strpbrk(p, "/")) != NULL)
		progname = ++p;
	if (progname == NULL)
		progname = argv[0];

	snprintf(prompt, sizeof(prompt), "%s> ", progname);
	snprintf(path, sizeof(path), "/tmp/.%s", progname);

	while ((opt = getopt(argc, argvopt, "B:i:A:P:D:FZ:v")) != EOF) {
		switch (opt) {
		/* Our peer id */ 
		case 'B':
			my_peer_id = (uint8_t)strtol(optarg, NULL, 0);
			break;
		/* The multicast group ifname used for discovery */
		case 'i':
			strncpy(groupifname, optarg, sizeof(groupifname));
			break;
		/* Our local IPv4 address */
		case 'A':
			myaddr = optarg;
			break;
		/* Foreground mode */
		case 'F':
			fg = 1;
			break;
		/* High Availability srvname */
		case 'Z':
			has_srvname = optarg;
			break;
		/* Our local port */
		case 'P':
			myport = (uint16_t)strtol(optarg, NULL, 0);
			break;
		/* Debug level */
		case 'D':
			level = syslog_arg2level("routed_loglevel", optarg);
			if (level >= 0)
				routed_loglevel = level;
			break;
		case 'v':
			verbose = 1;
		default:
			usage();
			break;
		}
	}

	if (my_peer_id == 0) {
		fprintf(stderr, "Blade ID is required\n");
		exit(1);
	}

	if (!strcmp(groupifname, "")) {
		fprintf(stderr, "Group interface name is required\n");
		exit(1);
	}

	if (myaddr == NULL) {
		fprintf(stderr, "Local IP address is required\n");
		exit(1);
	}

	openlog(progname, LOG_NDELAY | LOG_PID | (verbose ? LOG_PERROR : 0), LOG_DAEMON);
	ROUTED_LOG(LOG_INFO, "%s starting", progname);

	/* Init libevent and signals */
	hao_routed_event_init(&hao_routed_signal_handle);

	/*
	 * Daemon stuff : 
	 *  - detach terminal
	 *  - keep current working directory
	 *  - keep std outputs opened 
	 */	
	if (!fg) {
		if (daemon(1, 1) < 0)
			err(1, "daemon");
	} else
		command_stdin_init(prompt, command_table,
				sizeof(command_table) / sizeof(struct command_table));

	if (command_init(prompt, command_table,
		    sizeof(command_table) / sizeof(struct command_table),
			0, "/tmp/.hao-routed") == NULL) {
		ROUTED_LOG(LOG_ERR, "%s(): Unable to open user interface\n", __FUNCTION__);
		exit(-1);
	}

	/* Init high availability support */
#ifdef HA_SUPPORT
	rc = has_init(HA6W_COMP_HAO_ROUTES, &myhas, has_srvname,
	              argc, argv, HAS_SYNC_DAEMON, NULL);
	if (rc == HA6W_RESULT_ERROR) {
		ROUTED_LOG(LOG_ERR, "%s(): Can not initialize High Availability support\n", __FUNCTION__);
	} else {
		event_set (&has_event, myhas->sock, EV_READ | EV_PERSIST, 
		           has_handler_event, myhas);

		if (event_add (&has_event, NULL)) {
			ROUTED_LOG(LOG_INFO, "%s(): HA-event error\n", __FUNCTION__);
			has_exit(myhas);
		}

		ROUTED_LOG(LOG_INFO, "%s(): HA support event_add has_event\n", __FUNCTION__);
	}
#endif

	/* Init libhao */
	sin.sin_family = AF_INET;
	inet_pton(AF_INET, myaddr, &sin.sin_addr);
	sin.sin_port   = htons(myport);

	ROUTED_LOG(LOG_INFO, "%s(): initializing hao %s %d\n", __FUNCTION__, myaddr, myport);
	if (hao_init(argc, argv, my_peer_id, (struct sockaddr *)&sin, &callbacks, NULL))
		exit(1);

#ifdef HA_SUPPORT
	hao_set_has_ctx (&myhas, HAO_HAS_MONITOR_DUMP);
#endif

	/* Init libhao discovery part */
	group.sin_family = AF_INET;
	inet_pton(AF_INET, groupaddr, &group.sin_addr);
	group.sin_port   = htons(groupport);

	ROUTED_LOG(LOG_INFO, "%s(): initializing hao discovery %s %d %s\n", __FUNCTION__,
			groupaddr, groupport, groupifname);
	if (hao_disc_init(my_peer_id, (struct sockaddr *)&sin,
				(struct sockaddr *)&group, groupifname,
				NULL))
		exit(1);

	/* Connect to zebra, get ready to receive route advertisement and send routes */
	ROUTED_LOG(LOG_DEBUG, "%s(): initializing connection to zebra\n", __FUNCTION__);
	hao_routed_zebra_init();

	/* main loop */
	ROUTED_LOG(LOG_DEBUG, "%s(): main loop\n", __FUNCTION__);
	event_dispatch();

	return 0;
}
