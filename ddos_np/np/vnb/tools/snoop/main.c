/*
 * Copyright 2004-2013 6WIND S.A.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <event.h>
#include <netinet/in.h>
#ifndef __linux__
#include <net/if_dl.h>
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <syslog.h>
#include <stdarg.h>
#include <netinet/icmp6.h>
#include <time.h>

#include "snoop.h"
#include "proxy.h"
#include "mld.h"
#include "igmp.h"
#include "netlink.h"

static char prompt[20];
static int console_socket;

extern void display_console(int fd, const char *, ...);

extern void parse(char *, int fd);
extern void do_config (int nline, int fd);


/*
 * Default file names, acces names ...
 */
char  pidfilename[256] = "/var/run/snoopd.pid";
char  configfile[256] = "snoopd.cfg";

static char     **snoopd_argv;
static char     **snoopd_envp;

static char	current_command[1024];
static int	current_pos = 0;
static struct event console_evt;

void display_console(int fd, const char *str, ...)
{
	char buffer[1024];

	va_list ap;
        va_start(ap, str);
        vsnprintf(buffer, sizeof(buffer), str, ap);

	/* if we receive on stdin, we send on stdout */
	if (fd == 0)
		fd = 1;
	write(fd, buffer, strlen(buffer));
        va_end(ap);
}

static void console_cb(int fd, short event, void *param)
{
    /* data available on console socket */
	int n, i;
	char buf[1000];

	n = read(fd, buf, 1000);
	if (n > 0) {
		buf[n] = 0;
		for (i = 0; i < n; ++i) {
			if (buf[i] == '\n') {
				current_command[current_pos] = 0;
				parse(current_command, fd);
				do_config(1, fd);
				display_console(fd, prompt);
				current_pos = 0;
			} else if (current_pos < sizeof(current_command) - 1) {
				current_command[current_pos] = buf[i];
				current_pos++;
			}
		}
	} else if (param) {
		/* disconnection */
		struct event *ev = (struct event *)param;
		event_del(ev);
		free(ev);
	}
}

static void accept_cb(int fd, short event, void *arg)
{
    /* Accept a new connection. */
    struct event *ev;
    struct sockaddr_in s_in;
    socklen_t len = sizeof(s_in);
    int ns = accept(fd, (struct sockaddr *) &s_in, &len);
    if (ns < 0) {
        perror("accept");
        return;
    }

    ev = malloc(sizeof(struct event));
    event_set(ev, ns, EV_READ | EV_PERSIST, (void *) console_cb, ev);
    event_add(ev, NULL);
    display_console(ns, prompt);
}

int console_sock_open(void)
{

  /* create socket */
  console_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (console_socket < 0) {
	perror("cannot open socket ");
	return -1;
  }

  return 0;
}

int console_sock_bind(const char *path)
{
	struct sockaddr_un sa;
	/* bind server port */
        sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, path, sizeof(sa.sun_path));

	unlink(sa.sun_path);
        if (bind(console_socket, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
                perror("cannot bind port");
                return -1;
        }

        listen(console_socket, 1);

        return 0;
}

static void
do_exit(int code)
{
	log_msg(LOG_WARNING, 0, "%s exits with code %d\n", "snoopd", code);

	while (!LIST_EMPTY(&ifnet))
		stop_iface (LIST_FIRST(&ifnet), 0, 0);

	proxy_close();
	close(mld6_socket);
	close(pim6_socket);
	close(igmp_socket);
	close(pim4_socket);

#ifdef USE_RESTART_ABILITY
	if ( code < 0 )
		execve("/usr/local/6bin/snoopd", snoopd_argv, snoopd_envp);
#endif

	exit (code);
}

/*
 * Signal management
 *    - SIGUSR1 : dump of all tables
 *    - SIGHUP  : reload config
 *    - ...
 */
static struct event sigusr1;
static struct event sighup;
static struct event sigterm;
static void
sig_snoopd (int sig, short event, void *data)
{
	log_msg(LOG_WARNING, 0, "%s on signal %d\n", "snoopd", sig);

	if (sig == SIGUSR1)
		display_info (0, NULL, -1, DMC_ALL, 0);
	else if (sig == SIGHUP)
		config (configfile);
	else if (sig == SIGTERM)
		do_exit(0);
	return;
}

/*
 * Timer management : only ONE timer, every second
 * calling querier management for sending queries,
 * calling group management for any updates/cleanup
 */
static struct event evt_snoopd;
static struct timeval tm_snoopd;
static struct event evt_console;

static void
tmo_snoopd (int fd, short event, void *data)
{
	querier_timers();
	group_timers();
	evtimer_add (&evt_snoopd, &tm_snoopd);
	return;
}

static void
show_usage (void)
{
	fprintf (stderr,
	         "snoopd [-c cfgfilename] [-p pidfilename] [-F] [-U] [-v] [console-socket]\n");
	fprintf (stderr, "    -F to force foreground mode\n");
	fprintf (stderr, "    -v force logs on the std output\n");
}

int
main(int ac, char *av[], char *ep[])
{
	FILE *fp;
	int fg = 0;
	int vb = 0;
	int ch;

	snoopd_argv = av;
	snoopd_envp = ep;
	console_socket = -1;

	while ((ch = getopt(ac, av ,"c:p:UFv")) != -1) {
		switch(ch) {
		case 'c':
			strncpy(configfile, optarg, sizeof(configfile));
			break;
		case 'F':
			fg = 1;
			break;
		case 'p':
			strncpy(pidfilename, optarg, sizeof(pidfilename));
			break;
		case 'v':
			vb = 1;
			break;
		default:
			show_usage();
			break;
		}
	}
	if (optind < ac) {
		console_sock_open();
		console_sock_bind(av[optind++]);
	}

	/*
	 * Daemon stuff :
	 *  - detach terminal
	 *  - keep current working directory
	 *  - keep std outputs opened
	 */
	if (!fg) {
		if (daemon(1, 1) < 0)
			err(1, "daemon");
		if ((fp = fopen(pidfilename, "w")) != NULL) {
			fprintf(fp, "%d\n", (int) getpid());
			fclose(fp);
		}
	}
	sprintf(prompt, "snoopd(%d) >", getpid());

	/*
	 * TODO: XXX: use a combination of time and hostid to initialize the
	 * random generator.
	*/
	#ifdef SYSV
	srand48(time(NULL));
	#else
		srand(time(NULL));
	#endif

	/*
	 * Internal basic inits
	 */
	LIST_INIT (&ifnet);
	LIST_INIT (&all_proxies);
	event_init();

	openlog ("SNOOPD", LOG_NDELAY | LOG_CONS | LOG_PID | (vb ? LOG_PERROR : 0),
	         LOG_DAEMON);

	/*
	 * Open ICMPv6 raw socket for sending queries and receiving info from port
	 */
	mld_init();

	/* Open IGMP raw socket for sending queries */
	igmp_init();

	/* Initialise proxy socket */
	proxy_init();

	/*
	 * "apply" the configuration file
	 */
	config (configfile);

	/*
	 * Now add the various Sigs, and timers
	 */
	signal_set (&sigusr1, SIGUSR1, sig_snoopd, NULL);
	signal_add (&sigusr1, NULL);
	signal_set (&sighup, SIGHUP, sig_snoopd, NULL);
	signal_add (&sighup, NULL);
	signal_set (&sigterm, SIGTERM, sig_snoopd, NULL);
	signal_add (&sigterm, NULL);

	tm_snoopd.tv_sec  = 1;
	tm_snoopd.tv_usec = 0;
	evtimer_set (&evt_snoopd, tmo_snoopd, NULL);
	evtimer_add (&evt_snoopd, &tm_snoopd);


	if (console_socket >= 0) {
		event_set(&evt_console, console_socket, EV_READ | EV_PERSIST, accept_cb, 0);
		event_add(&evt_console, NULL);
	} else if (fg) {
		event_set(&evt_console, 0, EV_READ | EV_PERSIST, console_cb, 0);
		event_add(&evt_console, NULL);
		display_console(1, prompt);
	}

    /* Netlink message processer */
    netlink_init();

	/*
	 * Infinite loop
	 */
	event_dispatch();
	return 0;
}

void
fatal_exit(void)
{
	log_msg(LOG_WARNING, 0, "%s fatal error: daemon closed\n", "snoopd");

	do_exit (-1);
}

