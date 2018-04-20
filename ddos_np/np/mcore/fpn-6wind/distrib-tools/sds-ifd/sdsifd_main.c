/*
 * Copyright 2013 6WIND S.A.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>
#include <event.h>
#include <sys/signal.h>
#include <syslog.h>
#include <errno.h>
#include <libconsole.h>

#include <event.h>

#include "sock.h"
#include "stream.h"

#include "sdsifd_conf.h"

static struct event sigterm;

const char *sdsifd_progname = NULL;

#ifdef HA_SUPPORT
#include <6whasapi.h>
#include <hasupport.h>
static struct has_ctx *sdsifd_has = NULL;
static struct event has_event;
#endif

extern int sdsifd_cp_init(void);
extern int sdsifd_fp_init(void);
extern int sdsifd_nl_init(void);

/* libconsole */
extern void command_show_cp_peer(int, char *, void *);
extern void command_show_fp_peer(int, char *, void *);

static void command_show_peer(int s, char *dummy, void *evt)
{
	if (sdsifd_mode == CP_MODE)
		command_show_cp_peer(s, dummy, evt);
	else
		command_show_fp_peer(s, dummy, evt);
}

static void command_show_pid(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	command_printf(s, "Daemon pid: %d.\n", getpid());
}

static struct command_table show_command_table[] = {
	{ "pid",  command_show_pid, "show pid", NULL },
	{ "peer", command_show_peer, "show peer", NULL },
	{ NULL, NULL, NULL, NULL }
};

struct command_table command_table[] = {
	{ "show", NULL, "show statistics", show_command_table },
	{ NULL, NULL, NULL, NULL }
};

#ifdef HA_SUPPORT
static int has_event_init(char *srvname, int ac, char **av)
{
	int rc;

	rc = has_init(HA6W_COMP_SDSIFD, &sdsifd_has, srvname, ac, av,
			HAS_NOAUTO_READY, NULL);
	if (rc == HA6W_RESULT_ERROR) {
		IFD_LOG(LOG_ERR, "Can not initialize High Availability support\n");
		return -1;
	}

	event_set(&has_event, sdsifd_has->sock, EV_READ | EV_PERSIST,
			has_handler_event, sdsifd_has);
	if (event_add(&has_event, NULL)) {
		has_exit(sdsifd_has);
		IFD_LOG(LOG_ERR, "HA support event_add has_event");
		return -1;
	}

	return 0;
}
#endif

static void
catch_sig (int fd, short event, void *__data)
{
	int data = (int)(long)__data;

	if (data == SIGTERM) {
		IFD_LOG(LOG_INFO, "SIGTERM received: exiting\n");
#ifdef HA_SUPPORT
		has_exit(sdsifd_has);
#endif
		exit (0);
	}
}

/* daemon initialization */
static int sdsifd_init(int argc, char **argv)
{
	/* console */
	static char prompt[16];
	static char sockname[128];

	struct stat pidfile;
	FILE *fp;

	snprintf(prompt, sizeof(prompt), "%s> ", sdsifd_progname);
	snprintf(sockname, sizeof(sockname), "/tmp/.%s", sdsifd_progname);

	/* if pidfile exists : stop */
	if (stat(sdsifd_pidfile, &pidfile) == 0) {
		if (sdsifd_force) {
			IFD_LOG(LOG_INFO, "pid file already exists (deleting it)\n");
			unlink(sdsifd_pidfile);
		}
		else {
			IFD_LOG(LOG_ERR, "pid file already exists (is daemon running ?)\n");
			return -1;
		}
	}

	/* Daemon stuff */
	if (sdsifd_foreground && sdsifd_console) {
		command_stdin_init(prompt, command_table,
				sizeof(command_table) / sizeof(struct command_table));
	}
	else {
		if (command_init(prompt, command_table,
				 sizeof(command_table) / sizeof(struct command_table),
				 0, sockname) == NULL) {
			IFD_LOG(LOG_ERR, "%s: unable to open user interface\n", __FUNCTION__);
			return -1;
		}
	}

	if (!sdsifd_foreground) {
		if (daemon(1, 1) < 0)
			IFD_LOG(LOG_ERR, "%s: cannot daemonize\n", __FUNCTION__);
	}

	/* write pid file */
	if ((fp = fopen(sdsifd_pidfile, "w")) == NULL) {
		IFD_LOG(LOG_ERR, "%s: cannot write pid file: %s\n",
				__FUNCTION__, strerror(errno));
	} else {
		fprintf(fp, "%d\n", (int) getpid());
		fclose(fp);
	}

	sdsifd_nl_init();

	if (sdsifd_mode == CP_MODE)
		sdsifd_cp_init();
	else /* FP_MODE */
		sdsifd_fp_init();

	IFD_LOG(LOG_INFO, "daemon started\n");

	return 0;
}

int main(int argc, char **argv)
{
	sdsifd_progname = strrchr(argv[0], '/');
	if (sdsifd_progname)
		sdsifd_progname++;
	else
		sdsifd_progname = argv[0];

	event_init();

	if (conf_readargs(argc, argv))
		return 1;

	openlog(sdsifd_progname, LOG_NDELAY | LOG_PID |(sdsifd_verbose ? LOG_PERROR : 0), LOG_DAEMON);

#ifdef HA_SUPPORT
	if (has_event_init(has_srvname, argc, argv) < 0) {
		closelog();
		return 1;
	}
#endif

	signal_set (&sigterm, SIGTERM, catch_sig, (void *)SIGTERM);
	signal_add (&sigterm, NULL);

#ifdef HA_SUPPORT
	sdsifd_has->ready = 1;
	has_ready(sdsifd_has);
#endif

	IFD_LOG(LOG_INFO, "%s starting", sdsifd_progname);

	/* daemon init */
	if (sdsifd_init(argc, argv)) {
		IFD_LOG(LOG_CRIT, "cannot init %s\n", sdsifd_progname);
		closelog();
		return 1;
	}

	/* main loop */
	IFD_LOG(LOG_DEBUG, "main loop");

	event_dispatch();

	/* sdsifd_close(1); */

	IFD_LOG(LOG_CRIT, "no more event, exiting\n");

#ifdef HA_SUPPORT
	has_exit(sdsifd_has);
#endif

	return 0;
}
