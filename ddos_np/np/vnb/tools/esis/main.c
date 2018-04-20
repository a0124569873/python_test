/*
 * Copyright 2007-2013 6WIND S.A.
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <syslog.h>
#include <stdarg.h>

#include "esisd.h"

#define SZ_PROMPT 20
static char prompt[SZ_PROMPT];
static int console_socket;

int ping_fd = 0;


/*
 * Default file names, acces names ...
 */
char  pidfilename[256] = "/var/run/esisd.pid";

static char	current_command[1024];
static struct event console_evt;

void display_console(int fd, const char *str, ...)
{
	char buffer[4096];

	va_list ap;
        va_start(ap, str);
        vsnprintf(buffer, sizeof(buffer), str, ap);

	/* if we receive on stdin, we send on stdout */
	if (fd == 0)
		fd = 1;
	if (write(fd, buffer, strlen(buffer)) < 0)
		log_msg(LOG_ERR, errno, "write() failed: %s\n", __FUNCTION__);
	va_end(ap);
}

static void console_cb(int fd, short event, void *param)
{
    /* data available on console socket */
	int n, i;
	static int current_pos = 0;
#define MAX_BUF_SIZE 1000
	char buf[MAX_BUF_SIZE];

	n = read(fd, buf, MAX_BUF_SIZE);
	if (n > 0) {
		if (n < MAX_BUF_SIZE)
			buf[n] = 0;
		else
			buf[MAX_BUF_SIZE - 1] = 0;
		for (i = 0; i < n; ++i) {
			if (buf[i] == '\n') {
				current_command[current_pos] = 0;
				parse(current_command);
				do_config(1, fd);
				display_prompt (fd);
				current_pos = 0;
			} else if ((current_pos < sizeof(current_command) - 1) && (buf[i] != 0)) {
				current_command[current_pos] = buf[i];
				current_pos++;
			}
		}
	} else if (param) {
		/* disconnection */
		struct event *ev = (struct event *)param;
		event_del(ev);
		free(ev);
		console_acces = -1;
	}
#undef MAX_BUF_SIZE
}

int console_acces = -1;
static void accept_cb(int fd, short event, void *arg)
{
	/* Accept a new connection. */
	struct event *ev;
	struct sockaddr s;
	socklen_t len = sizeof(s);
	console_acces = accept(fd, &s, &len);

	if (console_acces < 0) {
		perror("accept");
		return;
	}
	ev = malloc(sizeof(struct event));
	event_set(ev, console_acces, EV_READ | EV_PERSIST,
	          (void *) console_cb, ev);
	event_add(ev, NULL);
	display_console(console_acces, prompt);
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

	log_msg(LOG_WARNING, 0, "%s exits with code %d\n", "esisd", code);

	while (!LIST_EMPTY(&ifnet))
		iface_delete (0, LIST_FIRST(&ifnet)->if_name);
	exit (code);
}

/*
 * Signal management
 *    - SIGUSR1 : dump of all tables
 *    - SIGHUP  : reload config
 *    - ...
 */
static struct event sigusr1;
static struct event sigterm;
static void
sig_esisd (int sig, short event, void *data)
{
	log_msg(LOG_WARNING, 0, "%s on signal %d\n", "esisd", sig);

	if (sig == SIGUSR1)
		// display_info (0, NULL, -1, DMC_ALL, 0);
		;
	else if (sig == SIGTERM)
		do_exit(0);
	return;
}

/*
 */
static struct event evt_console;

static void
show_usage (void)
{
	fprintf (stderr,
	         "esisd [-p pidfilename] [-F] [-U] [-v] [console-socket]\n");
	fprintf (stderr, "    -F to force foreground mode\n");
	fprintf (stderr, "    -v force logs on the std output\n");
}

void
set_prompt (u_int8_t *p)
{
	if (p) {
		if (*p == '$')
			snprintf(prompt, SZ_PROMPT, "esisd[%d]> ", getpid());
		else
			snprintf(prompt, SZ_PROMPT, "%s", p);
	}
	else {
		prompt[0] = ' ';
		prompt[1] = 0;
	}
}

void display_prompt (int fd)
{
	if (ping_fd != fd)
		display_console(fd, prompt);
	return;
}

int
main(int ac, char *av[], char *ep[])
{
	FILE *fp;
	int fg = 0;
	int vb = 0;
	int ch;

	console_socket = -1;

	while ((ch = getopt(ac, av ,"p:UFv")) != -1) {
		switch(ch) {
		case 'F':
			fg = 1;
			break;
		case 'p':
			snprintf(pidfilename, sizeof(pidfilename), "%s", optarg);
			break;
		case 'v':
			vb = 1;
			break;
		default:
			show_usage();
			return 0;
		}
	}

	openlog ("ESISD", LOG_NDELAY | LOG_CONS | LOG_PID | (vb ? LOG_PERROR : 0),
	         LOG_DAEMON);

	log_msg(LOG_INFO, 0, "daemon starting");

	if (optind < ac) {
		if (console_sock_open() || console_sock_bind(av[optind]))
			log_msg(LOG_ERR, errno, "can't open console socket %s", av[optind]);
		else
			log_msg(LOG_INFO, 0, "console socket %s opened", av[optind]);
		optind++;
	}

	/*
	 * Daemon stuff :
	 *  - detach terminal
	 *  - keep current working directory
	 *  - keep std outputs opened
	 */
	if (!fg) {
		if (daemon(1, 1) < 0)
			log_msg(LOG_ERR, errno, "can't daemonize");
	}

	if ((fp = fopen(pidfilename, "w")) == NULL) {
		log_msg(LOG_ERR, errno, "can't open pid file '%s'", pidfilename);
	} else {
		int pid = getpid();
		log_msg(LOG_INFO, 0, "pid create file %s (pid: %d)\n", pidfilename, pid);
		fprintf(fp, "%d\n", pid);
		fclose(fp);
	}
	set_prompt ("$");

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
	event_init();

	/*
	 * Now add the various Sigs, and timers
	 */
	signal_set (&sigusr1, SIGUSR1, sig_esisd, NULL);
	signal_add (&sigusr1, NULL);
	signal_set (&sigterm, SIGTERM, sig_esisd, NULL);
	signal_add (&sigterm, NULL);


	if (console_socket >= 0) {

		event_set (&evt_console, console_socket,
		           EV_READ | EV_PERSIST, accept_cb, 0);
		event_add(&evt_console, NULL);
	} else if (fg) {
		console_acces = 0;
		event_set(&evt_console, 0, EV_READ | EV_PERSIST, console_cb, 0);
		event_add(&evt_console, NULL);
		display_console(1, prompt);
	}

	/*
	 * Infinite loop
	 */
	event_dispatch();
	return 0;
}

void
fatal_exit(void)
{
	log_msg(LOG_WARNING, 0, "%s fatal error: daemon closed\n", "esisd");
	do_exit (-1);
}


/*
 * Log errors and other messages to the system log daemon and to stderr,
 * according to the severity of the message and the current debug level. For
 * errors of severity LOG_ERR or worse, terminate the program.
 */
#ifdef __STDC__
void
log_msg(int severity, int syserr, char *format, ...)
{
    va_list         ap;
    static char     fmt[2211] = "warning - ";
    char           *msg;
    va_start(ap, format);
#else
/* VARARGS3 */
void
log_msg(severity, syserr, format, va_alist)
    int             severity,
                    syserr;
    char           *format;
va_dcl
{
    va_list         ap;
    static char     fmt[2311] = "warning - ";
    char           *msg;
    char            tbuf[20];
    struct timeval  now;
    struct tm      *thyme;

    va_start(ap);
#endif
    vsnprintf(&fmt[10], sizeof(fmt) - 10, format, ap);
    va_end(ap);
    msg = (severity == LOG_WARNING) ? fmt : &fmt[10];


	/*
	 * Allow all logs ot the console
	 */
	if ((console_acces >= 0) && debug)
		display_console (console_acces, "%s", msg);

    if (syserr != 0) {
		errno = syserr;
		syslog(severity, "%s: %m", msg);
    } else {
		syslog(severity, "%s", msg);
    }

    if (severity <= LOG_ERR)
	fatal_exit();
}
