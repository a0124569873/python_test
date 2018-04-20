/*
 * Copyright 2013 6WIND S.A.
 */
#define _GNU_SOURCE
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
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <libconsole.h>

#include "sock.h"
#include "stream.h"

#include "sdsifd_conf.h"

extern struct command_table command_table[];

/* static fonctions to configure daemon */

static int conf_verbose (char *arg);
static int conf_mode (char *arg);
static int conf_force (char *arg);
static int conf_foreground (char *arg);
static int conf_pidfile (char *arg);
static int conf_cp_address (char *arg);
static int conf_cp_port (char *arg);
static int conf_peer_id (char *arg);
static int conf_bind_bladepeer (char *arg);
static int conf_gracetime (char *arg);
static int conf_fpib (char *arg);
static int conf_allmulti (char *arg);

static int conf_interface (char *arg);
static char *conf_current_ifname = NULL;


/* A structure which contains information on the commands this program
   can understand. */

typedef struct {
	char *name;          /* User printable name of the function. */
	int (*func)(char*);  /* Function to call to do the job. */
	char *doc;           /* Documentation for this function.  */
} COMMAND;

static const COMMAND commands[] = {
	{ "verbose",    conf_verbose, "" },
	{ "mode",       conf_mode, "" },
	{ "foreground", conf_foreground, "" },
	{ "pidfile",    conf_pidfile, "" },
	{ "force",      conf_force, "" },
	{ "cp_address", conf_cp_address, "" },
	{ "cp_port",    conf_cp_port, "" },
	{ "peer_id",    conf_peer_id, "" },
	{ "bind_bladepeer", conf_bind_bladepeer, "" },
	{ "gracetime",  conf_gracetime, "" },

	{ "interface",  conf_interface, "" },
	{    "fpib",    conf_fpib, "" },
	{    "always_allmulti",    conf_allmulti, "" },

	{ (char *)NULL, NULL, (char *)NULL }
};

static void conf_usage();
/* Forward declarations for configuration file */
static char *stripwhitesharp ();
static const COMMAND *find_command ();
static int execute_line ();
static int conf_readfile ();
static void add_interface(const char *ifname);

static void
conf_usage(int exitcode)
{
	fprintf(stderr, "%s [-hvFf] [-c conffile] [-p pidfile] [-D debugoption=level]\n", sdsifd_progname);
	fprintf(stderr, "\n"
		"   -h           help\n"
		"   -v           verbose: output on console\n"
		"   -F           foreground\n"
		"   -C           use console (in foreground mode only)\n"
		"   -f           force daemon start even if pidfile exists\n"
		"   -c CONF      set configuration file\n"
		"   -p PIDFILE   set pid file path\n"
		"   -P ID        set local blade id (server only)\n"
		"   -Z file      handle used by HA system\n"
		);

	exit(exitcode);
}

/* functions */
static int
conf_readfile (file)
	const char *file;
{
	char *line;
	char *s;
	size_t len;
	ssize_t read;
	FILE *conf;

	line = malloc(BUFSIZ);
	len = BUFSIZ;
	if (line == NULL)
		return -1;

	conf = fopen(file, "r");
	if (!conf) {
		fprintf(stderr, "%s: fopen \"%s\": %s\n", sdsifd_progname, file, strerror(errno));
		return -1;
	}

	/* Loop reading and executing lines until the user quits. */
	while ((read = getline(&line, &len, conf)) != -1)
	{
		/* Remove leading and trailing whitespace from the line.
		   Then, if there is anything left, execute it. */
		s = stripwhitesharp (line);

		if (*s)
			execute_line (s);
	}
	if (line)
		free (line);

	return 0;
}

/* Execute a command line. */
static int
execute_line (line)
	char *line;
{
	register int i;
	const COMMAND *command;
	char *word, *arg;
	int ret;

	/* Isolate the command word. */
	i = 0;
	while (line[i] && isspace (line[i]))
		i++;
	word = line + i;

	while (line[i] && !isspace (line[i]))
		i++;

	if (line[i])
		line[i++] = '\0';

	command = find_command (word);

	if (!command)
	{
		fprintf (stderr, "%s: <%s> No such command.\n", sdsifd_progname, word);
		return (-1);
	}

	/* Get argument to command, if any. */
	while (isspace (line[i]))
		i++;

	arg = line + i;

	if (*arg == 0)
		arg = NULL;

	/* Call the function. */
	ret = (*(command->func)) (arg);

	if (ret < 0)
		fprintf(stderr, "%s: Command %s returned an error\n", sdsifd_progname, word);

	return ret;
}

/* Look up NAME as the name of a command, and return a pointer to that
   command.  Return a NULL pointer if NAME isn't a command name. */
static const COMMAND *
find_command (name)
	char *name;
{
	register int i;

	for (i = 0; commands[i].name; i++)
		if (strcmp (name, commands[i].name) == 0)
			return (&commands[i]);

	return ((COMMAND *)NULL);
}

/* Strip isspace from the start and end of STRING.  Return a pointer
   into STRING. */
static char *
stripwhitesharp (string)
	char *string;
{
	register char *s, *t;

	for (s = string; isspace (*s); s++)
		;

	t = strchr(s, '#');
	if (t)
		*t = '\0';

	if (*s == 0)
		return (s);

	t = s + strlen (s) - 1;
	while (t > s && isspace (*t))
		t--;
	*++t = '\0';

	return s;
}

/* globals */
int         ifd_loglevel = LOG_DEBUG;
int         sdsifd_verbose = 0;
int         sdsifd_mode = 0;
int         sdsifd_force = 0;
int         sdsifd_foreground = 0;
int         sdsifd_console = 0;
const char *sdsifd_pidfile = "/var/run/sdsifd.pid";
/* information to connect control plane (required) */
const char *sdsifd_cp_address = NULL;
uint16_t    sdsifd_cp_port    = 0;
/* information to configure blade (required) */
uint8_t     sdsifd_local_peer_id   = 0;
int         sdsifd_gracetime = 30;
char        sdsifd_bind_bladepeer[16] = { 0 };

#ifdef HA_SUPPORT
char        has_srvname[16] = { 0 };
#endif

/* list of interface configuration */
SLIST_HEAD(sinterface_conf, sdsifd_interface_conf) sdsifd_interface_conf_list;

/* local */
static uint8_t conf_valid = 0;
#define CONF_PEER_ID       0x01
#define CONF_FPIB_IF       0x02
#define CONF_MODE          0x04

/* Commands */
static int conf_mode (char *arg) {
	if (!strcmp(arg, "cp")) {
		sdsifd_mode = CP_MODE;
	} else if (!strcmp(arg, "fp")) {
		sdsifd_mode = FP_MODE;
	} else {
		fprintf(stderr, "%s: invalid mode %s. expecting cp or fp\n", sdsifd_progname, arg);
		return -1;
	}

	conf_valid |= CONF_MODE;
	return 0;
}


static int conf_bind_bladepeer (char *arg) {
	if (arg == NULL || strlen(arg) >= 16)
		return -1;

	memcpy(sdsifd_bind_bladepeer, arg, strlen(arg) + 1);

	return 0;
}

#ifdef HA_SUPPORT
static int conf_has_srvname (char *arg) {
	if (arg == NULL || strlen(arg) >= 16)
		return -1;

	memcpy(has_srvname, arg, strlen(arg) + 1);

	return 0;
}
#endif

static int conf_verbose (char *arg) {
	sdsifd_verbose = 1;
	return 0;
}

static int conf_force (char *arg) {
	sdsifd_force = 1;
	return 0;
}

static int conf_foreground (char *arg) {
	sdsifd_foreground = 1;
	return 0;
}

static int conf_console_foreground (char *arg) {
	sdsifd_console = 1;
	return 0;
}

static int conf_pidfile (char *arg) {
	if (arg == NULL)
		return -1;
	sdsifd_pidfile = strdup(arg);
	return 0;
}

static int conf_cp_address (char *arg) {
	if (arg == NULL)
		return -1;
	sdsifd_cp_address = strdup(arg);
	return 0;
}

static int conf_cp_port (char *arg) {
	if (arg == NULL)
		return -1;
	sdsifd_cp_port = strtoul(arg, NULL, 0);
	if (sdsifd_cp_port == 0)
		return -1;
	return 0;
}

static int conf_peer_id (char *arg) {
	uint8_t id;
	if (arg == NULL)
		return -1;
	id = strtoul(arg, NULL, 0);
	if ((conf_valid & CONF_PEER_ID) && (sdsifd_local_peer_id != id)) {
		fprintf(stderr, "SDSIFD: Warning, a different peer ID was already "
			"specified to %d. Using new value %d.\n", sdsifd_local_peer_id, id);
	}
	sdsifd_local_peer_id = id;
	conf_valid |= CONF_PEER_ID;
	return 0;
}

static int conf_fpib (char *arg) {
	struct sdsifd_interface_conf *ifconf;

	if (arg == NULL)
		arg = conf_current_ifname;

	if (arg == NULL)
		return -1;

	ifconf = sdsifd_interface_conf_lookup_by_name(arg);

	if (!ifconf) {
		fprintf(stderr, "%s: not enough memory\n", __FUNCTION__);
		return -1;
	}

	ifconf->fpib = 1;
	conf_valid |= CONF_FPIB_IF;
	return 0;
}

static int conf_allmulti (char *arg) {
	struct sdsifd_interface_conf *ifconf;

	if (arg == NULL)
		arg = conf_current_ifname;

	if (arg == NULL)
		return -1;

	ifconf = sdsifd_interface_conf_lookup_by_name(arg);

	if (!ifconf) {
		fprintf(stderr, "%s: not enough memory\n", __FUNCTION__);
		return -1;
	}

	ifconf->allmulti = 1;
	return 0;
}

static int conf_interface (char *arg)
{
	fprintf(stderr, "new interface %s\n", arg);

	add_interface(arg);

	if (conf_current_ifname)
		free(conf_current_ifname);

	if (arg)
		conf_current_ifname = strdup(arg);
	else
		conf_current_ifname = NULL;

	return 0;
}

struct sdsifd_interface_conf *
sdsifd_interface_conf_lookup_by_name(const char *ifname)
{
	struct sdsifd_interface_conf *ifconf;
	struct sdsifd_interface_conf *defaultconf = NULL;
	int defaultlen = -1;

	SLIST_FOREACH(ifconf, &sdsifd_interface_conf_list, next) {
		int lastchar = strlen(ifconf->ifname) -1;
		if (!strcmp(ifconf->ifname, ifname))
			return ifconf;
		/*
		 * Special case for the FOO* names
		 * Longest radix match wins.
		 */
		else if (ifconf->ifname[lastchar] == '*') {
			if ((strncmp(ifname, ifconf->ifname, lastchar) == 0) && 
			    (lastchar > defaultlen)) {
				defaultconf = ifconf;
				defaultlen = lastchar;
			}
		}
	}

	return defaultconf;
}

static void add_interface(const char *ifname)
{
	struct sdsifd_interface_conf *ifconf;

	ifconf = sdsifd_interface_conf_lookup_by_name(ifname);
	if (ifconf)
		return;

	ifconf = (struct sdsifd_interface_conf *)
		calloc(1, sizeof(struct sdsifd_interface_conf));

	if (ifconf == NULL)
		return;

	ifconf->ifname = strdup(ifname);

	if (ifconf->ifname == NULL) {
		free(ifconf);
		return;
	}

	SLIST_INSERT_HEAD(&sdsifd_interface_conf_list, ifconf, next);

	return;
}

static int conf_gracetime (char *arg)
{
	if (arg == NULL)
		return -1;

	sdsifd_gracetime = strtoul(arg, NULL, 0);

	return 0;
}

int conf_readargs(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "hvFCfc:p:P:Z:")) != -1) {
		switch(ch) {
			case 'h':
				conf_usage(0);
				break;
			case 'v':
				conf_verbose(NULL);
				break;
			case 'F':
				conf_foreground(NULL);
				break;
			case 'C':
				conf_console_foreground(NULL);
				break;
			case 'f':
				conf_force(NULL);
				break;
			case 'c':
				conf_readfile(optarg);
				break;
			case 'p':
				conf_pidfile(optarg);
				break;
			case 'P':
				conf_peer_id(optarg);
				break;
			case 'Z':
#ifdef HA_SUPPORT
				conf_has_srvname(optarg);
#endif /* HA_SUPPORT */
				break;
			default:
				conf_usage(1);
				break;
		}
	}

	/* configuration validation */
	if (!sdsifd_cp_port) {
		fprintf(stderr, "%s: port is required\n", sdsifd_progname);
		return -1;
	}

	if ((conf_valid & CONF_MODE) == 0) {
		fprintf(stderr, "%s: Mode is required\n", sdsifd_progname);
		return -1;
	}

	if ((conf_valid & CONF_PEER_ID) == 0) {
		fprintf(stderr, "%s: Peer ID is required\n", sdsifd_progname);
		return -1;
	}

	return 0;
}
