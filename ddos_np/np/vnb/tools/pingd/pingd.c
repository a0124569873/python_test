/*
 * Copyright 2007-2012 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <event.h>
#include <time.h>
#include <sys/queue.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <netgraph.h>
#include <netgraph/ng_filter.h>


#include "pingd.h"
#include "util.h"
#include "command.h"
#include "node.h"
#include "network.h"

/* Global Variables */
int csock;
struct node_list nodes;
uint16_t ping_id;
int broadcast = 0;

static void command_node_new(int s, char *args, __attribute__ ((unused))void *evt);
static void command_node_config(int s, char *args, __attribute__ ((unused))void *evt);
static void command_node_delete(int s, char *name, __attribute__ ((unused))void *evt);
static void command_show_node(int s, char *args, __attribute__ ((unused))void *evt);
static void command_show_pid(int s, __attribute__ ((unused))char *dummy, __attribute__ ((unused))void *evt);
static void command_show_stats(int s, __attribute__ ((unused))char *dummy, __attribute__ ((unused))void *evt);

struct command_table node_command_table[] = {
	{"new", command_node_new, "node new <name> <fltname> <ifname> <our addr> <peer addr> [broadcast addr]"},
	{"config", command_node_config, "node config <name> <interval> <robustness> <check delay>"},
	{"delete", command_node_delete, "node delete <name>"},
	{NULL}
};

struct command_table show_command_table[] = {
	{"node", command_show_node, "show node <all|name>"},
	{"pid", command_show_pid, "show pid"},
	{"stats", command_show_stats, "show statistics"},
	{NULL}
};

struct command_table command_table[] = {
	{"node", NULL, "Manage netgraph nodes", node_command_table},
	{"show", NULL, "Show stats, node, pid", show_command_table},
};

static void command_node_new(int s, char *args, __attribute__ ((unused))void *evt)
{
	struct node *new = NULL;
	char *next_arg, *name, *fltname, *ifname;
	uint32_t ouraddr, peeraddr, brdaddr;

	/* Save the node name */
	if ((next_arg = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <name> is missing.\n");
		goto fail;
	}
	name = next_arg;

	/* Save the filter name */
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <fltname> is missing.\n");
		goto fail;
	}
	fltname = next_arg;

	/* Save the interface name */
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <ifname> is missing.\n");
		goto fail;
	}
	ifname = next_arg;

	/* Copy our addr */
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <our addr> is missing.\n");
		goto fail;
	}
	ouraddr = ascii2addr(next_arg);

	/* Copy peer addr */
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <peer addr> is missing.\n");
		goto fail;
	}
	peeraddr = ascii2addr(next_arg);

	/* Copy broadcast addr */
	if ((next_arg = strtok(NULL, " ")) == NULL)
		brdaddr = 0;
	else
		brdaddr = ascii2addr(next_arg);

	new = node_create(name, fltname, ifname, ouraddr, peeraddr, brdaddr);
	if (new == NULL) {
		command_printf(s, "Fail to create a new node.\n");
		return;
	}
	if (node_connect(new) < 0) {
		command_printf(s, "Fail to connect to the VNB node.\n");
		goto fail;
	}

	/* Set carrier status */
	check_carrier(0, 0, new);

	/* Set timer to send ping */
	node_set_pingtimer(new);

	command_printf(s, "Node %s has been added.\n", new->nd_name);
	return;
fail:
	node_destroy(new);
	return;
}

static void command_node_config(int s, char *args, __attribute__ ((unused))void *evt)
{
	struct node *entry;
	char *next_arg;
	int value;

	/* Parse the node name */
	if ((next_arg = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <name> is missing.\n");
		goto end;
	}
	entry = node_findbyname(next_arg);
	if (entry == NULL) {
		command_printf(s, "Error: node %s doesn't exists.\n", next_arg);
		goto end;
	}

	/* Parse the interval value */
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <interval> is missing.\n");
		goto end;
	}
	if ((value = atoi(next_arg)) > 0)
		entry->nd_interval = value;
	else
		command_printf(s, "Interval value must be > 0.\n");

	/* Parse the robustness value */
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <robustness> is missing.\n");
		goto end;
	}
	if ((value = atoi(next_arg)) > 0)
		entry->nd_robustness = value;
	else
		command_printf(s, "Robustness value must be > 0.\n");

	/* Parse the check delay value */
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <check delay> is missing.\n");
		goto end;
	}
	if ((value = atoi(next_arg)) > 0)
		entry->nd_checkdelay = value;
	else
		command_printf(s, "Check delay value must be > 0.\n");
end:
	return;
}

static void command_node_delete(int s, char *name, __attribute__ ((unused))void *evt)
{
	struct node *entry;
	char *next_arg;

	/* Parse the node name */
	if ((next_arg = strtok(name, " ")) == NULL) {
		command_printf(s, "Error: <name> is missing.\n");
		goto end;
	}
	entry = node_findbyname(next_arg);
	if (entry == NULL) {
		command_printf(s, "Error: node %s doesn't exists.\n", next_arg);
		goto end;
	}

	node_destroy(entry);
	command_printf(s, "Node has been deleted.\n");
end:
	return;
}

static void command_print_node(int s, struct node* entry)
{
	command_printf(s, "Tunnel %s (%u.%u.%u.%u -> %u.%u.%u.%u):\n",
			entry->nd_name,
			((uint8_t *)&entry->nd_ouraddr)[0],
			((uint8_t *)&entry->nd_ouraddr)[1],
			((uint8_t *)&entry->nd_ouraddr)[2],
			((uint8_t *)&entry->nd_ouraddr)[3],
			((uint8_t *)&entry->nd_peeraddr)[0],
			((uint8_t *)&entry->nd_peeraddr)[1],
			((uint8_t *)&entry->nd_peeraddr)[2],
			((uint8_t *)&entry->nd_peeraddr)[3]);
	command_printf(s, "\tinterval: %d\n", entry->nd_interval);
	command_printf(s, "\trobustness: %d\n", entry->nd_robustness);
	command_printf(s, "\tcheck delay: %d\n", entry->nd_checkdelay);
	command_printf(s, "\tcurrent seqno: %d\n", entry->nd_current_seqno);
	command_printf(s, "\tlast seqno: %d\n", entry->nd_last_seqno);
	if (entry->nd_brdaddr)
		command_printf(s, "\tlisten on: %u.%u.%u.%u\n",
				((uint8_t *)&entry->nd_brdaddr)[0],
				((uint8_t *)&entry->nd_brdaddr)[1],
				((uint8_t *)&entry->nd_brdaddr)[2],
				((uint8_t *)&entry->nd_brdaddr)[3]);
	if (entry->nd_carrier)
		command_printf(s, "\tcarrier detected.\n");
	else
		command_printf(s, "\tno carrier.\n");
	return;
}

static void command_show_node(int s, char *args, __attribute__ ((unused))void *evt)
{
	struct node *entry;
	char *next_arg;

	/* Parse the node name */
	if ((next_arg = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <name> is missing.\n");
		goto end;
	}
	if (strcmp("all", next_arg)) {
		entry = node_findbyname(next_arg);
		if (entry == NULL) {
			command_printf(s, "Error: node %s doesn't exist.\n", next_arg);
			goto end;
		}
		command_print_node(s, entry);
	} else
		if (LIST_FIRST(&nodes) == NULL)
			command_printf(s, "No node is registered.\n");
		else
			LIST_FOREACH(entry, &nodes, nd_entries)
				command_print_node(s, entry);
end:
	return;
}

static void command_show_pid(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	command_printf(s, "Daemon pid: %d.\n", getpid());
}

static void command_show_stats(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	struct node *entry;
	int n = 0, c = 0;

	LIST_FOREACH(entry, &nodes, nd_entries) {
		n++;
		if (entry->nd_carrier)
			c++;
	}

	command_printf(s, "%d nodes are registered.\n", n);
	command_printf(s, "%d nodes have carrier detected.\n", c);
	command_printf(s, "%d ping echo request have been sent.\n", stats_request_snd);
	command_printf(s, "%d ping echo request have been received.\n", stats_request_rcv);
	command_printf(s, "%d ping echo reply have been received.\n", stats_reply_rcv);
}

static void terminate(__attribute__ ((unused))int sock,
		__attribute__ ((unused))short event,
		__attribute__ ((unused))void *arg)
{
	/* Close all socket */
	close(csock);
	node_destroy_all();

	DEBUG(LOG_ERR, "exiting ...\n");
	exit(0);
}

static void pingd_usage(char *path)
{
	char *cmd;

	cmd = strrchr(path, '/');
	if (!cmd)
		cmd = path;
	else
		cmd++;
	fprintf(stderr, "%s [-b] [-f] [-D] [-d log_level] [-P pid_file] [-s unix_socket_name]\n", cmd);
	exit(PINGD_ERR_PARAM);
}

int main(int argc, char **argv)
{
	int ch, foreground = 0;
	FILE *pidfp;
	char *pid_file = NULL;
	char *sock_name = NULL;
	struct event evt_sigterm, evt_sigint;

	/* get options */
	while ((ch = getopt(argc, argv, "bfP:s:d:Dh")) != -1) {
		switch (ch) {
		case 'b':
			broadcast = 1;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'P':
			pid_file = optarg;
			break;
		case 's':
			sock_name = optarg;
			break;
		case 'D':
			log_output_stderr = 1;
			break;
		case 'd':
			setloglevel(atoi(optarg));
			break;
		case 'h':
			pingd_usage(argv[0]);
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			pingd_usage(argv[0]);
		}
	}

	/* open syslog infomation. */
	openlog("pingd", 0, LOG_DAEMON);
	DEBUG(LOG_INFO, "-- Start PINGD daemon at -- \n");

	if (foreground == 0) {
		if (daemon(0, 0) < 0)
			exit(PINGD_ERR_DAEMON);
	}

	/* initialization */
	event_init();
	LIST_INIT(&nodes);
	ping_id = htons(getpid() & 0xffff);

	csock = command_init("pingd> ", command_table,
	    sizeof(command_table) / sizeof(struct command_table),
	    PINGD_COMMAND_PORT, sock_name);
	if (csock < 0) {
		DEBUG(LOG_ERR, "Unable to open user interface\n");
		exit(PINGD_ERR_INIT);
	}

	/* dump current PID */
	if ((pidfp = fopen(pid_file?:PINGD_PIDFILE, "w")) != NULL) {
		fprintf(pidfp, "%d\n", getpid());
		fclose(pidfp);
	}

	/* register signal handlers. */
	signal_set(&evt_sigterm, SIGTERM, terminate, (void *)SIGTERM);
	signal_add(&evt_sigterm, NULL);
	signal_set(&evt_sigint, SIGINT, terminate, (void *)SIGINT);
	signal_add(&evt_sigint, NULL);

	signal(SIGPIPE, SIG_IGN); /* may happen on admin sock */

	/* Infinite loop */
	event_dispatch();
	return 0;
}
