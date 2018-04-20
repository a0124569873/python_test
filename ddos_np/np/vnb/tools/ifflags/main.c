/*
 * Copyright 2009-2013 6WIND S.A.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <event.h>
#include <time.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <ctype.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <libconsole.h>
#include <signal.h>
#include <linux/version.h>
#include <linux/netlink.h>
#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>

#include "libif.h"
#include "libifevent.h"
#include "ifflags.h"
#include "node.h"

#ifdef HA_SUPPORT
#include <hasupport.h>
struct has_ctx * myhas = NULL;
#endif

/* Global Variables */
struct command_socket* csock;
int log_output_stderr = 0;

#ifndef USE_VRF_NETNS
struct nl_sock *ifflags_nlsock;
#endif

static void interface_command_add(int, char *, __attribute__ ((unused))void *);
static void interface_command_delete(int, char *, __attribute__ ((unused))void *);
static void bind_command(int, char *, __attribute__ ((unused))void *);
static void unbind_command(int, char *, __attribute__ ((unused))void *);
static void command_show_root(int, char *, __attribute__ ((unused))void *);
static void command_show_leaf(int, char *, __attribute__ ((unused))void *);
static void command_show_pid(int, __attribute__ ((unused))char *, __attribute__ ((unused))void *);
struct command_table interface_command_table[] = {
	{"add", interface_command_add, "interface add <ifname>"},
	{"delete", interface_command_delete, "interface delete <ifname>"},
	{NULL}
};

struct command_table show_command_table[] = {
	{"root", command_show_root, "show root <all | name>"},
	{"leaf", command_show_leaf, "show leaf <all | name>"},
	{"pid", command_show_pid, "show pid"},
	{NULL}
};

struct command_table ifflags_command_table[] = {
	{"interface", NULL, "add or remove root node", interface_command_table},
	{"bind", bind_command, "bind <root_ifname> <leaf_ifname>"},
	{"unbind", unbind_command, "unbind <root_ifname> <leaf_ifname>"},
	{"show", NULL, "show the current info", show_command_table},
};

static void
interface_command_add(int s, char *args, __attribute__ ((unused))void *evt)
{
	struct dev_node *new = NULL;
	char *ifname;

	/* Parse arguments */
	if ((ifname = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <ifname> is missing.\n");
		goto fail;
	}

	new = create_root(ifname);
	if (new == NULL) {
		command_printf(s, "Fail to create a new root node.\n");
		return;
	}

	command_printf(s, "Node %s is added.\n", new->name);
	DEBUG(LOG_INFO, "Root Node %s is added.\n", new->name);
	return;

fail:
	return;
}

static void
interface_command_delete(int s, char *name, __attribute__ ((unused))void *evt)
{
	char *ifname;

	/* Parse the node name */
	if ((ifname = strtok(name, " ")) == NULL) {
		command_printf(s, "Error: <ifname> is missing.\n");
		goto end;
	}
	if(del_root(ifname) < 0 ) {
		command_printf(s, "Fail to delete the new root node.\n");
		return;
	}
	command_printf(s, "Node %s is deleted.\n", ifname);
	DEBUG(LOG_INFO, "Node %s is deleted.\n", ifname);
end:
	return;
}

static void
bind_command(int s, char *args, __attribute__ ((unused))void *evt)
{
	char *root, *leaf;

	/* Parse the channel-group-name */
	if ((root = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <root_ifname> is missing.\n");
		goto end;
	}

	/* Parse next keyword link or load-balance */
	if ((leaf = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <leaf_ifname> is missing.\n");
		goto end;
	}

	if(cli_addbinding(root, leaf) < 0) {
		command_printf(s, "Fail to bind %s with %s.\n", root, leaf);
		return;
	}

	command_printf(s, "%s with %s is binded.\n", root, leaf);
	DEBUG(LOG_INFO, "%s with %s is binded.\n", root, leaf);
	return;
end:
	return;
}

static void
unbind_command(int s, char *args, __attribute__ ((unused))void *evt)
{
	char *root, *leaf;

	/* Parse the channel-group-name */
	if ((root = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <root_ifname> is missing.\n");
		goto end;
	}

	/* Parse next keyword link or load-balance */
	if ((leaf = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <leaf_ifname> is missing.\n");
		goto end;
	}
	if(cli_delbinding(root, leaf) < 0) {
		command_printf(s, "Fail to unbind %s with %s.\n", root, leaf);
		return;
	}

	command_printf(s, "%s with %s is unbinded.\n", root, leaf);
	DEBUG(LOG_INFO, "%s with %s is unbinded.\n", root, leaf);
	return;
end:
	return;
}

static void
command_print_node(int s, struct dev_node* entry)
{
	struct bind_node *bindnode = NULL;
	struct bind_list *bindlist;

	command_printf(s, " Name:%s bindnum:%d status:%d bindlists:", entry->name, entry->bindnum, entry->status);
	bindlist = &entry->bindings;
	LIST_FOREACH(bindnode, bindlist, next) {
		command_printf(s, "%s ", bindnode->ptr->name);
	}
	command_printf(s, "\n");
	return;
}

extern struct dev_list root_bucket[HASHTABLE_SIZE];
static void
command_show_root(int s, char *args, __attribute__ ((unused))void *evt)
{
	struct dev_node *entry;
	char *ifname;

	/* Parse the node name */
	if ((ifname = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <ifname | all> is missing.\n");
		goto end;
	}
	if (!strcmp("all", ifname)) {
		int i;
		for (i=0; i<HASHTABLE_SIZE; i++)
			LIST_FOREACH(entry, &root_bucket[i], h_next) {
				command_print_node(s, entry);
			}
	} else {
		entry = device_root_findbyname(ifname);
		if(entry)
			command_print_node(s, entry);
	}
end:
	return;
}

extern struct dev_list leaf_bucket[HASHTABLE_SIZE];
static void
command_show_leaf(int s, char *args, __attribute__ ((unused))void *evt)
{
	struct dev_node *entry;
	char *ifname;

	/* Parse the node name */
	if ((ifname = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <ifname | all> is missing.\n");
		goto end;
	}
	if (!strcmp("all", ifname)) {
		int i;
		for (i=0; i<HASHTABLE_SIZE; i++)
			LIST_FOREACH(entry, &leaf_bucket[i], h_next) {
				command_print_node(s, entry);
			}
	} else {
		entry = device_leaf_findbyname(ifname);
		if(entry)
			command_print_node(s, entry);
	}
end:
	return;
}

static void
command_show_pid(int s, __attribute__ ((unused))char *dummy,
		__attribute__ ((unused))void *evt)
{
	command_printf(s, "Daemon pid: %d.\n", getpid());
}

static void
terminate(__attribute__ ((unused))int sock,
		__attribute__ ((unused))short event,
		__attribute__ ((unused))void *arg)
{
	/* Close all socket */
#ifndef USE_VRF_NETNS
	nl_socket_free(ifflags_nlsock);
	ifflags_nlsock = NULL;
	/* Remove VR 0 */
	libif_event_free_ctx(0);
#endif
	command_close(csock);

	libif_stop();

	DEBUG(LOG_ERR, "exiting ...\n");
	exit(0);
}

static void
ifflagsd_usage(char *path)
{
	char *cmd;

	cmd = strrchr(path, '/');
	if (!cmd)
		cmd = path;
	else
		cmd++;
	fprintf(stderr, "%s [-D] [-d log_level] [-P pid_file] [-s unix_socket_name]\n", cmd);
	exit(IFFLAGSD_ERR_PARAM);
}

#define NL_SOCKET_BUFSIZE 8388608  /* 8x1024x1024 */

#ifdef USE_VRF_NETNS
static void add_vrf(int vrfid, __attribute__ ((unused)) void *data)
{
	libvrf_change(vrfid);
	libif_event_new_ctx(vrfid, NL_SOCKET_BUFSIZE);
	libvrf_back();
}

static void del_vrf(int vrfid, __attribute__ ((unused)) void *data)
{
	libvrf_change(vrfid);
	libif_event_free_ctx(vrfid);
	libvrf_back();
}

static void vrf_monitor(__attribute__ ((unused)) int fd,
                        __attribute__ ((unused)) short event,
                        void * arg)
{
	libvrf_monitor_event(add_vrf, del_vrf, arg);
}

struct nl_sock *get_nl_sock (struct libif_iface *iface)
{
	struct nl_sock *nlsock = NULL;

	if (libif_get_user(iface->vrf_id, (void **)&nlsock) < 0)
		return NULL;

	/* OK we found the cache */
	if (nlsock)
		return nlsock;

	libvrf_change(iface->vrf_id);
	nlsock = nl_socket_alloc();
	if (!nlsock) {
		DEBUG(LOG_ERR, "Unable to create socket\n");
		exit(IFFLAGSD_ERR_INIT);
	}

	if (nl_connect(nlsock, NETLINK_ROUTE) < 0) {
		DEBUG(LOG_ERR, "Unable to connect socket\n");
		exit(IFFLAGSD_ERR_INIT);
	}
	libvrf_back();
	libif_set_user(iface->vrf_id, (void *)nlsock);

	return nlsock;
}
#endif


int main(int argc, char **argv)
{
	int ch, foreground = 0;
	FILE *pidfp;
	char *pid_file = NULL;
	const char *sock_name = NULL;
	struct event evt_sigterm, evt_sigint;
#ifdef HA_SUPPORT
	char *has_srvname = NULL;
	int rc;
	struct event has_event;
#endif
#ifdef USE_VRF_NETNS
	int vrf_fd;
	struct event vrf_ev;
#endif

	/* get options */
	while ((ch = getopt(argc, argv, "fP:s:d:DhZ:")) != -1) {
		switch (ch) {
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
			ifflagsd_usage(argv[0]);
			break;
		/* High Availability srvname */
		case 'Z':
#ifdef HA_SUPPORT
			has_srvname = optarg;
#endif
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			ifflagsd_usage(argv[0]);
		}
	}

	/* open syslog infomation. */
	openlog("IFFLAGSD", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	DEBUG(LOG_INFO, "-- Start IFFLAGS daemon at -- \n");

	if (foreground == 0) {
		if (daemon(0, 0) < 0) {
			DEBUG(LOG_ERR, "Unable to lanch the daemon\n");
			exit(IFFLAGSD_ERR_DAEMON);
		}
	}

	nlmsg_set_default_size(NL_SOCKET_BUFSIZE);

	/* initialization */
	event_init();
	hash_table_init();

	csock = command_init("ifflags> ", ifflags_command_table,
		    sizeof(ifflags_command_table) / sizeof(struct command_table),
		    IFFLAGSD_COMMAND_PORT, sock_name);
	if (csock == NULL) {
		DEBUG(LOG_ERR, "Unable to open user interface\n");
		exit(IFFLAGSD_ERR_INIT);
	}

        libif_start();
#ifdef USE_VRF_NETNS
	libvrf_init();
	vrf_fd = libvrf_monitor_init();
	event_set (&vrf_ev, vrf_fd, EV_READ | EV_PERSIST, vrf_monitor, NULL);
	event_add (&vrf_ev, NULL);
	libvrf_iterate(add_vrf, NULL);
#else
	/* Manage VR 0 */
	libif_event_new_ctx(0, NL_SOCKET_BUFSIZE);
#endif

#ifndef USE_VRF_NETNS
	ifflags_nlsock = nl_socket_alloc();
	if (!ifflags_nlsock) {
		DEBUG(LOG_ERR, "Unable to create socket\n");
		exit(IFFLAGSD_ERR_INIT);
	}

	if (nl_connect(ifflags_nlsock, NETLINK_ROUTE) < 0) {
		DEBUG(LOG_ERR, "Unable to connect socket\n");
		exit(IFFLAGSD_ERR_INIT);
	}
#endif

	/* Init high availability support */
#ifdef HA_SUPPORT
	rc = has_init(HA6W_COMP_IFFLAGS, &myhas, has_srvname,
		      argc,argv, 0, NULL);
	if (rc == HA6W_RESULT_ERROR) {
		DEBUG(LOG_ERR, "%s(): Can not initialize High Availability"
		      " support\n", __FUNCTION__);
	} else {
		event_set (&has_event, myhas->sock, EV_READ | EV_PERSIST,
			   has_handler_event, myhas);
		if (event_add (&has_event, NULL)) {
			DEBUG(LOG_INFO, "%s(): HA-event error\n", __FUNCTION__);
			has_exit(myhas);
		}
		DEBUG(LOG_INFO, "%s(): HA support event_add has_event\n",
		      __FUNCTION__);
	}
#endif
	/* dump current PID */
	if ((pidfp = fopen(pid_file?:IFFLAGSD_PIDFILE, "w")) != NULL) {
		DEBUG(LOG_DEBUG, "success open %d\n",getpid());
		fprintf(pidfp, "%d\n", getpid());
		fclose(pidfp);
	}

	/* register signal handlers. */
	signal_set(&evt_sigterm, SIGTERM, terminate, (void *)SIGTERM);
	signal_add(&evt_sigterm, NULL);
	signal_set(&evt_sigint, SIGINT, terminate, (void *)SIGINT);
	signal_add(&evt_sigint, NULL);

	signal(SIGPIPE, SIG_IGN); /* may happen on admin sock */

	libif_notif_add(LIBIF_F_CREATE | LIBIF_F_DELETE
			| LIBIF_F_UPDATE, ifflags_nl_cb, NULL);

	/* Infinite loop */
	event_dispatch();
	return 0;
}
