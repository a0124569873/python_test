/*
 * Copyright 2007-2013 6WIND S.A.
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
#include <netlink/msg.h>
#include <ctype.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <netgraph.h>
#include <netgraph/ng_message.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_ethgrp.h>
#include <libconsole.h>

#include <netgraph/ieee8023_slowprotocols.h>
#include <netgraph/ieee8023_tlv.h>
#include <netgraph/ieee8023ad_lacp.h>
#include "lacp.h"
#include "node.h"
#include "netlink.h"
#include "iface.h"
#include "ieee8023ad_lacp_debug.h"

#ifdef HA_SUPPORT
#include <hasupport.h>
struct has_ctx * myhas = NULL;
/* grace delay, in second : longer than the max LACP delay */
#define LACP_GRACEFUL_DELAY ((40*LACP_TICK_RATIO)/LACP_TICK_HZ)
#endif
struct lacp_state cur_lacp_state;

/* 40 times the system default buffersize */
#define LACP_DEFAULT_SOCKBUFSIZ 10*260096

#define LACP_MAX_OPEN_FILES 10240
/* Global Variables */
struct command_socket* csock;
int log_output_stderr = 0;

static int lacpd_nl_sockbufsiz = LACP_DEFAULT_SOCKBUFSIZ;

static void chgrp_command_node_new(int, char *, __attribute__ ((unused))void *);
static void chgrp_command_node_delete(int, char *, __attribute__ ((unused))void *);
static void chgrp_command_show_node(int, char *, __attribute__ ((unused))void *);
static void chgrp_command_show_pid(int, __attribute__ ((unused))char *, __attribute__ ((unused))void *);
static void chgrp_command_node_config(int, char *, __attribute__ ((unused))void *);
static void chgrp_command_node_link_subconfig(int, __attribute__ ((unused))char *, struct chgrp_node *);
static void chgrp_command_node_loadbalance_subconfig(int, __attribute__ ((unused))char *, struct chgrp_node *);
static void chgrp_command_node_lacprate_subconfig(int, __attribute__ ((unused))char *, struct chgrp_node *);
static void chgrp_command_node_del_link_subconfig(int, __attribute__ ((unused))char *, struct chgrp_node *);
static void chgrp_command_set_loglevel(int, char *, __attribute__ ((unused))void *);
static void chgrp_command_set_lacpdebug(int, char *, __attribute__ ((unused))void *);

struct command_table chgrp_node_command_table[] = {
	{"new", chgrp_command_node_new, "node new <channel-group-name> <node-name>"},
	{"config", chgrp_command_node_config,
	 "node config <channel-group-name> link <linkNum> "
	 "ifname <IFNAME> mode <static|active|passive> [priority <PRIO>]\n"
	 "	   - node config <channel-group-name> "
	 "load-balance <round-robin|xor-ip|xor-ip-port|xor-mac|backup>\n"
	 "	   - node config <channel-group-name> lacp-rate <fast|slow>\n"
	 "	   - node config <channel-group-name> del link <linkNum>"},
	{"delete", chgrp_command_node_delete, "node delete <channel-group-name>"},
	{NULL}
};

struct command_table chgrp_show_command_table[] = {
	{"node", chgrp_command_show_node, "show node <all|channel-group-name>"},
	{"pid", chgrp_command_show_pid, "show pid"},
	{NULL}
};

struct command_table chgrp_command_table[] = {
	{"node", NULL, "Manage netgraph nodes", chgrp_node_command_table},
	{"show", NULL, "Show status, stats", chgrp_show_command_table},
	{"loglevel", chgrp_command_set_loglevel, "Set loglevel"},
	{"lacpdebug", chgrp_command_set_lacpdebug, "Enable LACP debug"},
};

static void
chgrp_command_node_new(int s, char *args, __attribute__ ((unused))void *evt)
{
	struct chgrp_node *new = NULL;
	char *next_arg, *chgrpname, *nodename;

	/* Save the channel group name */
	if ((next_arg = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <channel-group-name> is missing.\n");
		goto fail;
	}
	chgrpname = next_arg;

	/* Save the node name */
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <node-name> is missing.\n");
		goto fail;
	}
	nodename = next_arg;

	new = chgrp_node_create(chgrpname, nodename);
	if (new == NULL) {
		command_printf(s, "Cannot create this node: %s\n", strerror(errno));
		return;
	}
#ifdef LACP_NOTIF
	if (chgrp_node_connect(new) < 0) {
		command_printf(s, "Cannot connect the ethgrp node to dsock\n");
		goto fail;
	}
#endif
	command_printf(s, "channel group '%s' is added.\n", new->chgrpname);
	DEBUG(LOG_INFO, "channel group '%s' is added.\n", new->chgrpname);
	return;

 fail:
	chgrp_node_destroy(new);
}

static void
chgrp_command_node_config(int s, char *args, __attribute__ ((unused))void *evt)
{
	struct chgrp_node *node = NULL;
	char *next_arg;
	char *chgrpname;

	/* Parse the channel-group-name */
	if ((chgrpname = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <channel-group-name> is missing.\n");
		return;
	}
	node = chgrp_node_lookup_by_chgrpname(chgrpname);
	if (node == NULL) {
		command_printf(s, "Error: channel-group %s doesn't exists.\n", chgrpname);
		return;
	}

	/* Parse next keyword link or load-balance */
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: next args is missing, please type 'node config help' for help\n");
		return;
	}

	if(!strcmp (next_arg, "link")) {
		chgrp_command_node_link_subconfig(s, NULL, node);
	} else if(!strcmp (next_arg, "load-balance")) {
		chgrp_command_node_loadbalance_subconfig(s, NULL, node);
	} else if(!strcmp (next_arg, "lacp-rate")) {
	    chgrp_command_node_lacprate_subconfig(s, NULL, node);
	} else if(!strcmp (next_arg, "del")) {
		chgrp_command_node_del_link_subconfig(s, NULL, node);
	}
}

static void
chgrp_command_node_link_subconfig(int s, __attribute__ ((unused))char *args,
				  struct chgrp_node *node)
{
	int linknum;
	int prio = NG_ETH_GRP_DEFAULT_PRIO;
	char *ifname, *mode, *next_arg;
	struct chgrp_link *link;
	struct lacpd_iface *iface;

	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <linkNum> is missing.\n");
		return;
	}
	linknum = atoi(next_arg);
	if (linknum < 0 || linknum > NG_ETH_GRP_MAX_LINKS) {
		command_printf(s, "Error: linkNum(%d) must be between 0 and %d.\n",
			       linknum, NG_ETH_GRP_MAX_LINKS);
		return;
	}
	if ((next_arg = strtok(NULL, " ")) == NULL
	    || strcmp (next_arg, "ifname")) {
		command_printf(s, "Error: 'ifname' is missing.\n");
		return;
	}
	if ((ifname = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <IFNAME> is missing.\n");
		return;
	}
	/* Parse the mode */
	if ((next_arg = strtok(NULL, " ")) == NULL
	  || strcmp (next_arg, "mode")) {
		command_printf(s, "Error: 'mode' is missing.\n");
		return;
	}
	if ((mode = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <static|active|passive> is missing.\n");
		return;
	}
	if (strcmp (mode, "static") && strcmp (mode, "active")
	    && strcmp (mode, "passive")) {
		command_printf(s, "Error: valid mode is <static|active|passive>.\n");
		return;
	}

	/* Parse the priority */
	prio = NG_ETH_GRP_DEFAULT_PRIO;
	if ((next_arg = strtok(NULL, " ")) != NULL) {
		if (strcmp (next_arg, "priority")) {
			command_printf(s, "Error: 'priority' is missing.\n");
			return;
		}
		if ((next_arg = strtok(NULL, " ")) == NULL) {
			command_printf(s, "Error: <PRIO> is missing.\n");
			return;
		}
		prio = atoi(next_arg);
		if (prio < 0 || prio > NG_ETH_GRP_MAX_PRIO) {
			command_printf(s, "Error: priority(%d) must be between 0 and %d.\n",
				       prio, NG_ETH_GRP_MAX_PRIO);
			return;
		}
	}

	/* parsing of args is finished, we can create/lookup the
	 * link */

	/* if a link already exist with same ifname and same linknum, use it */
	link = chgrp_link_lookup_by_ifname(node, ifname);
	if (link && link->linknum != linknum) {
		command_printf(s, "Error: this ifname is used on another link\n");
		return;
	}
	if (link == NULL)
		link = chgrp_link_create(node, linknum, ifname);
	if (link == NULL) {
		command_printf(s, "Error: cannot create link: %s\n", strerror(errno));
		return;
	}

	/* find iface in list */
	iface = lacpd_iface_lookup(ifname);
	if (iface)
		link->if_flags = iface->flags;

	if ( (link->if_flags & IFF_RUNNING) &&
	     (link->if_flags & IFF_UP) )
		link->status = NG_ETH_GRP_HOOK_ACTIVE;
	else
		link->status = NG_ETH_GRP_HOOK_INACTIVE;
	if(link->status == NG_ETH_GRP_HOOK_ACTIVE)
		increase(node);

	/* set link mode */
	if (!strcmp(mode, "static"))
		link->mode = MODE_LINK_ON;
	else if (!strcmp(mode, "active"))
		link->mode = MODE_LINK_LACP_ACTIVE;
	else if (!strcmp(mode, "passive")) {
		link->mode = MODE_LINK_LACP_PASSIV;
		/* LACP_STATE_ACTIVITY is set as default in chgrp_link_create */
		link->lp_state &= ~LACP_STATE_ACTIVITY;
	}

	link->priority = prio;

	/* connect and configure node if interface exists */
	if (iface) {
		/* in non-standalone mode, the connection to the node
		 * is already done by XMS */
		chgrp_link_connect(node, link);
		chgrp_node_configure_status(node, linknum, link->status);
		chgrp_node_configure_prio(node, linknum, prio);
	}
	DEBUG(LOG_INFO, "chgrp=%s, link=%s, linknum=%d, flags=%d, status=%d, mode=%d, pri=%d",
		node->chgrpname, link->ifname, link->linknum, link->if_flags, link->status,
		link->mode, link->priority);
}

static void
chgrp_command_node_loadbalance_subconfig(int s, __attribute__ ((unused))char *args,
					 struct chgrp_node *node)
{
	char *next_arg;

	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <round-robin|xor-ip|xor-ip-port|xor-mac|backup> is missing.\n");
		return;
	}
	if (!strcmp (next_arg, "round-robin"))
		node->algo = NG_ETH_GRP_ALGO_ROUND_ROBIN;
	else if (!strcmp (next_arg, "xor-mac"))
		node->algo = NG_ETH_GRP_ALGO_XOR_MAC;
	else if (!strcmp (next_arg, "xor-ip"))
		node->algo = NG_ETH_GRP_ALGO_XOR_IP;
	else if (!strcmp (next_arg, "backup"))
		node->algo = NG_ETH_GRP_ALGO_BACKUP;
	else if (!strcmp (next_arg, "xor-ip-port"))
		node->algo = NG_ETH_GRP_ALGO_XOR_IP_PORT;
	else {
		command_printf(s, "Error: valid load-balance is "
			       "<round-robin|xor-ip|xor-ip-port|xor-mac|backup>.\n");
		return;
	}
	if (chgrp_node_configure_algo(node, node->algo) < 0) {
		DEBUG(LOG_CRIT, "Can not set load-balance to vnb-node\n");
		return;
	}
}

static void
chgrp_command_node_lacprate_subconfig(int s, __attribute__ ((unused))char *args,
					 struct chgrp_node *node)
{
	char *next_arg;

	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <fast|slow> is missing.\n");
		return;
	}
	if (!strcmp (next_arg, "fast"))
		node->lacp_rate = LACP_FAST;
	else if (!strcmp (next_arg, "slow"))
		node->lacp_rate = LACP_SLOW;
	else {
		command_printf(s, "Error: valid lacp-rate is "
			       "<fast | slow>.\n");
		return;
	}
	chgrp_node_configure_lacprate(node);
}

static void
chgrp_command_node_del_link_subconfig(int s, __attribute__ ((unused))char *args, struct chgrp_node *node)
{
	char *next_arg;
	int linknum = -1;

	if (strtok(NULL, " ") == NULL) {
		command_printf(s, "Error: 'link' is missing.\n");
		return;
	}
	if ((next_arg = strtok(NULL, " ")) == NULL) {
		command_printf(s, "Error: <linkNum> is missing.\n");
		return;
	}
	linknum = atoi(next_arg);

	if (chgrp_link_free(node, linknum) < 0)
		command_printf(s, "Cannot free this link\n");
	DEBUG(LOG_INFO, "chgrp=%s, linknum=%d", node->chgrpname, linknum);
}

static void
chgrp_command_node_delete(int s, char *name, __attribute__ ((unused))void *evt)
{
	struct chgrp_node *node;
	char *chgrpname;

	/* Parse the node name */
	if ((chgrpname = strtok(name, " ")) == NULL) {
		command_printf(s, "Error: <channel-group-name> is missing.\n");
		return;
	}
	node = chgrp_node_lookup_by_chgrpname(chgrpname);
	if (node == NULL) {
		command_printf(s, "Error: channel group '%s' doesn't exists.\n", chgrpname);
		return;
	}

	chgrp_node_destroy(node);
	command_printf(s, "channel group '%s' is deleted.\n", chgrpname);
	DEBUG(LOG_INFO, "channel group '%s' is deleted\n", chgrpname);
}

static const char *
mode2str (u_int32_t type)
{
	const char *str = "unknown";
	switch (type) {
	case MODE_LINK_ON:
		str = "static";
		break;
	case MODE_LINK_LACP_ACTIVE:
		str = "active";
		break;
	case MODE_LINK_LACP_PASSIV:
		str = "passive";
		break;
	default:
		break;
	}

	return(str);
}

static const char *
algo2str (u_int32_t type)
{
	const char *str = "Default(Round-Robin)";
	switch (type) {
	case NG_ETH_GRP_ALGO_ROUND_ROBIN:
		str = "round-robin";
		break;
	case NG_ETH_GRP_ALGO_XOR_MAC:
		str = "xor-mac";
		break;
	case NG_ETH_GRP_ALGO_XOR_IP:
		str = "xor-ip";
		break;
	case NG_ETH_GRP_ALGO_BACKUP:
		str = "backup";
		break;
	case NG_ETH_GRP_ALGO_XOR_IP_PORT:
		str = "xor-ip-port";
		break;
	default:
		break;
	}

	return(str);
}

static const char *
status2str(u_int32_t status)
{
	const char *str = "unknown";

	switch (status) {
	case NG_ETH_GRP_HOOK_ACTIVE:
		str = "active";
		break;
	case NG_ETH_GRP_HOOK_INACTIVE:
		str = "inactive";
		break;
	default:
		break;
	}
	return str;
}

static void
chgrp_command_print_node(int s, struct chgrp_node* node)
{
	struct chgrp_link *link;
	int i;
	command_printf(s, " EtherGroup %s (nodename=%s)\n",
		       node->chgrpname, node->nodename);
	command_printf(s, " With dispatching policy %s, lacp-rate %s\n",
				algo2str(node->algo),
				(node->lacp_rate == LACP_FAST) ? "fast" : "slow");

	for (i = 0; i < NG_ETH_GRP_MAX_LINKS; i ++) {
		link = node->link[i];
		if (link == NULL)
			continue;
		command_printf(s, "\t link_%d is connected to %s mode %s",
			       link->linknum, link->ifname, mode2str(link->mode));
		if (link->priority != NG_ETH_GRP_DEFAULT_PRIO)
			command_printf(s, " priority %d", link->priority);

		command_printf(s, " status %s (RUNNING=%d UP=%d)\n",
			       status2str(link->status),
			       !!(link->if_flags & IFF_RUNNING),
			       !!(link->if_flags & IFF_UP));
		command_printf(s, "\t   actor lacp-rate is %s, parter lacp-rate is %s\n",
			       link->lp_state & LACP_STATE_TIMEOUT ? "fast" : "slow",
			       link->lp_partner.lip_state & LACP_STATE_TIMEOUT ? "fast" : "slow");
	}
}

static void
chgrp_command_show_node(int s, char *args, __attribute__ ((unused))void *evt)
{
	struct chgrp_node *node;
	char *chgrpname;

	/* Parse the node name */
	if ((chgrpname = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <channel-group-name> is missing.\n");
		return;
	}
	if (strcmp("all", chgrpname)) {
		node = chgrp_node_lookup_by_chgrpname(chgrpname);
		if (node == NULL) {
			command_printf(s, "Error: channel group '%s' doesn't exist.\n", chgrpname);
			return;
		}
		chgrp_command_print_node(s, node);
	} else {
		if (LIST_FIRST(&chgrp_nodes) == NULL)
			command_printf(s, "No registered node.\n");
		else {
			LIST_FOREACH(node, &chgrp_nodes, next)
				chgrp_command_print_node(s, node);
		}
	}
}

static void
chgrp_command_show_pid(int s, __attribute__ ((unused))char *dummy,
		       __attribute__ ((unused))void *evt)
{
	command_printf(s, "Daemon pid: %d.\n", getpid());
}

static void
chgrp_command_set_loglevel(int s, char *args, __attribute__ ((unused))void *evt)
{
	int level;
	char *next_arg;

	/* Parse log level */
	if ((next_arg = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <level> is missing.\n");
		return;
	}
	level = atoi(next_arg);
	setloglevel(level);
	command_printf(s, "Set log level to %d.\n", level);
}

static void
chgrp_command_set_lacpdebug(int s, char *args, __attribute__ ((unused))void *evt)
{
	int level;
	char *next_arg;

	/* Parse LACP debug level */
	if ((next_arg = strtok(args, " ")) == NULL) {
		command_printf(s, "Error: <level> is missing.\n");
		return;
	}
	level = atoi(next_arg);
	lacp_set_lacpdebug(level);
	command_printf(s, "Enable LACP debug: to %d.\n", level);
}

#ifdef HA_SUPPORT
static void
end_graceful_callback(int fd, short event, void *arg)
{
	struct lacp_state *lacp = arg;

	DEBUG(LOG_DEBUG, "[HA] end LACP graceful period");

	/* Stop the Graceful Restart */
	lacp->graceful = 0;

	/* sync link config : dump from lacpd to VNB */
	chgrp_node_sync_to_vnb_all();
}

/* Set LACP active */
static void
lacp_has_activate(struct lacp_state *lacp, int graceful)
{
	/* Mark the active state */
	lacp->active = 1;

	/* Perform the Graceful Restart */
	if (graceful) {
		struct timeval tv;

		DEBUG(LOG_DEBUG, "[HA] LACP graceful restart");

		lacp->graceful = 1;

		/* start timer */
		event_set(&lacp->timer_evt, -1,
			  EV_TIMEOUT, (void *) end_graceful_callback, lacp);
		timerclear(&tv);
		tv.tv_sec=LACP_GRACEFUL_DELAY;
		if (event_add(&lacp->timer_evt, &tv)) {
			DEBUG(LOG_ERR, "[HA] LACP activate event_add: %s\n", strerror(errno));
		}
	}
}

/* Set LACP inactive */
static void
lacp_has_deactivate(struct lacp_state *lacp)
{
	/* Mark the inactive state */
	lacp->active = 0;

	/* Stop the Graceful Restart */
	lacp->graceful = 0;
	/* stop timer */
	event_del(&lacp->timer_evt);
}

/* Keep the old hassetactive() function pointer */
static int (* ini_hassetactive)(struct has_ctx *, struct sockaddr_un *, int *) = NULL;

/* Callback function registered for myhas->hassetactive() */
static int
lacp_hassetactive (struct has_ctx *myhas, struct sockaddr_un *from, int *fromlen)
{
	/* Activity setting related actions must wait to be ready */
#if defined(notyet)
	if (! myhas->ready)
		goto endsetactive;
#endif

	if (myhas->activityState == HA6W_ACTIVITY_STATE_ACTIVE) {
		DEBUG(LOG_DEBUG, "[HA] Activate LACP daemon - %s mode",
		      myhas->graceful ? "graceful" : "non-graceful");

		lacp_has_activate (&cur_lacp_state, myhas->graceful);
	} else if (myhas->activityState == HA6W_ACTIVITY_STATE_INACTIVE) {
		DEBUG(LOG_DEBUG, "[HA] Deactivate LACP daemon");

		lacp_has_deactivate (&cur_lacp_state);
	}

#if defined(notyet)
endsetactive:
#endif
	/* Call the original function */
	/* if from is NULL it is a dummy request originated internally */
	if (ini_hassetactive && from)
		(* ini_hassetactive) (myhas, from, fromlen);

	if (chgrp_lacpdu_dup_init() < 0) {
		DEBUG(LOG_ERR, "Unable to init lacpdu_dup\n");
	}

	/* Graceful mode is now correct, we can do the dump. */
	if (lacpd_netlink_dump() < 0) {
		DEBUG(LOG_ERR, "Unable to dump netlink\n");
		exit(LACPD_ERR_INIT);
	}

	return 0;
}
#endif

static void
terminate(__attribute__ ((unused))int sock,
	  __attribute__ ((unused))short event,
	  __attribute__ ((unused))void *arg)
{
	DEBUG(LOG_ERR, "exiting ...\n");
	close(cur_lacp_state.sock_lacpdu); /* tx socket */
	lacpd_netlink_close();
	netlink_csock_close();
	chgrp_node_destroy_all();
	lacpd_iface_destroy_all();
	command_close(csock);
	exit(0);
}

static void
lacpd_usage(const char *path)
{
	const char *cmd;

	cmd = strrchr(path, '/');
	if (!cmd)
		cmd = path;
	else
		cmd++;
	fprintf(stderr, "%s [-D] [-d log_level] [-P pid_file] "
		"[-s unix_socket_name] [-l nl_sock_buffersize]\n", cmd);
	exit(LACPD_ERR_PARAM);
}

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
	struct timeval tv;
#endif
	struct rlimit rlim;

	/* get options */
	while ((ch = getopt(argc, argv, "fP:s:l:d:DhZ:")) != -1) {
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
		case 'l':
			lacpd_nl_sockbufsiz = strtol(optarg, NULL, 0);
			break;
		case 'D':
			log_output_stderr = 1;
			break;
		case 'd':
			setloglevel(atoi(optarg));
			break;
		case 'h':
			lacpd_usage(argv[0]);
			break;

			/* High Availability srvname */
		case 'Z':
#ifdef HA_SUPPORT
			has_srvname = optarg;
#endif
			break;

		default:
			fprintf(stderr, "Unknown option.\n");
			lacpd_usage(argv[0]);
		}
	}

	/* open syslog infomation. */
	openlog("LACPD", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	DEBUG(LOG_INFO, "-- Start LACP daemon at -- \n");

	if (foreground == 0) {
		if (daemon(0, 0) < 0) {
			DEBUG(LOG_ERR, "Unable to lanch the daemon\n");
			exit(LACPD_ERR_DAEMON);
		}
	}

	nlmsg_set_default_size(BUFSIZ);
	/* initialization */
	event_init();

	if (chgrp_vnb_init() < 0)
		exit(LACPD_ERR_INIT);
	if (chgrp_node_init() < 0)
		exit(LACPD_ERR_INIT);
	if (lacpd_iface_init() < 0)
		exit(LACPD_ERR_INIT);

	csock = command_init("lacpd> ", chgrp_command_table,
			     sizeof(chgrp_command_table) / sizeof(struct command_table),
			     LACPD_COMMAND_PORT, sock_name);
	if (csock == NULL) {
		DEBUG(LOG_ERR, "Unable to open user interface\n");
		exit(LACPD_ERR_INIT);
	}


	/* Init high availability support */
#ifdef HA_SUPPORT
	rc = has_init(HA6W_COMP_LACP, &myhas, has_srvname,
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
	/* bypass original has_setactive callback */
	ini_hassetactive = myhas->hassetactive;
	myhas->hassetactive = lacp_hassetactive;

	/* initially : not in active state */
	cur_lacp_state.active = 0;

	/* graceful restart : except if explicit not graceful */
	if (0) //for now : not graceful at startup
	{
		/* Perform the Graceful Restart */
		cur_lacp_state.graceful = 1;

		/* start graceful delay */
		event_set(&cur_lacp_state.timer_evt, -1,
			EV_TIMEOUT, (void *) end_graceful_callback, &cur_lacp_state);
		timerclear(&tv);
		tv.tv_sec=LACP_GRACEFUL_DELAY;
		event_add(&cur_lacp_state.timer_evt, &tv);
	}
#endif

	if (lacpd_netlink_init(lacpd_nl_sockbufsiz) < 0) {
		DEBUG(LOG_ERR, "Unable to init netlink\n");
		exit(LACPD_ERR_INIT);
	}

	if (netlink_csock_init(LACP_DEFAULT_SOCKBUFSIZ) < 0) {
		DEBUG(LOG_ERR, "Unable to init netlink\n");
		exit(LACPD_ERR_INIT);
	}

#ifndef HA_SUPPORT
	/* In HA mode, give a chance to the HA framework to set the
	   graceful mode. To do so, the netlink dump is delayed in
	   lacp_hassetactive. */
	if (lacpd_netlink_dump() < 0) {
		DEBUG(LOG_ERR, "Unable to dump netlink\n");
		exit(LACPD_ERR_INIT);
	}
#endif

	/* dump current PID */
	if ((pidfp = fopen(pid_file?:LACPD_PIDFILE, "w")) != NULL) {
		DEBUG(LOG_DEBUG, "success open %d\n",getpid());
		fprintf(pidfp, "%d\n", getpid());
		fclose(pidfp);
	}
	/* tx socket */
	cur_lacp_state.sock_lacpdu = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_SLOW));

	/* register signal handlers. */
	signal_set(&evt_sigterm, SIGTERM, terminate, (void *)SIGTERM);
	signal_add(&evt_sigterm, NULL);
	signal_set(&evt_sigint, SIGINT, terminate, (void *)SIGINT);
	signal_add(&evt_sigint, NULL);

	signal(SIGPIPE, SIG_IGN); /* may happen on admin sock */

	/* set max open file */
	rlim.rlim_cur = LACP_MAX_OPEN_FILES;
	rlim.rlim_max = LACP_MAX_OPEN_FILES;
	if (setrlimit(RLIMIT_NOFILE, &rlim) != 0)
		DEBUG(LOG_ERR, "setrlimit error: %s\n",strerror(errno));
	/* Infinite loop */
	event_dispatch();
	return 0;
}
