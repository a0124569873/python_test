/*
 * Copyright 2003-2013 6WIND S.A.
 */

#include "ngctl.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>


#define BUF_SIZE	4096
#define UNNAMED     "<unnamed>"

#define STATS_INDENT "     "

static int GetStats(int ac, char **av);
static int GetNodeStats(char *path, int recursive, void *visited, char *fromhook);

const struct ngcmd getstats_cmd = {
	GetStats,
	"getstats path [recurse_opt] [verbose]",
	"Send a netgraph getstats control message to the node at \"path\".",
	"The stats are displayed in a human readable form. The option"
	" \"recurse_opt\" requires to recursively follow connected hooks"
	" and display statistics of crossed nodes. Its possible values are:"
	" recursive (follow all hooks), up (follow only hooks from lower"
	" to upper network layers), down (follow only hooks from upper to"
	" lower network layers). The verbose option requires to also display"
	" crossed nodes that do not provide stats.",
	{ "dumpstats" }
};

/*
 * functions to manage list of visited nodes
 * -----------------------------------------
 */
static void * init_visited(void);
static int add_visited(ng_ID_t id, void *visited);
static int free_visited(void *visited);
static int was_visited(ng_ID_t id, void *visited);

/*
 * stuff to handle node type-specific functions
 * --------------------------------------------
 */
/* functions to determinate direction of links between netgraph nodes */
typedef int (*GETDIR_FUNC)(struct nodeinfo *, struct linkinfo *, int);

static int get_direction_ask_peer(struct nodeinfo *node, struct linkinfo *link);

/* functions to determinate getstats command exceptions */
typedef int (*GETSTAT_FUNC)(struct nodeinfo *, struct linkinfo *);

/* structure that stores pointers to functions handling a node type */
struct node_funcs
{
	GETSTAT_FUNC  getstat_func;
	GETDIR_FUNC   getdir_func;
};

/* determinate functions specific to a node type */
static int lookup_node_funcs(char *type, struct node_funcs *node_funcs);

/*
 * flags for recursive display of connected nodes
 * ----------------------------------------------
 */
/* navigate from lower to upper layer nodes / hook connected to upper layer */
#define HOOK_UPPER_LAYER   1
/* navigate from upper to lower layer nodes / hook connected to lower layer */
#define HOOK_LOWER_LAYER   2

/* navigate regardless of network layers / hook connected to  */
#define HOOK_ANY_LAYER     (HOOK_UPPER_LAYER|HOOK_LOWER_LAYER)
#define HOOK_UNKNOWN_LAYER HOOK_ANY_LAYER

/* verbose display */
#define VERBOSE_DISPLAY    4

static int divert_stdout(FILE **pread_pipe, FILE **preal_stdout);
static int restore_stdout(FILE *read_pipe, FILE *real_stdout);

/*
 * Main function for getstats command
 */
static int
GetStats(int ac, char **av)
{
	char *path;
	int recursive = 0;
	void *visited;

#ifdef GETSTATS_DEBUG
	{
	int i;
	printf("%s", __FUNCTION__);

	for (i=0; i<ac; i++)
		printf(" %s", av[i]);
	printf("\n");
	}
#endif

	/* Get arguments */
	if (ac < 2)
		return(CMDRTN_USAGE);
	path = av[1];

	ac -= 2; av += 2; /* point on options */

	while (ac) {
		if (strcmp(av[0], "recursive") == 0)
			recursive |= HOOK_ANY_LAYER;

		else if (strcmp(av[0], "up") == 0)
			recursive |= HOOK_UPPER_LAYER;

		else if (strcmp(av[0], "down") == 0)
			recursive |= HOOK_LOWER_LAYER;

		else if (strcmp(av[0], "verbose") == 0)
			recursive |= VERBOSE_DISPLAY;

		ac--; av++;
	}

#ifdef GETSTATS_DEBUG
	printf("path=%s recursive=%d\n", path, recursive);
#endif

	visited = init_visited();

	GetNodeStats(path, recursive, visited, "");

	free_visited(visited);

	/* Done */
	return(CMDRTN_OK);
}

/*
 * Recursive function that displays netgraph node statistics.
 * The list of visited nodes guaranties that recursion will stop.
 * In the worst case, all netgraph nodes will be visited.
 *
 * path:      path to the start node
 * recursive: flags to indicate if recursion should occur
 *            0                : no recursion
 *            HOOK_UPPER_LAYER : recursion from lower to upper layers
 *            HOOK_LOWER_LAYER : recursion from upper to lower layers
 *            HOOK_ANY_LAYER   : recursion in all directions
 * visited:   context that lists nodes that where already visited
 * fromhook:  local hook via which we reached the current node
 */
static int
GetNodeStats(char *path, int recursive, void *visited, char *fromhook)
{
	u_char rbuf[16 * 1024];
	struct ng_mesg *const resp = (struct ng_mesg *) rbuf;
	struct hooklist *const hlist = (struct hooklist *) resp->data;
	struct nodeinfo *const ninfo = &hlist->nodeinfo;
	char id[sizeof("[00000000]:")];
	unsigned k;
	struct node_funcs funcs;


#ifdef GETSTATS_DEBUG
	printf(__FUNCTION__"(%s, %d, 0x%x, 0x%x)\n", path, recursive, visited, fromhook);
#endif

	/* Get node info and hook list */
	if (NgSendMsg(csock, path, NGM_GENERIC_COOKIE,
	    NGM_LISTHOOKS, NULL, 0) < 0) {
		warn("send msg");
		return(CMDRTN_ERROR);
	}
	if (NgRecvMsg(csock, resp, sizeof(rbuf), NULL) < 0) {
		warn("recv msg");
		return(CMDRTN_ERROR);
	}

	/* Show node information */
	if (!*ninfo->name)
		snprintf(ninfo->name, sizeof(ninfo->name), "%s", UNNAMED);

	/* If node was already visited, return */
	if (recursive && was_visited(ninfo->id, visited))
	{
#ifdef GETSTATS_DEBUG
		printf("%s: node %s already visited\n", __FUNCTION__, ninfo->name);
#endif
		return(CMDRTN_OK);
	}

	lookup_node_funcs(ninfo->type, &funcs);

	if ((recursive & VERBOSE_DISPLAY) || funcs.getstat_func)
		printf("Name: %-15s Type: %-15s ID: %08x\n",
		ninfo->name, ninfo->type, ninfo->id);

	if (funcs.getstat_func)
		(*funcs.getstat_func)(ninfo, hlist->link);

	if (recursive)
	{
		/* Get stats for all nodes connected to our hooks */
		add_visited(ninfo->id, visited);

		/* Add current node to visited nodes list */
		for (k = 0; k < ninfo->hooks; k++) {
			struct linkinfo *const link = &hlist->link[k];

			if (strcmp(link->ourhook, fromhook))
			{
				if (recursive & (*funcs.getdir_func)(ninfo, link, 0))
				{
					sprintf(id, "[%x]:", link->nodeinfo.id);
#ifdef GETSTATS_DEBUG
					printf("%s: following hook %s:%s\n", __FUNCTION__, ninfo->name, link->peerhook);
#endif
					GetNodeStats(id, recursive, visited, link->peerhook);
				}
#ifdef GETSTATS_DEBUG
				else
					printf("%s: Hook %s is not connected to required direction\n", __FUNCTION__, link->ourhook);

#endif
			}
#ifdef GETSTATS_DEBUG
			else
				printf("%s: I will not follow hook %s back\n", __FUNCTION__, fromhook);
#endif
		}
	}

	return(CMDRTN_OK);
}

static int
generic_getstats(struct nodeinfo *ninfo,
		 __attribute__((unused)) struct linkinfo *linktab)
{
	char id[sizeof("[00000000]:")];
	char *argv[3]; /* arguments sent to DoCommand */

	/* Display stats for this node */
	sprintf(id, "[%x]:", ninfo->id);
	argv[0]="msg";
	argv[1]=id;
	argv[2]="getstats";

	return(DoCommand(3, argv));
}

static int
etf_getstats(struct nodeinfo *ninfo,
	     __attribute__((unused)) struct linkinfo *linktab)
{
	char id[sizeof("[00000000]:")];
	char *argv[3]; /* arguments sent to DoCommand */

	/* Display stats for this node */
	sprintf(id, "[%x]:", ninfo->id);
	argv[0]="msg";
	argv[1]=id;
	argv[2]="getstatus";

	return(DoCommand(3, argv));
}

static int
bridge_getstats(struct nodeinfo *ninfo, struct linkinfo *linktab)
{
	char id[sizeof("[00000000]:")];
	char *argv[4]; /* arguments sent to DoCommand */
	int k;

	/* The bridge getstats command requires a parameter, a link number.
	 * Here, we display stats for all connected links */
	sprintf(id, "[%x]:", ninfo->id);

	argv[0]="msg";
	argv[1]=id;
	argv[2]="getstats";

	for (k = ninfo->hooks - 1; k>=0; k--) {
		/* Display stats for this node and this link */
		argv[3]=&(linktab[k].ourhook[sizeof("link") - 1]);

		printf("- Hook: %s PeerHook: %s PeerName: %s PeerType: %-s\n",
			linktab[k].ourhook, linktab[k].peerhook, linktab[k].nodeinfo.name,
			linktab[k].nodeinfo.type);
		DoCommand(4, argv);
	}
	return(CMDRTN_OK);
}

static int
ppp_getstats(struct nodeinfo *ninfo, struct linkinfo *linktab)
{
	char id[sizeof("[00000000]:")];
	char *argv[4]; /* arguments sent to DoCommand */
	int k;

	/* The bridge getstats command requires a parameter, a link number.
	 * Here, we display stats for all connected links */
	sprintf(id, "[%x]:", ninfo->id);

	argv[0]="msg";
	argv[1]=id;
	argv[2]="getstats";

	for (k = ninfo->hooks - 1; k>=0; k--) {
		if (strncmp(linktab[k].ourhook, "link", 4) == 0)
		{
			/* Display stats for this node and this link */
			argv[3]=&(linktab[k].ourhook[sizeof("link") - 1]);

			printf("- Hook: %s PeerHook: %s PeerName: %s PeerType: %-s\n",
				linktab[k].ourhook, linktab[k].peerhook,
				linktab[k].nodeinfo.name, linktab[k].nodeinfo.type);
			DoCommand(4, argv);
		}
	}
	return(CMDRTN_OK);
}

static int
bpf_getstats(struct nodeinfo *ninfo, struct linkinfo *linktab)
{
	char id[sizeof("[00000000]:")];
	char *argv[4]; /* arguments sent to DoCommand */
	char hookname[NG_HOOKLEN + 3];
	int k;

	/* The bpf getstats command requires a parameter, a hook name.
	 * Here, we display stats for all connected hooks */
	sprintf(id, "[%x]:", ninfo->id);

	argv[0]="msg";
	argv[1]=id;
	argv[2]="getstats";
	argv[3]=hookname;

	for (k = ninfo->hooks - 1; k>=0; k--) {
		/* Display stats for this node and this link */
		sprintf(hookname, "\"%s\"", linktab[k].ourhook);

		printf("- Hook: %s PeerHook: %s PeerName: %s PeerType: %-s\n",
			linktab[k].ourhook, linktab[k].peerhook, linktab[k].nodeinfo.name,
			linktab[k].nodeinfo.type);
		DoCommand(4, argv);
	}
	return(CMDRTN_OK);
}

static int
pppoe_getstats(struct nodeinfo *ninfo,
	       __attribute__((unused)) struct linkinfo *linktab)
{
	char id[sizeof("[00000000]:")];
	char *argv[3]; /* arguments sent to DoCommand */

	/* Display stats for this node */
	sprintf(id, "[%x]:", ninfo->id);
	argv[0]="msg";
	argv[1]=id;
	argv[2]="status";

	return(DoCommand(3, argv));
}

static int rfc1483_reformat(FILE *f_in, FILE *f_out);

static int
rfc1483_getstats(struct nodeinfo *ninfo,
		 __attribute__((unused)) struct linkinfo *linktab)
{
	char id[sizeof("[00000000]:")];
	char *argv[2]; /* arguments sent to DoCommand */
	FILE *read_pipe = NULL, *old_stdout = NULL;
	int ret;

	/* Display stats for this node */
	sprintf(id, "[%x]:", ninfo->id);
	argv[0]="status";
	argv[1]=id;

	/* divert stdout so that output may be reformatted */
	ret = divert_stdout(&read_pipe, &old_stdout);
	if (ret != CMDRTN_OK)
		goto end;

	/* request stats and reformat them */
	ret = DoCommand(2, argv);
	if (ret == CMDRTN_OK)
		rfc1483_reformat(read_pipe, old_stdout);

	/* restore stdout */
	restore_stdout(read_pipe, old_stdout);

end:
	return(ret);
}

/*
 * Function to handle list of visited nodes
 */
struct visited
{
	struct visited * next;
	ng_ID_t		id;
};

static void *
init_visited(void)
{
	return(calloc(1, sizeof(struct visited*)));
}

#ifdef GETSTATS_DEBUG
void
dump_visited(void *visited)
{
	struct visited *elm;

	for (elm = *(struct visited **)visited; elm; elm = elm->next)
		printf("%08x ", elm->id);

	printf("\n");
}
#endif

static int
add_visited(ng_ID_t id, void *visited)
{
	struct visited *elm;

#ifdef GETSTATS_DEBUG
	printf("%s: adding %08x to visited nodes\n", __FUNCTION__, id);
#endif

	elm = (struct visited *)calloc(1, sizeof(struct visited));

	elm->id = id;
	elm->next = *(struct visited **)visited;

	*(struct visited **)visited = elm;

#ifdef GETSTATS_DEBUG
	dump_visited(visited);
#endif

	return(0);
}

static int
free_visited(void *visited)
{
	struct visited *elm, *elm_next;

	for (elm = *(struct visited **)visited; elm; elm = elm_next)
	{
		elm_next = elm->next;
		free(elm);
	}
	free(visited);

	return(0);
}

static int
was_visited(ng_ID_t id, void *visited)
{
	struct visited *elm;

	for (elm = *(struct visited **)visited; elm; elm = elm->next)
		if (elm->id == id)
			return(1);

	return(0);
}

/*
 * The following functions return the direction of the link, i.e. if it is
 * connected to an upper or lower layer.
 * (HOOK_UPPER_LAYER HOOK_LOWER_LAYER HOOK_UNKNOWN_LAYER)
 */
/*
 * node:  current node
 * link:  link (hook) to the peer node
 * flags: flags for the get_direction function
 */
/* flags */
/* when a node cannot make out if its link is connected to upper or lower
 * layer, it may ask the connected node and invert the answer. The flag
 * DONT_ASK_PEERNODE avoids loops by preventing the peer node to ask back
 */
#define DONT_ASK_PEERNODE 1

static int
generic_get_direction(struct nodeinfo *node,
		      __attribute__((unused)) struct linkinfo *link, int flags)
{
	/* unknown node type => ask peer hook */
	if ((flags & DONT_ASK_PEERNODE) == 0)
		return(get_direction_ask_peer(node, link));
	else
		return(HOOK_UNKNOWN_LAYER);
}

static int
eiface_get_direction(__attribute__((unused)) struct nodeinfo *node,
		     __attribute__((unused)) struct linkinfo *link,
		     __attribute__((unused)) int flags)
{
	/* eiface nodes provide 1 hook named "ether", which connects to lower layer */
	return(HOOK_LOWER_LAYER);
}

static int
bridge_get_direction(struct nodeinfo *node,
		     __attribute__((unused)) struct linkinfo *link,
		     __attribute__((unused)) int flags)
{
	/* bridge nodes provide an unlimited number of hooks, named "linkX".
	 * Only the linked node knowns what is the direction of the link */

	if ((flags & DONT_ASK_PEERNODE) == 0)
		return(get_direction_ask_peer(node, link));
	else
		return(HOOK_UNKNOWN_LAYER);
}

static int
vlan_get_direction(__attribute__((unused)) struct nodeinfo *node,
		   __attribute__((unused)) struct linkinfo *link,
		   __attribute__((unused)) int flags)
{
	/* vlan nodes provide an unlimited number of hooks, named "link_X".
	 * Only the type of the linked node or the name of the remote hook can
	 * give an indication of the direction */

	/* if linked node is of type etf, then this hook connects to lower layer.
	 * otherwise, assume it is upper layer */
	if (strcmp(link->nodeinfo.type, "etf") == 0)
		return(HOOK_LOWER_LAYER);
	else
		return(HOOK_UPPER_LAYER);
}

static int
etf_get_direction(__attribute__((unused)) struct nodeinfo *node,
		  struct linkinfo *link,
		  __attribute__((unused)) int flags)
{
	/* etf nodes provide an unlimited number of hooks. Two specific hooks,
	 * named "downstream" and "nomatch", connect to lower layer. Other hooks
	 * connect to upper layers */

	if ((strcmp(link->ourhook, "downstream") == 0) ||
	    (strcmp(link->ourhook, "nomatch"   ) == 0))
		return(HOOK_LOWER_LAYER);
	else
		return(HOOK_UPPER_LAYER);
}

static int
ether_get_direction(__attribute__((unused)) struct nodeinfo *node,
		    __attribute__((unused)) struct linkinfo *link,
		    __attribute__((unused)) int flags)
{
	/* ether nodes are terminal nodes, located at lower layers. All of
	 * their hooks connect to upper layers */
	return(HOOK_UPPER_LAYER);
}

static int
iface_get_direction(__attribute__((unused)) struct nodeinfo *node,
		    __attribute__((unused)) struct linkinfo *link,
		    __attribute__((unused)) int flags)
{
	/* iface nodes are terminal nodes, located at upper layers. All of
	 * their hooks connect to upper layers */
	return(HOOK_LOWER_LAYER);
}

static int
socket_get_direction(__attribute__((unused)) struct nodeinfo *node,
		     __attribute__((unused)) struct linkinfo *link,
		     __attribute__((unused)) int flags)
{
	/* socket nodes are terminal nodes, located at upper layers. All of
	 * their hooks connect to lower layers */
	return(HOOK_LOWER_LAYER);
}

static int
ksocket_get_direction(__attribute__((unused)) struct nodeinfo *node,
		      __attribute__((unused)) struct linkinfo *link,
		      __attribute__((unused)) int flags)
{
	/* ksocket nodes are terminal nodes, located at lower layers. All of
	 * their hooks connect to upper layers */
	return(HOOK_UPPER_LAYER);
}

static int
vjc_get_direction(__attribute__((unused)) struct nodeinfo *node,
		  __attribute__((unused)) struct linkinfo *link, int flags)
{
	/* vjc nodes provide an unlimited number of hooks. When they receive data
	 * from a hook, they process it and send it back by the same hook. In case
	 * several nodes are connected to the same vjc node, data will not enter
	 * via a hook and exit via another hook */

	/* If function is called to determine if a hook should be followed, reply
	 * no.
	 * If function is called to help another node to determinate the direction
	 * of a link pointing to me, then reply "any direction". In fact, the vjc
	 * node is located at the same layer as the calling node */
	if (flags & DONT_ASK_PEERNODE)
		return(HOOK_ANY_LAYER);
	else
		return(0);
}

static int
l2tp_get_direction(__attribute__((unused)) struct nodeinfo *node,
		   struct linkinfo *link,
		   __attribute__((unused)) int flags)
{
	/* l2tp nodes provide an unlimited number of hooks. The ctrl hook is
	 * connected to a control socket. The lower hook is connected to the
	 * lower layer (an udp ksocket). Other hooks are connected to upper
	 * layers (L2TP sessions */
	if (strcmp(link->ourhook, "ctrl") == 0)
		return(0); /* return(HOOK_ANY_LAYER) to always display ctrl stats) */
	if (strcmp(link->ourhook, "lower") == 0)
		return(HOOK_LOWER_LAYER);
	else
		return(HOOK_UPPER_LAYER);
}

static int
pppoe_get_direction(__attribute__((unused)) struct nodeinfo *node,
		    struct linkinfo *link,
		    __attribute__((unused)) int flags)
{
	/* pppoe nodes provide an unlimited number of hooks. The ethernet hook is
	 * connected to the ethernet physical interface. The other hooks are
	 * connected to the upper layer (typically a ppp node). A debug hook is
	 * also supported by not used */
	if (strcmp(link->ourhook, "ethernet") == 0)
		return(HOOK_LOWER_LAYER);
	if (strcmp(link->ourhook, "debug") == 0)
		return(0);
	else
		return(HOOK_UPPER_LAYER);
}

static int
ppp_get_direction(__attribute__((unused)) struct nodeinfo *node,
		  struct linkinfo *link,
		  __attribute__((unused)) int flags)
{
	/* ppp nodes provide several hooks. The inet and ipv6 hooks are connected
	 * to a bpf node that filters IPv4 and IPv6 paquets, and represent the lower
	 * layer. The bypass hook is connected to a socket XXX. The vjc_* hooks are
	 * are connected to a vjc node that performs Van Jacobson compression. The
	 * link* hooks connect to the lower layer. */
	if (strncmp(link->ourhook, "link", 4) == 0)
		return(HOOK_LOWER_LAYER);

	if ((strncmp(link->ourhook, "vjc_", 4) == 0) ||
	    (strcmp(link->ourhook, "compress"  ) == 0) ||
	    (strcmp(link->ourhook, "decompress") == 0) ||
	    (strcmp(link->ourhook, "encrypt"   ) == 0) ||
	    (strcmp(link->ourhook, "decrypt"   ) == 0) )
		return(HOOK_ANY_LAYER);

	/* hooks: inet inet6 atalk ipx bypass */
	else
		return(HOOK_UPPER_LAYER);
}

static int
bpf_get_direction(struct nodeinfo *node, struct linkinfo *link, int flags)
{
	/* bpf nodes provide an unlimited number of hooks, with arbitrary names.
	 * Only the linked node knowns what is the direction of the link */

	if ((flags & DONT_ASK_PEERNODE) == 0)
		return(get_direction_ask_peer(node, link));
	else
		return(HOOK_UNKNOWN_LAYER);
}

static int
async_get_direction(struct nodeinfo *node, struct linkinfo *link, int flags)
{
	/* async nodes provide two hooks sync and async. Only the linked node
	 * knowns what is the direction of the link */

	if ((flags & DONT_ASK_PEERNODE) == 0)
		return(get_direction_ask_peer(node, link));
	else
		return(HOOK_UNKNOWN_LAYER);
}

static int
cisco_get_direction(__attribute__((unused)) struct nodeinfo *node,
		    struct linkinfo *link,
		    __attribute__((unused)) int flags)
{
	/* cisco nodes provide five hooks downstream, inet, inet6, atalk and ipx.
	 * the downstream hook connects to a lower layer synchronous interface.
	 * Other hooks connect to upper layers */

	if (strcmp(link->ourhook, "downstream") == 0)
		return(HOOK_LOWER_LAYER);
	else
		return(HOOK_UPPER_LAYER);
}

static int
teredo_get_direction(__attribute__((unused)) struct nodeinfo *node,
		     struct linkinfo *link,
		     __attribute__((unused)) int flags)
{
	/* teredo nodes provide three hooks downstream, upstream, and secondary.
	 * the upstream hook connects to an upper layer point-to-point interface.
	 * Other hooks connect to lower layers */

	if (strcmp(link->ourhook, "upstream") == 0)
		return(HOOK_UPPER_LAYER);
	else
		return(HOOK_LOWER_LAYER);
}

static int
frame_relay_get_direction(__attribute__((unused)) struct nodeinfo *node,
			  struct linkinfo *link,
			  __attribute__((unused)) int flags)
{
	/* frame nodes provide an unlimited number of hooks, a downstream hook,
	 * and a dlciX hook per virtual channel.
	 * The downstream hook connects to a lower layer synchronous interface.
	 * Other hooks connect to upper layers */

	if (strcmp(link->ourhook, "downstream") == 0)
		return(HOOK_LOWER_LAYER);
	else
		return(HOOK_UPPER_LAYER);
}

static int
hole_get_direction(__attribute__((unused)) struct nodeinfo *node,
		   __attribute__((unused)) struct linkinfo *link, int flags)
{
	/* hole nodes support an unlimited number of hooks. These hooks receive
	 * data and discard it. They are end nodes */

	/* If function is called to determine if a hook should be followed, reply
	 * no (hole nodes are end nodes).
	 * If function is called to help another node to determinate the direction
	 * of a link pointing to me, then reply "I don't know". hole nodes may be
	 * indifferently located at upper or lower layer */
	if (flags & DONT_ASK_PEERNODE)
		return(HOOK_UNKNOWN_LAYER);
	else
		return(0);
}

static int
rfc1483_get_direction(__attribute__((unused)) struct nodeinfo *node,
		      struct linkinfo *link,
		      __attribute__((unused)) int flags)
{
	/* rfc1483 nodes support 5 hooks: downlink, ppp, inet, inet6, bridged_mode.
	 * The downlink hook connects to lower layer (ATM PVC), other hooks are
	 * are connected to upper layers */
	if (strcmp(link->ourhook, "downstream") == 0)
		return(HOOK_LOWER_LAYER);
	else
		return(HOOK_UPPER_LAYER);
}

/*
 * Return functions handling that type of node
 */
static int
lookup_node_funcs(char *type, struct node_funcs *funcs)
{
	/* most nodes do not provide stats */
	funcs->getstat_func = NULL;
	/* the following function uses the classical "msg getstats" command */
	//funcs->getstat_func = generic_getstats;

	if (strcmp(type, "eiface") == 0)
		funcs->getdir_func  = eiface_get_direction;

	else if (strcmp(type, "bridge") == 0)
	{
		funcs->getdir_func  = bridge_get_direction;
		funcs->getstat_func = bridge_getstats;
	}

	else if (strcmp(type, "vlan") == 0)
	{
		funcs->getdir_func  = vlan_get_direction;
		funcs->getstat_func = generic_getstats;
	}

	else if (strcmp(type, "etf") == 0)
	{
		funcs->getdir_func  = etf_get_direction;
		funcs->getstat_func = etf_getstats;
	}

	else if (strcmp(type, "ether") == 0)
		funcs->getdir_func  = ether_get_direction;

	else if (strcmp(type, "iface") == 0)
		funcs->getdir_func  = iface_get_direction;

	else if (strcmp(type, "socket") == 0)
		funcs->getdir_func  = socket_get_direction;

	else if (strcmp(type, "ksocket") == 0)
		funcs->getdir_func  = ksocket_get_direction;

	else if (strcmp(type, "vjc") == 0)
		funcs->getdir_func  = vjc_get_direction;

	else if (strcmp(type, "l2tp") == 0)
	{
		funcs->getdir_func  = l2tp_get_direction;
		funcs->getstat_func = generic_getstats;
	}

	else if (strcmp(type, "pppoe") == 0)
	{
		funcs->getdir_func  = pppoe_get_direction;
		funcs->getstat_func = pppoe_getstats;
	}

	else if (strcmp(type, "ppp") == 0)
	{
		funcs->getdir_func  = ppp_get_direction;
		funcs->getstat_func = ppp_getstats;
	}

	else if (strcmp(type, "iface_ppp") == 0)
		funcs->getdir_func  = eiface_get_direction;

	else if (strcmp(type, "bpf") == 0)
	{
		funcs->getdir_func  = bpf_get_direction;
		funcs->getstat_func  = bpf_getstats;
	}

	else if (strcmp(type, "async") == 0)
	{
		funcs->getdir_func  = async_get_direction;
		funcs->getstat_func = generic_getstats;
	}
	else if (strcmp(type, "cisco") == 0)
	{
		funcs->getdir_func  = cisco_get_direction;
		funcs->getstat_func = generic_getstats;
	}
	else if (strcmp(type, "teredo") == 0)
	{
		funcs->getdir_func  = teredo_get_direction;
		funcs->getstat_func = generic_getstats;
	}
	else if (strcmp(type, "rfc1483") == 0)
	{
		funcs->getdir_func  = rfc1483_get_direction;
		funcs->getstat_func = rfc1483_getstats;
	}

	else if (strcmp(type, "frame_relay") == 0)
		funcs->getdir_func  = frame_relay_get_direction;

	else if (strcmp(type, "hole") == 0)
		funcs->getdir_func  = hole_get_direction;

	else
		funcs->getdir_func  = generic_get_direction;

	return(0); /* XXX */
}

static int
get_direction_ask_peer(struct nodeinfo *node, struct linkinfo *link)
{
	struct nodeinfo *peernode;
	struct linkinfo peerlink;
	struct node_funcs funcs;
	int direction;

	peernode = &link->nodeinfo;

	lookup_node_funcs(peernode->type, &funcs);

	memset(&peerlink, 0, sizeof(struct linkinfo));
	strcpy(peerlink.ourhook,  link->peerhook);
	strcpy(peerlink.peerhook, link->ourhook );
	memcpy(&peerlink.nodeinfo, node, sizeof(struct nodeinfo));

	direction = (*funcs.getdir_func)(peernode, &peerlink, DONT_ASK_PEERNODE);

	/* reverse direction */
	if ((direction == HOOK_LOWER_LAYER) || (direction == HOOK_UPPER_LAYER))
		direction ^= HOOK_LOWER_LAYER|HOOK_UPPER_LAYER;

	return(direction);
}

/* All what is sent to stdout is diverted so that it can be read on read_pipe.
 * real_stdout can be used to really output data */
static int
divert_stdout(FILE **pread_pipe, FILE **preal_stdout)
{
	int pipe_fd[2] = {-1, -1};
	int error = CMDRTN_ERROR;
	int saved_stdout;
	FILE * read_pipe, * real_stdout;

	read_pipe   = NULL;
	real_stdout = NULL;

	/* duplicate stdout */
	if ((saved_stdout = dup(STDOUT_FILENO)) < 0) {
		warn("dup stdout");
		goto end;
	}

	/* create a non-blocking pipe */
	if (pipe(pipe_fd) < 0) {
		warn("create pipe");
		goto end;
	}
	fcntl(pipe_fd[0], F_SETFL, O_NONBLOCK);
	fcntl(pipe_fd[1], F_SETFL, O_NONBLOCK);

	/* connect write end of pipe to standard out */
	if (dup2(pipe_fd[1], STDOUT_FILENO) < 0) {
		warn("dup2 pipe_out");
		goto end;
	}

	close(pipe_fd[1]);
	pipe_fd[1] = -1;

	real_stdout = fdopen(saved_stdout, "w");
	if (real_stdout == NULL)
	{
		warn("fdopen real_stdout");
		goto end;
	}
	read_pipe   = fdopen(pipe_fd[0], "r");
	if (read_pipe == NULL)
	{
		warn("fdopen read_pipe");
		goto end;
	}

	/* set pipe to bufferize data until a complete line is available */
#if defined __linux__
	setlinebuf(stdout);
	setlinebuf(read_pipe);
#else
	if (setlinebuf(stdout) < 0)
	{
		warn("setlinebuf stdout");
		goto end;
	}
	if (setlinebuf(read_pipe) < 0)
	{
		warn("setlinebuf read_pipe");
		goto end;
	}
#endif

	*pread_pipe = read_pipe;
	*preal_stdout = real_stdout;

	error = CMDRTN_OK;

end:
	if (error != CMDRTN_OK)
	{
		if (pipe_fd[0] != -1)
			close(pipe_fd[0]);
		if (pipe_fd[1] != -1)
			close(pipe_fd[1]);
		// be sure stdin and stdout are restored
		if (saved_stdout != -1)
		{
			dup2(saved_stdout, STDOUT_FILENO);
			close(saved_stdout);
		}
		if (real_stdout)
			fclose(real_stdout);
		if (read_pipe)
			fclose(read_pipe);
	}

	return(error);
}

static int
restore_stdout(FILE *read_pipe, FILE *real_stdout)
{
	fclose(read_pipe);

	dup2(fileno(real_stdout), STDOUT_FILENO);

	fclose(real_stdout);

	return(CMDRTN_OK);
}

static int
rfc1483_reformat(FILE *f_in, FILE *f_out)
{
	/* We assume that lines are always shorter than buffer size */
#define REFORMAT_BUFSIZ 2048
#define SCANF_FORMAT "%2047[^\n]"
	char buf[REFORMAT_BUFSIZ];
	int state;

/* States
              "Status"
   [ST_INIT] ------------> [ST_STATUS]
                            |     |
                            |     | "stat :"
                            |     V
                            |  [ST_STATS]
                            |     |
                        EOF |     | EOF
                            V     V
                          [ST_SUCCESS]
*/

	#define ST_INIT        0
	#define ST_SUCCESS     1
	#define ST_ERROR       2
	#define ST_STATUS      3
	#define ST_STATS       4

	state = ST_INIT;

	/* read output line by line */

	while (fscanf(f_in, SCANF_FORMAT, buf) > 0)
	{
		int dummy, remaining=0;

		/* discard all characters up to end of line (included) */
		do {
			dummy = fgetc(f_in);
			remaining++;
		} while ((dummy != '\n') && (dummy != EOF));

		if (remaining > 1)
			fprintf(stderr, "Line too long => truncated\n");

		if (!strncmp(buf, "Status", 6)) {
			state = ST_STATUS;
			goto nextline;
		}
		else if (!strncmp(buf, "stat :", 6)) {
			state = ST_STATS;
			goto nextline;
		}

		/* events handling */

		switch(state)
		{
		case ST_INIT:
			/* discard line */
			break;
		case ST_SUCCESS:
			return(CMDRTN_OK);
		case ST_ERROR:
			return(CMDRTN_ERROR);
		case ST_STATUS:
			/* do not display status information */
			break;
		case ST_STATS:
		{
			/* display stats in standard netgraph format */
			char *sep = "";
			char *statname, *statvalue, *hookname, *nextword;
			/* read hook name */
			nextword = buf;
			/* read hookname */
			hookname = strsep(&nextword, " \t\n");
			fprintf(f_out, "- Hook: %s\nArgs:   { ", hookname);
			while ((nextword) && (*nextword)) {
				/* read stat name */
				statname = strsep(&nextword, " \t\n");
				/* read stat value */
				if ((nextword) && (*nextword)) {
					statvalue = strsep(&nextword, " \t\n");
					fprintf(f_out, "%s%s=%s", sep, statname, statvalue);
				} else {
					fprintf(f_out, "%s%s=?", sep, statname);
				}
				sep = ", ";
			}
			fprintf(f_out, " }\n");
		}
		default:
			break;
		}

	nextline:
	  ;
	}

	return(CMDRTN_OK);
}
