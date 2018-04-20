/*
 * Copyright 2006-2013 6WIND S.A.
 */

/*
 * ng_pae netgraph node type
 *
 * The node implement the 802.11X PAE standard: Port Authentication Entities.
 *
 * It implement a Mac Frame Filter, and a EAPOL frame handler.
 *
 * It comes on the top of a ng_ether node, or a ng_ether_rmon if there is one.
 * It implement the lower/upper interface, exactly like ng_ether_rmon.
 * It maintain a Mac Address WhileList, with some states associated to each Mac address
 * in the list.
 *
 * Here is a schematic:
 *
 *      |                 ^
 *      |                 |
 *      | upperin         | lowerout                              ^
 *      V                 V                                       |
 *   --------------------------------                             |
 *   |                              |                             |
 *   |                              |-- control messages          |
 *   |         PAE_Node             |                             |
 *   |                              |-- eapoldata                 |
 *   |                              |<----------------------------|
 *   --------------------------------
 *      |                 ^
 *      | upperout        | lowerin
 *      |                 |
 *      V                 V
 *
 *  Receive path from network card is  lowerin->lowerout: this path is filtered.
 *  Transmit path to network card is lowerout->lowerin. This path goes throught without filtering.
 *  In the following, if lowerout is not connected, then the packet is sent to upperout instead,
 *  to IP layer.
 *
 *  On the receive path, the PAE port can be
 *  - Blocked    : All packets are blocked (default)
 *  - Filtered   : Packets are blocked but some rules apply concerning the forwarding decision.
 *  - Authorized : Packets can flow from lowerin to lowerout unconditionally.
 *
 *  If the node is in Blocked mode, then all the packets are dropped. Only the EAPOL packets
 *  are forwarded to the "eapoldata" hook.
 *  Then, the authenticator (or ngctl) can put the node to authorized mode. It means that all
 *  packets coming from lowerin are forwarded to lowerout.
 *   >> this is the port based authentication. The MAC source addresses are never used.
 *      It means that only one user needs to be authenticated in order to allow any other users.
 *  The node can also be set to filtered mode. In this case the MacList is used.
 *   >> it is the MAC based authentication.
 *
 *  If the eapoldata hook is connected, then all EAP packets (those with ethertype 0x888e) are
 * diverted and sent to this hook. Additionally, the EAP multicast address (ethernet destination
 * 01:80:c2:00c00c03) is added to the MULTICAST list of the underlying card, if possible by the hardware.
 * This may not be possible if the hardware does not support this or if the underlying interface
 * is virtual (eg: bnet). The "first packet exception", see below, can still be of some use in this case.
 *
 *  The node maintain a list of source mac address, each entry having the following fields:
 *  - MAC address (char[6])
 *  - Authorized (bool)
 *  - Last time seen (uint16)
 *  - Entry state : "Manual", "Negociating" "EAP-Authenticated" (enum)
 *
 *  When in "Filtered" state, the port follows the following rules on its lowerin hook:
 *  - If the packet has the "EAP" Ethertype, it is sent to eapol_data hook (if connected), else to lowerout.
 *  - If a packet has an unknown source mac address (ie: not from MacList), it is sent to the eapol_data hook.
 *      This is the First Packet exception, and allow the EAP daemon to get notified of a new station.
 *  Moreover, it is added to the MacList, with the following fields:
 *        * Authorized=0,
 *        * Last Time Seen set to current time,
 *        * Allowed count = Drop counts = 0,
 *        * Entry State = Negociating.
 *
 * -  If a packet has a known mac address, the Authorized field is checked. If 1, the packet is forwarded
 *    Otherwise, the packet is dropped and the Dropped count is incremented.
 *
 * Garbage collection (like ng_bridge.c see ng_bridge_timeout():
 *   Every 10 seconds by default,, a timer fires and parse the MacList to remove
 *  old entries (= with Last Time Seen > 10 seconds)
 *
 * All packets coming from lowerout must be sent to lowerin unconditionally, all the time.
 * All packets from upperin go to upperout without beeing filtered.
 * If the eapol_data hook is disconnected, the port stay in its current Mode. The MacList is parsed and all entries
 * marked as not "static" are removed.
 *
 * The control messages of the node are:
 * - set_port_state : Get the Blocked/Filtered/Authorized state.
 * - get_port_state(uint8) : Set the port state
 * - add_macaddr(macaddress_struct) : Add a mac address to the MacList.
 * - del_macaddr(macaddress_struct) : Remove the mac address from the MacList.
 * - dump_macaddr: Return a dump of the MacList (an array of macaddress_struct)
 * - flush_macaddr: Flush the dynamic entries, keep static ones.
 * - flush_macaddr_full: Flush all the entries of the MacList, unconditionally.
 * - set_clean_delay(uint16): Set the timer delay for MacList cleaning, in seconds
 *
 * macaddress_struct type :
 * struct macaddress {
 *    char     saddr[6];   Source Ethernet Address
 *    uint8    authorized; This address is authorized if this field is != 0
 *    uint8    state; Enum: { Negociating, Manual, EAP_Authorized }
 *    unint16  staleness: Used as an "keepalive". RO from userland tools (value is automatically updated)
 *
 *   This structure is used by add_macaddress:
 *       If the address exists in the list, the entry is updated (and the staleness set to current time).
 *       Otherwise it is created likewise.
 *   For del_macaddress, Only the Source mac address is used to lookup an entry in the MacList. If found,
 *   this entry is removed.
 */

#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/if.h>

#include <netgraph/vnblinux.h>
#include <netgraph/queue.h>
#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ether.h> /* for ethernet address parsing */
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_pae.h>
#include <netgraph/ng_ether_rmon.h>


/* Do we want statistics on hooks: used for debugging */
#define NG_PAE_SUPPORT_STATS     1

/* Debug: Disable MacList cleaning : Unset to disable maclist garbage collection */
#define NG_PAE_MACLIST_CLEAN 1

static const char   eap_mc_addr[VNB_ETHER_ADDR_LEN] = { 0x01,0x80,0xc2,0x00,0x00,0x03 };

/* Per MacAddress private data.  */
struct ng_pae_macaddress {
	u_char        saddr[VNB_ETHER_ADDR_LEN];/* ethernet address of the source */
	u_int8_t      state;   	/* Only values from ENUM */
	u_int8_t      authorized;  	/* boolean: authorized or not */
	u_int16_t     staleness; 	/* time interval host last heard from */
	LIST_ENTRY(ng_pae_macaddress) next; /* next entry */
};


/*
 * Returns the element count from an array
 */
static int
ng_pae_getTableLength(const struct ng_parse_type *type,
		      const u_char *start, const u_char *buf)
{
	struct ng_pae_macaddress_list * macaddress_list;
        macaddress_list = (struct ng_pae_macaddress_list *)(buf - sizeof(u_int32_t));
	return macaddress_list->numMacs;
}


/*
 * Per PAE Port private data
 */
struct ng_pae_port_private {
	u_int8_t   port_state;    /* Only values from ENUM */
	u_int8_t   port_behavior; /* PAE_PORT_BASED_BEHAVIOR or PAE_ADDR_BASED_BEHAVIOR */
	node_p	   node;		/* netgraph node */
	hook_p	   lowerin;
	hook_p     lowerout;     /* All hooks */
	hook_p     upperin;
	hook_p     upperout;
	hook_p     eapoldata;
#ifdef NG_PAE_SUPPORT_STATS
	struct ng_pae_port_stats port_stats;  /* Stats (optional, compile time */
#endif
	u_int16_t  timer_delay;      /* Timer delay in unit of HZ */
	u_int16_t  macaddr_expire_delay;  /* maximum age of an idel address in "Negociating" state */
	u_int16_t  current_timer_value;  /* Counter */
	struct ng_callout timer; /* The timer itself */
	LIST_HEAD(, ng_pae_macaddress) MacList;
	/*
	  struct MacListHead MacList;
	*/
};
typedef struct ng_pae_port_private * pae_p;


/* parsing functions support */

static const struct ng_parse_struct_field
ng_pae_port_stats_type_fields[] = NG_PAE_PORT_STATS_TYPE_INFO;

static const struct ng_parse_type ng_pae_port_stats_type = {
	&ng_parse_struct_type,
	&ng_pae_port_stats_type_fields
};

/* Parse type for struct ng_pae_macaddr_ary */
static const struct ng_parse_struct_field ng_pae_macaddr_type_fields[]
	= NG_PAE_MACADDR_TYPE_INFO(&ng_ether_enaddr_type);

static const struct ng_parse_type ng_pae_macaddr_type = {
	&ng_parse_struct_type,
	&ng_pae_macaddr_type_fields
};

static const struct ng_parse_array_info ng_pae_macaddr_ary_type_info = {
	&ng_pae_macaddr_type,
	ng_pae_getTableLength
};

static const struct ng_parse_type ng_pae_macaddr_ary_type = {
	&ng_parse_array_type,
	&ng_pae_macaddr_ary_type_info
};

static const struct ng_parse_struct_field ng_pae_macaddr_list_type_fields[]
= NG_PAE_MACADDR_LIST_TYPE_INFO(&ng_pae_macaddr_ary_type);

static const struct ng_parse_type ng_pae_macaddr_list_type = {
	&ng_parse_struct_type,
	&ng_pae_macaddr_list_type_fields
};


/*
 * Function to add or remove the EAP-specific multicast macaddr.
 * These functions are specific to linux.
 */
struct net_device * find_host_interface(const node_p node){
        node_p node_eth = NULL;
        pae_p priv = NG_NODE_PRIVATE(node);
        KASSERT(priv != NULL);

        if(priv->lowerin == NULL)
		return NULL;

        node_eth = NG_PEER_NODE(priv->lowerin);

        if (!node_eth) return NULL;

        while (strcmp(node_eth->type->name, NG_ETHER_RMON_NODE_TYPE) == 0) {
		node_eth = NG_PEER_NODE(ng_findhook(node_eth, NG_ETHER_RMON_HOOK_LOWERIN));
		if (node_eth == NULL)
			return NULL;
	}
        /* Here we are supposed to have an ethernet node */
        if (strcmp(node_eth->type->name, NG_ETHER_NODE_TYPE) != 0) {
		/* Unknown node type below us */
		return NULL;
        }
	return dev_get_by_name(&init_net, node_eth->name);
}

int add_eap_addr_to_interface(const node_p node)
{
	struct net_device *dev = find_host_interface(node);
	int ret;
        if (!dev) return EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
        ret = dev_mc_add_global(dev, (void *) eap_mc_addr);
#else
        ret = dev_mc_add(dev, (void *) eap_mc_addr, VNB_ETHER_ADDR_LEN, 0);
#endif
	/* release the reference on the netdev */
	dev_put(dev);

	return ret;
}

int del_eap_addr_from_interface(const node_p node)
{
	struct net_device *dev = find_host_interface(node);
	int ret;
        if (!dev) return EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
        ret = dev_mc_del_global(dev, (void *)eap_mc_addr);
#else
        ret = dev_mc_delete(dev, (void *)eap_mc_addr, VNB_ETHER_ADDR_LEN, 0);
#endif
	/* release the reference on the netdev */
	dev_put(dev);

	return ret;
}


/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_pae_cmdlist[] = {
	{
		NGM_PAE_COOKIE,
		NGM_PAE_PORT_STATE_GET,
		"get_port_state",
		NULL,
		&ng_parse_uint8_type,
	},
	{
		NGM_PAE_COOKIE,
		NGM_PAE_PORT_STATE_SET,
		"set_port_state",
		&ng_parse_uint8_type,
		NULL,
	},
	{
		NGM_PAE_COOKIE,
		NGM_PAE_GET_PORT_BEHAVIOR,
		"get_port_behavior",
		NULL,
		&ng_parse_uint8_type,
	},
	{
		NGM_PAE_COOKIE,
		NGM_PAE_SET_PORT_BEHAVIOR,
		"set_port_behavior",
		&ng_parse_uint8_type,
		NULL,
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_PORT_STATS_GET,
		"get_port_stats",
		NULL,
		&ng_pae_port_stats_type,
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_PORT_STATS_RESET,
		"reset_port_stats",
		NULL,
		NULL,
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_PORT_STATS_GET_AND_RESET,
		"get_and_reset_port_stats",
		NULL,
		&ng_pae_port_stats_type,
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_MAC_ADD,
		"add_macaddr",
		&ng_pae_macaddr_type,
		NULL
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_MAC_DEL,
		"del_macaddr",
		&ng_pae_macaddr_type,
		NULL
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_MAC_DUMP,
		"dump_macaddr",
		NULL,
		&ng_pae_macaddr_list_type,
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_MAC_FLUSH,
		"flush_macaddr",
		NULL,
		NULL
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_MAC_FULL_FLUSH,
		"flush_macaddr_full",
		NULL,
		NULL
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_SET_TIMER_DELAY,
		"set_timer_delay",
		&ng_parse_uint16_type,
		NULL
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_GET_TIMER_DELAY,
		"get_timer_delay",
		NULL,
		&ng_parse_uint16_type,
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_SET_MACADDR_EXPIRE_DELAY,
		"set_macaddr_expire_delay",
		&ng_parse_uint16_type,
		NULL
	},
        {
		NGM_PAE_COOKIE,
		NGM_PAE_GET_MACADDR_EXPIRE_DELAY,
		"get_macaddr_expire_delay",
		NULL,
		&ng_parse_uint16_type,
	},
	{ 0 }
};

/**************************************************************/
/*                    Function prototypes                     */
/**************************************************************/

/********** Hook receive functions ************/
static int
ng_pae_recv_lowerin(const node_p node, struct mbuf *m, meta_p meta);
static int
ng_pae_recv_lowerout(const node_p node, struct mbuf *m, meta_p meta);
static int
ng_pae_recv_upperin(const node_p node, struct mbuf *m, meta_p meta);
static int
ng_pae_recv_upperout(const node_p node, struct mbuf *m, meta_p meta);
static int
ng_pae_recv_eapoldata(const node_p node, struct mbuf *m, meta_p meta);

/********* Utility functions *************/
/* Not used for now */
/* static const char ng_pae_nodename(node_p node); */

static int
is_eap_packet(const node_p node,  struct mbuf *m,  meta_p meta);

/********* Mac address List functions ******/
static void
ng_pae_timeout(void *arg);

static struct ng_pae_macaddress *
get_macaddress_from_packet(const node_p node,  struct mbuf *m,  meta_p meta);

static struct ng_pae_macaddress *
lookup_by_macaddr(const pae_p priv, const char *ether);

static int
add_macaddress_from_packet(const node_p node, struct mbuf *m, meta_p meta);
static int
add_macaddress_by_copy(const pae_p priv, const struct ng_pae_macaddr_msg *macaddr);
static int
del_macaddress_from_struct(const pae_p priv, const struct ng_pae_macaddr_msg *macaddr);
static int
add_macaddress_priv(pae_p priv, struct ng_pae_macaddress *macaddr);
static int
del_macaddress_priv(pae_p priv, struct ng_pae_macaddress *macaddr);
static int
flush_macaddress_list(pae_p priv, const int full_flush);

static u_int32_t
count_macaddress_list(const pae_p priv);


/*
 * This section contains the netgraph method declarations for the
 * pae node. These methods define the netgraph 'pae'.
 */
static ng_constructor_t	ng_pae_constructor;
static ng_rcvmsg_t	ng_pae_rcvmsg;
static ng_shutdown_t	ng_pae_rmnode;
static ng_newhook_t	ng_pae_newhook;
static ng_connect_t	ng_pae_connect;
static ng_rcvdata_t	ng_pae_rcvdata;	 /* note these are both ng_rcvdata_t */
static ng_disconnect_t	ng_pae_disconnect;


/* Netgraph node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_PAE_NODE_TYPE,
	.mod_event = NULL,
	.constructor=ng_pae_constructor,
	.rcvmsg    = ng_pae_rcvmsg,
	.shutdown  = ng_pae_rmnode,
	.newhook   = ng_pae_newhook,
	.findhook  = NULL,
	.connect   = ng_pae_connect,
	.afterconnect = NULL,
	.rcvdata   = ng_pae_rcvdata,
	.rcvdataq  = ng_pae_rcvdata,
	.disconnect= ng_pae_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist   = ng_pae_cmdlist,
};
NETGRAPH_INIT(pae, &typestruct);
NETGRAPH_EXIT(pae, &typestruct);


/*
 * Allocate the private data structure and the generic node
 * and link them together.
 *
 * ng_make_node_common() returns with a generic node struct
 * with a single reference for us.. we transfer it to the
 * private structure.. when we free the private struct we must
 * unref the node so it gets freed too.
 *
 * If this were a device node than this work would be done in the attach()
 * routine and the constructor would return EINVAL as you should not be able
 * to creatednodes that depend on hardware (unless you can add the hardware :)
 */
static int
ng_pae_constructor(node_p *nodep, ng_ID_t nodeid)
{
	pae_p priv=NULL;
	int error=0;

	/* Initialize private descriptor */
	MALLOC(priv, pae_p, sizeof(struct ng_pae_port_private), M_NETGRAPH, M_NOWAIT | M_ZERO);
	if (priv == NULL)
		return (ENOMEM);
        ng_callout_init(&priv->timer);

	/* Call the 'generic' (ie, superclass) node constructor */
	if ((error = ng_make_node_common(&typestruct, nodep, nodeid))) {
		FREE(priv, M_NETGRAPH);
		return (error);
	}
	LIST_INIT(&(priv->MacList));

	/* Link structs together; this counts as our one reference to *nodep */
        NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	priv->port_state = PAE_PORT_STATE_BLOCKED;
	priv->port_behavior = PAE_ADDR_BASED_BEHAVIOR;

	/* Start timer; timer is always running while node is alive */
	/* Default time is NG_PAE_DEFAULT_TIMER_DELAY. */
        priv->current_timer_value = 0;
        priv->timer_delay = NG_PAE_DEFAULT_TIMER_DELAY;
        priv->macaddr_expire_delay = NG_PAE_MACADDR_EXPIRE_DELAY;

	ng_callout_reset(&priv->timer, hz * (priv->timer_delay), ng_pae_timeout, priv->node);

	return (0);
}


static int
ng_pae_newhook(node_p node, hook_p hook, const char *name)
{
	/* Sanity checks */
        pae_p priv = NULL;

        if ( (node==NULL) || (hook==NULL) || (node->private==NULL)) {
		return EINVAL;
        }
        priv = NG_NODE_PRIVATE(node);

        /* Just register the hook in the private struct */
	if (strcmp(name, NG_PAE_HOOK_LOWERIN)==0 ) {
                if (priv->lowerin != NULL)
			return EADDRINUSE;
                priv->lowerin = hook;
        } else if (strcmp(name,NG_PAE_HOOK_LOWEROUT)==0) {
                if (priv->lowerout != NULL)
			return EADDRINUSE;
                priv->lowerout = hook;
        } else if (strcmp(name,NG_PAE_HOOK_UPPERIN)==0) {
                if (priv->upperin != NULL)
			return EADDRINUSE;
                priv->upperin = hook;
        } else if (strcmp(name,NG_PAE_HOOK_UPPEROUT)==0) {
                if (priv->upperout != NULL)
			return EADDRINUSE;
                priv->upperout = hook;
        } else if (strcmp(name,NG_PAE_HOOK_EAPOLDATA)==0) {
                if (priv->eapoldata != NULL)
			return EADDRINUSE;
                priv->eapoldata = hook;
                add_eap_addr_to_interface(node);
	} else {
		return EINVAL;	/* not a hook we know about */
        }
	return(0); /* everything went fine */
}

/*
 * Receive message from userland tools
 */
static int
ng_pae_rcvmsg(node_p node, struct ng_mesg *msg, const char *retaddr,
	      struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	const pae_p priv =  NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;

	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_PAE_COOKIE:
		switch (msg->header.cmd) {
		case NGM_PAE_PORT_STATE_GET: { /* get the port status */
			NG_MKRESPONSE(resp, msg, sizeof(u_int8_t), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			*((u_int8_t *)resp->data) = priv->port_state;
			break;
		}
		case NGM_PAE_PORT_STATE_SET: { /* set the port status */
			if (msg->header.arglen != sizeof(u_int8_t)) {
				error = EINVAL;
				break;
			}
			switch (*((u_int8_t *) msg->data)) {
			case PAE_PORT_STATE_BLOCKED:
			case PAE_PORT_STATE_FILTERED:
			case PAE_PORT_STATE_AUTHORIZED:
				priv->port_state = (*((u_int8_t *) msg->data));
				break;
			default:
				error=EINVAL;
				break;
			}
			break;
		}
		case NGM_PAE_GET_PORT_BEHAVIOR: { /* get the port behavior */
			NG_MKRESPONSE(resp, msg, sizeof(u_int8_t), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			*((u_int8_t *)resp->data) = priv->port_behavior;
			break;
		}
		case NGM_PAE_SET_PORT_BEHAVIOR: { /* set the port behavior */
			if (msg->header.arglen != sizeof(u_int8_t)) {
				error = EINVAL;
				break;
			}
			switch (*((u_int8_t *) msg->data)) {
			case PAE_PORT_BASED_BEHAVIOR:
			case PAE_ADDR_BASED_BEHAVIOR:
				priv->port_behavior = (*((u_int8_t *) msg->data));
				break;
			default:
				error=EINVAL;
				break;
			}
			break;
		}
#ifdef NG_PAE_SUPPORT_STATS
		case NGM_PAE_PORT_STATS_GET: { /* get the port statistics */
			NG_MKRESPONSE(resp, msg, sizeof(struct ng_pae_port_stats), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			priv->port_stats.timer = priv->current_timer_value;
			memcpy(resp->data,&(priv->port_stats),sizeof(struct ng_pae_port_stats));
			break;
		}
		case NGM_PAE_PORT_STATS_RESET: { /* reset statistics */
			bzero(&(priv->port_stats),sizeof(struct ng_pae_port_stats));
			break;
		}
		case NGM_PAE_PORT_STATS_GET_AND_RESET: { /* get the port statistics & reset*/
			NG_MKRESPONSE(resp, msg, sizeof(struct ng_pae_port_stats), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			priv->port_stats.timer = priv->current_timer_value;
			memcpy(resp->data,&(priv->port_stats),sizeof(struct ng_pae_port_stats));
			bzero(&(priv->port_stats),sizeof(struct ng_pae_port_stats));
			break;
		}
#endif
		case NGM_PAE_MAC_ADD: {
			if (msg->header.arglen != sizeof(struct ng_pae_macaddr_msg)) {
				error = EINVAL;
				break;
			}
			add_macaddress_by_copy( priv,(struct ng_pae_macaddr_msg *) msg->data );
			break;
		}
		case NGM_PAE_MAC_DEL: {
			if (msg->header.arglen != sizeof(struct ng_pae_macaddr_msg)) {
				error = EINVAL;
				break;
			}
			del_macaddress_from_struct( priv,(struct ng_pae_macaddr_msg *) msg->data );
			break;
		}
		case NGM_PAE_MAC_DUMP: {
			struct ng_pae_macaddress_list *macaddress_list=NULL;
			struct ng_pae_macaddress *macaddr=NULL;
			int count=0, i=0;

			count = count_macaddress_list(priv);

			NG_MKRESPONSE(resp, msg, sizeof(struct ng_pae_macaddress_list)
				      + count * sizeof(struct ng_pae_macaddr_msg), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			macaddress_list = (struct ng_pae_macaddress_list *)resp->data;

			bzero(macaddress_list,sizeof(struct ng_pae_macaddress_list)
			      + count * sizeof(struct ng_pae_macaddr_msg));

			macaddress_list->numMacs = count;
			LIST_FOREACH(macaddr, &(priv->MacList), next) {
				memcpy(&(macaddress_list->macaddress[i].saddr), macaddr->saddr,
				       VNB_ETHER_ADDR_LEN);
				macaddress_list->macaddress[i].state = macaddr->state;
				macaddress_list->macaddress[i].authorized = macaddr->authorized;
				macaddress_list->macaddress[i].staleness = macaddr->staleness;
				i++;
			}
			break;
		}
		case NGM_PAE_MAC_FLUSH: {
			flush_macaddress_list(priv,0);
			break;
		}
		case NGM_PAE_MAC_FULL_FLUSH: {
			flush_macaddress_list(priv,1);
			break;
		}
		case NGM_PAE_SET_TIMER_DELAY: {
			if (msg->header.arglen != sizeof(u_int16_t)) {
				error = EINVAL;
				break;
			}
			priv->timer_delay= *((u_int16_t *)msg->data);
			break;
		}
		case NGM_PAE_GET_TIMER_DELAY: {
			NG_MKRESPONSE(resp, msg, sizeof(u_int16_t), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			*((u_int16_t *)resp->data) = priv->timer_delay;
			break;
		}
		case NGM_PAE_SET_MACADDR_EXPIRE_DELAY: {
			if (msg->header.arglen != sizeof(u_int16_t)) {
				error = EINVAL;
				break;
			}
			priv->macaddr_expire_delay = *((u_int16_t *)msg->data);
			break;
		}
		case NGM_PAE_GET_MACADDR_EXPIRE_DELAY: {
			NG_MKRESPONSE(resp, msg, sizeof(u_int16_t), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			*((u_int16_t *)resp->data) = priv->macaddr_expire_delay;
			break;
		}
		default: {
			error=EINVAL;
			break;
		}/* unknown command */
                } /* end switch cmd */
                break;

	default:
		error = EINVAL;			/* unknown cookie type */
		break;
	}

	/* Take care of synchronous response, if any */
	if (rptr)
		*rptr = resp;
	else if (resp)
		FREE(resp, M_NETGRAPH);

	/* Free the message and return */
	FREE(msg, M_NETGRAPH);
	return(error);
}

/*
 * Receive a packet. This function just dispatch the packet according to its arrival hook.
 */
static int
ng_pae_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	const pae_p priv = NG_NODE_PRIVATE(node);

	/* Handle incoming frame from lowerin hook */
	if (hook == priv->lowerin) {
#ifdef NG_PAE_SUPPORT_STATS
                priv->port_stats.lowerin_count_in++;
#endif
		return ng_pae_recv_lowerin(node, m, meta);
	}
	/* Handle incoming frame from lowerout hook */
	if (hook == priv->lowerout) {
#ifdef NG_PAE_SUPPORT_STATS
		priv->port_stats.lowerout_count_in++;
#endif
		return ng_pae_recv_lowerout(node, m, meta);
	}
	/* Handle incoming frame from upperin hook */
	if (hook == priv->upperin) {
#ifdef NG_PAE_SUPPORT_STATS
		priv->port_stats.upperin_count_in++;
#endif
		return ng_pae_recv_upperin(node, m, meta);
	}
	/* Handle incoming frame from upperout hook */
	if (hook == priv->upperout) {
#ifdef NG_PAE_SUPPORT_STATS
		priv->port_stats.upperout_count_in++;
#endif
		return  ng_pae_recv_upperout(node, m, meta);
        }
	/* Handle incoming frame from eapol hook */
	if (hook == priv->eapoldata) {
#ifdef NG_PAE_SUPPORT_STATS
		priv->port_stats.eapoldata_count_in++;
#endif
		return  ng_pae_recv_eapoldata(node, m, meta);
        }
#ifdef NG_PAE_SUPPORT_STATS
        priv->port_stats.dropped_count++;
#endif
	return (EINVAL);
}


/*
 * Node removal was asked for : Housekeeping. Reconnect the up- and down- layers together.
 */
static int
ng_pae_rmnode(node_p node)
{
	pae_p priv = NULL;

        priv = NG_NODE_PRIVATE(node);
        KASSERT( priv != NULL);
	node->flags |= NG_INVALID;

        /*Ensure the timer does not run */
	ng_callout_stop_sync(&priv->timer);

        /* reconnect upper and lower nodes */
        if (priv->lowerin && priv->lowerout)
                ng_bypass(priv->lowerin, priv->lowerout);
	if (priv->upperin && priv->upperout)
                ng_bypass(priv->upperin, priv->upperout);

	ng_cutlinks(node);
	ng_unname(node);

        /* In this order: Free the Maclist, Free the private data, and unref the node */
        flush_macaddress_list(priv,1);

        FREE(node->private, M_NETGRAPH);

        NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	return (0);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_pae_connect(hook_p hook)
{
        /* TODO : Add multicast address listening on the iterface, if possible */
	return (0);
}

/*
 * Hook disconnection. Nothing to do except standard housekeeping.
 *
 */
static int
ng_pae_disconnect(hook_p hook)
{
        pae_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));

	if (hook == priv->lowerin) {
		priv->lowerin = NULL;
        } else if (hook==priv->lowerout ) {
                priv->lowerout = NULL;
        } else if (hook==priv->upperin ) {
                priv->upperin = NULL;
        } else if (hook==priv->upperout ) {
                priv->upperout = NULL;
        } else if (hook==priv->eapoldata ) {
                priv->eapoldata = NULL;
                del_eap_addr_from_interface(NG_HOOK_NODE(hook));
                /* flush_macaddress_list(priv,0); */
                /* TODO Do we really want this ? */
	} else {
		return (EINVAL);	/* not a hook we know about */
        }
        if (NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
                ng_rmnode(NG_HOOK_NODE(hook));
	return(0);                      /* everything went fine */
}

/*
 * Return node's "name", even if it doesn't have one.
 * For now this function is not used.
 */
/* static const char * */
/* ng_pae_nodename(node_p node) */
/* { */
/* 	static char name[NG_NODELEN+1]; */

/* 	if (node->name != NULL) */
/* 		snprintf(name, sizeof(name), "%s", node->name); */
/* 	else */
/* 		snprintf(name, sizeof(name), "eap[%x]", ng_node2ID(node)); */
/* 	return name; */
/* } */



/*
 * Timer expiration function: For MacList cleaning.
 * Go through the list, and lookup nodes with "negociating" state.
 * Check their staleness. if the difference with the current timer is > timer_delay,
 * then remove the entry.
 *
 ************  Warning  !!!! *********** The MacList needs a semaphore, there is
 * a risk of access-during-free depanding on how the sceduler call this timer handler.
 */
static void
ng_pae_timeout(void *arg)
{
	node_p node = (node_p) arg;
        pae_p  priv = NG_NODE_PRIVATE(node);
        struct ng_pae_macaddress * macaddr=NULL;
        struct ng_pae_macaddress * backup_mac=NULL;

        priv->current_timer_value++;

	if (NG_NODE_NOT_VALID(node)) /* Safegard against removal */
		return;

        for (macaddr = LIST_FIRST(&(priv->MacList)) ; macaddr != NULL ; ) {
#ifdef NG_PAE_MACLIST_CLEAN
		if  ( (macaddr->state == PAE_MACADDR_STATE_NEGOCIATING) &&
		      ((u_int16_t)(priv->current_timer_value - macaddr->staleness) >= (u_int16_t)priv->macaddr_expire_delay)) {
			backup_mac=macaddr;
                        macaddr=LIST_NEXT(macaddr, next);
                        LIST_REMOVE(backup_mac, next);
			FREE(backup_mac, M_NETGRAPH);
		} else
#endif
			{
				macaddr = LIST_NEXT(macaddr, next);
			}
        }
        ng_callout_reset(&priv->timer, hz * (priv->timer_delay), ng_pae_timeout, priv->node);
}


/**********************************************************************/
/*                      Receptions functions                          */
/**********************************************************************/

static int
ng_pae_recv_lowerin(const node_p node, struct mbuf *m, meta_p meta)
{
	struct ng_pae_macaddress * macaddr = NULL;
        pae_p priv = NG_NODE_PRIVATE(node);
        int error = 0;

        if ( priv->port_state == PAE_PORT_STATE_AUTHORIZED)
		goto out_ok;

        /* Send eap packets to eapoldata hook if the hook is connected.
           The packet will be added to the list if necessary, or its timestamp updated. */
        if ( priv->eapoldata && is_eap_packet(node, m, meta))
		goto out_eap;

        if ( priv->port_state == PAE_PORT_STATE_BLOCKED)
		goto out_reject;

        /* If we are here, then the port is in FILTERED state */
        macaddr = get_macaddress_from_packet(node, m, meta);

        /* mac address is unknown : send the packet to eapoldata socket and record it in the list */
        if (macaddr == NULL) {
                goto out_eap;
        }

	/*
	 * Either the address has been blacklisted (state=manual) or the
	 * authentication is not yet finished (state=negociating)
	 */
        if (macaddr->authorized==0)
		goto out_reject;

        /* Packet is accepted after mac filtering check => goto out_ok */
out_ok:
	if (priv->lowerout == NULL) {
		NG_SEND_DATA(error, priv->upperout, m, meta);
#ifdef NG_PAE_SUPPORT_STATS
                priv->port_stats.upperout_count_out++;
#endif
                return error;
        }
	NG_SEND_DATA(error, priv->lowerout, m, meta);
#ifdef NG_PAE_SUPPORT_STATS
        priv->port_stats.lowerout_count_out++;
#endif

        return error;

 out_eap:
	add_macaddress_from_packet(node, m, meta);
	NG_SEND_DATA(error, priv->eapoldata, m, meta);
#ifdef NG_PAE_SUPPORT_STATS
	priv->port_stats.eapoldata_count_out++;
#endif
	return error;

 out_reject:
	NG_FREE_DATA(m, meta);
#ifdef NG_PAE_SUPPORT_STATS
        priv->port_stats.dropped_count++;
#endif
	return error;
}

static int
ng_pae_recv_lowerout(const node_p node, struct mbuf *m, meta_p meta)
{
	int error = 0;

	NG_SEND_DATA(error, ((pae_p) NG_NODE_PRIVATE(node))->lowerout, m, meta);
#ifdef NG_PAE_SUPPORT_STATS
	((pae_p) NG_NODE_PRIVATE(node))->port_stats.lowerout_count_out++;
#endif
	return error;
}

static int
ng_pae_recv_upperin(const node_p node,  struct mbuf *m,  meta_p meta)
{
	int error = 0;

	NG_SEND_DATA(error, ((pae_p) NG_NODE_PRIVATE(node))->upperout, m, meta);
#ifdef NG_PAE_SUPPORT_STATS
	((pae_p) NG_NODE_PRIVATE(node))->port_stats.upperout_count_out++;
#endif
	return error;
}


static int
ng_pae_recv_upperout(const node_p node, struct mbuf *m, meta_p meta)
{
	int error = 0;

	/* must be the same logic as ng_ether_rmon.c */
	if ( ((pae_p) NG_NODE_PRIVATE(node))->upperin == NULL) {
		NG_SEND_DATA(error, ((pae_p) NG_NODE_PRIVATE(node))->lowerin, m, meta);
#ifdef NG_PAE_SUPPORT_STATS
		((pae_p) NG_NODE_PRIVATE(node))->port_stats.lowerin_count_out++;
#endif
	} else {
		NG_SEND_DATA(error, ((pae_p) NG_NODE_PRIVATE(node))->upperin, m, meta);
#ifdef NG_PAE_SUPPORT_STATS
		((pae_p) NG_NODE_PRIVATE(node))->port_stats.upperin_count_out++;
#endif
	}
	return error;
}

static int
ng_pae_recv_eapoldata(const node_p node,  struct mbuf *m, meta_p meta)
{
	int error = 0;

	NG_SEND_DATA(error, ((pae_p) NG_NODE_PRIVATE(node))->lowerin, m, meta);
#ifdef NG_PAE_SUPPORT_STATS
	((pae_p) NG_NODE_PRIVATE(node))->port_stats.lowerin_count_out++;
#endif
	return error;
}

/*******************************************************************/
/*             Helper functions                                    */
/*******************************************************************/

static int
is_eap_packet(const node_p node, struct mbuf *m,meta_p meta)
{
	struct vnb_ether_header *eh;
	/* Make sure we have an entire header */
        if (m->len < sizeof(struct vnb_ether_header)) {
                return 0;
        }
        if (!pskb_may_pull(m, sizeof(struct vnb_ether_header))) {
                return 0;
        }
	eh = mtod(m, struct vnb_ether_header *);

        if (eh->ether_type == htons(ETH_P_EAP)) {
		return 1;
        }

	return 0;
}


static struct ng_pae_macaddress *
get_macaddress_from_packet(const node_p node, struct mbuf *m, meta_p meta)
{
        struct vnb_ether_header *eh=NULL;
	pae_p priv = NG_NODE_PRIVATE(node);
	/* Make sure we have an entire header */
        if (m->len < sizeof(struct vnb_ether_header)) {
                return 0;
        }
        if (!pskb_may_pull(m, sizeof(struct vnb_ether_header))) {
                return 0;
        }
	eh = mtod(m, struct vnb_ether_header *);

        return lookup_by_macaddr(priv, eh->ether_shost);
}

/* This function is called only for first packet of this mac address */
static int
add_macaddress_from_packet(const node_p node, struct mbuf *m, meta_p meta)
{
	struct ng_pae_macaddress * macaddr = NULL;
        struct vnb_ether_header * eh = NULL;
	pae_p priv = NG_NODE_PRIVATE(node);

	/* Make sure we have an entire header */
        if (m->len < sizeof(struct vnb_ether_header)) {
                return 0;
        }
        if (!pskb_may_pull(m, sizeof(struct vnb_ether_header))) {
                return 0;
        }
	eh = mtod(m, struct vnb_ether_header *);

        macaddr = lookup_by_macaddr(priv, eh->ether_shost);
        if (macaddr) { /* This packet already is in the MacList  */
                macaddr->staleness = priv->current_timer_value;
                return 0;
        }

        MALLOC(macaddr, struct ng_pae_macaddress *, sizeof(struct ng_pae_macaddress), M_NETGRAPH, M_NOWAIT);
        if (macaddr == NULL)
		return ENOMEM;
	bzero(macaddr, sizeof(struct ng_pae_macaddress));
        memcpy(&(macaddr->saddr), eh->ether_shost, VNB_ETHER_ADDR_LEN);
        macaddr->authorized = 0;
        macaddr->state = PAE_MACADDR_STATE_NEGOCIATING;
        macaddr->staleness = priv->current_timer_value;

        return add_macaddress_priv(priv, macaddr);
}

/* Add a new mac_address structure by making a copy of the argument. Used by the receive_msg function */
static int
add_macaddress_by_copy(const pae_p priv, const struct ng_pae_macaddr_msg *mac)
{
        struct ng_pae_macaddress *macaddr=NULL;

        if ( mac == NULL)
		return EINVAL;

        macaddr = lookup_by_macaddr(priv, mac->saddr);

        if (macaddr != NULL) {
		/* Do not overwrite a static entry with a dynamic entry */
		if (macaddr->state == PAE_MACADDR_STATE_MANUAL && mac->state == PAE_MACADDR_STATE_EAP_AUTH)
			return 0;
		macaddr->authorized = mac->authorized;
		macaddr->state = mac->state;
                macaddr->staleness = priv->current_timer_value;
                return 0;
        }

        /* Address not present */
	MALLOC(macaddr, struct ng_pae_macaddress *, sizeof(*macaddr), M_NETGRAPH, M_ZERO);
        if (macaddr == NULL)
		return ENOMEM;
        memcpy(macaddr->saddr, mac->saddr, VNB_ETHER_ADDR_LEN);
        macaddr->authorized = mac->authorized;
        macaddr->state = mac->state;
        macaddr->staleness = priv->current_timer_value;
	add_macaddress_priv(priv, macaddr);

        return 0;
}


static int
del_macaddress_from_struct(const pae_p priv,const struct ng_pae_macaddr_msg *mac)
{
	struct ng_pae_macaddress *macaddr = NULL;

        if (mac == NULL)
		return EINVAL;

        macaddr = lookup_by_macaddr(priv, mac->saddr);

        if (macaddr == NULL)
		return 0; /* not found */

	/* Do not delete a static entry with a dynamic entry */
	if (macaddr->state == PAE_MACADDR_STATE_MANUAL && mac->state == PAE_MACADDR_STATE_EAP_AUTH)
		return 0;

	return del_macaddress_priv(priv, macaddr);
}


/* Low-level list handling functions */
static int
add_macaddress_priv(pae_p priv,struct ng_pae_macaddress *mac)
{
        LIST_INSERT_HEAD(&(priv->MacList), mac, next);
	return 0;
}

static int
del_macaddress_priv(pae_p priv, struct ng_pae_macaddress *mac)
{
        LIST_REMOVE(mac, next);
        FREE(mac, M_NETGRAPH);
	return 0;
}


static u_int32_t
count_macaddress_list(const pae_p priv)
{
	u_int32_t i=0;

        struct ng_pae_macaddress * macaddr;
        LIST_FOREACH(macaddr, &(priv->MacList), next) {
		i++;
        }
	return i;
}

static int
flush_macaddress_list(pae_p priv, const int full_flush)
{
	u_int32_t i=0;
	struct ng_pae_macaddress * macaddr;
        struct ng_pae_macaddress * backup_macaddr;

        for (macaddr=LIST_FIRST(&(priv->MacList)); macaddr!=NULL; ) {
		if ((full_flush==0) &&
                    (macaddr->state == PAE_MACADDR_STATE_MANUAL)){ /* Skip this one */
			macaddr=LIST_NEXT(macaddr, next);
			continue;
		}
		backup_macaddr=macaddr;
		macaddr=LIST_NEXT(macaddr, next);
		LIST_REMOVE(backup_macaddr,next);
		FREE(backup_macaddr, M_NETGRAPH);
		i++;
        }
	return i;
}

struct ng_pae_macaddress *
lookup_by_macaddr(const pae_p priv, const char *ether)
{
	struct ng_pae_macaddress * macaddr;

	LIST_FOREACH(macaddr, &(priv->MacList), next) {
                if (memcmp(macaddr->saddr,ether, VNB_ETHER_ADDR_LEN)==0) {
			return macaddr;
		}
	}
        return NULL;
}

#if defined(__LinuxKernelVNB__)
module_init(ng_pae_init);
module_exit(ng_pae_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB PAE node");
MODULE_LICENSE("6WIND");
#endif
