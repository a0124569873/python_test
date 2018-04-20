/*
 * Copyright 2007-2013 6WIND S.A.
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
#include <netgraph/vnblinux.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_filter.h>

#include <linux/ip.h>
#include <linux/icmp.h>


#define DEBUG_FILTER 0
#if DEBUG_FILTER >= 1
#define DEBUG(x, y...) do { \
		printk(KERN_DEBUG "%s:%s() " x "\n", strrchr(__FILE__, '/')+1, __FUNCTION__, ## y);\
	} while(0)
#else
#define DEBUG(x, y...) do {} while(0)
#endif

struct ng_filter_icmp_entry {
	LIST_ENTRY(ng_filter_icmp_entry) next;
	struct ng_filter_icmp            filter;
};
LIST_HEAD(filter_icmp_list, ng_filter_icmp_entry);
static VNB_DEFINE_SHARED(vnb_spinlock_t, list_lock);  /* lock for list access */

/* Per-node private data */
struct ng_filter_private {
	node_p                   filter_node;    /* back pointer to node */
	hook_p                   filter_upper;   /* upper hook connection */
	hook_p                   filter_lower;   /* lower hook connection */
	hook_p                   filter_daemon;  /* daemon hook connection */
	struct filter_icmp_list  filter_icmp;    /* list of ICMP filter */
};
typedef struct ng_filter_private *priv_p;

/*
 * Netgraph node methods
 */
static ng_constructor_t ng_filter_constructor;
static ng_rcvmsg_t      ng_filter_rcvmsg;
static ng_newhook_t     ng_filter_newhook;
static ng_rcvdata_t     ng_filter_rcvdata;
static ng_shutdown_t    ng_filter_rmnode;
static ng_disconnect_t  ng_filter_disconnect;

/* Parse type for struct ng_filter_icmp */
static const struct ng_parse_struct_field
	ng_filter_icmp_type_fields[] = NG_FILTER_ICMP_TYPE_INFO;
static const struct ng_parse_type ng_filter_icmp_type = {
	&ng_parse_struct_type,
	&ng_filter_icmp_type_fields,
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_filter_cmdlist[] = {
	{
		cookie:   NGM_FILTER_COOKIE,
		cmd:      NGM_FILTER_GET_ICMPSIZE,
		name:     "geticmpsize",
		mesgType: NULL,
		respType: &ng_parse_uint32_type
	},
	{
		cookie:   NGM_FILTER_COOKIE,
		cmd:      NGM_FILTER_GET_ICMP,
		name:     "geticmp",
		mesgType: &ng_parse_uint32_type,
		respType: &ng_filter_icmp_type
	},
	{
		cookie:   NGM_FILTER_COOKIE,
		cmd:      NGM_FILTER_SET_ICMP,
		name:     "seticmp",
		mesgType: &ng_filter_icmp_type,
		respType: NULL
	},
	{
		cookie:   NGM_FILTER_COOKIE,
		cmd:      NGM_FILTER_DEL_ICMP,
		name:     "delicmp",
		mesgType: &ng_filter_icmp_type,
		respType: NULL
	},
	{ 0 }
};

/*
 * Node type descriptor
 */
static VNB_DEFINE_SHARED(struct ng_type, ng_filter_typestruct) = {
        version:    NG_VERSION,
        name:       NG_FILTER_NODE_TYPE,
        mod_event:  NULL,                  /* module event handler (optional) */
        constructor:ng_filter_constructor, /* node constructor */
        rcvmsg:     ng_filter_rcvmsg,      /* control messages come here */
        shutdown:   ng_filter_rmnode,      /* reset, and free resources */
        newhook:    ng_filter_newhook,     /* first notification of new hook */
        findhook:   NULL,                  /* only if you have lots of hooks */
        connect:    NULL,                  /* final notification of new hook */
        afterconnect:NULL,
        rcvdata:    ng_filter_rcvdata,     /* date comes here */
        rcvdataq:   ng_filter_rcvdata,     /* or here if being queued */
        disconnect: ng_filter_disconnect,  /* notify on disconnect */
        rcvexception: NULL,                /* exceptions come here */
        dumpnode: NULL,
        restorenode: NULL,
        dumphook: NULL,
        restorehook: NULL,
        cmdlist:    ng_filter_cmdlist,     /* commands we can convert */
};
NETGRAPH_INIT(filter, &ng_filter_typestruct);
NETGRAPH_EXIT(filter, &ng_filter_typestruct);

/******************************************************************
                    NETGRAPH NODE METHODS
 ******************************************************************/

/*
 * Node constructor
 */
static int ng_filter_constructor(node_p *nodep, ng_ID_t nodeid)
{
        priv_p priv;
	int error = 0;

        /*
         * Allocate and initialize private info
         */
#if !defined(M_ZERO)
	priv = ng_malloc(sizeof(*priv), M_NOWAIT);
#else
	priv = ng_malloc(sizeof(*priv), M_NOWAIT | M_ZERO);
#endif
        if (priv == NULL)
                return (ENOMEM);
#if !defined(M_ZERO)
        bzero(priv, sizeof(*priv));
#endif

        /* Call superclass constructor that mallocs *nodep */
        if ((error = ng_make_node_common(&ng_filter_typestruct, nodep, nodeid))) {
                ng_free(priv);
                return (error);
        }
        NG_NODE_SET_PRIVATE(*nodep, priv);
        priv->filter_node = *nodep;
	LIST_INIT(&priv->filter_icmp);
	vnb_spinlock_init(&list_lock);

        return (0);
}

/*
 * Method for attaching a new hook
 * There are three kinds of hook:
 *      - the lower hook which links to an interface
 *	- the upper hook which links to an iface
 *	- the daemon hook
 */
static int ng_filter_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	hook_p *ph;

	/*
	 * Check for a lower hook
	 */
	if (strcmp(name, NG_FILTER_HOOK_LOWER) == 0)
		ph = &(priv->filter_lower);
	else if (strcmp(name, NG_FILTER_HOOK_UPPER) == 0)
		ph = &(priv->filter_upper);
	else if (strcmp(name, NG_FILTER_HOOK_DAEMON) == 0)
		ph = &(priv->filter_daemon);
	else
		return (EINVAL);

	/* Do not connect twice a hook */
	if (*ph != NULL)
		return (EISCONN);

	*ph = hook;
	return 0;
}

/*
 * Receive a control message
 */
static int ng_filter_rcvmsg(node_p node, struct ng_mesg *msg,
		const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
        const priv_p priv = NG_NODE_PRIVATE(node);
        struct ng_mesg *resp = NULL;
        int error = 0;

	switch (msg->header.typecookie) {
	case NGM_FILTER_COOKIE:
		switch (msg->header.cmd) {
		case NGM_FILTER_GET_ICMPSIZE:
		{
			struct ng_filter_icmp_entry *entry;
			uint32_t *size;

			NG_MKRESPONSE(resp, msg, sizeof(*size), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			size = (uint32_t *)resp->data;
			*size = 0;

			vnb_spinlock_lock(&list_lock);
			LIST_FOREACH(entry, &priv->filter_icmp, next)
				(*size)++;
			vnb_spinlock_unlock(&list_lock);

			break;
		}
		case NGM_FILTER_GET_ICMP:
		{
			struct ng_filter_icmp_entry *entry;
			struct ng_filter_icmp *filter;
			uint32_t i = 0, *n = (uint32_t *)msg->data;

			if (msg->header.arglen != sizeof(*n)) {
				error = EINVAL;
				break;
			}

			NG_MKRESPONSE(resp, msg, sizeof(*filter), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			filter = (struct ng_filter_icmp *)resp->data;

			vnb_spinlock_lock(&list_lock);
			LIST_FOREACH(entry, &priv->filter_icmp, next)
				if (*n == i) {
					memcpy(filter, &entry->filter, sizeof(*filter));
					break;
				} else
					i++;
			vnb_spinlock_unlock(&list_lock);

			if (*n != i)
				memset(filter, 0, sizeof(*filter));
			break;
		}
		case NGM_FILTER_SET_ICMP:
		{
			struct ng_filter_icmp_entry *entry;
			struct ng_filter_icmp *filter =
				(struct ng_filter_icmp *)msg->data;

			if (msg->header.arglen != sizeof(*filter)) {
				error = EINVAL;
				break;
			}

			entry = ng_malloc(sizeof(*entry), M_NOWAIT);
			if (entry == NULL)
				return ENOMEM;

			entry->filter.icmp_saddr = filter->icmp_saddr;
			entry->filter.icmp_daddr = filter->icmp_daddr;
			entry->filter.icmp_type = filter->icmp_type;
			entry->filter.icmp_echo_id = filter->icmp_echo_id;
			DEBUG("New filter:");
			DEBUG("saddr: %u:%u:%u:%u, daddr: %u:%u:%u:%u",
					NIPQUAD(entry->filter.icmp_saddr),
					NIPQUAD(entry->filter.icmp_daddr));
			DEBUG("icmp_type: %u, id: %u", entry->filter.icmp_type,
					ntohs(entry->filter.icmp_echo_id));

			vnb_spinlock_lock(&list_lock);
			LIST_INSERT_HEAD(&priv->filter_icmp, entry, next);
			vnb_spinlock_unlock(&list_lock);

                        break;
		}
		case NGM_FILTER_DEL_ICMP:
		{
			struct ng_filter_icmp_entry *entry, *entry2;
			struct ng_filter_icmp *filter =
				(struct ng_filter_icmp *)msg->data;

			if (msg->header.arglen != sizeof(*filter)) {
				error = EINVAL;
				break;
			}

			vnb_spinlock_lock(&list_lock);
			LIST_FOREACH_SAFE(entry, entry2, &priv->filter_icmp, next)
				if (entry->filter.icmp_saddr == filter->icmp_saddr &&
				    entry->filter.icmp_daddr == filter->icmp_daddr &&
				    entry->filter.icmp_type == filter->icmp_type &&
				    entry->filter.icmp_echo_id == filter->icmp_echo_id) {
					LIST_REMOVE(entry, next);
					ng_free(entry);
					break;
				}
			vnb_spinlock_unlock(&list_lock);
                        break;
		}
		default:
			error = EINVAL;
			break;
		}
		break;
	default:
		error = EINVAL;
		break;
	}

	if (rptr)
		*rptr = resp;
	else if (resp)
		FREE(resp, M_NETGRAPH);

	FREE(msg, M_NETGRAPH);
	return (error);
}

/*
 * Check if the packet match a filter
 */
static int ng_filter_check(priv_p priv, struct mbuf *m, meta_p meta)
{
	struct ng_filter_icmp_entry *entry;
	struct iphdr *iph;
	struct icmphdr *icmph;

	if (!pskb_may_pull(m, sizeof(*iph) + sizeof(*icmph)))
		return 0;

	iph = mtod(m, struct iphdr *);
	icmph = (struct icmphdr *)(iph + 1);
	DEBUG("saddr: %u:%u:%u:%u, daddr: %u:%u:%u:%u",
			NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
	DEBUG("protocol: %u, icmp_type: %u, id: %u",
			iph->protocol, icmph->type, ntohs(icmph->un.echo.id));

	vnb_spinlock_lock(&list_lock);
	LIST_FOREACH(entry, &priv->filter_icmp, next) {
		if ((!entry->filter.icmp_saddr ||
		     entry->filter.icmp_saddr == iph->saddr) &&
		    (!entry->filter.icmp_daddr ||
		     entry->filter.icmp_daddr == iph->daddr) &&
		    (iph->protocol == IPPROTO_ICMP) &&
		    (entry->filter.icmp_type == 255 ||
		     entry->filter.icmp_type == icmph->type) &&
		    (!entry->filter.icmp_echo_id ||
		     entry->filter.icmp_echo_id == icmph->un.echo.id)) {
			vnb_spinlock_unlock(&list_lock);
			DEBUG("Packet match the filter");
			return 1;
		}
	}
	vnb_spinlock_unlock(&list_lock);
	return 0;
}

/*
 * Receive data on a hook
 *
 * Data coming from upper or daemon link are forwarded through the
 * lower link.
 * Data coming from the lower link are filtered. Matching data are
 * sent to daemon, others data to the upper link.
 */
static int ng_filter_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	priv_p priv;
	int error = 0;

	if (!node) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	priv = NG_NODE_PRIVATE(node);
	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	/* Handle incoming frame from below */
	if (hook == priv->filter_lower) {
		if (ng_filter_check(priv, m, meta))
			NG_SEND_DATA(error, priv->filter_daemon, m, meta);
		else
			NG_SEND_DATA(error, priv->filter_upper, m, meta);
	}

	/* Handle outgoing data frame from the upper nodes */
	if (hook == priv->filter_upper)
		NG_SEND_DATA(error, priv->filter_lower, m, meta);

	/* Handle outgoing data frame from the daemon node */
	if (hook == priv->filter_daemon)
		NG_SEND_DATA(error, priv->filter_lower, m, meta);

	return error;
}

/*
 * Shutdown processing
 */
static int ng_filter_rmnode(node_p node)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_filter_icmp_entry *entry, *next;

	ng_cutlinks(node);
	ng_unname(node);


	vnb_spinlock_lock(&list_lock);
	for (entry = LIST_FIRST(&priv->filter_icmp); entry; entry = next) {
		next = LIST_NEXT(entry, next);
		LIST_REMOVE(entry, next);
		ng_free(entry);
	}
	vnb_spinlock_unlock(&list_lock);

	NG_NODE_SET_PRIVATE(node, NULL);
	ng_free(priv);
	NG_NODE_UNREF(node);
	return 0;
}

/*
 * Hook disconnection
 * If all the hooks are removed, let's free itself.
 */
static int ng_filter_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_filter_icmp_entry *entry, *next;

	/* Zero out hook pointer */
	if (hook == priv->filter_lower)
		priv->filter_lower = NULL;
	if (hook == priv->filter_upper)
		priv->filter_upper = NULL;
	if (hook == priv->filter_daemon) {
		priv->filter_daemon = NULL;

		/* XXX: If daemon is disconnected, remove all filters */
		vnb_spinlock_lock(&list_lock);
		for (entry = LIST_FIRST(&priv->filter_icmp); entry; entry = next) {
			next = LIST_NEXT(entry, next);
			LIST_REMOVE(entry, next);
			ng_free(entry);
		}
		vnb_spinlock_unlock(&list_lock);
	}

	/* Go away if no longer connected to anything */
	if (node->numhooks == 0)
		ng_rmnode(node);
	return 0;
}

#if defined(__LinuxKernelVNB__)
module_init(ng_filter_init);
module_exit(ng_filter_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB filter node");
MODULE_LICENSE("6WIND");
#endif
