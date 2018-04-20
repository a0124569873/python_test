/*
 * Copyright 2005-2013 6WIND S.A.
 */

#if defined(__LinuxKernelVNB__)
#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/ctype.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <netgraph/vnblinux.h>
#elif defined(__FastPath__)
#include <fp-netgraph.h>
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_pppchdlcdetect.h>


#define TRACE_DEBUG	0

#if TRACE_DEBUG == 1
#ifdef __LinuxKernelVNB__
#define TRACE(fmt, args...) \
	do { \
	   printk(KERN_DEBUG "ng_pppchdlcdetect(%s):" fmt, __FUNCTION__, ## args); \
	} while(0)
#else
#define TRACE(fmt, args...) \
	do { \
	   log(LOG_DEBUG,"ng_pppchdlcdetect(%s):" fmt, __FUNCTION__, ## args); \
	} while(0)
#endif
#else
#define TRACE(fmt, args...) while(0)
#endif

/**********/

/* Per-link private data */
struct ng_pppchdlcdetect_hook {
	hook_p				hook;	/* netgraph hook */
	struct ng_pppchdlcdetect_link_stats	stats;	/* link stats */
};


/* Per-node private data */
struct ng_pppchdlcdetect_private {
	struct ng_pppchdlcdetect_config        conf;		/* node configuration */
	struct ng_pppchdlcdetect_hook          down;		/* "down" hook */
	struct ng_pppchdlcdetect_hook	         up;		/* "up" hook */
	struct ng_pppchdlcdetect_hook          info;		/* "info" hook */
};
typedef struct ng_pppchdlcdetect_private *priv_p;



/**********/

/* Netgraph node methods */
static ng_constructor_t ng_pppchdlcdetect_constructor;
static ng_rcvmsg_t      ng_pppchdlcdetect_rcvmsg;
static ng_shutdown_t    ng_pppchdlcdetect_shutdown;
static ng_newhook_t     ng_pppchdlcdetect_newhook;
static ng_rcvdata_t     ng_pppchdlcdetect_rcvdata;
static ng_disconnect_t  ng_pppchdlcdetect_disconnect;

/* Other functions */

static int ng_pppchdlcdetect_getprotocol(struct mbuf *m, int * proto);
static int ng_pppchdlcdetect_setstate(node_p node, int state);
static int ng_pppchdlcdetect_notifystate(node_p node);

/******************************************************************
		    NETGRAPH PARSE TYPES
******************************************************************/

/* CONFIG (setconfig & getconfig commands)
 *
 * Config fields. Need to be synchronized with struct
 * ng_pppchdlcdetect_config in ng_pppchdlcdetect.h
 */
static const struct ng_parse_struct_field ng_pppchdlcdetect_config_type_fields[] = {
	{ .name = "state", .type = &ng_parse_uint32_type },
	{ .name = NULL }
};

static const struct ng_parse_type ng_pppchdlcdetect_config_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_pppchdlcdetect_config_type_fields
};

/**********/

/* STATS (getstats, clrstats, getclrstats commands)
 *
 * Parse type for struct ng_pppchdlcdetect_link_stats. Need to be
 * synchronized with struct ng_pppchdlcdetect_link_stats in
 * ng_pppchdlcdetect.h
 */
static const struct ng_parse_struct_field ng_pppchdlcdetect_link_stats_type_fields[] = {
	{ .name = "recvOctets", .type = &ng_parse_uint64_type },
	{ .name = "recvPackets", .type = &ng_parse_uint64_type },
	{ .name = "xmitOctets", .type = &ng_parse_uint64_type },
	{ .name = "xmitPackets", .type = &ng_parse_uint64_type },
	{ .name = "droppedRecvPackets", .type = &ng_parse_uint64_type },
	{ .name = "memoryFailures", .type = &ng_parse_uint64_type },
	{ .name = NULL }
};

static const struct ng_parse_type ng_pppchdlcdetect_link_stats_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_pppchdlcdetect_link_stats_type_fields
};

/**********/


/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_pppchdlcdetect_cmdlist[] = {
	{
		NGM_PPPCHDLCDETECT_COOKIE,
		NGM_PPPCHDLCDETECT_SET_CONFIG,
		"setconfig",
		&ng_pppchdlcdetect_config_type,
		NULL
	},
	{
		NGM_PPPCHDLCDETECT_COOKIE,
		NGM_PPPCHDLCDETECT_GET_CONFIG,
		"getconfig",
		NULL,
		&ng_pppchdlcdetect_config_type
	},
	{
		NGM_PPPCHDLCDETECT_COOKIE,
		NGM_PPPCHDLCDETECT_GET_STATS,
		"getstats",
		&ng_parse_int32_type,
		&ng_pppchdlcdetect_link_stats_type
	},
	{
		NGM_PPPCHDLCDETECT_COOKIE,
		NGM_PPPCHDLCDETECT_CLR_STATS,
		"clrstats",
		&ng_parse_int32_type,
		NULL,
	},
	{
		NGM_PPPCHDLCDETECT_COOKIE,
		NGM_PPPCHDLCDETECT_GETCLR_STATS,
		"getclrstats",
		&ng_parse_int32_type,
		&ng_pppchdlcdetect_link_stats_type
	},
	{
		.cookie = 0
	}
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_pppchdlcdetect_typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_PPPCHDLCDETECT_NODE_TYPE,
	.mod_event = NULL,
	.constructor=ng_pppchdlcdetect_constructor,
	.rcvmsg    = ng_pppchdlcdetect_rcvmsg,
	.shutdown  = ng_pppchdlcdetect_shutdown,
	.newhook   = ng_pppchdlcdetect_newhook,
	.findhook  = NULL,
	.connect   = NULL,
	.afterconnect = NULL,
	.rcvdata   = ng_pppchdlcdetect_rcvdata,
	.rcvdataq  = ng_pppchdlcdetect_rcvdata,
	.disconnect= ng_pppchdlcdetect_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist   = ng_pppchdlcdetect_cmdlist,
};
NETGRAPH_INIT(pppchdlcdetect, &ng_pppchdlcdetect_typestruct);
NETGRAPH_EXIT(pppchdlcdetect, &ng_pppchdlcdetect_typestruct);





/******************************************************************
		    NETGRAPH NODE METHODS
******************************************************************/

/*
 * Node constructor
 */
static int
ng_pppchdlcdetect_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p priv;
	int error;

	/* Call superclass constructor */
	if ((error = ng_make_node_common_and_priv(&ng_pppchdlcdetect_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}
	bzero(priv, sizeof(*priv));
	priv->conf.state = NG_PPPCHDLCDETECT_STATE_UNDEF;

	NG_NODE_SET_PRIVATE(*nodep, priv);

	/* Done */
	return (0);
}


/*
 * Method for attaching a new hook
 */
static int
ng_pppchdlcdetect_newhook(node_p node, hook_p hook, const char *name)
{
	priv_p priv = NG_NODE_PRIVATE(node);

	if (strcmp(name, NG_PPPCHDLCDETECT_HOOK_DOWN) == 0) {
		priv->down.hook = hook;
		bzero(&priv->down.stats, sizeof(priv->down.stats));
		hook->private = &priv->down;
	} else if (strcmp(name, NG_PPPCHDLCDETECT_HOOK_UP) == 0) {
		priv->up.hook = hook;
		bzero(&priv->up.stats, sizeof(priv->up.stats));
		hook->private = &priv->up;
	} else if (strcmp(name, NG_PPPCHDLCDETECT_HOOK_INFO) == 0) {
		priv->info.hook = hook;
		bzero(&priv->info.stats, sizeof(priv->info.stats));
		hook->private = &priv->info;
	} else
		return (EINVAL);
	return (0);
}


/*
 * Receive a control message
 */
static int
ng_pppchdlcdetect_rcvmsg(node_p node, struct ng_mesg *msg, const char *retaddr,
		         struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	priv_p priv;
	struct ng_mesg *resp = NULL;
	int error = 0;

	priv = node->private;
	switch (msg->header.typecookie) {
	case NGM_PPPCHDLCDETECT_COOKIE:
		switch (msg->header.cmd) {
		case NGM_PPPCHDLCDETECT_SET_CONFIG:
			{
				struct ng_pppchdlcdetect_config *conf;

				/* Check that new configuration is valid */
				if (msg->header.arglen != sizeof(*conf)) {
					error = EINVAL;
					break;
				}
				conf = (struct ng_pppchdlcdetect_config *)msg->data;

				/* Is the state correct ? */
				if ( (conf->state != NG_PPPCHDLCDETECT_STATE_UNDEF) &&
					(conf->state != NG_PPPCHDLCDETECT_STATE_PPP) &&
					(conf->state != NG_PPPCHDLCDETECT_STATE_CHDLC) ) {
					error = EINVAL;
					break;
				}
				ng_pppchdlcdetect_setstate(node, conf->state);
				break;
			}
		case NGM_PPPCHDLCDETECT_GET_CONFIG:
			{
				struct ng_pppchdlcdetect_config *conf;

				NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				conf = (struct ng_pppchdlcdetect_config *)resp->data;
				bcopy(&priv->conf, conf, sizeof(priv->conf));
				break;
			}
		case NGM_PPPCHDLCDETECT_GET_STATS:
		case NGM_PPPCHDLCDETECT_CLR_STATS:
		case NGM_PPPCHDLCDETECT_GETCLR_STATS:
			{
				struct ng_pppchdlcdetect_hook *link=NULL;
				int linkNum;

				if (msg->header.arglen != sizeof(int32_t)) {
					error = EINVAL;
					break;
				}

				/* Get link num */
				memcpy(&linkNum, msg->data, sizeof(linkNum));

				/* Get link struct */
				switch (linkNum) {
				case NG_PPPCHDLCDETECT_HOOK_NUM_DOWN:
					link = &priv->down;
					break;

				case NG_PPPCHDLCDETECT_HOOK_NUM_UP:
					link = &priv->up;
					break;

				case NG_PPPCHDLCDETECT_HOOK_NUM_INFO:
					link = &priv->info;
					break;

				default:
					error = EINVAL;
					break;
				}

				/* exit if error (invalid link num) */
				if (error != 0)
					break;

				/* Get/clear stats */
				if (msg->header.cmd != NGM_PPPCHDLCDETECT_CLR_STATS) {
					NG_MKRESPONSE(resp, msg,
							    sizeof(link->stats), M_NOWAIT);
					if (resp == NULL) {
						error = ENOMEM;
						break;
					}
					bcopy(&link->stats,
						 resp->data, sizeof(link->stats));
				}
				if (msg->header.cmd != NGM_PPPCHDLCDETECT_GET_STATS)
					bzero(&link->stats, sizeof(link->stats));

			}
			break;

		default:
			error = EINVAL;
			break;
		}
		break;
	default:
		error = EINVAL;
		break;
	}
	/* Done */
	if (rptr)
		*rptr = resp;
	else if (resp != NULL)
		FREE(resp, M_NETGRAPH);
	FREE(msg, M_NETGRAPH);

	return (error);
}

/*
 * Receive data on a hook
 */
static int
ng_pppchdlcdetect_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	const node_p node = NG_HOOK_NODE(hook);
	priv_p priv;

	struct ng_pppchdlcdetect_hook *const src =
		(struct ng_pppchdlcdetect_hook *) hook->private;

	struct ng_pppchdlcdetect_hook *dst = NULL;

	int error = 0;
	int proto;
	int len;

	if ((node == NULL) || (src == NULL) ||
	    ((priv = NG_NODE_PRIVATE(node)) == NULL))
		goto error;

	/* Update stats */
	src->stats.recvPackets++;
	src->stats.recvOctets += MBUF_LENGTH(m);

	/* Packet arrives on hook "down" */
	if (src == &priv->down) {
            dst = &priv->up;

            /* Try to determine protocol */
            error = ng_pppchdlcdetect_getprotocol(m, &proto);

            if (error == ENOBUFS) {
                src->stats.memoryFailures++;
                /* m is already freed by ng_pppchdlcdetect_getprotocol() */
                NG_FREE_META(meta);
                return error ;
            }
            if (error) {
                NG_FREE_DATA(m, meta);
                return error;
            }

            /* set protocol */
            if (proto == NG_PPPCHDLCDETECT_PROTO_PPP) {
                ng_pppchdlcdetect_setstate(node, NG_PPPCHDLCDETECT_STATE_PPP);
            }
            else if (proto == NG_PPPCHDLCDETECT_PROTO_CHDLC) {
                ng_pppchdlcdetect_setstate(node, NG_PPPCHDLCDETECT_STATE_CHDLC);
            }
            else {
                TRACE("Undefined protocol\n");
            }
        }

	/* Packet arrives on hook "up" */
        else if (src == &priv->up) {
            dst = &priv->down;
        }

	/* Packet arrives on hook "info" */
        else if (src == &priv->info) {
            src->stats.droppedRecvPackets++;
            NG_FREE_DATA(m, meta);
            TRACE("Ignore packet received on info hook, packet dropped\n");
            return 0;
        }

        /* Invalid hook */
        else {
	    goto error;
        }

	/* Copy length before the mbuf gets invalidated */
	len = MBUF_LENGTH(m);

	/* Deliver packet */
        if ((hook = dst->hook) == NULL) {
            src->stats.droppedRecvPackets++;
            NG_FREE_DATA(m, meta);
            TRACE("No destination hook\n");
            return ENOTCONN;
        }
	NG_SEND_DATA(error, hook, m, meta);

	/* Update stats */
	if (error == 0) {
            dst->stats.xmitPackets++;
            dst->stats.xmitOctets += len;
	}

	return (error);
error:
	NG_FREE_DATA(m, meta);
	return EINVAL;
}

/*
 * Shutdown node
 */
static int
ng_pppchdlcdetect_shutdown(node_p node)
{
	ng_unname(node);
	ng_cutlinks(node);

	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	return (0);
}

/*
 * Hook disconnection.
 */
static int
ng_pppchdlcdetect_disconnect(hook_p hook)
{
	struct ng_pppchdlcdetect_hook *const hinfo =
		(struct ng_pppchdlcdetect_hook *) hook->private;

	KASSERT(hinfo != NULL);
	hinfo->hook = NULL;
	if (hook->node->numhooks == 0)
		ng_rmnode(hook->node);
	return (0);
}

/******************************************************************
			OTHER FUNCTIONS
******************************************************************/

/* Determine the link-layer protocol of the packet
 *
 * protocol result in proto
 *   NG_PPPCHDLCDETECT_PROTO_UNKNOW    if unknow
 *   NG_PPPCHDLCDETECT_PROTO_PPP       if it is ppp
 *   NG_PPPCHDLCDETECT_PROTO_CHDLC     if it is chdlc
 *
 * return 0 on success
 */
static int
ng_pppchdlcdetect_getprotocol(struct mbuf * m, int * const proto)
{
	int datalen;
	uint16_t proto_field;

	/* default returned protocol */
	*proto = NG_PPPCHDLCDETECT_PROTO_UNKNOW ;

	datalen = MBUF_LENGTH(m);

	/* See if we can access to the protocol field, if packet is too
	   small, return unknow without error */
	if (datalen >= NG_PPPCHDLCDETECT_PROTO_LEN) {
		/* put data in a contiguous memory region */
		if ((m = m_pullup(m, NG_PPPCHDLCDETECT_PROTO_LEN)) == NULL)
			return (ENOBUFS);

		/* get the real protocol number in packet */
		proto_field = ntohs(*mtod(m, uint16_t *)) ;

		TRACE("getprotocol -> proto_field = %X\n", proto_field);

		/* A CHDLC packet :
		 *
		 * |-------|-------|-------|-------|----------------
		 * |Address|Control| Protocol code |  Information ...
		 * |-------|-------|-------|-------|----------------
		 *  1 byte  1 byte      2 bytes         variable
		 *
		 *  The adress field specifies the type of packet:
		 *  0x0F 	Unicast packets.
		 *  0x8F 	Broadcast packets.
		 *
		 *  The control field is always set to 0.
		 */
		if ( proto_field == 0x0F00 ||	proto_field == 0x8F00 )
			*proto = NG_PPPCHDLCDETECT_PROTO_CHDLC ;

		/* A PPP packet (from RFC 1549) :
		 *
		 *              +----------+----------+----------+-
		 *              | Address  | Control  | Protocol |  ...
		 *              | 11111111 | 00000011 | 16 bits  |
		 *              +----------+----------+----------+-
		 *
		 *    Address Field
		 *
		 *      The Address field is a single octet and contains the binary
		 *      sequence 11111111 (hexadecimal 0xff), the All-Stations address.
		 *      PPP does not assign individual station addresses.  The All-
		 *      Stations address MUST always be recognized and received.  The use
		 *      of other address lengths and values may be defined at a later
		 *      time, or by prior agreement.  Frames with unrecognized Addresses
		 *      SHOULD be silently discarded.
		 *
		 *    Control Field
		 *
		 *      The Control field is a single octet and contains the binary
		 *      sequence 00000011 (hexadecimal 0x03), the Unnumbered Information
		 *      (UI) command with the P/F bit set to zero.  The use of other
		 *      Control field values may be defined at a later time, or by prior
		 *      agreement.  Frames with unrecognized Control field values SHOULD
		 *      be silently discarded.
		 */
		else if (proto_field == 0xFF03)
			*proto = NG_PPPCHDLCDETECT_PROTO_PPP ;
	}

	TRACE("getprotocol -> proto = %d\n", *proto);

	return 0;
}

/* Set the new state (PPP or CHDLC or UNDEF) */
static int
ng_pppchdlcdetect_setstate(node_p node, int state)
{
    const priv_p priv = NG_NODE_PRIVATE(node);

    if (priv == NULL)
	return ENOTCONN;
    /* if we need to notify state */
    if((uint32_t)state != priv->conf.state) {
        priv->conf.state = state ;
        return ng_pppchdlcdetect_notifystate(node);
    }

    return 0;
}

/*
 * Send a message to the state hook.
 * The message is an ascii message that contains "ppp" or "chdlc"
 */
static int
ng_pppchdlcdetect_notifystate(node_p node)
{
        const priv_p priv = NG_NODE_PRIVATE(node);
	int error=0, len;
        char *state_str;
	struct mbuf *m;

	if (priv == NULL)
	    return ENOTCONN;
        if ( priv->info.hook ) {
            TRACE("notifystate to %s\n", (priv->info.hook)->name);
        }
        else {
            TRACE("No info hook. Cannot notify state\n");
            return ENOTCONN;
        }

    /* alloc the mbuf/skbuff */
	if (((m = m_alloc()) != NULL) &&
	    (m_append(m, NG_PPPCHDLCDETECT_STATE_STR_LEN_MAX) == NULL)) {
		m_freem(m);
		m = NULL;
	}
	if (!m)
		return (ENOBUFS);

        state_str = mtod(m, char *);

        /* set the message */
        if (priv->conf.state == NG_PPPCHDLCDETECT_STATE_PPP) {
            strcpy(state_str, NG_PPPCHDLCDETECT_STATE_STR_PPP);
        }
        else if (priv->conf.state == NG_PPPCHDLCDETECT_STATE_CHDLC) {
            strcpy(state_str, NG_PPPCHDLCDETECT_STATE_STR_CHDLC);
        }
        else {
            strcpy(state_str, NG_PPPCHDLCDETECT_STATE_STR_UNDEF);
        }

        len = strlen(state_str) + 1 ;

        /* set size */
	m_trim(m, (NG_PPPCHDLCDETECT_STATE_STR_LEN_MAX - len));

        NG_SEND_DATA_ONLY(error, priv->info.hook, m);

	/* Update stats */
	priv->info.stats.xmitPackets++;
#ifndef __LinuxKernelVNB__
	priv->info.stats.xmitOctets += len;
#else
	priv->info.stats.recvOctets += len;
#endif

	return error;
}

#if defined(__LinuxKernelVNB__)
module_init(ng_pppchdlcdetect_init);
module_exit(ng_pppchdlcdetect_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB pppchdlcdetect node");
MODULE_LICENSE("6WIND");
#endif
