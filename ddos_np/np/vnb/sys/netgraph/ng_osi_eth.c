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
#include <netgraph/ng_osi.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_osi_eth.h>

#ifdef DEBUG_OSI_ETH
#define TRACE(fmt, args...) do {\
        printk("ng_osi_eth(%d):" fmt "\n", __LINE__, ## args); \
} while (0)
#else
#define TRACE(x...)
#endif

struct eth_llc_header {
	u_char  ether_dhost[VNB_ETHER_ADDR_LEN];
	u_char  ether_shost[VNB_ETHER_ADDR_LEN];
	uint16_t	pktlen;
	uint8_t		dsap;
	uint8_t		ssap;
	uint8_t		ctrl;
} __attribute__ ((packed));

struct ng_osi_macosi_entry {
	LIST_ENTRY(ng_osi_macosi_entry) next;
	u_char		mac_addr[VNB_ETHER_ADDR_LEN];
	u_char		osi_addr[MAX_OSI_LEN];
};
LIST_HEAD(osilist, ng_osi_macosi_entry);

/* Per-node private data */
struct ng_osi_eth_private {
        node_p          node;                   /* back pointer to node */
        struct ng_osi_eth_config   conf;        /* node configuration */
        hook_p          osi_eth_lower;          /* lower hook connection */
        hook_p          osi_eth_upper;          /* upper hook connection */
        hook_p          osi_eth_daemon;         /* daemon hook connection */
	struct osilist  eslist;
	struct osilist  islist;
	struct osilist  rdlist;
#ifdef DEBUG_ETH
	/* Just for test */
	uint8_t  	dst_addr[VNB_ETHER_ADDR_LEN];
#endif
};
typedef struct ng_osi_eth_private *priv_p;

/*
 * Netgraph node methods
 */
static ng_constructor_t ng_osi_eth_constructor;
static ng_rcvmsg_t      ng_osi_eth_rcvmsg;
static ng_newhook_t     ng_osi_eth_newhook;
static ng_rcvdata_t     ng_osi_eth_rcvdata;
static ng_shutdown_t    ng_osi_eth_rmnode;
static ng_disconnect_t  ng_osi_eth_disconnect;

/*
 * Local processing
 */
static int ng_osi_eth_recv_lower(node_p node, struct mbuf *m, meta_p meta);
static int ng_osi_eth_xmit_data(node_p node, struct mbuf *m, meta_p meta);
static struct ng_osi_macosi_entry *get_osi_entry (struct ng_osi_eth_osi *resol,
			struct osilist *list);
static void flush_list(struct osilist *list);

/* Parse type for struct ng_osi_eth_config */
static const struct ng_parse_struct_field
        ng_osi_config_type_fields[] = NG_OSI_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_osi_eth_config_type = {
        &ng_parse_struct_type,
        &ng_osi_config_type_fields,
};

#ifdef DEBUG_ETH
/* Just for test */
/* Parse type for struct ng_osi_eth_addr */
static const struct ng_parse_struct_field ng_osi_eth_addr_fields[]
	= NG_OSI_ETH_ADDR_FIELDS;
static const struct ng_parse_type ng_osi_eth_addr_type = {
	&ng_parse_struct_type,
	&ng_osi_eth_addr_fields
};
#endif /* DEBUG_ETH */

/* Parse type for struct ng_osi_eth_resol */
static const struct ng_parse_struct_field ng_osi_eth_resol_fields[]
	= NG_OSI_ETH_RESOL_FIELDS;
static const struct ng_parse_type ng_osi_eth_resol_type = {
	&ng_parse_struct_type,
	&ng_osi_eth_resol_fields
};

/* Parse type for struct ng_osi_eth_osi */
static const struct ng_parse_struct_field ng_osi_eth_osi_fields[]
	= NG_OSI_ETH_OSI_FIELDS;
static const struct ng_parse_type ng_osi_eth_osi_type = {
	&ng_parse_struct_type,
	&ng_osi_eth_osi_fields
};


static const struct ng_cmdlist ng_osi_eth_cmdlist[] = {
        {
          NGM_OSI_ETH_COOKIE,
          NGM_OSI_ETH_SET_CONFIG,
          "setconfig",
          mesgType: &ng_osi_eth_config_type,
          respType: NULL
        },
        {
          NGM_OSI_ETH_COOKIE,
          NGM_OSI_ETH_GET_CONFIG,
          "getconfig",
          mesgType: NULL,
          respType: &ng_osi_eth_config_type
        },
#ifdef DEBUG_ETH
/* Just for test */
	{
	  NGM_OSI_ETH_COOKIE,
	  NGM_OSI_ETH_SET_DST,
	  "setdst",
	  mesgType:&ng_osi_eth_addr_type,
	  respType:NULL
	},
#endif /* DEBUG_ETH */
	{
	  NGM_OSI_ETH_COOKIE,
	  NGM_OSI_ETH_ADD_ES,
	  "set_es_entry",
	  mesgType:&ng_osi_eth_resol_type,
	  respType:NULL
	},
	{
	  NGM_OSI_ETH_COOKIE,
	  NGM_OSI_ETH_DEL_ES,
	  "del_es_entry",
	  mesgType:&ng_osi_eth_osi_type,
	  respType:NULL
	},
	{
	  NGM_OSI_ETH_COOKIE,
	  NGM_OSI_ETH_ADD_IS,
	  "set_is_entry",
	  mesgType:&ng_osi_eth_resol_type,
	  respType:NULL
	},
	{
	  NGM_OSI_ETH_COOKIE,
	  NGM_OSI_ETH_DEL_IS,
	  "del_is_entry",
	  mesgType:&ng_osi_eth_osi_type,
	  respType:NULL
	},
	{
	  NGM_OSI_ETH_COOKIE,
	  NGM_OSI_ETH_ADD_RD,
	  "set_rd_entry",
	  mesgType:&ng_osi_eth_resol_type,
	  respType:NULL
	},
	{
	  NGM_OSI_ETH_COOKIE,
	  NGM_OSI_ETH_DEL_RD,
	  "del_rd_entry",
	  mesgType:&ng_osi_eth_osi_type,
	  respType:NULL
	},
        { 0 }
};

/*
 * Node type descriptor
 */
static VNB_DEFINE_SHARED(struct ng_type, ng_osi_eth_typestruct) = {
        version:    NG_VERSION,
        name:       NG_OSI_ETH_NODE_TYPE,
        mod_event:  NULL,               /* Module event handler (optional) */
        constructor:ng_osi_eth_constructor, /* Node constructor */
        rcvmsg:     ng_osi_eth_rcvmsg,      /* control messages come here */
        shutdown:   ng_osi_eth_rmnode,      /* reset, and free resources */
        newhook:    ng_osi_eth_newhook,     /* first notification of new hook */
        findhook:   NULL,               /* only if you have lots of hooks */
        connect:    NULL,               /* final notification of new hook */
        afterconnect:NULL,
        rcvdata:    ng_osi_eth_rcvdata,     /* date comes here */
        rcvdataq:   ng_osi_eth_rcvdata,     /* or here if being queued */
        disconnect: ng_osi_eth_disconnect,  /* notify on disconnect */
        rcvexception: NULL,                 /* exceptions come here */
        dumpnode: NULL,
        restorenode: NULL,
        dumphook: NULL,
        restorehook: NULL,
        cmdlist:    ng_osi_eth_cmdlist,     /* commands we can convert */
};
NETGRAPH_INIT(osi_eth, &ng_osi_eth_typestruct);
NETGRAPH_EXIT(osi_eth, &ng_osi_eth_typestruct);

#ifdef __LinuxKernelVNB__
extern int ng_osi_tun_init(void);
extern void ng_osi_tun_exit(void);

int ng_osi_init(void)
{
	if (ng_osi_eth_init() != 0)
		return -EINVAL;
	if (ng_osi_tun_init() != 0)
		return -EINVAL;

	return 0;
}

void ng_osi_exit(void)
{
	ng_osi_tun_exit();
	ng_osi_eth_exit();
	return;
}

#endif

/******************************************************************
                    NETGRAPH NODE METHODS
 ******************************************************************/

/*
 * Node constructor
 */
static int
ng_osi_eth_constructor(node_p *nodep, ng_ID_t nodeid)
{
        priv_p priv;
        int error;

#ifdef SPLASSERT
        SPLASSERT(net, __FUNCTION__);
#endif

        /* Call superclass constructor that mallocs *nodep */
        if ((error = ng_make_node_common_and_priv(&ng_osi_eth_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
                return (error);
        }

        bzero(priv, sizeof(*priv));
        priv->conf.debug = NG_OSI_ETH_DEBUG_NONE;

        NG_NODE_SET_PRIVATE(*nodep, priv);
        priv->node = *nodep;
	LIST_INIT(&priv->eslist);
	LIST_INIT(&priv->islist);
	LIST_INIT(&priv->rdlist);

        /* Done */
        return (0);
}

static struct ng_osi_macosi_entry *
get_osi_entry (struct ng_osi_eth_osi *resol, struct osilist *list)
{
	struct ng_osi_macosi_entry *addr;

	LIST_FOREACH(addr, list, next) {
		if (!memcmp (addr->osi_addr, resol->ngoe_osi_val, resol->ngoe_osi_len))
			return addr;
	}
	return NULL;
}

static u_char *
get_dst_mac (u_char *osiaddr, u_char osilen, struct osilist *list)
{
	struct ng_osi_macosi_entry *addr;

	LIST_FOREACH(addr, list, next) {
		if (!memcmp (addr->osi_addr, osiaddr, osilen))
			return addr->mac_addr;
	}
	return NULL;
}
/*
 * Receive a control message from ngctl or the netgraph's API
 */
static int
ng_osi_eth_rcvmsg(node_p node, struct ng_mesg *msg,
        const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
        const priv_p priv = NG_NODE_PRIVATE(node);
        struct ng_mesg *resp = NULL;
        int error = 0;

        switch (msg->header.typecookie) {
        case NGM_OSI_ETH_COOKIE:
                switch (msg->header.cmd) {
                case NGM_OSI_ETH_GET_CONFIG:
                    {
                        struct ng_osi_eth_config *conf;

                        NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
                        if (resp == NULL) {
                                error = ENOMEM;
                                break;
                        }
                        conf = (struct ng_osi_eth_config *)resp->data;
                        *conf = priv->conf;     /* no sanity checking needed */
                        break;
                    }
                case NGM_OSI_ETH_SET_CONFIG:
                    {
                        struct ng_osi_eth_config * const conf =
                                (struct ng_osi_eth_config *)msg->data;

                        if (msg->header.arglen != sizeof(*conf)) {
                                error = EINVAL;
                                break;
                        }
                        priv->conf = *conf;
                        break;
                    }
#ifdef DEBUG_ETH
/* Just for test */
		case NGM_OSI_ETH_SET_DST:
		    {
		      uint8_t *eaddr;

		      if (msg->header.arglen != VNB_ETHER_ADDR_LEN) {
			  error = EINVAL;
			  break;
		      }
                      eaddr = (uint8_t *)(msg->data);
                         memmove (priv->dst_addr, eaddr, VNB_ETHER_ADDR_LEN);
		      break;
                    }
#endif /* DEBUG_ETH */
		case NGM_OSI_ETH_ADD_ES:
		case NGM_OSI_ETH_ADD_IS:
		case NGM_OSI_ETH_ADD_RD:
		    {
			struct ng_osi_macosi_entry *entry;
			struct ng_osi_eth_resol *eresol;

			if (msg->header.arglen != sizeof(struct ng_osi_eth_resol)) {
				TRACE ("msg ADD-xx len = %d (!= %d)\n",
				        msg->header.arglen,
				        sizeof(struct ng_osi_eth_resol));
				error = EINVAL;
				break;
			}
			eresol = (struct ng_osi_eth_resol *)msg->data;

			entry = ng_malloc(sizeof(*entry), M_NOWAIT | M_ZERO);
			if (entry == NULL) {
				return (ENOMEM);
			}
			memmove (entry->mac_addr, eresol->ngoe_mac_val, VNB_ETHER_ADDR_LEN);
			memmove (entry->osi_addr, eresol->ngoe_osi_val, eresol->ngoe_osi_len);
			/* Make sure this entry does not exist */
			if (msg->header.cmd == NGM_OSI_ETH_ADD_ES &&
				!get_osi_entry ((struct ng_osi_eth_osi *)eresol, &priv->eslist))
				LIST_INSERT_HEAD(&priv->eslist, entry, next);
			else if (msg->header.cmd == NGM_OSI_ETH_ADD_IS &&
			         !get_osi_entry ((struct ng_osi_eth_osi *)eresol, &priv->islist))
				LIST_INSERT_HEAD(&priv->islist, entry, next);
			else if (msg->header.cmd == NGM_OSI_ETH_ADD_RD &&
			         !get_osi_entry ((struct ng_osi_eth_osi *)eresol, &priv->rdlist))
				LIST_INSERT_HEAD(&priv->rdlist, entry, next);
			else {
				ng_free(entry);
				error = EEXIST;
			}
			break;
                    }
		case NGM_OSI_ETH_DEL_ES:
		case NGM_OSI_ETH_DEL_IS:
		case NGM_OSI_ETH_DEL_RD:
		    {
			struct ng_osi_eth_osi *osi;
			struct ng_osi_macosi_entry *entry = NULL;

			if (msg->header.arglen != sizeof(struct ng_osi_eth_osi)) {
				TRACE ("msg DEL-xx len = %d (!= %d)\n",
				        msg->header.arglen,
				        sizeof(struct ng_osi_eth_osi));
				error = EINVAL;
				break;
			}
			osi = (struct ng_osi_eth_osi *)msg->data;
			/* Search this entry */
			if ((msg->header.cmd == NGM_OSI_ETH_DEL_ES &&
			     (entry = get_osi_entry (osi, &priv->eslist)) != NULL) ||
			    (msg->header.cmd == NGM_OSI_ETH_DEL_IS &&
			     (entry = get_osi_entry (osi, &priv->islist)) != NULL) ||
			    (msg->header.cmd == NGM_OSI_ETH_DEL_RD &&
			     (entry = get_osi_entry (osi, &priv->rdlist)) != NULL))
				LIST_REMOVE(entry, next);
			else
				error = ENODATA;

			if (entry)
				ng_free(entry);
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

        /* Done */
        if (rptr)
                *rptr = resp;
        else if (resp != NULL)
                FREE(resp, M_NETGRAPH);

        FREE(msg, M_NETGRAPH);
        return (error);
}

/*
 * Method for attaching a new hook
 * There are three kinds of hook:
 *      - the lower hook which links to ethx_x
 *	- the upper hook which links to ng_tun_osi
 *	- the esisd daemon hook
 */
static  int
ng_osi_eth_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	hook_p *ph;

	/*
	 * Check for a lower hook
	 *
	 */
	if (strcmp(name, NG_OSI_ETH_HOOK_LOWER) == 0)
		ph = &(priv->osi_eth_lower);
        else if (strcmp(name, NG_OSI_ETH_HOOK_UPPER) == 0)
		ph = &(priv->osi_eth_upper);
        else if (strcmp(name, NG_OSI_ETH_HOOK_DAEMON) == 0)
		ph = &(priv->osi_eth_daemon);
	else
		/*Unknown hook name */
		return (EINVAL);

	/*
	 * Do not connect twice a hook
	 */
	if (*ph != NULL)
		return (EISCONN);
	*ph = hook;
	return 0;
}

/*
 * Receive data
 *
 * Handle incoming data on a hook.
 *
 * Called at splnet() or splimp()
 */
static int
ng_osi_eth_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
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
        if (hook == priv->osi_eth_lower) {
                error = ng_osi_eth_recv_lower(node, m, meta);
                return error;
        }
        if (hook == priv->osi_eth_upper) {
		/* Handle outgoing data frame to the upper nodes */
		error = ng_osi_eth_xmit_data(node, m, meta);
                return error;
		}
	if (hook == priv->osi_eth_daemon) {
		/* Daemon povides direct ETH frames to be sent */
		if (priv->osi_eth_lower == NULL) {
			error = ENOTCONN;
			goto drop;
		}
		NG_SEND_DATA(error,  priv->osi_eth_lower, m, meta);
                return error;
        }

drop:
	NG_FREE_DATA(m, meta);
        return (error);
}

/*
 * Receive data from lower layers (mainly ethernet)
 * Consume the mbuf and meta.
 *
 * Called at splnet() or splimp()
 */
static int
ng_osi_eth_recv_lower(node_p node, struct mbuf *m, meta_p meta)
{
        const priv_p priv = NG_NODE_PRIVATE(node);
        hook_p ohook = NULL;
        int error = 0;
	struct clnp_hdr_fix *ptr;
	struct eth_llc_header *elhdr;

	TRACE ("recv_lower \n");
	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

#define REQ_ETH_SZ_PKT_ANALYSIS_IN (sizeof(*elhdr) + sizeof (*ptr))
	if (m->len < REQ_ETH_SZ_PKT_ANALYSIS_IN) {
		TRACE ("LX skb len (%d)\n", m->len);
		NG_FREE_DATA(m, meta);
		return (EINVAL);
	}
	if (!pskb_may_pull (m,  REQ_ETH_SZ_PKT_ANALYSIS_IN)) {
		TRACE ("LX skb_may_pull (%d)\n", m->len);
		NG_FREE_DATA(m, meta);
		return (EINVAL);
	}
        elhdr = mtod(m, struct eth_llc_header *);
	if (m->len < sizeof(struct eth_llc_header) -
			LLC_SIZE + ntohs(elhdr->pktlen)) {
		TRACE ("len pb %d != %d - %d + %d \n",
		        m->len,  sizeof(struct eth_llc_header),
		        LLC_SIZE, ntohs(elhdr->pktlen));
		error = EINVAL;
		goto drop;
	}

	/* Have some check on the LLC part */
	if (elhdr->dsap != LLC_DSAP || elhdr->ssap != LLC_SSAP
		|| elhdr->ctrl != LLC_CTRL) {
		TRACE (" dsap = %02x ssap = %02x ctrl = %02x\n",
		       elhdr->dsap, elhdr->ssap, elhdr->ctrl);
		error = EINVAL;
		goto drop;
	}
	ptr = (struct clnp_hdr_fix *) (elhdr + 1);

        /*
         * Get the upper hook
         */
	/*
	 * 0x82 is ES-IS PDU going to esisd daemon
	 * 0x81 is CLNP going to osi_eth_upper unless it's the
	 *    echo request/replmy service whoich is managed by daemon.
	 */
	if (ptr->nlpid == NLPID_ESIS)
		ohook = priv->osi_eth_daemon;
	else if (ptr->nlpid == NLPID_CLNP) {
		switch (ptr->flag & CLNP_TYPE) {
			case CLNP_ERQ:
			case CLNP_ERP:
				ohook = priv->osi_eth_daemon;
				break;
			case CLNP_DATA:
				ohook = priv->osi_eth_upper;
				/* Remove the ether_llc header */
				m_adj(m, sizeof (struct eth_llc_header));
				break;
			default: {
				TRACE (" CLNP Flag == %02x (%02x)\n",
				        ptr->flag & CLNP_TYPE, ptr->flag);
				break;
			}
		}
	}
	else {
		TRACE ("NLPID == %02x\n", ptr->nlpid);
	}
	if (ohook == NULL) {
		error = ENOTCONN;
		goto drop;
	}

	/*
	 * Forward data to the output hook : osi_eth_upper or osi_eth_daemon
	 * The mbuf and meta are consumed by the nodes of the peers.
	 */
	NG_SEND_DATA(error, ohook, m, meta);

	/*
	 * When NG_SEND_DATA fails, the mbuf and meta do not
	 * need to be freed because it has already
	 * been done by the peer's node.
	 */
	return error;

drop:
	NG_FREE_DATA(m, meta);
	return (error);
}

/*
 * Add the new ethernet header
 * Consume the mbuf and meta.
 *
 * Called at splnet() or splimp()
 */
static int
ng_osi_eth_xmit_data(node_p node, struct mbuf *m, meta_p meta)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct eth_llc_header *elhdr;
	u_char *dst = NULL;
	int error = 0;
	struct clnp_hdr_fix *clnphdrfix;
	uint8_t *ptr = NULL;
	uint16_t elen;
	u_int8_t rlen;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}
#define REQ_ETH_SZ_PKT_ANALYSIS_OUT (sizeof(*clnphdrfix) + MAX_OSI_LEN + 1)
        if (m->len < REQ_ETH_SZ_PKT_ANALYSIS_OUT) {
		TRACE ("HIGH skb len (%d)\n", m->len);
		NG_FREE_DATA(m, meta);
                return (EINVAL);
        }
        if (!pskb_may_pull(m, REQ_ETH_SZ_PKT_ANALYSIS_OUT)) {
		TRACE ("HIGH skb_may_pull (%d)\n", m->len);
		NG_FREE_DATA(m, meta);
                return (EINVAL);
        }
		elen = m->len;
	/* Select the good dst MAC @ */
	clnphdrfix = mtod (m, struct clnp_hdr_fix *);
	ptr = (uint8_t *)(clnphdrfix + 1);
	rlen = *ptr++;
#ifdef DEBUG_ETH
/* Just for test */
        dst = priv->dst_addr;
#else /* !DEBUG_ETH */
	/* First ES table */
	dst = get_dst_mac (ptr, rlen, &priv->eslist);
	/* Then RD table */
	if (!dst)
		dst = get_dst_mac (ptr, rlen, &priv->rdlist);
	/* Then first available IS  */
	if (!dst && LIST_FIRST(&priv->islist))
		dst = LIST_FIRST(&priv->islist)->mac_addr;
#endif /* !DEBUG_ETH */
	if (dst == NULL) {
		TRACE ("HIGH dst==NULL\n");
		error = ENOTCONN ;
		goto drop;
	}

	/* Insert here the eth_llc */
	M_PREPEND(m, sizeof(struct eth_llc_header), M_DONTWAIT);
	elhdr = mtod(m, struct eth_llc_header *);
	elhdr->dsap = LLC_DSAP;
	elhdr->ssap = LLC_SSAP;
	elhdr->ctrl = LLC_CTRL;
	elen = htons (elen + LLC_SIZE);

	memset (elhdr->ether_shost, 0, VNB_ETHER_ADDR_LEN);
	memmove (elhdr->ether_dhost, dst, VNB_ETHER_ADDR_LEN);
	memmove (&elhdr->pktlen, &elen, 2);

	/*
	 * Send packet
	 * The mbuf and meta are consumed by the nodes of the peers.
	 */
	NG_SEND_DATA(error, priv->osi_eth_lower, m, meta);

	/*
	 * When NG_SEND_DATA fails, the mbuf and meta do not need to be
	 * freed because it has already been done by the peer's node.
	 */
	return error;
drop:
	NG_FREE_DATA(m, meta);
        return (error);
}

void
flush_list(struct osilist *list)
{
	struct ng_osi_macosi_entry *addr, *nextaddr;
	for (addr = LIST_FIRST(list); addr; addr = nextaddr) {
		nextaddr = LIST_NEXT(addr, next);
		LIST_REMOVE (addr, next);
		ng_free(addr);
	}
}

/*
 * Shutdown node
 *
 * Free the private data.
 *
 * Called at splnet()
 */
static int
ng_osi_eth_rmnode(node_p node)
{
        const priv_p priv = NG_NODE_PRIVATE(node);

#ifdef SPLASSERT
        SPLASSERT(net, __FUNCTION__);
#endif

        node->flags |= NG_INVALID;
        ng_cutlinks(node);
        ng_unname(node);

	flush_list(&priv->eslist);
	flush_list(&priv->islist);
	flush_list(&priv->rdlist);

        /* Free private data */
        NG_NODE_SET_PRIVATE(node, NULL);

        /* Unref node */
        NG_NODE_UNREF(node);

        return (0);
}

/*
 * Hook disconnection.
 *
 * If all the hooks are removed, let's free itself.
 */
static int
ng_osi_eth_disconnect(hook_p hook)
{
        const node_p node = NG_HOOK_NODE(hook);
        const priv_p priv = NG_NODE_PRIVATE(node);

        /* Zero out hook pointer */
        if (hook == priv->osi_eth_lower)
                priv->osi_eth_lower = NULL;
        else if (hook == priv->osi_eth_upper)
                priv->osi_eth_upper = NULL;
        else if (hook == priv->osi_eth_daemon)
                priv->osi_eth_daemon = NULL;
        /* Go away if no longer connected to anything */
        if (node->numhooks == 0)
                ng_rmnode(node);
        return (0);
}

#if defined(__LinuxKernelVNB__)
module_init(ng_osi_init);
module_exit(ng_osi_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB OSI node");
MODULE_LICENSE("6WIND");
#endif
