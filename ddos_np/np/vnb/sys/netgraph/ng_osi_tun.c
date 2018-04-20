/*
 * Copyright 2007-2013 6WIND S.A.
 */


#include <linux/version.h>

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
#include <netgraph/ng_osi_tun.h>

#ifdef DEBUG_OSI_TUN
#define TRACE(fmt, args...) do {\
        printk("ng_osi_tun(%d):" fmt "\n", __LINE__, ## args); \
} while (0)
#else
#define TRACE(x...)
#endif

#define LOGP_NSAP(na)\
TRACE("0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x\n",na->osi_addr[0],na->osi_addr[1],na->osi_addr[2],na->osi_addr[3],na->osi_addr[4],na->osi_addr[5],na->osi_addr[6],na->osi_addr[7],na->osi_addr[8],na->osi_addr[9],na->osi_addr[10],na->osi_addr[11],na->osi_addr[12],na->osi_addr[13],na->osi_addr[14],na->osi_addr[15],na->osi_addr[16],na->osi_addr[17],na->osi_addr[18],na->osi_addr[19]);

#define LOG_NSAP(na)\
TRACE("0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x\n",na.osi_addr[0],na.osi_addr[1],na.osi_addr[2],na.osi_addr[3],na.osi_addr[4],na.osi_addr[5],na.osi_addr[6],na.osi_addr[7],na.osi_addr[8],na.osi_addr[9],na.osi_addr[10],na.osi_addr[11],na.osi_addr[12],na.osi_addr[13],na.osi_addr[14],na.osi_addr[15],na.osi_addr[16],na.osi_addr[17],na.osi_addr[18],na.osi_addr[19]);

/*
 *   CLNPhdr = CLNPfix(9)+rlen(1)+remote+llen(1)+local+
 *		segmentation(6)+data(first byte SPI)
 *
 */
uint16_t global_ID = 0xcafe;
int skip_cksum = 0;

struct clnp_segmentation {
	uint16_t dataid;
	uint16_t segoffset;
	uint16_t totallen;
}__attribute__ ((packed));

struct nsap_addr {
	u_char osi_addr[MAX_OSI_LEN];
};

/* Per-node private data */
struct ng_osi_tun_private {
        node_p          node;                   /* back pointer to node */
        struct ng_osi_tun_config   conf;        /* node configuration */
        hook_p          osi_tun_lower;          /* lower hook connection */
        hook_p          osi_tun_links[NG_OSI_TUN_MAX_TAG + 1];
};
typedef struct ng_osi_tun_private *priv_p;

/* Per-link private data */
struct ng_osi_tun_link_hook_private {
        hook_p 			hook;		/* back point to hook */
        int			tag;
	uint8_t rlen;
        struct nsap_addr remote; /* nsel = 00 */
	uint8_t llen;
        struct nsap_addr local; /* nsel = 01 */
};
typedef struct ng_osi_tun_link_hook_private *hookpriv_p;

/*
 * Netgraph node methods
 */
static ng_constructor_t ng_osi_tun_constructor;
static ng_rcvmsg_t      ng_osi_tun_rcvmsg;
static ng_newhook_t     ng_osi_tun_newhook;
static ng_rcvdata_t     ng_osi_tun_rcvdata;
static ng_shutdown_t    ng_osi_tun_rmnode;
static ng_disconnect_t  ng_osi_tun_disconnect;

/*
 * Local processing
 */
static int ng_osi_tun_recv_lower(node_p node, struct mbuf *m, meta_p meta);
static int ng_osi_tun_xmit_data(node_p node, struct mbuf *m, meta_p meta, hookpriv_p hpriv);
hook_p get_link_hook (priv_p priv, struct nsap_addr *local, struct nsap_addr *remote);
static int iso_gen_csum (uint8_t *ptr, int ck_offset, int len, int compute);

/* Parse type for struct ng_osi_tun_addr */
static const struct ng_parse_struct_field
	ng_osi_tun_addr_fields[] = NG_OSI_TUN_ADDR_FIELDS;
static const struct ng_parse_type ng_osi_tun_addr_type = {
        &ng_parse_struct_type,
        &ng_osi_tun_addr_fields
};

/* Parse type for struct ng_osi_tun_config */
static const struct ng_parse_struct_field
        ng_osi_config_type_fields[] = NG_OSI_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_osi_tun_config_type = {
        &ng_parse_struct_type,
        &ng_osi_config_type_fields,
};

static const struct ng_cmdlist ng_osi_tun_cmdlist[] = {
        {
          NGM_OSI_TUN_COOKIE,
          NGM_OSI_TUN_SET_CONFIG,
          "setconfig",
          mesgType: &ng_osi_tun_config_type,
          respType: NULL
        },
        {
          NGM_OSI_TUN_COOKIE,
          NGM_OSI_TUN_GET_CONFIG,
          "getconfig",
          mesgType: NULL,
          respType: &ng_osi_tun_config_type
        },
        {
          NGM_OSI_TUN_COOKIE,
          NGM_OSI_TUN_SET_OSI_REMOTE,
          "setremote",
          mesgType: &ng_osi_tun_addr_type,
          respType: NULL
        },
        {
          NGM_OSI_TUN_COOKIE,
          NGM_OSI_TUN_SET_OSI_LOCAL,
          "setlocal",
          mesgType: &ng_osi_tun_addr_type,
          respType: NULL
        },
        { 0 }
};

/*
 * Node type descriptor
 */
static VNB_DEFINE_SHARED(struct ng_type, ng_osi_tun_typestruct) = {
        version:    NG_VERSION,
        name:       NG_OSI_TUN_NODE_TYPE,
        mod_event:  NULL,               /* Module event handler (optional) */
        constructor:ng_osi_tun_constructor, /* Node constructor */
        rcvmsg:     ng_osi_tun_rcvmsg,      /* control messages come here */
        shutdown:   ng_osi_tun_rmnode,      /* reset, and free resources */
        newhook:    ng_osi_tun_newhook,     /* first notification of new hook */
        findhook:   NULL,               /* only if you have lots of hooks */
        connect:    NULL,               /* final notification of new hook */
        afterconnect: NULL,
        rcvdata:    ng_osi_tun_rcvdata,     /* date comes here */
        rcvdataq:   ng_osi_tun_rcvdata,     /* or here if being queued */
        disconnect: ng_osi_tun_disconnect,  /* notify on disconnect */
        rcvexception: NULL,                 /* exceptions come here */
        dumpnode: NULL,
        restorenode: NULL,
        dumphook: NULL,
        restorehook: NULL,
        cmdlist:    ng_osi_tun_cmdlist,     /* commands we can convert */
};
NETGRAPH_INIT(osi_tun, &ng_osi_tun_typestruct);
NETGRAPH_EXIT(osi_tun, &ng_osi_tun_typestruct);

/******************************************************************
                    NETGRAPH NODE METHODS
 ******************************************************************/

/*
 * Node constructor
 */
static int
ng_osi_tun_constructor(node_p *nodep, ng_ID_t nodeid)
{
        priv_p priv;
        int error;

#ifdef SPLASSERT
        SPLASSERT(net, __FUNCTION__);
#endif

        /* Call superclass constructor that mallocs *nodep */
        if ((error = ng_make_node_common_and_priv(&ng_osi_tun_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
                return (error);
        }
        bzero(priv, sizeof(*priv));
        priv->conf.debug = NG_OSI_TUN_DEBUG_NONE;

        NG_NODE_SET_PRIVATE(*nodep, priv);
        priv->node = *nodep;

        /* Done */
        return (0);
}

/*
 * Receive a control message from ngctl or the netgraph's API
 */
static int
ng_osi_tun_rcvmsg(node_p node, struct ng_mesg *msg,
        const char *retaddr, struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
        const priv_p priv = NG_NODE_PRIVATE(node);
        struct ng_mesg *resp = NULL;
        int error = 0;

        switch (msg->header.typecookie) {
        case NGM_OSI_TUN_COOKIE:
                switch (msg->header.cmd) {
                case NGM_OSI_TUN_GET_CONFIG:
                    {
                        struct ng_osi_tun_config *conf;

                        NG_MKRESPONSE(resp, msg, sizeof(*conf), M_NOWAIT);
                        if (resp == NULL) {
                                error = ENOMEM;
                                break;
                        }
                        conf = (struct ng_osi_tun_config *)resp->data;
                        *conf = priv->conf;     /* no sanity checking needed */
                        break;
                    }
                case NGM_OSI_TUN_SET_CONFIG:
                    {
                        struct ng_osi_tun_config * const conf =
                                (struct ng_osi_tun_config *)msg->data;

                        if (msg->header.arglen != sizeof(*conf)) {
                                error = EINVAL;
                                break;
                        }
                        priv->conf = *conf;
                        break;
                    }
		case NGM_OSI_TUN_SET_OSI_REMOTE:
		case NGM_OSI_TUN_SET_OSI_LOCAL:
                    {
			struct ng_osi_tun_addr *tun_addr;
			hookpriv_p hpriv;
			struct nsap_addr *osia = NULL;
			uint8_t *hlen = NULL;
			if (msg->header.arglen != sizeof(struct ng_osi_tun_addr)) {
				error = EINVAL;
				break;
			}
			tun_addr = (struct ng_osi_tun_addr *)(msg->data);

			if (!priv->osi_tun_links[tun_addr->tunnel_id]) {
				error = EINVAL;
				break;
			}
			hpriv = NG_HOOK_PRIVATE(priv->osi_tun_links[tun_addr->tunnel_id]);

			/* Sanity check */
			if (tun_addr->len > MAX_OSI_LEN)  {
				error = EINVAL;
				break;
			}
			if (msg->header.cmd == NGM_OSI_TUN_SET_OSI_REMOTE) {
				osia = &hpriv->remote;
				hlen = &hpriv->rlen;
			} else {
				osia = &hpriv->local;
				hlen = &hpriv->llen;
			}
			if (osia == NULL || hlen == NULL) {
				error = EINVAL;
				break;
			}
			*hlen = tun_addr->len;
			memmove(osia->osi_addr, tun_addr->oct, tun_addr->len);
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
 * There are two kinds of hook:
 *      - the lower hook which links to ng_osi_eth
 *	- the links_x hook which links to ng_eiface
 */
static  int
ng_osi_tun_newhook(node_p node, hook_p hook, const char *name)
{
        const priv_p priv = NG_NODE_PRIVATE(node);

        /*
         * Check for a link hook
         */
        if (strncmp(name, NG_OSI_TUN_HOOK_LINK_PREFIX,
		sizeof(NG_OSI_TUN_HOOK_LINK_PREFIX) - 1) == 0) {

                const char *tag_str;
                char *err_ptr;
                unsigned long tag;
                hookpriv_p hpriv;

                /*
                 * Get the link index
                 * Parse link0xa, link10, ...
                 */
                tag_str = name + sizeof(NG_OSI_TUN_HOOK_LINK_PREFIX) - 1;

                /* Allow decimal and hexadecimal values.
                 * The hexadecimal values must be prefixed by 0x
                 */
                tag = strtoul(tag_str, &err_ptr, 0); /* allow decimal and hexadecimal */
                if ((*err_ptr) != '\0')
                        return (EINVAL);
		/* link_0 to link_15 is valid */
                if (tag > NG_OSI_TUN_MAX_TAG)
                        return (EINVAL);

                /*
                 * Do not create twice a link hook
                 */
                if (priv->osi_tun_links[tag] != NULL)
                        return (EISCONN);

                /*
                 * Register the per-link private data
                 */
#if !defined(M_ZERO)
		hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT);
#else
		hpriv = ng_malloc(sizeof(*hpriv), M_NOWAIT | M_ZERO);
#endif
                if (hpriv == NULL)
                        return (ENOMEM);
#if !defined(M_ZERO)
                bzero(hpriv, sizeof(*hpriv));
#endif
                hpriv->tag = tag;
                NG_HOOK_SET_PRIVATE(hook, hpriv);

                /*
                 * Initialize the hash entry
                 */
                priv->osi_tun_links[tag] = hook;
                return 0;
        /*
         * Check for a lower hook
         *
         */
        } else if (strcmp(name, NG_OSI_TUN_HOOK_LOWER) == 0) {

                /*
                 * Do not connect twice a lower hook
                 */
                if (priv->osi_tun_lower != NULL)
                        return (EISCONN);

                priv->osi_tun_lower = hook;
                return 0;
        }

        /* Unknown hook name */
        return (EINVAL);

}

/*
 * Receive data
 *
 * Handle incoming data on a hook.
 *
 * Called at splnet() or splimp()
 */
static int
ng_osi_tun_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
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
        if (hook == priv->osi_tun_lower) {
                error = ng_osi_tun_recv_lower(node, m, meta);
                return error;
        }
	/* Handle outgoing data frame to the link_x nodes */
	error = ng_osi_tun_xmit_data(node, m, meta, NG_HOOK_PRIVATE(hook));
        return error;
}

hook_p
get_link_hook (priv_p priv, struct nsap_addr *local, struct nsap_addr *remote)
{
	int i;
	hookpriv_p hpriv;

	for (i = 0; i < NG_OSI_TUN_MAX_TAG; i++) {
		if (priv->osi_tun_links[i]) {
			hpriv = NG_HOOK_PRIVATE(priv->osi_tun_links[i]);
			TRACE("check i=%d-----\n",i);
			TRACE("hpriv->remote:  ");
			LOG_NSAP(hpriv->remote);
			TRACE("hpriv->local:  ");
			LOG_NSAP(hpriv->local);
			if (hpriv->rlen != 0 && hpriv->llen != 0)
				if (!memcmp (remote, &hpriv->remote, hpriv->rlen-1) &&
					!memcmp (local, &hpriv->local, hpriv->llen-1)) {
					TRACE("get i=%d\n",i);
					return priv->osi_tun_links[i];
				}
		}
	}
	return NULL;
}

/*
 * Receive data from lower layers
 * Consume the mbuf and meta.
 *
 * Called at splnet() or splimp()
 */
static int
ng_osi_tun_recv_lower(node_p node, struct mbuf *m, meta_p meta)
{
        const priv_p priv = NG_NODE_PRIVATE(node);
        struct clnp_hdr_fix *clnpfixhdr;
        hook_p ohook = NULL;
        int error = 0;
	uint8_t *ptr;
	uint8_t lolen;
	struct nsap_addr *localaddr, *remoteaddr;

	TRACE("recv_lower\n");

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

#define REQ_TUN_SZ_PKT_ANALYSIS_IN (sizeof(*clnpfixhdr) + MAX_OSI_LEN + 1)
        if (m->len < REQ_TUN_SZ_PKT_ANALYSIS_IN) {
                TRACE ("LX skb len (%d)\n", m->len);
                NG_FREE_DATA(m, meta);
                return (EINVAL);
        }
        if (!pskb_may_pull (m,  REQ_TUN_SZ_PKT_ANALYSIS_IN)) {
                TRACE ("LX skb_may_pull (%d)\n", m->len);
                NG_FREE_DATA(m, meta);
                return (EINVAL);
        }

        clnpfixhdr = mtod(m, struct clnp_hdr_fix *);
	ptr = (uint8_t *)clnpfixhdr;
	/* keep only CLNP packets 0x81, first byte of payload == 0xCC */
	if (clnpfixhdr->nlpid != NLPID_CLNP ||
	    *(ptr + clnpfixhdr->len) != CLNP_SPI_IP) {
		TRACE ("nlpid(0x%x)!=0x81,(ptr+%d)(0x%x)!=0xcc\n",clnpfixhdr->nlpid,clnpfixhdr->len,*(ptr + clnpfixhdr->len));
		error = EINVAL;
		goto drop;
	}
	if (!iso_gen_csum (ptr, CLNP_CKSUM_OFF, clnpfixhdr->len, 0)) {
		TRACE("Checksum Failure...drop\n");
		error = EINVAL;
		goto drop;
	}
	ptr += sizeof (struct clnp_hdr_fix);
	lolen = *ptr;
	/* NSEL of dst NSAP == 0x00 */
	if (*(ptr + lolen) != CLNP_SEL_NONOSI) {
		TRACE("(ptr+%d)(0x%x)!=0x00\n",lolen,*(ptr + lolen));
		error = EINVAL;
		goto drop;
	}
	ptr ++;
	localaddr = (struct nsap_addr *)ptr;
	TRACE("localaddr:  ");
	LOGP_NSAP(remoteaddr);
	ptr += lolen;
	ptr ++;
	remoteaddr = (struct nsap_addr *)ptr;
	TRACE("remoteaddr:  ");
	LOGP_NSAP(localaddr);
        /*
         * Get the upper hook
         */
	ohook = get_link_hook (priv, localaddr, remoteaddr);
	if (ohook == NULL) {
		TRACE("ohook==NULL, drop\n");
		error = ENOTCONN;
		goto drop;
	}
	/*
	 * Remove osi header.
	 */
	m_adj(m, clnpfixhdr->len + 1);
	/*
	 * Forward data to the output hook : link_x_
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
 * Add the osi header
 * Consume the mbuf and meta.
 *
 * Called at splnet() or splimp()
 */
static int
ng_osi_tun_xmit_data(node_p node, struct mbuf *m, meta_p meta, hookpriv_p hpriv)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct clnp_hdr_fix *clnpfixhdr = NULL;
	int error = 0, clnp_len;
	uint8_t *ptr;
	uint16_t total_len, new_id;
	struct clnp_segmentation *seg_ptr;

	TRACE("recv_high\n");

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

#define REQ_TUN_SZ_PKT_ANALYSIS_OUT (MAX_OSI_LEN + 1)
        if (m->len < REQ_TUN_SZ_PKT_ANALYSIS_OUT) {
                TRACE ("HIGH skb len (%d)\n", m->len);
                NG_FREE_DATA(m, meta);
                return (EINVAL);
        }
        if (!pskb_may_pull(m, REQ_TUN_SZ_PKT_ANALYSIS_OUT)) {
                TRACE ("HIGH skb_may_pull (%d)\n", m->len);
                NG_FREE_DATA(m, meta);
                return (EINVAL);
        }

	clnp_len = sizeof (struct clnp_hdr_fix) + (1 + hpriv->rlen) +
	           (1 + hpriv->llen) + sizeof (struct clnp_segmentation);

	/* Prepend the clnp header */
	M_PREPEND(m, clnp_len + 1, M_DONTWAIT);
	total_len = htons (m->len);

	clnpfixhdr = mtod(m, struct clnp_hdr_fix *);
	clnpfixhdr->nlpid = NLPID_CLNP;
	clnpfixhdr->len = clnp_len;
	clnpfixhdr->version = CLNP_VID;
	clnpfixhdr->ttl = CLNP_TTL;
	clnpfixhdr->flag = CLNP_FLAG;
	memmove (&clnpfixhdr->seglen, &total_len, sizeof(clnpfixhdr->seglen));

	ptr = (uint8_t *)(clnpfixhdr + 1);
	*ptr++ = hpriv->rlen;
	memmove ((struct nsap_addr *)ptr, &hpriv->remote, hpriv->rlen);
	ptr += hpriv->rlen;
	*ptr++ = hpriv->llen;
	memmove ((struct nsap_addr *)ptr, &hpriv->local, hpriv->llen);
	ptr += hpriv->llen;

	seg_ptr = (struct clnp_segmentation *)ptr;
	memset (seg_ptr, 0, sizeof (struct clnp_segmentation));
	new_id = htons (global_ID++);
	memmove (&seg_ptr->totallen, &total_len, sizeof(seg_ptr->totallen));
	memmove (&seg_ptr->dataid, &new_id, sizeof(seg_ptr->dataid));
	ptr = (uint8_t *)(seg_ptr + 1);

	iso_gen_csum ((uint8_t *)clnpfixhdr, CLNP_CKSUM_OFF, clnp_len, 1);
	TRACE("clnpfixhdr->chsum  C0= %02x C1=%02x\n",
	              clnpfixhdr->chsum_C0, clnpfixhdr->chsum_C1);

	*ptr = CLNP_SPI_IP;

	/*
	 * Send packet
	 * The mbuf and meta are consumed by the nodes of the peers.
	 */
	NG_SEND_DATA(error, priv->osi_tun_lower, m, meta);

	/*
	 * When NG_SEND_DATA fails, the mbuf and meta do not need to be
	 * freed because it has already been done by the peer's node.
	 */
	return error;
}

/*
 * Shutdown node
 *
 * Free the private data.
 *
 * Called at splnet()
 */
static int
ng_osi_tun_rmnode(node_p node)
{
#ifdef SPLASSERT
        SPLASSERT(net, __FUNCTION__);
#endif

        node->flags |= NG_INVALID;
        ng_cutlinks(node);
        ng_unname(node);

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
ng_osi_tun_disconnect(hook_p hook)
{
        const node_p node = NG_HOOK_NODE(hook);
        const priv_p priv = NG_NODE_PRIVATE(node);

        /* Zero out hook pointer */
        if (hook == priv->osi_tun_lower)
                priv->osi_tun_lower = NULL;
        else {
                hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);

                /*
                 * Clean the hash entry
                 */
                KASSERT(priv->osi_tun_links[hpriv->tag] != NULL);
                priv->osi_tun_links[hpriv->tag] = NULL;

                NG_HOOK_SET_PRIVATE(hook, NULL);
                ng_free(hpriv);
	}

        /* Go away if no longer connected to anything */
        if (node->numhooks == 0)
                ng_rmnode(node);
        return (0);
}

/*
 * return 1 means checksum is disabled
 */
static int
iso_gen_csum (uint8_t *ptr, int ck_offset, int len, int compute)
{
    int    c0 = 0, c1 = 0;
    int    i = 0;
    uint8_t *p = ptr;

    if (compute) {
        ptr[ck_offset] = 0;
        ptr[ck_offset+1] = 0;
    } else {
        /* cks set to 0: no check ! */
        if ((ptr[ck_offset] == 0) && (ptr[ck_offset+1] == 0))
            return 1;
    }
    if (skip_cksum)
        return 1;

    while (i < len) {
        c0 = (c0 + *p++);
        c1 += c0;
        i++;
        ;
    }
    if (compute) {
        c1 = (((c0 * (len - 8)) - c1) % 255);
        ptr[ck_offset] = (u_char) ((c1 < 0) ? c1 + 255 : c1);
        c1 = (-(int) (c1 + c0)) % 255;
        ptr[ck_offset+1] = (u_char) (c1 < 0 ? c1 + 255 : c1);
        return 0;
    }
    return (((c0 % 255) == 0) && ((c1 % 255) == 0));
}
