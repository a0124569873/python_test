/*
 * Copyright  2003-2013 6WIND S.A.
 */

/* Specifications :
 * Add ethernet header to received packets and forward them
 */

#if defined(__LinuxKernelVNB__)

#include <linux/version.h>
#include <linux/module.h>
#include <linux/in6.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <netgraph/vnblinux.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/addrconf.h>
#include <net/ip6_checksum.h>

#elif defined(__FastPath__)
#include "fp-netgraph.h"
#ifdef CONFIG_MCORE_IP
#include "fp-fragment.h"
#endif
#endif

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/ng_ether.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_mpls_ether.h>
#include <netgraph/vnb_in.h>
#include <netgraph/vnb_ip.h>
#include <netgraph/vnb_ip6.h>
#include <netgraph/vnb_udp.h>
#include <netgraph/ng_mpls_oam.h>
#include <netgraph/ng_mpls_common.h>

#ifdef NG_SEPARATE_MALLOC
MALLOC_DEFINE(M_NETGRAPH_MPLS_ETHER, "ng_mpls_ether",
	      "netgraph MPLS");
#else
#define M_NETGRAPH_MPLS_ETHER M_NETGRAPH
#endif

#ifdef __LinuxKernelVNB__
#define NG_MPLS_ETHER_STATS
#endif

/* XXX stats should be per-core */
#ifdef NG_MPLS_ETHER_STATS
#define STATS_ADD(priv, name, val) do {				\
		priv_p __priv = priv;				\
		struct ng_mpls_ether_stats *stats;		\
		stats = &__priv->stats;				\
		stats->name += (val);				\
	} while(0)
#else
#define STATS_ADD(priv, name, val) do { } while(0)
#endif

#define STATS_INC(priv, name) STATS_ADD(priv, name, 1)

// #define NG_MPLS_ETHER_DEBUG
#ifdef NG_MPLS_ETHER_DEBUG
#ifdef __LinuxKernelVNB__
#define NG_MPLS_ETHER_DPRINTF(x, y...) do { \
		log(LOG_DEBUG, "%s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#else
/* for now : force DEBUG output */
#define NG_MPLS_ETHER_DPRINTF(x, y...) do { \
		FP_LOG(LOG_DEBUG, VNB, "FP %s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#endif
#else
#define NG_MPLS_ETHER_DPRINTF(args...) do {} while(0)
#endif

#if defined(CONFIG_VNB_MPLS_ETHER_MAX_IN)
#define NG_MPLS_ETHER_MAX_IN CONFIG_VNB_MPLS_ETHER_MAX_IN
#else
#define NG_MPLS_ETHER_MAX_IN 64
#endif

/* Per-node private data */
struct ng_mpls_private {
	node_p          node;			/* back pointer to node */
	struct ng_mpls_ether_config conf;	/* node configuration	 */
	hook_p          ether_in[NG_MPLS_ETHER_MAX_IN];	/* lower hook 		 */
	hook_p          ether_out;		/* upper hook	   	 */
#ifdef NG_MPLS_ETHER_STATS
	struct ng_mpls_ether_stats stats;	/* node stats 		 */
#endif
};

typedef struct ng_mpls_private *priv_p;

struct ng_mpls_hook_private {
	unsigned long tag;
};

typedef struct ng_mpls_hook_private *hookpriv_p;

/* Netgraph node methods */
static ng_constructor_t ng_mpls_constructor;
static ng_rcvmsg_t ng_mpls_rcvmsg;
static ng_shutdown_t ng_mpls_rmnode;
static ng_newhook_t ng_mpls_newhook;
static ng_findhook_t ng_mpls_findhook;
static ng_disconnect_t ng_mpls_disconnect;


/* Local processing */

/* Packets received from lower hook */
static int
ng_mpls_rcv_ether(hook_p hook, struct mbuf * m, meta_p meta);
static int
ng_mpls_send_ether_out(hook_p hook, struct mbuf * m, meta_p meta);

/* Local variables */

/* Parse type for struct ng_mpls_ether_config */
static const struct ng_parse_struct_field
                ng_mpls_ether_config_type_fields[] = NG_MPLS_ETHER_CONFIG_TYPE_INFO;

static const struct ng_parse_type ng_mpls_ether_config_type = {
		.supertype = &ng_parse_struct_type,
		.info = &ng_mpls_ether_config_type_fields
};

#ifdef NG_MPLS_ETHER_STATS
/* Parse type for struct ng_mpls_ether_stats */
static const struct ng_parse_struct_field
                ng_mpls_ether_stats_type_fields[] = NG_MPLS_ETHER_STATS_TYPE_INFO;

static const struct ng_parse_type ng_mpls_ether_stats_type = {
		.supertype = &ng_parse_struct_type,
		.info = &ng_mpls_ether_stats_type_fields
};
#endif

static const struct ng_cmdlist ng_mpls_cmdlist[] = {
	{
		NGM_MPLS_ETHER_COOKIE,
		NGM_MPLS_ETHER_GET_ENADDR,
		"getenaddr",
		.mesgType = NULL,
		.respType = &ng_ether_enaddr_type
	},
	{
		NGM_MPLS_ETHER_COOKIE,
		NGM_MPLS_ETHER_SET_ENADDR,
		"setenaddr",
		.mesgType = &ng_ether_enaddr_type,
		.respType = NULL
	},
	{
		NGM_MPLS_ETHER_COOKIE,
		NGM_MPLS_ETHER_GET_MTU,
		"getmtu",
		.mesgType = NULL,
		.respType = &ng_parse_int16_type
	},
	{
		NGM_MPLS_ETHER_COOKIE,
		NGM_MPLS_ETHER_SET_MTU,
		"setmtu",
		.mesgType = &ng_parse_int16_type,
		.respType = NULL
	},
#ifdef NG_MPLS_ETHER_STATS
	{
		NGM_MPLS_ETHER_COOKIE,
		NGM_MPLS_ETHER_GET_STATS,
		"getstats",
		.mesgType = NULL,
		.respType = &ng_mpls_ether_stats_type
	},
	{
		NGM_MPLS_ETHER_COOKIE,
		NGM_MPLS_ETHER_CLR_STATS,
		"clrstats",
		.mesgType = NULL,
		.respType = NULL
	},
	{
		NGM_MPLS_ETHER_COOKIE,
		NGM_MPLS_ETHER_GETCLR_STATS,
		"getclrstats",
		.mesgType = NULL,
		.respType = &ng_mpls_ether_stats_type
	},
#endif

	{ 0, 0, NULL, NULL, NULL }
};

/* Node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, ng_mpls_typestruct) = {
	.version = NG_VERSION,
	.name = NG_MPLS_ETHER_NODE_TYPE,
	.mod_event = NULL,			/* Module event handler (optional) */
	.constructor = ng_mpls_constructor,	/* Node constructor */
	.rcvmsg = ng_mpls_rcvmsg,		/* control messages come here */
	.shutdown = ng_mpls_rmnode,		/* reset, and free resources */
	.newhook = ng_mpls_newhook,		/* first notification of new hook */
	.findhook = ng_mpls_findhook,		/* specific findhook function */
	.connect = NULL,			/* final notification of new hook */
	.afterconnect = NULL,
	.rcvdata = NULL,			/* Only specific receive data functions */
	.rcvdataq = NULL,			/* Only specific receive data functions */
	.disconnect = ng_mpls_disconnect,	/* notify on disconnect */
	.rcvexception = NULL,			/* exceptions come here */
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist = ng_mpls_cmdlist,		/* commands we can convert */
};

NETGRAPH_INIT(mpls_ether, &ng_mpls_typestruct);
NETGRAPH_EXIT(mpls_ether, &ng_mpls_typestruct);

#ifdef __LinuxKernelVNB__
extern int ng_mpls_ilm2nhlfe_init(void);
extern int ng_mpls_nhlfe_init(void);
extern int ng_mpls_oam_init(void);
extern void ng_mpls_ilm2nhlfe_exit(void);
extern void ng_mpls_nhlfe_exit(void);
extern void ng_mpls_oam_exit(void);

int ng_mpls_init(void)
{
	if (ng_mpls_ilm2nhlfe_init() != 0)
		return -EINVAL;
	if (ng_mpls_nhlfe_init() != 0)
		return -EINVAL;
	if (ng_mpls_ether_init() != 0)
		return -EINVAL;
	if (ng_mpls_oam_init() != 0)
		return -EINVAL;

	return 0;
}

void ng_mpls_exit(void)
{
	ng_mpls_oam_exit();
	ng_mpls_ether_exit();
	ng_mpls_nhlfe_exit();
	ng_mpls_ilm2nhlfe_exit();
	return;
}
#endif

/******************************************************************
			NETGRAPH NODE METHODS
******************************************************************/

/*
 * Node constructor
 *
 * Called at splnet() */
static int
ng_mpls_constructor(node_p * nodep, ng_ID_t nodeid)
{
	priv_p          priv;
	int             error;

#ifdef SPLASSERT
	SPLASSERT(net, __FUNCTION__);
#endif

	/* Call superclass constructor that mallocs *nodep */
	if ((error = ng_make_node_common_and_priv(&ng_mpls_typestruct, nodep,
						  &priv, sizeof(*priv), nodeid))) {
		return (error);
	}

	bzero(priv, sizeof(*priv));

	NG_NODE_SET_PRIVATE(*nodep, priv);
	priv->node = *nodep;

	/* Done */
	return (0);
}

/*
 * Method for attaching a new hook
 * Two possible hooks : ether_in and ether_out
 * to receive and transmit data
 */

static int
ng_mpls_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);

	/* Check for a ether_in hook */
	if (strncmp(name, NG_MPLS_HOOK_ETHER_IN_PREFIX,
		    sizeof (NG_MPLS_HOOK_ETHER_IN_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;
		hookpriv_p      hpriv;

		/* Get the link index Parse ether_in_0xa, ether_in_10, ... */
		tag_str = name + sizeof(NG_MPLS_HOOK_ETHER_IN_PREFIX) - 1;

		/* Allow decimal and hexadecimal values. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return (EINVAL);

		if (tag >= NG_MPLS_ETHER_MAX_IN)
			return (EISCONN);

		/* Do not connect twice a lower hook */
		if (priv->ether_in[tag] != NULL)
			return (EISCONN);

		/* Register the per-link private data */
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

		hook->hook_rcvdata = ng_mpls_rcv_ether;
		priv->ether_in[tag] = hook;
		return 0;

		/* Check for a ether_out hook */
	} else if (strcmp(name, NG_MPLS_HOOK_ETHER_OUT) == 0) {
		/* Do not connect twice a r hook */
		if (priv->ether_out != NULL)
			return (EISCONN);

		priv->ether_out = hook;
		return 0;
	}

	/* Unknown hook name */
	return (EINVAL);
}

static hook_p
ng_mpls_findhook(node_p node, const char *name)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	hook_p hook = NULL;

	/* Check for a ether_in hook */
	if (strncmp(name, NG_MPLS_HOOK_ETHER_IN_PREFIX,
		    sizeof (NG_MPLS_HOOK_ETHER_IN_PREFIX) - 1) == 0) {
		const char     *tag_str;
		char           *err_ptr;
		unsigned long   tag;

		/* Get the link index Parse ether_in_0xa, ether_in_10, ... */
		tag_str = name + sizeof(NG_MPLS_HOOK_ETHER_IN_PREFIX) - 1;

		/* Only decimal and hexadecimal values are allowed. The hexadecimal values must
		 * be prefixed by 0x */
		tag = strtoul(tag_str, &err_ptr, 0);

		if ((*err_ptr) != '\0')
			return NULL;

		if (tag >= NG_MPLS_ETHER_MAX_IN)
			return NULL;

		hook = priv->ether_in[tag];

		/* Check for a ether_out hook */
	} else if (strcmp(name, NG_MPLS_HOOK_ETHER_OUT) == 0) {
		hook = priv->ether_out;
	}

	return hook;
}

static int
ng_mpls_rcvmsg(node_p node, struct ng_mesg * msg,
	       const char *retaddr, struct ng_mesg ** rptr, struct ng_mesg **nl_msg)
{
	const priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int             error = 0;

	switch (msg->header.typecookie) {
		/* Case node id (COOKIE) is suitable */
	case NGM_MPLS_ETHER_COOKIE:
		switch (msg->header.cmd) {
		case NGM_MPLS_ETHER_GET_ENADDR:
			{
				NG_MKRESPONSE(resp, msg, VNB_ETHER_ADDR_LEN, M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				/* Display ethernet address from ng_mpls_ether_config */
				bcopy(priv->conf.edst, resp->data, VNB_ETHER_ADDR_LEN);
				break;
			}
		case NGM_MPLS_ETHER_SET_ENADDR:
			{
				struct ng_mpls_ether_config *const conf =
				(struct ng_mpls_ether_config *) msg->data;

				if (msg->header.arglen != VNB_ETHER_ADDR_LEN) {
					error = EINVAL;
					break;
				}
				/* Store ethernet address into ng_mpls_ether_config */
				priv->conf = *conf;
				break;
			}
		case NGM_MPLS_ETHER_GET_MTU:
			{
				u_int16_t * p_mtu;
				NG_MKRESPONSE(resp, msg, sizeof(u_int16_t), M_NOWAIT);
				if (resp == NULL) {
					error = ENOMEM;
					break;
				}
				/* Get Max transmission unit of mpls tunnel's lower link layer */
				p_mtu = (u_int16_t *) resp->data;
				*p_mtu = priv->conf.mtu;
				break;
			}
		case NGM_MPLS_ETHER_SET_MTU:
			{
				u_int16_t * p_mtu;
				if (msg->header.arglen != sizeof(u_int16_t)) {
					error = EINVAL;
					break;
				}
				/* Set Max transmission unit of mpls tunnel's lower link layer */
				p_mtu = (u_int16_t *) msg->data;
				priv->conf.mtu = *p_mtu;
				break;
			}
#ifdef NG_MPLS_ETHER_STATS
		case NGM_MPLS_ETHER_GET_STATS:
		case NGM_MPLS_ETHER_CLR_STATS:
		case NGM_MPLS_ETHER_GETCLR_STATS:
			{
				if (msg->header.cmd != NGM_MPLS_ETHER_CLR_STATS) {
					NG_MKRESPONSE(resp, msg,
					     sizeof(priv->stats), M_NOWAIT);
					if (resp == NULL) {
						error = ENOMEM;
						break;
					}
					memcpy(resp->data,
					 &priv->stats, sizeof(priv->stats));
				}
				if (msg->header.cmd != NGM_MPLS_ETHER_GET_STATS)
					memset(&priv->stats, 0, sizeof(priv->stats));
				break;
			}
#endif

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

/* Package some parameters for: fragmentation API */
struct mpls_frag_param {
	hook_p hookp;
	meta_p meta;
#define MPLS_MAX_LABELS	4
	mpls_header_t label[MPLS_MAX_LABELS];
	int label_nbs;
};

static int mpls_send_fragment(struct mbuf *m, void *p1, void *p2)
{
	struct mpls_frag_param *param = (struct mpls_frag_param *)p1;
	int label_bytes;

	label_bytes = sizeof(mpls_header_t) * param->label_nbs;

	/* prepend mpls label stack */
	M_PREPEND(m, label_bytes, M_DONTWAIT);
	if (m == NULL)
	{
		NG_FREE_META(param->meta);
		return -1;
	}

	memcpy(mtod(m, char *), param->label, label_bytes);

	/*
	 * after fragmentation, this packet length is small enough to be
	 * sent successfully by ng_mpls_send_ether_out
	 */
	ng_mpls_send_ether_out(param->hookp, m, param->meta);
	return 0;
}

#if defined (__FastPath__)

#ifdef CONFIG_MCORE_IP
#define mpls4_fragment fp_ip_fragment
#else
#define mpls4_fragment(m,w,x,y,z) do {\
	/* no warning about unused var */ \
	(void) (w); \
	(void) (x); \
	(void) (y); \
	(void) (z); \
	m_freem(m); \
} while(0)
#endif

#elif defined (__LinuxKernelVNB__)
static int mpls4_fragment(struct mbuf *m, uint64_t mtu,
			  int (*mpls_send)(struct mbuf *m, void *p1, void *p2),
			  void *p1, void *p2)
{
	struct mbuf *newm = NULL;
	struct iphdr *ip, *ip2;
	uint32_t mtu_adj, ip_offset;
	uint16_t flag_off;
	uint8_t iphdrlen;
	struct mpls_frag_param *param =
		(struct mpls_frag_param *)p1;


	if (unlikely(m_pullup(m, sizeof(struct iphdr)) == NULL))
		goto fail;

	ip = mtod(m, struct iphdr *);
	iphdrlen = ip->ihl << 2;

	if (unlikely(m_pullup(m, iphdrlen) == NULL))
		goto fail;

	/* Fragment should be 8B aligned. */
	mtu_adj = ((mtu - iphdrlen) & ~7) + iphdrlen;
	flag_off = ntohs(ip->frag_off);
	ip_offset = (flag_off & IP_OFFSET) << 3;

	while (m) {
		/* if we need to create a new frag */
		if (MBUF_LENGTH(m) > mtu_adj) {
			/* split mbuf at offset mtu_adj */
			newm = m_split(m, mtu_adj, M_NOWAIT);
			if (unlikely(newm == NULL)) {
				goto fail;
			}

			/* prepend ip header to newm */
			ip = mtod(m, struct iphdr *);
			M_PREPEND(newm, iphdrlen, M_DONTWAIT);
			if (unlikely(newm == NULL))
				goto fail;

			ip2 = mtod(newm, struct iphdr *);
			memcpy(ip2, ip, iphdrlen);
		}
		else {
			ip = mtod(m, struct iphdr *);
			newm = NULL;
		}

		/* fix ip header for mbuf m */
		ip->frag_off &= ~htons(IP_OFFSET | IP_MF);
		ip->frag_off |= htons((ip_offset >> 3) & IP_OFFSET);
		if ((newm != NULL) || (flag_off & IP_MF))
			ip->frag_off |= htons(IP_MF);
		ip->tot_len = htons(MBUF_LENGTH(m));
		ip->check = 0;
		ip->check = ip_compute_csum((void *)ip, iphdrlen);

		/* update offset for next mbuf */
		ip_offset += MBUF_LENGTH(m) - iphdrlen;

		mpls_send(m, p1, p2);
		m = newm;
	}

	return 0;
fail:
	NG_FREE_META(param->meta);

	if (m)
		m_freem(m);
	if (newm)
		m_freem(newm);
	return 1;
}
#endif

#if defined (CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE) || defined (CONFIG_MCORE_IPV6)
#define MPLS_IPV6
#endif

#if defined (MPLS_IPV6)
/*
 * int ipv6_fraghdr_offset(const struct mbuf *m):
 * Check whether a packet has Fragment Header
 *
 * if yes, return: Fragment Header offset.
 * else,   retunn: -1.
 */
static int ipv6_fraghdr_offset(struct mbuf *m)
{
	struct vnb_ip6_hdr *ip6h;
	int start = sizeof(struct vnb_ip6_hdr);
	uint8_t nexthdr;

	if (unlikely(m_pullup(m, start) == NULL))
		return -1;

	ip6h = mtod(m, struct vnb_ip6_hdr *);
	nexthdr = ip6h->ip6_nxt;
	while (vnb_ipv6_ext_hdr(nexthdr)) {
		struct vnb_ip6_ext _hdr, *hp;
		int hdrlen;

		if (nexthdr == VNB_NEXTHDR_NONE)
			return -1;
#if defined (__FastPath__)
		hp = &_hdr;
		if (m_copytobuf(&_hdr, m, start, sizeof(_hdr)) != sizeof(_hdr))
			return -1;
#elif defined (__LinuxKernelVNB__)
		hp = skb_header_pointer(m, start, sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return -1;
#endif
		if (nexthdr == VNB_NEXTHDR_FRAGMENT)
			return start;
		else if (nexthdr == VNB_NEXTHDR_AUTH)
			hdrlen = (hp->ip6e_len + 2) << 2;
		else
			hdrlen = vnb_ipv6_optlen(hp);

		nexthdr = hp->ip6e_nxt;
		start += hdrlen;
	}
	return -1;
}

/*
 * Fragment an IPv6 packet which already has Fragment Header
 *
 * RFC2460 says: An IPv6 packet can be divided to Unfragmentable part
 * and Fragment part. Usually, the bytes before Fragment Header can't
 * be fragmented, we only fragment the payload after Fragment Header.
 */
#define MPLS_MAX_UNFRAGMENT_BYTES 512
static int mpls6_fragment(struct mbuf *m, uint64_t mtu,
			  int (*mpls_send)(struct mbuf *m, void *p1, void *p2),
			  void *p1, void *p2)
{
	struct mbuf *newm = NULL;
	struct vnb_ip6_hdr *ip6;
	char unfragment[MPLS_MAX_UNFRAGMENT_BYTES];
	long unfrag_len = (long)p2 + sizeof(struct vnb_ip6_frag);
	struct vnb_ip6_frag *ip6fh;
	uint16_t offset, last_frag;
	uint32_t mtu_adj;
	struct mpls_frag_param *param =
		(struct mpls_frag_param *)p1;

	if (unlikely(unfrag_len > MPLS_MAX_UNFRAGMENT_BYTES))
		/* Should not happen */
		return mpls_send(m, p1, p2);

	if (unlikely(m_pullup(m, unfrag_len) == NULL))
			goto fail;

	ip6 = mtod(m, struct vnb_ip6_hdr *);
	ip6fh = (struct vnb_ip6_frag *)
		((char *)ip6 + unfrag_len - sizeof(struct vnb_ip6_frag));
	offset = ntohs(ip6fh->ip6f_offlg) & ~7;
	last_frag = ntohs(ip6fh->ip6f_offlg) & 0x1;
	/* Adjust of data in IPv6 packet. Fragment should be 8B aligned. */
	mtu_adj = (mtu - unfrag_len) & ~7;

	/* Save original unfragmented part */
	memcpy(unfragment, mtod(m, void *), unfrag_len);

	/* remove ipv6 header, safe because m_pullup succeed */
	m_adj(m, unfrag_len);

	while (m) {
		/* if we need to create a new frag */
		if (MBUF_LENGTH(m) > mtu_adj) {
			/* split mbuf at offset mtu_adj */
#if defined (__FastPath__)
			newm = m_split(m, mtu_adj);
#else
			newm = m_split(m, mtu_adj, M_NOWAIT);
#endif
			if (unlikely(newm == NULL)) {
				goto fail;
			}
		}
		else {
			newm = NULL;
		}

		/* Prepend unfragmented part */
		M_PREPEND(m, unfrag_len, M_DONTWAIT);
		if (m == NULL)
			goto fail;

		ip6 = mtod(m, struct vnb_ip6_hdr *);
		memcpy(ip6, unfragment, unfrag_len);

		ip6fh = (struct vnb_ip6_frag *)((char *)ip6 + unfrag_len - sizeof(struct vnb_ip6_frag));
		ip6fh->ip6f_offlg = htons(offset);

		if (newm != NULL || last_frag != 0)
		     ip6fh->ip6f_offlg |= VNB_IP6F_MORE_FRAG;

		ip6->ip6_plen = htons(MBUF_LENGTH(m) - sizeof(struct vnb_ip6_hdr));

		mpls_send(m, p1, p2);

		m = newm;
		offset += mtu_adj;
	}

	return 0;
fail:
	NG_FREE_META(param->meta);

	if (m)
		m_freem(m);
	if (newm)
		m_freem(newm);
	return 1;
}
#endif

#if defined (__LinuxKernelVNB__)
static struct mbuf *
mpls_new_icmp_error_packet(struct mbuf *m, int mtu, int max_pktlen)
{
	struct mbuf *m_icmp;
	struct iphdr *iph, *orig_iph;
	struct icmphdr *icmph;
	char *payload;
	int payload_len;

	max_pktlen = (int)MBUF_LENGTH(m) > max_pktlen ? max_pktlen : (int)MBUF_LENGTH(m);
	payload_len = max_pktlen - sizeof(struct iphdr) - sizeof(struct icmphdr);

	m_icmp = m_alloc();
	if (unlikely(m_icmp == NULL))
		return NULL;

	iph = (struct iphdr *)m_append(m_icmp, sizeof(struct iphdr));
	if (unlikely(iph == NULL))
		goto fail;

	orig_iph = mtod(m, struct iphdr *);

	iph->version = IPVERSION;
	iph->ihl = 5;
	iph->tos = IPTOS_PREC_INTERNETCONTROL;
	iph->ttl = IPDEFTTL;

	/*
	 * For ICMP message source ip addr selection:
	 * 1. Firstly try to select an local ip address,
	 * 2. If failed, select dest ip addr in original pkt.
	 */
	iph->saddr = inet_select_addr(dev_get_by_index
				      (dev_net(m->dev), m_iif(m)),
				      0, RT_SCOPE_LINK);
	iph->saddr = (iph->saddr != 0) ? iph->saddr: orig_iph->daddr;

	iph->daddr = orig_iph->saddr;
	iph->protocol = IPPROTO_ICMP;
	iph->id = orig_iph->id;
	iph->frag_off = 0;
	iph->tot_len = ntohs(max_pktlen);
	iph->check = 0;
	iph->check= ip_compute_csum((void *)iph, sizeof(struct iphdr));

	icmph = (struct icmphdr *)m_append(m_icmp, sizeof(struct icmphdr));
	if (unlikely(icmph == NULL))
		goto fail;

	icmph->type = ICMP_DEST_UNREACH;
	icmph->code = ICMP_FRAG_NEEDED;
	icmph->un.gateway = ntohl(mtu);
	icmph->checksum = 0;

	payload = m_append(m_icmp, payload_len);
	if (unlikely(payload == NULL))
		goto fail;

	skb_copy_bits(m, 0, payload, payload_len);

	icmph->checksum = ip_compute_csum((void *)icmph,
			sizeof(struct icmphdr) + payload_len);
	return m_icmp;

fail:
	m_freem(m_icmp);
	return NULL;
}

#ifdef MPLS_IPV6
static struct mbuf *
mpls_new_icmpv6_error_packet(struct mbuf *m, int mtu, int max_pktlen)
{
	struct mbuf *m_icmp6;
	struct ipv6hdr *ip6h, *orig_ip6h;
	struct icmp6hdr *icmp6h;
	char *payload;
	int payload_len;
	__wsum csum = 0;

	max_pktlen = (int)MBUF_LENGTH(m) > max_pktlen ? max_pktlen : (int)MBUF_LENGTH(m);
	payload_len = max_pktlen - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr);

	m_icmp6 = m_alloc();
	if (unlikely(m_icmp6 == NULL))
		return NULL;

	ip6h = (struct ipv6hdr *)m_append(m_icmp6, sizeof(struct ipv6hdr));
	if (unlikely(ip6h == NULL))
		goto fail;

	orig_ip6h = mtod(m, struct ipv6hdr *);

	memset(ip6h, 0, sizeof(struct ipv6hdr) - 2 * sizeof(struct in6_addr));
	ip6h->version = 6;
	ip6h->nexthdr = NEXTHDR_ICMP;
	ip6h->hop_limit = IPDEFTTL;
	ip6h->payload_len = htons(max_pktlen - sizeof(struct ipv6hdr));

	memcpy(&ip6h->daddr, &orig_ip6h->saddr, sizeof(struct in6_addr));
	/*
	 * For ICMPv6 message source ipv6 addr selection:
	 * 1. Firstly try to select an local ipv6 address,
	 * 2. If failed, select dest ip addr in original pkt.
	 */
	if ((ipv6_dev_get_saddr(dev_net(m->dev),
#ifdef SO_VRFID
				dev_vrfid(m->dev),
#endif
				dev_get_by_index(dev_net(m->dev), m_iif(m)),
				&ip6h->daddr, 0, &ip6h->saddr) != 0) ||
	    (ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_LINKLOCAL)) {
		memcpy(&ip6h->saddr, &orig_ip6h->daddr, sizeof(struct in6_addr));
	}

	icmp6h = (struct icmp6hdr *)m_append(m_icmp6, sizeof(struct icmp6hdr));
	if (unlikely(icmp6h == NULL))
		goto fail;

	icmp6h->icmp6_type = ICMPV6_PKT_TOOBIG;
	icmp6h->icmp6_code = 0;
	icmp6h->icmp6_cksum = 0;
	icmp6h->icmp6_pointer = htonl(mtu);

	payload = m_append(m_icmp6, payload_len);
	if (unlikely(payload == NULL))
		goto fail;

	skb_copy_bits(m, 0, payload, payload_len);

	/*
	 * Compared with IPv4 ICMP checksum, ICMPv6 cksum should include
	 * a pseudo-header:
	 * 1. IPv6 saddr
	 * 2. IPv6 daddr
	 * 3. Payload len in IPv6 Header
	 * 4. Nexthdr in IPv6 Header
	 */
	csum = csum_partial((void *)icmp6h, sizeof(struct icmp6hdr) + payload_len, csum);
	icmp6h->icmp6_cksum = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
			max_pktlen - sizeof(struct ipv6hdr), ip6h->nexthdr, csum);
	return m_icmp6;

fail:
	m_freem(m_icmp6);
	return NULL;
}
#endif
#endif

/*
 * Do fragmentation for MPLS packets
 *
 * return value:
 * 0: already forwarded or dropped, means no need further processing.
 * -1: caller of mpls_fragment need do further processing.
 */
static int mpls_fragment(struct mbuf *m, int mtu, hook_p hook, meta_p meta)
{
	mpls_header_t *mhdr_start, mhdr;
	struct mpls_frag_param param;
	int nlabels;
	struct vnb_ip *iph;
#if defined (__LinuxKernelVNB__)
	struct mbuf *m_icmp;
#if defined (MPLS_IPV6)
	struct mbuf *m_icmp6;
#endif
#endif
	nlabels = 0;
	if (unlikely(m_pullup(m, sizeof(mpls_header_t)) == NULL))
		goto pkt_error;
	mhdr_start = mtod(m, mpls_header_t *);
	mhdr.header = ntohl(mhdr_start[nlabels].header);
	while (mhdr.mhbs == 0) {
		nlabels++;

		if (unlikely(nlabels == MPLS_MAX_LABELS))
			goto pkt_error;
		if (unlikely(m_pullup(m, sizeof(mpls_header_t) * (nlabels + 1)) == NULL))
			goto pkt_error;

		/* m_pullup may update mbuf data pointer */
		mhdr_start = mtod(m, mpls_header_t *);
		mhdr.header = ntohl(mhdr_start[nlabels].header);
	}
	nlabels++;

	/* For access check: (ip version) of ip header */
	if (unlikely(m_pullup(m, sizeof (mpls_header_t) * nlabels +
			      sizeof (struct vnb_ip)) == NULL))
		goto pkt_error;

	mhdr_start = mtod(m, mpls_header_t *);
	iph = (struct vnb_ip *)&mhdr_start[nlabels];
	if (likely(iph->ip_v == IPVERSION)) {
		/* IPv4 case */
		if (ntohs(iph->ip_off) & VNB_IP_DF) {
#if defined (__FastPath__)
			/* ICMP message should be generated, send to kernel VNB */
			ng_send_exception(hook->node, hook, VNB2VNB_DATA, 0, m, meta);
			return 0;
#elif defined (__LinuxKernelVNB__)
			/*
			 * strip the mpls headers,
			 * safe because m_pullup succeed
			 */
			m_adj(m, sizeof(mpls_header_t) * nlabels);
			/* RFC says return as much as we can without exceeding 576 bytes. */
			m_icmp = mpls_new_icmp_error_packet(m, mtu - sizeof(mpls_header_t) * nlabels,
							    (mtu > 576 ? 576 : mtu) - sizeof(mpls_header_t) * nlabels);
			if (m_icmp) {
				/* prepend mpls label stack */
				M_PREPEND(m_icmp, sizeof(mpls_header_t) * nlabels, M_DONTWAIT);
				if (likely(m_icmp)) {
					memcpy(mtod(m_icmp, char *), mhdr_start, sizeof(mpls_header_t) * nlabels);

					/* call ng_mpls_send_ether_out to send this icmp packet to mpls tunnel */
					ng_mpls_send_ether_out(hook, m_icmp, meta);
				}
			}

			/* drop original big packet */
			NG_FREE_DATA(m, meta);
			return 0;
#endif
		}
		param.hookp = hook;
		param.meta  = meta;
		memcpy(param.label, mhdr_start, sizeof(mpls_header_t) * nlabels);
		param.label_nbs = nlabels;

		/*
		 * strip the mpls headers,
		 * safe because m_pullup succeed
		 */
		m_adj(m, sizeof(mpls_header_t) * nlabels);

		/*
		 * Do fragmentation, and then call
		 * mpls_send_fragment(finally call ng_mpls_send_ether_out())
		 * to send fragmented packets
		 */
		mpls4_fragment(m, mtu - sizeof(mpls_header_t) * nlabels,
			       mpls_send_fragment, &param, NULL);
		return 0;
	}
#ifdef MPLS_IPV6
	else if (likely(iph->ip_v == IP6VERSION)) {
		/* IPv6 case */
		long fragoff;

		/*
		 * strip the mpls headers,
		 * safe because m_pullup succeed
		 */
		memcpy(param.label, mhdr_start, sizeof(mpls_header_t) * nlabels);
		m_adj(m, sizeof(mpls_header_t) * nlabels);
		/*
		 * According to RFC3032 Chap3.5:
		 * -----------------------------------
		 * 1.When IP datagram contains more than 1280 bytes, or it doesn't have a fragment header
		 * we need to send ICMP Packet Too Big Message.
		 *
		 * 2.When IP datagram <= 1280 bytes,and it has fragment header.
		 * we need do fragmentation and forward them.
		 */
		if (MBUF_LENGTH(m) > 1280 || (fragoff = ipv6_fraghdr_offset(m)) < 0) {
#if defined (__FastPath__)
                        M_PREPEND(m, sizeof(mpls_header_t) * nlabels, M_DONTWAIT);
                        if (unlikely(m == NULL)) {
                                NG_FREE_META(meta);
                                return 0;
                        }
                        memcpy(mtod(m, char *), param.label, sizeof(mpls_header_t) * nlabels);

			ng_send_exception(hook->node, hook, VNB2VNB_DATA, 0, m, meta);
			return 0;
#else
			/* RFC says return as much as we can without exceeding 1280 bytes. */
			m_icmp6 = mpls_new_icmpv6_error_packet(m, mtu - sizeof(mpls_header_t) * nlabels,
							       (mtu > 1280 ? 1280 : mtu) - sizeof(mpls_header_t) * nlabels);
			if (m_icmp6) {
				/* prepend mpls label stack */
				M_PREPEND(m_icmp6, sizeof(mpls_header_t) * nlabels, M_DONTWAIT);
				if (likely(m_icmp6)) {
					memcpy(mtod(m_icmp6, char *), param.label, sizeof(mpls_header_t) * nlabels);

					/* call ng_mpls_send_ether_out to send this icmp packet to mpls tunnel */
					ng_mpls_send_ether_out(hook, m_icmp6, meta);
				}
			}

			/* drop original big packet */
			NG_FREE_DATA(m, meta);
#endif
		} else {
			param.hookp = hook;
			param.meta  = meta;
			param.label_nbs = nlabels;

			/*
			 * Do fragmentation, and then call
			 * mpls_send_fragment(finally call ng_mpls_send_ether_out())
			 * to send fragmented packets
			 */
			mpls6_fragment(m, mtu - sizeof(mpls_header_t) * nlabels,
				       mpls_send_fragment,
				       &param, (void *)fragoff);
		}
		return 0;
	}
#endif
	/* return -1: to let non-IPv4 & non-IPv6 packet be further processed */
	return -1;

pkt_error:
	NG_FREE_DATA(m, meta);
	/* no need more processing, so here we return 0 */
	return 0;
}

static int
ng_mpls_rcv_ether(hook_p hook, struct mbuf * m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	struct ng_mpls_ether_config conf;
	unsigned short mtu;

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	conf = priv->conf;
	mtu  = conf.mtu;
	if (mtu && MBUF_LENGTH(m) > mtu) {
		if (mpls_fragment(m, mtu, hook, meta) == 0)
			return 0;
	}

	return (ng_mpls_send_ether_out(hook, m, meta));
}

static int
ng_mpls_send_ether_out(hook_p hook, struct mbuf * m, meta_p meta)
{
	const priv_p priv = hook->node_private;
	struct ng_mpls_ether_config conf;
	struct vnb_ether_header *ehdr;
	int error = 0;
#ifdef __LinuxKernelVNB__
	mpls_oam_meta_t *lsp_meta;
	mpls_header_t *pmhdr, mhdr;
#endif

	if (!priv) {
		NG_FREE_DATA(m, meta);
		return (ENOTCONN);
	}

	conf = priv->conf;
	/* Update stats */
	STATS_INC(priv, recvPackets);
	STATS_ADD(priv, recvOctets, MBUF_LENGTH(m));


#ifdef __LinuxKernelVNB__
	/* Get the mpls_oam key from meta-data */
	lsp_meta = (mpls_oam_meta_t *)ng_get_meta_option(meta, NGM_MPLS_OAM_COOKIE,
							 NGM_MPLS_OAM_LSP_INFO);
	if (lsp_meta) {
		NG_MPLS_ETHER_DPRINTF("got lsp meta data: exp: %u, ttl_bs: %u, ttl_nobs: %u, ra: %u\n",
				      lsp_meta->oam.exp, lsp_meta->oam.ttl_bs,
				      lsp_meta->oam.ttl_nobs, lsp_meta->oam.ra);
		if (lsp_meta->oam.ra != 0) {
			/* add a new outer MPLS header */
			NG_MPLS_ETHER_DPRINTF("Add RA");
			/* Prepend the MPLS header */
			M_PREPEND(m, sizeof(mpls_header_t), M_DONTWAIT);

			/* Prepend or m_pullup have failed */
			if (unlikely(m == NULL)) {
				STATS_INC(priv, memoryFailures);
				error = ENOBUFS;
				NG_MPLS_ETHER_DPRINTF("dropping Prepend (RA)");
				goto drop;
			}

			/* patch outer MPLS header */
			mhdr.header = 0;
			mhdr.mhttl = lsp_meta->oam.ttl_nobs;
			mhdr.mhexp = EXP_NOBS(lsp_meta->oam.exp);
			mhdr.mhtag = 1;
			pmhdr = mtod(m, mpls_header_t *);
			pmhdr->header = htonl(mhdr.header);
		}
	} else
		NG_MPLS_ETHER_DPRINTF("No lsp meta data");
#endif

	/* Prepend the ethernet header */
	M_PREPEND(m, sizeof(struct vnb_ether_header), M_DONTWAIT);

	/* Prepend or m_pullup have failed */
	if (m == NULL) {
		STATS_INC(priv, memoryFailures);
		error = ENOBUFS;
		goto drop;
	}

	ehdr = mtod(m, struct vnb_ether_header *);

	/* Clear memory */
	memset(ehdr->ether_dhost, 0, sizeof(ehdr->ether_dhost));
	memset(ehdr->ether_shost, 0, sizeof(ehdr->ether_shost));

	/* Set destination adress according to configuration */
	memcpy(ehdr->ether_dhost, conf.edst, sizeof(conf.edst));

	/* Set ether type */
	ehdr->ether_type = htons(VNB_ETHERTYPE_MPLS);

	/* Update stats */
	STATS_INC(priv, xmitPackets);
	STATS_ADD(priv, xmitOctets, MBUF_LENGTH(m));

	/* Send packet The mbuf and meta are consumed by the nodes of the
	 * peers. */
	NG_SEND_DATA(error, priv->ether_out, m, meta);

	return error;

drop:
	NG_MPLS_ETHER_DPRINTF("dropping");
	STATS_INC(priv, discarded);
	NG_FREE_DATA(m, meta);

	return error;
}
static int
ng_mpls_disconnect(hook_p hook)
{
	const node_p node = NG_HOOK_NODE(hook);
	const priv_p priv = NG_NODE_PRIVATE(node);
	hookpriv_p hpriv = NG_HOOK_PRIVATE(hook);

	/* Zero out hook pointer */
	if ((hpriv != NULL) && hook == priv->ether_in[hpriv->tag]) {
		hook->hook_rcvdata = NULL;
		priv->ether_in[hpriv->tag] = NULL;
		NG_HOOK_SET_PRIVATE(hook, NULL);
		ng_free(hpriv);
	}
	else if (hook == priv->ether_out)
		priv->ether_out = NULL;
	/* Go away if no longer connected to anything */
	if (node->numhooks == 0)
		ng_rmnode(node);
	return (0);

}

static int
ng_mpls_rmnode(node_p node)
{
#ifdef SPLASSERT
	SPLASSERT(net, __FUNCTION__);
#endif

	node->flags |= NG_INVALID;	/* inclusif or */
	ng_cutlinks(node);
	ng_unname(node);

	NG_NODE_SET_PRIVATE(node, NULL);

	/* Unref node */
	NG_NODE_UNREF(node);

	return (0);

}

#if defined(__LinuxKernelVNB__)
module_init(ng_mpls_init);
module_exit(ng_mpls_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB MPLS node");
MODULE_LICENSE("6WIND");
#endif
