
/*
 * ng_pppoe.c
 *
 * Copyright (c) 1996-1999 Whistle Communications, Inc.
 * All rights reserved.
 *
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 *
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Julian Elischer <julian@freebsd.org>
 *
 * $FreeBSD: src/sys/netgraph/ng_pppoe.c,v 1.23.2.17 2002/07/02 22:17:18 archie Exp $
 * $Whistle: ng_pppoe.c,v 1.10 1999/11/01 09:24:52 julian Exp $
 */
/*
 * Copyright 2003-2013 6WIND S.A.
 */

#if defined(__LinuxKernelVNB__)
#include <asm/byteorder.h>
#include <linux/version.h>
#include <linux/module.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/bitops.h>
#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif
#include <linux/ctype.h> /* for isdigit */
#include <netgraph/vnblinux.h>

#elif defined(__FastPath__)
#include "fp-netgraph.h"
#endif
#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>
#include <netgraph/vnb_ether.h>
#include <netgraph/ng_pppoe.h>
#include <netgraph/ng_ether.h>

#define SIGNOFF "session closed"
#define PPPOE_BIG_ROOM 500
#if defined(__LinuxKernelVNB__)
#define PPPOE_STATS
#endif

#define DEBUG_PPPOE 0
#if DEBUG_PPPOE >= 1
#ifdef __LinuxKernelVNB__
#define NG_PPPOE_DPRINTF(x, y...) do { \
		log(LOG_DEBUG, "%s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#else
/* for now : force DEBUG output */
#define NG_PPPOE_DPRINTF(x, y...) do { \
		log(LOG_ERR, "FP %s() " x "\n", __FUNCTION__, ## y);\
	} while(0)
#endif
#else
#define NG_PPPOE_DPRINTF(x, y...) do {} while(0)
#endif

/*
 * This section contains the netgraph method declarations for the
 * pppoe node. These methods define the netgraph pppoe 'type'.
 */

static ng_constructor_t	ng_pppoe_constructor;
static ng_rcvmsg_t	ng_pppoe_rcvmsg;
static ng_shutdown_t	ng_pppoe_rmnode;
static ng_newhook_t	ng_pppoe_newhook;
static ng_connect_t	ng_pppoe_connect;
static ng_rcvdata_t	ng_pppoe_rcvdata;
static ng_disconnect_t	ng_pppoe_disconnect;

#ifdef PPPOE_STATS
/* Type for a generic struct ngpppoestat */
static const struct ng_parse_struct_field
    ng_parse_pppoestat_type_fields[] = NGPPPOE_STATS_TYPE_INFO;
static const struct ng_parse_type ng_parse_pppoestat_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_parse_pppoestat_type_fields,
};
#endif
/* Type for a generic listen message */
static const struct ng_parse_struct_field
    ng_parse_pppoeinit_type_fields[] = NGPPPOE_INIT_TYPE_INFO;
static const struct ng_parse_type ng_parse_pppoeinit_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_parse_pppoeinit_type_fields,
};
/* Type for a generic struct ngpppoe_sts */
static const struct ng_parse_struct_field
    ng_parse_pppoests_type_fields[] = NGPPPOE_STS_TYPE_INFO;
static const struct ng_parse_type ng_parse_pppoests_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_parse_pppoests_type_fields,
};
/* Type for a generic struct ngpppoe_mac_filter */
static const struct ng_parse_struct_field
    ng_parse_pppoe_macf_type_fields[] = NGPPPOE_MACF_TYPE_INFO;
static const struct ng_parse_type ng_parse_pppoe_macf_type = {
	.supertype = &ng_parse_struct_type,
	.info = &ng_parse_pppoe_macf_type_fields,
};


static VNB_DEFINE_SHARED(struct ng_cmdlist, ng_pppoe_cmds[]) = {
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_CONNECT,
		"connect",
		&ng_parse_pppoeinit_type, /* parse ngpppoe_init_data */
		NULL
},
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_LISTEN,
		"listen",
		&ng_parse_pppoeinit_type, /* parse ngpppoe_init_data */
		NULL
	},
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_OFFER,
		"offer",
		&ng_parse_pppoeinit_type, /* parse ngpppoe_init_data */
		NULL
	},
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_SERVICE,
		"service",
		&ng_parse_pppoeinit_type, /* parse ngpppoe_init_data */
		NULL
	},
#ifdef PPPOE_STATS
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_GET_STATUS,
		"getstatus",
		NULL,
		&ng_parse_pppoestat_type /* return ngpppoestat */
	},
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_CLR_STATUS,
		"clrstatus",
		NULL,
		NULL
	},
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_GETCLR_STATUS,
		"getclrstatus",
		NULL,
		&ng_parse_pppoestat_type /* return ngpppoestat */
	},
#endif
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_SUCCESS,
		"success",
		&ng_parse_pppoests_type, /* parse ngpppoe_sts */
		NULL
	},
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_SET_MACFILTER,
		"set_mac_filter",
		&ng_parse_pppoe_macf_type, /* parse mac_filter */
		NULL,
	},
	{
		NGM_PPPOE_COOKIE,
		NGM_PPPOE_GET_MACFILTER,
		"get_mac_filter",
		NULL,
		&ng_parse_pppoe_macf_type, /* return mac_filter */
	},
	{
		.cookie = 0
	}
};

/* Netgraph node type descriptor */
static VNB_DEFINE_SHARED(struct ng_type, typestruct) = {
	.version   = NG_VERSION,
	.name      = NG_PPPOE_NODE_TYPE,
	.mod_event = NULL,
	.constructor=ng_pppoe_constructor,
	.rcvmsg    = ng_pppoe_rcvmsg,
	.shutdown  = ng_pppoe_rmnode,
	.newhook   = ng_pppoe_newhook,
	.findhook  = NULL,
	.connect   = ng_pppoe_connect,
	.afterconnect = NULL,
	.rcvdata   = ng_pppoe_rcvdata,
	.rcvdataq  = ng_pppoe_rcvdata,
	.disconnect= ng_pppoe_disconnect,
	.rcvexception = NULL,
	.dumpnode = NULL,
	.restorenode = NULL,
	.dumphook = NULL,
	.restorehook = NULL,
	.cmdlist   = ng_pppoe_cmds
};
NETGRAPH_INIT(pppoe, &typestruct);
NETGRAPH_EXIT(pppoe, &typestruct);

/*
 * States for the session state machine.
 * These have no meaning if there is no hook attached yet.
 */
enum state {
    PPPOE_SNONE=0,	/* [both] Initial state */
    PPPOE_LISTENING,	/* [Daemon] Listening for discover initiation pkt */
    PPPOE_SINIT,	/* [Client] Sent discovery initiation */
    PPPOE_PRIMED,	/* [Server] Awaiting PADI from daemon */
    PPPOE_SOFFER,	/* [Server] Sent offer message  (got PADI)*/
    PPPOE_SREQ,		/* [Client] Sent a Request */
    PPPOE_NEWCONNECTED,	/* [Server] Connection established, No data received */
    PPPOE_CONNECTED,	/* [Both] Connection established, Data received */
    PPPOE_DEAD		/* [Both] */
};

#ifndef __FastPath__
#define NUMTAGS 20 /* number of tags we are set up to work with */

/*
 * Information we store for each hook on each node for negotiating the
 * session. The mbuf and cluster are freed once negotiation has completed.
 * The whole negotiation block is then discarded.
 */

struct sess_neg {
	struct mbuf 		*m; /* holds cluster with last sent packet */
	union	packet		*pkt; /* points within the above cluster */
	struct ng_callout	timeout_handle;   /* see timeout(9) */
	u_int			timeout; /* 0,1,2,4,8,16 etc. seconds */
	u_int			numtags;
	const struct pppoe_tag	*tags[NUMTAGS];
	u_int			service_len;
	u_int			ac_name_len;

	struct datatag		service;
	struct datatag		ac_name;
};
typedef struct sess_neg *negp;
#endif

/*
 * Session information that is needed after connection.
 */
struct sess_con {
	hook_p  		hook;
	u_int16_t		Session_ID;
	enum state		state;
	char			creator[NG_NODELEN + 1]; /* who to notify */
	struct pppoe_full_hdr	pkt_hdr;	/* used when connected */
#ifndef __FastPath__
	negp			neg;		/* used when negotiating */
#endif
	u_int32_t		ul;		/* unique session ID */
	/*struct sess_con	*hash_next;*/	/* not yet used */
#ifndef __FastPath__
	vnb_spinlock_t  	sess_lock;	/* lock for session changes */
	LIST_ENTRY(sess_con) next; /* for the list of PPPOE_LISTENING hooks */
#endif
};
typedef struct sess_con *sessp;

/*
 * Information we store for each node
 */
struct PPPOE {
	node_p		node;		/* back pointer to node */
	hook_p  	ethernet_hook;
	hook_p  	debug_hook;
#ifdef PPPOE_STATS
	u_int64_t   	packets_in;	/* packets in from ethernet */
	u_int64_t   	packets_out;	/* packets out towards ethernet */
	u_int64_t   	packets_exc;	/* exceptions FP to CP */
	u_int64_t   	sessp_malloc;	/* number of malloc'ed sessp structs */
	u_int64_t   	sessp_free;	/* number of free'd sessp structs */
	u_int64_t   	negp_malloc;	/* number of malloc'ed sessp structs */
	u_int64_t   	negp_free;	/* number of free'd sessp structs */
	u_int64_t   	success_sent;	/* number of SUCCESS events */
	u_int64_t   	m_copy_fail;	/* number of failing m_copypacket */
	u_int64_t   	mcopy_nb;	/* nb of use of m_copypacket */
#endif
	u_int32_t	flags;
	/*struct sess_con *buckets[HASH_SIZE];*/	/* not yet used */
#define PPPOE_SESS_CACHE
#define PPPOE_MAX_SESSION (1<<16)
#if defined(PPPOE_SESS_CACHE)
/*
 * simplistic hook cache for the fast path:
 * only use session_id as discriminant information.
 */
/* 16 bits to define a session */
	hook_p  	pppoe_sess_cache[PPPOE_MAX_SESSION];
#endif
#ifndef __FastPath__
/* the sess_id "used" flags are packed into 64-bit words */
#define PPPOE_WORD_LEN_ORDER 6
#define PPPOE_WORD_SIZE (1 << PPPOE_WORD_LEN_ORDER)
#define PPPOE_WORD_MASK (PPPOE_WORD_SIZE - 1)
	/* bit vector of Session_ID use */
	u_int64_t   	sess_id_used[PPPOE_MAX_SESSION >> PPPOE_WORD_LEN_ORDER];
	vnb_spinlock_t  	sessid_lock;	/* lock for the bitmask of used sess_id */
	LIST_HEAD(, sess_con) head; /* for the list of PPPOE_LISTENING hooks */
#endif
	u_int8_t	mac_addr_lsb;
	u_int8_t	nb_valid_bits;
	u_int8_t	mac_mask;
};
typedef struct PPPOE *priv_p;

struct vnb_ether_header eh_prototype =
	{{0xff,0xff,0xff,0xff,0xff,0xff},
	 {0x00,0x00,0x00,0x00,0x00,0x00},
	 ETHERTYPE_PPPOE_DISC};

static int nonstandard = 0;

#ifndef __FastPath__
static VNB_DEFINE_SHARED(vnb_atomic_t, uniq_ul_iv) =
	VNB_ATOMIC_INIT(0xffffff); /* guaranteed to be random */
#endif
union uniq {
	char bytes[sizeof(unsigned long)];
	u_int32_t ul;
};

#define	LEAVE(x) do { error = x; goto quit; } while(0)
#ifndef __FastPath__
static struct mbuf * pppoe_start(sessp sp);
static struct mbuf * sendpacket(sessp sp);
static void	pppoe_ticker(void *arg);
static const	struct pppoe_tag *scan_tags(sessp sp,
			const struct pppoe_hdr* ph);
static struct ng_mesg * pppoe_send_event(sessp sp, enum cmd cmdid);
#else
static int ng_pppoe_rcvdata_ethernet(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_pppoe_rcvdata_upper(hook_p hook, struct mbuf *m, meta_p meta);
static int ng_pppoe_rcvdata_debug(hook_p hook, struct mbuf *m, meta_p meta);

#endif

/*************************************************************************
 * Some basic utilities  from the Linux version with author's permission.*
 * Author:	Michal Ostrowski <mostrows@styx.uwaterloo.ca>		 *
 ************************************************************************/

#ifndef __FastPath__
/*
 * Generate a new session id
 * XXX find out the FreeBSD locking scheme.
 */
static u_int16_t
get_new_sid(node_p node)
{
	static int pppoe_sid = PPPOE_WORD_SIZE;
	priv_p privp = node->private;
	int i, j, rem;

	if (privp == NULL)
		/* return known invalid session id */
		return 0;

	vnb_spinlock_lock(&privp->sessid_lock);
	/* as extension: Sess id less than 63 are not used */
	i = (pppoe_sid >> PPPOE_WORD_LEN_ORDER);
	j = 0;
	do {
		/* compare 64 bits each time */
		if (privp->sess_id_used[i] != ~(0ULL))
			break;
		i++;
		j++;
		if (i == ((PPPOE_MAX_SESSION >> PPPOE_WORD_LEN_ORDER) - 1))
			i = 1;
	} while (j < (PPPOE_MAX_SESSION >> PPPOE_WORD_LEN_ORDER));

	/* all possible sess_id were tried and no success */
	if ((j == (PPPOE_MAX_SESSION >> PPPOE_WORD_LEN_ORDER)) ||
	  (privp->sess_id_used[i] == ~(0ULL))) {
		vnb_spinlock_unlock(&privp->sessid_lock);
		if (net_ratelimit())
			log(LOG_ERR, "pppoe: sess id exhausted for i %d j %d (last %d)\n",
				i, j, pppoe_sid);
		/* return known invalid session id */
		return 0;
	}

	/* available is first clear bit in privp->sess_id_used[i] */
	rem = __ffs64(~privp->sess_id_used[i]);
	pppoe_sid = (i << PPPOE_WORD_LEN_ORDER) | rem;
	vnb_spinlock_unlock(&privp->sessid_lock);

	NG_PPPOE_DPRINTF("%s: pppoe_sid=%d %llx\n", __func__, pppoe_sid,
		(long long int)privp->sess_id_used[i]);
	return pppoe_sid;
}


/*
 * Return the location where the next tag can be put
 */
static __inline const struct pppoe_tag*
next_tag(const struct pppoe_hdr* ph)
{
	return (const struct pppoe_tag*)(((const char*)PPPOE_HDR_DATA(ph))
	    + ntohs(ph->length));
}

#if DEBUG_PPPOE > 1
static void ng_hexdump(const void *buf, unsigned int len)
{
	unsigned int i, out, ofs;
	const unsigned char *data = buf;
#define LINE_LEN 80
	char line[LINE_LEN];	/* space needed 8+16*3+3+16 == 75 */

	log(LOG_INFO, "[%p], len=%d\n", data, len);
	ofs = 0;
	while (ofs < len) {
		/* format 1 line in the buffer, then use printk to print them */
		out = snprintf(line, LINE_LEN, "%08X", ofs);
		for (i=0; ofs+i < len && i<16; i++)
			out += snprintf(line+out, LINE_LEN - out, " %02X", data[ofs+i]&0xff);
		for(;i<=16;i++)
			out += snprintf(line+out, LINE_LEN - out, "   ");
		for(i=0; ofs < len && i<16; i++, ofs++) {
			unsigned char c = data[ofs];
			if (!isascii(c) || !isprint(c))
				c = '.';
			out += snprintf(line+out, LINE_LEN - out, "%c", c);
		}
		log(LOG_INFO, "%s\n", line);
	}
}
#endif

/*
 * Look for a tag of a specific type
 * Don't trust any length the other end says.
 * but assume we already sanity checked ph->length.
 */
static const struct pppoe_tag*
get_tag(const struct pppoe_hdr* ph, u_int16_t idx)
{
	const char *const end = (const char *)next_tag(ph);
	const char *ptn;
	const struct pppoe_tag *pt = PPPOE_HDR_DATA(ph);
	/*
	 * Keep processing tags while a tag header will still fit.
	 */
#if DEBUG_PPPOE > 1
	NG_PPPOE_DPRINTF("search for %x\n", idx);
#endif
	while((const char*)(pt + 1) <= end) {
	    /*
	     * If the tag data would go past the end of the packet, abort.
	     */
	    ptn = (((const char *)(pt + 1)) + ntohs(pt->tag_len));
#if DEBUG_PPPOE > 1
	    if(pt->tag_len)
		NG_PPPOE_DPRINTF("found length = %d\n", ntohs(pt->tag_len));
#endif
	    if(ptn > end) {
		NG_PPPOE_DPRINTF("going past the end of the packet\n");
#if DEBUG_PPPOE > 1
		ng_hexdump((void *)pt, 32);
#endif
		return NULL;
	    }

#if DEBUG_PPPOE > 1
	    if(pt->tag_type)
		NG_PPPOE_DPRINTF("found type = 0x%x\n", pt->tag_type);
#endif
	    if(pt->tag_type == idx)
		return pt;

	    pt = (const struct pppoe_tag*)ptn;
	}
	return NULL;
}

/**************************************************************************
 * inlines to initialise or add tags to a session's tag list,
 **************************************************************************/
/*
 * Initialise the session's tag list
 */
static void
init_tags(sessp sp)
{
	if(sp->neg == NULL) {
		log(LOG_ERR, "pppoe: asked to init NULL neg pointer\n");
		return;
	}
	sp->neg->numtags = 0;
}

static void
insert_tag(sessp sp, const struct pppoe_tag *tp)
{
	int	i;
	negp neg;

	if((neg = sp->neg) == NULL) {
		log(LOG_ERR, "pppoe: asked to use NULL neg pointer\n");
		return;
	}
	if ((i = neg->numtags++) < NUMTAGS) {
		neg->tags[i] = tp;
	} else {
		log(LOG_ERR, "pppoe: asked to add too many tags (%d) to packet\n", i);
		neg->numtags--;
	}
}

/*
 * Make up a packet, using the tags filled out for the session.
 *
 * Assume that the actual pppoe header and ethernet header
 * are filled out externally to this routine.
 * Also assume that neg->wh points to the correct
 * location at the front of the buffer space.
 */
static struct mbuf *
make_packet(sessp sp) {
	struct pppoe_full_hdr *wh;
	const struct pppoe_tag **tag, *tag_src;
	char *dp;
	unsigned int count, numtags;
	unsigned int tlen;
	u_int16_t cur_len, length = 0;
	struct mbuf *m = NULL;
	negp neg;

	if (unlikely(sp == NULL)) {
		log(LOG_ERR, "pppoe: NULL sp\n");
		return NULL;
	}
	if (((neg = sp->neg) == NULL) || ((m = neg->m) == NULL)) {
		log(LOG_ERR, "pppoe: make_packet called from wrong state\n");
		return NULL;
	}
	numtags = neg->numtags;
	tag = neg->tags;
	wh = &neg->pkt->pkt_header;
	if (unlikely((wh == NULL) || (tag == NULL))) {
		log(LOG_ERR, "pppoe: make_packet with NULL wh or tags\n");
		return NULL;
	}
	dp = (char *)PPPOE_HDR_DATA(&wh->ph);
	for (count = 0;
	    ((count < numtags) && (count < NUMTAGS));
	    tag++, count++) {
		tag_src = *tag;
		if (unlikely((tag_src == NULL) || (dp == NULL))) {
			log(LOG_ERR, "pppoe: NULL tag/dp\n");
			break;
		}
		tlen = ntohs(tag_src->tag_len) + sizeof(**tag);
		if ((length + tlen) > (VNB_ETHER_MAX_LEN - 4 - sizeof(*wh))) {
			log(LOG_ERR, "pppoe: tags too long %d tags for %d len\n",
				count, (length + tlen));
			break;	/* XXX chop off what's too long */
		}
		bcopy(tag_src, (char *)dp, tlen);
		length += tlen;
		dp += tlen;
	}
	wh->ph.length = htons(length);
	tlen = (sizeof(*wh) + length);
	cur_len = MBUF_LENGTH(m);
	if (cur_len < tlen) {
		tlen -= cur_len;
		if (unlikely(m_append(m, tlen) == NULL)) {
			log(LOG_ERR, "pppoe: can't get contiguous mbuf %d tags for %d len\n",
				count, length);
			return NULL;
		}
	}
	else if (cur_len > tlen) {
		tlen = cur_len - tlen;
		m_trim(m, tlen);
	}
	return m;
}

/**************************************************************************
 * Routine to match a service offered					  *
 **************************************************************************/
/*
 * Find a hook that has a service string that matches that
 * we are seeking. for now use a simple string.
 * In the future we may need something like regexp().
 * for testing allow a null string to match 1st found and a null service
 * to match all requests. Also make '*' do the same.
 *
 * only in kernel VNB where machine state handling is done.
 */

#define NG_MATCH_EXACT	1
#define NG_MATCH_ANY	2

static hook_p
pppoe_match_svc(const node_p node, const char *svc_name,
                 const int svc_len, const int match)
{
	sessp	sp	= NULL;
	negp	neg	= NULL;
	priv_p	privp	= node->private;
	hook_p	allhook	= NULL;
	hook_p	hook	= NULL;

	if (privp == NULL)
		return NULL;

	LIST_FOREACH(sp, &privp->head, next) {

		if (sp == NULL)
			continue;

		/* Skip any sessions which are not in LISTEN mode. */
		if (sp->state != PPPOE_LISTENING)
			continue;

		/* in case sp->neg was reset */
		if (unlikely((neg = sp->neg) == NULL))
			continue;

		hook = sp->hook;

		/* Special case for a blank or "*" service name (wildcard) */
		if (match == NG_MATCH_ANY && neg->service_len == 1 &&
		    neg->service.data[0] == '*') {
			allhook = hook;
			continue;
		}

		/* If the lengths don't match, that aint it. */
		if (neg->service_len != (unsigned int)svc_len)
			continue;

		/* An exact match? */
		if (svc_len == 0)
			break;

		if (strncmp(svc_name,
			    (const char *)neg->service.data,
			    svc_len) == 0)
			break;
	}
	return (hook ? hook : allhook);
}
#endif /* __FastPath__ */
/**************************************************************************
 * Routine to find a particular session that matches an incoming packet	  *
 **************************************************************************/
static inline hook_p
pppoe_findsession(hook_p hook_orig, const struct pppoe_full_hdr *wh)
{
	sessp sp = NULL;
	hook_p hook = NULL;
	priv_p privp = hook_orig->node_private;
	u_int16_t session = ntohs(wh->ph.sid);
#if DEBUG_PPPOE >= 1
	uint32_t* start_mac;
#endif

	if (unlikely(privp == NULL))
		return NULL;

#if defined(PPPOE_SESS_CACHE)
	hook = privp->pppoe_sess_cache[session];
	if (likely(hook != NULL)) {

		if (unlikely((hook->node == NULL) || (hook->flags & HK_INVALID))) {
			log(LOG_ERR, "Invalid hook found in cache for %d\n", session);
			return NULL;
		}

		sp = hook->private;
		if (unlikely(sp == NULL)) {
			NG_PPPOE_DPRINTF("No cache found for %d\n", session);
#if DEBUG_PPPOE >= 1
			start_mac = (uint32_t*)wh->eh.ether_shost;
			NG_PPPOE_DPRINTF("wh mac %08x\n", htonl(*start_mac));
#endif
			return NULL;
		} else if (unlikely((hook->private == &privp->ethernet_hook) ||
		                    (hook->private == &privp->debug_hook))) {
			log(LOG_ERR, "Debug or Eth found in cache for %d\n", session);
			return NULL;
		} else {
			const uint16_t *a = (const uint16_t *) sp->pkt_hdr.eh.ether_dhost;
			const uint16_t *b = (const uint16_t *) wh->eh.ether_shost;
			const enum state hook_state = sp->state;

			if (((hook_state == PPPOE_CONNECTED) ||
				(hook_state == PPPOE_NEWCONNECTED)) &&
#if !defined(CONFIG_TILE) && !defined(CONFIG_TILEGX)
				!((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]))) {
#else
				/*use a generic MAC address compare for tile to avoid unaligned access */
				!(memcmp(a, b, VNB_ETHER_ADDR_LEN))) {
#endif
				return (hook);
			}
		}
	}
#endif
	return NULL;
}


#ifndef __FastPath__
/* find output hook for a given uniq tag */
static hook_p
pppoe_finduniq(node_p node, const struct pppoe_tag *tag)
{
	hook_p hook = NULL, hook_tmp;
	priv_p	privp = node->private;
	union uniq		uniq;
	sessp sp;

	if (privp == NULL)
		return NULL;

	bcopy(PPPOE_TAG_DATA(tag), uniq.bytes, sizeof(u_int32_t));
	/* cycle through all known hooks */
	LIST_FOREACH_SAFE(hook, hook_tmp, &node->hooks, hooks) {
		/* don't check special hooks */
		if ((hook->private == &privp->debug_hook)
		||  (hook->private == &privp->ethernet_hook))
			continue;
		if (((sp = hook->private) != NULL) && (sp->ul == uniq.ul))
			break;
	}
	return (hook);
}
#endif
/**************************************************************************
 * start of Netgraph entrypoints					  *
 **************************************************************************/

/*
 * Allocate the private data structure and the generic node
 * and link them together.
 *
 * ng_make_node_common() returns with a generic node struct
 * with a single reference for us.. we transfer it to the
 * private structure.. when we free the private struct we must
 * unref the node so it gets freed too.
 */
static int
ng_pppoe_constructor(node_p *nodep, ng_ID_t nodeid)
{
	priv_p privdata;
	int error;

	/* Call the 'generic' (ie, superclass) node constructor */
	if ((error = ng_make_node_common_and_priv(&typestruct, nodep,
						  &privdata, sizeof(*privdata), nodeid))) {
		return (error);
	}
	bzero(privdata, sizeof(*privdata));

	/* Link structs together; this counts as our one reference to *nodep */
	(*nodep)->private = privdata;
	privdata->node = *nodep;
#ifndef __FastPath__
	/* possible only in kernel */
	vnb_spinlock_init(&privdata->sessid_lock);
#endif
	return (0);
}

/*
 * Give our ok for a hook to be added...
 * point the hook's private info to the hook structure.
 *
 * The following hook names are special:
 *  Ethernet:  the hook that should be connected to a NIC.
 *  debug:	copies of data sent out here  (when I write the code).
 * All other hook names need only be unique. (the framework checks this).
 */
static int
ng_pppoe_newhook(node_p node, hook_p hook, const char *name)
{
	const priv_p privp = node->private;
	sessp sp;

	if (privp == NULL)
		return EINVAL;

	if (strncmp(name, NG_PPPOE_HOOK_ETHERNET,
	    sizeof(NG_PPPOE_HOOK_ETHERNET) - 1) == 0) {
		privp->ethernet_hook = hook;
		hook->private = &privp->ethernet_hook;
#ifdef __FastPath__
		hook->hook_rcvdata = ng_pppoe_rcvdata_ethernet;
#endif
	} else if (strncmp(name, NG_PPPOE_HOOK_DEBUG,
	           sizeof(NG_PPPOE_HOOK_DEBUG) - 1) == 0) {
		privp->debug_hook = hook;
		hook->private = &privp->debug_hook;
#ifdef __FastPath__
		hook->hook_rcvdata = ng_pppoe_rcvdata_debug;
#endif
	} else {
		/*
		 * Any other unique name is OK.
		 * The infrastructure has already checked that it's unique,
		 * so just allocate it and hook it in.
		 */
		sp = ng_malloc(sizeof(*sp), M_NOWAIT | M_ZERO);
		if (sp == NULL) {
				return (ENOMEM);
		}
#ifdef PPPOE_STATS
		privp->sessp_malloc++;
#endif

#ifndef __FastPath__
		/* possible only in kernel */
		sp->ul = htonl(vnb_atomic_read(&uniq_ul_iv));
		vnb_atomic_inc(&uniq_ul_iv);
		vnb_spinlock_init(&sp->sess_lock);
#endif
		hook->private = sp;
		sp->hook = hook;
#ifdef __FastPath__
		hook->hook_rcvdata = ng_pppoe_rcvdata_upper;
#endif
	}
	return(0);
}

/*
 * Get a netgraph control message.
 * Check it is one we understand. If needed, send a response.
 * We sometimes save the address for an async action later.
 * Always free the message.
 */
static int
ng_pppoe_rcvmsg(node_p node, struct ng_mesg *msg, const char *retaddr,
		struct ng_mesg **rptr, struct ng_mesg **nl_msg)
{
	priv_p privp = node->private;
	struct ng_mesg *resp = NULL;
	int error = 0;
	hook_p hook = NULL;
	sessp sp = NULL;
#ifdef __FastPath__
	struct ngpppoe_sts *sts = NULL;
#else
	struct ngpppoe_init_data *ourmsg = NULL;
	negp neg0, neg = NULL;
	struct mbuf *m, *m0 = NULL;
	void *dummy = NULL;
#endif

	if (privp == NULL)
		LEAVE(EINVAL);

	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_PPPOE_COOKIE:
		switch (msg->header.cmd) {
#ifndef __FastPath__
		/* the messages for handling the machine states are
		 * only significant in the kernel VNB */
		case NGM_PPPOE_CONNECT:
		case NGM_PPPOE_LISTEN:
		case NGM_PPPOE_OFFER:
		case NGM_PPPOE_SERVICE:
			ourmsg = (struct ngpppoe_init_data *)msg->data;
			if (( sizeof(*ourmsg) > msg->header.arglen)
			|| ((sizeof(*ourmsg) + ourmsg->data_len)
			    > msg->header.arglen)) {
				log(LOG_ERR, "pppoe_rcvmsg: bad arg size\n");
				LEAVE(EMSGSIZE);
			}
			if (ourmsg->data_len > PPPOE_SERVICE_NAME_SIZE) {
				log(LOG_ERR, "pppoe_rcvmsg: init data too long (%d)\n",
							ourmsg->data_len);
				LEAVE(EMSGSIZE);
			}
			/* make sure strcmp will terminate safely */
			ourmsg->hook[sizeof(ourmsg->hook) - 1] = '\0';

			hook = ng_findhook(node, ourmsg->hook);

			if (hook == NULL) {
				log(LOG_ERR, "pppoe_rcvmsg: NULL hook\n");
				LEAVE(ENOENT);
			}
			if ((hook->private == &privp->debug_hook)
			||  (hook->private == &privp->ethernet_hook)) {
				log(LOG_ERR, "pppoe_rcvmsg: refusing debug/eth hooks\n");
				LEAVE(EINVAL);
			}
			sp = hook->private;
			vnb_spinlock_lock(&sp->sess_lock);

			if (msg->header.cmd == NGM_PPPOE_LISTEN) {
				/*
				 * Ensure we aren't already listening for this
				 * service.
				 */
				if (pppoe_match_svc(node, ourmsg->data,
				    ourmsg->data_len, NG_MATCH_EXACT) != NULL) {
					vnb_spinlock_unlock(&sp->sess_lock);
					log(LOG_ERR, "pppoe_rcvmsg: already listening\n");
					LEAVE(EEXIST);
				}
			}

			/*
			 * PPPOE_SERVICE advertisments are set up
			 * on sessions that are in PRIMED state.
			 */
			if (msg->header.cmd == NGM_PPPOE_SERVICE) {
				break;
			}
			if (sp->state != PPPOE_SNONE) {
				vnb_spinlock_unlock(&sp->sess_lock);
				log(LOG_ERR, "pppoe_rcvmsg: Session already active\n");
				LEAVE(EISCONN);
			}

			/*
			 * set up prototype header
			 */
			neg = ng_malloc(sizeof(*neg), M_NOWAIT | M_ZERO);

			if (neg == NULL) {
				vnb_spinlock_unlock(&sp->sess_lock);
				log(LOG_ERR, "pppoe_rcvmsg: Session out of memory\n");
				LEAVE(ENOMEM);
			}
#ifdef PPPOE_STATS
			privp->negp_malloc++;
#endif
			ng_callout_init(&neg->timeout_handle);
			if (((m = m_alloc()) != NULL) &&
			    (m_append(m,
				      (sizeof(struct pppoe_full_hdr) +
				       VNB_ETHER_MAX_LEN)) == NULL)) {
				m_freem(m);
				neg->m = NULL;
				neg->pkt = NULL;
			}
			if (m == NULL) {
				ng_free(neg);
#ifdef PPPOE_STATS
				privp->negp_free++;
#endif
				vnb_spinlock_unlock(&sp->sess_lock);
				log(LOG_ERR, "pppoe_rcvmsg: Session out of buffer\n");
				LEAVE(ENOBUFS);
			}
			neg->m = m;
			neg->pkt = mtod(neg->m, union packet*);
			neg->pkt->pkt_header.eh = eh_prototype;
			neg->pkt->pkt_header.ph.ver = 0x1;
			neg->pkt->pkt_header.ph.type = 0x1;
			neg->pkt->pkt_header.ph.sid = 0x0000;
			neg->timeout = 0;

			/* avoid memory leaks if the session was half-negotiated */
			if ((neg0 = sp->neg) != NULL) {
				m = neg0->m;
				neg0->m = NULL;
				neg0->pkt = NULL;
				if (m != NULL)
					m_freem(m);
				sp->neg = NULL;
				ng_free(neg0);
#ifdef PPPOE_STATS
				privp->negp_free++;
#endif
			}
			/* only for NGM_PPPOE_CONNECT, NGM_PPPOE_LISTEN, NGM_PPPOE_OFFER */
			sp->neg = neg;
			strncpy(sp->creator, retaddr, NG_NODELEN);
			sp->creator[NG_NODELEN] = '\0';
		}
		switch (msg->header.cmd) {
		case NGM_PPPOE_CONNECT:
			/*
			 * Check the hook exists and is Uninitialised.
			 * Send a PADI request, and start the timeout logic.
			 * Store the originator of this message so we can send
			 * a success of fail message to them later.
			 * Move the session to SINIT
			 * Set up the session to the correct state and
			 * start it.
			 */
			neg->service.hdr.tag_type = PTT_SRV_NAME;
			neg->service.hdr.tag_len =
					htons((u_int16_t)ourmsg->data_len);
			/* store the servce name ("session" from mpd) */
			if (ourmsg->data_len) {
				bcopy(ourmsg->data,
					neg->service.data, ourmsg->data_len);
			}
			neg->service_len = ourmsg->data_len;
			m0 = pppoe_start(sp);
			vnb_spinlock_unlock(&sp->sess_lock);
			if (m0 != NULL) {
				int dont_care;
				NG_SEND_DATA(dont_care, privp->ethernet_hook, m0, dummy);
				(void) dont_care;
#ifdef PPPOE_STATS
				privp->packets_out++;
#endif
			}
			break;
		case NGM_PPPOE_LISTEN:
			/*
			 * Check the hook exists and is Uninitialised.
			 * Install the service matching string.
			 * Store the originator of this message so we can send
			 * a success or fail message to them later.
			 * Move the hook to 'LISTENING'
			 */
			neg->service.hdr.tag_type = PTT_SRV_NAME;
			neg->service.hdr.tag_len =
					htons((u_int16_t)ourmsg->data_len);

			if (ourmsg->data_len) {
				bcopy(ourmsg->data,
					neg->service.data, ourmsg->data_len);
			}
			neg->service_len = ourmsg->data_len;
			neg->pkt->pkt_header.ph.code = PADT_CODE;
			/*
			 * wait for PADI packet coming from ethernet
			 */
			sp->state = PPPOE_LISTENING;
			LIST_INSERT_HEAD(&privp->head, sp, next);
			vnb_spinlock_unlock(&sp->sess_lock);
			break;
		case NGM_PPPOE_OFFER:
			/*
			 * Check the hook exists and is Uninitialised.
			 * Store the originator of this message so we can send
			 * a success of fail message to them later.
			 * Store the AC-Name given and go to PRIMED.
			 */
			neg->ac_name.hdr.tag_type = PTT_AC_NAME;
			neg->ac_name.hdr.tag_len =
					htons((u_int16_t)ourmsg->data_len);
			if (ourmsg->data_len) {
				bcopy(ourmsg->data,
					neg->ac_name.data, ourmsg->data_len);
			}
			neg->ac_name_len = ourmsg->data_len;
			neg->pkt->pkt_header.ph.code = PADO_CODE;
			/*
			 * Wait for PADI packet coming from hook
			 */
			sp->state = PPPOE_PRIMED;
			vnb_spinlock_unlock(&sp->sess_lock);
			break;
		case NGM_PPPOE_SERVICE:
			/*
			 * Check the session is primed.
			 * for now just allow ONE service to be advertised.
			 * If you do it twice you just overwrite.
			 */
			if (sp->state != PPPOE_PRIMED) {
				vnb_spinlock_unlock(&sp->sess_lock);
				log(LOG_ERR, "pppoe_rcvmsg: Session not primed\n");
				LEAVE(EISCONN);
			}
			neg = sp->neg;
			neg->service.hdr.tag_type = PTT_SRV_NAME;
			neg->service.hdr.tag_len =
			    htons((u_int16_t)ourmsg->data_len);

			if (ourmsg->data_len)
				bcopy(ourmsg->data, neg->service.data,
				    ourmsg->data_len);
			neg->service_len = ourmsg->data_len;
			vnb_spinlock_unlock(&sp->sess_lock);
			break;
		case NGM_PPPOE_SUCCESS:
			/* nothing to do in the kernel VNB
			 * *OR* (could) check the parameters against the hook private
			 * and assert identity */
			NG_PPPOE_DPRINTF("pppoe_rcvmsg: received SUCCESS: ignoring\n");
			break;
#else /* __FastPath__ */
		case NGM_PPPOE_CONNECT:
		case NGM_PPPOE_LISTEN:
		case NGM_PPPOE_OFFER:
		case NGM_PPPOE_SERVICE:
			/* these messages are treated only in kernel
			   discard them in the fast path*/
			NG_PPPOE_DPRINTF("pppoe_rcvmsg: received cmd %d: ignoring\n",
			    msg->header.cmd);
			break;
		case NGM_PPPOE_SUCCESS:
			/* synchronize Session_ID from kernel VNB
			 * store the parameters in the hook private */
			NG_PPPOE_DPRINTF("pppoe_rcvmsg: received SUCCESS: copying\n");

			sts = (struct ngpppoe_sts *)msg->data;
			/* make sure strcmp will terminate safely */
			sts->hook[sizeof(sts->hook) - 1] = '\0';

			hook = ng_findhook(node, sts->hook);

			if (hook == NULL) {
				log(LOG_ERR, "pppoe_rcvmsg: NULL hook\n");
				LEAVE(ENOENT);
			}
			if ((hook->private == &privp->debug_hook)
			||  (hook->private == &privp->ethernet_hook)) {
				log(LOG_ERR, "pppoe_rcvmsg: refusing debug/eth hook\n");
				LEAVE(EINVAL);
			}

			/* tell FP VNB to consider that hook as one connected
			 * directly to a server.
			 * LCP and IPCP packets will be treated as exceptions */
			if (!sts->repeater)
				hook->flags |= HK_EXCEP;

#if defined(PPPOE_SESS_CACHE)
			privp->pppoe_sess_cache[sts->Session_ID] = hook;
#endif
			sp = hook->private;
			sp->pkt_hdr.eh.ether_type = ETHERTYPE_PPPOE_SESS;
			memcpy(sp->pkt_hdr.eh.ether_dhost,
			   sts->peer_mac, VNB_ETHER_ADDR_LEN);
			sp->pkt_hdr.ph.ver = 0x1;
			sp->pkt_hdr.ph.type = 0x1;
			/* code changed like in the kernel VNB */
			sp->pkt_hdr.ph.code = 0;
			sp->pkt_hdr.ph.sid = htons(sts->Session_ID);
			sp->Session_ID = sts->Session_ID;

			/* enable traffic on the hook */
			sp->state = PPPOE_CONNECTED;
			break;
#endif /* __FastPath__ */
#ifdef PPPOE_STATS
		case NGM_PPPOE_GET_STATUS:
		case NGM_PPPOE_CLR_STATUS:
		case NGM_PPPOE_GETCLR_STATUS:
		    {
			if (msg->header.cmd != NGM_PPPOE_CLR_STATUS) {
				struct ngpppoestat *stats;
				NG_MKRESPONSE(resp, msg, sizeof(*stats), M_NOWAIT);
				if (!resp) {
					log(LOG_ERR, "pppoe_rcvmsg: can't build response'\n");
					LEAVE(ENOMEM);
				}
				stats = (struct ngpppoestat *) resp->data;
				stats->packets_in   = privp->packets_in;
				stats->packets_out  = privp->packets_out;
				stats->packets_exc  = privp->packets_exc;
				stats->sessp_malloc = privp->sessp_malloc;
				stats->sessp_free   = privp->sessp_free;
				stats->negp_malloc  = privp->negp_malloc;
				stats->negp_free    = privp->negp_free;
				stats->success_sent = privp->success_sent;
				stats->m_copy_fail  = privp->m_copy_fail;
				stats->mcopy_nb     = privp->mcopy_nb;
			}
			if (msg->header.cmd != NGM_PPPOE_GET_STATUS) {
				privp->packets_in   = 0;
				privp->packets_out  = 0;
				privp->packets_exc  = 0;
				privp->sessp_malloc = 0;
				privp->sessp_free   = 0;
				privp->negp_malloc  = 0;
				privp->negp_free    = 0;
				privp->success_sent = 0;
				privp->m_copy_fail  = 0;
			}
			break;
		    }
#endif
		case NGM_PPPOE_GET_MACFILTER:
		    {
			struct ngpppoe_mac_filter *mac_filter;
			NG_PPPOE_DPRINTF("pppoe_rcvmsg: received GET_MAC\n");
			NG_MKRESPONSE(resp, msg, sizeof(*mac_filter), M_NOWAIT);
			if (!resp) {
				log(LOG_ERR, "pppoe_rcvmsg: can't build response'\n");
				LEAVE(ENOMEM);
			}
			mac_filter = (struct ngpppoe_mac_filter *) resp->data;
			mac_filter->mac_addr_lsb   = privp->mac_addr_lsb;
			mac_filter->nb_valid_bits  = privp->nb_valid_bits;
			break;
		    }
		case NGM_PPPOE_SET_MACFILTER:
		    {
			struct ngpppoe_mac_filter *mac_filter;
			NG_PPPOE_DPRINTF("pppoe_rcvmsg: received SET_MAC\n");

			mac_filter = (struct ngpppoe_mac_filter *)msg->data;
			privp->mac_addr_lsb  = mac_filter->mac_addr_lsb;
			privp->nb_valid_bits = mac_filter->nb_valid_bits;
			privp->mac_mask      = (1 << privp->nb_valid_bits) - 1;
			break;
		    }
		default:
			LEAVE(EINVAL);
		}
		break;
	default:
		LEAVE(EINVAL);
	}

	/* Take care of synchronous response, if any */
	if (rptr)
		*rptr = resp;
	else if (resp)
		FREE(resp, M_NETGRAPH);

	/* Free the message and return */
quit:
	FREE(msg, M_NETGRAPH);
	return(error);
}

#ifndef __FastPath__
/*
 * Start a client into the first state. A separate function because
 * it can be needed if the negotiation times out.
 * Note: only in kernel VNB: state machine mngt
 */
static struct mbuf *
pppoe_start(sessp sp)
{
	struct {
		struct pppoe_tag hdr;
		union	uniq	data;
	} __attribute ((packed)) uniqtag;
	struct mbuf *m0 = NULL, *m = NULL;
	negp neg;
	union packet *pkt = NULL;

	/*
	 * kick the state machine into starting up
	 */
	sp->state = PPPOE_SINIT;

	/* protection against NULL pointers */
	if (unlikely((neg = sp->neg) == NULL))
		return NULL;
	if (unlikely((m = neg->m) == NULL))
		return NULL;

	/* reset the packet header to broadcast */
	pkt = neg->pkt;
	pkt->pkt_header.eh = eh_prototype;
	pkt->pkt_header.ph.code = PADI_CODE;
	uniqtag.hdr.tag_type = PTT_HOST_UNIQ;
	uniqtag.hdr.tag_len = htons((u_int16_t)sizeof(uniqtag.data));
	uniqtag.data.ul = sp->ul;
	init_tags(sp);
	insert_tag(sp, &uniqtag.hdr);
	insert_tag(sp, &neg->service.hdr);
	if (make_packet(sp) != NULL)
		m0 = sendpacket(sp);
	else {
		neg->m = NULL;
		neg->pkt = NULL;
		m_freem(m);
		m0 = NULL;
		log(LOG_ERR, "pppoe_start: failing make_packet\n");
	}

	return m0;
}

/* send to mpd the acname returned by the server (only for log)
 * called on PADO reception => only in kernel VNB */
static struct ng_mesg *
send_acname(sessp sp, const struct pppoe_tag *tag)
{
	int tlen;
	struct ng_mesg *msg;
	struct ngpppoe_sts *sts;

	NG_MKMESSAGE(msg, NGM_PPPOE_COOKIE, NGM_PPPOE_ACNAME,
	    sizeof(struct ngpppoe_sts), M_NOWAIT);
	if (msg == NULL)
		return (NULL);

	sts = (struct ngpppoe_sts *)msg->data;
	tlen = ((NG_HOOKLEN <= ntohs(tag->tag_len)) ?
		NG_HOOKLEN : ntohs(tag->tag_len));
	/* Note: the "hook" field is reused to store the acname */
	strncpy(sts->hook, PPPOE_TAG_DATA(tag), tlen);
	sts->hook[tlen] = '\0';

	return (msg);
}
#endif /*__FastPath__*/

#ifdef __FastPath__

static int
ng_pppoe_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	NG_PPPOE_DPRINTF("%s: %d: should never get there\n",
			 __func__, __LINE__);

	NG_FREE_DATA(m, meta);
	return ENOTCONN;
}

static int
ng_pppoe_rcvdata_upper(hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p			privp = hook->node_private;
	sessp			sp;
	int			error = 0;
	u_int16_t		length;

	if (unlikely(privp == NULL))
		LEAVE(EINVAL);

	NG_PPPOE_DPRINTF("%x received packet (upper)", hook->node->ID);
	/*
	 * 	Not ethernet or debug hook..
	 *
	 * The packet has come in on a normal hook.
	 * We need to find out what kind of hook,
	 * So we can decide how to handle it.
	 * Check the hook's state.
	 */
	sp = hook->private;
	if (unlikely(sp == NULL))
		LEAVE(error);

	switch (sp->state) {
	case	PPPOE_NEWCONNECTED:
	case	PPPOE_CONNECTED: {
		/* forwarding PPP packets in FP VNB */
		struct pppoe_full_hdr *wh;

		/*
		 * Remove PPP address and control fields, if any.
		 * For example, ng_ppp(4) always sends LCP packets
		 * with address and control fields as required by
		 * generic PPP. PPPoE is an exception to the rule.
		 */
		if(likely(MBUF_LENGTH(m) >= 2)) {
			if (mtod(m, uint8_t *)[0] == 0xff &&
			    mtod(m, uint8_t *)[1] == 0x03)
				m_adj(m, 2);
		}
		length = MBUF_LENGTH(m);
		/*
		 * Bang in a pre-made header, then correct the length.
		 * And then send it to the ethernet driver.
		 */
		M_PREPEND(m, sizeof(*wh), M_DONTWAIT);
		if (unlikely(m == NULL)) {
			log(LOG_ERR, "pppoe_rcvdata: couldn't prepend (from PPP)\n");
			LEAVE(ENOBUFS);
		}
		wh = mtod(m, struct pppoe_full_hdr *);
		bcopy(&sp->pkt_hdr, wh, sizeof(*wh));
		wh->ph.length = htons(length);
		NG_PPPOE_DPRINTF("forwarding packet (from PPP)");
		NG_SEND_DATA( error, privp->ethernet_hook, m, meta);
#ifdef PPPOE_STATS
		privp->packets_out++;
#endif
		return error;
	}
	default:
		/* a LCP packet may arrive before the SUCCESS was seen in the FP */
		if (sp->state == 0) {
			node_p node = hook->node;

			if (node == NULL)
				LEAVE(ENOTCONN);

			NG_PPPOE_DPRINTF("packet from upper => exception\n");
			error = ng_send_exception(node, hook,
						  VNB2VNB_DATA,
						  0, m, meta);
			m = NULL;
			meta = NULL;
#ifdef PPPOE_STATS
			privp->packets_exc++;
#endif
			LEAVE(error);
		}
		NG_PPPOE_DPRINTF("FP packet from upper in unexpected state %d\n", sp->state);
		LEAVE(ENETUNREACH);
	}
quit:
	NG_FREE_DATA(m, meta);
	return error;
}

static int
ng_pppoe_rcvdata_ethernet(hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p			privp = hook->node_private;
	sessp			sp;
	const struct pppoe_full_hdr *wh;
	int			error = 0;
	u_int16_t		length;
	int pktlen;

	hook_p 			sendhook;

	if (unlikely(privp == NULL))
		LEAVE(EINVAL);

	/*
	 * Incoming data.
	 * Dig out various fields from the packet.
	 * use them to decide where to send it.
	 */
	NG_PPPOE_DPRINTF("%x received packet (ethernet)", hook->node->ID);
#ifdef PPPOE_STATS
	privp->packets_in++;
#endif
	if (unlikely((m = m_pullup(m, sizeof(*wh))) == NULL)) {
		log(LOG_ERR, "pppoe_rcvdata: couldn't pull\n");
		LEAVE(ENOBUFS);
	}
	wh = mtod(m, struct pppoe_full_hdr *);
	length = ntohs(wh->ph.length);

	switch(wh->eh.ether_type) {
	case	ETHERTYPE_PPPOE_STUPID_DISC:
		/* nonstandard case is not supported for kernel/FP synchro */
		nonstandard = 1;
		eh_prototype.ether_type = ETHERTYPE_PPPOE_STUPID_DISC;
		/* fall through */
	case	ETHERTYPE_PPPOE_DISC:
	{
		node_p node = hook->node;

		if (unlikely(node == NULL))
			LEAVE(ENOTCONN);
		/* sanity check incoming ph->length */
		if (unlikely((length + sizeof(struct pppoe_full_hdr)) > MBUF_LENGTH(m))) {
			log(LOG_ERR, "pppoe_rcvdata: invalid payload length %d\n", length);
			/* Packet too short, dump it */
			LEAVE(EMSGSIZE);
		}

		/* for broadcast packets, in the fast path */
		if (unlikely(privp->nb_valid_bits && vnb_is_bcast(m))) {
			/* when code == PADI */
			if (wh->ph.code == PADI_CODE) {
				u_char ether_check = 0;
				/* check lsb of src MAC address */
				ether_check = wh->eh.ether_shost[VNB_ETHER_ADDR_LEN-1] &
					privp->mac_mask;
				if (ether_check != privp->mac_addr_lsb)
					/* and possibly drop the packet */
					LEAVE(0);
			} else
				LEAVE(EINVAL);
		}

		NG_PPPOE_DPRINTF("received packet (DISC)");
		/* here, only in kernel VNB => send exception
		 * the state machine must also be updated in FP VNB */
		log(LOG_DEBUG, "sending exception (DISC)\n");
		error = ng_send_exception(node, hook,
					  VNB2VNB_DATA,
					  0, m, meta);
		m = NULL;
		meta = NULL;
#ifdef PPPOE_STATS
		privp->packets_exc++;
#endif
		LEAVE(error);
		break;
	}
	case	ETHERTYPE_PPPOE_STUPID_SESS:
	case	ETHERTYPE_PPPOE_SESS:
	{
		NG_PPPOE_DPRINTF("received packet (SESS)");

		/* sanity check incoming ph->length */
		if (unlikely((length + sizeof(struct pppoe_full_hdr)) > MBUF_LENGTH(m))) {
			log(LOG_ERR, "pppoe_rcvdata: invalid payload length %d\n", length);
			/* Packet too short, dump it */
			LEAVE(EMSGSIZE);
		}

		/*
		 * find matching peer/session combination.
		 */
		sendhook = pppoe_findsession(hook, wh);
		if (unlikely(sendhook == NULL)) {
			node_p node = hook->node;

			if (node == NULL)
				LEAVE(ENOTCONN);
			/* it is probably an LCP packet that arrived
			   before the SUCCESS was seen, leaving FP
			   without knowledge of this session.
			   let the kernel manage it. */
			log(LOG_INFO, "packet without upper => exception\n");
			error = ng_send_exception(node, hook,
						  VNB2VNB_DATA,
						  0, m, meta);
			m = NULL;
			meta = NULL;
#ifdef PPPOE_STATS
			privp->packets_exc++;
#endif
			LEAVE (error);
		}
		sp = sendhook->private;
		if (unlikely(sp == NULL)) {
			log(LOG_ERR, "pppoe_rcvdata SESS: no session\n");
			LEAVE(ENETUNREACH);
		}
		/* Treat LCP and IPCP packets as exceptions, if HK_EXCEP is set */
		if (unlikely(sendhook->flags & HK_EXCEP)) {
			/* the PPP underlying protocol */
			u_int16_t ppp_prot;

			pktlen = MBUF_LENGTH(m);

			/* linearize the input packet which could be multi-segment */
			if ((m = m_pullup(m, pktlen)) == NULL) {
				log(LOG_ERR, "pppoe_rcvdata SESS: couldn't pull for PPP %u\n", pktlen);
				LEAVE(ENOBUFS);
			}

			m_copytobuf(&ppp_prot, m, VNB_ETHER_HDR_LEN + PPPOE_HDR_LEN, 2);
			if (ppp_prot == PPPOE_SESS_LCP ||
			    ppp_prot == PPPOE_SESS_IPCP) {
				node_p node = hook->node;

				if (node == NULL)
					LEAVE(ENOTCONN);

				log(LOG_DEBUG, "sending %s packet as exception\n",
				    ppp_prot == PPPOE_SESS_LCP ? "LCP" : "IPCP");
				error = ng_send_exception(node, hook,
							  VNB2VNB_DATA,
							  0, m, meta);
				m = NULL;
				meta = NULL;
#ifdef PPPOE_STATS
				privp->packets_exc++;
#endif
				LEAVE(error);
			}
		}
		if (unlikely(sp->state != PPPOE_CONNECTED)) {
			node_p node = hook->node;

			if (node == NULL)
				LEAVE(ENOTCONN);

			log(LOG_DEBUG, "sending exception (unconnected)\n");
			error = ng_send_exception(node, hook,
						  VNB2VNB_DATA,
						  0, m, meta);
			m = NULL;
			meta = NULL;
#ifdef PPPOE_STATS
			privp->packets_exc++;
#endif
			LEAVE(error);
		}

		m_adj(m, sizeof(*wh));
		pktlen = MBUF_LENGTH(m);

		/* Need to trim excess at the end */
		if (pktlen > length) {
			m_trim(m, (pktlen - length));
		}
		log(LOG_DEBUG, "forwarding mbuf (connected)\n");
		NG_PPPOE_DPRINTF("sending packet (established session)");
		NG_SEND_DATA(error, sendhook, m, meta);
		return error;
	}
	default:
		NG_PPPOE_DPRINTF( "pppoe_rcvdata SESS: dropping packet "
		    "(ethtype %x not supported)\n", htons(wh->eh.ether_type));
		LEAVE(EPFNOSUPPORT);
	}
quit:
	NG_FREE_DATA(m, meta);
	return error;
}

static int
ng_pppoe_rcvdata_debug(hook_p hook, struct mbuf *m, meta_p meta)
{
	priv_p			privp = hook->node_private;
	int			error = 0;

	if (privp == NULL)
		LEAVE(EINVAL);

	/*
	 * Data from the debug hook gets sent without modification
	 * straight to the ethernet.
	 */
	NG_PPPOE_DPRINTF("sending packet (debug)");
	NG_SEND_DATA(error, privp->ethernet_hook, m, meta);
#ifdef PPPOE_STATS
	privp->packets_out++;
#endif
	return error;
quit:
	NG_FREE_DATA(m, meta);
	return error;
}

#else
/*
 * Receive data, and do something with it.
 * The caller will never free m or meta, so
 * if we use up this data or abort we must free BOTH of these.
 */
static int
ng_pppoe_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
{
	node_p			node = hook->node;
	priv_p			privp = NULL;
	sessp			sp;
	const struct pppoe_full_hdr *wh;
	int			error = 0;
	u_int16_t		length;
	/* the following variables are used for machine state management
	 * => only in kernel VNB */
	const struct pppoe_hdr	*ph;
	u_int8_t		code;
	const struct pppoe_tag	*utag = NULL, *tag = NULL;
	struct {
		struct pppoe_tag hdr;
		union	uniq	data;
	} __attribute ((packed)) uniqtag;
	negp			neg = NULL;
	struct mbuf *m0 = NULL;
	meta_p dummy = NULL;
	struct ng_mesg *msg = NULL;
	hook_p 			sendhook;

	if (node == NULL) {
		log(LOG_ERR, "pppoe_rcvdata: NULL node\n");
		LEAVE(EINVAL);
	}
	privp = node->private;
	if (privp == NULL)
		LEAVE(EINVAL);

	if (hook->private == &privp->debug_hook) {
		/*
		 * Data from the debug hook gets sent without modification
		 * straight to the ethernet.
		 */
		NG_PPPOE_DPRINTF("sending packet (debug)");
		NG_SEND_DATA( error, privp->ethernet_hook, m, meta);
#ifdef PPPOE_STATS
		privp->packets_out++;
#endif
	} else if (hook->private == &privp->ethernet_hook) {
		/*
		 * Incoming data.
		 * Dig out various fields from the packet.
		 * use them to decide where to send it.
		 */
		int pktlen;

		NG_PPPOE_DPRINTF("%x received packet (ethernet)", node->ID);
#ifdef PPPOE_STATS
		privp->packets_in++;
#endif
		if ((m = m_pullup(m, sizeof(*wh))) == NULL) {
			log(LOG_ERR, "pppoe_rcvdata: couldn't pull\n");
			LEAVE(ENOBUFS);
		}
		wh = mtod(m, struct pppoe_full_hdr *);
		length = ntohs(wh->ph.length);

		switch(wh->eh.ether_type) {
		case	ETHERTYPE_PPPOE_STUPID_DISC:
			/* nonstandard case is not supported for kernel/FP synchro */
			nonstandard = 1;
			eh_prototype.ether_type = ETHERTYPE_PPPOE_STUPID_DISC;
			/* fall through */
		case	ETHERTYPE_PPPOE_DISC:
			NG_PPPOE_DPRINTF("received packet (DISC)");
			pktlen = MBUF_LENGTH(m);

			/* sanity check incoming ph->length */
			if ((length + sizeof(struct pppoe_full_hdr)) > MBUF_LENGTH(m)) {
				log(LOG_ERR, "pppoe_rcvdata: invalid payload length %d\n", length);
				/* Packet too short, dump it */
				LEAVE(EMSGSIZE);
			}

			/* linearize the input packet which could be multi-segment */
			if ((m = m_pullup(m, pktlen)) == NULL) {
				log(LOG_ERR, "pppoe_rcvdata: couldn't pull %d\n", pktlen);
				LEAVE(ENOBUFS);
			}
			wh = mtod(m, struct pppoe_full_hdr *);
			ph = &wh->ph;
			code = ph->code;
#if DEBUG_PPPOE >= 2
			ng_hexdump((void *)ph, MBUF_LENGTH(m));
#endif
			switch(code) {
			case	PADI_CODE:
				/*
				 * We are a server:
				 * Look for a hook with the required service
				 * and send the ENTIRE packet up there.
				 * It should come back to a new hook in
				 * PRIMED state. Look there for further
				 * processing.
				 */
				tag = get_tag(ph, PTT_SRV_NAME);
				if (tag == NULL) {
					log(LOG_ERR, "pppoe_rcvdata PADI: no service tag\n");
					LEAVE(ENETUNREACH);
				}
				sendhook = pppoe_match_svc(hook->node,
					PPPOE_TAG_DATA(tag),
					ntohs(tag->tag_len),
					NG_MATCH_ANY);
				if (sendhook) {
					NG_PPPOE_DPRINTF("sending packet (service)");
					NG_SEND_DATA(error, sendhook, m, meta);
				} else {
					if (net_ratelimit())
						log(LOG_ERR, "pppoe_rcvdata PADI: no sendhook\n");
					LEAVE(ENETUNREACH);
				}
				break;
			case	PADO_CODE: {
				struct ng_callout *cur_callout_to_stop = NULL;
				/*
				 * We are a client:
				 * Use the host_uniq tag to find the
				 * hook this is in response to.
				 * Received #2, now send #3
				 * For now simply accept the first we receive.
				 */
				utag = get_tag(ph, PTT_HOST_UNIQ);
				if ((utag == NULL)
				|| (ntohs(utag->tag_len) != sizeof(sp))) {
					log(LOG_ERR, "pppoe_rcvdata PADO: no host unique field\n");
					LEAVE(ENETUNREACH);
				}

				sendhook = pppoe_finduniq(node, utag);
				if (sendhook == NULL) {
					log(LOG_ERR, "pppoe_rcvdata PADO: no matching session\n");
					LEAVE(ENETUNREACH);
				}

				/*
				 * Check the session is in the right state.
				 * It needs to be in PPPOE_SINIT.
				 */
				sp = sendhook->private;
				if (sp == NULL) {
					log(LOG_ERR, "pppoe_rcvdata PADO: no session\n");
					LEAVE(ENETUNREACH);
				}
				vnb_spinlock_lock(&sp->sess_lock);
				if (sp->state != PPPOE_SINIT) {
					vnb_spinlock_unlock(&sp->sess_lock);
					log(LOG_ERR, "pppoe_rcvdata PADO: session in wrong state %d\n",
						sp->state);
					LEAVE(ENETUNREACH);
				}
				neg = sp->neg;
				cur_callout_to_stop = &neg->timeout_handle;

				/*
				 * This is the first time we hear
				 * from the server, so note it's
				 * unicast address, replacing the
				 * broadcast address .
				 */
				bcopy(wh->eh.ether_shost,
					neg->pkt->pkt_header.eh.ether_dhost,
					VNB_ETHER_ADDR_LEN);
				neg->timeout = 0;
				neg->pkt->pkt_header.ph.code = PADR_CODE;
				init_tags(sp);
				insert_tag(sp, utag);      /* Host Unique */
				if ((tag = get_tag(ph, PTT_AC_COOKIE)))
					insert_tag(sp, tag); /* return cookie */
				if ((tag = get_tag(ph, PTT_AC_NAME))) {
					insert_tag(sp, tag); /* return it */
					msg = send_acname(sp, tag);
				}
				insert_tag(sp, &neg->service.hdr); /* Service */
				scan_tags(sp, ph);
				if (make_packet(sp) == NULL) {
					m0 = neg->m;
					neg->m = NULL;
					neg->pkt = NULL;
					m_freem(m0);
					vnb_spinlock_unlock(&sp->sess_lock);
					log(LOG_ERR, "pppoe_rcvdata PADO: failing make_packet\n");
					LEAVE(ENOBUFS);
				}
				sp->state = PPPOE_SREQ;
				NG_PPPOE_DPRINTF("sending PADR");
				m0 = sendpacket(sp);
				vnb_spinlock_unlock(&sp->sess_lock);
				/* ng_callout_stop_sync() cannot be used in
				 * the data path. */
				ng_callout_stop(cur_callout_to_stop);
				if (msg != NULL)
					error = ng_send_msg(node, msg, sp->creator, NULL, NULL);
				if (m0 != NULL) {
					NG_SEND_DATA( error, privp->ethernet_hook, m0, dummy);
#ifdef PPPOE_STATS
					privp->packets_out++;
#endif
				}
				break;
			}
			case	PADR_CODE: {
				u_int16_t new_sess_id = 0;
				struct ng_callout *cur_callout_to_stop = NULL;
				/*
				 * We are a server:
				 * Use the ac_cookie tag to find the
				 * hook this is in response to.
				 */
				utag = get_tag(ph, PTT_AC_COOKIE);
				if ((utag == NULL)
				|| (ntohs(utag->tag_len) != sizeof(sp))) {
					log(LOG_ERR, "pppoe_rcvdata PADR: no ac_cookie field\n");
					LEAVE(ENETUNREACH);
				}

				/* pppoe_finduniq is only used in kernel VNB */
				sendhook = pppoe_finduniq(node, utag);
				if (sendhook == NULL) {
					log(LOG_ERR, "pppoe_rcvdata PADR: %x no sendhook\n", node->ID);
					LEAVE(ENETUNREACH);
				}

				/*
				 * Check the session is in the right state.
				 * It needs to be in PPPOE_SOFFER
				 * or PPPOE_NEWCONNECTED. If the latter,
				 * then this is a retry by the client.
				 * so be nice, and resend.
				 */
				sp = sendhook->private;
				if (sp == NULL) {
					log(LOG_ERR, "pppoe_rcvdata PADR: no session\n");
					LEAVE(ENETUNREACH);
				}
				vnb_spinlock_lock(&sp->sess_lock);
				if (sp->state == PPPOE_NEWCONNECTED) {
					/*
					 * Whoa! drop back to resend that
					 * PADS packet.
					 * We should still have a copy of it.
					 */
					sp->state = PPPOE_SOFFER;
				}
				if (sp->state != PPPOE_SOFFER) {
					vnb_spinlock_unlock(&sp->sess_lock);
					log(LOG_ERR, "pppoe_rcvdata PADR: session in wrong state %d\n",
						sp->state);
					LEAVE (ENETUNREACH);
					break;
				}
				neg = sp->neg;
				if (neg == NULL) {
					vnb_spinlock_unlock(&sp->sess_lock);
					log(LOG_ERR, "pppoe_rcvdata PADR: no neg\n");
					LEAVE(ENETUNREACH);
				}
				cur_callout_to_stop = &neg->timeout_handle;
				neg->pkt->pkt_header.ph.code = PADS_CODE;
				if (sp->Session_ID == 0) {
					new_sess_id = get_new_sid(node);
					if (new_sess_id == 0) {
						vnb_spinlock_unlock(&sp->sess_lock);
						LEAVE (EINVAL);
						break;
					}
#if defined(PPPOE_SESS_CACHE)
					privp->pppoe_sess_cache[new_sess_id] = sendhook;
#endif
					/* register use of this Session_ID */
					vnb_spinlock_lock(&privp->sessid_lock);
					privp->sess_id_used[(new_sess_id)>>PPPOE_WORD_LEN_ORDER] |=
						(1ULL << (new_sess_id&PPPOE_WORD_MASK));
					vnb_spinlock_unlock(&privp->sessid_lock);
					neg->pkt->pkt_header.ph.sid =
					    htons(sp->Session_ID
						= new_sess_id);
				}
				/* here, not all info is present in sp
				 * => do not use for kernel / FP synchro */
				neg->timeout = 0;
				/*
				 * start working out the tags to respond with.
				 */
				init_tags(sp);
				insert_tag(sp, &neg->ac_name.hdr); /* AC_NAME */
				if ((tag = get_tag(ph, PTT_SRV_NAME)))
					insert_tag(sp, tag);/* return service */
				if ((tag = get_tag(ph, PTT_HOST_UNIQ)))
					insert_tag(sp, tag); /* return it */
				insert_tag(sp, utag);	/* ac_cookie */
				scan_tags(sp, ph);
				if (make_packet(sp) == NULL) {
					m0 = neg->m;
					neg->m = NULL;
					neg->pkt = NULL;
					m_freem(m0);
					vnb_spinlock_unlock(&sp->sess_lock);
					log(LOG_ERR, "pppoe_rcvdata PADR: failing make_packet\n");
					/* ng_callout_stop_sync() cannot be
					 * used in the data path. */
					ng_callout_stop(cur_callout_to_stop);
					LEAVE(ENOBUFS);
				}
				sp->state = PPPOE_NEWCONNECTED;
				NG_PPPOE_DPRINTF("sending PADS");
				m0 = sendpacket(sp);
				/*
				 * Having sent the last Negotiation header,
				 * Set up the stored packet header to
				 * be correct for the actual session.
				 * But keep the negotialtion stuff
				 * around in case we need to resend this last
				 * packet. We'll discard it when we move
				 * from NEWCONNECTED to CONNECTED
				 */
				sp->pkt_hdr = neg->pkt->pkt_header;
				if (nonstandard)
					sp->pkt_hdr.eh.ether_type
						= ETHERTYPE_PPPOE_STUPID_SESS;
				else
					sp->pkt_hdr.eh.ether_type
						= ETHERTYPE_PPPOE_SESS;
				sp->pkt_hdr.ph.code = 0;
				/* When the session is established in the kernel VNB:
				 * send all relevant parameters from sp: => mpd => fast path VNB
				 * sp->pkt_hdr.eh.ether_dhost ; sp->Session_ID */
				msg = pppoe_send_event(sp, NGM_PPPOE_SUCCESS);
				vnb_spinlock_unlock(&sp->sess_lock);
				/* ng_callout_stop_sync() cannot be used in the
				 * data path. */
				ng_callout_stop(cur_callout_to_stop);
				if (msg != NULL)
					error = ng_send_msg(node, msg, sp->creator, NULL, NULL);
				if (m0 != NULL) {
					NG_SEND_DATA( error, privp->ethernet_hook, m0, dummy);
#ifdef PPPOE_STATS
					privp->packets_out++;
#endif
				}
				break;
			}
			case	PADS_CODE: {
				struct ng_callout *cur_callout_to_stop = NULL;
				/*
				 * We are a client:
				 * Use the host_uniq tag to find the
				 * hook this is in response to.
				 * take the session ID and store it away.
				 * Also make sure the pre-made header is
				 * correct and set us into Session mode.
				 */
				utag = get_tag(ph, PTT_HOST_UNIQ);
				if ((utag == NULL)
				|| (ntohs(utag->tag_len) != sizeof(sp))) {
					log(LOG_ERR, "pppoe_rcvdata PADS: no host_uniq tag\n");
					LEAVE (ENETUNREACH);
					break;
				}
				sendhook = pppoe_finduniq(node, utag);
				if (sendhook == NULL) {
					log(LOG_ERR, "pppoe_rcvdata PADS: no sendhook (client)\n");
					LEAVE(ENETUNREACH);
				}

				/*
				 * Check the session is in the right state.
				 * It needs to be in PPPOE_SREQ.
				 */
				sp = sendhook->private;
				if (sp == NULL) {
					log(LOG_ERR, "pppoe_rcvdata PADS: no session\n");
					LEAVE(ENETUNREACH);
				}
				vnb_spinlock_lock(&sp->sess_lock);
				if (sp->state != PPPOE_SREQ) {
					vnb_spinlock_unlock(&sp->sess_lock);
					log(LOG_ERR, "pppoe_rcvdata PADS: session in wrong state %d (client)\n",
						sp->state);
					LEAVE(ENETUNREACH);
				}
				neg = sp->neg;
				if (neg == NULL) {
					vnb_spinlock_unlock(&sp->sess_lock);
					log(LOG_ERR, "pppoe_rcvdata PADS: no neg\n");
					LEAVE(ENETUNREACH);
				}
				cur_callout_to_stop = &neg->timeout_handle;
				neg->pkt->pkt_header.ph.sid = wh->ph.sid;
				sp->Session_ID = ntohs(wh->ph.sid);
				/* as a client, no need to register the use of this Session_ID */
#if defined(PPPOE_SESS_CACHE)
				privp->pppoe_sess_cache[sp->Session_ID] = sendhook;
#endif
				neg->timeout = 0;
				sp->state = PPPOE_CONNECTED;
				/*
				 * Now we have gone to Connected mode,
				 * Free all resources needed for
				 * negotiation.
				 * Keep a copy of the header we will be using.
				 */
				sp->pkt_hdr = neg->pkt->pkt_header;
				if (nonstandard)
					sp->pkt_hdr.eh.ether_type
						= ETHERTYPE_PPPOE_STUPID_SESS;
				else
					sp->pkt_hdr.eh.ether_type
						= ETHERTYPE_PPPOE_SESS;
				sp->pkt_hdr.ph.code = 0;
				m0 = neg->m;
				neg->m = NULL;
				neg->pkt = NULL;
				if (m0 != NULL)
					m_freem(m0);
				sp->neg = NULL;
				ng_free(neg);
#ifdef PPPOE_STATS
				privp->negp_free++;
#endif
				msg = pppoe_send_event(sp, NGM_PPPOE_SUCCESS);
				vnb_spinlock_unlock(&sp->sess_lock);
				/* ng_callout_stop_sync() cannot be used in the
				 * data path. */
				ng_callout_stop(cur_callout_to_stop);
				if (msg != NULL)
					error = ng_send_msg(node, msg, sp->creator, NULL, NULL);
				break;
			}
			case	PADT_CODE:
				/*
				 * Send a 'close' message to the controlling
				 * process (the one that set us up);
				 * And then tear everything down.
				 *
				 * Find matching peer/session combination.
				 */
				sendhook = pppoe_findsession(hook, wh);
				NG_FREE_DATA(m, meta); /* no longer needed */
				if (sendhook == NULL) {
					NG_PPPOE_DPRINTF("pppoe_rcvdata PADT: no sendhook (close)\n");
					LEAVE(ENETUNREACH);
				}
				/* send message to creator */
				if (sendhook) {
					sp = sendhook->private;
					if (sp == NULL) {
						log(LOG_ERR, "pppoe_rcvdata PADT: no session\n");
						LEAVE(ENETUNREACH);
					}
					vnb_spinlock_lock(&sp->sess_lock);
					msg = pppoe_send_event(sp, NGM_PPPOE_CLOSE);
					vnb_spinlock_unlock(&sp->sess_lock);
					if (msg != NULL)
						error = ng_send_msg(node, msg, sp->creator, NULL, NULL);
				}
				break;
			default:
				log(LOG_ERR, "pppoe_rcvdata: Nego CODE not supported\n");
				LEAVE(EPFNOSUPPORT);
			}
			break;
		case	ETHERTYPE_PPPOE_STUPID_SESS:
		case	ETHERTYPE_PPPOE_SESS:
			NG_PPPOE_DPRINTF("received packet (SESS)");

			/* sanity check incoming ph->length */
			if ((length + sizeof(struct pppoe_full_hdr)) > MBUF_LENGTH(m)) {
				log(LOG_ERR, "pppoe_rcvdata: invalid payload length %d\n", length);
				/* Packet too short, dump it */
				LEAVE(EMSGSIZE);
			}

			/*
			 * find matching peer/session combination.
			 */
			sendhook = pppoe_findsession(hook, wh);
			if (sendhook == NULL) {
				NG_PPPOE_DPRINTF("no session found\n");
				LEAVE (ENETUNREACH);
			}
			sp = sendhook->private;
			if (sp == NULL) {
				log(LOG_ERR, "pppoe_rcvdata SESS: no session\n");
				LEAVE(ENETUNREACH);
			}
			vnb_spinlock_lock(&sp->sess_lock);

			m_adj(m, sizeof(*wh));
			pktlen = MBUF_LENGTH(m);

			/* Need to trim excess at the end */
			if (pktlen > length) {
				m_trim(m, (pktlen - length));
			}
			/* machine state management: only in kernel VNB */
			if ( sp->state != PPPOE_CONNECTED) {
				if (sp->state == PPPOE_NEWCONNECTED) {
					sp->state = PPPOE_CONNECTED;
					/*
					 * Now we have gone to Connected mode,
					 * Free all resources needed for
					 * negotiation. Be paranoid about
					 * whether there may be a timeout.
					 */
					if (unlikely((neg = sp->neg) == NULL)) {
						vnb_spinlock_unlock(&sp->sess_lock);
						log(LOG_ERR, "pppoe_rcvdata SESS: NULL neg\n");
						LEAVE (ENETUNREACH);
					}
					m0 = neg->m;
					neg->m = NULL;
					neg->pkt = NULL;
					if (m0 != NULL)
						m_freem(m0);
					/* ng_callout_stop_sync() cannot be
					 * used in the data path. */
					ng_callout_stop(&neg->timeout_handle);
					sp->neg = NULL;
					ng_free(neg);
#ifdef PPPOE_STATS
					privp->negp_free++;
#endif
				} else {
					vnb_spinlock_unlock(&sp->sess_lock);
					log(LOG_ERR, "pppoe_rcvdata SESS: dropping packet (not connected)\n");
					LEAVE (ENETUNREACH);
					break;
				}
			}
			vnb_spinlock_unlock(&sp->sess_lock);
			if (m != NULL) {
				NG_PPPOE_DPRINTF("sending packet (established session)");
				NG_SEND_DATA(error, sendhook, m, meta);
			} else {
				log(LOG_ERR, "pppoe_rcvdata SESS: dropping packet (m == NULL)");
			}
			break;
		default:
			NG_PPPOE_DPRINTF("pppoe_rcvdata SESS: dropping packet "
			             "(ethtype %x not supported)\n", htons(wh->eh.ether_type));
			LEAVE(EPFNOSUPPORT);
		}
	} else {
		NG_PPPOE_DPRINTF("%x received packet (upper)", node->ID);
		/*
		 * 	Not ethernet or debug hook..
		 *
		 * The packet has come in on a normal hook.
		 * We need to find out what kind of hook,
		 * So we can decide how to handle it.
		 * Check the hook's state.
		 */
		sp = hook->private;
		if (sp == NULL) {
			if (net_ratelimit())
				log(LOG_ERR, "packet from upper NULL sp\n");
			LEAVE(EINVAL);
		}
		switch (sp->state) {
		case	PPPOE_NEWCONNECTED:
		case	PPPOE_CONNECTED: {
			/* forwarding PPP packets in kernel VNB */
			struct pppoe_full_hdr *wh;

			/*
			 * Remove PPP address and control fields, if any.
			 * For example, ng_ppp(4) always sends LCP packets
			 * with address and control fields as required by
			 * generic PPP. PPPoE is an exception to the rule.
			 */
			if(likely(MBUF_LENGTH(m) >= 2)) {
				if (mtod(m, uint8_t *)[0] == 0xff &&
					mtod(m, uint8_t *)[1] == 0x03)
					m_adj(m, 2);
			}
			length = MBUF_LENGTH(m);
			/*
			 * Bang in a pre-made header, then correct the length.
			 * And then send it to the ethernet driver.
			 */
			M_PREPEND(m, sizeof(*wh), M_DONTWAIT);
			if (m == NULL) {
				log(LOG_ERR, "pppoe_rcvdata: couldn't prepend (from PPP)\n");
				LEAVE(ENOBUFS);
			}
			wh = mtod(m, struct pppoe_full_hdr *);
			bcopy(&sp->pkt_hdr, wh, sizeof(*wh));
			wh->ph.length = htons(length);
			NG_PPPOE_DPRINTF("forwarding packet (from PPP)");
			NG_SEND_DATA( error, privp->ethernet_hook, m, meta);
#ifdef PPPOE_STATS
			privp->packets_out++;
#endif
			break;
			}
		/* these states are only valid in kernel VNB */
		case	PPPOE_PRIMED:
		case	PPPOE_SOFFER: {
			struct ng_callout *cur_callout_to_stop = NULL;
			/*
			 * A PADI packet is being returned by the application
			 * that has set up this hook. This indicates that it
			 * wants us to offer service.
			 */
			length = MBUF_LENGTH(m);
			if ((m = m_pullup(m, sizeof(*wh))) == NULL) {
				m_freem(m);
				log(LOG_ERR, "pppoe_rcvdata: couldn't pull sizeof(*wh: %zd) len %d\n",
				  sizeof(*wh), length);
				LEAVE(ENOBUFS);
			}
			wh = mtod(m, struct pppoe_full_hdr *);
			ph = &wh->ph;
			code = wh->ph.code;
			if ( (code != PADI_CODE) &&
			     /* in case of repeater, we may also receive early LCP packets */
			     (mtod(m, uint8_t *)[0] != 0xff &&
			      mtod(m, uint8_t *)[1] != 0x03) ) {
				log(LOG_ERR, "pppoe_rcvdata: %x received code: %d from %s hook mlen %d\n",
					node->ID, code, hook->name, length);
#if DEBUG_PPPOE > 1
				ng_hexdump((void *)wh, length);
#endif
				LEAVE(EINVAL);
			}
			vnb_spinlock_lock(&sp->sess_lock);
			neg = sp->neg;
			if (neg == NULL) {
				vnb_spinlock_unlock(&sp->sess_lock);
				log(LOG_ERR, "pppoe_rcvdata: NULL neg\n");
				LEAVE(EINVAL);
			}
			cur_callout_to_stop = &neg->timeout_handle;

			/*
			 * This is the first time we hear
			 * from the client, so note it's
			 * unicast address, replacing the
			 * broadcast address.
			 */
			/* synchro in fast path VNB via mpd */
			bcopy(wh->eh.ether_shost,
				neg->pkt->pkt_header.eh.ether_dhost,
				VNB_ETHER_ADDR_LEN);
			sp->state = PPPOE_SOFFER;
			neg->timeout = 0;
			neg->pkt->pkt_header.ph.code = PADO_CODE;

			/*
			 * start working out the tags to respond with.
			 */
			uniqtag.hdr.tag_type = PTT_AC_COOKIE;
			uniqtag.hdr.tag_len = htons((u_int16_t)sizeof(sp));
			uniqtag.data.ul = sp->ul;
			init_tags(sp);
			insert_tag(sp, &neg->ac_name.hdr); /* AC_NAME */
			if ((tag = get_tag(ph, PTT_SRV_NAME)))
				insert_tag(sp, tag);	  /* return service */
			/*
			 * If we have a NULL service request
			 * and have an extra service defined in this hook,
			 * then also add a tag for the extra service.
			 * XXX this is a hack. eventually we should be able
			 * to support advertising many services, not just one
			 */
			if (((tag == NULL) || (tag->tag_len == 0))
			&& (neg->service.hdr.tag_len != 0)) {
				insert_tag(sp, &neg->service.hdr); /* SERVICE */
			}
			if ((tag = get_tag(ph, PTT_HOST_UNIQ)))
				insert_tag(sp, tag); /* returned hostunique */
			insert_tag(sp, &uniqtag.hdr);
			scan_tags(sp, ph);
			/* state machine maanagement is only done in kernel VNB */
			if (make_packet(sp) == NULL) {
				m0 = neg->m;
				neg->m = NULL;
				neg->pkt = NULL;
				m_freem(m0);
				vnb_spinlock_unlock(&sp->sess_lock);
				log(LOG_ERR, "pppoe_rcvdata PADI: failing make_packet\n");
				LEAVE(ENOBUFS);
			}
			NG_PPPOE_DPRINTF("answer PADI (from mpd) => PADO");
			m0 = sendpacket(sp);
			vnb_spinlock_unlock(&sp->sess_lock);
			/* ng_callout_stop_sync() cannot be used in the
			 * data path. */
			ng_callout_stop(cur_callout_to_stop);
			if (m0 != NULL) {
				NG_SEND_DATA( error, privp->ethernet_hook, m0, dummy);
#ifdef PPPOE_STATS
				privp->packets_out++;
#endif
			}
			break;
		}
		/*
		 * Packets coming from the hook make no sense
		 * to sessions in these states. Throw them away.
		 */
		case	PPPOE_SINIT:
		case	PPPOE_SREQ:
		case	PPPOE_SNONE:
		case	PPPOE_LISTENING:
		case	PPPOE_DEAD:
		default:
			NG_PPPOE_DPRINTF("Lx packet from upper in unexpected state %d\n", sp->state);
			LEAVE(ENETUNREACH);
		}
	}
quit:
	NG_FREE_DATA(m, meta);
	return error;
}
#endif
/*
 * Do local shutdown processing..
 * If we are a persistant device, we might refuse to go away, and
 * we'd only remove our links and reset ourself.
 */
static int
ng_pppoe_rmnode(node_p node)
{
	const priv_p privdata = node->private;

	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);
	node->private = NULL;
	ng_unref(privdata->node);
	return (0);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_pppoe_connect(hook_p hook)
{
	/* be really amiable and just say "YUP that's OK by me! " */
	return (0);
}

/*
 * Hook disconnection
 *
 * Clean up all dangling links and information about the session/hook.
 * For this type, removal of the last link destroys the node
 */
static int
ng_pppoe_disconnect(hook_p hook)
{
	node_p node = hook->node;
	priv_p privp = NULL;
	sessp	sp;

	if ((node == NULL) || ((privp = node->private) == NULL))
		return EINVAL;

	if (hook->private == &privp->debug_hook) {
		privp->debug_hook = NULL;
	} else if (hook->private == &privp->ethernet_hook) {
		privp->ethernet_hook = NULL;
		ng_rmnode(node);
	} else {
#ifndef __FastPath__
		struct ng_mesg *msg = NULL;
		struct mbuf *m = NULL, *m0 = NULL;
		void *dummy = NULL;
		int error;
		negp neg = NULL;
		struct ng_callout *cur_callout_to_stop = NULL;
		enum state state;
#endif
		u_int16_t session;

		sp = hook->private;

		if (sp == NULL) {
			log(LOG_ERR, "pppoe: ng_pppoe_disconnect with NULL sp\n");
			return EINVAL;
		}

		session = sp->Session_ID;
#if defined(PPPOE_SESS_CACHE)
		privp->pppoe_sess_cache[session] = NULL;
#endif
#ifndef __FastPath__
		neg = sp->neg;
		state = sp->state;

		/* register availability of a Session_ID */
		vnb_spinlock_lock(&privp->sessid_lock);
		privp->sess_id_used[(session)>>PPPOE_WORD_LEN_ORDER] &=
			~(1ULL << (session&PPPOE_WORD_MASK));
		vnb_spinlock_unlock(&privp->sessid_lock);
		/* machine state management is done only in kernel VNB */
		vnb_spinlock_lock(&sp->sess_lock);
		if (state != PPPOE_SNONE ) {
			msg = pppoe_send_event(sp, NGM_PPPOE_CLOSE);
		}
		/*
		 * According to the spec, if we are connected,
		 * we should send a DISC packet if we are shutting down
		 * a session.
		 */
		if ((privp->ethernet_hook)
		&& ((state == PPPOE_CONNECTED)
		 || (state == PPPOE_NEWCONNECTED))) {
			struct pppoe_full_hdr *wh;
			struct pppoe_tag *tag;
			const int	msglen = sizeof(SIGNOFF) - 1;
			int skblen;

			/* revert the stored header to DISC/PADT mode */
			wh = &sp->pkt_hdr;
			wh->ph.code = PADT_CODE;
			if (nonstandard)
				wh->eh.ether_type = ETHERTYPE_PPPOE_STUPID_DISC;
			else
				wh->eh.ether_type = ETHERTYPE_PPPOE_DISC;

			/* generate a packet of that type */
			skblen = sizeof(*wh) + sizeof(*tag) + msglen;
			if (((m = m_alloc()) != NULL) &&
			    (m_append(m, skblen) == NULL)) {
				m_freem(m);
				m = NULL;
			}
			if(m == NULL)
				log(LOG_ERR, "pppoe: Session out of mbufs\n");
			else {
				bcopy((caddr_t)wh, mtod(m, caddr_t),
				    sizeof(*wh));
				/*
				 * Add a General error message and adjust
				 * sizes
				 */
				wh = mtod(m, struct pppoe_full_hdr *);
				tag = PPPOE_HDR_DATA(&wh->ph);
				tag->tag_type = PTT_GEN_ERR;
				tag->tag_len = htons((u_int16_t)msglen);
				strncpy(PPPOE_TAG_DATA(tag), SIGNOFF, msglen);
				wh->ph.length = htons(sizeof(*tag) + msglen);
			}
		}

		if (state == PPPOE_LISTENING) {
			/* remove from the PPPOE_LISTENING linked list */
			if (!LIST_EMPTY(&privp->head)) {
				struct sess_con *entry;
				LIST_FOREACH(entry, &privp->head, next) {
					if (entry->hook == hook){
						LIST_REMOVE(entry, next);
						break;
					}
				}
			} else
				log(LOG_ERR, "pppoe: Unexpected empty list of listening hooks\n");
		}

		/*
		 * As long as we have somewhere to store the timeout handle,
		 * we may have a timeout pending.. get rid of it.
		 */
		if (neg != NULL) {
			cur_callout_to_stop = &neg->timeout_handle;
			m0 = neg->m;
			neg->m = NULL;
			neg->pkt = NULL;
			if (m0 != NULL)
				m_freem(m0);
			/* sp->neg == NULL means the data path must not
			 * perform ng_callout_reset() */
			sp->neg = NULL;
			ng_free(neg);
#ifdef PPPOE_STATS
			privp->negp_free++;
#endif
		}
		vnb_spinlock_unlock(&sp->sess_lock);
		if (cur_callout_to_stop != NULL)
			ng_callout_stop_sync(cur_callout_to_stop);
		if (msg != NULL)
			error = ng_send_msg(node, msg, sp->creator, NULL, NULL);
		if (m != NULL) {
			NG_SEND_DATA(error, privp->ethernet_hook, m, dummy);
#ifdef PPPOE_STATS
			privp->packets_out++;
#endif
		}
		(void)error;
#endif /* !__FastPath__ */
		hook->private = NULL;
		ng_free(sp);
#ifdef PPPOE_STATS
		privp->sessp_free++;
#endif
	}
	/*
	 * If no hooks are left or if there's only an ethernet hook,
	 * commit suicide.
	 */
	if ((node->numhooks == 0) ||
	    ((node->numhooks == 1) && (privp->ethernet_hook != NULL)))
		ng_rmnode(node);
	return (0);
}

#ifndef __FastPath__
/*
 * timeouts come here.
 */
static void
pppoe_ticker(void *arg)
{
	hook_p hook = NULL;
	node_p node = NULL;
	sessp	sp = NULL;
	negp	neg = NULL;
	int	error = 0;
	struct mbuf *m0 = NULL, *m1 = NULL, *m = NULL;
	priv_p privp = NULL;
	meta_p dummy = NULL;

	if (unlikely((hook = arg) == NULL))
		return;
	if (unlikely((sp = hook->private) == NULL))
		return;
	if (((node = hook->node) == NULL) || ((privp = node->private) == NULL))
		return;

	switch(sp->state) {
		/*
		 * resend the last packet, using an exponential backoff.
		 * After a period of time, stop growing the backoff,
		 * and either leave it, or revert to the start.
		 */
	case	PPPOE_SINIT:
	case	PPPOE_SREQ:
		vnb_spinlock_lock(&sp->sess_lock);
		if (unlikely((neg = sp->neg) == NULL)) {
			vnb_spinlock_unlock(&sp->sess_lock);
			return;
		}
		if (unlikely((m = neg->m) == NULL)) {
			vnb_spinlock_unlock(&sp->sess_lock);
			return;
		}
		/* timeouts on these produce resends */
		m0 = m_copypacket(m, M_DONTWAIT);
#ifdef PPPOE_STATS
		privp->mcopy_nb++;
		if (m0 == NULL)
			privp->m_copy_fail++;
#endif
		ng_callout_reset(&neg->timeout_handle, neg->timeout * hz,
				 pppoe_ticker, hook);
		if ((neg->timeout <<= 1) > PPPOE_TIMEOUT_LIMIT) {
			if (sp->state == PPPOE_SREQ) {
				/* revert to SINIT mode */
				m1 = pppoe_start(sp);
			} else {
				neg->timeout = PPPOE_TIMEOUT_LIMIT;
			}
		}
		vnb_spinlock_unlock(&sp->sess_lock);
		break;
	case	PPPOE_PRIMED:
	case	PPPOE_SOFFER: {
		struct ng_callout *cur_callout_to_stop = NULL;
		vnb_spinlock_lock(&sp->sess_lock);
		if (unlikely((neg = sp->neg) == NULL)) {
			vnb_spinlock_unlock(&sp->sess_lock);
			return;
		}
		/* a timeout on these says "give up" */
		cur_callout_to_stop = &neg->timeout_handle;
		vnb_spinlock_unlock(&sp->sess_lock);
		/* ng_callout_stop_sync() cannot be used on its own callout. */
		ng_callout_stop(cur_callout_to_stop);
		ng_destroy_hook(hook);
		break;
	}
	default:
		/* timeouts have no meaning in other states */
		log(LOG_ERR, "pppoe: unexpected timeout\n");
	}

	if (m0 != NULL) {
		NG_SEND_DATA( error, privp->ethernet_hook, m0, dummy);
#ifdef PPPOE_STATS
		privp->packets_out++;
#endif
	}
	if (m1 != NULL) {
		NG_SEND_DATA( error, privp->ethernet_hook, m1, dummy);
#ifdef PPPOE_STATS
		privp->packets_out++;
#endif
	}
	(void)error;
}



/* packet send only in kernel VNB
 * state machine *management* is done in kernel VNB */
static struct mbuf *
sendpacket(sessp sp)
{
	struct mbuf *m, *m0 = NULL;
	hook_p hook;
	node_p node;
	negp	neg;
	priv_p	privp;

	if (unlikely((sp == NULL) || ((hook = sp->hook) == NULL))) {
		log(LOG_ERR, "pppoe: NULL sp/hook\n");
		return NULL;
	}
	if (unlikely(((node = hook->node) == NULL) || ((privp = node->private) == NULL))) {
		log(LOG_ERR, "pppoe: NULL node/privp\n");
		return NULL;
	}

	if (unlikely((neg = sp->neg) == NULL)) {
		log(LOG_ERR, "pppoe: NULL neg\n");
		return NULL;
	}
	if (unlikely((m = neg->m) == NULL)) {
		log(LOG_ERR, "pppoe: NULL neg->m\n");
		return NULL;
	}
	switch(sp->state) {
	case	PPPOE_LISTENING:
	case	PPPOE_DEAD:
	case	PPPOE_SNONE:
	case	PPPOE_CONNECTED:
		log(LOG_ERR, "pppoe: sendpacket: unexpected state\n");
		break;

	case	PPPOE_NEWCONNECTED:
		/* send the PADS without a timeout - we're now connected */
		m0 = m_copypacket(m, M_DONTWAIT);
#ifdef PPPOE_STATS
		privp->mcopy_nb++;
		if (m0 == NULL)
			privp->m_copy_fail++;
#endif
		break;

	case	PPPOE_PRIMED:
		/* No packet to send, but set up the timeout */
		ng_callout_reset(&neg->timeout_handle,
				 PPPOE_OFFER_TIMEOUT * hz,
				 pppoe_ticker, hook);
		break;

	case	PPPOE_SOFFER:
		/*
		 * send the offer but if they don't respond
		 * in PPPOE_OFFER_TIMEOUT seconds, forget about it.
		 */
		m0 = m_copypacket(m, M_DONTWAIT);
#ifdef PPPOE_STATS
		privp->mcopy_nb++;
		if (m0 == NULL)
			privp->m_copy_fail++;
#endif
		ng_callout_reset(&neg->timeout_handle,
				 PPPOE_OFFER_TIMEOUT * hz,
				 pppoe_ticker, hook);
		break;

	case	PPPOE_SINIT:
	case	PPPOE_SREQ:
		m0 = m_copypacket(m, M_DONTWAIT);
#ifdef PPPOE_STATS
		privp->mcopy_nb++;
		if (m0 == NULL)
			privp->m_copy_fail++;
#endif
		ng_callout_reset(&neg->timeout_handle,
				 hz * PPPOE_INITIAL_TIMEOUT,
				 pppoe_ticker, hook);
		neg->timeout = PPPOE_INITIAL_TIMEOUT * 2;
		break;

	default:
		log(LOG_ERR, "pppoe: timeout: bad state\n");
	}
	return m0;
}

/*
 * Parse an incoming packet to see if any tags should be copied to the
 * output packet. Don't do any tags that have been handled in the main
 * state machine.
 */
static const struct pppoe_tag*
scan_tags(sessp	sp, const struct pppoe_hdr* ph)
{
	const char *const end = (const char *)next_tag(ph);
	const char *ptn;
	const struct pppoe_tag *pt = PPPOE_HDR_DATA(ph);
	/*
	 * Keep processing tags while a tag header will still fit.
	 */
	while((const char*)(pt + 1) <= end) {
		/*
		 * If the tag data would go past the end of the packet, abort.
		 */
		ptn = (((const char *)(pt + 1)) + ntohs(pt->tag_len));
		if(ptn > end)
			return NULL;

		switch (pt->tag_type) {
		case	PTT_RELAY_SID:
			insert_tag(sp, pt);
			break;
		case	PTT_EOL:
			return NULL;
		case	PTT_SRV_NAME:
		case	PTT_AC_NAME:
		case	PTT_HOST_UNIQ:
		case	PTT_AC_COOKIE:
		case	PTT_VENDOR:
		case	PTT_SRV_ERR:
		case	PTT_SYS_ERR:
		case	PTT_GEN_ERR:
			break;
		}
		pt = (const struct pppoe_tag*)ptn;
	}
	return NULL;
}

/* notification of kernel VNB state machine to mpd
 * => only in kernel VNB
 */
static	struct ng_mesg *
pppoe_send_event(sessp sp, enum cmd cmdid)
{
	struct ng_mesg *msg;
	struct ngpppoe_sts *sts;
	hook_p hook = NULL;
	char * name = NULL;

	if (unlikely(sp == NULL))
		return (NULL);
	if (unlikely(((hook = sp->hook) == NULL) || ((name = hook->name) == NULL)))
		return (NULL);
	NG_MKMESSAGE(msg, NGM_PPPOE_COOKIE, cmdid,
			sizeof(struct ngpppoe_sts), M_NOWAIT);
	if (msg == NULL)
		return (NULL);
	sts = (struct ngpppoe_sts *)msg->data;
	strncpy(sts->hook, name, NG_HOOKLEN + 1);
	if (cmdid == NGM_PPPOE_SUCCESS) {
#ifdef PPPOE_STATS
		priv_p	privp;
		node_p node = NULL;
		if (unlikely(((node = hook->node) == NULL) || ((privp = node->private) == NULL))) {
			FREE(msg, M_NETGRAPH);
			return (NULL);
		}
		privp->success_sent++;
#endif
		/* Add more info from sp: session id from sp->neg->pkt->pkt_header */
		sts->Session_ID = sp->Session_ID;
		memcpy(sts->peer_mac, sp->pkt_hdr.eh.ether_dhost, VNB_ETHER_ADDR_LEN);
		NG_PPPOE_DPRINTF("id %d ul %d \n", sp->Session_ID, sp->ul);
	}
	return (msg);
}
#endif /* !__FastPath__ */

#if defined(__LinuxKernelVNB__)
module_init(ng_pppoe_init);
module_exit(ng_pppoe_exit);
MODULE_AUTHOR("6WIND");
MODULE_DESCRIPTION("VNB PPPoE node");
MODULE_LICENSE("6WIND");
#endif
