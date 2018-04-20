/*
 * Copyright (c) 2006 6WIND
 * $Id: ipsec.c,v 1.69 2010-12-06 16:54:59 gouault Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/syslog.h>
#include <net/if.h>
#if defined(CONFIG_MCORE_IPSEC_TRIE) || defined(CONFIG_MCORE_MULTIBLADE)
#include <event.h>
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
#include <sys/queue.h>
#endif

#include "fpm_common.h"
#include "fpm_plugin.h"
#include "fpm_vrf.h"
#include "fp.h"
#include "netipsec/fp-ah.h"
#include "fpn-crypto-algo.h"

// #define DEBUG 1
#ifdef CONFIG_MCORE_MULTIBLADE
#define MAX_SYNC_MSG_COUNT          4
#define MAX_SYNC_REQUEST_COUNT      5

#define FPM_SA_SYNC_SCHEDULING_S    1
#define FPM_SA_SYNC_SCHEDULING_US   0

typedef struct fpm_sa_sync_node {
	uint32_t     index;
	uint32_t     count;

	LIST_ENTRY(fpm_sa_sync_node) list;
} fpm_sa_sync_node_t;

LIST_HEAD(fpm_sa_sync_pending_list, fpm_sa_sync_node);

/* list of pending IPv4 SA replay sync */
static struct fpm_sa_sync_pending_list sa_sync_pending_list;

/* IPv4 SA replay sync event */
struct event ipsec_sa_sync_evt;

#ifdef CONFIG_MCORE_IPSEC_IPV6
/* list of pending IPv6 SA replay sync */
static struct fpm_sa_sync_pending_list sa6_sync_pending_list;

/* IPv6 SA replay sync event */
struct event ipsec_v6_sa_sync_evt;
#endif
#endif

static uint32_t fpm_sa_genid = 0;
#ifdef CONFIG_MCORE_IPSEC_IPV6
static uint32_t fpm_v6_sa_genid = 0;
#endif

#ifdef CONFIG_MCORE_IPSEC_TRIE
#define SPD_TRIE_OUT_BUILDING_SCHEDULING_S    0
#define SPD_TRIE_OUT_BUILDING_SCHEDULING_US   100000
struct event ipsec_trie_out_build_evt;

#define SPD_TRIE_IN_BUILDING_SCHEDULING_S    0
#define SPD_TRIE_IN_BUILDING_SCHEDULING_US   100000
struct event ipsec_trie_in_build_evt;
#endif /* CONFIG_MCORE_IPSEC_TRIE */


/* store these values no matter if CONFIG_MCORE_IPSEC_LOOKUP_PORTS is defined or not,
 * because they are useful for fps to locate xfrm policy
 */
#define copy_sp_ports_to_filter(sp, f) do {	\
	(f)->srcport = (sp)->sport;		\
	(f)->srcport_mask = (sp)->sportmask;	\
	(f)->dstport = (sp)->dport;		\
	(f)->dstport_mask = (sp)->dportmask;	\
} while(0)

#ifdef CONFIG_MCORE_MULTIBLADE
static fpm_sa_sync_node_t * fpm_sa_sync_node_alloc(uint32_t sa_index)
{
	fpm_sa_sync_node_t *sync_node;

	sync_node = malloc(sizeof(fpm_sa_sync_node_t));
	if (sync_node == NULL) {
		syslog(LOG_ERR, "%s: failed to alloc sync node\n", __FUNCTION__);
		return NULL;
	}

	sync_node->index  = sa_index;
	sync_node->count = 0;

	return sync_node;
}

static int fpm_sa_sync_node_delete(uint32_t sa_index)
{
	fpm_sa_sync_node_t *sync_node;

	/* look up and delete the corresponding node */
	LIST_FOREACH(sync_node, &sa_sync_pending_list, list) {
		if (sync_node->index != sa_index)
			continue;

		LIST_REMOVE(sync_node, list);
		free(sync_node);

		if (LIST_FIRST(&sa_sync_pending_list) == NULL) {
			/* pending list is null, stop sync event*/
			if (!evtimer_pending(&ipsec_sa_sync_evt, NULL))
				evtimer_del(&ipsec_sa_sync_evt);
		}
		return 1;
	}
	syslog(LOG_ERR, "%s: sync node not found\n", __FUNCTION__);
	return 0;
}

static void fpm_sa_sync_timer_cb(int fd, short event, void *arg)
{
	fpm_sa_sync_node_t *sync_node;
	struct timeval tv;
	uint32_t replay[MAX_SYNC_MSG_COUNT];
	int replay_count = 0;
	fp_sad_t *sad = fp_get_sad();
	uint32_t i;

	/* check SA state and send sync request if needed.
	 * remove the synced node from the pending list
	 */
	LIST_FOREACH(sync_node, &sa_sync_pending_list, list) {

		/* remove the sync node if request count exceeds max */
		if (sync_node->count >= MAX_SYNC_REQUEST_COUNT){
			if (f_verbose)
				syslog(LOG_INFO, "%s:SA(index 0x%08d) not sync'd after %d tries,"
				       " give up syncing.\n", __FUNCTION__,
				       ntohl(sync_node->index), sync_node->count);

			LIST_REMOVE(sync_node, list);
			free(sync_node);
			continue;
		}

		/* SA not found or sync received,
		 * remove from the pending_list
		 */
		i = sync_node->index;

		if ((i == 0) || (sad->table[i].sync_state == FP_SA_STATE_SYNC_RECVD)) {
			LIST_REMOVE(sync_node, list);
			free(sync_node);
			continue;
		}

		/* send the netfpc cmd to local Fast Path */
		replay[replay_count] = i;
		sync_node->count ++;

		/* send netfpc msg in group */
		replay_count ++;
		if (replay_count >= MAX_SYNC_MSG_COUNT) {
			netfpc_send(s_nfpc, replay, MAX_SYNC_MSG_COUNT * sizeof(uint32_t),
			            0, NETFPC_MSGTYPE_REPLAYWIN);
			replay_count -= MAX_SYNC_MSG_COUNT;
		}
	}

	/* send the remaining netfpc replay requests */
	if (replay_count) {
		netfpc_send(s_nfpc, replay, replay_count * sizeof(uint32_t),
		            0, NETFPC_MSGTYPE_REPLAYWIN);
	}
	/* don't start sync event if pending list is empty */
	if (LIST_FIRST(&sa_sync_pending_list) == NULL)
		return;
	/* reschedule sync event */
	if (!evtimer_pending(&ipsec_sa_sync_evt, NULL)) {
		tv.tv_sec = FPM_SA_SYNC_SCHEDULING_S;
		tv.tv_usec = FPM_SA_SYNC_SCHEDULING_US;
		evtimer_add(&ipsec_sa_sync_evt, &tv);
	}
}

/* add new sync node into pending list */
static int fpm_add_pendinglist(uint32_t sa_index)
{
	fpm_sa_sync_node_t *sync_node;
	struct timeval tv;

	sync_node = fpm_sa_sync_node_alloc(sa_index);

	if (sync_node == NULL) {
		syslog(LOG_ERR, "\talloc sync node failure\n");
		return -1;
	}
	LIST_INSERT_HEAD(&sa_sync_pending_list, sync_node, list);

	/* start SA sync timer */
	if (!evtimer_pending(&ipsec_sa_sync_evt, NULL)) {
		tv.tv_sec = FPM_SA_SYNC_SCHEDULING_S;
		tv.tv_usec = FPM_SA_SYNC_SCHEDULING_US;
		evtimer_add(&ipsec_sa_sync_evt, &tv);
	}
	return 0;
}

static void fpm_sync_pendinglist_rebuild(void)
{
	int32_t i;
	fp_sa_entry_t sa;
	fp_sad_t *sad = fp_get_sad();

	for (i = FP_MAX_SA_ENTRIES -1 ; i > 0; i--) {
		/* search for not sync'd SAs */
		sa = sad->table[i];
		if (sa.state == FP_SA_STATE_UNSPEC)
			continue;
		if (sa.sync_state == FP_SA_STATE_SYNC_RECVD)
			continue;
		/* insert the SA to the pending list */
		fpm_add_pendinglist(i);
	}

}

#ifdef CONFIG_MCORE_IPSEC_IPV6
static fpm_sa_sync_node_t * fpm_sa_sync_node_alloc6(uint32_t sa_index)
{
	fpm_sa_sync_node_t *sync_node;

	sync_node = malloc(sizeof(fpm_sa_sync_node_t));
	if (sync_node == NULL) {
		syslog(LOG_ERR, "%s:fail to alloc sync node\n", __FUNCTION__);
		return NULL;
	}

	sync_node->index  = sa_index;
	sync_node->count = 0;

        return sync_node;
}

static int fpm_sa_sync_node_delete6(uint32_t sa_index)
{
	fpm_sa_sync_node_t *sync_node;

	/* look up and delete the corresponding node */
	LIST_FOREACH(sync_node, &sa6_sync_pending_list, list) {
		if (sync_node->index != sa_index)
			continue;

		LIST_REMOVE(sync_node, list);
		if (LIST_FIRST(&sa6_sync_pending_list) == NULL) {
			/* pending list is null, stop sync event*/
			if (!evtimer_pending(&ipsec_v6_sa_sync_evt, NULL))
				evtimer_del(&ipsec_v6_sa_sync_evt);
		}

		free(sync_node);
		return 1;
	}
	syslog(LOG_ERR, "%s: sync node not found\n", __FUNCTION__);
        return 0;
}

static void fpm_sa6_sync_timer_cb(int fd, short event, void *arg)
{
	fpm_sa_sync_node_t *sync_node;
	struct timeval tv;
	uint32_t replay[MAX_SYNC_MSG_COUNT];
	int replay_count = 0;
	fp_sad6_t *sad = fp_get_sad6();
	uint32_t i;
	
	/* check and send sync request.
	 * remove the syncd node from the pending list
	 */
	LIST_FOREACH(sync_node, &sa6_sync_pending_list, list) {

		/* remove the sync node if request count exceeds */
		if (sync_node->count >= MAX_SYNC_REQUEST_COUNT) {
			if (f_verbose)
				syslog(LOG_INFO, "%s:SA(index 0x%08d) not sync'd after %d tries,"
						 " give up syncing.\n", __FUNCTION__,
						 ntohl(sync_node->index), sync_node->count);

			LIST_REMOVE(sync_node, list);
			free(sync_node);
			continue;
		}

		/* sa not found or sync recieved
		 * remove from the pending_list
		 */
		i = sync_node->index;
		if (sad->table[i].sync_state == FP_SA_STATE_SYNC_RECVD) {
			LIST_REMOVE(sync_node, list);
			free(sync_node);
			continue;
		}

		/* send the netfpc cmd to local fastpath*/
		replay[replay_count] = i;
		sync_node->count ++;

		/* send netfpc msg in group */
		replay_count ++;
		if (replay_count >= MAX_SYNC_MSG_COUNT) {
			netfpc_send(s_nfpc, replay, MAX_SYNC_MSG_COUNT * sizeof(uint32_t),
						 0, NETFPC_MSGTYPE_REPLAYWIN6);
			replay_count = 0;
		}
	}

	/* send the rest netfpc msg*/
	if (replay_count) {
		netfpc_send(s_nfpc, replay, replay_count * sizeof(uint32_t),
					 0, NETFPC_MSGTYPE_REPLAYWIN6);
	}

	/* don't start sync event if pending list is null */
	if (LIST_FIRST(&sa6_sync_pending_list) == NULL)
		return;
	/* reschedule sync timer */
	if (!evtimer_pending(&ipsec_v6_sa_sync_evt, NULL)) {
		tv.tv_sec = FPM_SA_SYNC_SCHEDULING_S;
		tv.tv_usec = FPM_SA_SYNC_SCHEDULING_US;
		evtimer_add(&ipsec_v6_sa_sync_evt, &tv);
	}
}

/* add new sync node into pending list */
static int fpm_add_pendinglist6(uint32_t sa_index)
{
	fpm_sa_sync_node_t *sync_node;
	struct timeval tv;

	sync_node = fpm_sa_sync_node_alloc6(sa_index);

	if (sync_node == NULL) {
		syslog(LOG_ERR, "\talloc sync node failure\n");
		return -1;
	}

	LIST_INSERT_HEAD(&sa6_sync_pending_list, sync_node, list);

	/* start sa sync timer */
	if (!evtimer_pending(&ipsec_v6_sa_sync_evt, NULL)) {
		tv.tv_sec = FPM_SA_SYNC_SCHEDULING_S;
		tv.tv_usec = FPM_SA_SYNC_SCHEDULING_US;
		evtimer_add(&ipsec_v6_sa_sync_evt, &tv);
	}
	return 0;
}

static void fpm_sync_pendinglist6_rebuild(void)
{
	int32_t i;
	fp_v6_sa_entry_t sa;

	for (i = FP_MAX_IPV6_SA_ENTRIES -1 ; i > 0; i--) {
		/* search for not sync'd SAs */
		sa = fp_get_sad6()->table[i];
		if (sa.state == FP_SA_STATE_UNSPEC)
			continue;
		if (sa.sync_state == FP_SA_STATE_SYNC_RECVD)
			continue;
		/* insert the SA to the pending list */
		fpm_add_pendinglist6(i);
	}
}
#endif /* CONFIG_MCORE_IPSEC_IPV6 */
#endif /* CONFIG_MCORE_MULTIBLADE */

#ifdef CONFIG_MCORE_IPSEC_TRIE
static void fp_ipsec_trie_out_build_timer_cb(int fd, short event, void *arg)
{
	fp_spd_trie_out_commit();
}

static void fp_ipsec_trie_in_build_timer_cb(int fd, short event, void *arg)
{
	fp_spd_trie_in_commit();
}
#endif	/* CONFIG_MCORE_IPSEC_TRIE */

static int fpm_ipsec_sa_create(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_ipsec_sa_add *sa = (struct cp_ipsec_sa_add *)request;
	fp_sa_entry_t user_sa;
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_v6_sa_entry_t user_sa6;
#endif
#ifdef CONFIG_MCORE_MULTIBLADE
	int err;
#endif
	uint8_t ealgo = FP_EALGO_NULL, aalgo = FP_AALGO_NULL;
	uint16_t akeylen;
	uint16_t ekeylen;
	uint32_t flags;
	int sa_index = -1;
	uint16_t ahsize = 0;
	uint16_t *sa_state = NULL;

	if (f_verbose) {
		syslog(LOG_INFO, "fpm_ipsec_sa_create:\n");
		if (sa->family == AF_INET)
			syslog(LOG_DEBUG, "\tproto=%s vr=%d spi=0x%08x dst=%u.%u.%u.%u "
			       "src=%u.%u.%u.%u sport=%d dport=%d reqid=%u xvr=%d svti=0x%08x\n"
			       "\tekeylen=%d ealgo=%d akeylen=%d aalgo=%d\n",
			       sa->proto == IPPROTO_AH ? "ah" : "esp",
			       ntohl(sa->vrfid), ntohl(sa->spi), FP_NIPQUAD(sa->daddr),
			       FP_NIPQUAD(sa->saddr), ntohs(sa->sport), ntohs(sa->dport),
			       ntohl(sa->reqid), ntohl(sa->xvrfid), ntohl(sa->svti_ifuid),
			       ntohs(sa->ekeylen), sa->ealgo, ntohs(sa->akeylen), sa->aalgo);

#ifdef CONFIG_MCORE_IPSEC_IPV6
		if (sa->family == AF_INET6)
			syslog(LOG_DEBUG, "\tproto=%s vr=%d spi=0x%08x dst="FP_NIP6_FMT" "
			       "src="FP_NIP6_FMT" sport=%d dport=%d reqid=%u xvr=%d svti=0x%08x\n"
			       "\tekeylen=%d ealgo=%d akeylen=%d aalgo=%d\n",
			       sa->proto == IPPROTO_AH ? "ah" : "esp",
			       ntohl(sa->vrfid), ntohl(sa->spi), NIP6(sa->daddr.addr6),
			       NIP6(sa->saddr.addr6), ntohs(sa->sport), ntohs(sa->dport),
			       ntohl(sa->reqid), ntohl(sa->xvrfid), ntohl(sa->svti_ifuid),
			       ntohs(sa->ekeylen), sa->ealgo, ntohs(sa->akeylen), sa->aalgo);
#endif  /* CONFIG_MCORE_IPSEC_IPV6 */
	}

	if ((ntohl(sa->vrfid) & FP_VRFID_MASK) >= FP_MAX_VR ||
	    (ntohl(sa->xvrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "\tinvalid vrfid\n");
		return EXIT_FAILURE;
	}

	/* check supported features */
	if (sa->family != AF_INET
#ifdef CONFIG_MCORE_IPSEC_IPV6
            && sa->family != AF_INET6
#endif
            ) {
		syslog(LOG_ERR, "\tunhandled address family\n");
		return EXIT_FAILURE;
	}

	akeylen = ntohs(sa->akeylen);
	ekeylen = ntohs(sa->ekeylen);

	if (ekeylen) {
		if (ekeylen > FP_MAX_KEY_ENC_LENGTH) {
			syslog(LOG_ERR, "\tkey size too big %d>%d\n", ekeylen, FP_MAX_KEY_ENC_LENGTH);
			return EXIT_FAILURE;
		}

		switch(sa->ealgo) {
		case CM_IPSEC_EALG_NONE:
			ealgo = FP_EALGO_NULL;
			break;
		case CM_IPSEC_EALG_DESCBC:
			ealgo = FP_EALGO_DESCBC;
			break;
		case CM_IPSEC_EALG_3DESCBC:
			ealgo = FP_EALGO_3DESCBC;
			break;
		case CM_IPSEC_EALG_AESCBC:
			ealgo = FP_EALGO_AESCBC;
			break;
		case CM_IPSEC_EALG_AESGCM:
			ealgo = FP_EALGO_AESGCM;
			break;
		case CM_IPSEC_EALG_NULL_AESGMAC:
			ealgo = FP_EALGO_NULL_AESGMAC;
			break;
		default:
			syslog(LOG_ERR, "\tunhandled encryption algo\n");
			return EXIT_FAILURE;
		}
	}
	if (akeylen) {
		if (akeylen > FP_MAX_KEY_AUTH_LENGTH) {
			syslog(LOG_ERR, "\tauth key size too big %d>%d\n", akeylen, FP_MAX_KEY_AUTH_LENGTH);
			return EXIT_FAILURE;
		}

		switch (sa->aalgo) {
		case CM_IPSEC_AALG_NONE:
			aalgo = FP_AALGO_NULL;
			break;
		case CM_IPSEC_AALG_MD5HMAC:
			aalgo = FP_AALGO_HMACMD5;
			break;
		case CM_IPSEC_AALG_SHA1HMAC:
			aalgo = FP_AALGO_HMACSHA1;
			break;
		case CM_IPSEC_AALG_AES_XCBC_MAC:
			aalgo = FP_AALGO_AESXCBC;
			break;
		case CM_IPSEC_AALG_SHA2_256HMAC:
			aalgo = FP_AALGO_HMACSHA256;
			break;
		case CM_IPSEC_AALG_SHA2_384HMAC:
			aalgo = FP_AALGO_HMACSHA384;
			break;
		case CM_IPSEC_AALG_SHA2_512HMAC:
			aalgo = FP_AALGO_HMACSHA512;
			break;
		default:
			syslog(LOG_ERR, "\tunhandled auth algo\n");
			return EXIT_FAILURE;
		}
		if (aalgo != FP_AALGO_NULL)
			ahsize = sizeof(struct fp_ah) + fp_get_sa_ah_algo(aalgo)->authsize;
	}

	/* during graceful restart, rules are added a second time */
	if (fpm_graceful_restart_in_progress) {
		if ((sa->family == AF_INET &&
		     (__fp_sa_get(fp_get_sad(), sa->spi, sa->daddr.addr4.s_addr, sa->proto, ntohl(sa->vrfid)) != 0))
#ifdef CONFIG_MCORE_IPSEC_IPV6
		    ||
		    (sa->family == AF_INET6 &&
		     (__fp_v6_sa_get(fp_get_sad6(), sa->spi, (uint8_t *)&sa->daddr.addr6, sa->proto, ntohl(sa->vrfid)) != 0))
#endif
		   ) {
			syslog(LOG_ERR, "\nSA already exists\n");
			return EXIT_FAILURE;
		}
	}

	flags = ntohl(sa->flags);
	if (sa->family == AF_INET) {
		uint32_t acq_index;
		fp_sad_t *sad = fp_get_sad();

		memset(&user_sa, 0, sizeof(fp_sa_entry_t));
		user_sa.spi = sa->spi;
		user_sa.dst4 = sa->daddr.addr4.s_addr;
		user_sa.src4 = sa->saddr.addr4.s_addr;
		user_sa.proto = sa->proto;
		user_sa.mode = sa->mode == CM_IPSEC_MODE_TUNNEL ? FP_IPSEC_MODE_TUNNEL : FP_IPSEC_MODE_TRANSPORT;
		user_sa.reqid = ntohl(sa->reqid);
		user_sa.vrfid = ntohl(sa->vrfid) & FP_VRFID_MASK;
		user_sa.xvrfid = ntohl(sa->xvrfid) & FP_VRFID_MASK;
		if (sa->output_blade)
			user_sa.output_blade = sa->output_blade;
		else
			user_sa.output_blade = fp_shared->ipsec.output_blade;
		user_sa.svti_ifuid = sa->svti_ifuid;
		user_sa.alg_auth = aalgo;
		user_sa.alg_enc = ealgo;
		if (ealgo == FP_EALGO_NULL && aalgo != FP_AALGO_NULL)
		{
			user_sa.ahsize = FPM_ALIGN4(ahsize);
			user_sa.ah_len = (user_sa.ahsize >> 2) - 2;
		}
		{
			uint8_t *keys = sa->keys;

			if (ekeylen) {
				memcpy(user_sa.key_enc, keys, ekeylen);
				user_sa.key_enc_len = ekeylen;
				keys += ekeylen;
			}
			if (akeylen) {
				memcpy(user_sa.key_auth, keys, akeylen);
				/* FP assumes the key is padded with 0. */
				if (akeylen < FP_MAX_KEY_AUTH_LENGTH)
					memset(user_sa.key_auth + akeylen, 0,
					       FP_MAX_KEY_AUTH_LENGTH - akeylen);
			}
		}
#ifdef CONFIG_MCORE_MULTIBLADE
		user_sa.sync_state = FP_SA_STATE_NOT_SYNCD;
#endif
		/* ignore reqid, calgo, flags */

		if (sa->dport && sa->sport) {
			user_sa.flags |= FP_SA_FLAG_UDPTUNNEL;
			user_sa.dport = sa->dport;
			user_sa.sport = sa->sport;
		}
		if (flags & CM_SA_FLAG_DONT_ENCAPDSCP)
			user_sa.flags |= FP_SA_FLAG_DONT_ENCAPDSCP;
		if (flags & CM_SA_FLAG_DECAPDSCP)
			user_sa.flags |= FP_SA_FLAG_DECAPDSCP;
		if (flags & CM_SA_FLAG_NOPMTUDISC)
			user_sa.flags |= FP_SA_FLAG_NOPMTUDISC;
		if (flags & CM_SA_FLAG_ESN)
			user_sa.flags |= FP_SA_FLAG_ESN;

		user_sa.replay.seq = ntohll(sa->seq);
		user_sa.replay.oseq = ntohll(sa->oseq);
		user_sa.replay.wsize = ntohl(sa->replay);
		if (user_sa.replay.wsize > FP_SECREPLAY_ESN_MAX) {
			syslog(LOG_ERR, "\tSA anti-replay window cannot be larger than %u\n",
			       FP_SECREPLAY_ESN_MAX);
			return EXIT_FAILURE;
		}

		if (++fpm_sa_genid == 0)
			++fpm_sa_genid;

		user_sa.genid = fpm_sa_genid;

		/* delete a possibly existing temporary SA (with state ACQUIRE) */
		acq_index = fp_sad_find_acq(user_sa.src4, user_sa.dst4, user_sa.proto,
				user_sa.mode, user_sa.reqid,
				user_sa.vrfid, user_sa.xvrfid
#ifdef CONFIG_MCORE_IPSEC_SVTI
				, sa->svti_ifuid
#endif
				);

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
		/* Set default values */
		user_sa.soft.nb_bytes   = FP_SA_LIMIT_INF;
		user_sa.soft.nb_packets = FP_SA_LIMIT_INF;
		user_sa.hard.nb_bytes   = FP_SA_LIMIT_INF;
		user_sa.hard.nb_packets = FP_SA_LIMIT_INF;
#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */

		sa_index = fp_sa_add(sad, &user_sa);

		if (acq_index) {
			fp_sa_del_by_index(sad, acq_index);
			if (f_verbose)
				syslog(LOG_DEBUG, "\tremove temporary SA\n");
		}

		if (sa_index < 0) {
			syslog(LOG_ERR, "\tadd SA failure\n");
			return EXIT_FAILURE;
		}
#ifdef CONFIG_MCORE_MULTIBLADE
		err = fpm_add_pendinglist(sa_index);
		if (err < 0) {
			syslog(LOG_ERR, "\tadd pending list failure\n");
			return EXIT_FAILURE;
		}
#endif
		sa_state = &sad->table[sa_index].state;
	}

#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (sa->family == AF_INET6) {
		uint32_t acq_index;
		fp_sad6_t *sad6 = fp_get_sad6();

		memset(&user_sa6, 0, sizeof(fp_v6_sa_entry_t));
		user_sa6.spi = sa->spi;
		memcpy(user_sa6.dst6.fp_s6_addr, sa->daddr.addr6.s6_addr, sizeof(fp_in6_addr_t));
		memcpy(user_sa6.src6.fp_s6_addr, sa->saddr.addr6.s6_addr, sizeof(fp_in6_addr_t));
		user_sa6.proto = sa->proto;
		user_sa6.mode = sa->mode == CM_IPSEC_MODE_TUNNEL ? FP_IPSEC_MODE_TUNNEL : FP_IPSEC_MODE_TRANSPORT;
		user_sa6.reqid = ntohl(sa->reqid);
		user_sa6.vrfid = ntohl(sa->vrfid) & FP_VRFID_MASK;
		user_sa6.xvrfid = ntohl(sa->xvrfid) & FP_VRFID_MASK;
		if (sa->output_blade)
			user_sa6.output_blade = sa->output_blade;
		else
			user_sa6.output_blade = fp_shared->ipsec6.output_blade;
		user_sa6.svti_ifuid = sa->svti_ifuid;
		user_sa6.alg_auth = aalgo;
		user_sa6.alg_enc = ealgo;
		if (ealgo == FP_EALGO_NULL && aalgo != FP_AALGO_NULL)
		{
			user_sa6.ahsize = FPM_ALIGN8(ahsize);
			user_sa6.ah_len = (user_sa6.ahsize >> 2) - 2;
		}
		{
			uint8_t *keys = sa->keys;

			if (ekeylen) {
				memcpy(user_sa6.key_enc, keys, ekeylen);
				user_sa6.key_enc_len = ekeylen;
				keys += ekeylen;
			}
			if (akeylen) {
				memcpy(user_sa6.key_auth, keys, akeylen);
				/* FP assumes the key is padded with 0. */
				if (akeylen < FP_MAX_KEY_AUTH_LENGTH)
					memset(user_sa6.key_auth + akeylen, 0,
					       FP_MAX_KEY_AUTH_LENGTH - akeylen);
			}
		}
#ifdef CONFIG_MCORE_MULTIBLADE
		user_sa6.sync_state = FP_SA_STATE_NOT_SYNCD;
#endif
		/* ignore reqid, calgo, flags */

		if (sa->dport && sa->sport) {
			user_sa6.flags |= FP_SA_FLAG_UDPTUNNEL;
			user_sa6.dport = sa->dport;
			user_sa6.sport = sa->sport;
		}
		if (flags & CM_SA_FLAG_DONT_ENCAPDSCP)
			user_sa6.flags |= FP_SA_FLAG_DONT_ENCAPDSCP;
		if (flags & CM_SA_FLAG_DECAPDSCP)
			user_sa6.flags |= FP_SA_FLAG_DECAPDSCP;
		if (flags & CM_SA_FLAG_ESN)
			user_sa6.flags |= FP_SA_FLAG_ESN;

		user_sa6.replay.seq = ntohll(sa->seq);
		user_sa6.replay.oseq = ntohll(sa->oseq);
		user_sa6.replay.wsize = ntohl(sa->replay);
		if (user_sa6.replay.wsize > FP_SECREPLAY_ESN_MAX) {
			syslog(LOG_ERR, "\tSA anti-replay window cannot be larger than %u\n",
			       FP_SECREPLAY_ESN_MAX);
			return EXIT_FAILURE;
		}

		if (++fpm_v6_sa_genid == 0)
			++fpm_v6_sa_genid;

		user_sa6.genid = fpm_v6_sa_genid;

		/* delete a possibly existing temporary SA (with state ACQUIRE) */
		acq_index = fp_sad6_find_acq(&user_sa6.src6,
				&user_sa6.dst6, user_sa6.proto,
				user_sa6.mode, user_sa6.reqid,
				user_sa6.vrfid, user_sa6.xvrfid
#ifdef CONFIG_MCORE_IPSEC_SVTI
				, user_sa6.svti_ifuid
#endif
				);

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
		/* Set default values */
		user_sa6.soft.nb_bytes   = FP_SA_LIMIT_INF;
		user_sa6.soft.nb_packets = FP_SA_LIMIT_INF;
		user_sa6.hard.nb_bytes   = FP_SA_LIMIT_INF;
		user_sa6.hard.nb_packets = FP_SA_LIMIT_INF;
#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */

		sa_index = fp_v6_sa_add(sad6, &user_sa6);

		if (acq_index) {
			fp_v6_sa_del_by_index(sad6, acq_index);
			if (f_verbose)
				syslog(LOG_DEBUG, "\tremove temporary SA\n");
		}

		if (sa_index < 0) {
			syslog(LOG_ERR, "\tadd IPv6 SA failure\n");
			return EXIT_FAILURE;
		}
#ifdef CONFIG_MCORE_MULTIBLADE
		err = fpm_add_pendinglist6(sa_index);
		if (err < 0) {
			syslog(LOG_ERR, "\tadd pending list failure\n");
			return EXIT_FAILURE;
		}
#endif
		sa_state = &sad6->table[sa_index].state;
	}
#endif  /* CONFIG_MCORE_IPSEC_IPV6 */

	if (sa_state != NULL) {
		if (sa->spi == 0) {
			*sa_state = FP_SA_STATE_ACQUIRE;
		} else {
			*sa_state = FP_SA_STATE_ACTIVE;
		}
	}

	syslog(LOG_INFO, "\tadd SA success\n");
	return EXIT_SUCCESS;
}

static int fpm_ipsec_sa_delete(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_ipsec_sa_del *sa = (struct cp_ipsec_sa_del *)request;
	fp_sa_entry_t user_sa;
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_v6_sa_entry_t user_sa6;
#endif
	int sa_index = -1;

	if (f_verbose) {
		syslog(LOG_INFO, "fpm_ipsec_sa_delete:\n");
		if (sa->family == AF_INET)
			syslog(LOG_DEBUG, "\tvr=%d proto=%s spi=0x%08x dst=%u.%u.%u.%u state=%d\n",
			       ntohl(sa->vrfid), sa->proto == IPPROTO_AH ? "ah" : "esp",
			       ntohl(sa->spi), FP_NIPQUAD(sa->daddr), sa->state);
#ifdef CONFIG_MCORE_IPSEC_IPV6
		if (sa->family == AF_INET6)
			syslog(LOG_DEBUG, "\tvr=%d proto=%s spi=0x%08x dst="FP_NIP6_FMT" state=%d\n",
			       ntohl(sa->vrfid), sa->proto == IPPROTO_AH ? "ah" : "esp",
			       ntohl(sa->spi), NIP6(sa->daddr.addr6), sa->state);
#endif
	}

	if ((ntohl(sa->vrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "\tinvalid vrfid\n");
		return EXIT_FAILURE;
	}

	/* check supported features */
	if (sa->family != AF_INET
#ifdef CONFIG_MCORE_IPSEC_IPV6
	    && sa->family != AF_INET6
#endif
	   ) {
		syslog(LOG_ERR, "\tunhandled address family\n");
		return EXIT_FAILURE;
	}

	if (sa->state == CM_IPSEC_STATE_DYING)
		return EXIT_SUCCESS; /* do nothing, wait for DEAD SA */

	if (sa->family == AF_INET) {
		memset(&user_sa, 0, sizeof(fp_sa_entry_t));
		user_sa.spi = sa->spi;
		user_sa.dst4 = sa->daddr.addr4.s_addr;
		user_sa.proto = sa->proto;
		user_sa.vrfid = ntohl(sa->vrfid) & FP_VRFID_MASK;

		sa_index = fp_sa_del(fp_get_sad(), &user_sa);
#ifdef CONFIG_MCORE_MULTIBLADE
		fpm_sa_sync_node_delete(sa_index);
#endif
	}
#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (sa->family == AF_INET6) {
		memset(&user_sa6, 0, sizeof(fp_v6_sa_entry_t));
		user_sa6.spi = sa->spi;
		memcpy(user_sa6.dst6.fp_s6_addr, sa->daddr.addr6.s6_addr, sizeof(fp_in6_addr_t));
		user_sa6.proto = sa->proto;
		user_sa6.vrfid = ntohl(sa->vrfid) & FP_VRFID_MASK;
		sa_index = fp_v6_sa_del(fp_get_sad6(), &user_sa6);
#ifdef CONFIG_MCORE_MULTIBLADE
		fpm_sa_sync_node_delete6(sa_index);
#endif
	}
#endif

	if (sa_index < 0) {
		syslog(LOG_ERR, "\tdel SA failure\n");
		return EXIT_FAILURE;
	}

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT

	/* Unset SA FP_SA_FLAG_LIFETIME flag */
	if (sa->family == AF_INET) {
		fp_sad_t *sad = fp_get_sad();
		fp_sa_entry_t *sa_entry = &sad->table[sa_index];

		if (sa_entry->flags & FP_SA_FLAG_LIFETIME) {
			/* Reset flag */
			sa_entry->flags &= ~FP_SA_FLAG_LIFETIME;
		}
	}
#ifdef CONFIG_MCORE_IPSEC_IPV6
	/* Unset SA FP_SA_FLAG_LIFETIME flag */
	if (sa->family == AF_INET6) {
		fp_sad6_t *sad6 = fp_get_sad6();
		fp_v6_sa_entry_t *sa6_entry = &sad6->table[sa_index];

		if (sa6_entry->flags & FP_SA_FLAG_LIFETIME) {
			/* Reset flag */
			sa6_entry->flags &= ~FP_SA_FLAG_LIFETIME;
		}
	}

#endif /* CONFIG_MCORE_IPSEC_IPV6 */

#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */

	/* Release index now to be sure that it can not be re allocated before
	   calls to netfpc */
	if (sa->family == AF_INET) {
		fp_sa_release_index(sa_index);
	}

#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (sa->family == AF_INET6) {
   		fp_v6_sa_release_index(sa_index);
	}
#endif

	if (f_verbose)
		syslog(LOG_INFO, "\tdel SA success\n");
	return EXIT_SUCCESS;
}

static int fpm_ipsec_sa_flush(const uint8_t *request, const struct cp_hdr *hdr)
{
	uint32_t *vrfid = (uint32_t *)request;
#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
	fp_sad_t *sad = fp_get_sad();
	fp_sa_entry_t *sa_entry;
	uint32_t i;
#endif
	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_ipsec_sa_flush: vr=%d\n", ntohl(*vrfid));

	if ((ntohl(*vrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "\tinvalid vrfid\n");
		return EXIT_FAILURE;
	}

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
	/* Unset SA FP_SA_FLAG_LIFETIME flag */
	for (i = 1; i < FP_MAX_SA_ENTRIES; i++) {
		sa_entry = &sad->table[i];

		if ((sa_entry->state == FP_SA_STATE_ACTIVE) &&
			(sa_entry->vrfid == *vrfid) &&
			(sa_entry->flags & FP_SA_FLAG_LIFETIME)) {
			/* Reset flag */
			sa_entry->flags &= ~FP_SA_FLAG_LIFETIME;
		}
	}

#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_sad6_t *sad6 = fp_get_sad6();
	fp_v6_sa_entry_t *sa6_entry;

	/* Unset SA FP_SA_FLAG_LIFETIME flag */
	for (i = 1; i < FP_MAX_IPV6_SA_ENTRIES; i++) {
		sa6_entry = &sad6->table[i];

		if ((sa6_entry->state == FP_SA_STATE_ACTIVE) &&
			(sa6_entry->vrfid == *vrfid) &&
			(sa6_entry->flags & FP_SA_FLAG_LIFETIME)) {
			/* Reset flag */
			sa6_entry->flags &= ~FP_SA_FLAG_LIFETIME;
		}
	}
#endif /* CONFIG_MCORE_IPSEC_IPV6 */

#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */

	fp_sa_flush_by_vrfid(fp_get_sad(), ntohl(*vrfid) & FP_VRFID_MASK);
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_v6_sa_flush_by_vrfid(fp_get_sad6(), ntohl(*vrfid) & FP_VRFID_MASK);
#endif

	return EXIT_SUCCESS;
}

#ifdef CONFIG_MCORE_MULTIBLADE
static int fp_sa_migrate(uint16_t vrfid, fp_sa_entry_t *user_sa, uint32_t gap, uint8_t output_blade) 
{
	fp_sad_t *sad;
	uint32_t i;

	sad = fp_get_sad();

	i = __fp_sa_get(sad, user_sa->spi, user_sa->dst4, user_sa->proto, vrfid);

	if (i == 0) {
		syslog(LOG_ERR, "%s: SA not found\n", __FUNCTION__);
		return -1; /* not found */
	}

	/* XXX: we should use netfpc messages to update these data */
	/* if the SA migrates to my blade id, and if the blade id changes, apply the GAP */
	if ((output_blade == fp_shared->fp_blade_id) &&
	    (sad->table[i].output_blade != output_blade))
		sad->table[i].replay.oseq += gap;

	sad->table[i].output_blade = output_blade;

	return 0;
}

static int fp_sa_bulk_migrate(uint8_t mig_type, uint8_t output_blade,
			      uint32_t gap, char data[128]) 
{
	fp_sad_t *sad = NULL;
	uint32_t i = 0;

	if (mig_type == CM_BULK_MIGRATE_BY_BLADE_ID) {
		uint8_t src_blade_id = data[0];

		sad = &fp_shared->ipsec.sad;
		if (!sad) {
			return 0;
		}
		for (i = 1; i < FP_MAX_SA_ENTRIES; i++) {
			if (sad->table[i].output_blade == src_blade_id) {
				/* XXX: we should use netfpc messages to update these data */
				/* if the SA migrates to my blade id, and if the blade id changes, apply the GAP */
				if (output_blade == fp_shared->fp_blade_id) {
					sad->table[i].replay.oseq += gap;
				}
				sad->table[i].output_blade = output_blade;
			}
		}
	}

	return 0;
}


#ifdef CONFIG_MCORE_IPSEC_IPV6
static int fp_v6_sa_migrate(uint16_t vrfid, fp_v6_sa_entry_t *user_sa, uint32_t gap, uint8_t output_blade)
{
	fp_sad6_t *sad6;
	uint32_t i;

	sad6 = fp_get_sad6();

	i = __fp_v6_sa_get(sad6, user_sa->spi, user_sa->dst6.fp_s6_addr, user_sa->proto, vrfid);

	if (i == 0) {
		syslog(LOG_ERR, "%s: SA not found\n", __FUNCTION__);
		return -1; /* not found */
	}

	/* XXX: we should use netfpc messages to update these data */
	/* if the SA migrates to my blade id, and if the blade id changes, apply the GAP */
	if ((output_blade == fp_shared->fp_blade_id) &&
	    (sad6->table[i].output_blade != output_blade))
		sad6->table[i].replay.oseq += gap;

	sad6->table[i].output_blade = output_blade;

	return 0;
}

static int fp_v6_sa_bulk_migrate(uint8_t mig_type, uint8_t output_blade,
			      uint32_t gap, char data[128])
{
	fp_sad6_t *sad6 = NULL;
	uint32_t i = 0;

	if (mig_type == CM_BULK_MIGRATE_BY_BLADE_ID) {
		uint8_t src_blade_id = data[0];

		sad6 = fp_get_sad6();
		if (!sad6) {
			return 0;
		}
		for (i = 1; i < FP_MAX_IPV6_SA_ENTRIES; i++) {
			if (sad6->table[i].output_blade == src_blade_id) {
				/* XXX: we should use netfpc messages to update these data */
				/* if the SA migrates to my blade id, and if the blade id changes, apply the GAP */
				if (output_blade == fp_shared->fp_blade_id) {
					sad6->table[i].replay.oseq += gap;
				}
				sad6->table[i].output_blade = output_blade;
			}
		}
	}

	return 0;
}
#endif  /* CONFIG_MCORE_IPSEC_IPV6 */
#endif  /* CONFIG_MCORE_MULTIBLADE */

#ifdef CONFIG_MCORE_MULTIBLADE
static int
fpm_ipsec_sa_migrate(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_ipsec_sa_migrate *sa = (struct cp_ipsec_sa_migrate *)request;
	fp_sa_entry_t user_sa;
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_v6_sa_entry_t user_sa6;
#endif
	int err = -1;

	if (f_verbose) {
		syslog(LOG_INFO, "fpm_ipsec_sa_migrate:\n");
		if (sa->family == AF_INET)
			syslog(LOG_DEBUG, "\tvr=%d proto=%s spi=0x%08x dst=%u.%u.%u.%u "
			       "outputblade=%u gap=%d\n",
			       ntohl(sa->vrfid), sa->proto == IPPROTO_AH ? "ah" : "esp",
			       ntohl(sa->spi), FP_NIPQUAD(sa->daddr), sa->output_blade,
			       htonl(sa->gap));
#ifdef CONFIG_MCORE_IPSEC_IPV6
		if (sa->family == AF_INET6)
			syslog(LOG_DEBUG, "\tvr=%d proto=%s spi=0x%08x dst="FP_NIP6_FMT" "
			       "outputblade=%u gap=%d\n",
			       ntohl(sa->vrfid), sa->proto == IPPROTO_AH ? "ah" : "esp",
			       ntohl(sa->spi), NIP6(sa->daddr.addr6), sa->output_blade,
			       htonl(sa->gap));
#endif
	}

	if ((ntohl(sa->vrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "\tinvalid vrfid\n");
		return EXIT_FAILURE;
	}

	/* check supported features */
	if (sa->family != AF_INET
#ifdef CONFIG_MCORE_IPSEC_IPV6
	    && sa->family != AF_INET6
#endif
	   ) {
		syslog(LOG_ERR, "\tunhandled address family\n");
		return EXIT_FAILURE;
	}


	if (sa->family == AF_INET) {
		memset(&user_sa, 0, sizeof(fp_sa_entry_t));
		user_sa.spi = sa->spi;
		user_sa.dst4 = sa->daddr.addr4.s_addr;
		user_sa.proto = sa->proto;
		user_sa.vrfid = ntohl(sa->vrfid) & FP_VRFID_MASK;

		err = fp_sa_migrate((uint16_t)(ntohl(sa->vrfid) & FP_VRFID_MASK),
				&user_sa, ntohl(sa->gap), sa->output_blade);
	}

#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (sa->family == AF_INET6) {
		memset(&user_sa6, 0, sizeof(fp_v6_sa_entry_t));
		user_sa6.spi = sa->spi;
		memcpy(user_sa6.dst6.fp_s6_addr, sa->daddr.addr6.s6_addr, sizeof(fp_in6_addr_t));
		user_sa6.proto = sa->proto;
		user_sa6.vrfid = ntohl(sa->vrfid) & FP_VRFID_MASK;

		err = fp_v6_sa_migrate((uint16_t)(ntohl(sa->vrfid) & FP_VRFID_MASK),
				&user_sa6, ntohl(sa->gap), sa->output_blade);
	}
#endif

	if (err < 0) {
		syslog(LOG_ERR, "\tSA migration failure\n");
		return EXIT_FAILURE;
	}

	if (f_verbose)
		syslog(LOG_INFO, "\tSA migration success\n");
	return EXIT_SUCCESS;
}

static int
fpm_ipsec_sa_bulk_migrate(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_ipsec_sa_bulk_migrate *sa =
		(struct cp_ipsec_sa_bulk_migrate *)request;
	int err;

	if (f_verbose) {
		syslog(LOG_INFO, "fpm_ipsec_sa_bulk_migrate:\n");
		syslog(LOG_DEBUG, "\tmig_type=%d outputblade=%d gap=%d data=%d\n",
		       sa->mig_type, sa->dst_output_blade, ntohl(sa->gap),
		       sa->data[0]);
	}

	err = fp_sa_bulk_migrate(sa->mig_type, sa->dst_output_blade,
	                         ntohl(sa->gap), sa->data);

	if (err < 0) {
		syslog(LOG_ERR, "\tBulk SA migration failure\n");
		return EXIT_FAILURE;
	}

#ifdef CONFIG_MCORE_IPSEC_IPV6
	err = fp_v6_sa_bulk_migrate(sa->mig_type, sa->dst_output_blade,
	                         ntohl(sa->gap), sa->data);

	if (err < 0) {
		syslog(LOG_ERR, "\tBulk IPv6 SA migration failure\n");
		return EXIT_FAILURE;
	}
#endif

	if (f_verbose)
		syslog(LOG_INFO, "\tBulk SA migration success\n");
	return EXIT_SUCCESS;
}
#endif

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
static int fpm_ipsec_sa_lifetime(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_ipsec_sa_lifetime *sa = (struct cp_ipsec_sa_lifetime *)request;
	uint32_t sa_index = 0;

	syslog(LOG_INFO, "fpm_ipsec_sa_lifetime:\n");
	if (sa->family == AF_INET)
		syslog(LOG_DEBUG, "\tvr=%d proto=%s spi=0x%08x dst=%u.%u.%u.%u",
		       ntohl(sa->vrfid), sa->proto == IPPROTO_AH ? "ah" : "esp",
		       ntohl(sa->spi), FP_NIPQUAD(sa->daddr));
#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (sa->family == AF_INET6)
		syslog(LOG_DEBUG, "\tvr=%d proto=%s spi=0x%08x dst="FP_NIP6_FMT,
		       ntohl(sa->vrfid), sa->proto == IPPROTO_AH ? "ah" : "esp",
		       ntohl(sa->spi), NIP6(sa->daddr.addr6));
#endif
	syslog(LOG_DEBUG, "\tsoft : bytes=%"PRIu64" packets=%"PRIu64"\n",
		   ntohll(sa->soft.nb_bytes), ntohll(sa->soft.nb_packets));
	syslog(LOG_DEBUG, "\thard : bytes=%"PRIu64" packets=%"PRIu64"\n",
		   ntohll(sa->hard.nb_bytes), ntohll(sa->hard.nb_packets));

	if (sa->family == AF_INET) {
		fp_sad_t *sad  = fp_get_sad();

		sa_index = __fp_sa_get(sad, sa->spi,
		                       sa->daddr.addr4.s_addr,
		                       sa->proto, ntohl(sa->vrfid));

		if (sa_index <= 0) {
			syslog(LOG_ERR, "%s: SA not found\n", __FUNCTION__);
			return EXIT_FAILURE; /* not found */
		}

		fp_sa_entry_t * sa_entry = &sad->table[sa_index];

		/* Set new values */
		sa_entry->soft.nb_bytes   = ntohll(sa->soft.nb_bytes);
		sa_entry->soft.nb_packets = ntohll(sa->soft.nb_packets);
		sa_entry->hard.nb_bytes   = ntohll(sa->hard.nb_bytes);
		sa_entry->hard.nb_packets = ntohll(sa->hard.nb_packets);

		/* If no limit given, it is an unlink request */
		if ((sa_entry->soft.nb_bytes   == FP_SA_LIMIT_INF) &&
		    (sa_entry->soft.nb_packets == FP_SA_LIMIT_INF) &&
		    (sa_entry->hard.nb_bytes   == FP_SA_LIMIT_INF) &&
		    (sa_entry->hard.nb_packets == FP_SA_LIMIT_INF)) {
			if (sa_entry->flags & FP_SA_FLAG_LIFETIME) {
				/* Reset flag */
				sa_entry->flags &= ~FP_SA_FLAG_LIFETIME;
			}
		} else {
			if (!(sa_entry->flags & FP_SA_FLAG_LIFETIME)) {
				/* Set flag */
				sa_entry->flags |= FP_SA_FLAG_LIFETIME;
			}
		}
	}

#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (sa->family == AF_INET6) {
		fp_sad6_t *sad6 = fp_get_sad6();

		sa_index = __fp_v6_sa_get(sad6, sa->spi,
		                          (uint8_t *)&sa->daddr.addr6,
		                          sa->proto, ntohl(sa->vrfid));

		if (sa_index <= 0) {
			syslog(LOG_ERR, "%s: SA not found\n", __FUNCTION__);
			return EXIT_FAILURE; /* not found */
		}

		fp_v6_sa_entry_t * sa6_entry = &sad6->table[sa_index];

		/* Set new values */
		sa6_entry->soft.nb_bytes   = ntohll(sa->soft.nb_bytes);
		sa6_entry->soft.nb_packets = ntohll(sa->soft.nb_packets);
		sa6_entry->hard.nb_bytes   = ntohll(sa->hard.nb_bytes);
		sa6_entry->hard.nb_packets = ntohll(sa->hard.nb_packets);

		/* If no limit given, it is an unlink request */
		if ((sa6_entry->soft.nb_bytes   == FP_SA_LIMIT_INF) &&
		    (sa6_entry->soft.nb_packets == FP_SA_LIMIT_INF) &&
		    (sa6_entry->hard.nb_bytes   == FP_SA_LIMIT_INF) &&
		    (sa6_entry->hard.nb_packets == FP_SA_LIMIT_INF)) {
			if (sa6_entry->flags & FP_SA_FLAG_LIFETIME) {
				/* Reset flag */
				sa6_entry->flags &= ~FP_SA_FLAG_LIFETIME;
			}
		} else {
			if (!(sa6_entry->flags & FP_SA_FLAG_LIFETIME)) {
				/* Set flag */
				sa6_entry->flags |= FP_SA_FLAG_LIFETIME;
			}
		}
	}
#endif

	syslog(LOG_INFO, "\tSet SA lifetime success\n");
	return EXIT_SUCCESS;
}
#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */

static inline uint32_t plen2mask(uint8_t plen)
{
	return plen ? htonl(~((1<<(32-plen)) -1)) : 0;
}



int __fpm_ipsec_v4_sp_create(struct cp_ipsec_sp_add *sp, int update)
{
	fp_sp_entry_t user_sp;
#ifdef CONFIG_MCORE_IPSEC_TRIE
	struct timeval tv;
#endif
	int err;

	if (f_verbose) {
		syslog(LOG_DEBUG, "%s:\n", __FUNCTION__);
		if (sp->family == AF_INET) {
			uint8_t i;
			syslog(LOG_DEBUG, "\tdir=%u index=%u proto=%d src=%u.%u.%u.%u/%d"
			       " dst=%u.%u.%u.%u/%d svti=0x%08x vr=%d link-vr=%u action=%d"
			       " xfrm=%d\n",
			       sp->dir, ntohl(sp->index), sp->proto, FP_NIPQUAD(sp->saddr),
			       sp->spfxlen, FP_NIPQUAD(sp->daddr), sp->dpfxlen,
			       ntohl(sp->svti_ifuid), ntohl(sp->vrfid),
			       ntohl(sp->link_vrfid), sp->action, sp->xfrm_count);
			for (i = 0 ; i < sp->xfrm_count; i++) {
				struct cp_ipsec_xfrm *xfrm = &sp->xfrm[i];
				if (xfrm->family == AF_INET)
					syslog(LOG_DEBUG, "\t#%d: proto %s src=%u.%u.%u.%u dst=%u.%u.%u.%u"
					       " mode %s reqid=%u\n",
					       i, xfrm->proto == IPPROTO_AH ? "ah" : "esp",
					       FP_NIPQUAD(xfrm->saddr), FP_NIPQUAD(xfrm->daddr),
					       xfrm->mode ? "tunnel" : "transport", ntohl(xfrm->reqid));
				else if (xfrm->family == AF_INET6)
					syslog(LOG_DEBUG, "\t#%d: proto %s src="FP_NIP6_FMT" dst="FP_NIP6_FMT
					       " mode %s reqid=%u\n",
					       i, xfrm->proto == IPPROTO_AH ? "ah" : "esp",
					       NIP6(xfrm->saddr.addr6), NIP6(xfrm->daddr.addr6),
					       xfrm->mode ? "tunnel" : "transport", ntohl(xfrm->reqid));
			}
		}
	}

	if ((ntohl(sp->vrfid) & FP_VRFID_MASK) >= FP_MAX_VR ||
	    (ntohl(sp->link_vrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "\tinvalid vrfid\n");
		return EXIT_FAILURE;	
	}

	/* check supported features */
	if (sp->family != AF_INET) {
		syslog(LOG_ERR, "\tunhandled address family\n");
		return EXIT_FAILURE;
	}

	if (sp->action == CM_IPSEC_ACTION_IPSEC) {
		if (sp->xfrm_count != 1) {
			syslog(LOG_ERR, "\tunhandled transform count\n");
			return EXIT_FAILURE;
		}
		if ((sp->xfrm[0].family != AF_INET) && (sp->xfrm[0].family != AF_INET6)) {
			syslog(LOG_ERR, "\tunhandled transform address family\n");
			return EXIT_FAILURE;
		}
	}

	/* during graceful restart, rules are added a second time */
	if (fpm_graceful_restart_in_progress)
		update = 1;

	memset(&user_sp, 0, sizeof(fp_sp_entry_t));

	user_sp.rule_index = ntohl(sp->index);
	/* ignore sp->family */
	/* filter fields */
	user_sp.filter.cost = ntohl(sp->priority);
	user_sp.filter.src = sp->saddr.addr4.s_addr;
	user_sp.filter.dst = sp->daddr.addr4.s_addr;
	user_sp.filter.src_plen = sp->spfxlen;
	user_sp.filter.dst_plen = sp->dpfxlen;
	user_sp.filter.src_mask = plen2mask(sp->spfxlen);
	user_sp.filter.dst_mask = plen2mask(sp->dpfxlen);
	/* 255 means any */
	user_sp.filter.ul_proto = sp->proto == 255 ? FILTER_ULPROTO_ANY : sp->proto;

	/* VR */
	user_sp.filter.vrfid = ntohl(sp->vrfid) & FP_VRFID_MASK;

#ifdef CONFIG_MCORE_IPSEC_SVTI
	/* SVTI interface */
	user_sp.svti_ifuid = sp->svti_ifuid;
#endif

	/* L4 local port */
	copy_sp_ports_to_filter(sp, &user_sp.filter);

	user_sp.vrfid = ntohl(sp->vrfid) & FP_VRFID_MASK;
	user_sp.link_vrfid = ntohl(sp->link_vrfid) & FP_VRFID_MASK;

	/* ignore flags */
	switch(sp->action) {
	case CM_IPSEC_ACTION_CLEAR:
		user_sp.filter.action = FP_SP_ACTION_BYPASS;
		break;
	case CM_IPSEC_ACTION_DISCARD:
		user_sp.filter.action = FP_SP_ACTION_DISCARD;
		break;
	case CM_IPSEC_ACTION_IPSEC:
		{
			struct cp_ipsec_xfrm *xfrm = &sp->xfrm[0];

			user_sp.filter.action = FP_SP_ACTION_PROTECT;
			user_sp.sa_proto = xfrm->proto;
			user_sp.reqid = ntohl(xfrm->reqid);
			if (xfrm->flags & CM_IPSEC_FLAG_LEVEL_USE)
				user_sp.flags |= FP_SP_FLAG_LEVEL_USE;

			if (xfrm->mode) {
				user_sp.mode = FP_IPSEC_MODE_TUNNEL;
				/* save transform address family to use_sp.outer_family */
				if (xfrm->family == AF_INET) {
					user_sp.outer_family = AF_INET;
					user_sp.tunnel4_src = xfrm->saddr.addr4.s_addr;
					user_sp.tunnel4_dst = xfrm->daddr.addr4.s_addr;
				}
#ifdef CONFIG_MCORE_IPSEC_IPV6
				else {
					user_sp.outer_family = AF_INET6;
					memcpy(user_sp.tunnel6_src.fp_s6_addr, xfrm->saddr.addr6.s6_addr, sizeof(fp_in6_addr_t));
					memcpy(user_sp.tunnel6_dst.fp_s6_addr, xfrm->daddr.addr6.s6_addr, sizeof(fp_in6_addr_t));
				}
#endif
			} else
				user_sp.mode = FP_IPSEC_MODE_TRANSPORT;
			/* ignore spi, reqid */
		}
		break;
	}

	/* Disable caching of last used SA */
	if (user_sp.mode == FP_IPSEC_MODE_TRANSPORT &&
	       (user_sp.filter.src_plen < 32 || user_sp.filter.dst_plen < 32)) {
		user_sp.flags |= FP_SP_FLAG_NO_SA_CACHE;
	}

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (user_sp.svti_ifuid) {
		if (sp->dir == CM_IPSEC_DIR_INBOUND) {
			if (update)
				err = fp_svti_sp_update(
					fp_svti_get_spd_in(user_sp.svti_ifuid),
					fp_get_spd_in(), &user_sp);
			else
				err = fp_svti_sp_add(
					fp_svti_get_spd_in(user_sp.svti_ifuid),
					fp_get_spd_in(), &user_sp);
		} else {
			if (update)
				err = fp_svti_sp_update(
					fp_svti_get_spd_out(user_sp.svti_ifuid),
					fp_get_spd_out(), &user_sp);
			else
				err = fp_svti_sp_add(
					fp_svti_get_spd_out(user_sp.svti_ifuid),
					fp_get_spd_out(), &user_sp);
		}

		if (err < 0) {
			syslog(LOG_ERR, "\tadd SVTI SP failure\n");
			return EXIT_FAILURE;
		}

	} else
#endif
	{
		if (sp->dir == CM_IPSEC_DIR_INBOUND) {
			if (update)
				err = fp_sp_update(fp_get_spd_in(), &user_sp);
			else
				err = fp_sp_add(fp_get_spd_in(), &user_sp);
		} else {
			if (update)
				err = fp_sp_update(fp_get_spd_out(), &user_sp);
			else
				err = fp_sp_add(fp_get_spd_out(), &user_sp);
		}

		if (err < 0) {
			syslog(LOG_ERR, "\tadd SP failure\n");
			return EXIT_FAILURE;
		}

		if (sp->dir == CM_IPSEC_DIR_OUTBOUND)
			fp_spd_out_commit();
		else
			fp_spd_in_commit();

#ifdef CONFIG_MCORE_IPSEC_TRIE
		if (sp->dir == CM_IPSEC_DIR_OUTBOUND &&
				!evtimer_pending(&ipsec_trie_out_build_evt, NULL)) {
			tv.tv_sec = SPD_TRIE_OUT_BUILDING_SCHEDULING_S;
			tv.tv_usec = SPD_TRIE_OUT_BUILDING_SCHEDULING_US;
			evtimer_add(&ipsec_trie_out_build_evt, &tv);
		}

		if (sp->dir == CM_IPSEC_DIR_INBOUND && 
				!evtimer_pending(&ipsec_trie_in_build_evt, NULL)) {
			tv.tv_sec = SPD_TRIE_IN_BUILDING_SCHEDULING_S;
			tv.tv_usec = SPD_TRIE_IN_BUILDING_SCHEDULING_US;
			evtimer_add(&ipsec_trie_in_build_evt, &tv);
		}
#endif	/* CONFIG_MCORE_IPSEC_TRIE */
	}

	if (f_verbose)
		syslog(LOG_INFO, "\tadd SP success\n");
	return EXIT_SUCCESS;
}


#ifdef CONFIG_MCORE_IPSEC_IPV6
/*
 * Convert a prefix length into a 128 bit prefix
 * (network order)
 */
static inline char* plen2mask_v6(int i)
{
	static uint32_t mask[4];

	mask[0] = mask[1] = mask[2] = mask[3] = ~0;

	if (i >= 128) {
		return (char *)mask;
	}
	else if (i > 96) {
		mask[0] = ((uint32_t)0xffffffff) << (128 - i);
	}
	else if (i > 64) {
		mask[0] = 0;
		mask[1] = ((uint32_t)0xffffffff) << (96 - i);
	}
	else if (i > 32) {
		mask[0] = mask[1] = 0;
		mask[2] = ((uint32_t)0xffffffff) << (64 - i);
	}
	else if (i > 0) {
		mask[0] = mask[1] = mask[2] = 0;
		mask[3] = ((uint32_t)0xffffffff) << (32 - i);
	}
	return (char *)mask;
}

int __fpm_ipsec_v6_sp_create(struct cp_ipsec_sp_add *sp, int update)
{
	fp_v6_sp_entry_t user_sp;
	int err;

	if (f_verbose) {
		syslog(LOG_DEBUG, "%s:\n", __FUNCTION__);
		if (sp->family == AF_INET6) {
			uint8_t i;
			syslog(LOG_DEBUG, "\tdir=%u index=%u proto=%d src="FP_NIP6_FMT"/%d"
			       " dst="FP_NIP6_FMT"/%d svti=0x%08x vr=%d link-vr=%u action=%d"
			       " xfrm=%d\n",
			       sp->dir, ntohl(sp->index), sp->proto, NIP6(sp->saddr.addr6),
			       sp->spfxlen, NIP6(sp->daddr.addr6), sp->dpfxlen,
			       ntohl(sp->svti_ifuid), ntohl(sp->vrfid),
			       ntohl(sp->link_vrfid), sp->action, sp->xfrm_count);
			for (i = 0 ; i < sp->xfrm_count; i++) {
				struct cp_ipsec_xfrm *xfrm = &sp->xfrm[i];
				if (xfrm->family == AF_INET6)
					syslog(LOG_DEBUG, "\t#%d: proto %s src="FP_NIP6_FMT" dst="FP_NIP6_FMT
					       " mode %s reqid=%u\n",
					       i, xfrm->proto == IPPROTO_AH ? "ah" : "esp",
					       NIP6(xfrm->saddr.addr6), NIP6(xfrm->daddr.addr6),
					       xfrm->mode ? "tunnel" : "transport", ntohl(xfrm->reqid));
				else if (xfrm->family == AF_INET)
					syslog(LOG_DEBUG, "\t#%d: proto %s src=%u.%u.%u.%u dst=%u.%u.%u.%u"
					       " mode %s reqid=%u\n",
					       i, xfrm->proto == IPPROTO_AH ? "ah" : "esp",
					       FP_NIPQUAD(xfrm->saddr), FP_NIPQUAD(xfrm->daddr),
					       xfrm->mode ? "tunnel" : "transport", ntohl(xfrm->reqid));
			}
		}
	}

	if ((ntohl(sp->vrfid) & FP_VRFID_MASK) >= FP_MAX_VR ||
	    (ntohl(sp->link_vrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "\tinvalid vrfid\n");
		return EXIT_FAILURE;
	}

	/* check supported features */
	if (sp->family != AF_INET6) {
		syslog(LOG_ERR, "\tunhandled address family\n");
		return EXIT_FAILURE;
	}

	if (sp->action == CM_IPSEC_ACTION_IPSEC) {
		if (sp->xfrm_count != 1) {
			syslog(LOG_ERR, "\tunhandled transform count\n");
			return EXIT_FAILURE;
		}
		if ((sp->xfrm[0].family != AF_INET6) && (sp->xfrm[0].family != AF_INET)) {
			syslog(LOG_ERR, "\tunhandled transform address family\n");
			return EXIT_FAILURE;
		}
	}

	/* during graceful restart, rules are added a second time */
	if (fpm_graceful_restart_in_progress)
		update = 1;

	memset(&user_sp, 0, sizeof(fp_v6_sp_entry_t));
	user_sp.rule_index = ntohl(sp->index);
	/* ignore sp->family */
	/* filter fields */
	user_sp.filter.cost = ntohl(sp->priority);
	user_sp.filter.src_plen = sp->spfxlen;
	user_sp.filter.dst_plen = sp->dpfxlen;
	memcpy(&user_sp.filter.src6, &sp->saddr.addr6, sizeof(fp_in6_addr_t));
	memcpy(&user_sp.filter.dst6, &sp->daddr.addr6, sizeof(fp_in6_addr_t));
	memcpy(&user_sp.filter.src6_mask, plen2mask_v6(sp->spfxlen), sizeof(fp_in6_addr_t));
	memcpy(&user_sp.filter.dst6_mask, plen2mask_v6(sp->dpfxlen), sizeof(fp_in6_addr_t));
	/* 255 means any */
	user_sp.filter.ul_proto = sp->proto == 255 ? FILTER_ULPROTO_ANY : sp->proto;

	/* VR */
	user_sp.filter.vrfid = ntohl(sp->vrfid) & FP_VRFID_MASK;

#ifdef CONFIG_MCORE_IPSEC_SVTI
	/* SVTI interface */
	user_sp.svti_ifuid = sp->svti_ifuid;
#endif

	/* L4 local port */
	copy_sp_ports_to_filter(sp, &user_sp.filter);

	user_sp.vrfid = ntohl(sp->vrfid) & FP_VRFID_MASK;
	user_sp.link_vrfid = ntohl(sp->link_vrfid) & FP_VRFID_MASK;

	/* ignore flags */
	switch(sp->action) {
	case CM_IPSEC_ACTION_CLEAR:
		user_sp.filter.action = FP_SP_ACTION_BYPASS;
		break;
	case CM_IPSEC_ACTION_DISCARD:
		user_sp.filter.action = FP_SP_ACTION_DISCARD;
		break;
	case CM_IPSEC_ACTION_IPSEC:
		{
			struct cp_ipsec_xfrm *xfrm = &sp->xfrm[0];

			user_sp.filter.action = FP_SP_ACTION_PROTECT;
			user_sp.sa_proto = xfrm->proto;
			user_sp.reqid = ntohl(xfrm->reqid);
			if (xfrm->flags & CM_IPSEC_FLAG_LEVEL_USE)
				user_sp.flags |= FP_SP_FLAG_LEVEL_USE;

			if (xfrm->mode) {
				user_sp.mode = FP_IPSEC_MODE_TUNNEL;
				memcpy(user_sp.tunnel6_src.fp_s6_addr, xfrm->saddr.addr6.s6_addr, sizeof(fp_in6_addr_t));
				memcpy(user_sp.tunnel6_dst.fp_s6_addr, xfrm->daddr.addr6.s6_addr, sizeof(fp_in6_addr_t));
				/* save transform address family to use_sp.outer_family */
				if (xfrm->family == AF_INET6)
					user_sp.outer_family = AF_INET6;
				else
					user_sp.outer_family = AF_INET;
			} else
				user_sp.mode = FP_IPSEC_MODE_TRANSPORT;
			/* ignore spi, reqid */
		}
		break;
	}

	/* Disable caching of last used SA */
	if (user_sp.mode == FP_IPSEC_MODE_TRANSPORT &&
	    (user_sp.filter.src_plen < 128 || user_sp.filter.dst_plen < 128)) {
		user_sp.flags |= FP_SP_FLAG_NO_SA_CACHE;
	}

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (user_sp.svti_ifuid) {
		if (sp->dir == CM_IPSEC_DIR_INBOUND) {
			if (update)
				err = fp_svti6_sp_update(
					fp_svti6_get_spd_in(user_sp.svti_ifuid),
					fp_get_spd6_in(), &user_sp);
			else
				err = fp_svti6_sp_add(
					fp_svti6_get_spd_in(user_sp.svti_ifuid),
					fp_get_spd6_in(), &user_sp);
		} else {
			if (update)
				err = fp_svti6_sp_update(
					fp_svti6_get_spd_out(user_sp.svti_ifuid),
					fp_get_spd6_out(), &user_sp);
			else
				err = fp_svti6_sp_add(
					fp_svti6_get_spd_out(user_sp.svti_ifuid),
					fp_get_spd6_out(), &user_sp);
		}

		if (err < 0) {
			syslog(LOG_ERR, "\tadd SVTI SP failure\n");
			return EXIT_FAILURE;
		}

	} else
#endif
	{
		if (sp->dir == CM_IPSEC_DIR_INBOUND) {
			if (update)
				err = fp_v6_sp_update(fp_get_spd6_in(), &user_sp);
			else
				err = fp_v6_sp_add(fp_get_spd6_in(), &user_sp);
		} else {
			if (update)
				err = fp_v6_sp_update(fp_get_spd6_out(), &user_sp);
			else
				err = fp_v6_sp_add(fp_get_spd6_out(), &user_sp);
		}

		if (err < 0) {
			syslog(LOG_ERR, "\tadd IPv6 SP failure\n");
			return EXIT_FAILURE;
		}
	}

	if (f_verbose)
		syslog(LOG_INFO, "\tadd SP success\n");
	return EXIT_SUCCESS;
}
#endif	/* CONFIG_MCORE_IPSEC_IPV6 */


static int fpm_ipsec_sp_create(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_ipsec_sp_add *sp = (struct cp_ipsec_sp_add *)request;
	uint32_t msgid = ntohl(hdr->cphdr_type);
	int update = (msgid == CMD_IPSEC_SP_UPDATE);

	if (sp->family == AF_INET)
		return __fpm_ipsec_v4_sp_create(sp, update);
#ifdef CONFIG_MCORE_IPSEC_IPV6
	else if (sp->family == AF_INET6)
		return __fpm_ipsec_v6_sp_create(sp, update);
#endif
	else {
		syslog(LOG_ERR, "%s(): unhandled address family\n", __FUNCTION__);
		return EXIT_FAILURE;
	}
}

static int fpm_ipsec_sp_delete(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_ipsec_sp_del *sp = (struct cp_ipsec_sp_del *)request;
	fp_sp_entry_t user_sp;
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_v6_sp_entry_t user_sp6;
#endif
	int err;

	if (f_verbose) {
		syslog(LOG_INFO, "fpm_ipsec_sp_delete:\n");
		if (sp->family == AF_INET)
			syslog(LOG_DEBUG, "\tvr=%d index=%u proto=%d src=%u.%u.%u.%u/%d"
			       " dst=%u.%u.%u.%u/%d svti=0x%08x\n ",
			       ntohl(sp->vrfid), ntohl(sp->index), sp->proto,
			       FP_NIPQUAD(sp->saddr), sp->spfxlen,
			       FP_NIPQUAD(sp->daddr), sp->dpfxlen,
			       ntohl(sp->svti_ifuid));
#ifdef CONFIG_MCORE_IPSEC_IPV6
		if (sp->family == AF_INET6)
			syslog(LOG_DEBUG, "\tvr=%d index=%u proto=%d src="FP_NIP6_FMT"/%d"
			       " dst="FP_NIP6_FMT"/%d svti=0x%08x\n ",
			       ntohl(sp->vrfid), ntohl(sp->index), sp->proto,
			       NIP6(sp->saddr.addr6), sp->spfxlen,
			       NIP6(sp->daddr.addr6), sp->dpfxlen,
			       ntohl(sp->svti_ifuid));
#endif
	}

	if ((ntohl(sp->vrfid) & FP_VRFID_MASK) >= FP_MAX_VR) {
		syslog(LOG_ERR, "\tinvalid vrfid\n");
		return EXIT_FAILURE;
	}

	if (sp->family == AF_INET) {
		memset(&user_sp, 0, sizeof(fp_sp_entry_t));
		user_sp.rule_index = ntohl(sp->index);
		user_sp.vrfid = ntohl(sp->vrfid) & FP_VRFID_MASK;
		user_sp.filter.src = sp->saddr.addr4.s_addr;
		user_sp.filter.dst = sp->daddr.addr4.s_addr;
		user_sp.filter.src_plen = sp->spfxlen;
		user_sp.filter.dst_plen = sp->dpfxlen;
	}
#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (sp->family == AF_INET6) {
		memset(&user_sp6, 0, sizeof(fp_v6_sp_entry_t));
		user_sp6.rule_index = ntohl(sp->index);
		user_sp6.vrfid = ntohl(sp->vrfid) & FP_VRFID_MASK;
		user_sp6.filter.src_plen = sp->spfxlen;
		user_sp6.filter.dst_plen = sp->dpfxlen;
		memcpy(&user_sp6.filter.src6, &sp->saddr.addr6, sizeof(fp_in6_addr_t));
		memcpy(&user_sp6.filter.dst6, &sp->daddr.addr6, sizeof(fp_in6_addr_t));
		memcpy(&user_sp6.filter.src6_mask, plen2mask_v6(sp->spfxlen), sizeof(fp_in6_addr_t));
		memcpy(&user_sp6.filter.dst6_mask, plen2mask_v6(sp->dpfxlen), sizeof(fp_in6_addr_t));
	}
#endif

#ifdef CONFIG_MCORE_IPSEC_SVTI
	/* SVTI interface */
	if (sp->family == AF_INET) {
		user_sp.svti_ifuid = sp->svti_ifuid;
	}
#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (sp->family == AF_INET6) {
		user_sp6.svti_ifuid = sp->svti_ifuid;
	}
#endif
#endif

	if (sp->family == AF_INET) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (user_sp.svti_ifuid) {
			fp_ifnet_t *ifp = __fp_ifuid2ifnet(user_sp.svti_ifuid);

			if (ifp->if_type != FP_IFTYPE_SVTI)
				err = -1;
			else if (sp->dir == CM_IPSEC_DIR_INBOUND)
				err = fp_svti_sp_del(fp_svti_get_spd_in(user_sp.svti_ifuid),
						fp_get_spd_in(), &user_sp);
			else
				err = fp_svti_sp_del(fp_svti_get_spd_out(user_sp.svti_ifuid),
						fp_get_spd_out(), &user_sp);

			if (err < 0) {
				syslog(LOG_ERR, "\tdel SVTI SP failure\n");
				return EXIT_FAILURE;
			}

		} else
#endif
		{
			if (sp->dir == CM_IPSEC_DIR_INBOUND)
				err =  fp_sp_del(fp_get_spd_in(), &user_sp);
			else
				err =  fp_sp_del(fp_get_spd_out(), &user_sp);
			if (err < 0) {
				syslog(LOG_ERR, "\tdel SP failure\n");
				return EXIT_FAILURE;
			}

		}
		if (sp->dir == CM_IPSEC_DIR_OUTBOUND) {
			fp_spd_out_commit();
#ifdef CONFIG_MCORE_IPSEC_TRIE
			fp_spd_trie_out_commit();
#endif
		} else {
			fp_spd_in_commit();
#ifdef CONFIG_MCORE_IPSEC_TRIE
			fp_spd_trie_in_commit();
#endif
		}
	}

#ifdef CONFIG_MCORE_IPSEC_IPV6
	if (sp->family == AF_INET6) {
#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (user_sp6.svti_ifuid) {
			fp_ifnet_t *ifp = __fp_ifuid2ifnet(user_sp6.svti_ifuid);

			if (ifp->if_type != FP_IFTYPE_SVTI)
				err = -1;
			else if (sp->dir == CM_IPSEC_DIR_INBOUND)
				err = fp_svti6_sp_del(fp_svti6_get_spd_in(user_sp6.svti_ifuid),
						fp_get_spd6_in(), &user_sp6);
			else
				err = fp_svti6_sp_del(fp_svti6_get_spd_out(user_sp6.svti_ifuid),
						fp_get_spd6_out(), &user_sp6);

			if (err < 0) {
				syslog(LOG_ERR, "\tdel SVTI SP failure\n");
				return EXIT_FAILURE;
			}

		} else
#endif
		{
			if (sp->dir == CM_IPSEC_DIR_INBOUND)
				err =  fp_v6_sp_del(fp_get_spd6_in(), &user_sp6);
			else
				err =  fp_v6_sp_del(fp_get_spd6_out(), &user_sp6);

			if (err < 0) {
				syslog(LOG_ERR, "\tdel SP IPv6 failure\n");
				return EXIT_FAILURE;
			}
		}
		/*process out_commit ?*/
	}
#endif	/* CONFIG_MCORE_IPSEC_IPV6 */

	if (f_verbose)
		syslog(LOG_INFO, "\tdel SP success\n");
	return EXIT_SUCCESS;
}

static int fpm_ipsec_sp_flush(const uint8_t *request, const struct cp_hdr *hdr)
{
	struct cp_ipsec_sp_flush *flush = (struct cp_ipsec_sp_flush *)request;
	uint16_t vrfid = ntohl(flush->vrfid) & FP_VRFID_MASK;
	uint32_t ifuid = flush->svti_ifuid;

	if (f_verbose)
		syslog(LOG_DEBUG, "fpm_ipsec_sp_flush: vr=%d svti_ifuid=0x%08x\n", vrfid, ntohl(ifuid));

	if (vrfid >= FP_MAX_VR) {
		syslog(LOG_ERR, "\tinvalid vrfid\n");
		return EXIT_FAILURE;
	}

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if (ifuid) {
		fp_svti_sp_flush(fp_svti_get_spd_in(ifuid), fp_get_spd_in());
		fp_svti_sp_flush(fp_svti_get_spd_out(ifuid), fp_get_spd_out());
#ifdef CONFIG_MCORE_IPSEC_IPV6
		fp_svti6_sp_flush(fp_svti6_get_spd_in(ifuid), fp_get_spd6_in());
		fp_svti6_sp_flush(fp_svti6_get_spd_out(ifuid), fp_get_spd6_out());
#endif
		return EXIT_SUCCESS;
	}
#endif

	fp_sp_flush_by_vrfid(fp_get_spd_in(), vrfid);
	fp_sp_flush_by_vrfid(fp_get_spd_out(), vrfid);

#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_v6_sp_flush_by_vrfid(fp_get_spd6_in(), vrfid);
	fp_v6_sp_flush_by_vrfid(fp_get_spd6_out(), vrfid);
#endif

	fp_spd_out_commit();
	fp_spd_in_commit();
#ifdef CONFIG_MCORE_IPSEC_TRIE
	fp_spd_trie_out_commit();
	fp_spd_trie_in_commit();
#endif

	return EXIT_SUCCESS;
}

void fpm_ipsec_init(void)
{
#ifdef CONFIG_MCORE_MULTIBLADE
	LIST_INIT(&sa_sync_pending_list);
	/* Init the event base */
	evtimer_set(&ipsec_sa_sync_evt, fpm_sa_sync_timer_cb, NULL);
#endif

#ifdef CONFIG_MCORE_IPSEC_TRIE
	/* Init the event base */
	evtimer_set(&ipsec_trie_out_build_evt, fp_ipsec_trie_out_build_timer_cb, NULL);
	evtimer_set(&ipsec_trie_in_build_evt, fp_ipsec_trie_in_build_timer_cb, NULL);
#endif
	if (fpm_graceful_restart_in_progress) {
		fp_ipsec_index_rebuild();
#ifdef CONFIG_MCORE_MULTIBLADE
		fpm_sync_pendinglist_rebuild();
#endif
	} else
		fp_ipsec_index_init();
}

#ifdef CONFIG_MCORE_IPSEC_IPV6
void fpm_ipsec6_init(void)
{
#ifdef CONFIG_MCORE_MULTIBLADE
	LIST_INIT(&sa6_sync_pending_list);
	/* Init the event base */
	evtimer_set(&ipsec_v6_sa_sync_evt, fpm_sa6_sync_timer_cb, NULL);
#endif
	if (fpm_graceful_restart_in_progress) {
		fp_ipsec6_index_rebuild();
#ifdef CONFIG_MCORE_MULTIBLADE
		fpm_sync_pendinglist6_rebuild();
#endif
	} else
		fp_ipsec6_index_init();
}
#endif

void fpm_ipsec_vrf_del(uint16_t vrfid)
{
	/* SA */
	fp_sa_flush_by_vrfid(fp_get_sad(), vrfid);
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_v6_sa_flush_by_vrfid(fp_get_sad6(), vrfid);
#endif

	/* SP */
	fp_sp_flush_by_vrfid(fp_get_spd_in(), vrfid);
	fp_sp_flush_by_vrfid(fp_get_spd_out(), vrfid);
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fp_v6_sp_flush_by_vrfid(fp_get_spd6_in(), vrfid);
	fp_v6_sp_flush_by_vrfid(fp_get_spd6_out(), vrfid);
#endif
	fp_spd_out_commit();
	fp_spd_in_commit();
#ifdef CONFIG_MCORE_IPSEC_TRIE
	fp_spd_trie_out_commit();
	fp_spd_trie_in_commit();
#endif
}

static struct fpm_vrf_handler vrf_hdlr = {
	.name = "ipsec",
	.del = fpm_ipsec_vrf_del,
};

static int fpm_ipsec_sa_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_ipsec_sa_add *sa1 = cmd1->data;
	struct cp_ipsec_sa_add *sa2 = cmd2->data;

	if ((sa1->vrfid == sa2->vrfid) && (sa1->spi == sa2->spi) &&
	    (sa1->proto == sa2->proto) ) {
		return memcmp(&sa1->daddr, &sa2->daddr, sizeof(cp_ipsec_addr_t));
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_ipsec_sa_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_IPSEC_SA_DELETE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_ipsec_sa_display(const fpm_cmd_t *fpm_cmd,
                                 char *buffer, int len)
{
	struct cp_ipsec_sa_add *data = fpm_cmd->data;
	char addr_str[INET6_ADDRSTRLEN];

	snprintf(buffer, len, "CMD_IPSEC_SA_CREATE - VR#%d/XVR#%d - spi: 0x%08x proto %d -> %s\n",
	   ntohl(data->vrfid), ntohl(data->xvrfid),
	   ntohl(data->spi), data->proto,
	   inet_ntop(data->family, &data->daddr, addr_str, sizeof(addr_str)));
}

static fpm_cmd_t *fpm_ipsec_sa_graceful(int gr_type, uint32_t cmd,
                                        const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_IPSEC_SA, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_ipsec_sa_add));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_IPSEC_SA;
	fpm_cmd->comp    = fpm_ipsec_sa_comp;
	fpm_cmd->revert  = fpm_ipsec_sa_revert;
	fpm_cmd->display = fpm_ipsec_sa_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
static int fpm_ipsec_sa_lifetime_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_ipsec_sa_lifetime *sa1 = cmd1->data;
	struct cp_ipsec_sa_lifetime *sa2 = cmd2->data;

	if ((sa1->vrfid == sa2->vrfid) && (sa1->spi == sa2->spi) &&
	    (sa1->proto == sa2->proto) &&
	    (!memcmp(&sa1->daddr, &sa2->daddr, sizeof(cp_ipsec_addr_t)))) {
		if ((sa1->soft.nb_bytes   == sa2->soft.nb_bytes)  &&
		    (sa1->soft.nb_packets == sa2->soft.nb_packets) &&
		    (sa1->hard.nb_bytes   == sa2->hard.nb_bytes)   &&
		    (sa1->hard.nb_packets == sa2->hard.nb_packets)) {
		    return(0);
		}
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_ipsec_sa_lifetime_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sa_lifetime *req = fpm_cmd->data;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type      = htonl(CMD_IPSEC_SA_LIFETIME);
	req->soft.nb_bytes   = htonll(FP_SA_LIMIT_INF);
	req->soft.nb_packets = htonll(FP_SA_LIMIT_INF);
	req->hard.nb_bytes   = htonll(FP_SA_LIMIT_INF);
	req->hard.nb_packets = htonll(FP_SA_LIMIT_INF);
	fpm_dispatch(hdr, fpm_cmd->data);

	free(hdr);

	return 0;
}

static void fpm_ipsec_sa_lifetime_display(const fpm_cmd_t *fpm_cmd,
                                          char *buffer, int len)
{
	struct cp_ipsec_sa_lifetime *data = fpm_cmd->data;
	char addr_str[INET6_ADDRSTRLEN];

	snprintf(buffer, len, "CMD_IPSEC_SA_LIFETIME - VR#%d - spi: 0x%08x proto %d -> %s"
			              " : soft = %"PRIu64"/%"PRIu64" - hard %"PRIu64"/%"PRIu64"\n",
	   ntohl(data->vrfid), ntohl(data->spi), data->proto,
	   inet_ntop(data->family, &data->daddr, addr_str, sizeof(addr_str)),
	   ntohll(data->soft.nb_packets), ntohll(data->soft.nb_bytes),
	   ntohll(data->hard.nb_packets), ntohll(data->hard.nb_bytes));
}

static fpm_cmd_t *fpm_ipsec_sa_lifetime_graceful(int gr_type, uint32_t cmd,
                                                 const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_IPSEC_SA, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_ipsec_sa_lifetime));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_IPSEC_SA;
	fpm_cmd->comp    = fpm_ipsec_sa_lifetime_comp;
	fpm_cmd->revert  = fpm_ipsec_sa_lifetime_revert;
	fpm_cmd->display = fpm_ipsec_sa_lifetime_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}
#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */

static int fpm_ipsec_sp_comp(const fpm_cmd_t *cmd1, const fpm_cmd_t *cmd2)
{
	struct cp_ipsec_sp_add *sp1 = cmd1->data;
	struct cp_ipsec_sp_add *sp2 = cmd2->data;

#ifdef CONFIG_MCORE_IPSEC_SVTI
	if ((sp1->svti_ifuid) || (sp2->svti_ifuid)) {
		if ((sp1->svti_ifuid == sp2->svti_ifuid) &&
		    (sp1->index == sp2->index)) {
			return 0;
		}
		return 1;
	}
#endif

	if ((sp1->vrfid == sp2->vrfid) && (sp1->index == sp2->index)) {
		return 0;
	}
	return 1;
}

/* Invert the command, and send it to the fpm dispatch function */
static int fpm_ipsec_sp_revert(const fpm_cmd_t *fpm_cmd)
{
	struct cp_hdr *hdr;

	/* Allocate memory for message */
	hdr = calloc(sizeof(struct cp_hdr), 1);
	if (hdr == NULL)
		return -1;

	hdr->cphdr_type = htonl(CMD_IPSEC_SP_DELETE);
	fpm_dispatch(hdr, fpm_cmd->data);
	free(hdr);

	return 0;
}

static void fpm_ipsec_sp_display(const fpm_cmd_t *fpm_cmd,
                                 char *buffer, int len)
{
	struct cp_ipsec_sp_add *data = fpm_cmd->data;
	char src_str[INET6_ADDRSTRLEN];
	char dst_str[INET6_ADDRSTRLEN];

	snprintf(buffer, len, "CMD_IPSEC_SP - VR#%d SVTI 0x%08x - #%d, %s | %s/%u -> %s/%u\n",
	   ntohl(data->vrfid), ntohl(data->svti_ifuid), ntohl(data->index),
	   data->dir ? "in": "out",
	   inet_ntop(data->family, &data->saddr, src_str, sizeof(src_str)),
	   (unsigned)data->spfxlen,
	   inet_ntop(data->family, &data->daddr, dst_str, sizeof(dst_str)),
	   (unsigned)data->dpfxlen);
}

static fpm_cmd_t *fpm_ipsec_sp_graceful(int gr_type, uint32_t cmd,
                                        const void *data)
{
	fpm_cmd_t *fpm_cmd;

	/* If graceful is not needed for this type, exit */
	if (!fpm_cmd_match_gr_type(FPM_CMD_IPSEC_SP, gr_type))
		return NULL;

	/* Allocate memory for message */
	fpm_cmd = fpm_cmd_alloc(sizeof(struct cp_ipsec_sp_add));
	if (!fpm_cmd)
		return NULL;

	fpm_cmd->cmd     = cmd;
	fpm_cmd->group   = FPM_CMD_IPSEC_SP;
	fpm_cmd->comp    = fpm_ipsec_sp_comp;
	fpm_cmd->revert  = fpm_ipsec_sp_revert;
	fpm_cmd->display = fpm_ipsec_sp_display;
	memcpy(fpm_cmd->data, data, fpm_cmd->len);

	return fpm_cmd;
}

/* IPsec entries */
static int fpm_sad_entries_to_cmd(fp_sad_t *sad, enum list_type list)
{
	int sa_idx;
	int ret = 0;

	for (sa_idx=1; sa_idx<FP_MAX_SA_ENTRIES; sa_idx++) {
		if (sad->table[sa_idx].state != FP_SA_STATE_UNSPEC) {
			fp_sa_entry_t *sa = &sad->table[sa_idx];
			struct cp_ipsec_sa_del req;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			req.vrfid = htonl(sa->vrfid);
			req.spi = sa->spi;
			req.proto = sa->proto;
			req.family = AF_INET;
			req.daddr.addr4.s_addr = sa->dst4;

			ret |= fpm_cmd_create_and_enqueue(list, CMD_IPSEC_SA_CREATE, &req);

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
			if (sa->flags & FP_SA_FLAG_LIFETIME) {
				struct cp_ipsec_sa_lifetime req;

				/* Clear memory */
				memset(&req, 0, sizeof(req));

				req.spi             = sa->spi;
				req.proto           = sa->proto;
				req.family          = AF_INET;
				req.daddr.addr4.s_addr = sa->dst4;
				req.vrfid           = htonl(sa->vrfid);
				req.soft.nb_bytes   = htonll(sa->soft.nb_bytes);
				req.soft.nb_packets = htonll(sa->soft.nb_packets);
				req.hard.nb_bytes   = htonll(sa->hard.nb_bytes);
				req.hard.nb_packets = htonll(sa->hard.nb_packets);

				ret |= fpm_cmd_create_and_enqueue(list, CMD_IPSEC_SA_LIFETIME, &req);
			}
#endif
		}
	}

	return ret;
}

static int fpm_spd_entries_to_cmd(fp_spd_t *spd, uint8_t dir, enum list_type list)
{
	int sp_idx;
	int ret = 0;

#ifdef CONFIG_MCORE_IPSEC_SVTI
	for (sp_idx=1; sp_idx<FP_MAX_SP_ENTRIES; sp_idx++)
#else
	fp_hlist_for_each(sp_idx, fp_get_spd_head(spd), spd->table, list)
#endif
	{
		fp_sp_entry_t *sp = &spd->table[sp_idx];
		struct cp_ipsec_sp_del req;

#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (sp->state == FP_SP_STATE_UNSPEC)
			continue;
#endif

		/* Clear memory */
		memset(&req, 0, sizeof(req));

		req.vrfid = htonl(sp->vrfid);
		req.index = htonl(sp->rule_index);
		req.dir = dir;
		req.proto = htonl(sp->sa_proto);
		req.family = AF_INET;
		req.saddr.addr4.s_addr = sp->filter.src;
		req.daddr.addr4.s_addr = sp->filter.dst;
		req.priority = htonl(sp->filter.cost);
		req.sport = 0;
		req.dport = 0xFFFF;
		req.sportmask = 0;
		req.dportmask = 0;
		req.spfxlen = sp->filter.src_plen;
		req.dpfxlen = sp->filter.dst_plen;
		req.svti_ifuid = sp->svti_ifuid;

		ret |= fpm_cmd_create_and_enqueue(list, CMD_IPSEC_SP_CREATE, &req);
	}

	return ret;
}

#ifdef CONFIG_MCORE_IPSEC_IPV6
/* IPsec6 entries */
static int fpm_sad6_entries_to_cmd(fp_sad6_t *sad6, enum list_type list)
{
	int sa_idx;
	int ret = 0;

	for (sa_idx=1; sa_idx<FP_MAX_IPV6_SA_ENTRIES; sa_idx++) {
		if (sad6->table[sa_idx].state != FP_SA_STATE_UNSPEC) {
			fp_v6_sa_entry_t *sa6 = &sad6->table[sa_idx];
			struct cp_ipsec_sa_del req;

			/* Clear memory */
			memset(&req, 0, sizeof(req));

			req.vrfid = htonl(sa6->vrfid);
			req.spi = sa6->spi;
			req.proto = sa6->proto;
			req.family = AF_INET6;
			memcpy(req.daddr.addr6.s6_addr, sa6->dst6.fp_s6_addr, sizeof(fp_in6_addr_t));

			ret |= fpm_cmd_create_and_enqueue(list, CMD_IPSEC_SA_CREATE, &req);

#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
			if (sa6->flags & FP_SA_FLAG_LIFETIME) {
				struct cp_ipsec_sa_lifetime req;

				/* Clear memory */
				memset(&req, 0, sizeof(req));

				req.spi             = sa6->spi;
				req.proto           = sa6->proto;
				req.family          = AF_INET6;
				req.vrfid           = htonl(sa6->vrfid);
				req.soft.nb_bytes   = htonll(sa6->soft.nb_bytes);
				req.soft.nb_packets = htonll(sa6->soft.nb_packets);
				req.hard.nb_bytes   = htonll(sa6->hard.nb_bytes);
				req.hard.nb_packets = htonll(sa6->hard.nb_packets);
				memcpy(req.daddr.addr6.s6_addr, sa6->dst6.fp_s6_addr, sizeof(fp_in6_addr_t));

				ret |= fpm_cmd_create_and_enqueue(list, CMD_IPSEC_SA_LIFETIME, &req);
			}
#endif /* CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT */
		}
	}

	return ret;
}

static int fpm_spd6_entries_to_cmd(fp_spd6_t *spd6, uint8_t dir, enum list_type list)
{
	int sp_idx;
	int ret = 0;

#ifdef CONFIG_MCORE_IPSEC_SVTI
	for (sp_idx=1; sp_idx<FP_MAX_IPV6_SP_ENTRIES; sp_idx++)
#else
	fp_hlist_for_each(sp_idx, fp_get_spd6_head(spd6), spd6->table, list)
#endif
	{
		fp_v6_sp_entry_t *sp6 = &spd6->table[sp_idx];
		struct cp_ipsec_sp_del req;

#ifdef CONFIG_MCORE_IPSEC_SVTI
		if (sp6->state == FP_SP_STATE_UNSPEC)
			continue;
#endif

		/* Clear memory */
		memset(&req, 0, sizeof(req));

		req.index = htonl(sp6->rule_index);
		req.priority = htonl(sp6->filter.cost);
		req.family = AF_INET6;
		req.dir = dir;
		req.proto = htonl(sp6->sa_proto);
		memcpy(req.saddr.addr6.s6_addr, sp6->filter.src6.fp_s6_addr, sizeof(fp_in6_addr_t));
		memcpy(req.daddr.addr6.s6_addr, sp6->filter.dst6.fp_s6_addr, sizeof(fp_in6_addr_t));
		req.sport = 0;
		req.dport = 0xFFFF;
		req.sportmask = 0;
		req.dportmask = 0;
		req.vrfid = htonl(sp6->vrfid);
		req.svti_ifuid = sp6->svti_ifuid;
		req.spfxlen = sp6->filter.src_plen;
		req.dpfxlen = sp6->filter.dst_plen;
		req.action = sp6->filter.action;

		ret |= fpm_cmd_create_and_enqueue(list, CMD_IPSEC_SP_CREATE, &req);
	}

	return ret;
}
#endif

static int fpm_ipsec_shared_cmd(int gr_type, enum list_type list)
{
	int ret = 0;

	/* Dump SAs if needed */
	if (fpm_cmd_match_gr_type(FPM_CMD_IPSEC_SA, gr_type)) {
		ret |= fpm_sad_entries_to_cmd(&fp_shared->ipsec.sad, list);
#ifdef CONFIG_MCORE_IPSEC_IPV6
		ret |= fpm_sad6_entries_to_cmd(&fp_shared->ipsec6.sad6, list);
#endif
	}

	/* Dump SPs if needed */
	if (fpm_cmd_match_gr_type(FPM_CMD_IPSEC_SP, gr_type)) {
		ret |= fpm_spd_entries_to_cmd(&fp_shared->ipsec.spd_in, CM_IPSEC_DIR_INBOUND, list);
		ret |= fpm_spd_entries_to_cmd(&fp_shared->ipsec.spd_out, CM_IPSEC_DIR_OUTBOUND, list);
#ifdef CONFIG_MCORE_IPSEC_IPV6
		ret |= fpm_spd6_entries_to_cmd(&fp_shared->ipsec6.spd6_in, CM_IPSEC_DIR_INBOUND, list);
		ret |= fpm_spd6_entries_to_cmd(&fp_shared->ipsec6.spd6_out, CM_IPSEC_DIR_OUTBOUND, list);
#endif
	}

	return ret;
}

static void fpm_ipsec_module_init(__attribute__((unused)) int graceful)
{
	fpm_vrf_register(&vrf_hdlr);

	fpm_register_msg(CMD_IPSEC_SA_CREATE, fpm_ipsec_sa_create,
	                 fpm_ipsec_sa_graceful);
	fpm_register_msg(CMD_IPSEC_SA_DELETE, fpm_ipsec_sa_delete, NULL);
	fpm_register_msg(CMD_IPSEC_SA_FLUSH, fpm_ipsec_sa_flush, NULL);
#ifdef CONFIG_MCORE_MULTIBLADE
	fpm_register_msg(CMD_IPSEC_SA_MIGRATE, fpm_ipsec_sa_migrate, NULL);
	fpm_register_msg(CMD_IPSEC_SA_BULK_MIGRATE, fpm_ipsec_sa_bulk_migrate, NULL);
#endif
	fpm_register_msg(CMD_IPSEC_SP_CREATE, fpm_ipsec_sp_create,
	                 fpm_ipsec_sp_graceful);
	fpm_register_msg(CMD_IPSEC_SP_UPDATE, fpm_ipsec_sp_create, NULL);
	fpm_register_msg(CMD_IPSEC_SP_DELETE, fpm_ipsec_sp_delete, NULL);
	fpm_register_msg(CMD_IPSEC_SP_FLUSH, fpm_ipsec_sp_flush, NULL);
#ifdef CONFIG_MCORE_IPSEC_SA_VOLUME_LIMIT
	fpm_register_msg(CMD_IPSEC_SA_LIFETIME, fpm_ipsec_sa_lifetime,
	    fpm_ipsec_sa_lifetime_graceful);
#endif

	fpm_ipsec_init();
#ifdef CONFIG_MCORE_IPSEC_SPD_ADDR_HASH_TABLE
	fp_set_spd_conf(spd_hash_loc_plen, spd_hash_rem_plen);
#endif
#ifdef CONFIG_MCORE_IPSEC_IPV6
	fpm_ipsec6_init();
#ifdef CONFIG_MCORE_IPSEC_IPV6_SPD_ADDR_HASH_TABLE
	fp_set_spd6_conf(spd6_hash_loc_plen, spd6_hash_rem_plen);
#endif
#endif
}

static struct fpm_mod fpm_ipsec_mod = {
	.name = "ipsec",
	.init = fpm_ipsec_module_init,
	.shared_cmd = fpm_ipsec_shared_cmd,
};

static void init(void) __attribute__((constructor));
void init(void)
{
	fpm_mod_register(&fpm_ipsec_mod);
}
