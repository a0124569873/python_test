/*
 * Copyright(c) 2013 6WIND, all rights reserved
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <net/if.h>
#include <netinet/in.h>
#include <linux/types.h> /* for 2.4 kernel */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <linux/xfrm.h>
#include <linux/ipsec.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netlink/msg.h>

#include "fpc.h"
#include "cm_netlink.h"
#include "cm_pub.h"
#include "cm_ipsec_pub.h"
#include "cm_priv.h"

#include "ifuid.h"

u_int32_t cm_ifindex2ifuid (u_int32_t ifindex, u_int32_t vrfid, u_int8_t strict)
{
	struct cm_iface *ifp;

	ifp = iflookup(ifindex, vrfid);
	if (ifp)
		return ifp->ifuid;

	if (!strict) {
		char name[IF_NAMESIZE];

		if (if_indextoname(ifindex, name) != NULL)
			return ifname2ifuid (name, vrfid);
	}

	syslog(LOG_INFO, "%s: Unknown ifindex %d vrfid %d\n",
	       __FUNCTION__, ifindex, vrfid);
	return 0;
}

/* cbc/ecb(*) are for recent kernels */
static u_int8_t
ealg_nl2cm(char *alg_name)
{
	u_int8_t alg;

	if(!strcmp(alg_name, "cipher_null") || !strcmp(alg_name, "ecb(cipher_null)"))
	{
		/*SADB_EALG_NULL*/
		alg = CM_IPSEC_EALG_NONE;
	}
	else if(!strcmp(alg_name, "des") || !strcmp(alg_name, "cbc(des)"))
	{
		/*SADB_EALG_DESCBC*/
		alg = CM_IPSEC_EALG_DESCBC;
	}
	else if(!strcmp(alg_name, "des3_ede") || !strcmp(alg_name, "cbc(des3_ede)"))
	{
		/*SADB_EALG_3DESCBC*/
		alg = CM_IPSEC_EALG_3DESCBC;
	}
	else if(!strcmp(alg_name, "cast128") || !strcmp(alg_name, "cbc(cast5)"))
	{
		/*SADB_X_EALG_CASTCBC*/
		alg = CM_IPSEC_EALG_CASTCBC;
	}
	else if(!strcmp(alg_name, "blowfish") || !strcmp(alg_name, "cbc(blowfish)"))
	{
		/*SADB_X_EALG_BLOWFISHCBC*/
		alg = CM_IPSEC_EALG_BLOWFISHCBC;
	}
	else if(!strcmp(alg_name, "aes") || !strcmp(alg_name, "cbc(aes)"))
	{
		/*SADB_X_EALG_AESCBC*/
		alg = CM_IPSEC_EALG_AESCBC;
	}
	else if(!strcmp(alg_name, "rfc4106(gcm(aes))"))
	{
		/*SADB_X_EALG_AESGCM*/
		alg = CM_IPSEC_EALG_AESGCM;
	}
	else if(!strcmp(alg_name, "rfc4543(gcm(aes))"))
	{
		/*SADB_X_EALG_NULL_AESGMAC*/
		alg = CM_IPSEC_EALG_NULL_AESGMAC;
	}
	else if(!strcmp(alg_name, "serpent") || !strcmp(alg_name, "cbc(serpent)"))
	{
		/*SADB_X_EALG_SERPENTCBC*/
		alg = CM_IPSEC_EALG_SERPENTCBC;
	}
	else if(!strcmp(alg_name, "twofish") || !strcmp(alg_name, "cbc(twofish)"))
	{
		/*SADB_X_EALG_TWOFISHCBC*/
		alg = CM_IPSEC_EALG_TWOFISHCBC;
	}
	else
	{
		alg = CM_IPSEC_ALG_UNKNOWN;
	}

	return alg;
}

/* hmac(*) are for recent kernels */
static u_int8_t
aalg_nl2cm(char *alg_name)
{
	u_int8_t alg;

	if(!strcmp(alg_name, "digest_null"))
	{
		/*SADB_X_AALG_NULL*/
		alg = CM_IPSEC_AALG_NONE;
	}
	else if(!strcmp(alg_name, "md5") || !strcmp(alg_name, "hmac(md5)"))
	{
		/*SADB_AALG_MD5HMAC*/
		alg = CM_IPSEC_AALG_MD5HMAC;
	}
	else if(!strcmp(alg_name, "sha1") || !strcmp(alg_name, "hmac(sha1)"))
	{
		/*SADB_AALG_SHA1HMAC*/
		alg = CM_IPSEC_AALG_SHA1HMAC;
	}
	else if(!strcmp(alg_name, "sha256") || !strcmp(alg_name, "hmac(sha256)"))
	{
		/*SADB_X_AALG_SHA2_256HMAC*/
		alg = CM_IPSEC_AALG_SHA2_256HMAC;
	}
	else if(!strcmp(alg_name, "sha384") || !strcmp(alg_name, "hmac(sha384)"))
	{
		/*SADB_AALG_SHA384HMAC*/
		alg = CM_IPSEC_AALG_SHA2_384HMAC;
	}
	else if(!strcmp(alg_name, "sha512") || !strcmp(alg_name, "hmac(sha512)"))
	{
		/*SADB_X_AALG_SHA2_512HMAC*/
		alg = CM_IPSEC_AALG_SHA2_512HMAC;
	}
	else if(!strcmp(alg_name, "ripemd160") || !strcmp(alg_name, "hmac(rmd160)"))
	{
		/*SADB_X_AALG_RIPEMD160HMAC*/
		alg = CM_IPSEC_AALG_RIPEMD160HMAC;
	}
	else if(!strcmp(alg_name, "xcbc(aes)"))
	{
		/*SADB_X_AALG_AES_XCBC_MAC*/
		alg = CM_IPSEC_AALG_AES_XCBC_MAC;
	}
	else
	{
		alg = CM_IPSEC_ALG_UNKNOWN;
	}

	return alg;
}


/*
 * Convert a NETLINK SA to a cache manager SA
 */
static struct cm_ipsec_sa *
sa_nl2cm(struct xfrm_usersa_info *p, struct nlattr **xfrma, uint32_t sock_vrfid)
{
	struct xfrm_algo *auth_algp = NULL;
	struct xfrm_algo *crypt_algp = NULL;
	struct xfrm_algo_aead *aead_algp = NULL;
	struct xfrm_encap_tmpl *encap = NULL;
	struct cm_ipsec_sa *sa = NULL;
	uint16_t keybytes = 0;
	uint16_t keyoff = 0;
	uint32_t *pvrfid = NULL, *pxvrfid = NULL;
	struct xfrm_replay_state *replay = NULL;
#ifdef XFRM_STATE_ESN
	struct xfrm_replay_state_esn *replay_esn = NULL;
#endif

	if (xfrma) {
		if (xfrma[XFRMA_ALG_AUTH])
			auth_algp = nla_data(xfrma[XFRMA_ALG_AUTH]);

		if (xfrma[XFRMA_ALG_CRYPT])
			crypt_algp = nla_data(xfrma[XFRMA_ALG_CRYPT]);

		if (xfrma[XFRMA_ALG_AEAD])
			aead_algp = RTA_DATA(xfrma[XFRMA_ALG_AEAD]);

		if (xfrma[XFRMA_ENCAP])
			encap = nla_data(xfrma[XFRMA_ENCAP]);

		if (auth_algp)
			keybytes += (auth_algp->alg_key_len + 7U) / 8;
		if (crypt_algp)
			keybytes += (crypt_algp->alg_key_len + 7U) / 8;
		if (aead_algp)
			keybytes += (aead_algp->alg_key_len + 7U) / 8;

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
		pvrfid = &sock_vrfid;
		pxvrfid = &sock_vrfid;
#else
#if defined(XFRMA_VRFID) && defined(XFRMA_XVRFID)
		if (xfrma[XFRMA_VRFID])
			pvrfid = nla_data(xfrma[XFRMA_VRFID]);

		if (xfrma[XFRMA_XVRFID])
			pxvrfid = nla_data(xfrma[XFRMA_XVRFID]);
#endif
#endif /*XFRMA_VRFID*/
		if (xfrma[XFRMA_REPLAY_VAL])
			replay = (struct xfrm_replay_state *)RTA_DATA(xfrma[XFRMA_REPLAY_VAL]);
#ifdef XFRM_STATE_ESN
		if (xfrma[XFRMA_REPLAY_ESN_VAL])
			replay_esn = (struct xfrm_replay_state_esn *)RTA_DATA(xfrma[XFRMA_REPLAY_ESN_VAL]);
#endif
	}

	sa = (struct cm_ipsec_sa *)calloc(1, sizeof(*sa)+keybytes);

	if (!sa)
		goto bad;

	/* family */
	sa->family = p->family;

	/* SA protocol */
	sa->proto = p->id.proto;

	/* SPI */
	sa->spi = p->id.spi;

	/* VRFID and XVRFID */
	sa->vrfid = pvrfid ? *pvrfid : 0;
	sa->xvrfid = pxvrfid ? *pxvrfid : 0;

	/* destination address */
	memcpy(&sa->daddr, &p->id.daddr,
				sizeof(sa->daddr));

	/* source address */
	memcpy(&sa->saddr, &p->saddr,
				sizeof(sa->saddr));

	/* IPsec mode */
	sa->mode = p->mode;

	/* request ID */
	sa->reqid = p->reqid;

	/* replay window size */
	sa->replay = p->replay_window;

	if (replay) {
		sa->seq = (uint64_t)replay->seq;
		sa->oseq = (uint64_t)replay->oseq;
	}
#ifdef XFRM_STATE_ESN
	if (replay_esn) {
		sa->seq = ((uint64_t)replay_esn->seq_hi << 32) + replay_esn->seq;
		sa->oseq = ((uint64_t)replay_esn->oseq_hi << 32) + replay_esn->oseq;
		sa->replay = replay_esn->replay_window;
	}
#endif
	/* SA flags */
#ifdef XFRM_SA_XFLAG_DONT_ENCAP_DSCP /* vanilla kernels */
	if (xfrma && xfrma[XFRMA_SA_EXTRA_FLAGS]) {
		__u32 extra_flags = *(__u32 *)nla_data(xfrma[XFRMA_SA_EXTRA_FLAGS]);
		if (extra_flags & XFRM_SA_XFLAG_DONT_ENCAP_DSCP)
			sa->flags |= CM_SA_FLAG_DONT_ENCAPDSCP;
	}
#endif
	if (p->flags & XFRM_STATE_DECAP_DSCP)
		sa->flags |= CM_SA_FLAG_DECAPDSCP;
	if (p->flags & XFRM_STATE_NOPMTUDISC)
		sa->flags |= CM_SA_FLAG_NOPMTUDISC;
#ifdef XFRM_STATE_ESN
	if (p->flags & XFRM_STATE_ESN)
		sa->flags |= CM_SA_FLAG_ESN;
#endif
	/* encryption algorithm */
	if (crypt_algp) {
		sa->ealgo = ealg_nl2cm(crypt_algp->alg_name);
		if (sa->ealgo == CM_IPSEC_ALG_UNKNOWN) {
			syslog(LOG_ERR, "%s: unknown encryption algorithm\n", __FUNCTION__);
			goto bad;
		}

		sa->ekeylen = CM_ALIGNUNIT8(crypt_algp->alg_key_len);
		memcpy(sa->keys, crypt_algp->alg_key, sa->ekeylen);
		keyoff += sa->ekeylen;
	}
	else
	{
		sa->ealgo = CM_IPSEC_AALG_NONE;
	}

	/* authentication algorithm */
	if (auth_algp) {
		sa->aalgo = aalg_nl2cm(auth_algp->alg_name);
		if (sa->aalgo == CM_IPSEC_ALG_UNKNOWN) {
			syslog(LOG_ERR, "%s: unknown authentication algorithm\n", __FUNCTION__);
			goto bad;
		}
		sa->akeylen = CM_ALIGNUNIT8(auth_algp->alg_key_len);
		memcpy(sa->keys + keyoff, auth_algp->alg_key, sa->akeylen);
	}
	else
	{
		sa->aalgo = CM_IPSEC_AALG_NONE;
	}

	/* Crypto + auth algorithms */
	if (aead_algp) {
		sa->ealgo = ealg_nl2cm(aead_algp->alg_name);
		if (sa->ealgo == CM_IPSEC_ALG_UNKNOWN) {
			syslog(LOG_ERR, "%s: unknown authenticated encryption algorithm\n", __FUNCTION__);
			goto bad;
		}

		sa->ekeylen = CM_ALIGNUNIT8(aead_algp->alg_key_len);
		memcpy(sa->keys, aead_algp->alg_key, sa->ekeylen);
	}

	/* NAT Traversal */
	if (encap) {
		sa->sport = encap->encap_sport;
		sa->dport = encap->encap_dport;
	} else {
		sa->sport = 0;
		sa->dport = 0;
	}

	sa->output_blade = p->sel.user;

	if (xfrma) {
#ifdef XFRMA_SVTI_IFINDEX
		if (xfrma[XFRMA_SVTI_IFINDEX]) {
			uint32_t svti_ifindex = 0;
			uint32_t svti_ifuid = 0;
			svti_ifindex = *(u_int32_t *)nla_data(xfrma[XFRMA_SVTI_IFINDEX]);
			svti_ifuid = cm_ifindex2ifuid (svti_ifindex, sa->vrfid, 1);
			if (svti_ifuid == 0) {
				syslog(LOG_DEBUG, "%s: SVTI with unknown ifindex %d\n",
				       __FUNCTION__, svti_ifindex);
				goto bad;
			}
			sa->svti_ifuid = svti_ifuid;
		}
#endif
#ifdef CONFIG_CACHEMGR_XFRMA_MARK
	if (xfrma[XFRMA_MARK]) {
		struct xfrm_mark *mark = (void*)RTA_DATA(xfrma[XFRMA_MARK]);

		if (mark->m == 0xffffffff)
			sa->svti_ifuid = htonl(mark->v);
	}
#endif
	}

	/* Store limits */
	sa->soft.nb_bytes   = p->lft.soft_byte_limit;
	sa->soft.nb_packets = p->lft.soft_packet_limit;
	sa->hard.nb_bytes   = p->lft.hard_byte_limit;
	sa->hard.nb_packets = p->lft.hard_packet_limit;

	return sa;

bad:
	if (sa)
		free(sa);
	return NULL;
}

/*
 * Convert a NETLINK SA id to a cache manager SA
 */
static struct cm_ipsec_sa *
sa_nlid2cm(struct xfrm_usersa_id *p, uint32_t *pvrfid)
{
	struct cm_ipsec_sa *sa = NULL;

	sa = (struct cm_ipsec_sa *)calloc(1, sizeof(*sa));

	if (!sa)
		goto bad;

	/* Family*/
	sa->family = p->family;

	/* SA protocol */
	sa->proto = p->proto;

	/* SPI */
	sa->spi = p->spi;

	/* destination address */
	memcpy(&sa->daddr, &p->daddr,
				sizeof(sa->daddr));

	/* vrfid */
	sa->vrfid = pvrfid ? *pvrfid : 0;

	return sa;

bad:
	if (sa)
		free(sa);
	return NULL;
}

/*
 * Convert a NETLINK ACQUIRE to a special cache manager SA(null alg, null spi)
 */
static struct cm_ipsec_sa *
sa_nlacquire2cm(struct xfrm_user_acquire *p, struct nlattr **xfrma, uint32_t sock_vrfid)
{
	struct xfrm_user_tmpl *user_tmpl = NULL;
	struct cm_ipsec_sa *sa = NULL;

	if (xfrma[XFRMA_TMPL]) {
		/*
		 * Only examining the first SA template.
		 * SA bundles such as AH+ESP are not supported
		 */
		user_tmpl = nla_data(xfrma[XFRMA_TMPL]);
	} else {
		syslog(LOG_ERR, "%s: invalid acquire message, no XFRMA_TMPL attribute\n", __FUNCTION__);
		goto bad;
	}

	sa = (struct cm_ipsec_sa *)calloc(1, sizeof(*sa));

	if (!sa) {
		syslog(LOG_ERR, "%s: failed to allocate memory for FPC message\n", __FUNCTION__);
		goto bad;
	}

	/* address family */
	sa->family = user_tmpl->family;

	/* SA protocol (ESP/AH) */
	sa->proto = p->id.proto;

	/* VRFID and XVRFID */
#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	sa->vrfid = sock_vrfid;
	sa->xvrfid = sock_vrfid;
#else
#if defined(XFRMA_VRFID) && defined(XFRMA_XVRFID)
	if (xfrma[XFRMA_VRFID])
		sa->vrfid = *(uint32_t*)nla_data(xfrma[XFRMA_VRFID]);
	if (xfrma[XFRMA_XVRFID])
		sa->xvrfid = *(uint32_t*)nla_data(xfrma[XFRMA_XVRFID]);
#endif
#endif /*XFRMA_VRFID*/

	/* destination address */
	memcpy(&sa->daddr, &p->id.daddr,
				sizeof(sa->daddr));

	/* source address */
	memcpy(&sa->saddr, &p->saddr,
				sizeof(sa->saddr));

	/* IPsec mode */
	sa->mode = user_tmpl->mode;

	/* request ID */
	sa->reqid = user_tmpl->reqid;

	sa->output_blade = p->sel.user;

#ifdef XFRMA_SVTI_IFINDEX
		if (xfrma[XFRMA_SVTI_IFINDEX]) {
			uint32_t svti_ifindex = 0;
			uint32_t svti_ifuid = 0;
			svti_ifindex = *(u_int32_t *)nla_data(xfrma[XFRMA_SVTI_IFINDEX]);
			svti_ifuid = cm_ifindex2ifuid (svti_ifindex, sa->vrfid, 1);
			if (svti_ifuid == 0) {
				syslog(LOG_DEBUG, "%s: SVTI with unknown ifindex %d\n",
				       __FUNCTION__, svti_ifindex);
				goto bad;
			}
			sa->svti_ifuid = svti_ifuid;
		}
#endif
	return sa;

bad:
	if (sa)
		free(sa);
	return NULL;
}

static void
cm_nl_acquiresa(struct nlmsghdr *h, uint32_t sock_vrfid)
{
	struct xfrm_user_acquire * acquire = nlmsg_data(h);
	struct nlattr *xfrma[XFRMA_MAX + 1];
	struct cm_ipsec_sa *sa;
	int err;

	syslog(LOG_DEBUG, "%s(h=%p) ...\n", __FUNCTION__, h);
	err = cm_nlmsg_parse(h, sizeof(*acquire), xfrma, XFRMA_MAX, MSG_FAMILY_XFRM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	sa = sa_nlacquire2cm(acquire, xfrma, sock_vrfid);
	if (sa) {
		cm2cp_ipsec_sa_create(h->nlmsg_seq, sa);
		free(sa);
	}

}

static void
cm_nl_newsa(struct nlmsghdr *h, uint32_t sock_vrfid)
{
	struct xfrm_usersa_info *p = nlmsg_data(h);
	struct nlattr *tb[XFRMA_MAX + 1];
	struct cm_ipsec_sa *sa;
	int err;
	err = cm_nlmsg_parse(h, sizeof(*p), tb, XFRMA_MAX, MSG_FAMILY_XFRM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	sa = sa_nl2cm(p, tb, sock_vrfid);
	if (sa) {
		cm2cp_ipsec_sa_create(h->nlmsg_seq, sa);
		free(sa);
	}
}

static void
cm_nl_delsa(struct nlmsghdr *h, uint32_t sock_vrfid)
{
	struct nlattr *tb[XFRMA_MAX + 1];
	struct xfrm_usersa_id *p = nlmsg_data(h);
	struct cm_ipsec_sa *sa;
	uint32_t *pvrfid = NULL;
	int err;

	err = cm_nlmsg_parse(h, sizeof(*p), tb, XFRMA_MAX, MSG_FAMILY_XFRM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	pvrfid = &sock_vrfid;
#else
#ifdef XFRMA_VRFID
	if (tb[XFRMA_VRFID])
		pvrfid = nla_data(tb[XFRMA_VRFID]);
#endif /*XFRMA_VRFID*/
#endif

	sa = sa_nlid2cm(p, pvrfid);
	if (sa) {
		cm2cp_ipsec_sa_delete(h->nlmsg_seq, sa);
		free(sa);
	}
}

static void
cm_nl_expiresa(struct nlmsghdr *h, uint32_t sock_vrfid)
{
	struct nlattr *tb[XFRMA_MAX + 1];
	struct xfrm_user_expire *exp = nlmsg_data(h);
	struct xfrm_usersa_info *p = &exp->state;
	struct cm_ipsec_sa *sa;
	int err;

	/* ignore soft expire */
	if (exp->hard == 0)
		return;

	err = cm_nlmsg_parse(h, sizeof(*exp), tb, XFRMA_MAX, MSG_FAMILY_XFRM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	sa = sa_nl2cm(p, tb, sock_vrfid);
	if (sa) {
		cm2cp_ipsec_sa_delete(h->nlmsg_seq, sa);
		free(sa);
	}
}

int
cm_nl_getsa(struct nl_msg *msg, void *arg)
{
	cm_nl_newsa(nlmsg_hdr(msg), *(uint32_t *)arg);
	return 0;
}

/*
 * Convert a NETLINK SP to a cache manager SP
 */
static struct cm_ipsec_sp *
sp_nl2cm(struct xfrm_userpolicy_info *p, struct nlattr **xfrma, uint32_t sock_vrfid)
{
	struct cm_ipsec_sp *sp = NULL;
	int xfrm_count = 0, i;
	struct nlattr *rt = xfrma[XFRMA_TMPL];
	struct xfrm_user_tmpl *ut;
	uint32_t *pvrfid = NULL, *plinkvrfid = NULL;

	/* ignore policies bound to an interface: not supported */
	if (p->sel.ifindex)
		goto out;

	if (rt)
		xfrm_count = (rt->nla_len - sizeof(*rt)) / sizeof(*ut);

	sp = (struct cm_ipsec_sp *)calloc(1, sizeof(*sp) +
		xfrm_count * sizeof(struct cp_ipsec_xfrm));

	if (!sp)
		goto out;

	/* family */
	sp->family = p->sel.family;

	/* destination address and prefix length */
	memcpy(&sp->daddr, &p->sel.daddr, sizeof(sp->daddr));
	sp->dpfxlen = p->sel.prefixlen_d;

	/* source address and prefix length */
	memcpy(&sp->saddr, &p->sel.saddr, sizeof(sp->saddr));
	sp->spfxlen = p->sel.prefixlen_s;

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	pvrfid = &sock_vrfid;
	plinkvrfid = &sock_vrfid;
#else
#if defined(XFRMA_VRFID) && defined(XFRMA_LINKVRFID)
	if (xfrma[XFRMA_VRFID])
		pvrfid = nla_data(xfrma[XFRMA_VRFID]);

	if (xfrma[XFRMA_LINKVRFID])
		plinkvrfid = nla_data(xfrma[XFRMA_LINKVRFID]);
#endif
#endif /*XFRMA_VRFID*/

	sp->vrfid = pvrfid ? *pvrfid : 0;
	sp->link_vrfid = plinkvrfid ? *plinkvrfid : 0;

#ifdef XFRMA_SVTI_IFINDEX
	if (xfrma[XFRMA_SVTI_IFINDEX]) {
		uint32_t svti_ifindex = 0;
		uint32_t svti_ifuid = 0;
		svti_ifindex = *(u_int32_t *)nla_data(xfrma[XFRMA_SVTI_IFINDEX]);
		svti_ifuid = cm_ifindex2ifuid (svti_ifindex, sp->vrfid, 1);
		if (svti_ifuid == 0) {
			syslog(LOG_DEBUG, "%s: SVTI with unknown ifindex %d\n",
			       __FUNCTION__, svti_ifindex);
			goto out;
		}
		sp->svti_ifuid = svti_ifuid;
	}
#endif
#ifdef CONFIG_CACHEMGR_XFRMA_MARK
	if (xfrma[XFRMA_MARK]) {
		struct xfrm_mark *mark = (void*)RTA_DATA(xfrma[XFRMA_MARK]);

		if (mark->m == 0xffffffff)
			sp->svti_ifuid = htonl(mark->v);
	}
#endif

	/* source and destination port or type/code */
	sp->sport = p->sel.sport;
	sp->dport = p->sel.dport;
	sp->sportmask = p->sel.sport_mask;
	sp->dportmask = p->sel.dport_mask;

	/* layer 4 protocol */
	if (p->sel.proto)
		sp->proto = p->sel.proto;
	else
		sp->proto = 0xFF;

	/* rule index (unique ID) */
	sp->index = p->index;

	/* rule priority (order in table) */
	sp->priority = p->priority;

	/* flow direction */
	switch (p->dir) {
	case XFRM_POLICY_IN:
		sp->dir = CM_IPSEC_DIR_INBOUND;
		break;
	case XFRM_POLICY_OUT:
		sp->dir = CM_IPSEC_DIR_OUTBOUND;
		break;
	case XFRM_POLICY_FWD:
		/* Our assumption is: table IN and FWD are the same, thus we
		 * ignore XFRM_POLICY_FWD.
		 */
		goto out;
		break;
	default:
		syslog(LOG_ERR, "%s: invalid policy direction %d\n", __FUNCTION__,
				p->dir);
		goto out;
		break;
	}

	/* action */
	switch (p->action) {
	case XFRM_POLICY_BLOCK:
		sp->action = CM_IPSEC_ACTION_DISCARD;
		break;
	case XFRM_POLICY_ALLOW:
		if (xfrm_count)
			sp->action = CM_IPSEC_ACTION_IPSEC;
		else
			sp->action = CM_IPSEC_ACTION_CLEAR;
		break;
	default:
		syslog(LOG_ERR, "%s: invalid policy action %d\n", __FUNCTION__,
			p->action);
		goto out;
		break;
	}

	/* transformations */
	ut = nla_data(rt);
	sp->xfrm_count = xfrm_count;
	for (i=0; i < xfrm_count; i++, ut++) {
		struct cp_ipsec_xfrm *xfrm = &sp->xfrm[i];

		/* protocol (AH or ESP) */
		xfrm->proto = ut->id.proto;

		xfrm->family = ut->family;
		/* optional "outer" destination address */
		memcpy(&xfrm->daddr, &ut->id.daddr,
				sizeof(xfrm->daddr));

		/* "inner" source address */
		memcpy(&xfrm->saddr, &ut->saddr,
				sizeof(xfrm->saddr));

		/* transformation mode (transport/tunnel) */
		xfrm->mode = ut->mode ? CM_IPSEC_MODE_TUNNEL : CM_IPSEC_MODE_TRANSPORT;

		if (ut->optional)
			xfrm->flags |= CM_IPSEC_FLAG_LEVEL_USE;
		xfrm->reqid = ut->reqid;
	}

	return sp;

out:
	if (sp)
		free(sp);

	return NULL;
}


/*
 * Convert a NETLINK SP id to an cache manager SP
 */
static struct cm_ipsec_sp *
sp_nlid2cm(struct xfrm_userpolicy_info *p, struct nlattr **tb, uint32_t sock_vrfid)
{
	struct cm_ipsec_sp *sp = NULL;

	sp = (struct cm_ipsec_sp *)calloc(1, sizeof(*sp));

	if (!sp)
		goto bad;

	/* family */
	sp->family = p->sel.family;

	/* destination address and prefix length */
	memcpy(&sp->daddr, &p->sel.daddr,
			sizeof(sp->daddr));
	sp->dpfxlen = p->sel.prefixlen_d;

	/* source address and prefix length */
	memcpy(&sp->saddr, &p->sel.saddr,
			sizeof(sp->saddr));

	sp->spfxlen = p->sel.prefixlen_s;

	/* source and destination port or type/code */
	sp->sport = p->sel.sport;
	sp->dport = p->sel.dport;
	sp->sportmask = p->sel.sport_mask;
	sp->dportmask = p->sel.dport_mask;

	/* layer 4 protocol */
	if (p->sel.proto)
		sp->proto = p->sel.proto;
	else
		sp->proto = 0xFF;

	/* rule index (unique ID) */
	sp->index = p->index;

	/* flow direction */
	switch (p->dir) {
	case XFRM_POLICY_IN:
		sp->dir = CM_IPSEC_DIR_INBOUND;
		break;
	case XFRM_POLICY_OUT:
		sp->dir = CM_IPSEC_DIR_OUTBOUND;
		break;
	case XFRM_POLICY_FWD:
		syslog(LOG_DEBUG, "%s: ignoring policy direction fwd\n", __FUNCTION__);
		goto bad;
	default:
		syslog(LOG_ERR, "%s: invalid policy direction %d\n", __FUNCTION__,
				p->dir);
		goto bad;
		break;
	}

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	sp->vrfid = sock_vrfid;
#else
#ifdef XFRMA_VRFID
	if (tb[XFRMA_VRFID])
		sp->vrfid = *(uint32_t*)nla_data(tb[XFRMA_VRFID]);
#endif /*XFRMA_VRFID*/
#endif

#ifdef XFRMA_SVTI_IFINDEX
	if (tb[XFRMA_SVTI_IFINDEX]) {
		uint32_t svti_ifindex = 0;
		uint32_t svti_ifuid = 0;
		svti_ifindex = *(u_int32_t *)nla_data(tb[XFRMA_SVTI_IFINDEX]);
		svti_ifuid = cm_ifindex2ifuid (svti_ifindex, sp->vrfid, 1);
		if (svti_ifuid == 0) {
			syslog(LOG_DEBUG, "%s: SVTI with unknown ifindex %d\n",
			       __FUNCTION__, svti_ifindex);
			goto bad;
		}
		sp->svti_ifuid = svti_ifuid;
	}
#endif
#ifdef CONFIG_CACHEMGR_XFRMA_MARK
	if (tb[XFRMA_MARK]) {
		struct xfrm_mark *mark = (void*)RTA_DATA(tb[XFRMA_MARK]);

		if (mark->m == 0xffffffff)
			sp->svti_ifuid = htonl(mark->v);
	}
#endif

	return sp;

bad:
	if (sp)
		free(sp);
	return NULL;
}

static void
cm_nl_newsp(struct nlmsghdr *h, int update, uint32_t sock_vrfid)
{
	struct xfrm_userpolicy_info *p = nlmsg_data(h);
	struct nlattr *tb[XFRMA_MAX + 1];
	struct cm_ipsec_sp *sp;
	int err;

	if ((p->index & 0x7) >= XFRM_POLICY_MAX) {
		if (cm_debug_level & CM_DUMP_DBG_NL_RECV)
			syslog(LOG_INFO, "%s: ignoring socket policy\n", __FUNCTION__);
		return;
	}

	err = cm_nlmsg_parse(h, sizeof(*p), tb, XFRMA_MAX, MSG_FAMILY_XFRM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	sp = sp_nl2cm(p, tb, sock_vrfid);
	if (sp) {
		cm2cp_ipsec_sp_create(h->nlmsg_seq, sp, update);
		free(sp);
	}
}

static void cm_nl_delsp(struct nlmsghdr *h, uint32_t sock_vrfid)
{
	struct nlattr *tb[XFRMA_MAX + 1];
	int err;
	struct cm_ipsec_sp *sp;

	err = cm_nlmsg_parse(h, sizeof(struct xfrm_userpolicy_id), tb, XFRMA_MAX, MSG_FAMILY_XFRM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	if (!tb[XFRMA_POLICY]) {
		syslog(LOG_ERR, "netlink XFRM_MSG_DELPOLICY: missing XFRMA_POLICY attribute\n");
		return;
	}

	sp = sp_nlid2cm((struct xfrm_userpolicy_info *)nla_data(tb[XFRMA_POLICY]), tb, sock_vrfid);
	if (sp) {
		cm2cp_ipsec_sp_delete(h->nlmsg_seq, sp);
		free(sp);
	}
}

static void cm_nl_expiresp(struct nlmsghdr *h, uint32_t sock_vrfid)
{
	struct nlattr *tb[XFRMA_MAX + 1];
	struct xfrm_user_polexpire *xpexp = nlmsg_data(h);
	struct xfrm_userpolicy_info *xpinfo = &xpexp->pol;
	struct cm_ipsec_sp *sp;
	int err;

	/* ignore soft expire */
	if (xpexp->hard == 0)
		return;

	err = cm_nlmsg_parse(h, sizeof(*xpexp), tb, XFRMA_MAX, MSG_FAMILY_XFRM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

	sp = sp_nlid2cm(xpinfo, tb, sock_vrfid);
	if (sp) {
		cm2cp_ipsec_sp_delete(h->nlmsg_seq, sp);
		free(sp);
	}
}

int
cm_nl_getsp(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *h = nlmsg_hdr(msg);

	cm_nl_newsp(h, h->nlmsg_type == XFRM_MSG_UPDPOLICY, *(uint32_t *)arg);
	return 0;
}

static void
cm_nl_flushsa(struct nlmsghdr *h, uint32_t sock_vrfid)
{
	struct nlattr *tb[XFRMA_MAX + 1];
	uint32_t *pvrfid = NULL;
	int err;

	err = cm_nlmsg_parse(h, sizeof(struct xfrm_usersa_flush), tb, XFRMA_MAX, MSG_FAMILY_XFRM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	pvrfid = &sock_vrfid;
#else
#ifdef XFRMA_VRFID
	if (tb[XFRMA_VRFID])
		pvrfid = nla_data(tb[XFRMA_VRFID]);
#endif /*XFRMA_VRFID*/
#endif

	cm2cp_ipsec_sa_flush(h->nlmsg_seq, pvrfid ? *pvrfid : 0);
}

static void
cm_nl_flushsp(struct nlmsghdr *h, uint32_t sock_vrfid)
{
	struct nlattr *tb[XFRMA_MAX + 1];
	uint32_t *pvrfid = NULL, *psvti = NULL;
	int err;

	err = cm_nlmsg_parse(h, 0, tb, XFRMA_MAX, MSG_FAMILY_XFRM);
	if (err < 0) {
		syslog(LOG_ERR, "%s: could not parse message (%s)", __func__, nl_geterror(err));
		return;
	}

#ifdef CONFIG_PORTS_CACHEMGR_NETNS
	pvrfid = &sock_vrfid;
#else
#ifdef XFRMA_VRFID
	if (tb[XFRMA_VRFID])
		pvrfid = nla_data(tb[XFRMA_VRFID]);
#endif /*XFRMA_VRFID*/
#endif

#ifdef XFRMA_SVTI_IFINDEX
	if (tb[XFRMA_SVTI_IFINDEX])
		psvti = nla_data(tb[XFRMA_SVTI_IFINDEX]);
#endif

	cm2cp_ipsec_sp_flush(h->nlmsg_seq, pvrfid ? *pvrfid : 0, psvti ? *psvti : 0);
}

void cm_nl_xfrm_dispatch(struct nlmsghdr *h, u_int32_t sock_vrfid)
{
	switch (h->nlmsg_type) {
	case XFRM_MSG_ACQUIRE:
		cm_nl_acquiresa(h, sock_vrfid);
		break;
	case XFRM_MSG_NEWSA:
	case XFRM_MSG_UPDSA:
		cm_nl_newsa(h, sock_vrfid);
		break;

	case XFRM_MSG_DELSA:
		cm_nl_delsa(h, sock_vrfid);
		break;

	case XFRM_MSG_EXPIRE:
		cm_nl_expiresa(h, sock_vrfid);
		break;

	case XFRM_MSG_FLUSHSA:
		cm_nl_flushsa(h, sock_vrfid);
		break;

	case XFRM_MSG_NEWPOLICY:
	case XFRM_MSG_UPDPOLICY:
		cm_nl_newsp(h, h->nlmsg_type == XFRM_MSG_UPDPOLICY, sock_vrfid);
		break;

	case XFRM_MSG_DELPOLICY:
		cm_nl_delsp(h, sock_vrfid);
		break;

	case XFRM_MSG_POLEXPIRE:
		cm_nl_expiresp(h, sock_vrfid);
		break;

	case XFRM_MSG_FLUSHPOLICY:
		cm_nl_flushsp(h, sock_vrfid);
		break;

	default:
		break;
	}
}
